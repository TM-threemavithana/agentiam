package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"flag"
	"golang.org/x/crypto/bcrypt"

	"github.com/tm-threemavithana/agentiam"
	"github.com/tm-threemavithana/agentiam/internal/cache"
	"github.com/tm-threemavithana/agentiam/internal/policy"
	"github.com/tm-threemavithana/agentiam/internal/proxy"
)

func main() {
	hashPassword := flag.String("hash-password", "", "Generate a bcrypt hash for the provided password and exit")
	flag.Parse()

	if *hashPassword != "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(*hashPassword), bcrypt.DefaultCost)
		if err != nil {
			log.Fatalf("Failed to hash password: %v", err)
		}
		fmt.Printf("%s\n", string(hash))
		os.Exit(0)
	}

	if _, err := proxy.InitTracer(); err != nil {
		log.Printf("Failed to initialize OpenTelemetry Tracer: %v", err)
	}

	upstreamDSN := os.Getenv("AGENTIAM_UPSTREAM_DSN")
	if upstreamDSN == "" {
		log.Fatal("AGENTIAM_UPSTREAM_DSN is required")
	}

	listenPort := os.Getenv("AGENTIAM_LISTEN_PORT")
	if listenPort == "" {
		listenPort = "5433"
	}

	policyFile := os.Getenv("AGENTIAM_POLICY_FILE")
	if policyFile == "" {
		policyFile = "./policies.yaml"
	}

	apiUrl := os.Getenv("AGENTIAM_IAM_API_URL")

	// Initialize structured logger
	logger := proxy.NewLogger(os.Stdout)

	insecureAuth := os.Getenv("AGENTIAM_INSECURE_CLEARTEXT_AUTH") == "true"
	if insecureAuth {
		logger.Warn("INSECURE CLEARTEXT AUTH IS ENABLED. DO NOT USE IN PRODUCTION WITHOUT SECURE BOUNDARIES.")
	}

	store, err := policy.NewStore(policyFile, apiUrl, logger.Logger)
	if err != nil {
		log.Fatalf("Failed to initialize policy store: %v", err)
	}

	// Start the hot-reload watcher (fsnotify + HTTP polling + TCP control plane)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go store.Watch(ctx)

	tlsConfig, err := loadTLSConfig(logger)
	if err != nil {
		log.Fatalf("Failed to initialize TLS: %v", err)
	}

	var astCache cache.ASTCache
	lc, err := cache.NewLocalCache(2000)
	if err != nil {
		log.Fatalf("Failed to initialize local cache: %v", err)
	}
	astCache = lc
	logger.Info("Using local LRU for AST Cache")

	metricsAddr := os.Getenv("AGENTIAM_METRICS_ADDR")
	if metricsAddr == "" {
		// S6: Bind metrics/dashboard to localhost by default.
		// Set AGENTIAM_METRICS_ADDR=":9090" to expose on all interfaces (e.g., behind a VPN).
		metricsAddr = "127.0.0.1:9090"
	}

	poolSize := 50
	if psStr := os.Getenv("AGENTIAM_POOL_SIZE"); psStr != "" {
		if ps, err := strconv.Atoi(psStr); err == nil && ps > 0 {
			poolSize = ps
		} else {
			logger.Warn("Invalid AGENTIAM_POOL_SIZE, falling back to default 50", "input", psStr)
		}
	}

	handlers := make(map[proxy.ProtocolType]proxy.ProtocolHandler)
	webhookUrl := os.Getenv("AGENTIAM_WEBHOOK_URL")
	webhook := proxy.NewWebhookDispatcher(webhookUrl, logger.Logger)

	uiFS, err := agentiam.GetUIFS()
	if err != nil {
		logger.Warn("UI embedded filesystem not found, dashboard will be disabled", "error", err)
	}

	srv := proxy.NewServer(":"+listenPort, upstreamDSN, store, tlsConfig, logger, astCache, handlers, insecureAuth, metricsAddr, poolSize, webhook, uiFS)

	pgHandler := proxy.NewPostgresProtocolHandler(upstreamDSN, store, tlsConfig, logger, srv, insecureAuth)
	mysqlHandler := proxy.NewMySQLProtocolHandler(store, logger, srv, insecureAuth)

	srv.SetHandler(proxy.ProtocolPostgres, pgHandler)
	srv.SetHandler(proxy.ProtocolMySQL, mysqlHandler)

	edwHttpPort := os.Getenv("AGENTIAM_EDW_HTTP_PORT")
	if edwHttpPort == "" {
		edwHttpPort = "8080"
	}
	
	edwUpstreamAuth := os.Getenv("AGENTIAM_EDW_UPSTREAM_AUTH")
	if edwUpstreamAuth == "" && strings.Contains(upstreamDSN, "http") {
		logger.Warn("AGENTIAM_EDW_UPSTREAM_AUTH is not set, EDW proxy will not inject upstream auth")
	}

	if strings.Contains(upstreamDSN, "http") {
		httpInterceptor, err := proxy.NewHTTPInterceptorProxy(upstreamDSN, store, logger, astCache, edwUpstreamAuth)
		if err != nil {
			logger.Error("Failed to init HTTP Proxy", "error", err)
			os.Exit(1)
		}
		
		go func() {
			logger.Info("Starting HTTP EDW Interceptor...", "port", edwHttpPort)
			if err := http.ListenAndServe(":"+edwHttpPort, httpInterceptor); err != nil {
				logger.Error("HTTP Proxy failed", "error", err)
			}
		}()
	}

	logger.Info("AgentIAM starting with Unified Port Multiplexer...", "port", listenPort)

	// O2: Graceful shutdown — catch SIGTERM/SIGINT, stop accepting new connections,
	// wait up to 30 seconds for in-flight sessions to complete.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		sig := <-sigCh
		logger.Info("Shutdown signal received, stopping...", "signal", sig)
		cancel() // Stop hot-reload watchers and session contexts

		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer shutdownCancel()

		if err := srv.Shutdown(shutdownCtx); err != nil {
			logger.Error("Graceful shutdown timed out", "error", err)
			os.Exit(1)
		}
		logger.Info("AgentIAM shutdown complete")
		os.Exit(0)
	}()

	if err := srv.Start(); err != nil {
		logger.Error("Proxy server failed", "error", err)
		os.Exit(1)
	}
}

func loadTLSConfig(logger *proxy.Logger) (*tls.Config, error) {
	certFile := os.Getenv("AGENTIAM_TLS_CERT")
	keyFile := os.Getenv("AGENTIAM_TLS_KEY")
	mtlsCA := os.Getenv("AGENTIAM_MTLS_CA")

	cfg := &tls.Config{
		MinVersion: tls.VersionTLS13,
	}

	if mtlsCA != "" {
		caCert, err := os.ReadFile(mtlsCA)
		if err != nil {
			return nil, fmt.Errorf("failed to read mTLS CA file: %w", err)
		}
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
		cfg.ClientCAs = caCertPool
		cfg.ClientAuth = tls.VerifyClientCertIfGiven
		logger.Info("mTLS CA loaded, Client Certificates will be verified", "file", mtlsCA)
	}

	if certFile != "" && keyFile != "" {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load TLS pair: %w", err)
		}
		cfg.Certificates = []tls.Certificate{cert}
		return cfg, nil
	}

	if os.Getenv("AGENTIAM_DEV_MODE") == "true" {
		logger.Warn("TLS: using ephemeral self-signed cert — not for production")
		cert, err := proxy.GenerateEphemeralCert()
		if err != nil {
			return nil, err
		}
		cfg.Certificates = []tls.Certificate{cert}
		return cfg, nil
	}

	return nil, fmt.Errorf("TLS configuration missing (set AGENTIAM_TLS_CERT/KEY or AGENTIAM_DEV_MODE=true)")
}
