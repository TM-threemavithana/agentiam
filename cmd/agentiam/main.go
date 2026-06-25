package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/TM-threemavithana/agentiam/internal/cache"
	"github.com/TM-threemavithana/agentiam/internal/policy"
	"github.com/TM-threemavithana/agentiam/internal/proxy"

	"github.com/redis/go-redis/v9"
)

func main() {
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

	var rdb *redis.Client
	redisUrl := os.Getenv("AGENTIAM_REDIS_URL")
	if redisUrl != "" {
		opt, err := redis.ParseURL(redisUrl)
		if err != nil {
			log.Fatalf("Failed to parse Redis URL: %v", err)
		}
		opt.ReadTimeout = 50 * time.Millisecond
		opt.WriteTimeout = 50 * time.Millisecond
		opt.DialTimeout = 100 * time.Millisecond
		rdb = redis.NewClient(opt)

		ctx := context.Background()
		if err := rdb.Ping(ctx).Err(); err != nil {
			log.Fatalf("Failed to connect to Redis: %v", err)
		}
	}

	store, err := policy.NewStore(rdb, policyFile, apiUrl, logger.Logger)
	if err != nil {
		log.Fatalf("Failed to initialize policy store: %v", err)
	}

	// Start the hot-reload watcher (Redis Pub/Sub or fsnotify)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go store.Watch(ctx)

	tlsConfig, err := loadTLSConfig(logger)
	if err != nil {
		log.Fatalf("Failed to initialize TLS: %v", err)
	}

	var astCache cache.ASTCache
	if rdb != nil {
		rc := cache.NewRedisCacheFromClient(rdb, 24*time.Hour)
		lc, err := cache.NewLocalCache(2000)
		if err != nil {
			log.Fatalf("Failed to initialize local fallback cache: %v", err)
		}
		astCache = cache.NewFallbackCache(lc, rc)
		logger.Info("Using Redis+Local fallback for distributed AST Cache")
	} else {
		lc, err := cache.NewLocalCache(2000)
		if err != nil {
			log.Fatalf("Failed to initialize local cache: %v", err)
		}
		astCache = lc
		logger.Info("Using local LRU for AST Cache")
	}

	handlers := make(map[proxy.ProtocolType]proxy.ProtocolHandler)
	srv := proxy.NewServer(":"+listenPort, upstreamDSN, store, tlsConfig, logger, astCache, handlers)

	pgHandler := proxy.NewPostgresProtocolHandler(upstreamDSN, store, tlsConfig, logger, srv)
	mysqlHandler := proxy.NewMySQLProtocolHandler(store, logger)

	srv.SetHandler(proxy.ProtocolPostgres, pgHandler)
	srv.SetHandler(proxy.ProtocolMySQL, mysqlHandler)

	logger.Info("AgentIAM starting with Unified Port Multiplexer...", "port", listenPort)
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
