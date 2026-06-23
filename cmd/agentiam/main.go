package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"os"

	"agentiam/internal/policy"
	"agentiam/internal/proxy"
)

func main() {
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

	// Initialize structured logger
	logger := proxy.NewLogger(os.Stdout)

	store, err := policy.NewStore(policyFile, logger.Logger)
	if err != nil {
		log.Fatalf("Failed to initialize policy store: %v", err)
	}

	// Start the fsnotify hot-reload watcher
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go store.Watch(ctx)

	tlsConfig, err := loadTLSConfig(logger)
	if err != nil {
		log.Fatalf("Failed to initialize TLS: %v", err)
	}

	srv := proxy.NewServer(":"+listenPort, upstreamDSN, store, tlsConfig, logger)
	logger.Info("AgentIAM starting...", "port", listenPort)
	if err := srv.Start(); err != nil {
		logger.Error("Proxy server failed", "error", err)
		os.Exit(1)
	}
}

func loadTLSConfig(logger *proxy.Logger) (*tls.Config, error) {
	certFile := os.Getenv("AGENTIAM_TLS_CERT")
	keyFile := os.Getenv("AGENTIAM_TLS_KEY")

	if certFile != "" && keyFile != "" {
		cert, err := tls.LoadX509KeyPair(certFile, keyFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load TLS pair: %w", err)
		}
		return &tls.Config{Certificates: []tls.Certificate{cert}}, nil
	}

	if os.Getenv("AGENTIAM_DEV_MODE") == "true" {
		logger.Warn("TLS: using ephemeral self-signed cert — not for production")
		cert, err := proxy.GenerateEphemeralCert()
		if err != nil {
			return nil, err
		}
		return &tls.Config{Certificates: []tls.Certificate{cert}}, nil
	}

	return nil, nil
}
