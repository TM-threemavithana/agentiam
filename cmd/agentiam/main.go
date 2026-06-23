package main

import (
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

	dbPath := os.Getenv("AGENTIAM_POLICY_DB_PATH")
	if dbPath == "" {
		dbPath = "./agentiam.db"
	}

	store, err := policy.NewStore(dbPath)
	if err != nil {
		log.Fatalf("Failed to initialize policy store: %v", err)
	}

	// Initialize structured logger
	logger := proxy.NewLogger(os.Stdout)

	// For demonstration purposes, seed the database with a test agent API key
	// that allows SELECT, INSERT, CREATE, and TRUNCATE, but blocks DELETE.
	err = store.AddAgent("test-agent-key", "Test Agent", []string{"SELECT", "INSERT", "CREATE", "TRUNCATE"})
	if err != nil {
		log.Fatalf("Failed to seed test agent: %v", err)
	}
	logger.Info("Seeded test agent with policy: SELECT, INSERT, CREATE, TRUNCATE", "agent", "test-agent-key")

	srv := proxy.NewServer(":"+listenPort, upstreamDSN, store, nil, logger)
	logger.Info("AgentIAM starting...", "port", listenPort)
	if err := srv.Start(); err != nil {
		logger.Error("Proxy server failed", "error", err)
		os.Exit(1)
	}
}
