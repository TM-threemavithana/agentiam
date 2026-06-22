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

	// For demonstration purposes, seed the database with a test agent API key
	// that only allows SELECT operations.
	err = store.AddAgent("test-agent-key", "Test Agent", []string{"SELECT"})
	if err != nil {
		log.Fatalf("Failed to seed test agent: %v", err)
	}
	log.Println("Seeded test agent 'test-agent-key' with policy: SELECT only")

	srv := proxy.NewServer(":"+listenPort, upstreamDSN, store)
	log.Printf("AgentIAM starting on port %s...", listenPort)
	if err := srv.Start(); err != nil {
		log.Fatalf("Proxy server failed: %v", err)
	}
}
