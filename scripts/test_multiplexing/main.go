package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/jackc/pgx/v5"
)

func main() {
	dsn := "postgres://test-agent:test-agent-secret@127.0.0.1:5433/postgres?sslmode=require"

	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		log.Fatalf("Failed to connect to proxy: %v", err)
	}
	defer conn.Close(ctx)

	fmt.Println("🤖 Connected to AgentIAM successfully.")

	fmt.Println("📝 Executing: SET timezone TO 'Antarctica/Troll'")
	_, err = conn.Exec(ctx, "SET timezone TO 'Antarctica/Troll'")
	if err != nil {
		log.Fatalf("Failed to set timezone: %v", err)
	}

	// Sleep to allow connection pool logic a chance to rotate connections
	time.Sleep(500 * time.Millisecond)

	fmt.Println("🔍 Querying: SHOW timezone")
	var tz string
	err = conn.QueryRow(ctx, "SHOW timezone").Scan(&tz)
	if err != nil {
		log.Fatalf("Failed to query timezone: %v", err)
	}

	fmt.Printf("Current timezone is: %s\n", tz)

	if tz != "Antarctica/Troll" {
		log.Fatalf("❌ FAILED: Session state was lost! Expected Antarctica/Troll, got %s", tz)
	}

	fmt.Println("✅ SUCCESS: Session state was successfully replayed across multiplexed transactions!")
}
