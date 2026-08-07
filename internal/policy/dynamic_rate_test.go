package policy

import (
	"log/slog"
	"os"
	"testing"
	"time"
)

func TestContextAwareRateLimiting(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))
	store, _ := NewStore("", "", logger)

	cfg := AgentConfig{
		Name:           "congested_agent",
		Key:            "bcrypt_key",
		RateLimitRPM:   60,
		RateLimitBurst: 1,
	}
	store.SetAgentPolicy("congested_agent", cfg)

	// 1. Normal latency (cost = 1) -> Allow first request
	store.SetPoolLatency(0)
	err := store.CheckRateLimit("congested_agent")
	if err != nil {
		t.Fatalf("expected first request to be allowed under normal latency: %v", err)
	}

	// Immediate next request should fail because bucket is empty
	err = store.CheckRateLimit("congested_agent")
	if err == nil {
		t.Fatal("expected second request to be rate limited")
	}

	// 2. Wait for bucket refilled
	time.Sleep(1100 * time.Millisecond)

	// 3. Set high pool latency (cost = 2) -> Should fail because rate limit burst is only 1!
	store.SetPoolLatency(200 * time.Millisecond)
	err = store.CheckRateLimit("congested_agent")
	if err == nil {
		t.Fatal("expected request under high pool latency to be blocked because cost (2) exceeds bucket burst (1)")
	}
}
