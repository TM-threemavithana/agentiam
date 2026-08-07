package policy

import (
	"io"
	"log/slog"
	"testing"
	"time"
)

func TestStore_TimingOracleProtection(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	store, _ := NewStore("", "", logger)

	store.SetAgentPolicy("test-agent", AgentConfig{
		Name: "test-agent",
		Key:  "$2a$10$Qj2z5r/T5xX3mBveqXg.1.uG0o1o1o1o1o1o1o1o1o1o1o1o1o1o1", // mock bcrypt
	})

	// 1. Password authentication for non-existent client (timing attack target)
	start := time.Now()
	_, _, err := store.GetRulesForAgent("non-existent", "wrong-password")
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if elapsed < 145*time.Millisecond {
		t.Errorf("timing oracle vulnerability: invalid user check was too fast (%v)", elapsed)
	}

	// 2. Password authentication for existing client with wrong password
	start = time.Now()
	_, _, err = store.GetRulesForAgent("test-agent", "wrong-password")
	elapsed = time.Since(start)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if elapsed < 145*time.Millisecond {
		t.Errorf("timing oracle vulnerability: invalid password check was too fast (%v)", elapsed)
	}

	// 3. mTLS verification (should be fast/immediate)
	start = time.Now()
	_, _, err = store.GetRulesForAgent("test-agent", "mTLS_VERIFIED")
	elapsed = time.Since(start)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if elapsed > 10*time.Millisecond {
		t.Errorf("mTLS verification was too slow (%v)", elapsed)
	}
}
