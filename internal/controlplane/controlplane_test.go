package controlplane

import (
	"log/slog"
	"os"
	"sync"
	"testing"
	"time"
)

func TestControlPlaneStreaming(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelDebug}))

	// Start server on a dynamic port
	server := NewServer("127.0.0.1:0", logger)
	err := server.Start()
	if err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer server.Close()

	// Get listener address
	addr := server.listener.Addr().String()

	var wg sync.WaitGroup
	wg.Add(1)

	var receivedData []byte
	client := NewClient(addr, logger, func(payload []byte) {
		receivedData = payload
		wg.Done()
	})
	client.Start()
	defer client.Close()

	// Wait for client to connect
	time.Sleep(100 * time.Millisecond)

	// Broadcast config update
	testPayload := []byte(`{"version": "v2", "agents": []}`)
	server.BroadcastConfig(testPayload)

	// Wait for callback with timeout
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for configuration broadcast")
	}

	if string(receivedData) != string(testPayload) {
		t.Errorf("received payload mismatch: got %s, want %s", string(receivedData), string(testPayload))
	}
}
