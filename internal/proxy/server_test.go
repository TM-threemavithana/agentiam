package proxy

import (
	"github.com/tm-threemavithana/agentiam/internal/policy"
	"io"
	"log/slog"
	"net"
	"os"
	"runtime"
	"sync"
	"testing"
	"time"
)

func TestMaxConnectionsAndGoroutineCleanup(t *testing.T) {
	tmpFile, _ := os.CreateTemp("", "policies-*.yaml")
	tmpFile.Write([]byte("agents:\n  - name: dummy\n    key: dummy\n"))
	tmpFile.Close()
	defer os.Remove(tmpFile.Name())
	store, _ := policy.NewStore(nil, tmpFile.Name(), "", slog.New(slog.NewTextHandler(io.Discard, nil)))
	logger := NewLogger(io.Discard)
	// We use a dummy upstream DSN since we won't actually dial it for rejected connections
	handlers := make(map[ProtocolType]ProtocolHandler)
	server := NewServer("127.0.0.1:0", "postgres://dummy", store, nil, logger, nil, handlers)
	pgHandler := NewPostgresProtocolHandler("postgres://dummy", store, nil, logger, server)
	server.SetHandler(ProtocolPostgres, pgHandler)

	// Force max connections to 5 for testing
	server.maxConns = 5
	server.sem = make(chan struct{}, 5)

	// Start server
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	defer l.Close()

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			select {
			case server.sem <- struct{}{}:
				go func(c net.Conn) {
					session := NewSession(c, "postgres://dummy", store, nil, logger, server)
					defer session.Close()
					session.Run()
					<-server.sem
				}(conn)
			default:
				conn.Close() // Reject instantly
			}
		}
	}()

	addr := l.Addr().String()

	// Wait a bit to ensure stable baseline
	time.Sleep(100 * time.Millisecond)
	baselineGoroutines := runtime.NumGoroutine()

	var wg sync.WaitGroup
	var conns []net.Conn
	var mu sync.Mutex

	// Open 5 connections (the maximum allowed)
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := net.Dial("tcp", addr)
			if err == nil {
				mu.Lock()
				conns = append(conns, conn)
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if len(conns) != 5 {
		t.Fatalf("Failed to open 5 allowed connections. Opened: %d", len(conns))
	}

	// Now try to open the 6th connection (should be rejected immediately)
	conn6, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("Failed to dial 6th connection: %v", err)
	}

	// Try to read from conn6, it should return EOF immediately because the server closed it
	buf := make([]byte, 1)
	conn6.SetReadDeadline(time.Now().Add(1 * time.Second))
	_, err = conn6.Read(buf)
	if err == nil {
		t.Fatalf("Expected 6th connection to be closed by server, but it stayed open")
	}
	conn6.Close()

	// Wait briefly to allow the rejected connection's goroutine cleanup (if any) to happen.
	// Since we rejected it synchronously before spawning a goroutine, NumGoroutine shouldn't have spiked permanently.
	time.Sleep(100 * time.Millisecond)

	// Close all valid connections to trigger teardown of their goroutines
	for _, c := range conns {
		c.Close()
	}

	// Wait for all teardown to complete
	time.Sleep(200 * time.Millisecond)

	finalGoroutines := runtime.NumGoroutine()

	// Final count should equal baseline (or very close, accounting for Go's internal runtime noise)
	// We allow a small tolerance, but if it leaked 5*3=15 goroutines, it would be a major failure.
	if finalGoroutines > baselineGoroutines+2 {
		t.Errorf("Goroutine leak detected! Baseline: %d, Final: %d", baselineGoroutines, finalGoroutines)
	}
}

func TestStartupIterationLimit(t *testing.T) {
	tmpFile, _ := os.CreateTemp("", "policies-*.yaml")
	tmpFile.Write([]byte("agents:\n  - name: dummy\n    key: dummy\n"))
	tmpFile.Close()
	defer os.Remove(tmpFile.Name())
	store, _ := policy.NewStore(nil, tmpFile.Name(), "", slog.New(slog.NewTextHandler(io.Discard, nil)))
	// Use a dummy upstream DSN since we only care about the startup phase
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	defer l.Close()

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				logger := NewLogger(io.Discard)
				handlers := make(map[ProtocolType]ProtocolHandler)
				server := NewServer("127.0.0.1:0", "postgres://dummy", store, nil, logger, nil, handlers)
				pgHandler := NewPostgresProtocolHandler("postgres://dummy", store, nil, logger, server)
				server.SetHandler(ProtocolPostgres, pgHandler)
				session := NewSession(c, "postgres://dummy", store, nil, logger, server)
				defer session.Close()
				_ = session.Run() // Run the session, which should hit the iteration limit
			}(conn)
		}
	}()

	addr := l.Addr().String()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("Failed to dial server: %v", err)
	}
	defer conn.Close()

	// SSLRequest is always 8 bytes: 00 00 00 08 04 d2 16 2f
	sslRequest := []byte{0, 0, 0, 8, 4, 210, 22, 47}

	// We send 3 SSLRequests and expect 'N' back each time.
	for i := 0; i < 3; i++ {
		_, err := conn.Write(sslRequest)
		if err != nil {
			t.Fatalf("Failed to write SSLRequest on iteration %d: %v", i+1, err)
		}

		// Read the 1-byte response ('N' since TLS is not configured)
		resp := make([]byte, 1)
		conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, err := conn.Read(resp)
		if err != nil {
			t.Fatalf("Failed to read proxy response on iteration %d: %v", i+1, err)
		}
		if n != 1 || resp[0] != 'N' {
			t.Fatalf("Expected 'N' on iteration %d, got %v", i+1, resp)
		}
	}

	// On the 4th send, the server loop has broken and the connection should be closed.
	_, err = conn.Write(sslRequest)
	if err != nil {
		// It's possible the write fails immediately if the socket is already closed locally
		return
	}

	// But if the write succeeds (buffered), the read must fail with EOF/reset
	resp := make([]byte, 1)
	conn.SetReadDeadline(time.Now().Add(1 * time.Second))
	_, err = conn.Read(resp)
	if err == nil {
		t.Fatalf("Expected connection to be closed by proxy after 3 iterations, but read succeeded")
	}
}
