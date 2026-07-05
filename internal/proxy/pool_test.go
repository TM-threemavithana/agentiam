package proxy

import (
	"context"
	"io"
	"net"
	"testing"
	"time"

	"github.com/jackc/pgproto3/v2"
)

// mockUpstream represents a dummy upstream database to test pool dialing.
func mockUpstream(t *testing.T, listenAddr string) net.Listener {
	l, err := net.Listen("tcp", listenAddr)
	if err != nil {
		t.Fatalf("Failed to start mock upstream: %v", err)
	}
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				backend := pgproto3.NewBackend(pgproto3.NewChunkReader(c), c)
				// Consume startup message
				_, _ = backend.ReceiveStartupMessage()
				// Send AuthenticationOk and ReadyForQuery
				_ = backend.Send(&pgproto3.AuthenticationOk{})
				_ = backend.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
				// Wait for DISCARD ALL or close
				_, _ = backend.Receive()
				c.Close()
			}(conn)
		}
	}()
	return l
}

func TestPool_DialFailureRecovery(t *testing.T) {
	// Start a mock upstream server
	l := mockUpstream(t, "127.0.0.1:0")
	dsn := "postgres://user:pass@" + l.Addr().String() + "/db?sslmode=disable"
	
	logger := NewLogger(io.Discard)
	pool := NewPool(dsn, 2, logger)
	
	ctx := context.Background()
	if err := pool.Init(ctx); err != nil {
		t.Fatalf("Failed to initialize pool: %v", err)
	}

	// 1. Acquire a connection
	u1, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("Expected to acquire connection, got err: %v", err)
	}
	if u1 == nil || u1.Conn == nil {
		t.Fatalf("Acquired nil connection!")
	}

	// 2. Break the connection explicitly to force redial on release
	u1.Broken.Store(true)

	// 3. Stop the upstream server so the background redial FAILS
	l.Close()

	// 4. Release it. The pool background worker will try to dial(), fail, and push a Broken dummy connection.
	pool.Release(u1)
	
	// Wait a tiny bit for the background redial to execute and fail
	time.Sleep(100 * time.Millisecond)

	// 5. Restart the upstream server so the NEXT dial can succeed
	l = mockUpstream(t, l.Addr().String())
	defer l.Close()

	// 6. Acquire again. The pool should pull the dummy Broken connection, close it, and synchronously redial.
	u2, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("Expected successful re-dial in Acquire, got error: %v", err)
	}
	if u2 == nil || u2.Conn == nil {
		t.Fatalf("Acquire returned a connection with nil Conn (Nil Pointer Panic vulnerability!)")
	}

	// 7. Success! No panic, and we have a valid connection again.
	pool.Release(u2)
}
