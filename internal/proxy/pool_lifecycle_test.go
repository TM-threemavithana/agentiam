package proxy_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/tm-threemavithana/agentiam/internal/proxy"
)

// mockUpstreamServer creates a mock PostgreSQL server that responds to Startup, Query, and DISCARD ALL.
func mockUpstreamServer(t *testing.T, handler func(backend *pgproto3.Backend, c net.Conn)) (net.Listener, string) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				backend := pgproto3.NewBackend(c, c)
				// Startup handshake
				_, err := backend.ReceiveStartupMessage()
				if err != nil {
					return
				}
				backend.Send(&pgproto3.AuthenticationOk{})
				backend.Send(&pgproto3.ParameterStatus{Name: "server_version", Value: "15.0"})
				backend.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
				if err := backend.Flush(); err != nil {
					return
				}

				if handler != nil {
					handler(backend, c)
				} else {
					// Default loop handling DISCARD ALL
					for {
						msg, err := backend.Receive()
						if err != nil {
							return
						}
						switch msg.(type) {
						case *pgproto3.Query:
							backend.Send(&pgproto3.CommandComplete{CommandTag: []byte("DISCARD ALL")})
							backend.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
							_ = backend.Flush()
						case *pgproto3.Terminate:
							return
						}
					}
				}
			}(conn)
		}
	}()

	dsn := fmt.Sprintf("postgres://user:pass@%s/testdb?sslmode=disable", l.Addr().String())
	return l, dsn
}

// TestPool_DoubleRelease_Idempotent verifies that releasing the same connection multiple times
// is strictly idempotent, does not corrupt channel capacity, and cannot duplicate connections.
func TestPool_DoubleRelease_Idempotent(t *testing.T) {
	l, dsn := mockUpstreamServer(t, nil)
	defer l.Close()

	logger := proxy.NewLogger(io.Discard)
	pool := proxy.NewPool(dsn, 2, logger)
	ctx := context.Background()
	if err := pool.Init(ctx); err != nil {
		t.Fatalf("pool.Init failed: %v", err)
	}
	defer pool.Close()

	u, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("Acquire failed: %v", err)
	}

	if pool.GetActiveCount() != 1 {
		t.Errorf("Expected active count 1, got %d", pool.GetActiveCount())
	}

	// First release
	pool.Release(u)

	// Second release of identical pointer
	pool.Release(u)

	// Third release concurrently
	done := make(chan struct{})
	go func() {
		pool.Release(u)
		close(done)
	}()
	<-done

	// Wait for cleanup
	time.Sleep(100 * time.Millisecond)

	if pool.GetActiveCount() != 0 {
		t.Errorf("Expected active count 0, got %d", pool.GetActiveCount())
	}
	if pool.GetIdleCount() != 2 {
		t.Errorf("Expected idle count exactly 2 (capacity preserved, no duplication), got %d", pool.GetIdleCount())
	}
}

// TestPool_ConcurrentAcquireAndRelease tests high concurrency acquisition and release
// under race detector to verify zero race conditions and metric invariants.
func TestPool_ConcurrentAcquireAndRelease(t *testing.T) {
	l, dsn := mockUpstreamServer(t, nil)
	defer l.Close()

	logger := proxy.NewLogger(io.Discard)
	const poolSize = 5
	pool := proxy.NewPool(dsn, poolSize, logger)
	ctx := context.Background()
	if err := pool.Init(ctx); err != nil {
		t.Fatalf("pool.Init failed: %v", err)
	}
	defer pool.Close()

	const workers = 20
	const iterations = 50

	var wg sync.WaitGroup
	var successCount atomic.Int64

	wg.Add(workers)
	for i := 0; i < workers; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				acquireCtx, cancel := context.WithTimeout(ctx, 500*time.Millisecond)
				u, err := pool.Acquire(acquireCtx)
				cancel()
				if err != nil {
					continue
				}

				// Simulate brief query processing
				time.Sleep(time.Duration((j%5)+1) * time.Millisecond)
				successCount.Add(1)

				pool.Release(u)
			}
		}()
	}

	wg.Wait()

	if successCount.Load() == 0 {
		t.Fatalf("Expected successful acquires, got 0")
	}

	// Allow pending DISCARD ALL routines to settle
	time.Sleep(300 * time.Millisecond)

	totalTracked := pool.GetIdleCount() + pool.GetActiveCount() + pool.GetCleaningCount()
	if totalTracked != poolSize {
		t.Errorf("Capacity invariant violated: idle(%d) + active(%d) + cleaning(%d) = %d != %d",
			pool.GetIdleCount(), pool.GetActiveCount(), pool.GetCleaningCount(), totalTracked, poolSize)
	}
}

// TestPool_DiscardAll_SuccessAndFailure verifies cleanup behavior when DISCARD ALL succeeds vs fails.
func TestPool_DiscardAll_SuccessAndFailure(t *testing.T) {
	t.Run("DiscardAll_Success", func(t *testing.T) {
		l, dsn := mockUpstreamServer(t, nil)
		defer l.Close()

		logger := proxy.NewLogger(io.Discard)
		pool := proxy.NewPool(dsn, 1, logger)
		ctx := context.Background()
		if err := pool.Init(ctx); err != nil {
			t.Fatalf("pool.Init failed: %v", err)
		}
		defer pool.Close()

		u, err := pool.Acquire(ctx)
		if err != nil {
			t.Fatalf("Acquire failed: %v", err)
		}

		pool.Release(u)

		// Wait for DISCARD ALL to complete
		time.Sleep(100 * time.Millisecond)

		if u.State() != proxy.ConnStateIdle {
			t.Errorf("Expected ConnStateIdle after successful release, got %v", u.State())
		}
		if u.InUse.Load() {
			t.Errorf("Expected InUse to be false after clean return to pool")
		}

		// Re-acquire and verify it is healthy
		u2, err := pool.Acquire(ctx)
		if err != nil || u2 == nil {
			t.Fatalf("Failed re-acquiring after clean release: %v", err)
		}
		pool.Release(u2)
	})

	t.Run("DiscardAll_Failure_ClosesAndReplaces", func(t *testing.T) {
		// Handler that deliberately abruptly closes connection on DISCARD ALL
		l, dsn := mockUpstreamServer(t, func(backend *pgproto3.Backend, c net.Conn) {
			for {
				msg, err := backend.Receive()
				if err != nil {
					return
				}
				if _, ok := msg.(*pgproto3.Query); ok {
					// Abruptly close connection instead of answering DISCARD ALL
					c.Close()
					return
				}
			}
		})
		defer l.Close()

		logger := proxy.NewLogger(io.Discard)
		pool := proxy.NewPool(dsn, 1, logger)
		ctx := context.Background()
		if err := pool.Init(ctx); err != nil {
			t.Fatalf("pool.Init failed: %v", err)
		}
		defer pool.Close()

		u, err := pool.Acquire(ctx)
		if err != nil {
			t.Fatalf("Acquire failed: %v", err)
		}

		// Release connection; DISCARD ALL will fail because mock closes socket
		pool.Release(u)

		// Wait for failure handling to close connection and replace with broken stub
		time.Sleep(150 * time.Millisecond)

		if !u.Broken.Load() {
			t.Errorf("Expected failed connection to be marked Broken")
		}
		if u.State() != proxy.ConnStateClosed {
			t.Errorf("Expected connection to be marked ConnStateClosed, got %v", u.State())
		}

		// Re-acquiring should safely detect the broken stub and redial a fresh connection
		u2, err := pool.Acquire(ctx)
		if err != nil || u2 == nil {
			t.Fatalf("Acquire should recover and redial after failed DISCARD ALL, got: %v", err)
		}
		if u2.Broken.Load() {
			t.Errorf("Re-acquired connection should be fresh and healthy")
		}
		pool.Release(u2)
	})
}

// TestPool_ExhaustionAndCancellation verifies that acquiring from an exhausted pool
// respects context cancellation without leaking capacity or blocking forever.
func TestPool_ExhaustionAndCancellation(t *testing.T) {
	l, dsn := mockUpstreamServer(t, nil)
	defer l.Close()

	logger := proxy.NewLogger(io.Discard)
	pool := proxy.NewPool(dsn, 1, logger)
	ctx := context.Background()
	if err := pool.Init(ctx); err != nil {
		t.Fatalf("pool.Init failed: %v", err)
	}
	defer pool.Close()

	// Acquire only connection
	u1, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("First acquire failed: %v", err)
	}

	// Second acquire with short deadline must timeout
	timeoutCtx, cancel := context.WithTimeout(ctx, 50*time.Millisecond)
	defer cancel()

	u2, err := pool.Acquire(timeoutCtx)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("Expected DeadlineExceeded, got err=%v, u2=%v", err, u2)
	}

	// Release first connection
	pool.Release(u1)
	time.Sleep(50 * time.Millisecond)

	// Now acquire should succeed immediately
	u3, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("Expected successful acquire after release, got: %v", err)
	}
	pool.Release(u3)
}

// TestPool_ReleaseRacingWithClose verifies that pool shutdown concurrent with connection release
// exits cleanly without panics, double closes, or hanging goroutines.
func TestPool_ReleaseRacingWithClose(t *testing.T) {
	l, dsn := mockUpstreamServer(t, nil)
	defer l.Close()

	logger := proxy.NewLogger(io.Discard)
	pool := proxy.NewPool(dsn, 5, logger)
	ctx := context.Background()
	if err := pool.Init(ctx); err != nil {
		t.Fatalf("pool.Init failed: %v", err)
	}

	conns := make([]*proxy.UpstreamConn, 5)
	for i := 0; i < 5; i++ {
		u, err := pool.Acquire(ctx)
		if err != nil {
			t.Fatalf("Acquire failed: %v", err)
		}
		conns[i] = u
	}

	// Concurrently release while closing pool
	var wg sync.WaitGroup
	for _, conn := range conns {
		c := conn
		wg.Add(1)
		go func() {
			defer wg.Done()
			time.Sleep(10 * time.Millisecond)
			pool.Release(c)
		}()
	}

	// Close pool concurrently
	pool.Close()
	wg.Wait()

	// Acquire on closed pool must immediately return ErrPoolClosed
	_, err := pool.Acquire(ctx)
	if !errors.Is(err, proxy.ErrPoolClosed) {
		t.Errorf("Expected ErrPoolClosed after Close(), got: %v", err)
	}
}

// TestPool_BrokenConnectionDisposal verifies that explicitly broken connections
// are closed and safely redialed on subsequent acquires.
func TestPool_BrokenConnectionDisposal(t *testing.T) {
	l, dsn := mockUpstreamServer(t, nil)
	defer l.Close()

	logger := proxy.NewLogger(io.Discard)
	pool := proxy.NewPool(dsn, 2, logger)
	ctx := context.Background()
	if err := pool.Init(ctx); err != nil {
		t.Fatalf("pool.Init failed: %v", err)
	}
	defer pool.Close()

	u, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("Acquire failed: %v", err)
	}

	u.Broken.Store(true)
	pool.Release(u)

	// Wait for background redial to complete
	time.Sleep(100 * time.Millisecond)

	// Next acquire must yield a healthy connection
	u2, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("Acquire failed after broken connection disposal: %v", err)
	}
	if u2.Broken.Load() {
		t.Errorf("Acquired connection must not be broken")
	}
	if u2.Conn == nil {
		t.Errorf("Acquired connection must have active net.Conn")
	}
	pool.Release(u2)
}

// TestPool_MaintainingUsableCapacityAfterFailures verifies that after a cascade of dial failures,
// the pool recovers full capacity once the upstream server is available again.
func TestPool_MaintainingUsableCapacityAfterFailures(t *testing.T) {
	l, dsn := mockUpstreamServer(t, nil)
	listenAddr := l.Addr().String()

	logger := proxy.NewLogger(io.Discard)
	const poolSize = 3
	pool := proxy.NewPool(dsn, poolSize, logger)
	ctx := context.Background()
	if err := pool.Init(ctx); err != nil {
		t.Fatalf("pool.Init failed: %v", err)
	}
	defer pool.Close()

	// 1. Acquire all connections and mark them broken
	conns := make([]*proxy.UpstreamConn, poolSize)
	for i := 0; i < poolSize; i++ {
		u, err := pool.Acquire(ctx)
		if err != nil {
			t.Fatalf("Acquire failed: %v", err)
		}
		conns[i] = u
		conns[i].Broken.Store(true)
	}

	// 2. Shut down upstream server
	l.Close()

	// 3. Release broken connections (background redial will fail and store broken stubs)
	for _, c := range conns {
		pool.Release(c)
	}
	time.Sleep(150 * time.Millisecond)

	// 4. Restart upstream server
	l2, err := net.Listen("tcp", listenAddr)
	if err != nil {
		t.Fatalf("Failed restarting mock server on %s: %v", listenAddr, err)
	}
	defer l2.Close()

	go func() {
		for {
			conn, err := l2.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				backend := pgproto3.NewBackend(c, c)
				_, _ = backend.ReceiveStartupMessage()
				backend.Send(&pgproto3.AuthenticationOk{})
				backend.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
				_ = backend.Flush()

				for {
					msg, err := backend.Receive()
					if err != nil {
						return
					}
					if _, ok := msg.(*pgproto3.Query); ok {
						backend.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
						_ = backend.Flush()
					}
				}
			}(conn)
		}
	}()

	// 5. Verify all 3 slots recover and can be acquired concurrently
	recoveredConns := make([]*proxy.UpstreamConn, poolSize)
	for i := 0; i < poolSize; i++ {
		recU, err := pool.Acquire(ctx)
		if err != nil {
			t.Fatalf("Failed acquiring recovered slot %d: %v", i, err)
		}
		if recU == nil || recU.Conn == nil || recU.Broken.Load() {
			t.Fatalf("Recovered slot %d returned invalid connection", i)
		}
		recoveredConns[i] = recU
	}

	// 6. Release all recovered connections
	for _, c := range recoveredConns {
		pool.Release(c)
	}
	time.Sleep(100 * time.Millisecond)

	if pool.GetIdleCount() != poolSize {
		t.Errorf("Expected full pool capacity %d, got idle count %d", poolSize, pool.GetIdleCount())
	}
}
