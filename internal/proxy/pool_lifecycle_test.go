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
	dto "github.com/prometheus/client_model/go"
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

// TestPool_WorkerAdmission_CloseRaceBarrier uses deterministic synchronization barriers
// to verify that worker admission and Pool.Close() synchronize cleanly without WaitGroup panic or leaks.
func TestPool_WorkerAdmission_CloseRaceBarrier(t *testing.T) {
	for iter := 0; iter < 10; iter++ {
		l, dsn := mockUpstreamServer(t, nil)

		logger := proxy.NewLogger(io.Discard)
		const poolSize = 4
		pool := proxy.NewPool(dsn, poolSize, logger)
		ctx := context.Background()
		if err := pool.Init(ctx); err != nil {
			l.Close()
			t.Fatalf("iter %d: pool.Init failed: %v", iter, err)
		}

		// Acquire all connections
		conns := make([]*proxy.UpstreamConn, poolSize)
		for i := 0; i < poolSize; i++ {
			u, err := pool.Acquire(ctx)
			if err != nil {
				l.Close()
				t.Fatalf("iter %d: Acquire %d failed: %v", iter, i, err)
			}
			conns[i] = u
		}

		// Barrier to release and close simultaneously
		startBarrier := make(chan struct{})
		var wg sync.WaitGroup

		for _, conn := range conns {
			c := conn
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-startBarrier
				pool.Release(c)
			}()
		}

		wg.Add(1)
		go func() {
			defer wg.Done()
			<-startBarrier
			pool.Close()
		}()

		// Trigger simultaneous release and close
		close(startBarrier)
		wg.Wait()

		// Verify pool is closed and cannot acquire
		_, err := pool.Acquire(ctx)
		if !errors.Is(err, proxy.ErrPoolClosed) {
			t.Errorf("iter %d: Expected ErrPoolClosed, got %v", iter, err)
		}

		l.Close()
	}
}

// TestPool_RepeatedRelease_RacingWithShutdown tests repeated concurrent releases racing with Close()
// to verify that double-release CAS protection and worker admission sealing prevent panics or deadlocks.
func TestPool_RepeatedRelease_RacingWithShutdown(t *testing.T) {
	l, dsn := mockUpstreamServer(t, nil)
	defer l.Close()

	logger := proxy.NewLogger(io.Discard)
	const poolSize = 5
	pool := proxy.NewPool(dsn, poolSize, logger)
	ctx := context.Background()
	if err := pool.Init(ctx); err != nil {
		t.Fatalf("pool.Init failed: %v", err)
	}

	conns := make([]*proxy.UpstreamConn, poolSize)
	for i := 0; i < poolSize; i++ {
		u, err := pool.Acquire(ctx)
		if err != nil {
			t.Fatalf("Acquire failed: %v", err)
		}
		conns[i] = u
	}

	var wg sync.WaitGroup
	// Concurrently invoke Release 5 times per connection
	for _, conn := range conns {
		for r := 0; r < 5; r++ {
			c := conn
			wg.Add(1)
			go func() {
				defer wg.Done()
				pool.Release(c)
			}()
		}
	}

	// Concurrently close
	wg.Add(1)
	go func() {
		defer wg.Done()
		pool.Close()
	}()

	wg.Wait()

	// Invariant: pool must be closed cleanly
	_, err := pool.Acquire(ctx)
	if !errors.Is(err, proxy.ErrPoolClosed) {
		t.Errorf("Expected ErrPoolClosed after shutdown, got: %v", err)
	}
}

// TestPool_ShutdownWhileDiscardAllBlocked verifies that if an upstream connection hangs during DISCARD ALL,
// Pool.Close() aborts the blocked operation promptly and completes shutdown without hanging for the full 5s timeout.
func TestPool_ShutdownWhileDiscardAllBlocked(t *testing.T) {
	// Mock server that deliberately hangs on receiving DISCARD ALL
	discardReceived := make(chan struct{})
	l, dsn := mockUpstreamServer(t, func(backend *pgproto3.Backend, c net.Conn) {
		for {
			msg, err := backend.Receive()
			if err != nil {
				return
			}
			if _, ok := msg.(*pgproto3.Query); ok {
				// Signal that DISCARD ALL was received and deliberately block without sending response
				select {
				case <-discardReceived:
				default:
					close(discardReceived)
				}
				// Hang until socket is closed by client
				buf := make([]byte, 1)
				_, _ = c.Read(buf)
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

	u, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("Acquire failed: %v", err)
	}

	// Release starts DISCARD ALL worker
	pool.Release(u)

	// Wait for worker to send DISCARD ALL and block
	select {
	case <-discardReceived:
	case <-time.After(2 * time.Second):
		t.Fatalf("Timed out waiting for DISCARD ALL to be received by mock server")
	}

	// Now close the pool; it should cancel pool context and unblock promptly
	startClose := time.Now()
	pool.Close()
	closeDuration := time.Since(startClose)

	if closeDuration > 2*time.Second {
		t.Errorf("Pool.Close() took %v; expected prompt cancellation well under 2s", closeDuration)
	}

	_, err = pool.Acquire(ctx)
	if !errors.Is(err, proxy.ErrPoolClosed) {
		t.Errorf("Expected ErrPoolClosed, got %v", err)
	}
}

func readGaugeValue(g interface{ Write(*dto.Metric) error }) float64 {
	var m dto.Metric
	if err := g.Write(&m); err != nil {
		return 0
	}
	if m.Gauge != nil {
		return m.Gauge.GetValue()
	}
	return 0
}

// TestPool_MetricAccounting_BrokenVsHealthy directly verifies Finding D:
// 1. Broken placeholder tokens are NEVER counted as healthy idle connections in PoolIdleConnections.
// 2. PoolBrokenConnections tracks placeholder stubs accurately.
// 3. Gauges remain balanced during acquire, failure, recovery, and close.
func TestPool_MetricAccounting_BrokenVsHealthy(t *testing.T) {
	l, dsn := mockUpstreamServer(t, nil)
	listenAddr := l.Addr().String()

	logger := proxy.NewLogger(io.Discard)
	const poolSize = 3
	pool := proxy.NewPool(dsn, poolSize, logger)
	ctx := context.Background()
	if err := pool.Init(ctx); err != nil {
		l.Close()
		t.Fatalf("pool.Init failed: %v", err)
	}
	defer pool.Close()

	// 1. Initial metrics
	if pool.GetIdleCount() != 3 {
		t.Fatalf("Expected healthy idle count 3, got %d", pool.GetIdleCount())
	}
	if pool.GetBrokenCount() != 0 {
		t.Fatalf("Expected broken count 0, got %d", pool.GetBrokenCount())
	}
	if idleMetric := readGaugeValue(proxy.PoolIdleConnections); idleMetric != 3 {
		t.Fatalf("Expected PoolIdleConnections gauge 3, got %v", idleMetric)
	}
	if brokenMetric := readGaugeValue(proxy.PoolBrokenConnections); brokenMetric != 0 {
		t.Fatalf("Expected PoolBrokenConnections gauge 0, got %v", brokenMetric)
	}

	// 2. Acquire 1 connection
	u1, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("Acquire failed: %v", err)
	}
	if pool.GetIdleCount() != 2 {
		t.Fatalf("Expected idle count 2 after acquire, got %d", pool.GetIdleCount())
	}
	if idleMetric := readGaugeValue(proxy.PoolIdleConnections); idleMetric != 2 {
		t.Fatalf("Expected PoolIdleConnections gauge 2, got %v", idleMetric)
	}

	// 3. Mark connection broken and close upstream so background redial fails
	u1.Broken.Store(true)
	l.Close()

	pool.Release(u1)

	// Wait for background redial to fail and place broken placeholder into pool
	for start := time.Now(); time.Since(start) < 2*time.Second; time.Sleep(5 * time.Millisecond) {
		if pool.GetRedialingCount() == 0 && pool.GetBrokenCount() == 1 {
			break
		}
	}

	// Invariant check: PoolIdleConnections MUST NOT have incremented!
	if pool.GetIdleCount() != 2 {
		t.Errorf("Finding D violation: healthy idle count must remain 2, got %d", pool.GetIdleCount())
	}
	if idleMetric := readGaugeValue(proxy.PoolIdleConnections); idleMetric != 2 {
		t.Errorf("Finding D violation: PoolIdleConnections gauge must remain 2, got %v", idleMetric)
	}
	if pool.GetBrokenCount() != 1 {
		t.Errorf("Expected broken count 1, got %d", pool.GetBrokenCount())
	}
	if brokenMetric := readGaugeValue(proxy.PoolBrokenConnections); brokenMetric != 1 {
		t.Errorf("Expected PoolBrokenConnections gauge 1, got %v", brokenMetric)
	}
	if pool.GetChannelLen() != 3 {
		t.Errorf("Expected channel length 3 (2 healthy + 1 broken), got %d", pool.GetChannelLen())
	}

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

	// 5. Acquire 3 times: 2 healthy immediately, 1 broken slot triggers redial and succeeds
	c1, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("Acquire 1 failed: %v", err)
	}
	c2, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("Acquire 2 failed: %v", err)
	}
	c3, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("Acquire 3 (redialed slot) failed: %v", err)
	}

	if pool.GetBrokenCount() != 0 {
		t.Errorf("Expected broken count 0 after redial, got %d", pool.GetBrokenCount())
	}
	if brokenMetric := readGaugeValue(proxy.PoolBrokenConnections); brokenMetric != 0 {
		t.Errorf("Expected PoolBrokenConnections 0, got %v", brokenMetric)
	}
	if pool.GetActiveCount() != 3 {
		t.Errorf("Expected active count 3, got %d", pool.GetActiveCount())
	}

	// 6. Release all three cleanly
	pool.Release(c1)
	pool.Release(c2)
	pool.Release(c3)
	for start := time.Now(); time.Since(start) < 2*time.Second; time.Sleep(5 * time.Millisecond) {
		if pool.GetCleaningCount() == 0 && pool.GetIdleCount() == 3 {
			break
		}
	}

	if pool.GetIdleCount() != 3 {
		t.Errorf("Expected all 3 healthy idle, got %d", pool.GetIdleCount())
	}
	if idleMetric := readGaugeValue(proxy.PoolIdleConnections); idleMetric != 3 {
		t.Errorf("Expected PoolIdleConnections 3, got %v", idleMetric)
	}
}

// TestPool_CapacityInvariant_StateTransitions verifies the formal state-based capacity invariant:
// healthyIdleCount + brokenCount + activeCount + cleaningCount + redialingCount == p.size
// across all valid lifecycle transitions.
func TestPool_CapacityInvariant_StateTransitions(t *testing.T) {
	l, dsn := mockUpstreamServer(t, nil)
	defer l.Close()

	logger := proxy.NewLogger(io.Discard)
	const poolSize = 4
	pool := proxy.NewPool(dsn, poolSize, logger)
	ctx := context.Background()
	if err := pool.Init(ctx); err != nil {
		t.Fatalf("pool.Init failed: %v", err)
	}
	defer pool.Close()

	checkInvariant := func(stage string) {
		h := pool.GetHealthyIdleCount()
		b := pool.GetBrokenCount()
		a := pool.GetActiveCount()
		c := pool.GetCleaningCount()
		r := pool.GetRedialingCount()
		sum := h + b + a + c + r
		if sum != poolSize {
			t.Errorf("[%s] Invariant violated: healthy(%d) + broken(%d) + active(%d) + cleaning(%d) + redialing(%d) = %d != %d",
				stage, h, b, a, c, r, sum, poolSize)
		}
		if pool.GetChannelLen() != h+b {
			t.Errorf("[%s] Channel length mismatch: len(conns)=%d != healthy(%d) + broken(%d)",
				stage, pool.GetChannelLen(), h, b)
		}
	}

	checkInvariant("init")

	// Acquire 2
	u1, _ := pool.Acquire(ctx)
	u2, _ := pool.Acquire(ctx)
	checkInvariant("after acquire 2")

	// Acquire remaining 2
	u3, _ := pool.Acquire(ctx)
	u4, _ := pool.Acquire(ctx)
	checkInvariant("after acquire all")

	// Release 1 normally (undergoes cleaning)
	pool.Release(u1)
	// Even during cleaning, invariant holds (active - 1, cleaning + 1)
	checkInvariant("immediately after release u1")

	for start := time.Now(); time.Since(start) < 2*time.Second; time.Sleep(5 * time.Millisecond) {
		if pool.GetCleaningCount() == 0 {
			break
		}
	}
	checkInvariant("after u1 cleaning finished")

	// Mark u2 broken and release
	u2.Broken.Store(true)
	pool.Release(u2)
	checkInvariant("immediately after broken release u2")

	for start := time.Now(); time.Since(start) < 2*time.Second; time.Sleep(5 * time.Millisecond) {
		if pool.GetRedialingCount() == 0 {
			break
		}
	}
	checkInvariant("after u2 background redial finished")

	// Release u3 and u4
	pool.Release(u3)
	pool.Release(u4)
	for start := time.Now(); time.Since(start) < 2*time.Second; time.Sleep(5 * time.Millisecond) {
		if pool.GetCleaningCount() == 0 {
			break
		}
	}
	checkInvariant("all released")

	if pool.GetIdleCount() != poolSize {
		t.Errorf("Expected full healthy idle count %d, got %d", poolSize, pool.GetIdleCount())
	}
}
