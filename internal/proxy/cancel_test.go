package proxy

import (
	"context"
	"io"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"
)

// mockUpstreamWithDialCount starts a mock PostgreSQL server that counts connection handshakes.
func mockUpstreamWithDialCount(t *testing.T, listenAddr string, dialCount *atomic.Int64) net.Listener {
	l, err := net.Listen("tcp", listenAddr)
	if err != nil {
		t.Fatalf("failed to start mock upstream on %s: %v", listenAddr, err)
	}
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			if dialCount != nil {
				dialCount.Add(1)
			}
			go func(c net.Conn) {
				backend := pgproto3.NewBackend(c, c)
				// Handshake
				_, _ = backend.ReceiveStartupMessage()
				backend.Send(&pgproto3.AuthenticationOk{})
				backend.Send(&pgproto3.ParameterStatus{Name: "server_version", Value: "15.0"})
				backend.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
				_ = backend.Flush()

				for {
					msg, err := backend.Receive()
					if err != nil {
						c.Close()
						return
					}
					switch m := msg.(type) {
					case *pgproto3.Query:
						if strings.HasPrefix(m.String, "SET") || m.String == "DISCARD ALL" {
							backend.Send(&pgproto3.CommandComplete{CommandTag: []byte("OK")})
							backend.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
							_ = backend.Flush()
						} else {
							backend.Send(&pgproto3.RowDescription{
								Fields: []pgproto3.FieldDescription{
									{Name: []byte("val"), DataTypeOID: 23, DataTypeSize: 4},
								},
							})
							backend.Send(&pgproto3.DataRow{Values: [][]byte{[]byte("100")}})
							backend.Send(&pgproto3.CommandComplete{CommandTag: []byte("SELECT 1")})
							backend.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
							_ = backend.Flush()
						}
					case *pgproto3.Terminate:
						c.Close()
						return
					}
				}
			}(conn)
		}
	}()
	return l
}

// TestCancelQuery_SingleReplacement verifies that a query cancellation detaches the connection,
// marks it broken, and triggers EXACTLY ONE replacement dial, preserving pool capacity.
func TestCancelQuery_SingleReplacement(t *testing.T) {
	var dialCount atomic.Int64
	l := mockUpstreamWithDialCount(t, "127.0.0.1:0", &dialCount)
	defer l.Close()

	dsn := "postgres://user:pass@" + l.Addr().String() + "/db?sslmode=disable"
	logger := NewLogger(io.Discard)
	poolSize := 3
	pool := NewPool(dsn, poolSize, logger)
	ctx := context.Background()

	if err := pool.Init(ctx); err != nil {
		t.Fatalf("failed to init pool: %v", err)
	}
	defer pool.Close()

	if initialDials := dialCount.Load(); initialDials != int64(poolSize) {
		t.Fatalf("expected %d initial dials, got %d", poolSize, initialDials)
	}

	server := &Server{
		pool:   pool,
		logger: logger,
	}
	c1, c2 := net.Pipe()
	defer c2.Close()
	session := &Session{
		server:      server,
		clientConn:  c1,
		logger:      logger,
		sessionVars: make(map[string]string),
	}

	// 1. Acquire connection for session
	u, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("failed to acquire connection: %v", err)
	}
	session.uconnMu.Lock()
	session.uconn = u
	session.uconnMu.Unlock()

	// Verify session holds connection and pool idle count is decremented
	if pool.GetActiveCount() != 1 {
		t.Fatalf("expected active count 1, got %d", pool.GetActiveCount())
	}

	// 2. Trigger cancellation
	session.CancelQuery()

	// Verify session immediately detached uconn
	session.uconnMu.Lock()
	detached := session.uconn
	session.uconnMu.Unlock()
	if detached != nil {
		t.Fatalf("CancelQuery() failed to detach s.uconn; got non-nil: %v", detached)
	}
	if !u.Broken.Load() {
		t.Fatalf("CancelQuery() failed to mark connection broken")
	}

	// 3. Wait for the background replacement dial to complete
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if dialCount.Load() == int64(poolSize+1) && len(pool.conns) == poolSize {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Verify exactly 1 replacement was dialed
	totalDials := dialCount.Load()
	if totalDials != int64(poolSize+1) {
		t.Fatalf("expected exactly %d total dials (1 replacement), got %d", poolSize+1, totalDials)
	}

	// Verify pool capacity and idle connections are restored
	if len(pool.conns) != poolSize {
		t.Fatalf("expected pool.conns channel len %d, got %d", poolSize, len(pool.conns))
	}
	if pool.GetActiveCount() != 0 {
		t.Fatalf("expected 0 active connections after replacement, got %d", pool.GetActiveCount())
	}
}

// TestCancelQuery_IdempotentRepeated verifies that calling CancelQuery multiple times
// in succession or concurrently is completely idempotent and triggers at most 1 replacement.
func TestCancelQuery_IdempotentRepeated(t *testing.T) {
	var dialCount atomic.Int64
	l := mockUpstreamWithDialCount(t, "127.0.0.1:0", &dialCount)
	defer l.Close()

	dsn := "postgres://user:pass@" + l.Addr().String() + "/db?sslmode=disable"
	logger := NewLogger(io.Discard)
	poolSize := 2
	pool := NewPool(dsn, poolSize, logger)
	ctx := context.Background()

	if err := pool.Init(ctx); err != nil {
		t.Fatalf("failed to init pool: %v", err)
	}
	defer pool.Close()

	server := &Server{
		pool:   pool,
		logger: logger,
	}
	c1, c2 := net.Pipe()
	defer c2.Close()
	session := &Session{
		server:      server,
		clientConn:  c1,
		logger:      logger,
		sessionVars: make(map[string]string),
	}

	u, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("failed to acquire connection: %v", err)
	}
	session.uconnMu.Lock()
	session.uconn = u
	session.uconnMu.Unlock()

	// Call CancelQuery 20 times concurrently
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			session.CancelQuery()
		}()
	}
	wg.Wait()

	// Wait for replacement dial
	time.Sleep(100 * time.Millisecond)

	// Exactly 1 replacement dial should occur
	expectedDials := int64(poolSize + 1)
	if actualDials := dialCount.Load(); actualDials != expectedDials {
		t.Fatalf("expected %d total dials, got %d (duplicate replacement occurred!)", expectedDials, actualDials)
	}
	if len(pool.conns) != poolSize {
		t.Fatalf("expected channel len %d, got %d", poolSize, len(pool.conns))
	}
}

// TestCancelQuery_ConcurrentWithUpstreamEOF verifies that when CancelQuery closes the upstream
// socket, the concurrent upstream reader goroutine encountering EOF/error and calling
// releaseUpstream() or Close() does NOT cause a double release or duplicate replacement.
func TestCancelQuery_ConcurrentWithUpstreamEOF(t *testing.T) {
	var dialCount atomic.Int64
	l := mockUpstreamWithDialCount(t, "127.0.0.1:0", &dialCount)
	defer l.Close()

	dsn := "postgres://user:pass@" + l.Addr().String() + "/db?sslmode=disable"
	logger := NewLogger(io.Discard)
	poolSize := 2
	pool := NewPool(dsn, poolSize, logger)
	ctx := context.Background()

	if err := pool.Init(ctx); err != nil {
		t.Fatalf("failed to init pool: %v", err)
	}
	defer pool.Close()

	server := &Server{
		pool:   pool,
		logger: logger,
	}

	for iter := 0; iter < 10; iter++ {
		c1, c2 := net.Pipe()
		session := &Session{
			server:      server,
			clientConn:  c1,
			logger:      logger,
			sessionVars: make(map[string]string),
		}

		u, err := pool.Acquire(ctx)
		if err != nil {
			t.Fatalf("iter %d: failed to acquire connection: %v", iter, err)
		}
		session.uconnMu.Lock()
		session.uconn = u
		session.uconnMu.Unlock()

		dialsBefore := dialCount.Load()

		// Race CancelQuery against reader error cleanup and Session.Close()
		var raceWg sync.WaitGroup
		raceWg.Add(3)

		go func() {
			defer raceWg.Done()
			session.CancelQuery()
		}()

		go func() {
			defer raceWg.Done()
			// Simulate reader goroutine encountering read error: marks broken and calls releaseUpstream
			u.Broken.Store(true)
			session.releaseUpstream()
		}()

		go func() {
			defer raceWg.Done()
			// Simulate session termination
			session.Close()
		}()

		raceWg.Wait()
		c2.Close()

		// Wait for replacement dial
		deadline := time.Now().Add(1 * time.Second)
		for time.Now().Before(deadline) {
			if dialCount.Load() == dialsBefore+1 && len(pool.conns) == poolSize {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}

		dialsAfter := dialCount.Load()
		if dialsAfter != dialsBefore+1 {
			t.Fatalf("iter %d: expected 1 replacement dial (total %d), got %d",
				iter, dialsBefore+1, dialsAfter)
		}
		if len(pool.conns) != poolSize {
			t.Fatalf("iter %d: channel len corrupted: expected %d, got %d",
				iter, poolSize, len(pool.conns))
		}
	}
}

// TestCancelQuery_ConcurrentWithSessionClose verifies that CancelQuery and Session.Close
// racing against each other cannot double-release the upstream connection.
func TestCancelQuery_ConcurrentWithSessionClose(t *testing.T) {
	var dialCount atomic.Int64
	l := mockUpstreamWithDialCount(t, "127.0.0.1:0", &dialCount)
	defer l.Close()

	dsn := "postgres://user:pass@" + l.Addr().String() + "/db?sslmode=disable"
	logger := NewLogger(io.Discard)
	pool := NewPool(dsn, 2, logger)
	ctx := context.Background()

	if err := pool.Init(ctx); err != nil {
		t.Fatalf("failed to init pool: %v", err)
	}
	defer pool.Close()

	server := &Server{
		pool:   pool,
		logger: logger,
	}
	c1, c2 := net.Pipe()
	defer c2.Close()
	session := &Session{
		server:      server,
		clientConn:  c1,
		logger:      logger,
		sessionVars: make(map[string]string),
	}

	u, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("failed to acquire connection: %v", err)
	}
	session.uconnMu.Lock()
	session.uconn = u
	session.uconnMu.Unlock()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		session.CancelQuery()
	}()
	go func() {
		defer wg.Done()
		session.Close()
	}()
	wg.Wait()

	time.Sleep(100 * time.Millisecond)

	// Exactly 1 replacement dial (initial 2 + 1 replacement = 3)
	if totalDials := dialCount.Load(); totalDials != 3 {
		t.Fatalf("expected 3 total dials, got %d", totalDials)
	}
	if len(pool.conns) != 2 {
		t.Fatalf("expected 2 idle connections, got %d", len(pool.conns))
	}
}

// TestCancelQuery_ConcurrentWithPoolClose verifies that cancelling queries while Pool.Close()
// is executing does not cause goroutine leaks, channel write panics, or deadlocks.
func TestCancelQuery_ConcurrentWithPoolClose(t *testing.T) {
	var dialCount atomic.Int64
	l := mockUpstreamWithDialCount(t, "127.0.0.1:0", &dialCount)
	defer l.Close()

	dsn := "postgres://user:pass@" + l.Addr().String() + "/db?sslmode=disable"
	logger := NewLogger(io.Discard)
	poolSize := 5
	pool := NewPool(dsn, poolSize, logger)
	ctx := context.Background()

	if err := pool.Init(ctx); err != nil {
		t.Fatalf("failed to init pool: %v", err)
	}

	server := &Server{
		pool:   pool,
		logger: logger,
	}

	sessions := make([]*Session, poolSize)
	for i := 0; i < poolSize; i++ {
		c1, c2 := net.Pipe()
		defer c2.Close()
		s := &Session{
			server:      server,
			clientConn:  c1,
			logger:      logger,
			sessionVars: make(map[string]string),
		}
		u, err := pool.Acquire(ctx)
		if err != nil {
			t.Fatalf("failed to acquire conn %d: %v", i, err)
		}
		s.uconnMu.Lock()
		s.uconn = u
		s.uconnMu.Unlock()
		sessions[i] = s
	}

	// Concurrently cancel all queries while closing the pool
	var wg sync.WaitGroup
	for _, s := range sessions {
		wg.Add(1)
		go func(sess *Session) {
			defer wg.Done()
			sess.CancelQuery()
		}(s)
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		pool.Close()
	}()

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		// Success
	case <-time.After(3 * time.Second):
		t.Fatalf("deadlock during concurrent CancelQuery and Pool.Close")
	}

	// Verify post-close Acquire fails promptly
	_, err := pool.Acquire(ctx)
	if err == nil {
		t.Fatalf("expected error acquiring from closed pool, got nil")
	}
}

// TestCancelQuery_SubsequentQueryUsesHealthyConnection verifies that after query cancellation,
// the pool replaces the canceled connection with a healthy one, and subsequent queries succeed.
func TestCancelQuery_SubsequentQueryUsesHealthyConnection(t *testing.T) {
	var dialCount atomic.Int64
	l := mockUpstreamWithDialCount(t, "127.0.0.1:0", &dialCount)
	defer l.Close()

	dsn := "postgres://user:pass@" + l.Addr().String() + "/db?sslmode=disable"
	logger := NewLogger(io.Discard)
	pool := NewPool(dsn, 2, logger)
	ctx := context.Background()

	if err := pool.Init(ctx); err != nil {
		t.Fatalf("failed to init pool: %v", err)
	}
	defer pool.Close()

	server := &Server{
		pool:   pool,
		logger: logger,
	}
	c1, c2 := net.Pipe()
	defer c2.Close()
	session := &Session{
		server:      server,
		clientConn:  c1,
		logger:      logger,
		sessionVars: make(map[string]string),
	}

	// Acquire and cancel
	u1, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("failed to acquire: %v", err)
	}
	session.uconnMu.Lock()
	session.uconn = u1
	session.uconnMu.Unlock()

	session.CancelQuery()

	// Wait for replacement to land in pool
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(pool.conns) == 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	// Acquire a connection for a new query
	u2, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("failed to acquire connection after replacement: %v", err)
	}
	defer pool.Release(u2)

	// Verify u2 is healthy and distinct from u1
	if u2 == u1 {
		t.Fatalf("pool re-issued the canceled connection u1!")
	}
	if u2.Broken.Load() {
		t.Fatalf("pool re-issued a broken connection!")
	}

	// Send a test query to verify wire communication is functional
	if err := u2.SendAndFlush(&pgproto3.Query{String: "SELECT 1;"}); err != nil {
		t.Fatalf("failed to send query on replaced connection: %v", err)
	}
	msg, err := u2.Frontend.Receive()
	if err != nil {
		t.Fatalf("failed to receive response on replaced connection: %v", err)
	}
	if _, ok := msg.(*pgproto3.RowDescription); !ok {
		t.Fatalf("expected RowDescription, got %T", msg)
	}
}

// TestCancelQuery_CanceledConnectionNeverReturnedAsHealthy verifies that when a connection
// is canceled, it is marked Broken and never recycled back into the pool as healthy.
func TestCancelQuery_CanceledConnectionNeverReturnedAsHealthy(t *testing.T) {
	var dialCount atomic.Int64
	l := mockUpstreamWithDialCount(t, "127.0.0.1:0", &dialCount)
	defer l.Close()

	dsn := "postgres://user:pass@" + l.Addr().String() + "/db?sslmode=disable"
	logger := NewLogger(io.Discard)
	poolSize := 3
	pool := NewPool(dsn, poolSize, logger)
	ctx := context.Background()

	if err := pool.Init(ctx); err != nil {
		t.Fatalf("failed to init pool: %v", err)
	}
	defer pool.Close()

	server := &Server{
		pool:   pool,
		logger: logger,
	}

	c1, c2 := net.Pipe()
	defer c2.Close()
	session := &Session{
		server:      server,
		clientConn:  c1,
		logger:      logger,
		sessionVars: make(map[string]string),
	}

	uCanceled, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("failed to acquire: %v", err)
	}
	session.uconnMu.Lock()
	session.uconn = uCanceled
	session.uconnMu.Unlock()

	session.CancelQuery()

	// Wait for pool replenishment
	time.Sleep(150 * time.Millisecond)

	// Drain all connections from pool and inspect them
	checkedOut := make([]*UpstreamConn, poolSize)
	for i := 0; i < poolSize; i++ {
		c, err := pool.Acquire(ctx)
		if err != nil {
			t.Fatalf("failed to acquire connection %d: %v", i, err)
		}
		checkedOut[i] = c
	}

	for i, c := range checkedOut {
		defer pool.Release(c)
		if c == uCanceled {
			t.Fatalf("connection %d is identical to canceled connection! Recycled broken connection!", i)
		}
		if c.Broken.Load() {
			t.Fatalf("connection %d in pool is marked broken!", i)
		}
	}
}

// TestCancelQuery_DialFailureGraceful verifies that if the upstream database is down
// when a canceled connection is being replaced, the replacement failure is handled
// gracefully without crashing, and subsequent dial succeeds once upstream recovers.
func TestCancelQuery_DialFailureGraceful(t *testing.T) {
	var dialCount atomic.Int64
	l := mockUpstreamWithDialCount(t, "127.0.0.1:0", &dialCount)
	listenAddr := l.Addr().String()

	dsn := "postgres://user:pass@" + listenAddr + "/db?sslmode=disable"
	logger := NewLogger(io.Discard)
	pool := NewPool(dsn, 2, logger)
	ctx := context.Background()

	if err := pool.Init(ctx); err != nil {
		t.Fatalf("failed to init pool: %v", err)
	}
	defer pool.Close()

	server := &Server{
		pool:   pool,
		logger: logger,
	}

	c1, c2 := net.Pipe()
	defer c2.Close()
	session := &Session{
		server:      server,
		clientConn:  c1,
		logger:      logger,
		sessionVars: make(map[string]string),
	}

	u, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("failed to acquire: %v", err)
	}
	session.uconnMu.Lock()
	session.uconn = u
	session.uconnMu.Unlock()

	// Shut down upstream so background redial in discardAndReplace FAILS
	l.Close()

	session.CancelQuery()

	// Wait for the background dial to attempt and fail, placing the broken placeholder into the pool channel
	deadline := time.Now().Add(2 * time.Second)
	for len(pool.conns) < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}

	// Restart upstream server on the exact same address
	l2 := mockUpstreamWithDialCount(t, listenAddr, &dialCount)
	defer l2.Close()

	// Acquire again: the pool should pop the broken placeholder, discard it, and synchronously re-dial
	uRecovered, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("expected Acquire to synchronously re-dial and recover, got: %v", err)
	}
	defer pool.Release(uRecovered)

	if uRecovered.Broken.Load() || uRecovered.Conn == nil {
		t.Fatalf("recovered connection is invalid or broken")
	}
}

// TestPoolMetrics_AccurateAfterCancellation verifies that PoolTotalConnections and
// PoolIdleConnections metrics remain completely consistent after multiple cancellations.
func TestPoolMetrics_AccurateAfterCancellation(t *testing.T) {
	var dialCount atomic.Int64
	l := mockUpstreamWithDialCount(t, "127.0.0.1:0", &dialCount)
	defer l.Close()

	dsn := "postgres://user:pass@" + l.Addr().String() + "/db?sslmode=disable"
	logger := NewLogger(io.Discard)
	poolSize := 3
	pool := NewPool(dsn, poolSize, logger)
	ctx := context.Background()

	if err := pool.Init(ctx); err != nil {
		t.Fatalf("failed to init pool: %v", err)
	}
	defer pool.Close()

	server := &Server{
		pool:   pool,
		logger: logger,
	}

	for i := 0; i < 5; i++ {
		c1, c2 := net.Pipe()
		session := &Session{
			server:      server,
			clientConn:  c1,
			logger:      logger,
			sessionVars: make(map[string]string),
		}

		u, err := pool.Acquire(ctx)
		if err != nil {
			t.Fatalf("iter %d: failed to acquire: %v", i, err)
		}
		session.uconnMu.Lock()
		session.uconn = u
		session.uconnMu.Unlock()

		session.CancelQuery()
		c2.Close()

		// Wait for replacement
		deadline := time.Now().Add(1 * time.Second)
		for time.Now().Before(deadline) {
			if len(pool.conns) == poolSize {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}

		if active := pool.GetActiveCount(); active != 0 {
			t.Fatalf("iter %d: expected 0 active connections, got %d", i, active)
		}
	}

	// Final verification of pool channel capacity
	if len(pool.conns) != poolSize {
		t.Fatalf("expected pool.conns channel len %d, got %d", poolSize, len(pool.conns))
	}
}
