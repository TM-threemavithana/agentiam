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
	dto "github.com/prometheus/client_model/go"
)

func getGaugeValue(g interface{ Write(*dto.Metric) error }) float64 {
	var m dto.Metric
	if err := g.Write(&m); err != nil {
		return 0
	}
	if m.Gauge != nil {
		return m.Gauge.GetValue()
	}
	return 0
}

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
			session.releaseUpstream(u)
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
		if idleGauge := getGaugeValue(PoolIdleConnections); idleGauge != float64(poolSize) {
			t.Fatalf("iter %d: expected idle gauge %d, got %v", i, poolSize, idleGauge)
		}
		if totalGauge := getGaugeValue(PoolTotalConnections); totalGauge != float64(poolSize) {
			t.Fatalf("iter %d: expected total gauge %d, got %v", i, poolSize, totalGauge)
		}
	}

	// Final verification of pool channel capacity and Prometheus gauge metrics
	if len(pool.conns) != poolSize {
		t.Fatalf("expected pool.conns channel len %d, got %d", poolSize, len(pool.conns))
	}
	if idleGauge := getGaugeValue(PoolIdleConnections); idleGauge != float64(poolSize) {
		t.Fatalf("final: expected idle gauge %d, got %v", poolSize, idleGauge)
	}
	if totalGauge := getGaugeValue(PoolTotalConnections); totalGauge != float64(poolSize) {
		t.Fatalf("final: expected total gauge %d, got %v", poolSize, totalGauge)
	}
}

// TestCancelQuery_CancelU1_AcquireU2_DeliverR1EOF verifies that when u1 is canceled, u2 is acquired,
// and then the stale reader R1 receives EOF from u1, R1 does NOT release or corrupt u2.
func TestCancelQuery_CancelU1_AcquireU2_DeliverR1EOF(t *testing.T) {
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

	// 1. Session owns upstream connection u1
	u1, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("failed to acquire u1: %v", err)
	}
	session.uconnMu.Lock()
	session.uconn = u1
	session.uconnMu.Unlock()

	r1Reading := make(chan struct{})
	r1CanHandleEOF := make(chan struct{})
	r1Finished := make(chan struct{})

	// 2. Reader goroutine R1 is blocked reading from u1
	go func() {
		close(r1Reading)
		_, err := u1.Frontend.Receive()
		if err != nil {
			// Deterministic barrier: wait until u2 has been acquired and assigned
			<-r1CanHandleEOF
			u1.Broken.Store(true)
			// R1 attempts cleanup with its connection identity u1
			session.releaseUpstream(u1)
			close(r1Finished)
			return
		}
	}()

	<-r1Reading

	// 3. CancelQuery detaches and releases u1
	session.CancelQuery()

	// Verify u1 was cleanly detached
	session.uconnMu.Lock()
	if session.uconn != nil {
		session.uconnMu.Unlock()
		t.Fatalf("expected s.uconn to be nil after CancelQuery")
	}
	session.uconnMu.Unlock()

	// 4. A subsequent connection u2 is acquired from the pool
	u2, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("failed to acquire u2: %v", err)
	}
	if !u2.InUse.Load() {
		t.Fatalf("expected u2.InUse to be true")
	}

	// 5. Session assigns s.uconn = u2
	session.uconnMu.Lock()
	session.uconn = u2
	session.uconnMu.Unlock()

	// 6. R1 handles EOF from u1's closed socket and runs releaseUpstream(u1)
	close(r1CanHandleEOF)
	<-r1Finished

	// 7. Verify u2 ownership was NOT hijacked by R1
	if !u2.InUse.Load() {
		t.Fatalf("STALE-READER REGRESSION: u2.InUse was set to false by R1!")
	}
	session.uconnMu.Lock()
	currentUconn := session.uconn
	session.uconnMu.Unlock()
	if currentUconn != u2 {
		t.Fatalf("STALE-READER REGRESSION: session.uconn was detached or modified by R1!")
	}

	// Verify query on u2 executes successfully
	if err := u2.SendAndFlush(&pgproto3.Query{String: "SELECT 1;"}); err != nil {
		t.Fatalf("query on u2 failed: %v", err)
	}
	msg, err := u2.Frontend.Receive()
	if err != nil {
		t.Fatalf("receive on u2 failed: %v", err)
	}
	if _, ok := msg.(*pgproto3.RowDescription); !ok {
		t.Fatalf("expected RowDescription on u2, got %T", msg)
	}

	// 8. Normal release of u2 by its proper owner
	session.releaseUpstream(u2)
	if u2.InUse.Load() {
		t.Fatalf("expected u2.InUse to be false after proper release")
	}
	if u2.Broken.Load() {
		t.Fatalf("u2 was unexpectedly marked broken")
	}
}

// TestCancelQuery_SecondQueryQueued_ReacquisitionPrevented verifies that once a session
// has been canceled, subsequent/queued queries cannot unsafely reacquire pooled connections.
func TestCancelQuery_SecondQueryQueued_ReacquisitionPrevented(t *testing.T) {
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

	// Session acquires initial connection u1
	u1, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("failed to acquire u1: %v", err)
	}
	session.uconnMu.Lock()
	session.uconn = u1
	session.uconnMu.Unlock()

	// Cancel the query
	session.CancelQuery()

	// Verify canceled flag is set
	if !session.canceled.Load() {
		t.Fatalf("expected session.canceled to be true")
	}

	// Attempt to acquire an upstream connection for a second/queued query
	writeCh := make(chan pgproto3.BackendMessage, 10)
	u2, err := session.getOrAcquireUpstream(ctx, writeCh)
	if err == nil {
		session.releaseUpstream(u2)
		t.Fatalf("expected getOrAcquireUpstream to reject reacquisition after cancellation, got success: %v", u2)
	}

	// Verify s.uconn remains nil
	session.uconnMu.Lock()
	uconn := session.uconn
	session.uconnMu.Unlock()
	if uconn != nil {
		t.Fatalf("expected s.uconn to remain nil, got %v", uconn)
	}
}

// TestCancelQuery_OldReaderRacingWithNewReader verifies that when an old reader cleans up
// concurrently with a new reader's query execution, no data races, deadlocks, or state corruption occur.
func TestCancelQuery_OldReaderRacingWithNewReader(t *testing.T) {
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
	defer pool.Close()

	server := &Server{
		pool:   pool,
		logger: logger,
	}

	for iter := 0; iter < 20; iter++ {
		c1, c2 := net.Pipe()
		session1 := &Session{
			server:      server,
			clientConn:  c1,
			logger:      logger,
			sessionVars: make(map[string]string),
		}

		u1, err := pool.Acquire(ctx)
		if err != nil {
			t.Fatalf("iter %d: acquire u1: %v", iter, err)
		}
		session1.uconnMu.Lock()
		session1.uconn = u1
		session1.uconnMu.Unlock()

		// Cancel session1
		session1.CancelQuery()

		// Session2 acquires u2
		c3, c4 := net.Pipe()
		session2 := &Session{
			server:      server,
			clientConn:  c3,
			logger:      logger,
			sessionVars: make(map[string]string),
		}
		u2, err := pool.Acquire(ctx)
		if err != nil {
			t.Fatalf("iter %d: acquire u2: %v", iter, err)
		}
		session2.uconnMu.Lock()
		session2.uconn = u2
		session2.uconnMu.Unlock()

		var wg sync.WaitGroup
		wg.Add(2)

		// Goroutine 1: Old reader R1 cleanup racing
		go func() {
			defer wg.Done()
			u1.Broken.Store(true)
			session1.releaseUpstream(u1)
		}()

		// Goroutine 2: New reader activity on u2
		go func() {
			defer wg.Done()
			_ = u2.SendAndFlush(&pgproto3.Query{String: "SELECT 1;"})
			msg, err := u2.Frontend.Receive()
			if err == nil && msg != nil {
				// Read until ReadyForQuery
				for {
					m, err := u2.Frontend.Receive()
					if err != nil {
						break
					}
					if _, ok := m.(*pgproto3.ReadyForQuery); ok {
						break
					}
				}
			}
			session2.releaseUpstream(u2)
		}()

		wg.Wait()
		c2.Close()
		c4.Close()
	}
}

// TestCancelQuery_SubsequentHealthySessionExecutesQueries verifies that after multiple
// cancellations and recoveries, a new session successfully acquires connections and executes queries.
func TestCancelQuery_SubsequentHealthySessionExecutesQueries(t *testing.T) {
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

	// Perform 3 cancel cycles
	for i := 0; i < 3; i++ {
		c1, c2 := net.Pipe()
		s := &Session{
			server:      server,
			clientConn:  c1,
			logger:      logger,
			sessionVars: make(map[string]string),
		}
		u, err := pool.Acquire(ctx)
		if err != nil {
			t.Fatalf("cancel iter %d: acquire: %v", i, err)
		}
		s.uconnMu.Lock()
		s.uconn = u
		s.uconnMu.Unlock()
		s.CancelQuery()
		c2.Close()
	}

	// Wait for pool replacement connections to settle
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if len(pool.conns) == poolSize {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	// New healthy session
	cClient, cProxy := net.Pipe()
	defer cClient.Close()
	defer cProxy.Close()

	healthySession := &Session{
		server:        server,
		clientConn:    cProxy,
		clientBackend: pgproto3.NewBackend(cProxy, cProxy),
		logger:        logger,
		sessionVars:   make(map[string]string),
	}

	writeCh := make(chan pgproto3.BackendMessage, 10)
	u, err := healthySession.getOrAcquireUpstream(ctx, writeCh)
	if err != nil {
		t.Fatalf("failed to acquire upstream for healthy session: %v", err)
	}
	defer healthySession.releaseUpstream(u)

	if u.Broken.Load() {
		t.Fatalf("acquired connection is marked broken")
	}

	// Execute a real query
	if err := u.SendAndFlush(&pgproto3.Query{String: "SELECT 42;"}); err != nil {
		t.Fatalf("query failed on healthy session: %v", err)
	}
	select {
	case msg := <-writeCh:
		if _, ok := msg.(*pgproto3.RowDescription); !ok {
			t.Fatalf("expected RowDescription on writeCh, got %T", msg)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timeout waiting for query response on writeCh")
	}

	// Verify Prometheus metrics directly
	if total := getGaugeValue(PoolTotalConnections); total != float64(poolSize) {
		t.Fatalf("expected PoolTotalConnections to be %d, got %v", poolSize, total)
	}
}
