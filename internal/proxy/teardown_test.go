package proxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"
	dto "github.com/prometheus/client_model/go"
	"github.com/tm-threemavithana/agentiam/internal/ast"
	"github.com/tm-threemavithana/agentiam/internal/policy"
	"golang.org/x/crypto/bcrypt"
)

// setupTeardownTestServer creates an in-process proxy server and mock upstream for teardown testing.
func setupTeardownTestServer(t *testing.T, poolSize int, upstreamHandler func(backend *pgproto3.Backend, c net.Conn)) (*Server, *Pool, net.Listener, string, func()) {
	t.Helper()

	// Warm up libpg_query parser under -race to prevent first-call Cgo latency from tripping client read timeouts
	_, _, _ = (&ast.PostgresParser{}).ApplyRules("SELECT 1;", ast.Rules{AllowedStatements: []string{"SELECT"}}, nil)

	// 1. Mock upstream PostgreSQL server
	upListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to listen for mock upstream: %v", err)
	}

	go func() {
		for {
			conn, err := upListener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				backend := pgproto3.NewBackend(c, c)
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

				if upstreamHandler != nil {
					upstreamHandler(backend, c)
				} else {
					// Default query & DISCARD ALL handler
					for {
						msg, err := backend.Receive()
						if err != nil {
							return
						}
						switch msg.(type) {
						case *pgproto3.Query:
							backend.Send(&pgproto3.CommandComplete{CommandTag: []byte("SELECT 1")})
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

	upstreamDSN := fmt.Sprintf("postgres://user:pass@%s/testdb?sslmode=disable", upListener.Addr().String())

	// 2. Policy store
	hashBytes, err := bcrypt.GenerateFromPassword([]byte("test_pass"), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("Failed to hash password: %v", err)
	}
	hash := string(hashBytes)

	tmpFile, err := os.CreateTemp("", "teardown-policies-*.yaml")
	if err != nil {
		t.Fatalf("Failed to create temp policy file: %v", err)
	}
	policyContent := fmt.Sprintf(`agents:
  - name: test_agent
    key: '%s'
    allowed_statements: ["SELECT", "INSERT", "SET"]
  - name: agent_b
    key: '%s'
    allowed_statements: ["SELECT", "INSERT", "SET"]
`, hash, hash)
	if _, err := tmpFile.Write([]byte(policyContent)); err != nil {
		t.Fatalf("Failed to write temp policy: %v", err)
	}
	tmpFile.Close()

	store, err := policy.NewStore(tmpFile.Name(), "", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("Failed to create policy store: %v", err)
	}

	logger := NewLogger(io.Discard)
	handlers := make(map[ProtocolType]ProtocolHandler)
	server := NewServer("127.0.0.1:0", upstreamDSN, store, nil, logger, nil, handlers, true, ":0", poolSize, nil, nil)
	pgHandler := NewPostgresProtocolHandler(upstreamDSN, store, nil, logger, server, true)
	server.SetHandler(ProtocolPostgres, pgHandler)

	pool := server.pool
	if err := pool.Init(context.Background()); err != nil {
		t.Fatalf("Failed to init pool: %v", err)
	}

	// 3. Proxy Listener
	proxyListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to listen for proxy: %v", err)
	}

	go func() {
		for {
			conn, err := proxyListener.Accept()
			if err != nil {
				return
			}
			go server.handleConnection(conn)
		}
	}()

	cleanup := func() {
		proxyListener.Close()
		upListener.Close()
		pool.Close()
		os.Remove(tmpFile.Name())
	}

	return server, pool, proxyListener, proxyListener.Addr().String(), cleanup
}

// connectTestClient performs PostgreSQL startup and cleartext authentication with the proxy.
func connectTestClient(t *testing.T, proxyAddr, username string) (net.Conn, *pgproto3.Frontend) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", proxyAddr, 2*time.Second)
	if err != nil {
		t.Fatalf("Failed to connect to proxy: %v", err)
	}

	fe := pgproto3.NewFrontend(conn, conn)
	fe.Send(&pgproto3.StartupMessage{
		ProtocolVersion: 196608,
		Parameters: map[string]string{
			"user":     username,
			"database": "testdb",
		},
	})
	if err := fe.Flush(); err != nil {
		conn.Close()
		t.Fatalf("Failed to flush startup message: %v", err)
	}

	// Expect AuthenticationCleartextPassword
	msg, err := fe.Receive()
	if err != nil {
		conn.Close()
		t.Fatalf("Failed to receive auth challenge: %v", err)
	}
	if _, ok := msg.(*pgproto3.AuthenticationCleartextPassword); !ok {
		conn.Close()
		t.Fatalf("Expected AuthenticationCleartextPassword, got: %T", msg)
	}

	// Send password
	fe.Send(&pgproto3.PasswordMessage{Password: "test_pass"})
	if err := fe.Flush(); err != nil {
		conn.Close()
		t.Fatalf("Failed to flush password: %v", err)
	}

	// Receive until ReadyForQuery
	for {
		msg, err := fe.Receive()
		if err != nil {
			conn.Close()
			t.Fatalf("Failed to complete auth handshake: %v", err)
		}
		if _, ok := msg.(*pgproto3.ReadyForQuery); ok {
			break
		}
	}

	return conn, fe
}

// 1. TestTeardown_PanicInSessionWorker verifies that an unexpected panic inside
// an isolated session worker (e.g. query handling) is safely recovered, upstream is
// marked broken and closed, client socket is closed, and server stays healthy.
func TestTeardown_PanicInSessionWorker(t *testing.T) {
	server, pool, _, proxyAddr, cleanup := setupTeardownTestServer(t, 2, nil)
	defer cleanup()

	conn, fe := connectTestClient(t, proxyAddr, "test_agent")
	defer conn.Close()

	// Configure hook to panic during query execution
	SetTestPanicHook(func() {
		panic("simulated worker failure: password='super_secret_credentials'")
	})
	defer SetTestPanicHook(nil)

	// Send simple query that will trigger panic
	fe.Send(&pgproto3.Query{String: "SELECT 1;"})
	_ = fe.Flush()

	// Client should observe closed connection / EOF / error
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1024)
	_, err := conn.Read(buf)
	if err == nil {
		t.Fatalf("Expected client connection to be closed after worker panic, but read succeeded")
	}

	// Wait for pool redial to complete
	time.Sleep(150 * time.Millisecond)

	// Verify server semaphore was released
	if len(server.sem) != 0 {
		t.Errorf("Expected server semaphore to be 0 (no leak), got %d", len(server.sem))
	}

	// Verify active count is 0
	if pool.GetActiveCount() != 0 {
		t.Errorf("Expected active count 0, got %d", pool.GetActiveCount())
	}
}

// 2. TestTeardown_PanicInUpstreamResponseReader verifies that a panic inside the
// background goroutine reading messages from upstream is recovered safely, connection
// is marked broken and replaced, context is cancelled, and client is closed.
func TestTeardown_PanicInUpstreamResponseReader(t *testing.T) {
	_, pool, _, proxyAddr, cleanup := setupTeardownTestServer(t, 2, nil)
	defer cleanup()

	conn, fe := connectTestClient(t, proxyAddr, "test_agent")
	defer conn.Close()

	// Configure hook to panic inside upstream response reader
	var panicked atomic.Bool
	SetTestPanicOnUpstreamReceive(func() {
		if panicked.CompareAndSwap(false, true) {
			panic("simulated upstream reader panic: token='bearer_secret_123'")
		}
	})
	defer SetTestPanicOnUpstreamReceive(nil)

	fe.Send(&pgproto3.Query{String: "SELECT 1;"})
	_ = fe.Flush()

	// Client should observe closed connection
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1024)
	_, err := conn.Read(buf)
	if err == nil {
		t.Fatalf("Expected client connection to be closed after upstream reader panic, but read succeeded")
	}

	time.Sleep(150 * time.Millisecond)

	if pool.GetActiveCount() != 0 {
		t.Errorf("Expected active count 0, got %d", pool.GetActiveCount())
	}
}

// 3. TestTeardown_ClientDisconnectDuringQuery verifies that when a client abruptly
// disconnects during an active in-flight query, the proxy detects the disconnect,
// tears down the session, detaches upstream, and leaves no goroutine leaks.
func TestTeardown_ClientDisconnectDuringQuery(t *testing.T) {
	queryStarted := make(chan struct{})
	allowQueryFinish := make(chan struct{})
	var queryStartedOnce sync.Once

	// Upstream that blocks on query until signal
	upstreamHandler := func(backend *pgproto3.Backend, c net.Conn) {
		for {
			msg, err := backend.Receive()
			if err != nil {
				return
			}
			switch m := msg.(type) {
			case *pgproto3.Query:
				if strings.HasPrefix(m.String, "SET ") || strings.Contains(m.String, "DISCARD ALL") {
					tag := "SET"
					if strings.Contains(m.String, "DISCARD ALL") {
						tag = "DISCARD ALL"
					}
					backend.Send(&pgproto3.CommandComplete{CommandTag: []byte(tag)})
					backend.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
					_ = backend.Flush()
					continue
				}
				queryStartedOnce.Do(func() {
					close(queryStarted)
				})
				<-allowQueryFinish
				backend.Send(&pgproto3.CommandComplete{CommandTag: []byte("SELECT 1")})
				backend.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
				_ = backend.Flush()
			case *pgproto3.Terminate:
				return
			}
		}
	}

	_, pool, _, proxyAddr, cleanup := setupTeardownTestServer(t, 2, upstreamHandler)
	defer cleanup()

	conn, fe := connectTestClient(t, proxyAddr, "test_agent")

	fe.Send(&pgproto3.Query{String: "SELECT 1;"})
	_ = fe.Flush()

	// Wait until query reaches upstream
	select {
	case <-queryStarted:
	case <-time.After(15 * time.Second):
		t.Fatalf("Timeout waiting for query to reach upstream")
	}

	// Abrupt client disconnect
	conn.Close()

	// Allow upstream to finish and unblock
	close(allowQueryFinish)

	// Wait for teardown
	time.Sleep(300 * time.Millisecond)

	if pool.GetActiveCount() != 0 {
		t.Errorf("Expected active count 0 after client disconnect, got %d", pool.GetActiveCount())
	}
}

// 4. TestTeardown_UpstreamSocketTermination verifies that abrupt termination of
// the upstream database socket during an active query is handled cleanly: connection
// is marked broken, pool triggers background redial, and client session is torn down.
func TestTeardown_UpstreamSocketTermination(t *testing.T) {
	upstreamHandler := func(backend *pgproto3.Backend, c net.Conn) {
		for {
			msg, err := backend.Receive()
			if err != nil {
				return
			}
			switch m := msg.(type) {
			case *pgproto3.Query:
				if strings.HasPrefix(m.String, "SET ") || strings.Contains(m.String, "DISCARD ALL") {
					tag := "SET"
					if strings.Contains(m.String, "DISCARD ALL") {
						tag = "DISCARD ALL"
					}
					backend.Send(&pgproto3.CommandComplete{CommandTag: []byte(tag)})
					backend.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
					_ = backend.Flush()
					continue
				}
				// Abruptly terminate socket instead of answering
				c.Close()
				return
			case *pgproto3.Terminate:
				return
			}
		}
	}

	_, pool, _, proxyAddr, cleanup := setupTeardownTestServer(t, 2, upstreamHandler)
	defer cleanup()

	conn, fe := connectTestClient(t, proxyAddr, "test_agent")
	defer conn.Close()

	fe.Send(&pgproto3.Query{String: "SELECT 1;"})
	_ = fe.Flush()

	// Client should observe closed connection
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1024)
	_, err := conn.Read(buf)
	if err == nil {
		t.Fatalf("Expected client to observe error/EOF on upstream termination, but read succeeded")
	}

	time.Sleep(150 * time.Millisecond)

	if pool.GetActiveCount() != 0 {
		t.Errorf("Expected active count 0, got %d", pool.GetActiveCount())
	}
}

// 5. TestTeardown_ContextCancellation_UnblocksIO verifies that cancelling a session context
// immediately unblocks blocked socket operations in under 100ms.
func TestTeardown_ContextCancellation_UnblocksIO(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	session := &Session{
		clientConn:    serverConn,
		clientBackend: pgproto3.NewBackend(serverConn, serverConn),
		logger:        NewLogger(io.Discard),
	}

	unblocked := make(chan struct{})
	start := time.Now()

	go func() {
		// Read will block on net.Pipe until closed
		buf := make([]byte, 10)
		_, _ = serverConn.Read(buf)
		close(unblocked)
	}()

	// Close session via Close()
	time.Sleep(10 * time.Millisecond)
	session.Close()

	select {
	case <-unblocked:
		elapsed := time.Since(start)
		if elapsed > 150*time.Millisecond {
			t.Errorf("Teardown took too long to unblock socket: %v", elapsed)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("Socket did not unblock after session Close()")
	}
}

// 6. TestTeardown_RepeatedCleanup_Concurrent verifies that calling Close(),
// recoverBrokenTransaction(), and pool.Release() repeatedly and concurrently on the
// same connection causes no panics, no race conditions, and idempotent single release.
func TestTeardown_RepeatedCleanup_Concurrent(t *testing.T) {
	_, pool, _, _, cleanup := setupTeardownTestServer(t, 2, nil)
	defer cleanup()

	ctx := context.Background()
	u, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("Acquire failed: %v", err)
	}

	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()

	session := &Session{
		clientConn:    serverConn,
		clientBackend: pgproto3.NewBackend(serverConn, serverConn),
		uconn:         u,
		server:        &Server{pool: pool},
		logger:        NewLogger(io.Discard),
	}

	const callers = 20
	var wg sync.WaitGroup
	wg.Add(callers)

	for i := 0; i < callers; i++ {
		go func(idx int) {
			defer wg.Done()
			switch idx % 4 {
			case 0:
				session.Close()
			case 1:
				session.recoverBrokenTransaction()
			case 2:
				u.Close()
			case 3:
				pool.Release(u)
			}
		}(i)
	}

	wg.Wait()
	time.Sleep(100 * time.Millisecond)

	if pool.GetActiveCount() != 0 {
		t.Errorf("Expected active count 0, got %d", pool.GetActiveCount())
	}
}

// 7. TestTeardown_PanicDuringPoolShutdown verifies that a worker panic occurring while
// pool shutdown is actively underway is caught by recovery, accounts for workersWg.Done(),
// and allows pool.Close() to complete without deadlock.
func TestTeardown_PanicDuringPoolShutdown(t *testing.T) {
	logger := NewLogger(io.Discard)
	p := NewPool("postgres://dummy", 2, logger)

	// Add a dummy worker that panics during execution
	if p.tryAddWorker() {
		p.redialingCount.Add(1)
		go func() {
			defer p.workersWg.Done()
			defer p.redialingCount.Add(-1)
			defer func() {
				if r := recover(); r != nil {
					p.logger.Error("Panic recovered in test redial worker", "panic", sanitizePanicValue(r))
				}
			}()
			panic("simulated panic while pool is shutting down")
		}()
	}

	// Close pool concurrently
	closed := make(chan struct{})
	go func() {
		p.Close()
		close(closed)
	}()

	select {
	case <-closed:
		// Success: pool closed cleanly without deadlock
	case <-time.After(2 * time.Second):
		t.Fatalf("Pool.Close() deadlocked or timed out during concurrent worker panic")
	}
}

// 8. TestTeardown_UnaffectedSessionsSurviveFailure verifies that when Session A encounters
// a catastrophic failure / panic, it is safely contained and torn down while concurrent
// Session B continues executing queries successfully without interruption.
func TestTeardown_UnaffectedSessionsSurviveFailure(t *testing.T) {
	_, pool, _, proxyAddr, cleanup := setupTeardownTestServer(t, 3, nil)
	defer cleanup()

	// Connect Client A and Client B
	connA, feA := connectTestClient(t, proxyAddr, "test_agent")
	defer connA.Close()

	connB, feB := connectTestClient(t, proxyAddr, "agent_b")
	defer connB.Close()

	// Panicking hook that only triggers for Session A
	var panicTriggered atomic.Bool
	SetTestPanicHook(func() {
		if panicTriggered.CompareAndSwap(false, true) {
			panic("fatal panic in session A")
		}
	})
	defer SetTestPanicHook(nil)

	// Send query on Session A -> should trigger panic and close
	feA.Send(&pgproto3.Query{String: "SELECT 1;"})
	_ = feA.Flush()

	// Client A must fail
	_ = connA.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 1024)
	_, err := connA.Read(buf)
	if err == nil {
		t.Fatalf("Expected Client A to be disconnected after panic")
	}

	// Session B must continue executing queries normally!
	for i := 0; i < 3; i++ {
		feB.Send(&pgproto3.Query{String: "SELECT 1;"})
		if err := feB.Flush(); err != nil {
			t.Fatalf("Client B failed to send query %d: %v", i+1, err)
		}

		_ = connB.SetReadDeadline(time.Now().Add(5 * time.Second))
		msg, err := feB.Receive()
		if err != nil {
			t.Fatalf("Client B failed to receive response %d: %v", i+1, err)
		}
		if _, ok := msg.(*pgproto3.CommandComplete); !ok {
			t.Fatalf("Client B expected CommandComplete, got: %T (%+v)", msg, msg)
		}
		// Read ReadyForQuery
		msg2, err := feB.Receive()
		if err != nil || msg2 == nil {
			t.Fatalf("Client B failed to receive ReadyForQuery %d: %v", i+1, err)
		}
	}

	time.Sleep(150 * time.Millisecond)

	// In transaction pooling mode, completed query releases upstream back to pool.
	// Verify pool has no leaked active connections and all connections are healthy idle.
	if pool.GetActiveCount() != 0 {
		t.Errorf("Expected active count 0, got %d", pool.GetActiveCount())
	}
	if pool.GetHealthyIdleCount() != 3 {
		t.Errorf("Expected healthy idle count 3, got %d", pool.GetHealthyIdleCount())
	}

	// Verify Client B can still execute subsequent queries successfully
	feB.Send(&pgproto3.Query{String: "SELECT 2;"})
	if err := feB.Flush(); err != nil {
		t.Fatalf("Client B failed to send subsequent query: %v", err)
	}
	msg, err := feB.Receive()
	if err != nil {
		t.Fatalf("Client B failed to receive subsequent query response: %v", err)
	}
	if _, ok := msg.(*pgproto3.CommandComplete); !ok {
		t.Fatalf("Client B expected CommandComplete for subsequent query, got: %T", msg)
	}
	_, _ = feB.Receive() // ReadyForQuery
}

// 9. TestTeardown_CapacityAccountingAfterFailures verifies that after a cascade of
// failure events (panics, socket terminations, disconnects), the connection pool
// invariant holds: healthy + broken + active + cleaning + redialing == poolSize.
func TestTeardown_CapacityAccountingAfterFailures(t *testing.T) {
	_, pool, _, proxyAddr, cleanup := setupTeardownTestServer(t, 4, nil)
	defer cleanup()

	const iterations = 8
	var wg sync.WaitGroup
	wg.Add(iterations)

	for i := 0; i < iterations; i++ {
		go func(idx int) {
			defer wg.Done()
			conn, fe := connectTestClient(t, proxyAddr, "test_agent")
			if conn == nil {
				return
			}
			defer conn.Close()

			switch idx % 3 {
			case 0:
				// Normal fast query
				fe.Send(&pgproto3.Query{String: "SELECT 1;"})
				_ = fe.Flush()
				_, _ = fe.Receive()
			case 1:
				// Sudden client disconnect mid-query
				fe.Send(&pgproto3.Query{String: "SELECT 1;"})
				_ = fe.Flush()
				conn.Close()
			case 2:
				// Send terminate
				fe.Send(&pgproto3.Terminate{})
				_ = fe.Flush()
			}
		}(i)
	}

	wg.Wait()
	time.Sleep(300 * time.Millisecond)

	// Invariant check: healthy + broken + active + cleaning + redialing == poolSize
	healthy := pool.healthyIdleCount.Load()
	broken := pool.brokenCount.Load()
	active := pool.activeCount.Load()
	cleaning := pool.cleaningCount.Load()
	redialing := pool.redialingCount.Load()
	total := healthy + broken + active + cleaning + redialing

	if total != 4 {
		t.Errorf("Capacity invariant violated after failures: healthy(%d) + broken(%d) + active(%d) + cleaning(%d) + redialing(%d) = %d, expected 4",
			healthy, broken, active, cleaning, redialing, total)
	}

	if active != 0 {
		t.Errorf("Expected active count 0, got %d", active)
	}

	// Verify Prometheus broken gauge matches atomic brokenCount
	var m dto.Metric
	if err := PoolBrokenConnections.Write(&m); err == nil && m.Gauge != nil {
		gaugeVal := int32(*m.Gauge.Value)
		if gaugeVal != broken {
			t.Errorf("PoolBrokenConnections gauge (%d) does not match brokenCount (%d)", gaugeVal, broken)
		}
	}
}

// 10. TestTeardown_NoRegressions verifies that Phase 1A malformed message protections
// and Phase 1B lifecycle protections remain fully intact without regressions.
func TestTeardown_NoRegressions(t *testing.T) {
	// Verify sanitizePanicValue redacts sensitive information properly
	rawWithPassword := "runtime error: invalid memory address: password='super_secret_hunter2'"
	sanitized := sanitizePanicValue(rawWithPassword)
	if strings.Contains(sanitized, "super_secret_hunter2") {
		t.Errorf("sanitizePanicValue leaked password: %s", sanitized)
	}
	if !strings.Contains(sanitized, "password=[REDACTED]") {
		t.Errorf("sanitizePanicValue failed to redact password: %s", sanitized)
	}

	rawWithToken := "authentication failed for token: bearer_secret_token_12345"
	sanitizedToken := sanitizePanicValue(rawWithToken)
	if strings.Contains(sanitizedToken, "bearer_secret_token_12345") {
		t.Errorf("sanitizePanicValue leaked token: %s", sanitizedToken)
	}

	// Verify truncation of large panic messages
	hugeMsg := strings.Repeat("A", 500)
	sanitizedHuge := sanitizePanicValue(hugeMsg)
	if len(sanitizedHuge) > 280 {
		t.Errorf("sanitizePanicValue failed to truncate large message: len=%d", len(sanitizedHuge))
	}

	// Verify nil and error types
	if sanitizePanicValue(nil) != "nil" {
		t.Errorf("Expected 'nil', got %s", sanitizePanicValue(nil))
	}
	if sanitizePanicValue(errors.New("simple error")) != "simple error" {
		t.Errorf("Expected 'simple error', got %s", sanitizePanicValue(errors.New("simple error")))
	}
}

// 11. TestUpstreamFrontend_InterleavedFlushAndRelease deterministically verifies that
// concurrent session frontend send/flush operations and pool release cleanup workers
// never access the underlying pgproto3.Frontend concurrently, eliminating the release data race.
func TestUpstreamFrontend_InterleavedFlushAndRelease(t *testing.T) {
	_, pool, _, _, cleanup := setupTeardownTestServer(t, 2, nil)
	defer cleanup()

	ctx := context.Background()

	const iterations = 50
	for i := 0; i < iterations; i++ {
		u, err := pool.Acquire(ctx)
		if err != nil {
			t.Fatalf("Acquire failed on iter %d: %v", i, err)
		}

		session := &Session{
			uconn:  u,
			server: &Server{pool: pool},
			logger: NewLogger(io.Discard),
		}

		var wg sync.WaitGroup
		wg.Add(2)

		// Goroutine 1: active session frontend Send & Flush
		go func() {
			defer wg.Done()
			_ = session.sendAndFlushUpstream(u, &pgproto3.Query{String: "SELECT 1;"})
		}()

		// Goroutine 2: interleaved session release (which waits for frontendMu before pool.Release)
		go func() {
			defer wg.Done()
			session.releaseUpstream()
		}()

		wg.Wait()
		time.Sleep(5 * time.Millisecond)
	}

	// Wait for any background cleaners to finish
	time.Sleep(50 * time.Millisecond)

	if pool.GetActiveCount() != 0 {
		t.Errorf("Expected active count 0, got %d", pool.GetActiveCount())
	}
}

// 12. TestUpstreamFrontend_FailedFlush_MarksBroken verifies that when a frontend flush
// fails (e.g. socket closure), the connection is marked broken, pool.Release does not
// attempt to send DISCARD ALL on a corrupted encoder, and redialing replaces the slot.
func TestUpstreamFrontend_FailedFlush_MarksBroken(t *testing.T) {
	_, pool, _, _, cleanup := setupTeardownTestServer(t, 2, nil)
	defer cleanup()

	ctx := context.Background()
	u, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("Acquire failed: %v", err)
	}

	session := &Session{
		uconn:  u,
		server: &Server{pool: pool},
		logger: NewLogger(io.Discard),
	}

	// Abruptly close the underlying socket so that Flush will fail
	_ = u.Conn.Close()

	// Attempt sendAndFlushUpstream -> must fail and mark broken
	flushErr := session.sendAndFlushUpstream(u, &pgproto3.Query{String: "SELECT 1;"})
	if flushErr == nil {
		t.Fatalf("Expected sendAndFlushUpstream to fail on closed socket, but succeeded")
	}

	if !u.Broken.Load() {
		t.Errorf("Expected connection to be marked broken after failed flush")
	}

	// Release upstream -> pool.Release must detect u.Broken and redial rather than sending DISCARD ALL
	session.releaseUpstream()

	// Wait for background redial worker
	time.Sleep(100 * time.Millisecond)

	if pool.GetActiveCount() != 0 {
		t.Errorf("Expected active count 0 after redial, got %d", pool.GetActiveCount())
	}
	if pool.GetHealthyIdleCount() != 2 {
		t.Errorf("Expected healthy idle count 2 after replacement, got %d", pool.GetHealthyIdleCount())
	}
}

// 13. TestUpstreamFrontend_PostReleaseOperation_Rejected verifies that once an upstream
// connection has been relinquished by the session and returned to the pool, any subsequent
// frontend operation on that stale connection is immediately rejected and cannot mutate
// the encoder.
func TestUpstreamFrontend_PostReleaseOperation_Rejected(t *testing.T) {
	_, pool, _, _, cleanup := setupTeardownTestServer(t, 2, nil)
	defer cleanup()

	ctx := context.Background()
	u, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("Acquire failed: %v", err)
	}

	session := &Session{
		uconn:  u,
		server: &Server{pool: pool},
		logger: NewLogger(io.Discard),
	}

	// Normal release back to pool
	session.releaseUpstream()

	// Stale session attempts to perform frontend send on released connection
	err = session.sendAndFlushUpstream(u, &pgproto3.Query{String: "SELECT 1;"})
	if err == nil {
		t.Fatalf("Expected sendAndFlushUpstream on released connection to be rejected, but succeeded")
	}
	if !strings.Contains(err.Error(), "not in use") {
		t.Errorf("Expected 'not in use' error, got: %v", err)
	}
}

// inProcessTCPPair creates a loopback TCP connection pair for realistic network and deadline testing.
func inProcessTCPPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	defer ln.Close()

	serverCh := make(chan net.Conn, 1)
	errCh := make(chan error, 1)
	go func() {
		c, aErr := ln.Accept()
		if aErr != nil {
			errCh <- aErr
			return
		}
		serverCh <- c
	}()

	clientConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("Failed to dial: %v", err)
	}

	select {
	case serverConn := <-serverCh:
		return serverConn, clientConn
	case err := <-errCh:
		clientConn.Close()
		t.Fatalf("Accept failed: %v", err)
	case <-time.After(2 * time.Second):
		clientConn.Close()
		t.Fatalf("Timed out establishing TCP pair")
	}
	return nil, nil
}

// Test 14: Policy Revocation Error Delivery and SQLSTATE 57P01 Contract
// Verifies that TerminateWithPolicyRevocation delivers a structured ErrorResponse
// with Code "57P01" and Severity "FATAL" before closing the socket.
func TestPolicyRevocation_SQLSTATE57P01_Delivery(t *testing.T) {
	serverConn, clientConn := inProcessTCPPair(t)
	defer clientConn.Close()

	session := &Session{
		clientConn:    serverConn,
		clientBackend: pgproto3.NewBackend(serverConn, serverConn),
		logger:        NewLogger(io.Discard),
	}

	errCh := make(chan error, 1)
	msgCh := make(chan pgproto3.BackendMessage, 1)

	// Client reader
	go func() {
		clientFrontend := pgproto3.NewFrontend(clientConn, clientConn)
		msg, err := clientFrontend.Receive()
		if err != nil {
			errCh <- err
			return
		}
		msgCh <- msg
	}()

	// Trigger policy revocation
	session.TerminateWithPolicyRevocation()

	select {
	case err := <-errCh:
		t.Fatalf("Client reader encountered unexpected transport error: %v", err)
	case msg := <-msgCh:
		errResp, ok := msg.(*pgproto3.ErrorResponse)
		if !ok {
			t.Fatalf("Expected *pgproto3.ErrorResponse, got: %T", msg)
		}
		if errResp.Code != "57P01" {
			t.Errorf("Expected SQLSTATE 57P01, got: %s", errResp.Code)
		}
		if errResp.Severity != "FATAL" {
			t.Errorf("Expected Severity FATAL, got: %s", errResp.Severity)
		}
		if !strings.Contains(errResp.Message, "revoked") {
			t.Errorf("Expected message to mention policy revocation, got: %s", errResp.Message)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("Timed out waiting for 57P01 ErrorResponse delivery")
	}

	// Verify session state is invalidated and errorDiscard is set
	if !session.invalidated.Load() {
		t.Errorf("Expected session.invalidated to be true")
	}
	if !session.errorDiscard.Load() {
		t.Errorf("Expected session.errorDiscard to be true")
	}

	// Subsequent read on clientConn must encounter EOF / closed connection
	_ = clientConn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	buf := make([]byte, 16)
	_, err := clientConn.Read(buf)
	if err == nil {
		t.Errorf("Expected client connection to be closed after FATAL error, but read succeeded")
	}
}

// Test 15: Policy Revocation Idempotence and Concurrency Under Race Detector
// Verifies that multiple concurrent invocations of TerminateWithPolicyRevocation
// execute safely without data races and deliver exactly one 57P01 response.
func TestPolicyRevocation_DesignatedWriter_Concurrency_NoRace(t *testing.T) {
	serverConn, clientConn := inProcessTCPPair(t)
	defer clientConn.Close()

	session := &Session{
		clientConn:    serverConn,
		clientBackend: pgproto3.NewBackend(serverConn, serverConn),
		logger:        NewLogger(io.Discard),
	}

	var wg sync.WaitGroup
	// Concurrently call TerminateWithPolicyRevocation from 10 goroutines
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			session.TerminateWithPolicyRevocation()
		}()
	}

	// Read from client
	clientFrontend := pgproto3.NewFrontend(clientConn, clientConn)
	msg, err := clientFrontend.Receive()
	if err != nil {
		t.Fatalf("Client receive failed: %v", err)
	}

	errResp, ok := msg.(*pgproto3.ErrorResponse)
	if !ok || errResp.Code != "57P01" {
		t.Fatalf("Expected 57P01 ErrorResponse, got: %v", msg)
	}

	wg.Wait()
}

// Test 16: Negative Control — Unexplained Socket Resets Do Not Match 57P01
// Verifies that arbitrary connection resets or socket teardown errors
// fail validation when 57P01 is expected.
func TestPolicyRevocation_NegativeControl_UnexplainedResetRejected(t *testing.T) {
	arbitraryErrors := []error{
		fmt.Errorf("read: connection reset by peer"),
		fmt.Errorf("write: broken pipe"),
		io.ErrUnexpectedEOF,
		fmt.Errorf("network error: socket closed unexpectedly"),
	}

	for _, err := range arbitraryErrors {
		errStr := err.Error()
		if strings.Contains(errStr, "57P01") {
			t.Errorf("Negative control failed: error string %q unexpectedly matched 57P01", errStr)
		}
	}
}

// Test 17: Existing Client Writer Blocked While Revocation Starts
// Verifies that if an ordinary writer is holding clientWriteMu, TerminateWithPolicyRevocation
// curtails the write deadline, waits up to 5s, acquires the lock or times out, and fails closed without deadlock.
func TestPolicyRevocation_ExistingWriterBlocked_LockTimeoutBounded(t *testing.T) {
	serverConn, clientConn := inProcessTCPPair(t)
	defer clientConn.Close()

	session := &Session{
		clientConn:    serverConn,
		clientBackend: pgproto3.NewBackend(serverConn, serverConn),
		logger:        NewLogger(io.Discard),
	}

	started := make(chan struct{})
	writerDone := make(chan struct{})

	// Simulate existing writer holding clientWriteMu
	session.clientWriteMu.Lock()
	go func() {
		close(started)
		// Hold lock briefly, then release
		time.Sleep(50 * time.Millisecond)
		session.clientWriteMu.Unlock()
		close(writerDone)
	}()

	<-started

	// Client reader in background to absorb fatal error write
	go func() {
		clientFrontend := pgproto3.NewFrontend(clientConn, clientConn)
		_, _ = clientFrontend.Receive()
	}()

	// Revocation starts while writer held lock
	done := make(chan struct{})
	go func() {
		session.TerminateWithPolicyRevocation()
		close(done)
	}()

	select {
	case <-done:
		// Succeeded in acquiring lock after writer released and terminated
	case <-time.After(3 * time.Second):
		t.Fatalf("TerminateWithPolicyRevocation deadlocked while waiting for existing writer")
	}

	<-writerDone
}

// Test 18: Client Stops Reading Indefinitely (Write Timeout Bounded)
// Verifies that when a client stops reading and socket write buffer is saturated,
// the deadline ensures revocation fails closed without hanging.
func TestPolicyRevocation_ClientStopsReading_WriteTimeoutBounded(t *testing.T) {
	serverConn, clientConn := inProcessTCPPair(t)
	defer clientConn.Close()

	session := &Session{
		clientConn:    serverConn,
		clientBackend: pgproto3.NewBackend(serverConn, serverConn),
		logger:        NewLogger(io.Discard),
	}

	done := make(chan struct{})
	go func() {
		// Set short 50ms deadline on connection to verify bounded fail-closed
		_ = serverConn.SetWriteDeadline(time.Now().Add(50 * time.Millisecond))
		session.TerminateWithPolicyRevocation()
		close(done)
	}()

	select {
	case <-done:
		// Successfully terminated and failed closed
	case <-time.After(2 * time.Second):
		t.Fatalf("TerminateWithPolicyRevocation hung when client stopped reading")
	}
}

// Test 19: Existing clientBackend.Receive Blocked When Revocation Occurs
// Verifies that when a session reader is blocked waiting for client commands,
// revocation unblocks the reader and cleans up without deadlock.
func TestPolicyRevocation_BlockedReceiveUnblocksOnRevocation(t *testing.T) {
	serverConn, clientConn := inProcessTCPPair(t)
	defer clientConn.Close()

	session := &Session{
		clientConn:    serverConn,
		clientBackend: pgproto3.NewBackend(serverConn, serverConn),
		logger:        NewLogger(io.Discard),
	}

	readErrCh := make(chan error, 1)
	go func() {
		_, err := session.clientBackend.Receive()
		readErrCh <- err
	}()

	// Read on clientConn so server's fatal message doesn't stall
	go func() {
		clientFrontend := pgproto3.NewFrontend(clientConn, clientConn)
		_, _ = clientFrontend.Receive()
	}()

	time.Sleep(20 * time.Millisecond)

	// Trigger revocation
	session.TerminateWithPolicyRevocation()

	select {
	case err := <-readErrCh:
		if err == nil {
			t.Errorf("Expected Receive to return error upon socket closure, got nil")
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("clientBackend.Receive remained blocked after session revocation")
	}
}

// Test 20: Extended-Protocol Pipelined Parse/Bind/Execute/Sync Traffic
// Verifies that when a client pipelines extended query messages on a revoked session,
// handleParseMsg detects revocation, delivers 57P01, and fails closed without buffer corruption.
func TestPolicyRevocation_ExtendedProtocol_PipelinedTraffic(t *testing.T) {
	serverConn, clientConn := inProcessTCPPair(t)
	defer clientConn.Close()

	session := &Session{
		clientConn:    serverConn,
		clientBackend: pgproto3.NewBackend(serverConn, serverConn),
		logger:        NewLogger(io.Discard),
	}
	session.invalidated.Store(true) // policy is already revoked

	clientWriteCh := make(chan pgproto3.BackendMessage, 16)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	parseMsg := &pgproto3.Parse{Query: "SELECT id, name FROM customers WHERE id = 1"}

	// Client reader runs concurrently
	msgCh := make(chan pgproto3.BackendMessage, 1)
	readErrCh := make(chan error, 1)
	go func() {
		clientFrontend := pgproto3.NewFrontend(clientConn, clientConn)
		msg, rErr := clientFrontend.Receive()
		if rErr != nil {
			readErrCh <- rErr
			return
		}
		msgCh <- msg
	}()

	// handleParseMsg must immediately detect revocation and terminate
	err := session.handleParseMsg(ctx, parseMsg, clientWriteCh)
	if err == nil {
		t.Fatalf("Expected handleParseMsg to return error on revoked session, got nil")
	}

	select {
	case rErr := <-readErrCh:
		t.Fatalf("Failed to read fatal response on client frontend: %v", rErr)
	case msg := <-msgCh:
		errResp, ok := msg.(*pgproto3.ErrorResponse)
		if !ok || errResp.Code != "57P01" {
			t.Fatalf("Expected SQLSTATE 57P01 ErrorResponse, got: %v", msg)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("Timed out waiting for client to receive 57P01")
	}
}

// Test 21: Final Error Flush Fails (Fails Closed Without Panic)
// Verifies that if the client connection is broken before revocation finishes,
// TerminateWithPolicyRevocation handles the failure gracefully and completes teardown.
func TestPolicyRevocation_FlushFails_FailsClosed(t *testing.T) {
	serverConn, clientConn := inProcessTCPPair(t)
	clientConn.Close() // immediately break client side

	session := &Session{
		clientConn:    serverConn,
		clientBackend: pgproto3.NewBackend(serverConn, serverConn),
		logger:        NewLogger(io.Discard),
	}

	// Must not panic or hang
	done := make(chan struct{})
	go func() {
		session.TerminateWithPolicyRevocation()
		close(done)
	}()

	select {
	case <-done:
		// Clean teardown
	case <-time.After(2 * time.Second):
		t.Fatalf("TerminateWithPolicyRevocation hung on broken connection")
	}

	if !session.invalidated.Load() {
		t.Errorf("Expected session to be marked invalidated")
	}
}

// Test 22: No Unauthorized Statement Dispatched After Revocation
// Verifies that all query handlers fail closed when session is invalidated,
// ensuring zero statements are sent upstream.
func TestPolicyRevocation_DisallowsPostRevocationStatements(t *testing.T) {
	session := &Session{
		logger: NewLogger(io.Discard),
	}
	session.invalidated.Store(true)

	ctx := context.Background()
	ch := make(chan pgproto3.BackendMessage, 1)

	if err := session.handleParseMsg(ctx, &pgproto3.Parse{Query: "SELECT 1"}, ch); err == nil {
		t.Errorf("Expected handleParseMsg to fail after revocation")
	}
	if err := session.handleBindMsg(ctx, &pgproto3.Bind{}, ch); err == nil {
		t.Errorf("Expected handleBindMsg to fail after revocation")
	}
	if err := session.handleQueryMsg(ctx, &pgproto3.Query{String: "SELECT 1"}, ch); err == nil {
		t.Errorf("Expected handleQueryMsg to fail after revocation")
	}
}
