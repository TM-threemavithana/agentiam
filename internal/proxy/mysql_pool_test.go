package proxy

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-mysql-org/go-mysql/client"
	"github.com/go-mysql-org/go-mysql/mysql"
	"github.com/go-mysql-org/go-mysql/packet"
	"github.com/go-mysql-org/go-mysql/server"
	driver "github.com/go-sql-driver/mysql"
)

// Helper to construct a mock MySQLUpstreamConn backed by net.Pipe.
func createMockUpstreamConn(clientPipe, serverPipe net.Conn) *MySQLUpstreamConn {
	pktConn := packet.NewConn(clientPipe)
	c := &client.Conn{
		Conn: pktConn,
	}
	return &MySQLUpstreamConn{
		Conn: c,
	}
}

func TestMySQLUpstreamConn_Close_Idempotent(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c2.Close()

	u := createMockUpstreamConn(c1, c2)
	// Concurrent close calls should not panic or race
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			u.Close()
		}()
	}
	wg.Wait()

	if u.Conn != nil {
		t.Fatal("expected u.Conn to be nil after Close")
	}

	// Calling Close on nil u should not panic
	var nilConn *MySQLUpstreamConn
	nilConn.Close()
}

func TestMySQLUpstreamConn_ResetConnection_Preconditions(t *testing.T) {
	// Nil connection
	var nilConn *MySQLUpstreamConn
	if err := nilConn.ResetConnection(); err == nil {
		t.Fatal("expected error resetting nil connection, got nil")
	}

	// Broken connection
	broken := &MySQLUpstreamConn{}
	broken.Broken.Store(true)
	if err := broken.ResetConnection(); err == nil {
		t.Fatal("expected error resetting broken connection, got nil")
	}

	// Nil client.Conn
	noConn := &MySQLUpstreamConn{}
	if err := noConn.ResetConnection(); err == nil {
		t.Fatal("expected error resetting connection with nil client.Conn, got nil")
	}
}

func TestMySQLUpstreamConn_ResetConnection_Success(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	u := createMockUpstreamConn(c1, c2)

	// Server goroutine: verify COM_RESET_CONNECTION packet and send OK response
	serverErrCh := make(chan error, 1)
	go func() {
		// Read 4-byte header
		header := make([]byte, 4)
		if _, err := io.ReadFull(c2, header); err != nil {
			serverErrCh <- err
			return
		}
		length := int(uint32(header[0]) | uint32(header[1])<<8 | uint32(header[2])<<16)
		payload := make([]byte, length)
		if _, err := io.ReadFull(c2, payload); err != nil {
			serverErrCh <- err
			return
		}
		if len(payload) != 1 || payload[0] != mysql.COM_RESET_CONNECTION {
			serverErrCh <- io.ErrUnexpectedEOF
			return
		}

		// Send OK packet: len=7, seq=1, header=0x00, affected_rows=0, last_insert_id=0, status=0x0002 (SERVER_STATUS_AUTOCOMMIT)
		okPacket := []byte{
			0x07, 0x00, 0x00, 0x01, // 4-byte header (len=7, seq=1)
			0x00,                   // OK header
			0x00,                   // 0 affected rows
			0x00,                   // 0 last insert id
			0x02, 0x00,             // SERVER_STATUS_AUTOCOMMIT
			0x00, 0x00,             // 0 warnings
		}
		_, err := c2.Write(okPacket)
		serverErrCh <- err
	}()

	if err := u.ResetConnection(); err != nil {
		t.Fatalf("expected successful ResetConnection, got: %v", err)
	}

	if err := <-serverErrCh; err != nil {
		t.Fatalf("server mock encountered error: %v", err)
	}

	if u.Broken.Load() {
		t.Fatal("connection should not be marked broken after successful reset")
	}
}

func TestMySQLUpstreamConn_ResetConnection_ErrorPacket_Discards(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	u := createMockUpstreamConn(c1, c2)

	go func() {
		header := make([]byte, 4)
		_, _ = io.ReadFull(c2, header)
		payload := make([]byte, 1)
		_, _ = io.ReadFull(c2, payload)

		// Send MySQL ERR packet: 0xff, error_code=1105 (0x0451), sql_state="#HY000", message="Unknown error"
		// len = 1 (0xff) + 2 (code) + 1 (#) + 5 (state) + 13 (msg) = 22 bytes
		errPacket := []byte{
			0x16, 0x00, 0x00, 0x01, // len=22, seq=1
			0xff,                   // ERR header
			0x51, 0x04,             // error code 1105
			'#', 'H', 'Y', '0', '0', '0', // SQL state
			'U', 'n', 'k', 'n', 'o', 'w', 'n', ' ', 'e', 'r', 'r', 'o', 'r',
		}
		_, _ = c2.Write(errPacket)
	}()

	err := u.ResetConnection()
	if err == nil {
		t.Fatal("expected error on ERR packet response, got nil")
	}
	if !u.Broken.Load() {
		t.Fatal("connection must be marked broken after ERR packet")
	}
}

func TestMySQLUpstreamConn_ResetConnection_MalformedPacket_Discards(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	u := createMockUpstreamConn(c1, c2)

	go func() {
		header := make([]byte, 4)
		_, _ = io.ReadFull(c2, header)
		payload := make([]byte, 1)
		_, _ = io.ReadFull(c2, payload)

		// Send bogus packet header (0x42 instead of 0x00 or 0xff)
		badPacket := []byte{
			0x01, 0x00, 0x00, 0x01,
			0x42,
		}
		_, _ = c2.Write(badPacket)
	}()

	err := u.ResetConnection()
	if err == nil {
		t.Fatal("expected error on malformed packet response, got nil")
	}
	if !u.Broken.Load() {
		t.Fatal("connection must be marked broken after malformed packet")
	}
}

func TestMySQLUpstreamConn_ResetConnection_ServerDisconnect_Discards(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()

	u := createMockUpstreamConn(c1, c2)

	go func() {
		header := make([]byte, 4)
		_, _ = io.ReadFull(c2, header)
		payload := make([]byte, 1)
		_, _ = io.ReadFull(c2, payload)
		// Immediately close server side
		c2.Close()
	}()

	err := u.ResetConnection()
	if err == nil {
		t.Fatal("expected error on disconnected server, got nil")
	}
	if !u.Broken.Load() {
		t.Fatal("connection must be marked broken after server disconnect")
	}
}

func TestMySQLPool_Release_DiscardAndReplace(t *testing.T) {
	logger := NewLogger(io.Discard)
	pool := NewMySQLPool("127.0.0.1:3306", "root", "", "testdb", 2, logger)

	// Create mock broken connection
	brokenConn := &MySQLUpstreamConn{}
	brokenConn.Broken.Store(true)

	// Release broken connection into pool
	// discardAndReplace will attempt p.dial(), which fails because no real server on 127.0.0.1:3306
	// but it must insert a placeholder so pool capacity is preserved and no panic occurs
	pool.Release(brokenConn)

	// Channel must have 1 item (placeholder)
	select {
	case item := <-pool.conns:
		if item == brokenConn {
			t.Fatal("dirty/broken connection must NEVER be returned to the pool")
		}
		if !item.Broken.Load() {
			t.Fatal("placeholder connection should be marked broken")
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("pool channel starved: no placeholder inserted after failed replacement")
	}
}

func TestMySQLPool_Concurrency_AcquireReleaseClose(t *testing.T) {
	logger := NewLogger(io.Discard)
	pool := NewMySQLPool("127.0.0.1:3306", "root", "", "testdb", 5, logger)

	// Pre-fill pool with 5 mock connections that succeed on reset
	for i := 0; i < 5; i++ {
		c1, c2 := net.Pipe()
		u := createMockUpstreamConn(c1, c2)
		go func(srv net.Conn) {
			for {
				header := make([]byte, 4)
				if _, err := io.ReadFull(srv, header); err != nil {
					return
				}
				length := int(uint32(header[0]) | uint32(header[1])<<8 | uint32(header[2])<<16)
				payload := make([]byte, length)
				if _, err := io.ReadFull(srv, payload); err != nil {
					return
				}
				// Return OK packet
				okPacket := []byte{0x07, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00}
				if _, err := srv.Write(okPacket); err != nil {
					return
				}
			}
		}(c2)
		pool.conns <- u
	}
	pool.ready.Store(true)

	var ops atomic.Int64
	var wg sync.WaitGroup
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	// 10 concurrent worker goroutines
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				default:
					u, err := pool.Acquire(ctx)
					if err != nil {
						return
					}
					ops.Add(1)
					time.Sleep(1 * time.Millisecond)
					pool.Release(u)
				}
			}
		}()
	}

	wg.Wait()
	pool.Close()

	if ops.Load() == 0 {
		t.Fatal("expected concurrent acquire/release operations to execute successfully")
	}
}


func TestMySQLPool_Close_ConcurrentRelease_NoLeak(t *testing.T) {
	logger := NewLogger(io.Discard)
	pool := NewMySQLPool("127.0.0.1:3306", "root", "", "testdb", 10, logger)

	var conns []*MySQLUpstreamConn
	for i := 0; i < 10; i++ {
		c1, c2 := net.Pipe()
		u := createMockUpstreamConn(c1, c2)
		go func(srv net.Conn) {
			for {
				header := make([]byte, 4)
				if _, err := io.ReadFull(srv, header); err != nil {
					return
				}
				length := int(uint32(header[0]) | uint32(header[1])<<8 | uint32(header[2])<<16)
				payload := make([]byte, length)
				if _, err := io.ReadFull(srv, payload); err != nil {
					return
				}
				okPacket := []byte{0x07, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00}
				if _, err := srv.Write(okPacket); err != nil {
					return
				}
			}
		}(c2)
		conns = append(conns, u)
	}

	var wg sync.WaitGroup
	// Start concurrent release
	for _, u := range conns {
		wg.Add(1)
		go func(conn *MySQLUpstreamConn) {
			defer wg.Done()
			pool.Release(conn)
		}(u)
	}

	// Close pool concurrently
	pool.Close()
	wg.Wait()

	// Verify no sockets were leaked into pool.conns after Close
	select {
	case leaked := <-pool.conns:
		if leaked != nil && leaked.Conn != nil {
			t.Fatal("socket leaked in pool.conns after pool.Close()")
		}
	default:
		// Expected: channel is empty
	}
}

func TestMySQLPool_PlaceholderRecovery_OutageAndCancellation(t *testing.T) {
	logger := NewLogger(io.Discard)
	// Point to unreachable port so dialing fails deterministically
	pool := NewMySQLPool("127.0.0.1:1", "root", "", "testdb", 2, logger)

	// Pre-fill pool with 2 broken placeholders (simulating outage)
	p1 := &MySQLUpstreamConn{}
	p1.Broken.Store(true)
	p2 := &MySQLUpstreamConn{}
	p2.Broken.Store(true)
	pool.conns <- p1
	pool.conns <- p2
	pool.ready.Store(true)

	// 1. Multiple callers call Acquire with short timeouts
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
			defer cancel()
			u, err := pool.Acquire(ctx)
			if err == nil {
				pool.Release(u)
				t.Error("expected acquire to fail against unreachable upstream")
			}
		}()
	}
	wg.Wait()

	// Verify pool channel capacity is preserved (contains 2 placeholders, not starved)
	if len(pool.conns) != 2 {
		t.Fatalf("expected 2 placeholder slots in pool.conns, got %d", len(pool.conns))
	}

	// 2. Caller with canceled context returns immediately without deadlock
	canceledCtx, cancelNow := context.WithCancel(context.Background())
	cancelNow()
	_, err := pool.Acquire(canceledCtx)
	if err == nil || (!errors.Is(err, context.Canceled) && !strings.Contains(err.Error(), "canceled")) {
		t.Fatalf("expected context cancellation error, got %v", err)
	}
	if len(pool.conns) != 2 {
		t.Fatalf("expected 2 placeholder slots in pool.conns after canceled acquire, got %d", len(pool.conns))
	}
}

func TestMySQLUpstreamConn_Execute_Mutex_Protection(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	u := createMockUpstreamConn(c1, c2)

	// Sever connection on server side
	c2.Close()

	// Execute should detect bad connection and mark Broken
	_, err := u.Execute("SELECT 1")
	if err == nil {
		t.Fatal("expected error on severed connection, got nil")
	}
	if !u.Broken.Load() {
		t.Fatal("connection must be marked broken on network error")
	}
}

func generateTestServerCert(caCert *x509.Certificate, caKey interface{}, host string) (tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject: pkix.Name{
			CommonName:   host,
			Organization: []string{"Test Server"},
		},
		NotBefore:             time.Now().Add(-1 * time.Minute),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	if ip := net.ParseIP(host); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{host}
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, caCert, &priv.PublicKey, caKey)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	privBytes, _ := x509.MarshalECPrivateKey(priv)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes})

	return tls.X509KeyPair(certPEM, keyPEM)
}

type mockTLSAuthHandler struct{}

func (m *mockTLSAuthHandler) Authenticate(c *server.Conn, authPluginName string, clientAuthData []byte) error {
	return nil
}
func (m *mockTLSAuthHandler) Validate(authPluginName string) bool {
	return true
}
func (m *mockTLSAuthHandler) GetCredential(username string) (server.Credential, bool, error) {
	return server.Credential{Passwords: []string{""}, AuthPluginName: "mysql_native_password"}, true, nil
}
func (m *mockTLSAuthHandler) OnAuthSuccess(conn *server.Conn) error {
	return nil
}
func (m *mockTLSAuthHandler) OnAuthFailure(conn *server.Conn, err error) {
}

type mockTLSQueryHandler struct {
	server.EmptyHandler
}

func (m *mockTLSQueryHandler) HandleQuery(query string) (*mysql.Result, error) {
	if strings.Contains(query, "Ssl_cipher") {
		names := []string{"Variable_name", "Value"}
		values := [][]any{{"Ssl_cipher", "TLS_AES_128_GCM_SHA256"}}
		rs, err := mysql.BuildSimpleResultset(names, values, false)
		if err != nil {
			return nil, err
		}
		return &mysql.Result{Resultset: rs}, nil
	}
	return &mysql.Result{Status: 2}, nil
}

func startMockTLSServer(t *testing.T, serverTLS *tls.Config) (string, func()) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}

	authHandler := &mockTLSAuthHandler{}
	queryHandler := &mockTLSQueryHandler{}
	serverConf := server.NewServerWithAuth("8.0.32", 255, "mysql_native_password", nil, serverTLS, authHandler)

	done := make(chan struct{})
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				select {
				case <-done:
					return
				default:
					return
				}
			}
			go func(c net.Conn) {
				defer c.Close()
				sConn, err := serverConf.NewCustomizedConn(c, authHandler, queryHandler)
				if err != nil {
					return
				}
				for {
					if err := sConn.HandleCommand(); err != nil {
						return
					}
				}
			}(conn)
		}
	}()

	cleanup := func() {
		close(done)
		_ = l.Close()
	}
	return l.Addr().String(), cleanup
}

func TestMySQLPool_UpstreamTLS_Scenarios(t *testing.T) {
	logger := NewLogger(io.Discard)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Generate trusted test CA and server certificate
	caTlsCert, caX509, err := generateTestCA()
	if err != nil {
		t.Fatalf("failed to generate test CA: %v", err)
	}
	serverCert, err := generateTestServerCert(caX509, caTlsCert.PrivateKey, "127.0.0.1")
	if err != nil {
		t.Fatalf("failed to generate server cert: %v", err)
	}

	serverTLS := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
	}
	serverAddr, cleanupServer := startMockTLSServer(t, serverTLS)
	defer cleanupServer()

	// Client CA pool trusting our test server
	trustedPool := x509.NewCertPool()
	trustedPool.AddCert(caX509)

	clientTLS := &tls.Config{
		RootCAs:            trustedPool,
		ServerName:         "127.0.0.1",
		InsecureSkipVerify: false,
	}

	// 1. Valid TLS Negotiated & Cipher Active
	t.Run("Valid_TLS_Negotiated_Cipher_Active", func(t *testing.T) {
		pool := NewMySQLPool(serverAddr, "root", "", "testdb", 2, logger, clientTLS)
		if err := pool.Init(ctx); err != nil {
			t.Fatalf("failed to init pool with TLS: %v", err)
		}
		defer pool.Close()

		u, err := pool.Acquire(ctx)
		if err != nil {
			t.Fatalf("failed to acquire connection: %v", err)
		}
		defer pool.Release(u)

		if !u.IsTLS() {
			t.Fatal("expected u.IsTLS() to be true for TLS connection, got false")
		}

		state, ok := u.TLSConnectionState()
		if !ok {
			t.Fatal("expected TLSConnectionState to return ok=true")
		}
		if state.CipherSuite == 0 {
			t.Fatal("expected valid non-zero CipherSuite in TLSConnectionState")
		}
		if state.Version < tls.VersionTLS12 {
			t.Fatalf("expected TLS version >= TLS 1.2, got 0x%04x", state.Version)
		}

		res, err := u.Execute("SHOW STATUS LIKE 'Ssl_cipher'")
		if err != nil {
			t.Fatalf("failed to execute query over TLS: %v", err)
		}
		if res == nil || res.Resultset == nil || len(res.Values) == 0 {
			t.Fatal("expected non-empty result for Ssl_cipher query")
		}
	})

	// 2. COM_RESET_CONNECTION Preserves TLS
	t.Run("COM_RESET_CONNECTION_PreservesTLS", func(t *testing.T) {
		pool := NewMySQLPool(serverAddr, "root", "", "testdb", 1, logger, clientTLS)
		if err := pool.Init(ctx); err != nil {
			t.Fatalf("failed to init pool: %v", err)
		}
		defer pool.Close()

		u, err := pool.Acquire(ctx)
		if err != nil {
			t.Fatalf("failed to acquire connection: %v", err)
		}
		if !u.IsTLS() {
			t.Fatal("expected connection to be TLS before release")
		}

		// Release triggers COM_RESET_CONNECTION
		pool.Release(u)

		// Re-acquire the same connection and verify TLS is preserved
		u2, err := pool.Acquire(ctx)
		if err != nil {
			t.Fatalf("failed to re-acquire connection: %v", err)
		}
		defer pool.Release(u2)

		if !u2.IsTLS() {
			t.Fatal("expected connection to remain TLS after COM_RESET_CONNECTION release")
		}

		state, ok := u2.TLSConnectionState()
		if !ok || state.CipherSuite == 0 {
			t.Fatal("expected active TLS connection state after reset")
		}

		if _, err := u2.Execute("SELECT 1"); err != nil {
			t.Fatalf("failed to execute query on reset TLS connection: %v", err)
		}
	})

	// 3. DiscardAndReplace Preserves TLS
	t.Run("DiscardAndReplace_PreservesTLS", func(t *testing.T) {
		pool := NewMySQLPool(serverAddr, "root", "", "testdb", 1, logger, clientTLS)
		if err := pool.Init(ctx); err != nil {
			t.Fatalf("failed to init pool: %v", err)
		}
		defer pool.Close()

		u, err := pool.Acquire(ctx)
		if err != nil {
			t.Fatalf("failed to acquire: %v", err)
		}

		// Mark connection broken to force discardAndReplace
		u.Broken.Store(true)
		pool.Release(u)

		// Acquire replacement connection and verify TLS configuration was inherited
		uRepl, err := pool.Acquire(ctx)
		if err != nil {
			t.Fatalf("failed to acquire replacement connection: %v", err)
		}
		defer pool.Release(uRepl)

		if !uRepl.IsTLS() {
			t.Fatal("replacement connection must be TLS-encrypted")
		}
		state, ok := uRepl.TLSConnectionState()
		if !ok || state.CipherSuite == 0 {
			t.Fatal("replacement connection must have valid TLS state")
		}
	})

	// 4. Untrusted Certificate Fails Closed
	t.Run("Untrusted_Certificate_FailsClosed", func(t *testing.T) {
		// Empty root CA pool -> does not trust the test CA
		emptyPool := x509.NewCertPool()
		untrustedTLS := &tls.Config{
			RootCAs:            emptyPool,
			ServerName:         "127.0.0.1",
			InsecureSkipVerify: false,
		}

		badPool := NewMySQLPool(serverAddr, "root", "", "testdb", 1, logger, untrustedTLS)
		err := badPool.Init(ctx)
		if err == nil {
			badPool.Close()
			t.Fatal("expected pool init to fail on untrusted certificate, got nil")
		}
		if !strings.Contains(err.Error(), "certificate") && !strings.Contains(err.Error(), "unknown authority") && !strings.Contains(err.Error(), "x509") {
			t.Fatalf("expected certificate verification error, got: %v", err)
		}
	})

	// 5. ServerName Mismatch Fails Closed
	t.Run("ServerName_Mismatch_FailsClosed", func(t *testing.T) {
		wrongHostTLS := &tls.Config{
			RootCAs:            trustedPool,
			ServerName:         "unmatched.domain.internal",
			InsecureSkipVerify: false,
		}

		badPool := NewMySQLPool(serverAddr, "root", "", "testdb", 1, logger, wrongHostTLS)
		err := badPool.Init(ctx)
		if err == nil {
			badPool.Close()
			t.Fatal("expected pool init to fail on hostname mismatch, got nil")
		}
		if !strings.Contains(err.Error(), "certificate") && !strings.Contains(err.Error(), "valid for") && !strings.Contains(err.Error(), "x509") {
			t.Fatalf("expected hostname verification error, got: %v", err)
		}
	})

	// 6. Plaintext Server Rejected When TLS Required (Zero Plaintext Fallback)
	t.Run("Plaintext_Server_Rejected_When_TLS_Required", func(t *testing.T) {
		plainServerAddr, cleanupPlain := startMockTLSServer(t, nil) // serverTLS = nil (plaintext server)
		defer cleanupPlain()

		tlsRequiredPool := NewMySQLPool(plainServerAddr, "root", "", "testdb", 1, logger, clientTLS)
		err := tlsRequiredPool.Init(ctx)
		if err == nil {
			tlsRequiredPool.Close()
			t.Fatal("expected pool init to fail against plaintext server when TLS is required, got nil")
		}
		if !strings.Contains(err.Error(), "does not support TLS required by the client") {
			t.Fatalf("expected TLS unsupported rejection error, got: %v", err)
		}
	})
}

func TestMySQLProtocolHandler_InitPool_TLSPropagation(t *testing.T) {
	logger := NewLogger(io.Discard)

	// 1. DSN with ?tls=skip-verify
	cfg1, err := driver.ParseDSN("root@tcp(127.0.0.1:3306)/testdb?tls=skip-verify")
	if err != nil {
		t.Fatalf("failed to parse DSN: %v", err)
	}
	p1 := NewMySQLPool(cfg1.Addr, cfg1.User, cfg1.Passwd, cfg1.DBName, 1, logger, cfg1.TLS)
	tls1 := p1.GetTLSConfig()
	if tls1 == nil {
		t.Fatal("expected pool to have TLS config for ?tls=skip-verify")
	}
	if !tls1.InsecureSkipVerify {
		t.Fatal("expected InsecureSkipVerify=true for ?tls=skip-verify")
	}

	// 2. DSN with ?tls=true (enforces verification & populates ServerName)
	cfg2, err := driver.ParseDSN("root@tcp(127.0.0.1:3306)/testdb?tls=true")
	if err != nil {
		t.Fatalf("failed to parse DSN: %v", err)
	}
	p2 := NewMySQLPool(cfg2.Addr, cfg2.User, cfg2.Passwd, cfg2.DBName, 1, logger, cfg2.TLS)
	tls2 := p2.GetTLSConfig()
	if tls2 == nil {
		t.Fatal("expected pool to have TLS config for ?tls=true")
	}
	if tls2.InsecureSkipVerify {
		t.Fatal("expected InsecureSkipVerify=false for ?tls=true")
	}

	// 3. DSN with ?tls=custom
	customKey := fmt.Sprintf("custom-pool-test-%d", time.Now().UnixNano())
	customRootPool := x509.NewCertPool()
	customCfg := &tls.Config{
		RootCAs:            customRootPool,
		ServerName:         "custom.host",
		InsecureSkipVerify: false,
	}
	if err := driver.RegisterTLSConfig(customKey, customCfg); err != nil {
		t.Fatalf("failed to register TLS config: %v", err)
	}
	defer driver.DeregisterTLSConfig(customKey)

	cfg3, err := driver.ParseDSN(fmt.Sprintf("root@tcp(127.0.0.1:3306)/testdb?tls=%s", customKey))
	if err != nil {
		t.Fatalf("failed to parse DSN with custom TLS: %v", err)
	}
	p3 := NewMySQLPool(cfg3.Addr, cfg3.User, cfg3.Passwd, cfg3.DBName, 1, logger, cfg3.TLS)
	tls3 := p3.GetTLSConfig()
	if tls3 == nil {
		t.Fatal("expected pool to have TLS config for ?tls=custom")
	}
	if tls3.ServerName != "custom.host" {
		t.Fatalf("expected ServerName='custom.host', got '%s'", tls3.ServerName)
	}

	// 4. DSN without tls parameter (plaintext default)
	cfg4, err := driver.ParseDSN("root@tcp(127.0.0.1:3306)/testdb")
	if err != nil {
		t.Fatalf("failed to parse plaintext DSN: %v", err)
	}
	p4 := NewMySQLPool(cfg4.Addr, cfg4.User, cfg4.Passwd, cfg4.DBName, 1, logger, cfg4.TLS)
	if p4.GetTLSConfig() != nil {
		t.Fatal("expected pool to have nil TLS config for plaintext DSN")
	}

	// 5. Unregistered TLS config fails closed during ParseDSN/InitPool
	handler := &MySQLProtocolHandler{
		upstreamDSN: "root@tcp(127.0.0.1:3306)/testdb?tls=unknown_nonexistent_config",
		logger:      logger,
	}
	if err := handler.InitPool(); err == nil {
		t.Fatal("expected InitPool to fail on unregistered TLS config, got nil")
	} else if !strings.Contains(err.Error(), "unknown config name") {
		t.Fatalf("expected 'unknown config name' error, got: %v", err)
	}
}
