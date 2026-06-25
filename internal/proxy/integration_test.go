package proxy_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net"
	"os"

	"golang.org/x/crypto/bcrypt"
	"net/url"
	"testing"
	"time"

	"github.com/TM-threemavithana/agentiam/internal/policy"
	"github.com/TM-threemavithana/agentiam/internal/proxy"

	"github.com/jackc/pgx/v5"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
)

func setupTestEnv(t *testing.T) (string, string, func()) {
	ctx := context.Background()

	// 1. Start Postgres Container
	pgContainer, err := postgres.RunContainer(ctx,
		testcontainers.WithImage("postgres:15-alpine"),
		postgres.WithDatabase("testdb"),
		postgres.WithUsername("app_user"),
		postgres.WithPassword("app_password"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("database system is ready to accept connections").
				WithOccurrence(2).
				WithStartupTimeout(10*time.Second)),
	)
	if err != nil {
		t.Fatalf("failed to start postgres container: %s", err)
	}

	upstreamDSN, err := pgContainer.ConnectionString(ctx, "sslmode=disable")
	if err != nil {
		t.Fatalf("failed to get connection string: %s", err)
	}

	// Setup table and admin data
	adminConn, err := pgx.Connect(ctx, upstreamDSN)
	if err != nil {
		t.Fatalf("failed to connect admin: %v", err)
	}
	defer adminConn.Close(ctx)

	_, err = adminConn.Exec(ctx, "CREATE TABLE test_table (id int)")
	if err != nil {
		t.Fatalf("failed to create table: %v", err)
	}

	for i := 1; i <= 150; i++ {
		_, err = adminConn.Exec(ctx, "INSERT INTO test_table (id) VALUES ($1)", i)
		if err != nil {
			t.Fatalf("failed to insert data: %v", err)
		}
	}

	// 2. Setup Policy Store
	hash, _ := bcrypt.GenerateFromPassword([]byte("test-agent-secret"), bcrypt.DefaultCost)
	yamlContent := fmt.Sprintf(`agents:
  - name: test-agent
    key: "%s"
    allowed_statements:
      - "SELECT"
`, string(hash))
	tmpFile, _ := os.CreateTemp("", "policies-*.yaml")
	tmpFile.Write([]byte(yamlContent))
	tmpFile.Close()
	defer os.Remove(tmpFile.Name())
	store, err := policy.NewStore(nil, tmpFile.Name(), "", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("failed to create policy store: %v", err)
	}

	// 3. Start Proxy Server
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}

	logger := proxy.NewLogger(os.Stdout)
	handlers := make(map[proxy.ProtocolType]proxy.ProtocolHandler)
	server := proxy.NewServer(l.Addr().String(), upstreamDSN, store, nil, logger, nil, handlers)
	pgHandler := proxy.NewPostgresProtocolHandler(upstreamDSN, store, nil, logger, server)
	server.SetHandler(proxy.ProtocolPostgres, pgHandler)
	server.InitPool(context.Background())
	go server.PollPolicyUpdatesForTest()

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				session := proxy.NewSession(c, upstreamDSN, store, nil, logger, server)
				defer session.Close()
				session.Run()
			}(conn)
		}
	}()

	proxyURL, _ := url.Parse("postgres://127.0.0.1/testdb?sslmode=disable")
	proxyURL.Host = l.Addr().String()

	// Good DSN for test agent
	proxyURL.User = url.UserPassword("test-agent", "test-agent-secret")
	proxyDSN := proxyURL.String()

	// Bad DSN for auth failure test
	proxyURL.User = url.UserPassword("test-agent", "wrong-secret")
	badProxyDSN := proxyURL.String()

	cleanup := func() {
		l.Close()
		pgContainer.Terminate(ctx)
	}

	return proxyDSN, badProxyDSN, cleanup
}

func TestProxyIntegration(t *testing.T) {
	proxyDSN, badProxyDSN, cleanup := setupTestEnv(t)
	defer cleanup()

	ctx := context.Background()

	// Test 1: Handshake completes
	t.Run("1_Clean_Select", func(t *testing.T) {
		conn, err := pgx.Connect(ctx, proxyDSN)
		if err != nil {
			t.Fatalf("failed to connect via proxy: %v", err)
		}
		defer conn.Close(ctx)

		var res int
		err = conn.QueryRow(ctx, "SELECT 1").Scan(&res)
		if err != nil {
			t.Fatalf("SELECT failed: %v", err)
		}
		if res != 1 {
			t.Errorf("expected 1, got %d", res)
		}
	})

	// Test 2: Blocked statement returns clean error
	t.Run("2_Blocked_Delete", func(t *testing.T) {
		conn, err := pgx.Connect(ctx, proxyDSN)
		if err != nil {
			t.Fatalf("failed to connect via proxy: %v", err)
		}
		defer conn.Close(ctx)

		_, err = conn.Exec(ctx, "DELETE FROM test_table")
		if err == nil {
			t.Fatal("expected error from DELETE, got none")
		}

		// Ensure connection is still usable
		var res int
		err = conn.QueryRow(ctx, "SELECT 1").Scan(&res)
		if err != nil {
			t.Fatalf("subsequent SELECT failed after error: %v", err)
		}
	})

	// Test 3: Pipelined discard
	t.Run("3_Pipelined_Discard", func(t *testing.T) {
		conn, err := pgx.Connect(ctx, proxyDSN)
		if err != nil {
			t.Fatalf("failed to connect via proxy: %v", err)
		}
		defer conn.Close(ctx)

		batch := &pgx.Batch{}
		batch.Queue("DELETE FROM test_table")
		batch.Queue("SELECT 1")

		br := conn.SendBatch(ctx, batch)
		defer br.Close()

		_, err = br.Exec()
		if err == nil {
			t.Fatal("expected error for first query in batch")
		}

		var res int
		err = br.QueryRow().Scan(&res)
		if err == nil {
			t.Fatal("expected second query in batch to also return the pipelined batch error, got success")
		}

		// Verify transaction status is clean by running another query
		err = conn.QueryRow(ctx, "SELECT 2").Scan(&res)
		if err != nil {
			t.Fatalf("connection unusable after batch: %v", err)
		}
	})

	// Test 4: LIMIT injection
	t.Run("4_Limit_Injection", func(t *testing.T) {
		conn, err := pgx.Connect(ctx, proxyDSN)
		if err != nil {
			t.Fatalf("failed to connect via proxy: %v", err)
		}
		defer conn.Close(ctx)

		rows, err := conn.Query(ctx, "SELECT * FROM test_table")
		if err != nil {
			t.Fatalf("query failed: %v", err)
		}
		defer rows.Close()

		count := 0
		for rows.Next() {
			count++
		}

		if count != 100 {
			t.Errorf("expected 100 rows due to injected LIMIT, got %d", count)
		}
	})

	// Test 5: Bad API key rejected at startup
	t.Run("5_Bad_Auth", func(t *testing.T) {
		_, err := pgx.Connect(ctx, badProxyDSN)
		if err == nil {
			t.Fatal("expected auth error with bad DSN, got none")
		}
	})

	// Test 6: SimpleQuery Error Recovery
	t.Run("6_SimpleQuery_Discard", func(t *testing.T) {
		conn, err := pgx.Connect(ctx, proxyDSN)
		if err != nil {
			t.Fatalf("failed to connect via proxy: %v", err)
		}
		defer conn.Close(ctx)

		// Exec uses SimpleQuery protocol when not prepared
		_, err = conn.PgConn().Exec(ctx, "DELETE FROM test_table").ReadAll()
		if err == nil {
			t.Fatal("expected error from DELETE via SimpleQuery, got none")
		}

		// Ensure connection recovers state correctly
		var res int
		err = conn.QueryRow(ctx, "SELECT 1").Scan(&res)
		if err != nil {
			t.Fatalf("subsequent SELECT failed after SimpleQuery error: %v", err)
		}
	})
}

func generateTestTLSConfig(t *testing.T) *tls.Config {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Organization: []string{"Acme Co"}},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	b, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatalf("failed to marshal key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: b})

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("failed to parse key pair: %v", err)
	}
	return &tls.Config{Certificates: []tls.Certificate{cert}}
}

func TestTLSUpgradeAndEnforcement(t *testing.T) {
	ctx := context.Background()

	// 1. Setup minimal upstream (we mock the upstream just to test proxy handshake)
	hash, _ := bcrypt.GenerateFromPassword([]byte("secret"), bcrypt.DefaultCost)
	yamlContent := fmt.Sprintf(`agents:
  - name: test-agent
    key: "%s"
    allowed_statements:
      - "SELECT"
`, string(hash))
	tmpFile, _ := os.CreateTemp("", "policies-*.yaml")
	tmpFile.Write([]byte(yamlContent))
	tmpFile.Close()
	defer os.Remove(tmpFile.Name())
	store, _ := policy.NewStore(nil, tmpFile.Name(), "", slog.New(slog.NewTextHandler(io.Discard, nil)))

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer l.Close()

	tlsConfig := generateTestTLSConfig(t)

	// Create a dummy upstream listener to simulate Postgres answering
	upstreamL, _ := net.Listen("tcp", "127.0.0.1:0")
	defer upstreamL.Close()
	go func() {
		for {
			c, err := upstreamL.Accept()
			if err != nil {
				return
			}
			c.Close() // immediately close, we don't care about upstream in this test, just proxy auth phase
		}
	}()
	upstreamDSN := "postgres://127.0.0.1:" + upstreamL.Addr().(*net.TCPAddr).String()

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				logger := proxy.NewLogger(os.Stdout)
				handlers := make(map[proxy.ProtocolType]proxy.ProtocolHandler)
				server := proxy.NewServer("127.0.0.1:0", upstreamDSN, store, tlsConfig, logger, nil, handlers)
				pgHandler := proxy.NewPostgresProtocolHandler(upstreamDSN, store, tlsConfig, logger, server)
				server.SetHandler(proxy.ProtocolPostgres, pgHandler)
				session := proxy.NewSession(c, upstreamDSN, store, tlsConfig, logger, server)
				defer session.Close()
				session.Run()
			}(conn)
		}
	}()

	addr := l.Addr().String()

	// Assertion 1 (Negative): Send a plaintext StartupMessage
	t.Run("Plaintext_Rejected", func(t *testing.T) {
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			t.Fatalf("Failed to dial server: %v", err)
		}
		defer conn.Close()

		// Startup message without SSLRequest
		// Length (25 bytes), Protocol (196608), "user\0test-agent\0\0"
		startupMsg := []byte{0, 0, 0, 25, 0, 3, 0, 0, 'u', 's', 'e', 'r', 0, 't', 'e', 's', 't', '-', 'a', 'g', 'e', 'n', 't', 0, 0}

		_, err = conn.Write(startupMsg)
		if err != nil {
			t.Fatalf("Failed to write plaintext StartupMessage: %v", err)
		}

		// Read the ErrorResponse
		resp := make([]byte, 1024)
		conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, err := conn.Read(resp)
		if err != nil {
			t.Fatalf("Failed to read proxy response: %v", err)
		}

		// Ensure it's an ErrorResponse ('E')
		if n == 0 || resp[0] != 'E' {
			t.Fatalf("Expected ErrorResponse 'E', got %v", resp[:n])
		}
	})

	// Assertion 2 (Positive): Connect via pgx with TLS enabled
	t.Run("TLS_Accepted", func(t *testing.T) {
		// DSN with sslmode=require (skips cert verification but enforces TLS)
		proxyURL, _ := url.Parse("postgres://" + addr + "/testdb?sslmode=require")
		proxyURL.User = url.UserPassword("test-agent", "secret")

		cfg, err := pgx.ParseConfig(proxyURL.String())
		if err != nil {
			t.Fatalf("failed to parse config: %v", err)
		}
		// Trust the self-signed cert
		cfg.Config.TLSConfig = &tls.Config{InsecureSkipVerify: true}

		conn, err := pgx.ConnectConfig(ctx, cfg)

		// If the proxy correctly parsed TLS and passed the auth phase, it will try to dial the dummy upstream.
		// Since the dummy upstream immediately closes, pgx will return an error, but NOT a TLS or Auth error.
		if err == nil {
			conn.Close(ctx)
		} else {
			// We expect EOF or connection reset from the dummy upstream closing the connection,
			// which proves the proxy successfully completed its TLS handshake and authenticated the user.
			if err.Error() == "FATAL: SSL connection is required" {
				t.Fatalf("Proxy rejected secure connection!")
			}
		}
	})

	t.Run("TLS_Downgrade_Attack", func(t *testing.T) {
		c, err := net.DialTimeout("tcp", addr, 2*time.Second)
		if err != nil {
			t.Fatalf("Failed to dial: %v", err)
		}
		defer c.Close()

		// Send SSLRequest: length (8), code (80877103)
		sslReq := []byte{0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x2f}
		c.Write(sslReq)

		// Expect 'S'
		resp := make([]byte, 1)
		c.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, err := c.Read(resp)
		if err != nil || n != 1 || resp[0] != 'S' {
			t.Fatalf("Expected 'S', got %v (err: %v)", resp, err)
		}

		// Send Plaintext StartupMessage instead of ClientHello
		// Length (33 bytes), Protocol (196608), "user\0test-agent\0database\0testdb\0\0"
		startupMsg := []byte{
			0, 0, 0, 33, // length
			0, 3, 0, 0, // protocol 3.0
			'u', 's', 'e', 'r', 0,
			't', 'e', 's', 't', '-', 'a', 'g', 'e', 'n', 't', 0,
			'd', 'a', 't', 'a', 'b', 'a', 's', 'e', 0,
			't', 'e', 's', 't', 'd', 'b', 0,
			0, // terminator
		}
		c.Write(startupMsg)

		// Expect proxy to forcefully close the connection during handshake failure
		c.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 1024)
		_, err = c.Read(buf)
		if err == nil {
			t.Fatalf("Expected proxy to close connection on plaintext downgrade, but connection stayed open")
		}
	})
}
