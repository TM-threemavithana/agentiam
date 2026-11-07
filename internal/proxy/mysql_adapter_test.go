package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync/atomic"
	"testing"

	driver "github.com/go-sql-driver/mysql"
	"github.com/tm-threemavithana/agentiam/internal/ast"
	"github.com/tm-threemavithana/agentiam/internal/cache"
	"github.com/tm-threemavithana/agentiam/internal/policy"
)

func TestMySQLHandler_HandleQuery_RulesEnforced(t *testing.T) {
	// Setup policy store
	discardLogger := slog.New(slog.NewTextHandler(io.Discard, nil))
	store, _ := policy.NewStore("", "", discardLogger)

	// Mock Server
	handlers := make(map[ProtocolType]ProtocolHandler)
	lc, _ := cache.NewLocalCache(10)
	srv := NewServer("127.0.0.1:0", "postgres://dummy", store, nil, NewLogger(io.Discard), lc, handlers, false, ":0", 5, nil, nil)

	store.SetAgentPolicy("test-agent", policy.AgentConfig{
		Name: "test-agent",
	})

	handler := &AgentIAMMySQLHandler{
		pool:     nil, // we won't query unless rules pass
		logger:   NewLogger(io.Discard),
		server:   srv,
		clientID: "test-agent",
		rules: ast.Rules{
			AllowedStatements: []string{"SELECT"},
			AllowedTables:     []string{"users"},
			BlockedFunctions:  []string{"sleep"},
		},
	}

	// 1. Blocked statement (DELETE)
	_, err := handler.HandleQuery("DELETE FROM users WHERE id = 1")
	if err == nil {
		t.Fatal("expected error for blocked DELETE statement, got nil")
	}
	if err.Error() != "policy violation: statement DELETE not allowed" {
		t.Errorf("unexpected error message: %v", err)
	}

	// 2. Blocked table
	_, err = handler.HandleQuery("SELECT * FROM passwords")
	if err == nil {
		t.Fatal("expected error for blocked table passwords, got nil")
	}
	if err.Error() != "policy violation: access to table passwords denied" {
		t.Errorf("unexpected error message: %v", err)
	}

	// 3. Blocked function
	_, err = handler.HandleQuery("SELECT sleep(5)")
	if err == nil {
		t.Fatal("expected error for blocked function sleep, got nil")
	}
	if err.Error() != "policy violation: function sleep is blocked" {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestMySQLAuthHandler_Authenticate(t *testing.T) {
	// Setup policy store
	discardLogger := slog.New(slog.NewTextHandler(io.Discard, nil))
	store, _ := policy.NewStore("", "", discardLogger)

	// Create test agent policy
	store.SetAgentPolicy("test-agent", policy.AgentConfig{
		Name:              "test-agent",
		Key:               "$2a$10$Qj2z5r/T5xX3mBveqXg.1.uG0o1o1o1o1o1o1o1o1o1o1o1o1o1o1", // mock bcrypt
		AllowedStatements: []string{"SELECT"},
	})

	proxyHandler := &AgentIAMMySQLHandler{}
	authHandlerInsecure := &AgentIAMAuthHandler{
		store:        store,
		logger:       NewLogger(bytes.NewBuffer(nil)),
		insecureAuth: true,
		mysqlHandler: proxyHandler,
	}

	// Verify GetCredential for root fallback in insecure mode
	cred, found, err := authHandlerInsecure.GetCredential("root")
	if err != nil {
		t.Fatalf("unexpected GetCredential error: %v", err)
	}
	if !found {
		t.Fatal("expected root user to be found when insecureAuth: true")
	}
	if cred.AuthPluginName != "mysql_native_password" {
		t.Errorf("expected mysql_native_password, got %s", cred.AuthPluginName)
	}

	// Verify GetCredential for configured agent in insecure mode
	cred, found, err = authHandlerInsecure.GetCredential("test-agent")
	if err != nil {
		t.Fatalf("unexpected GetCredential error: %v", err)
	}
	if !found {
		t.Fatal("expected test-agent to be found")
	}
	if cred.AuthPluginName != "mysql_native_password" {
		t.Errorf("expected mysql_native_password, got %s", cred.AuthPluginName)
	}

	// Verify GetCredential for unconfigured agent in insecure mode
	_, found, err = authHandlerInsecure.GetCredential("unknown-agent")
	if err != nil {
		t.Fatalf("unexpected GetCredential error: %v", err)
	}
	if found {
		t.Fatal("expected unknown-agent not to be found")
	}

	// Verify secure production mode (insecureAuth: false)
	authHandlerSecure := &AgentIAMAuthHandler{
		store:        store,
		logger:       NewLogger(bytes.NewBuffer(nil)),
		insecureAuth: false,
		mysqlHandler: proxyHandler,
	}

	// Root fallback MUST NOT exist in production mode
	_, found, err = authHandlerSecure.GetCredential("root")
	if err != nil {
		t.Fatalf("unexpected GetCredential error: %v", err)
	}
	if found {
		t.Fatal("expected root user NOT to be found when insecureAuth: false")
	}

	// Configured agent MUST be found in production mode for mTLS handshake
	cred, found, err = authHandlerSecure.GetCredential("test-agent")
	if err != nil {
		t.Fatalf("unexpected GetCredential error: %v", err)
	}
	if !found {
		t.Fatal("expected test-agent to be found in secure mode")
	}
	if cred.AuthPluginName != "mysql_native_password" {
		t.Errorf("expected mysql_native_password, got %s", cred.AuthPluginName)
	}
}

func TestMySQLMutualTLSAuthentication(t *testing.T) {
	// 1. Setup mock policy
	discardLogger := slog.New(slog.NewTextHandler(io.Discard, nil))
	store, err := policy.NewStore("", "", discardLogger)
	if err != nil {
		t.Fatalf("failed to create store: %v", err)
	}

	store.SetAgentPolicy("mtls-agent", policy.AgentConfig{
		Name:              "mtls-agent",
		Key:               "$2a$10$w3O1nZ5M2.uC8kC6aDXZM.V9r/6Z2m4V6n/zZ2m4V6n/zZ2m4V6n",
		AllowedStatements: []string{"SELECT"},
	})
	store.SetAgentPolicy("other-agent", policy.AgentConfig{
		Name:              "other-agent",
		Key:               "$2a$10$w3O1nZ5M2.uC8kC6aDXZM.V9r/6Z2m4V6n/zZ2m4V6n/zZ2m4V6n",
		AllowedStatements: []string{"INSERT"},
	})

	// 2. Setup Certificates
	serverCert, err := GenerateEphemeralCert()
	if err != nil {
		t.Fatalf("failed to generate server cert: %v", err)
	}

	caTlsCert, caX509, err := generateTestCA()
	if err != nil {
		t.Fatalf("failed to generate trusted CA: %v", err)
	}

	clientCert, err := generateTestClientCert(caX509, caTlsCert.PrivateKey, "mtls-agent")
	if err != nil {
		t.Fatalf("failed to generate client cert: %v", err)
	}

	caPool := x509.NewCertPool()
	caPool.AddCert(caX509)

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientCAs:    caPool,
		ClientAuth:   tls.VerifyClientCertIfGiven,
	}

	// 3. Start proxy listener with secure production setting (insecureAuth: false)
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}
	defer l.Close()
	proxyAddr := l.Addr().String()

	logger := NewLogger(io.Discard)
	handlers := make(map[ProtocolType]ProtocolHandler)
	srv := NewServer(proxyAddr, "mysql://dummy", store, tlsConfig, logger, nil, handlers, false, ":0", 5, nil, nil)
	mysqlHandler := NewMySQLProtocolHandler(store, logger, srv, false)
	// Provide a dummy initialized pool so HandleSession does not attempt upstream DSN connection
	mysqlHandler.pool = &MySQLPool{}
	srv.SetHandler(ProtocolMySQL, mysqlHandler)

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = mysqlHandler.HandleSession(context.Background(), c)
			}(conn)
		}
	}()

	var tlsCounter int64

	// Subtest 1: Valid client cert matches identity -> Accepted
	t.Run("Valid_Client_Cert_Accepted", func(t *testing.T) {
		idx := atomic.AddInt64(&tlsCounter, 1)
		tlsKey := fmt.Sprintf("valid-tls-%d", idx)
		err := driver.RegisterTLSConfig(tlsKey, &tls.Config{
			InsecureSkipVerify: true,
			Certificates:       []tls.Certificate{clientCert},
		})
		if err != nil {
			t.Fatalf("failed to register TLS config: %v", err)
		}

		db, err := sql.Open("mysql", fmt.Sprintf("mtls-agent@tcp(%s)/testdb?tls=%s", proxyAddr, tlsKey))
		if err != nil {
			t.Fatalf("failed to open mysql connection: %v", err)
		}
		defer db.Close()

		if err := db.Ping(); err != nil {
			t.Fatalf("expected ping to succeed with valid mTLS, got: %v", err)
		}
	})

	// Subtest 2: Missing client certificate in secure mode -> Rejected
	t.Run("Missing_Client_Cert_Rejected", func(t *testing.T) {
		idx := atomic.AddInt64(&tlsCounter, 1)
		tlsKey := fmt.Sprintf("no-cert-tls-%d", idx)
		err := driver.RegisterTLSConfig(tlsKey, &tls.Config{
			InsecureSkipVerify: true,
		})
		if err != nil {
			t.Fatalf("failed to register TLS config: %v", err)
		}

		db, err := sql.Open("mysql", fmt.Sprintf("mtls-agent@tcp(%s)/testdb?tls=%s", proxyAddr, tlsKey))
		if err != nil {
			t.Fatalf("failed to open mysql connection: %v", err)
		}
		defer db.Close()

		if err := db.Ping(); err == nil {
			t.Fatal("expected ping to fail when client cert is missing in secure mode, got nil")
		}
	})

	// Subtest 3: Untrusted client certificate -> Rejected by TLS verification
	t.Run("Untrusted_Client_Cert_Rejected", func(t *testing.T) {
		untrustedTlsCert, untrustedX509, err := generateTestCA()
		if err != nil {
			t.Fatalf("failed to generate untrusted CA: %v", err)
		}
		untrustedClientCert, err := generateTestClientCert(untrustedX509, untrustedTlsCert.PrivateKey, "mtls-agent")
		if err != nil {
			t.Fatalf("failed to generate untrusted client cert: %v", err)
		}

		idx := atomic.AddInt64(&tlsCounter, 1)
		tlsKey := fmt.Sprintf("untrusted-tls-%d", idx)
		err = driver.RegisterTLSConfig(tlsKey, &tls.Config{
			InsecureSkipVerify: true,
			Certificates:       []tls.Certificate{untrustedClientCert},
		})
		if err != nil {
			t.Fatalf("failed to register TLS config: %v", err)
		}

		db, err := sql.Open("mysql", fmt.Sprintf("mtls-agent@tcp(%s)/testdb?tls=%s", proxyAddr, tlsKey))
		if err != nil {
			t.Fatalf("failed to open mysql connection: %v", err)
		}
		defer db.Close()

		if err := db.Ping(); err == nil {
			t.Fatal("expected ping to fail with untrusted client cert, got nil")
		}
	})

	// Subtest 4: Identity spoofing (cert CN=mtls-agent, connects as other-agent) -> Rejected
	t.Run("CN_Mismatch_Impersonation_Rejected", func(t *testing.T) {
		idx := atomic.AddInt64(&tlsCounter, 1)
		tlsKey := fmt.Sprintf("spoof-tls-%d", idx)
		err := driver.RegisterTLSConfig(tlsKey, &tls.Config{
			InsecureSkipVerify: true,
			Certificates:       []tls.Certificate{clientCert}, // CN = "mtls-agent"
		})
		if err != nil {
			t.Fatalf("failed to register TLS config: %v", err)
		}

		// Connect as other-agent using mtls-agent's certificate
		db, err := sql.Open("mysql", fmt.Sprintf("other-agent@tcp(%s)/testdb?tls=%s", proxyAddr, tlsKey))
		if err != nil {
			t.Fatalf("failed to open mysql connection: %v", err)
		}
		defer db.Close()

		if err := db.Ping(); err == nil {
			t.Fatal("expected ping to fail on CN mismatch impersonation attempt, got nil")
		}
	})

	// Subtest 5: Unknown agent identity -> Rejected
	t.Run("Unknown_Agent_Identity_Rejected", func(t *testing.T) {
		idx := atomic.AddInt64(&tlsCounter, 1)
		tlsKey := fmt.Sprintf("unknown-tls-%d", idx)
		err := driver.RegisterTLSConfig(tlsKey, &tls.Config{
			InsecureSkipVerify: true,
			Certificates:       []tls.Certificate{clientCert},
		})
		if err != nil {
			t.Fatalf("failed to register TLS config: %v", err)
		}

		db, err := sql.Open("mysql", fmt.Sprintf("ghost-agent@tcp(%s)/testdb?tls=%s", proxyAddr, tlsKey))
		if err != nil {
			t.Fatalf("failed to open mysql connection: %v", err)
		}
		defer db.Close()

		if err := db.Ping(); err == nil {
			t.Fatal("expected ping to fail for unknown agent, got nil")
		}
	})

	// Subtest 6: Plaintext connection without TLS in secure mode -> Rejected
	t.Run("Plaintext_Connection_Rejected", func(t *testing.T) {
		db, err := sql.Open("mysql", fmt.Sprintf("mtls-agent@tcp(%s)/testdb", proxyAddr))
		if err != nil {
			t.Fatalf("failed to open mysql connection: %v", err)
		}
		defer db.Close()

		if err := db.Ping(); err == nil {
			t.Fatal("expected plaintext connection to fail when insecureAuth: false, got nil")
		}
	})
}

func TestMySQLProtocolHandler_InitPool_DSNValidation(t *testing.T) {
	logger := NewLogger(io.Discard)
	store, _ := policy.NewStore("", "", logger.Logger)

	// 1. Invalid/malformed DSN must fail closed without fallback
	handler := &MySQLProtocolHandler{
		store:       store,
		logger:      logger,
		upstreamDSN: "invalid-dsn-without-slash",
	}
	err := handler.InitPool()
	if err == nil {
		t.Fatal("expected error for malformed DSN, got nil")
	}

	// 2. Missing network address must fail closed
	handlerNoAddr := &MySQLProtocolHandler{
		store:       store,
		logger:      logger,
		upstreamDSN: "user:pass@/",
	}
	err = handlerNoAddr.InitPool()
	if err == nil {
		t.Fatal("expected error for missing network address, got nil")
	}
}
