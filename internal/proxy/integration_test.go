package proxy_test

import (
	"context"
	"net"
	"net/url"
	"testing"
	"time"

	"agentiam/internal/policy"
	"agentiam/internal/proxy"

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
	store, err := policy.NewStore("file::memory:?cache=shared")
	if err != nil {
		t.Fatalf("failed to create policy store: %v", err)
	}
	// "test-agent" can only SELECT
	err = store.AddAgent("test-agent-key", "Test", []string{"SELECT"})
	if err != nil {
		t.Fatalf("failed to add agent: %v", err)
	}

	// 3. Start Proxy Server
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}

	_ = proxy.NewServer(l.Addr().String(), upstreamDSN, store)
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				session := proxy.NewSession(c, upstreamDSN, store)
				defer session.Close()
				session.Run()
			}(conn)
		}
	}()

	proxyURL, _ := url.Parse("postgres://127.0.0.1/testdb?sslmode=disable")
	proxyURL.Host = l.Addr().String()

	// Good DSN for test agent
	proxyURL.User = url.UserPassword("test-agent-key", "ignored")
	proxyDSN := proxyURL.String()

	// Bad DSN for auth failure test
	proxyURL.User = url.UserPassword("wrong-key", "ignored")
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
}
