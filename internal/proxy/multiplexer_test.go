//go:build integration

package proxy_test

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/postgres"
	"github.com/testcontainers/testcontainers-go/wait"
	"github.com/tm-threemavithana/agentiam/internal/policy"
	"github.com/tm-threemavithana/agentiam/internal/proxy"
	"golang.org/x/crypto/bcrypt"
)

func setupMultiplexerEnv(t *testing.T, poolMode string) (string, func()) {
	ctx := context.Background()

	// 1. Start Postgres Container
	pgContainer, err := postgres.Run(ctx,
		"postgres:15-alpine",
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

	// 2. Setup Policy Store with provided PoolMode
	hash, _ := bcrypt.GenerateFromPassword([]byte("test-agent-secret"), bcrypt.DefaultCost)
	yamlContent := fmt.Sprintf(`agents:
  - name: test-agent
    key: "%s"
    pool_mode: "%s"
    allowed_statements:
      - "SELECT"
      - "SET"
      - "SHOW"
`, string(hash), poolMode)
	tmpFile, _ := os.CreateTemp("", "policies-*.yaml")
	tmpFile.Write([]byte(yamlContent))
	tmpFile.Close()

	store, err := policy.NewStore(tmpFile.Name(), "", slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("failed to create policy store: %v", err)
	}

	// 3. Start Proxy Server with pool size 1 to force physical multiplexing
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to listen: %v", err)
	}

	logger := proxy.NewLogger(io.Discard)
	handlers := make(map[proxy.ProtocolType]proxy.ProtocolHandler)
	// pool size = 1 guarantees both test clients will fight for the same physical connection
	server := proxy.NewServer(l.Addr().String(), upstreamDSN, store, nil, logger, nil, handlers, false, ":0", 1, nil, nil)
	pgHandler := proxy.NewPostgresProtocolHandler(upstreamDSN, store, nil, logger, server, true)
	server.SetHandler(proxy.ProtocolPostgres, pgHandler)
	server.InitPool(context.Background())

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				session := proxy.NewSession(c, upstreamDSN, store, nil, logger, server, true)
				defer session.Close()
				session.Run()
			}(conn)
		}
	}()

	proxyURL, _ := url.Parse("postgres://127.0.0.1/testdb?sslmode=disable")
	proxyURL.Host = l.Addr().String()
	proxyURL.User = url.UserPassword("test-agent", "test-agent-secret")

	cleanup := func() {
		l.Close()
		pgContainer.Terminate(ctx)
		os.Remove(tmpFile.Name())
	}

	return proxyURL.String(), cleanup
}

func TestMultiplexer_StateReplay(t *testing.T) {
	proxyDSN, cleanup := setupMultiplexerEnv(t, "transaction")
	defer cleanup()

	ctx := context.Background()

	// Connect Client A
	connA, err := pgx.Connect(ctx, proxyDSN)
	if err != nil {
		t.Fatalf("Client A failed to connect: %v", err)
	}
	defer connA.Close(ctx)

	// Connect Client B
	connB, err := pgx.Connect(ctx, proxyDSN)
	if err != nil {
		t.Fatalf("Client B failed to connect: %v", err)
	}
	defer connB.Close(ctx)

	// 1. Client A sets timezone to Antarctica/Troll
	_, err = connA.Exec(ctx, "SET timezone TO 'Antarctica/Troll'")
	if err != nil {
		t.Fatalf("Client A SET failed: %v", err)
	}

	// 2. Client B sets timezone to UTC
	_, err = connB.Exec(ctx, "SET timezone TO 'UTC'")
	if err != nil {
		t.Fatalf("Client B SET failed: %v", err)
	}

	// 3. Client A checks timezone (AgentIAM should replay Antarctica/Troll state)
	var tz int
	var tzStr string
	err = connA.QueryRow(ctx, "SHOW timezone").Scan(&tzStr)
	if err != nil {
		t.Fatalf("Client A SHOW failed: %v", err)
	}
	if tzStr != "Antarctica/Troll" {
		t.Errorf("Expected Client A timezone 'Antarctica/Troll', got '%s'", tzStr)
	}

	// 4. Client B checks timezone (AgentIAM should replay UTC state)
	err = connB.QueryRow(ctx, "SHOW timezone").Scan(&tzStr)
	if err != nil {
		t.Fatalf("Client B SHOW failed: %v", err)
	}
	if tzStr != "UTC" {
		t.Errorf("Expected Client B timezone 'UTC', got '%s'", tzStr)
	}
	
	// Print test logic block dummy variable to ignore unused
	_ = tz
}
