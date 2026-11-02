//go:build integration

package proxy_test

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"os"
	"testing"
	"time"

	"github.com/tm-threemavithana/agentiam/internal/policy"
	"github.com/tm-threemavithana/agentiam/internal/proxy"

	_ "github.com/go-sql-driver/mysql"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/mysql"
	"github.com/testcontainers/testcontainers-go/wait"
)

func TestMySQLAdapterIntegration(t *testing.T) {
	ctx := context.Background()

	// 1. Spin up a real MySQL container
	mysqlContainer, err := mysql.Run(ctx,
		"mysql:8.0",
		mysql.WithDatabase("testdb"),
		mysql.WithUsername("testuser"),
		mysql.WithPassword("testpass"),
		testcontainers.WithWaitStrategy(
			wait.ForLog("port: 3306  MySQL Community Server").WithOccurrence(1).WithStartupTimeout(2*time.Minute)),
	)
	if err != nil {
		if os.Getenv("CI") != "" {
			t.Fatalf("failed to start mysql container in CI: %v", err)
		}
		t.Skipf("failed to start mysql container (skipping test): %v", err)
	}
	defer func() {
		if err := mysqlContainer.Terminate(ctx); err != nil {
			t.Fatalf("failed to terminate container: %s", err)
		}
	}()

	upstreamDSN, err := mysqlContainer.ConnectionString(ctx)
	if err != nil {
		t.Fatalf("failed to get connection string: %s", err)
	}

	logger := proxy.NewLogger(io.Discard)

	// 2. Setup AgentIAM Proxy with MySQL Dialect and policy allowing root client
	store, _ := policy.NewStore("", "", logger.Logger)
	store.SetAgentPolicy("root", policy.AgentConfig{
		Name:              "root",
		AllowedStatements: []string{"SELECT", "SHOW", "SET"},
		AllowedTables:     []string{"*"},
		Dialect:           "mysql",
	})

	handlers := make(map[proxy.ProtocolType]proxy.ProtocolHandler)
	// Bind to 127.0.0.1:0 to safely allocate an ephemeral port and avoid collisions
	srv := proxy.NewServer("127.0.0.1:0", upstreamDSN, store, nil, logger, nil, handlers, true, ":0", 5, nil, nil)
	mysqlHandler := proxy.NewMySQLProtocolHandler(store, logger, srv, true)
	srv.SetHandler(proxy.ProtocolMySQL, mysqlHandler)
	go srv.Start()
	defer srv.Shutdown(context.Background())

	// Poll until listener address is assigned
	var proxyAddr string
	for i := 0; i < 50; i++ {
		if addr := srv.Addr(); addr != nil {
			proxyAddr = addr.String()
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if proxyAddr == "" {
		t.Fatalf("timed out waiting for proxy server to start listening")
	}

	// 3. Connect to Proxy with go-sql-driver/mysql
	db, err := sql.Open("mysql", fmt.Sprintf("root@tcp(%s)/", proxyAddr))
	if err != nil {
		t.Fatalf("failed to connect to proxy: %v", err)
	}
	defer db.Close()

	// Assert ping succeeds against upstream through proxy
	err = db.Ping()
	if err != nil {
		t.Fatalf("failed to ping MySQL through proxy: %v", err)
	}

	// Verify executing a basic query through proxy
	var one int
	err = db.QueryRow("SELECT 1").Scan(&one)
	if err != nil {
		t.Fatalf("failed to execute SELECT 1 through proxy: %v", err)
	}
	if one != 1 {
		t.Fatalf("expected 1 from SELECT 1, got %d", one)
	}
}
