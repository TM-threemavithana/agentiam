//go:build integration

package proxy_test

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"os"
	"strings"
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

	// 2. Pre-seed database directly upstream
	upstreamDB, err := sql.Open("mysql", upstreamDSN)
	if err != nil {
		t.Fatalf("failed to connect directly to upstream MySQL: %v", err)
	}
	defer upstreamDB.Close()

	_, err = upstreamDB.Exec(`CREATE TABLE IF NOT EXISTS allowed_tbl (id INT AUTO_INCREMENT PRIMARY KEY, val VARCHAR(50))`)
	if err != nil {
		t.Fatalf("failed to create allowed_tbl: %v", err)
	}
	_, err = upstreamDB.Exec(`CREATE TABLE IF NOT EXISTS secret_tbl (id INT AUTO_INCREMENT PRIMARY KEY, secret VARCHAR(50))`)
	if err != nil {
		t.Fatalf("failed to create secret_tbl: %v", err)
	}

	for i := 1; i <= 20; i++ {
		_, err = upstreamDB.Exec(fmt.Sprintf("INSERT INTO allowed_tbl (val) VALUES ('item-%d')", i))
		if err != nil {
			t.Fatalf("failed to seed allowed_tbl: %v", err)
		}
	}

	logger := proxy.NewLogger(io.Discard)

	// 3. Setup AgentIAM Proxy with MySQL Dialect and policy allowing root client
	store, _ := policy.NewStore("", "", logger.Logger)
	store.SetAgentPolicy("root", policy.AgentConfig{
		Name:              "root",
		AllowedStatements: []string{"SELECT"},
		AllowedTables:     []string{"allowed_tbl"},
		SelectLimit:       10,
		Dialect:           "mysql",
	})
	store.SetAgentPolicy("restricted_agent", policy.AgentConfig{
		Name:              "restricted_agent",
		AllowedStatements: []string{"SELECT"},
		AllowedTables:     []string{"other_tbl"},
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

	// Subtest 1: Valid Agent Credentials & Clean SELECT
	t.Run("Valid_Credentials_Clean_Select", func(t *testing.T) {
		db, err := sql.Open("mysql", fmt.Sprintf("root@tcp(%s)/testdb", proxyAddr))
		if err != nil {
			t.Fatalf("failed to connect to proxy: %v", err)
		}
		defer db.Close()

		var one int
		if err := db.QueryRow("SELECT 1").Scan(&one); err != nil {
			t.Fatalf("failed to execute SELECT 1 through proxy: %v", err)
		}
		if one != 1 {
			t.Fatalf("expected 1, got %d", one)
		}
	})

	// Subtest 2: Invalid Password Rejected
	t.Run("Invalid_Password_Rejected", func(t *testing.T) {
		badDB, err := sql.Open("mysql", fmt.Sprintf("root:wrongpass@tcp(%s)/testdb", proxyAddr))
		if err != nil {
			t.Fatalf("failed to open mysql with bad pass: %v", err)
		}
		defer badDB.Close()

		err = badDB.Ping()
		if err == nil {
			t.Fatal("expected authentication error with wrong password, got nil")
		}
	})

	// Subtest 3: Unknown Agent Identity Rejected
	t.Run("Unknown_Agent_Identity_Rejected", func(t *testing.T) {
		unknownDB, err := sql.Open("mysql", fmt.Sprintf("unknown_agent@tcp(%s)/testdb", proxyAddr))
		if err != nil {
			t.Fatalf("failed to open mysql with unknown agent: %v", err)
		}
		defer unknownDB.Close()

		err = unknownDB.Ping()
		if err == nil {
			t.Fatal("expected authentication error with unknown agent, got nil")
		}
	})

	// Subtest 4: Missing or Unconfigured Policy Rejected
	t.Run("Missing_Policy_Configuration_Rejected", func(t *testing.T) {
		// Server with empty store (root unconfigured)
		emptyStore, _ := policy.NewStore("", "", logger.Logger)
		emptyHandlers := make(map[proxy.ProtocolType]proxy.ProtocolHandler)
		emptySrv := proxy.NewServer("127.0.0.1:0", upstreamDSN, emptyStore, nil, logger, nil, emptyHandlers, true, ":0", 5, nil, nil)
		emptyMySQLHandler := proxy.NewMySQLProtocolHandler(emptyStore, logger, emptySrv, true)
		emptySrv.SetHandler(proxy.ProtocolMySQL, emptyMySQLHandler)
		go emptySrv.Start()
		defer emptySrv.Shutdown(context.Background())

		var emptyAddr string
		for i := 0; i < 50; i++ {
			if addr := emptySrv.Addr(); addr != nil {
				emptyAddr = addr.String()
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
		if emptyAddr == "" {
			t.Fatalf("timed out waiting for empty proxy server to start")
		}

		db, err := sql.Open("mysql", fmt.Sprintf("root@tcp(%s)/testdb", emptyAddr))
		if err != nil {
			t.Fatalf("failed to open mysql: %v", err)
		}
		defer db.Close()

		err = db.Ping()
		if err == nil {
			t.Fatal("expected handshake rejection for agent missing policy configuration, got nil")
		}
	})

	// Subtest 5: Prohibited SQL Statement Blocked
	t.Run("Prohibited_Statement_Blocked", func(t *testing.T) {
		db, err := sql.Open("mysql", fmt.Sprintf("root@tcp(%s)/testdb", proxyAddr))
		if err != nil {
			t.Fatalf("failed to connect: %v", err)
		}
		defer db.Close()

		_, err = db.Exec("DELETE FROM allowed_tbl WHERE id = 1")
		if err == nil {
			t.Fatal("expected policy error for DELETE statement, got nil")
		}
		if !strings.Contains(err.Error(), "statement DELETE not allowed") {
			t.Fatalf("unexpected error message: %v", err)
		}

		_, err = db.Exec("DROP TABLE allowed_tbl")
		if err == nil {
			t.Fatal("expected policy error for DROP statement, got nil")
		}
		if !strings.Contains(err.Error(), "not allowed") {
			t.Fatalf("unexpected error message: %v", err)
		}
	})

	// Subtest 6: Disallowed Table Blocked
	t.Run("Disallowed_Table_Blocked", func(t *testing.T) {
		db, err := sql.Open("mysql", fmt.Sprintf("root@tcp(%s)/testdb", proxyAddr))
		if err != nil {
			t.Fatalf("failed to connect: %v", err)
		}
		defer db.Close()

		_, err = db.Query("SELECT * FROM secret_tbl")
		if err == nil {
			t.Fatal("expected policy error for querying disallowed table secret_tbl, got nil")
		}
		if !strings.Contains(err.Error(), "access to table secret_tbl denied") {
			t.Fatalf("unexpected error message: %v", err)
		}
	})

	// Subtest 7: Excessive LIMIT Clamped through Proxy
	t.Run("Excessive_Limit_Clamped", func(t *testing.T) {
		db, err := sql.Open("mysql", fmt.Sprintf("root@tcp(%s)/testdb", proxyAddr))
		if err != nil {
			t.Fatalf("failed to connect: %v", err)
		}
		defer db.Close()

		// Policy enforces SelectLimit = 10; query requests 100 rows from a table with 20 rows
		rows, err := db.Query("SELECT id FROM allowed_tbl LIMIT 100")
		if err != nil {
			t.Fatalf("SELECT with excessive LIMIT failed: %v", err)
		}
		defer rows.Close()

		count := 0
		for rows.Next() {
			count++
		}
		if err := rows.Err(); err != nil {
			t.Fatalf("error iterating rows: %v", err)
		}
		if count != 10 {
			t.Fatalf("expected LIMIT 100 to be clamped to 10 rows, got %d rows", count)
		}
	})

	// Subtest 8: Unsupported Transaction & Session Operations Fail-Closed
	t.Run("Unsupported_Transaction_And_Session_Operations", func(t *testing.T) {
		db, err := sql.Open("mysql", fmt.Sprintf("root@tcp(%s)/testdb", proxyAddr))
		if err != nil {
			t.Fatalf("failed to connect: %v", err)
		}
		defer db.Close()

		ops := []struct {
			name        string
			fn          func() error
			expectedErr string
		}{
			{
				name: "1. START TRANSACTION blocked",
				fn: func() error {
					_, err := db.Exec("START TRANSACTION")
					return err
				},
				expectedErr: "statement BEGIN not allowed",
			},
			{
				name: "2. BEGIN blocked",
				fn: func() error {
					_, err := db.Exec("BEGIN")
					return err
				},
				expectedErr: "statement BEGIN not allowed",
			},
			{
				name: "3. COMMIT blocked",
				fn: func() error {
					_, err := db.Exec("COMMIT")
					return err
				},
				expectedErr: "statement COMMIT not allowed",
			},
			{
				name: "4. ROLLBACK blocked",
				fn: func() error {
					_, err := db.Exec("ROLLBACK")
					return err
				},
				expectedErr: "statement ROLLBACK not allowed",
			},
			{
				name: "5. SET autocommit = 0 blocked",
				fn: func() error {
					_, err := db.Exec("SET autocommit = 0")
					return err
				},
				expectedErr: "statement SET not allowed",
			},
			{
				name: "6. SET session variable blocked",
				fn: func() error {
					_, err := db.Exec("SET @session_variable = 'value'")
					return err
				},
				expectedErr: "statement SET not allowed",
			},
			{
				name: "7. CREATE TEMPORARY TABLE blocked",
				fn: func() error {
					_, err := db.Exec("CREATE TEMPORARY TABLE temp_tbl (id INT)")
					return err
				},
				expectedErr: "statement CREATE not allowed",
			},
			{
				name: "8. LOCK TABLES blocked",
				fn: func() error {
					_, err := db.Exec("LOCK TABLES allowed_tbl WRITE")
					return err
				},
				expectedErr: "statement LOCK not allowed",
			},
			{
				name: "9. Binary prepared statements (db.Prepare) unsupported",
				fn: func() error {
					stmt, err := db.Prepare("SELECT id FROM allowed_tbl WHERE id = ?")
					if err == nil {
						stmt.Close()
					}
					return err
				},
				expectedErr: "not supported now",
			},
			{
				name: "10. Multiple SQL statements in one request blocked",
				fn: func() error {
					_, err := db.Exec("SELECT 1; SELECT 2")
					return err
				},
				expectedErr: "multiple statements not allowed",
			},
		}

		for _, op := range ops {
			t.Run(op.name, func(t *testing.T) {
				err := op.fn()
				if err == nil {
					t.Fatalf("expected operation %s to fail, but it succeeded", op.name)
				}
				if !strings.Contains(err.Error(), op.expectedErr) {
					t.Fatalf("expected error containing %q, got: %v", op.expectedErr, err)
				}
			})
		}
	})

	// Subtest 9: Permitted SELECT Side Effects and Session Isolation Investigation
	t.Run("Permitted_SELECT_Side_Effects", func(t *testing.T) {
		db, err := sql.Open("mysql", fmt.Sprintf("root@tcp(%s)/testdb", proxyAddr))
		if err != nil {
			t.Fatalf("failed to connect: %v", err)
		}
		defer db.Close()

		// 1. SELECT @var := 'value' executes upstream because it is parsed as SELECT
		var setVal string
		err = db.QueryRow("SELECT @var := 'leak_test'").Scan(&setVal)
		if err != nil {
			t.Fatalf("SELECT @var := 'leak_test' failed: %v", err)
		}
		if setVal != "leak_test" {
			t.Errorf("expected @var to be 'leak_test', got %s", setVal)
		}

		// 2. SELECT CONNECTION_ID() reveals connection hopping across pooled connections
		var connID1, connID2 int64
		if err := db.QueryRow("SELECT CONNECTION_ID()").Scan(&connID1); err != nil {
			t.Fatalf("SELECT CONNECTION_ID() #1 failed: %v", err)
		}
		if err := db.QueryRow("SELECT CONNECTION_ID()").Scan(&connID2); err != nil {
			t.Fatalf("SELECT CONNECTION_ID() #2 failed: %v", err)
		}
		t.Logf("Observed MySQL connection IDs: #1=%d, #2=%d", connID1, connID2)

		// 3. User advisory locks (GET_LOCK / RELEASE_LOCK)
		var getLockRes sql.NullInt64
		err = db.QueryRow("SELECT GET_LOCK('agentiam_audit_lock', 5)").Scan(&getLockRes)
		if err != nil {
			t.Fatalf("GET_LOCK failed: %v", err)
		}
		if !getLockRes.Valid || getLockRes.Int64 != 1 {
			t.Fatalf("expected GET_LOCK to return 1, got %v", getLockRes)
		}

		// Try releasing the lock; because of connection hopping across pooled connections,
		// RELEASE_LOCK will return 0 (not owner of lock) if it lands on a different pooled connection.
		var relLockRes sql.NullInt64
		err = db.QueryRow("SELECT RELEASE_LOCK('agentiam_audit_lock')").Scan(&relLockRes)
		if err != nil {
			t.Fatalf("RELEASE_LOCK failed: %v", err)
		}
		t.Logf("RELEASE_LOCK returned: %v (1 = released on same conn, 0 = lock not held by this connection)", relLockRes)
	})
}
