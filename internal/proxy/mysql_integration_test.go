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

	driver "github.com/go-sql-driver/mysql"
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

	// 3. Setup AgentIAM Proxy with MySQL Dialect and policy configurations
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
	store.SetAgentPolicy("permissive_agent", policy.AgentConfig{
		Name:              "permissive_agent",
		AllowedStatements: []string{"SELECT", "BEGIN", "COMMIT", "ROLLBACK", "SET", "CREATE", "LOCK", "*"},
		AllowedTables:     []string{"*"},
		SelectLimit:       10,
		Dialect:           "mysql",
	})
	store.SetAgentPolicy("agent_alpha", policy.AgentConfig{
		Name:              "agent_alpha",
		AllowedStatements: []string{"SELECT"},
		AllowedTables:     []string{"allowed_tbl"},
		SelectLimit:       10,
		Dialect:           "mysql",
	})
	store.SetAgentPolicy("agent_beta", policy.AgentConfig{
		Name:              "agent_beta",
		AllowedStatements: []string{"SELECT"},
		AllowedTables:     []string{"allowed_tbl"},
		SelectLimit:       10,
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
	// Validates fail-closed behavior under BOTH standard policy AND overly permissive policy
	t.Run("Unsupported_Transaction_And_Session_Operations", func(t *testing.T) {
		dbStandard, err := sql.Open("mysql", fmt.Sprintf("root@tcp(%s)/testdb", proxyAddr))
		if err != nil {
			t.Fatalf("failed to connect as root: %v", err)
		}
		defer dbStandard.Close()

		dbPermissive, err := sql.Open("mysql", fmt.Sprintf("permissive_agent@tcp(%s)/testdb", proxyAddr))
		if err != nil {
			t.Fatalf("failed to connect as permissive_agent: %v", err)
		}
		defer dbPermissive.Close()

		ops := []struct {
			name        string
			fn          func(db *sql.DB) error
			expectedErr string
		}{
			{
				name: "1. START TRANSACTION blocked",
				fn: func(db *sql.DB) error {
					_, err := db.Exec("START TRANSACTION")
					return err
				},
				expectedErr: "statement BEGIN not allowed",
			},
			{
				name: "2. BEGIN blocked",
				fn: func(db *sql.DB) error {
					_, err := db.Exec("BEGIN")
					return err
				},
				expectedErr: "statement BEGIN not allowed",
			},
			{
				name: "3. COMMIT blocked",
				fn: func(db *sql.DB) error {
					_, err := db.Exec("COMMIT")
					return err
				},
				expectedErr: "statement COMMIT not allowed",
			},
			{
				name: "4. ROLLBACK blocked",
				fn: func(db *sql.DB) error {
					_, err := db.Exec("ROLLBACK")
					return err
				},
				expectedErr: "statement ROLLBACK not allowed",
			},
			{
				name: "5. SET autocommit = 0 blocked",
				fn: func(db *sql.DB) error {
					_, err := db.Exec("SET autocommit = 0")
					return err
				},
				expectedErr: "statement SET not allowed",
			},
			{
				name: "6. SET session variable blocked",
				fn: func(db *sql.DB) error {
					_, err := db.Exec("SET @session_variable = 'value'")
					return err
				},
				expectedErr: "statement SET not allowed",
			},
			{
				name: "7. CREATE TEMPORARY TABLE blocked",
				fn: func(db *sql.DB) error {
					_, err := db.Exec("CREATE TEMPORARY TABLE temp_tbl (id INT)")
					return err
				},
				expectedErr: "statement CREATE TEMPORARY TABLE not allowed",
			},
			{
				name: "8. LOCK TABLES blocked",
				fn: func(db *sql.DB) error {
					_, err := db.Exec("LOCK TABLES allowed_tbl WRITE")
					return err
				},
				expectedErr: "statement LOCK not allowed",
			},
			{
				name: "9. Binary prepared statements (db.Prepare) unsupported",
				fn: func(db *sql.DB) error {
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
				fn: func(db *sql.DB) error {
					_, err := db.Exec("SELECT 1; SELECT 2")
					return err
				},
				expectedErr: "multiple statements not allowed",
			},
		}

		for _, op := range ops {
			t.Run("StandardPolicy_"+op.name, func(t *testing.T) {
				err := op.fn(dbStandard)
				if err == nil {
					t.Fatalf("expected operation %s to fail under standard policy, but it succeeded", op.name)
				}
				if !strings.Contains(err.Error(), op.expectedErr) {
					t.Fatalf("expected error containing %q, got: %v", op.expectedErr, err)
				}
			})

			// Regression check: verify fail-closed enforcement even under permissive policy
			t.Run("PermissivePolicy_"+op.name, func(t *testing.T) {
				err := op.fn(dbPermissive)
				if err == nil {
					t.Fatalf("CRITICAL SECURITY REGRESSION: operation %s succeeded under permissive policy", op.name)
				}
				if !strings.Contains(err.Error(), op.expectedErr) {
					t.Fatalf("expected error containing %q, got: %v", op.expectedErr, err)
				}
			})
		}
	})

	// Subtest 9: Unsafe Session-Mutating Expressions Blocked at AST Level (Part 3 & Part 5)
	t.Run("Unsafe_Session_Mutating_Expressions_Blocked", func(t *testing.T) {
		db, err := sql.Open("mysql", fmt.Sprintf("root@tcp(%s)/testdb", proxyAddr))
		if err != nil {
			t.Fatalf("failed to connect: %v", err)
		}
		defer db.Close()

		// 1. SELECT @var := 'value' must be rejected
		_, err = db.Exec("SELECT @var := 'leak_test'")
		if err == nil {
			t.Fatal("expected SELECT with variable assignment to be blocked, but it succeeded")
		}
		if !strings.Contains(err.Error(), "variable assignment not allowed") {
			t.Fatalf("expected variable assignment error, got: %v", err)
		}

		// 2. WHERE clause with variable assignment must be rejected
		_, err = db.Exec("SELECT * FROM allowed_tbl WHERE (@leak := 1) = 1")
		if err == nil {
			t.Fatal("expected WHERE clause variable assignment to be blocked, but it succeeded")
		}
		if !strings.Contains(err.Error(), "variable assignment not allowed") {
			t.Fatalf("expected variable assignment error, got: %v", err)
		}

		// 3. User advisory locks (GET_LOCK, RELEASE_LOCK, RELEASE_ALL_LOCKS) must be rejected
		_, err = db.Exec("SELECT GET_LOCK('agentiam_audit_lock', 5)")
		if err == nil {
			t.Fatal("expected GET_LOCK to be blocked, but it succeeded")
		}
		if !strings.Contains(err.Error(), "advisory locking unsupported") && !strings.Contains(err.Error(), "function GET_LOCK is blocked") {
			t.Fatalf("expected advisory locking error, got: %v", err)
		}

		_, err = db.Exec("SELECT RELEASE_LOCK('agentiam_audit_lock')")
		if err == nil {
			t.Fatal("expected RELEASE_LOCK to be blocked, but it succeeded")
		}
		if !strings.Contains(err.Error(), "advisory locking unsupported") && !strings.Contains(err.Error(), "function RELEASE_LOCK is blocked") {
			t.Fatalf("expected advisory locking error, got: %v", err)
		}

		_, err = db.Exec("SELECT RELEASE_ALL_LOCKS()")
		if err == nil {
			t.Fatal("expected RELEASE_ALL_LOCKS to be blocked, but it succeeded")
		}
		if !strings.Contains(err.Error(), "advisory locking unsupported") && !strings.Contains(err.Error(), "function RELEASE_ALL_LOCKS is blocked") {
			t.Fatalf("expected advisory locking error, got: %v", err)
		}

		// 4. Safe expressions must be preserved
		var connID int64
		if err := db.QueryRow("SELECT CONNECTION_ID()").Scan(&connID); err != nil {
			t.Fatalf("SELECT CONNECTION_ID() failed: %v", err)
		}
		if connID <= 0 {
			t.Fatalf("expected valid CONNECTION_ID, got %d", connID)
		}

		var nullVar sql.NullString
		if err := db.QueryRow("SELECT @unassigned_var").Scan(&nullVar); err != nil {
			t.Fatalf("SELECT read-only user variable failed: %v", err)
		}
		if nullVar.Valid {
			t.Fatalf("expected NULL for unassigned user variable, got %s", nullVar.String)
		}
	})

	// Subtest 10: Deterministic Cross-Client Session Isolation and Leakage Audit (Part 2)
	t.Run("Cross_Client_Session_Isolation_Deterministic_Audit", func(t *testing.T) {
		// Parse upstream DSN to configure a dedicated pool of size 1
		cfg, err := driver.ParseDSN(upstreamDSN)
		if err != nil {
			t.Fatalf("failed to parse upstream DSN: %v", err)
		}

		poolSizeOne := proxy.NewMySQLPool(cfg.Addr, cfg.User, cfg.Passwd, cfg.DBName, 1, logger)
		if err := poolSizeOne.Init(ctx); err != nil {
			t.Fatalf("failed to initialize pool of size 1: %v", err)
		}
		defer poolSizeOne.Close()

		// Dedicated proxy server sharing the pool of size 1
		p1Handlers := make(map[proxy.ProtocolType]proxy.ProtocolHandler)
		p1Srv := proxy.NewServer("127.0.0.1:0", upstreamDSN, store, nil, logger, nil, p1Handlers, true, ":0", 5, nil, nil)
		p1MySQLHandler := proxy.NewMySQLProtocolHandler(store, logger, p1Srv, true)
		p1MySQLHandler.SetPool(poolSizeOne)
		p1Srv.SetHandler(proxy.ProtocolMySQL, p1MySQLHandler)
		go p1Srv.Start()
		defer p1Srv.Shutdown(context.Background())

		var p1Addr string
		for i := 0; i < 50; i++ {
			if addr := p1Srv.Addr(); addr != nil {
				p1Addr = addr.String()
				break
			}
			time.Sleep(50 * time.Millisecond)
		}
		if p1Addr == "" {
			t.Fatalf("timed out waiting for 1-pool proxy server to start")
		}

		// Connect Client A (agent_alpha) and Client B (agent_beta)
		dbAlpha, err := sql.Open("mysql", fmt.Sprintf("agent_alpha@tcp(%s)/testdb", p1Addr))
		if err != nil {
			t.Fatalf("failed to connect as agent_alpha: %v", err)
		}
		defer dbAlpha.Close()

		dbBeta, err := sql.Open("mysql", fmt.Sprintf("agent_beta@tcp(%s)/testdb", p1Addr))
		if err != nil {
			t.Fatalf("failed to connect as agent_beta: %v", err)
		}
		defer dbBeta.Close()

		// Step 1: Verify Client A is PREVENTED by proxy AST from injecting session variables
		_, err = dbAlpha.Exec("SELECT @cross_token := 'synthetic_alpha_secret'")
		if err == nil {
			t.Fatal("expected Client A variable assignment to be rejected by proxy AST, got nil")
		}
		if !strings.Contains(err.Error(), "variable assignment not allowed") {
			t.Fatalf("expected variable assignment error, got: %v", err)
		}

		// Step 2: Verify Client A is PREVENTED by proxy AST from acquiring advisory locks
		_, err = dbAlpha.Exec("SELECT GET_LOCK('synthetic_cross_lock', 5)")
		if err == nil {
			t.Fatal("expected Client A GET_LOCK to be rejected by proxy AST, got nil")
		}
		if !strings.Contains(err.Error(), "advisory locking unsupported") && !strings.Contains(err.Error(), "function GET_LOCK is blocked") {
			t.Fatalf("expected advisory locking error, got: %v", err)
		}

		// Step 3: Empirically demonstrate the underlying pool vulnerability when state is present:
		// Directly dirty the single pooled connection to test whether MySQLPool.Release cleanses state.
		uConn, err := poolSizeOne.Acquire(ctx)
		if err != nil {
			t.Fatalf("failed to acquire raw pooled connection: %v", err)
		}

		// Set a synthetic session variable and acquire an advisory lock on the connection
		_, err = uConn.Conn.Execute("SELECT @simulated_leak := 'synthetic_alpha_secret'")
		if err != nil {
			poolSizeOne.Release(uConn)
			t.Fatalf("failed to execute variable assignment on raw connection: %v", err)
		}
		_, err = uConn.Conn.Execute("SELECT GET_LOCK('synthetic_cross_lock', 5)")
		if err != nil {
			poolSizeOne.Release(uConn)
			t.Fatalf("failed to execute GET_LOCK on raw connection: %v", err)
		}

		// Release back to the pool: MySQLPool.Release only calls Ping(), not COM_RESET_CONNECTION
		poolSizeOne.Release(uConn)

		// Client B (agent_beta) now queries through the proxy on the same single-connection pool
		var leakedVal sql.NullString
		err = dbBeta.QueryRow("SELECT @simulated_leak").Scan(&leakedVal)
		if err != nil {
			t.Fatalf("Client B failed to query user variable: %v", err)
		}

		// Confirmation of reproduced cross-client leakage on unsanitized pool connection
		if leakedVal.Valid && leakedVal.String == "synthetic_alpha_secret" {
			t.Logf("CONFIRMED REPRODUCED LEAKAGE: Client B read Client A's session variable: %q", leakedVal.String)
		} else {
			t.Fatalf("expected reproduced leakage of 'synthetic_alpha_secret', got %v", leakedVal)
		}

		// Verify advisory lock is still held by the pooled connection:
		// An independent client on upstreamDB cannot acquire the lock (returns 0)
		var lockAcquired int
		err = upstreamDB.QueryRow("SELECT GET_LOCK('synthetic_cross_lock', 0)").Scan(&lockAcquired)
		if err != nil {
			t.Fatalf("upstream GET_LOCK check failed: %v", err)
		}
		if lockAcquired != 0 {
			t.Fatalf("expected lock 'synthetic_cross_lock' to remain held by pooled connection (returned %d)", lockAcquired)
		}
		t.Logf("CONFIRMED REPRODUCED LOCK RETENTION: 'synthetic_cross_lock' remains held by idle pooled connection")

		// Reliable cleanup after test
		uClean, err := poolSizeOne.Acquire(ctx)
		if err == nil {
			_, _ = uClean.Conn.Execute("SELECT RELEASE_LOCK('synthetic_cross_lock')")
			_, _ = uClean.Conn.Execute("SET @simulated_leak = NULL")
			poolSizeOne.Release(uClean)
		}
		_, _ = upstreamDB.Exec("SELECT RELEASE_ALL_LOCKS()")
	})
}
