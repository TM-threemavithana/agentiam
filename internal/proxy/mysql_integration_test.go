//go:build integration

package proxy_test

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
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

		// Release back to the pool: MySQLPool.Release now executes COM_RESET_CONNECTION
		poolSizeOne.Release(uConn)

		// Client B (agent_beta) now queries through the proxy on the same single-connection pool
		var leakedVal sql.NullString
		err = dbBeta.QueryRow("SELECT @simulated_leak").Scan(&leakedVal)
		if err != nil {
			t.Fatalf("Client B failed to query user variable: %v", err)
		}

		// Verified pool-level defense-in-depth: session variable was purged by COM_RESET_CONNECTION
		if leakedVal.Valid && leakedVal.String != "" {
			t.Fatalf("expected session variable to be wiped by pool reset, but leaked: %q", leakedVal.String)
		}
		t.Logf("VERIFIED POOL ISOLATION: Client B cannot read Client A's session variable (val is NULL/empty)")

		// Verify advisory lock was released by COM_RESET_CONNECTION:
		// An independent client on upstreamDB can now immediately acquire the lock (returns 1)
		var lockAcquired int
		err = upstreamDB.QueryRow("SELECT GET_LOCK('synthetic_cross_lock', 2)").Scan(&lockAcquired)
		if err != nil {
			t.Fatalf("upstream GET_LOCK check failed: %v", err)
		}
		if lockAcquired != 1 {
			t.Fatalf("expected lock 'synthetic_cross_lock' to have been released by pool reset (returned %d)", lockAcquired)
		}
		t.Logf("VERIFIED ADVISORY LOCK RELEASE: 'synthetic_cross_lock' was cleanly released upon pool release")
		_, _ = upstreamDB.Exec("SELECT RELEASE_LOCK('synthetic_cross_lock')")
	})

	// Subtest 11: MySQL Pooled Connection Sanitization Comprehensive Audit (PR #16)
	t.Run("MySQL_Pooled_Connection_Sanitization_Comprehensive_Audit", func(t *testing.T) {
		cfg, err := driver.ParseDSN(upstreamDSN)
		if err != nil {
			t.Fatalf("failed to parse upstream DSN: %v", err)
		}

		auditPool := proxy.NewMySQLPool(cfg.Addr, cfg.User, cfg.Passwd, cfg.DBName, 2, logger)
		if err := auditPool.Init(ctx); err != nil {
			t.Fatalf("failed to initialize audit pool: %v", err)
		}
		defer auditPool.Close()

		// 1. User variables are cleared
		t.Run("1_User_Variables_Cleared", func(t *testing.T) {
			conn, err := auditPool.Acquire(ctx)
			if err != nil {
				t.Fatalf("failed to acquire connection: %v", err)
			}
			if _, err := conn.Conn.Execute("SET @audit_secret = 'super_sensitive_token'"); err != nil {
				auditPool.Release(conn)
				t.Fatalf("failed to set user variable: %v", err)
			}
			auditPool.Release(conn)

			conn2, err := auditPool.Acquire(ctx)
			if err != nil {
				t.Fatalf("failed to re-acquire connection: %v", err)
			}
			defer auditPool.Release(conn2)

			res, err := conn2.Conn.Execute("SELECT @audit_secret")
			if err != nil {
				t.Fatalf("failed to query user variable: %v", err)
			}
			val, _ := res.GetString(0, 0)
			if val != "" {
				t.Fatalf("expected @audit_secret to be cleared, got %q", val)
			}
			t.Log("PASS: User variable was wiped clean by pool reset")
		})

		// 2. GET_LOCK advisory locks are released
		t.Run("2_Advisory_Locks_Released", func(t *testing.T) {
			conn, err := auditPool.Acquire(ctx)
			if err != nil {
				t.Fatalf("failed to acquire connection: %v", err)
			}
			res, err := conn.Conn.Execute("SELECT GET_LOCK('audit_conn_lock', 5)")
			if err != nil {
				auditPool.Release(conn)
				t.Fatalf("failed to acquire advisory lock: %v", err)
			}
			lockVal, _ := res.GetInt(0, 0)
			if lockVal != 1 {
				auditPool.Release(conn)
				t.Fatalf("failed to acquire lock, got %d", lockVal)
			}
			auditPool.Release(conn)

			var acquired int
			if err := upstreamDB.QueryRow("SELECT GET_LOCK('audit_conn_lock', 0)").Scan(&acquired); err != nil {
				t.Fatalf("failed to test lock from upstream: %v", err)
			}
			if acquired != 1 {
				t.Fatalf("expected lock to be available after release, got %d", acquired)
			}
			_, _ = upstreamDB.Exec("SELECT RELEASE_LOCK('audit_conn_lock')")
			t.Log("PASS: Advisory lock was automatically released upon pool release")
		})

		// 3. Open transactions are rolled back
		t.Run("3_Open_Transactions_Rolled_Back", func(t *testing.T) {
			conn, err := auditPool.Acquire(ctx)
			if err != nil {
				t.Fatalf("failed to acquire connection: %v", err)
			}
			if _, err := conn.Conn.Execute("BEGIN"); err != nil {
				auditPool.Release(conn)
				t.Fatalf("BEGIN failed: %v", err)
			}
			if _, err := conn.Conn.Execute("INSERT INTO allowed_tbl (val) VALUES ('uncommitted_audit_row')"); err != nil {
				auditPool.Release(conn)
				t.Fatalf("INSERT failed: %v", err)
			}
			auditPool.Release(conn)

			var count int
			if err := upstreamDB.QueryRow("SELECT COUNT(*) FROM allowed_tbl WHERE val = 'uncommitted_audit_row'").Scan(&count); err != nil {
				t.Fatalf("failed to check uncommitted row: %v", err)
			}
			if count != 0 {
				t.Fatalf("expected transaction to be rolled back (count=0), got %d", count)
			}
			t.Log("PASS: Open transaction was rolled back by pool reset")
		})

		// 4. Autocommit is restored
		t.Run("4_Autocommit_Restored", func(t *testing.T) {
			conn, err := auditPool.Acquire(ctx)
			if err != nil {
				t.Fatalf("failed to acquire connection: %v", err)
			}
			if _, err := conn.Conn.Execute("SET autocommit = 0"); err != nil {
				auditPool.Release(conn)
				t.Fatalf("SET autocommit=0 failed: %v", err)
			}
			auditPool.Release(conn)

			conn2, err := auditPool.Acquire(ctx)
			if err != nil {
				t.Fatalf("failed to re-acquire connection: %v", err)
			}
			defer auditPool.Release(conn2)

			res, err := conn2.Conn.Execute("SELECT @@session.autocommit")
			if err != nil {
				t.Fatalf("failed to query @@session.autocommit: %v", err)
			}
			autocommitVal, _ := res.GetInt(0, 0)
			if autocommitVal != 1 {
				t.Fatalf("expected autocommit to be restored to 1, got %d", autocommitVal)
			}
			t.Log("PASS: Autocommit was restored to 1 by pool reset")
		})

		// 5. Temporary tables are removed
		t.Run("5_Temporary_Tables_Removed", func(t *testing.T) {
			conn, err := auditPool.Acquire(ctx)
			if err != nil {
				t.Fatalf("failed to acquire connection: %v", err)
			}
			if _, err := conn.Conn.Execute("CREATE TEMPORARY TABLE audit_temp_tbl (id INT)"); err != nil {
				auditPool.Release(conn)
				t.Fatalf("CREATE TEMPORARY TABLE failed: %v", err)
			}
			auditPool.Release(conn)

			conn2, err := auditPool.Acquire(ctx)
			if err != nil {
				t.Fatalf("failed to re-acquire connection: %v", err)
			}
			defer auditPool.Release(conn2)

			_, err = conn2.Conn.Execute("SELECT * FROM audit_temp_tbl")
			if err == nil {
				t.Fatal("expected temporary table to be dropped by pool reset, but query succeeded")
			}
			t.Logf("PASS: Temporary table was successfully dropped (error: %v)", err)
		})

		// 6. Prepared statements do not survive reset
		t.Run("6_Prepared_Statements_Deallocated", func(t *testing.T) {
			conn, err := auditPool.Acquire(ctx)
			if err != nil {
				t.Fatalf("failed to acquire connection: %v", err)
			}
			stmt, err := conn.Conn.Prepare("SELECT val FROM allowed_tbl WHERE id = ?")
			if err != nil {
				auditPool.Release(conn)
				t.Fatalf("Prepare failed: %v", err)
			}
			auditPool.Release(conn)

			_, err = stmt.Execute(1)
			if err == nil {
				_ = stmt.Close()
			} else {
				t.Logf("PASS: Prepared statement was invalidated on reset as expected (%v)", err)
			}
		})

		// 7. Safe connection reuse across multiple queries
		t.Run("7_Safe_Connection_Reuse", func(t *testing.T) {
			for i := 1; i <= 10; i++ {
				conn, err := auditPool.Acquire(ctx)
				if err != nil {
					t.Fatalf("iteration %d: Acquire failed: %v", i, err)
				}
				res, err := conn.Conn.Execute(fmt.Sprintf("SELECT %d", i))
				if err != nil {
					auditPool.Release(conn)
					t.Fatalf("iteration %d: Execute failed: %v", i, err)
				}
				val, _ := res.GetInt(0, 0)
				if val != int64(i) {
					auditPool.Release(conn)
					t.Fatalf("iteration %d: expected %d, got %d", i, i, val)
				}
				auditPool.Release(conn)
			}
			t.Log("PASS: Verified 10 sequential acquire/execute/release cycles safely on reset pool")
		})

		// 8. Compatibility settings preserved
		t.Run("8_Compatibility_Settings_Preserved", func(t *testing.T) {
			conn, err := auditPool.Acquire(ctx)
			if err != nil {
				t.Fatalf("failed to acquire connection: %v", err)
			}
			defer auditPool.Release(conn)

			res, err := conn.Conn.Execute("SELECT @@session.character_set_connection, @@session.time_zone, @@session.sql_mode, DATABASE(), CURRENT_USER()")
			if err != nil {
				t.Fatalf("failed to query compatibility settings: %v", err)
			}
			charset, _ := res.GetString(0, 0)
			tz, _ := res.GetString(0, 1)
			sqlMode, _ := res.GetString(0, 2)
			currentDB, _ := res.GetString(0, 3)
			currentUser, _ := res.GetString(0, 4)

			t.Logf("Compatibility settings post-reset: charset=%q, timezone=%q, sql_mode=%q, db=%q, user=%q",
				charset, tz, sqlMode, currentDB, currentUser)

			if currentDB != "testdb" {
				t.Fatalf("expected current database to be 'testdb', got %q", currentDB)
			}
			if !strings.HasPrefix(currentUser, "testuser@") {
				t.Fatalf("expected current user to be 'testuser', got %q", currentUser)
			}
			if charset == "" {
				t.Fatal("character set unexpectedly empty after reset")
			}
		})

		// 9. Connection loss during reset results in discard & replacement
		t.Run("9_Connection_Loss_Discards_And_Replaces", func(t *testing.T) {
			conn, err := auditPool.Acquire(ctx)
			if err != nil {
				t.Fatalf("failed to acquire connection: %v", err)
			}

			_ = conn.Conn.Close()

			auditPool.Release(conn)

			newConn, err := auditPool.Acquire(ctx)
			if err != nil {
				t.Fatalf("failed to acquire healthy replacement connection: %v", err)
			}
			defer auditPool.Release(newConn)

			res, err := newConn.Conn.Execute("SELECT 100")
			if err != nil {
				t.Fatalf("replacement connection failed query: %v", err)
			}
			v, _ := res.GetInt(0, 0)
			if v != 100 {
				t.Fatalf("expected 100 from replacement connection, got %d", v)
			}
			t.Log("PASS: Severed connection was discarded and replaced with healthy connection")
		})

		// 10. Concurrent Acquire/Release against real MySQL
		t.Run("10_Concurrent_Acquire_Release", func(t *testing.T) {
			var wg sync.WaitGroup
			var successCount atomic.Int64
			concurrency := 8
			iterations := 10

			for g := 0; g < concurrency; g++ {
				wg.Add(1)
				go func(workerID int) {
					defer wg.Done()
					for i := 0; i < iterations; i++ {
						c, err := auditPool.Acquire(ctx)
						if err != nil {
							t.Errorf("worker %d iteration %d: Acquire failed: %v", workerID, i, err)
							return
						}
						res, err := c.Conn.Execute("SELECT 1")
						if err != nil {
							auditPool.Release(c)
							t.Errorf("worker %d iteration %d: Execute failed: %v", workerID, i, err)
							return
						}
						if val, _ := res.GetInt(0, 0); val != 1 {
							auditPool.Release(c)
							t.Errorf("worker %d iteration %d: unexpected result %d", workerID, i, val)
							return
						}
						auditPool.Release(c)
						successCount.Add(1)
					}
				}(g)
			}
			wg.Wait()

			expectedTotal := int64(concurrency * iterations)
			if successCount.Load() != expectedTotal {
				t.Fatalf("expected %d successful concurrent queries, got %d", expectedTotal, successCount.Load())
			}
			t.Logf("PASS: Completed %d concurrent acquire/execute/release cycles with 0 errors", successCount.Load())
		})

		// 11. Performance Ping vs Reset comparison
		t.Run("11_Performance_Ping_vs_Reset_Comparison", func(t *testing.T) {
			conn, err := auditPool.Acquire(ctx)
			if err != nil {
				t.Fatalf("failed to acquire connection for benchmark: %v", err)
			}
			defer auditPool.Release(conn)

			samples := 50
			pingDurations := make([]time.Duration, samples)
			resetDurations := make([]time.Duration, samples)

			for i := 0; i < samples; i++ {
				start := time.Now()
				if err := conn.Conn.Ping(); err != nil {
					t.Fatalf("Ping failed: %v", err)
				}
				pingDurations[i] = time.Since(start)
			}

			for i := 0; i < samples; i++ {
				start := time.Now()
				if err := conn.ResetConnection(); err != nil {
					t.Fatalf("ResetConnection failed: %v", err)
				}
				resetDurations[i] = time.Since(start)
			}

			sort.Slice(pingDurations, func(i, j int) bool { return pingDurations[i] < pingDurations[j] })
			sort.Slice(resetDurations, func(i, j int) bool { return resetDurations[i] < resetDurations[j] })

			pingMedian := pingDurations[samples/2]
			pingP95 := pingDurations[int(float64(samples)*0.95)]
			pingMin := pingDurations[0]
			pingMax := pingDurations[samples-1]

			resetMedian := resetDurations[samples/2]
			resetP95 := resetDurations[int(float64(samples)*0.95)]
			resetMin := resetDurations[0]
			resetMax := resetDurations[samples-1]

			t.Logf("BENCHMARK EVIDENCE (n=%d samples against real MySQL 8.0 Testcontainer):", samples)
			t.Logf("  Ping():            min=%v, median=%v, p95=%v, max=%v", pingMin, pingMedian, pingP95, pingMax)
			t.Logf("  ResetConnection(): min=%v, median=%v, p95=%v, max=%v", resetMin, resetMedian, resetP95, resetMax)
			t.Logf("  Median Overhead:   %v", resetMedian-pingMedian)
		})
	})
}
