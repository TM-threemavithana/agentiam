package ast

import (
	"strings"
	"testing"

	"github.com/tm-threemavithana/agentiam/internal/cache"
)

func TestMySQLParser_ApplyRules(t *testing.T) {
	rules := Rules{
		AllowedStatements:  []string{"SELECT", "INSERT", "UPDATE"},
		AllowedTables:      []string{"users", "orders"},
		BlockedFunctions:   []string{"sleep"},
		EnforceSelectLimit: 10,
	}

	tests := []struct {
		name          string
		sql           string
		expectBlocked bool
		expectSQL     string
	}{
		{
			name:          "Allowed SELECT on allowed table",
			sql:           "SELECT * FROM users",
			expectBlocked: false,
			expectSQL:     "SELECT * FROM `users` LIMIT 10",
		},
		{
			name:          "Allowed INSERT on allowed table",
			sql:           "INSERT INTO orders (id) VALUES (1)",
			expectBlocked: false,
			expectSQL:     "INSERT INTO `orders` (`id`) VALUES (1)",
		},
		{
			name:          "Blocked DELETE statement",
			sql:           "DELETE FROM users",
			expectBlocked: true,
		},
		{
			name:          "Blocked SELECT on blocked table",
			sql:           "SELECT * FROM secrets",
			expectBlocked: true,
		},
		{
			name:          "Multiple statements not allowed",
			sql:           "SELECT * FROM users; SELECT * FROM orders",
			expectBlocked: true,
		},
		{
			name:          "Syntax Error",
			sql:           "SELECT * FROM",
			expectBlocked: true,
		},
		{
			name:          "Blocked function sleep",
			sql:           "SELECT sleep(10)",
			expectBlocked: true,
		},
		{
			name:          "CTE Smuggling Attempt",
			sql:           "WITH x AS (DELETE FROM users WHERE id=1) SELECT * FROM x",
			expectBlocked: true, // Should fail at parser level in MySQL
		},
	}

	parser := &MySQLParser{}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rewritten, _, err := parser.ApplyRules(tt.sql, rules, nil)
			if tt.expectBlocked {
				if err == nil {
					t.Errorf("expected query to be blocked, but it was allowed: %s", tt.sql)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error for query %s: %v", tt.sql, err)
				}
				if tt.expectSQL != "" && rewritten != tt.expectSQL {
					t.Errorf("expected %s, got %s", tt.expectSQL, rewritten)
				}
			}
		})
	}
}

func TestMySQLParser_EnforceSelectLimit(t *testing.T) {
	rules := Rules{
		AllowedStatements:  []string{"SELECT"},
		AllowedTables:      []string{"users", "orders"},
		EnforceSelectLimit: 50,
	}

	tests := []struct {
		name         string
		sql          string
		rules        Rules
		expectErr    bool
		wantContains string
		wantParams   []int
	}{
		{
			name:         "SELECT without LIMIT injects limit",
			sql:          "SELECT * FROM users",
			rules:        rules,
			wantContains: "LIMIT 50",
		},
		{
			name:         "SELECT with LIMIT below maximum preserved",
			sql:          "SELECT * FROM users LIMIT 10",
			rules:        rules,
			wantContains: "LIMIT 10",
		},
		{
			name:         "SELECT with LIMIT equal to maximum preserved",
			sql:          "SELECT * FROM users LIMIT 50",
			rules:        rules,
			wantContains: "LIMIT 50",
		},
		{
			name:         "SELECT with LIMIT above maximum clamped to maximum",
			sql:          "SELECT * FROM users LIMIT 1000000",
			rules:        rules,
			wantContains: "LIMIT 50",
		},
		{
			name:         "SELECT with LIMIT above maximum and OFFSET syntax preserves offset and clamps limit",
			sql:          "SELECT * FROM users LIMIT 1000000 OFFSET 20",
			rules:        rules,
			wantContains: "LIMIT 20,50",
		},
		{
			name:         "SELECT with comma offset syntax preserves offset and clamps limit",
			sql:          "SELECT * FROM users LIMIT 20, 1000000",
			rules:        rules,
			wantContains: "LIMIT 20,50",
		},
		{
			name:         "Parameterized single LIMIT tracks param index 1",
			sql:          "SELECT * FROM users LIMIT ?",
			rules:        rules,
			wantContains: "LIMIT ?",
			wantParams:   []int{1},
		},
		{
			name:         "Parameterized WHERE and comma LIMIT offset tracks count param index 3",
			sql:          "SELECT * FROM users WHERE id = ? LIMIT ?, ?",
			rules:        rules,
			wantContains: "LIMIT ?,?",
			wantParams:   []int{3},
		},
		{
			name:         "Parameterized LIMIT with OFFSET syntax tracks count param index 1",
			sql:          "SELECT * FROM users LIMIT ? OFFSET ?",
			rules:        rules,
			wantContains: "LIMIT ?,?",
			wantParams:   []int{1},
		},
		{
			name:         "Subquery in FROM with LIMIT above maximum clamps both inner and outer",
			sql:          "SELECT * FROM (SELECT * FROM users LIMIT 1000000) sub",
			rules:        rules,
			wantContains: "SELECT * FROM (SELECT * FROM `users` LIMIT 50) AS `sub` LIMIT 50",
		},
		{
			name:         "Subquery in WHERE clause with LIMIT above maximum clamps subquery and injects outer",
			sql:          "SELECT * FROM users WHERE id IN (SELECT user_id FROM orders LIMIT 1000000)",
			rules:        rules,
			wantContains: "SELECT * FROM `users` WHERE `id` IN (SELECT `user_id` FROM `orders` LIMIT 50) LIMIT 50",
		},
		{
			name: "Tenant isolation with LIMIT above maximum clamps limit and applies tenant predicate",
			sql:  "SELECT * FROM users LIMIT 1000000",
			rules: Rules{
				AllowedStatements:  []string{"SELECT"},
				AllowedTables:      []string{"users"},
				EnforceSelectLimit: 50,
				TenantIsolation: &TenantIsolationRule{
					Enabled:      true,
					TenantColumn: "tenant_id",
					TenantID:     "tenant-1",
				},
			},
			wantContains: "SELECT * FROM (SELECT * FROM `users` WHERE `tenant_id`=_UTF8MB4'tenant-1' LIMIT 50) AS `users` LIMIT 50",
		},
		{
			name: "EnforceSelectLimit 0 leaves query untouched",
			sql:  "SELECT * FROM users LIMIT 1000000",
			rules: Rules{
				AllowedStatements:  []string{"SELECT"},
				AllowedTables:      []string{"users"},
				EnforceSelectLimit: 0,
			},
			wantContains: "LIMIT 1000000",
		},
		{
			name:         "Oversized uint64 LIMIT clamped to policy maximum",
			sql:          "SELECT * FROM users LIMIT 18446744073709551615",
			rules:        rules,
			wantContains: "LIMIT 50",
		},
		{
			name:      "Negative LIMIT value fails closed",
			sql:       "SELECT * FROM users LIMIT -5",
			rules:     rules,
			expectErr: true,
		},
		{
			name:      "Unsupported arithmetic expression in LIMIT fails closed",
			sql:       "SELECT * FROM users LIMIT 10 + 5",
			rules:     rules,
			expectErr: true,
		},
	}

	p := &MySQLParser{}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rewritten, params, err := p.ApplyRules(tt.sql, tt.rules, nil)
			if tt.expectErr {
				if err == nil {
					t.Fatalf("expected error for query %q, got rewritten: %s", tt.sql, rewritten)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error for query %q: %v", tt.sql, err)
			}
			if !strings.Contains(rewritten, tt.wantContains) {
				t.Errorf("expected rewritten query to contain %q, got: %s", tt.wantContains, rewritten)
			}
			if len(tt.wantParams) > 0 {
				if len(params) != len(tt.wantParams) {
					t.Fatalf("expected limit params %v, got %v", tt.wantParams, params)
				}
				for i := range params {
					if params[i] != tt.wantParams[i] {
						t.Errorf("expected param %d to be %d, got %d", i, tt.wantParams[i], params[i])
					}
				}
			}
		})
	}
}

func TestMySQLParser_PolicyIsolation_SuccessiveContexts(t *testing.T) {
	// Verify that successive executions of identical SQL across differing tenant identities,
	// limit settings, and table permissions are completely isolated from each other.
	sharedCache, _ := cache.NewLocalCache(100)
	p := &MySQLParser{}

	sql := "SELECT * FROM users"

	// Context 1: Tenant A, EnforceSelectLimit: 20
	rulesA := Rules{
		AllowedStatements:  []string{"SELECT"},
		AllowedTables:      []string{"users"},
		EnforceSelectLimit: 20,
		TenantIsolation: &TenantIsolationRule{
			Enabled:      true,
			TenantColumn: "tenant_id",
			TenantID:     "tenant-A",
		},
	}
	outA, _, errA := p.ApplyRules(sql, rulesA, sharedCache)
	if errA != nil {
		t.Fatalf("unexpected error in Context 1: %v", errA)
	}
	if !strings.Contains(outA, "tenant-A") || !strings.Contains(outA, "LIMIT 20") {
		t.Errorf("Context 1 output invalid: %s", outA)
	}

	// Context 2: Tenant B, EnforceSelectLimit: 50
	rulesB := Rules{
		AllowedStatements:  []string{"SELECT"},
		AllowedTables:      []string{"users"},
		EnforceSelectLimit: 50,
		TenantIsolation: &TenantIsolationRule{
			Enabled:      true,
			TenantColumn: "tenant_id",
			TenantID:     "tenant-B",
		},
	}
	outB, _, errB := p.ApplyRules(sql, rulesB, sharedCache)
	if errB != nil {
		t.Fatalf("unexpected error in Context 2: %v", errB)
	}
	if !strings.Contains(outB, "tenant-B") || !strings.Contains(outB, "LIMIT 50") {
		t.Errorf("Context 2 output invalid: %s", outB)
	}
	if outA == outB {
		t.Fatalf("CRITICAL SECURITY VIOLATION: Context 1 and Context 2 outputs collided across tenants: %s", outA)
	}

	// Context 3: Tenant C, users table is NOT allowed
	rulesC := Rules{
		AllowedStatements:  []string{"SELECT"},
		AllowedTables:      []string{"orders"},
		EnforceSelectLimit: 50,
		TenantIsolation: &TenantIsolationRule{
			Enabled:      true,
			TenantColumn: "tenant_id",
			TenantID:     "tenant-C",
		},
	}
	_, _, errC := p.ApplyRules(sql, rulesC, sharedCache)
	if errC == nil {
		t.Fatal("expected error in Context 3 for disallowed table, but query succeeded")
	}

	// Context 4: Non-tenant session with EnforceSelectLimit: 10
	rulesD := Rules{
		AllowedStatements:  []string{"SELECT"},
		AllowedTables:      []string{"users"},
		EnforceSelectLimit: 10,
	}
	outD, _, errD := p.ApplyRules(sql, rulesD, sharedCache)
	if errD != nil {
		t.Fatalf("unexpected error in Context 4: %v", errD)
	}
	if strings.Contains(outD, "tenant") || !strings.Contains(outD, "LIMIT 10") {
		t.Errorf("Context 4 output leaked tenant context: %s", outD)
	}
}

func TestMySQLVisitor(t *testing.T) {
	v := &mysqlVisitor{}

	// Test blocked fast-path
	v.blocked = true
	_, skip := v.Enter(nil)
	if !skip {
		t.Error("expected skip when blocked")
	}

	v.blocked = false
}

func TestMySQLParser_UnsupportedStatements_Diagnostics(t *testing.T) {
	rules := Rules{
		AllowedStatements: []string{"SELECT", "INSERT", "UPDATE"},
		AllowedTables:     []string{"users", "orders"},
	}
	p := &MySQLParser{}

	tests := []struct {
		name        string
		sql         string
		expectedErr string
	}{
		{
			name:        "START TRANSACTION blocked with clear diagnostic",
			sql:         "START TRANSACTION",
			expectedErr: "policy violation: statement BEGIN not allowed",
		},
		{
			name:        "BEGIN blocked with clear diagnostic",
			sql:         "BEGIN",
			expectedErr: "policy violation: statement BEGIN not allowed",
		},
		{
			name:        "COMMIT blocked with clear diagnostic",
			sql:         "COMMIT",
			expectedErr: "policy violation: statement COMMIT not allowed",
		},
		{
			name:        "ROLLBACK blocked with clear diagnostic",
			sql:         "ROLLBACK",
			expectedErr: "policy violation: statement ROLLBACK not allowed",
		},
		{
			name:        "SET autocommit = 0 blocked with clear diagnostic",
			sql:         "SET autocommit = 0",
			expectedErr: "policy violation: statement SET not allowed",
		},
		{
			name:        "SET @session_variable = 'value' blocked with clear diagnostic",
			sql:         "SET @session_variable = 'value'",
			expectedErr: "policy violation: statement SET not allowed",
		},
		{
			name:        "CREATE TEMPORARY TABLE blocked with clear diagnostic",
			sql:         "CREATE TEMPORARY TABLE temp_tbl (id INT)",
			expectedErr: "policy violation: statement CREATE not allowed",
		},
		{
			name:        "LOCK TABLES blocked with clear diagnostic",
			sql:         "LOCK TABLES users WRITE",
			expectedErr: "policy violation: statement LOCK not allowed",
		},
		{
			name:        "Multiple SQL statements blocked with clear diagnostic",
			sql:         "SELECT 1; SELECT 2",
			expectedErr: "policy violation: multiple statements not allowed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := p.ApplyRules(tt.sql, rules, nil)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tt.expectedErr)
			}
			if !strings.Contains(err.Error(), tt.expectedErr) {
				t.Fatalf("expected error containing %q, got %q", tt.expectedErr, err.Error())
			}
		})
	}
}

func TestMySQLParser_SideEffectingSelect(t *testing.T) {
	rules := Rules{
		AllowedStatements:  []string{"SELECT"},
		AllowedTables:      []string{"users"},
		EnforceSelectLimit: 10,
	}
	p := &MySQLParser{}

	// Verify parser treats SELECT with user variable assignment as SELECT
	out, _, err := p.ApplyRules("SELECT @var := 'value'", rules, nil)
	if err != nil {
		t.Fatalf("unexpected error parsing SELECT @var := 'value': %v", err)
	}
	if !strings.Contains(out, ":=") || !strings.Contains(out, "var") {
		t.Errorf("expected rewritten query to contain variable assignment, got %s", out)
	}

	// Verify parser treats SELECT CONNECTION_ID() as SELECT
	out, _, err = p.ApplyRules("SELECT CONNECTION_ID()", rules, nil)
	if err != nil {
		t.Fatalf("unexpected error parsing SELECT CONNECTION_ID(): %v", err)
	}
	if !strings.Contains(out, "CONNECTION_ID()") {
		t.Errorf("expected rewritten query to contain CONNECTION_ID(), got %s", out)
	}

	// Verify parser treats SELECT GET_LOCK and RELEASE_LOCK as SELECT when not blocked
	out, _, err = p.ApplyRules("SELECT GET_LOCK('my_lock', 10)", rules, nil)
	if err != nil {
		t.Fatalf("unexpected error parsing SELECT GET_LOCK: %v", err)
	}
	if !strings.Contains(out, "GET_LOCK") {
		t.Errorf("expected rewritten query to contain GET_LOCK, got %s", out)
	}

	// Verify when GET_LOCK is in BlockedFunctions, it fails closed
	rulesBlocked := Rules{
		AllowedStatements: []string{"SELECT"},
		BlockedFunctions:  []string{"get_lock"},
	}
	_, _, err = p.ApplyRules("SELECT GET_LOCK('my_lock', 10)", rulesBlocked, nil)
	if err == nil {
		t.Fatal("expected GET_LOCK to be blocked when listed in BlockedFunctions, got nil")
	}
	if !strings.Contains(err.Error(), "function GET_LOCK is blocked") {
		t.Fatalf("expected function blocked error, got %v", err)
	}
}
