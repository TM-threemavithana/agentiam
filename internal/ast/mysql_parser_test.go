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
			name:         "Subquery with LIMIT above maximum clamps both inner and outer",
			sql:          "SELECT * FROM (SELECT * FROM users LIMIT 1000000) sub",
			rules:        rules,
			wantContains: "SELECT * FROM (SELECT * FROM `users` LIMIT 50) AS `sub` LIMIT 50",
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

func TestMySQLParser_ASTCache(t *testing.T) {
	rules := Rules{
		AllowedStatements:  []string{"SELECT"},
		AllowedTables:      []string{"users"},
		EnforceSelectLimit: 25,
	}

	c, _ := cache.NewLocalCache(10)
	p := &MySQLParser{}

	sql := "SELECT * FROM users WHERE id = ? LIMIT ?"
	out1, params1, err1 := p.ApplyRules(sql, rules, c)
	if err1 != nil {
		t.Fatalf("unexpected error: %v", err1)
	}

	out2, params2, err2 := p.ApplyRules(sql, rules, c)
	if err2 != nil {
		t.Fatalf("unexpected error on cached retrieval: %v", err2)
	}

	if out1 != out2 {
		t.Errorf("cache mismatch: first=%s, second=%s", out1, out2)
	}
	if len(params1) != len(params2) || (len(params1) > 0 && params1[0] != params2[0]) {
		t.Errorf("cache params mismatch: first=%v, second=%v", params1, params2)
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
