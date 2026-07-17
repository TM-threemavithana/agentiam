package ast

import (
	"strings"
	"testing"
	"github.com/tm-threemavithana/agentiam/internal/cache"
)

func TestApplyRules(t *testing.T) {
	rules := Rules{
		AllowedStatements: []string{"SELECT"}, EnforceSelectLimit: 100,
	}

	tests := []struct {
		name          string
		sql           string
		expectBlocked bool
		expectLimit   bool
	}{
		{
			name:          "Empty Policy Denies All",
			sql:           "SELECT 1",
			expectBlocked: true,
			expectLimit:   false,
		},
		{
			name:          "Clean Select",
			sql:           "SELECT * FROM users",
			expectBlocked: false,
			expectLimit:   true,
		},
		{
			name:          "Select with Lower Limit",
			sql:           "SELECT * FROM users LIMIT 5",
			expectBlocked: false,
			expectLimit:   false, // Keeps 5, doesn't rewrite to 100
		},
		{
			name:          "Select with Higher Limit",
			sql:           "SELECT * FROM users LIMIT 500",
			expectBlocked: false,
			expectLimit:   true, // Rewrites to 100
		},
		{
			name:          "Select For Update",
			sql:           "SELECT * FROM users FOR UPDATE",
			expectBlocked: true,
			expectLimit:   false,
		},
		{
			name:          "Delete Statement",
			sql:           "DELETE FROM users",
			expectBlocked: true,
			expectLimit:   false,
		},
		{
			name:          "Subquery Limit Injection",
			sql:           "SELECT * FROM (SELECT * FROM users, nil)",
			expectBlocked: false,
			expectLimit:   true,
		},
		{
			name:          "CTE Limit Injection",
			sql:           "WITH u AS (SELECT * FROM users) SELECT * FROM u",
			expectBlocked: false,
			expectLimit:   true,
		},
		{
			name:          "UNION Limit Injection",
			sql:           "SELECT id FROM users UNION SELECT id FROM admins",
			expectBlocked: false,
			expectLimit:   true,
		},
		{
			name:          "LIMIT ALL bypass",
			sql:           "SELECT * FROM users LIMIT ALL",
			expectBlocked: false,
			expectLimit:   true,
		},
		{
			name:          "FETCH FIRST bypass",
			sql:           "SELECT * FROM users FETCH FIRST 5 ROWS ONLY",
			expectBlocked: false,
			expectLimit:   false, // Limit is 5, we shouldn't rewrite it
		},
		{
			name:          "LIMIT $1 dynamic bypass",
			sql:           "SELECT * FROM users LIMIT $1",
			expectBlocked: false,
			expectLimit:   false,
		},
		{
			name:          "FETCH FIRST $1 ROWS ONLY dynamic bypass",
			sql:           "SELECT * FROM users FETCH FIRST $1 ROWS ONLY",
			expectBlocked: false,
			expectLimit:   false,
		},
		{
			name:          "COPY Exfiltration",
			sql:           "COPY users TO STDOUT",
			expectBlocked: true,
			expectLimit:   false,
		},
		{
			name:          "SET Configuration Injection",
			sql:           "SET search_path = public",
			expectBlocked: true,
			expectLimit:   false,
		},
		{
			name:          "RESET Configuration Injection",
			sql:           "RESET ALL",
			expectBlocked: true,
			expectLimit:   false,
		},
		{
			name:          "EXPLAIN ANALYZE Execution DoS",
			sql:           "EXPLAIN ANALYZE SELECT * FROM users",
			expectBlocked: true,
			expectLimit:   false,
		},
		{
			name:          "EXPLAIN (ANALYZE on) Execution DoS",
			sql:           "EXPLAIN (ANALYZE on) SELECT * FROM users",
			expectBlocked: true,
			expectLimit:   false,
		},
		{
			name:          "EXPLAIN (ANALYZE true) Execution DoS",
			sql:           "EXPLAIN (ANALYZE true) SELECT * FROM users",
			expectBlocked: true,
			expectLimit:   false,
		},
		{
			name:          "EXPLAIN (ANALYZE false) Planning",
			sql:           "EXPLAIN (ANALYZE false) SELECT * FROM users",
			expectBlocked: false,
			expectLimit:   true, // limit should be injected recursively
		},
		{
			name:          "EXPLAIN Planning",
			sql:           "EXPLAIN SELECT * FROM users",
			expectBlocked: false,
			expectLimit:   true, // limit should be injected recursively
		},
		{
			name:          "CTE DML Evasion",
			sql:           "WITH cte AS (DELETE FROM users) SELECT * FROM cte",
			expectBlocked: true,
			expectLimit:   false,
		},
		{
			name:          "Nested CTE DML Evasion",
			sql:           "WITH x AS (WITH y AS (DELETE FROM users) SELECT * FROM y) SELECT * FROM x",
			expectBlocked: true,
			expectLimit:   false,
		},
		{
			name:          "Multi-CTE DML Evasion",
			sql:           "WITH a AS (SELECT * FROM users), b AS (DELETE FROM users) SELECT * FROM a",
			expectBlocked: true,
			expectLimit:   false,
		},
		{
			name:          "Nested CTE SELECT (Allowed)",
			sql:           "WITH x AS (WITH y AS (SELECT * FROM users) SELECT * FROM y) SELECT * FROM x",
			expectBlocked: false,
			expectLimit:   true, // Limit is injected at the top level
		},
		{
			name:          "Insert Statement",
			sql:           "INSERT INTO users (id) VALUES (1)",
			expectBlocked: true,
			expectLimit:   false,
		},
		{
			name:          "Update Statement",
			sql:           "UPDATE users SET name='test' WHERE id=1",
			expectBlocked: true,
			expectLimit:   false,
		},
		{
			name:          "Drop Statement",
			sql:           "DROP TABLE users",
			expectBlocked: true,
			expectLimit:   false,
		},
		{
			name:          "Truncate Statement",
			sql:           "TRUNCATE TABLE users",
			expectBlocked: true,
			expectLimit:   false,
		},
		{
			name:          "Create Statement",
			sql:           "CREATE TABLE users (id int)",
			expectBlocked: true,
			expectLimit:   false,
		},
		{
			name:          "Alter Statement",
			sql:           "ALTER TABLE users ADD COLUMN name text",
			expectBlocked: true,
			expectLimit:   false,
		},
		{
			name:          "Show Statement",
			sql:           "SHOW config_file",
			expectBlocked: true,
			expectLimit:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// For the "Empty Policy Denies All" test, we override the rules
			testRules := rules
			if tt.name == "Empty Policy Denies All" {
				testRules.AllowedStatements = []string{}
			}

			result, limitParams, err := (&PostgresParser{}).ApplyRules(tt.sql, testRules, nil)

			if tt.expectBlocked {
				if err == nil {
					t.Errorf("expected query to be blocked, but it was allowed: %s", tt.sql)
				}
				return
			}

			if err != nil {
				t.Errorf("unexpected error for query %s: %v", tt.sql, err)
				return
			}

			if tt.expectLimit && !strings.Contains(result, "LIMIT 100") {
				t.Errorf("expected LIMIT 100 to be injected, got: %s", result)
			}
			if !tt.expectLimit && strings.Contains(result, "LIMIT 100") {
				t.Errorf("expected LIMIT 100 NOT to be injected, got: %s", result)
			}
			
			if tt.name == "LIMIT $1 dynamic bypass" {
				if len(limitParams) != 1 || limitParams[0] != 1 {
					t.Errorf("expected limitParams to contain [1], got: %v", limitParams)
				}
			}
		})
	}
}

func TestApplyRules_Analytical_Queries_Bypass_Limit(t *testing.T) {
	rules := Rules{
		AllowedStatements:  []string{"SELECT"},
		EnforceSelectLimit: 10,
	}

	tests := []struct {
		name     string
		sql      string
		expected string
	}{
		{
			name:     "Count Aggregation",
			sql:      "SELECT count(*) FROM users",
			expected: "SELECT count(*) FROM users", // No limit injected
		},
		{
			name:     "Sum Aggregation",
			sql:      "SELECT sum(amount) FROM orders",
			expected: "SELECT sum(amount) FROM orders",
		},
		{
			name:     "Group By Clause",
			sql:      "SELECT status, count(*) FROM orders GROUP BY status",
			expected: "SELECT status, count(*) FROM orders GROUP BY status",
		},
		{
			name:     "Window Function",
			sql:      "SELECT id, sum(amount) OVER (PARTITION BY user_id) FROM orders",
			expected: "SELECT id, sum(amount) OVER (PARTITION BY user_id) FROM orders",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, _, err := (&PostgresParser{}).ApplyRules(tt.sql, rules, nil)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}

func TestApplyRules_CacheAndErrors(t *testing.T) {
	rules := Rules{
		AllowedStatements:  []string{"SELECT"},
		EnforceSelectLimit: 10,
	}

	c, _ := cache.NewLocalCache(100)
	parser := &PostgresParser{}

	// Test syntax error
	_, _, err := parser.ApplyRules("SELECT * FROM", rules, c)
	if err == nil {
		t.Error("expected syntax error")
	}

	// Test cache miss and cache add
	sql := "SELECT * FROM users"
	_, _, err = parser.ApplyRules(sql, rules, c)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}

	// Test cache hit
	result, _, err := parser.ApplyRules(sql, rules, c)
	if err != nil {
		t.Errorf("unexpected error on cache hit: %v", err)
	}
	if !strings.Contains(result, "LIMIT 10") {
		t.Errorf("expected cached result to have limit: %v", result)
	}
}

// TestSelectBypassFix verifies that SELECT is blocked when not in AllowedStatements.
// This was the critical security bug fixed in this release.
func TestSelectBypassFix(t *testing.T) {
	parser := &PostgresParser{}
	c, _ := cache.NewLocalCache(10)

	t.Run("SELECT blocked when not allowed", func(t *testing.T) {
		rules := Rules{
			AllowedStatements:  []string{"INSERT"},
			EnforceSelectLimit: 100,
		}
		_, _, err := parser.ApplyRules("SELECT * FROM users", rules, c)
		if err == nil {
			t.Error("expected SELECT to be blocked when AllowedStatements=[INSERT], got nil error")
		}
	})

	t.Run("SELECT allowed when in allowed list", func(t *testing.T) {
		rules := Rules{
			AllowedStatements:  []string{"SELECT"},
			EnforceSelectLimit: 100,
		}
		_, _, err := parser.ApplyRules("SELECT id FROM users", rules, c)
		if err != nil {
			t.Errorf("expected SELECT to pass, got: %v", err)
		}
	})
}

// TestAllowedTablesPostgres verifies that AllowedTables is now enforced for the Postgres parser.
func TestAllowedTablesPostgres(t *testing.T) {
	parser := &PostgresParser{}
	c, _ := cache.NewLocalCache(10)

	t.Run("allowed table passes", func(t *testing.T) {
		rules := Rules{
			AllowedStatements:  []string{"SELECT"},
			AllowedTables:      []string{"users"},
			EnforceSelectLimit: 100,
		}
		_, _, err := parser.ApplyRules("SELECT id FROM users", rules, c)
		if err != nil {
			t.Errorf("expected allowed table to pass, got: %v", err)
		}
	})

	t.Run("blocked table denied", func(t *testing.T) {
		rules := Rules{
			AllowedStatements:  []string{"SELECT"},
			AllowedTables:      []string{"users"},
			EnforceSelectLimit: 100,
		}
		_, _, err := parser.ApplyRules("SELECT secret FROM passwords", rules, c)
		if err == nil {
			t.Error("expected access to 'passwords' to be denied, got nil error")
		}
	})

	t.Run("wildcard allows all tables", func(t *testing.T) {
		rules := Rules{
			AllowedStatements:  []string{"SELECT"},
			AllowedTables:      []string{"*"},
			EnforceSelectLimit: 100,
		}
		_, _, err := parser.ApplyRules("SELECT col FROM any_table", rules, c)
		if err != nil {
			t.Errorf("expected wildcard to allow any table, got: %v", err)
		}
	})

	t.Run("empty allowed_tables allows all (no restriction)", func(t *testing.T) {
		rules := Rules{
			AllowedStatements:  []string{"SELECT"},
			AllowedTables:      []string{},
			EnforceSelectLimit: 100,
		}
		_, _, err := parser.ApplyRules("SELECT col FROM any_table", rules, c)
		if err != nil {
			t.Errorf("expected empty allowed_tables to allow any table, got: %v", err)
		}
	})
}
