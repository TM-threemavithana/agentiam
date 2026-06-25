package ast

import (
	"strings"
	"testing"
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
			expectBlocked: true,
			expectLimit:   false,
		},
		{
			name:          "FETCH FIRST $1 ROWS ONLY dynamic bypass",
			sql:           "SELECT * FROM users FETCH FIRST $1 ROWS ONLY",
			expectBlocked: true,
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// For the "Empty Policy Denies All" test, we override the rules
			testRules := rules
			if tt.name == "Empty Policy Denies All" {
				testRules.AllowedStatements = []string{}
			}

			result, err := (&PostgresParser{}).ApplyRules(tt.sql, testRules, nil)

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
			result, err := (&PostgresParser{}).ApplyRules(tt.sql, rules, nil)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}
