package ast

import (
	"testing"
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

func TestMySQLVisitor(t *testing.T) {
	v := &mysqlVisitor{}

	// Test blocked fast-path
	v.blocked = true
	_, skip := v.Enter(nil)
	if !skip {
		t.Error("expected skip when blocked")
	}

	v.blocked = false
	// We can't easily instantiate internal tidb ast nodes directly without pain, 
	// but the parser loop inherently covers Enter/Leave for normal queries. 
	// The 76.9% in Enter implies we are missing coverage for some specific statements
	// we didn't include in TestMySQLParser_ApplyRules.
}
