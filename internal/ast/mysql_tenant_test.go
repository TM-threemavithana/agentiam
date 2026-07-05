package ast_test

import (
	"strings"
	"testing"

	"github.com/tm-threemavithana/agentiam/internal/ast"
)

func TestMySQLTenantIsolation_Select(t *testing.T) {
	parser := &ast.MySQLParser{}
	rules := ast.Rules{
		AllowedStatements: []string{"SELECT"},
		AllowedTables:     []string{"users", "public_data"},
		TenantIsolation: &ast.TenantIsolationRule{
			Enabled:      true,
			TenantColumn: "tenant_id",
			TenantID:     "123",
			SharedTables: []string{"public_data"},
		},
	}

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "simple select",
			input:    "SELECT id, name FROM users",
			expected: "SELECT `id`,`name` FROM (SELECT * FROM `users` WHERE `tenant_id`=_UTF8MB4'123') AS `users`",
		},
		{
			name:     "shared table bypass",
			input:    "SELECT data FROM public_data",
			expected: "SELECT `data` FROM `public_data`",
		},
		{
			name:     "table with alias",
			input:    "SELECT u.name FROM users u",
			expected: "SELECT `u`.`name` FROM (SELECT * FROM `users` WHERE `tenant_id`=_UTF8MB4'123') AS `u`",
		},
		{
			name:     "select with where",
			input:    "SELECT id FROM users WHERE status = 1",
			expected: "SELECT `id` FROM (SELECT * FROM `users` WHERE `tenant_id`=_UTF8MB4'123') AS `users` WHERE `status`=1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output, _, err := parser.ApplyRules(tt.input, rules, nil)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if strings.TrimSpace(output) != tt.expected {
				t.Errorf("expected: %s\ngot:      %s", tt.expected, output)
			}
		})
	}
}

func TestMySQLTenantIsolation_Update(t *testing.T) {
	parser := &ast.MySQLParser{}
	rules := ast.Rules{
		AllowedStatements: []string{"UPDATE"},
		AllowedTables:     []string{"users", "public_data"},
		TenantIsolation: &ast.TenantIsolationRule{
			Enabled:      true,
			TenantColumn: "tenant_id",
			TenantID:     "123",
			SharedTables: []string{"public_data"},
		},
	}

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "simple update",
			input:    "UPDATE users SET name = 'John'",
			expected: "UPDATE `users` SET `name`=_UTF8MB4'John' WHERE `tenant_id`=_UTF8MB4'123'",
		},
		{
			name:     "update with where",
			input:    "UPDATE users SET name = 'John' WHERE id = 5",
			expected: "UPDATE `users` SET `name`=_UTF8MB4'John' WHERE `id`=5 AND `tenant_id`=_UTF8MB4'123'",
		},
		{
			name:     "shared table update bypass",
			input:    "UPDATE public_data SET views = 1",
			expected: "UPDATE `public_data` SET `views`=1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output, _, err := parser.ApplyRules(tt.input, rules, nil)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if strings.TrimSpace(output) != tt.expected {
				t.Errorf("expected: %s\ngot:      %s", tt.expected, output)
			}
		})
	}
}

func TestMySQLTenantIsolation_Delete(t *testing.T) {
	parser := &ast.MySQLParser{}
	rules := ast.Rules{
		AllowedStatements: []string{"DELETE"},
		AllowedTables:     []string{"users", "public_data"},
		TenantIsolation: &ast.TenantIsolationRule{
			Enabled:      true,
			TenantColumn: "tenant_id",
			TenantID:     "123",
			SharedTables: []string{"public_data"},
		},
	}

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "simple delete",
			input:    "DELETE FROM users",
			expected: "DELETE FROM `users` WHERE `tenant_id`=_UTF8MB4'123'",
		},
		{
			name:     "delete with where",
			input:    "DELETE FROM users WHERE id = 5",
			expected: "DELETE FROM `users` WHERE `id`=5 AND `tenant_id`=_UTF8MB4'123'",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			output, _, err := parser.ApplyRules(tt.input, rules, nil)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if strings.TrimSpace(output) != tt.expected {
				t.Errorf("expected: %s\ngot:      %s", tt.expected, output)
			}
		})
	}
}

func TestMySQLTenantIsolation_InsertBlocked(t *testing.T) {
	parser := &ast.MySQLParser{}
	rules := ast.Rules{
		AllowedStatements: []string{"INSERT"},
		AllowedTables:     []string{"users", "public_data"},
		TenantIsolation: &ast.TenantIsolationRule{
			Enabled:      true,
			TenantColumn: "tenant_id",
			TenantID:     "123",
			SharedTables: []string{"public_data"},
		},
	}

	// Should block insert to tenant table
	_, _, err := parser.ApplyRules("INSERT INTO users (name) VALUES ('x')", rules, nil)
	if err == nil {
		t.Fatal("expected error for INSERT into tenant table, got none")
	}

	// Should allow insert to shared table
	_, _, err = parser.ApplyRules("INSERT INTO public_data (views) VALUES (1)", rules, nil)
	if err != nil {
		t.Fatalf("unexpected error for INSERT into shared table: %v", err)
	}
}
