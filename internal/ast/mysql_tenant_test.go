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

func TestMySQLTenantIsolation_Update_TenantColumnProhibited(t *testing.T) {
	parser := &ast.MySQLParser{}
	rules := ast.Rules{
		AllowedStatements: []string{"UPDATE"},
		AllowedTables:     []string{"users", "public_data", "orders"},
		TenantIsolation: &ast.TenantIsolationRule{
			Enabled:      true,
			TenantColumn: "tenant_id",
			TenantID:     "123",
			SharedTables: []string{"public_data"},
		},
	}

	failTests := []struct {
		name        string
		sql         string
		errContains string
	}{
		{
			name:        "direct assignment to tenant column",
			sql:         "UPDATE users SET tenant_id = '999' WHERE id = 1",
			errContains: "modifying tenant isolation column 'tenant_id' is prohibited",
		},
		{
			name:        "backtick quoted tenant column",
			sql:         "UPDATE users SET `tenant_id` = '999' WHERE id = 1",
			errContains: "modifying tenant isolation column 'tenant_id' is prohibited",
		},
		{
			name:        "case-insensitive uppercase tenant column",
			sql:         "UPDATE users SET TENANT_ID = '999' WHERE id = 1",
			errContains: "modifying tenant isolation column 'tenant_id' is prohibited",
		},
		{
			name:        "table-qualified tenant column",
			sql:         "UPDATE users SET users.tenant_id = '999' WHERE id = 1",
			errContains: "modifying tenant isolation column 'tenant_id' is prohibited",
		},
		{
			name:        "alias-qualified tenant column",
			sql:         "UPDATE users u SET u.tenant_id = '999' WHERE u.id = 1",
			errContains: "modifying tenant isolation column 'tenant_id' is prohibited",
		},
		{
			name:        "backtick quoted alias and tenant column",
			sql:         "UPDATE users u SET `u`.`tenant_id` = '999' WHERE u.id = 1",
			errContains: "modifying tenant isolation column 'tenant_id' is prohibited",
		},
		{
			name:        "mixed valid and prohibited assignments",
			sql:         "UPDATE users SET name = 'alice', tenant_id = '999' WHERE id = 1",
			errContains: "modifying tenant isolation column 'tenant_id' is prohibited",
		},
		{
			name:        "multi-table update attempting tenant reassignment",
			sql:         "UPDATE users u, orders o SET u.tenant_id = '999' WHERE u.id = o.user_id",
			errContains: "modifying tenant isolation column 'tenant_id' is prohibited",
		},
		{
			name:        "unsupported multi-table comma join on tenant table",
			sql:         "UPDATE users u, orders o SET u.name = 'alice' WHERE u.id = o.user_id",
			errContains: "multi-table UPDATE statements are not supported while TenantIsolation is enabled",
		},
		{
			name:        "unsupported multi-table explicit join on tenant table",
			sql:         "UPDATE users u JOIN orders o ON u.id = o.user_id SET u.name = 'alice'",
			errContains: "multi-table UPDATE statements are not supported while TenantIsolation is enabled",
		},
	}

	for _, tt := range failTests {
		t.Run("Fail_"+tt.name, func(t *testing.T) {
			_, _, err := parser.ApplyRules(tt.sql, rules, nil)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil for SQL: %s", tt.errContains, tt.sql)
			}
			if !strings.Contains(err.Error(), tt.errContains) {
				t.Errorf("expected error containing %q, got: %v", tt.errContains, err)
			}
		})
	}

	passTests := []struct {
		name     string
		sql      string
		expected string
	}{
		{
			name:     "single table unrelated column",
			sql:      "UPDATE users SET name = 'alice' WHERE id = 1",
			expected: "UPDATE `users` SET `name`=_UTF8MB4'alice' WHERE `id`=1 AND `tenant_id`=_UTF8MB4'123'",
		},
		{
			name:     "aliased single table unrelated column",
			sql:      "UPDATE users u SET u.name = 'alice' WHERE u.id = 1",
			expected: "UPDATE `users` AS `u` SET `u`.`name`=_UTF8MB4'alice' WHERE `u`.`id`=1 AND `tenant_id`=_UTF8MB4'123'",
		},
		{
			name:     "shared table update bypasses tenant isolation",
			sql:      "UPDATE public_data SET views = 10",
			expected: "UPDATE `public_data` SET `views`=10",
		},
	}

	for _, tt := range passTests {
		t.Run("Pass_"+tt.name, func(t *testing.T) {
			output, _, err := parser.ApplyRules(tt.sql, rules, nil)
			if err != nil {
				t.Fatalf("unexpected error for permitted update: %v", err)
			}
			if strings.TrimSpace(output) != tt.expected {
				t.Errorf("expected: %s\ngot:      %s", tt.expected, output)
			}
		})
	}

	t.Run("Pass_tenant_isolation_disabled", func(t *testing.T) {
		disabledRules := ast.Rules{
			AllowedStatements: []string{"UPDATE"},
			AllowedTables:     []string{"users"},
			TenantIsolation: &ast.TenantIsolationRule{
				Enabled: false,
			},
		}
		sql := "UPDATE users SET tenant_id = '999' WHERE id = 1"
		output, _, err := parser.ApplyRules(sql, disabledRules, nil)
		if err != nil {
			t.Fatalf("unexpected error when tenant isolation is disabled: %v", err)
		}
		expected := "UPDATE `users` SET `tenant_id`=_UTF8MB4'999' WHERE `id`=1"
		if strings.TrimSpace(output) != expected {
			t.Errorf("expected: %s\ngot:      %s", expected, output)
		}
	})
}
