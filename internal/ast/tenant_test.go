package ast

import (
	"strings"
	"testing"
)

func TestTenantIsolation_SelectBasic(t *testing.T) {
	rules := Rules{
		AllowedStatements: []string{"SELECT"},
		TenantIsolation: &TenantIsolationRule{
			Enabled:      true,
			TenantColumn: "tenant_id",
			TenantID:     "12345",
			SharedTables: []string{"countries"},
		},
	}

	sql := "SELECT id, name FROM users"
	parser := &PostgresParser{}
	rewritten, _, err := parser.ApplyRules(sql, rules, nil)
	if err != nil {
		t.Fatalf("Failed: %v", err)
	}

	expected := "SELECT id, name FROM (SELECT * FROM users WHERE tenant_id = '12345') users"
	if rewritten != expected {
		t.Errorf("Expected: %s, got: %s", expected, rewritten)
	}
}

func TestTenantIsolation_SharedTable(t *testing.T) {
	rules := Rules{
		AllowedStatements: []string{"SELECT"},
		TenantIsolation: &TenantIsolationRule{
			Enabled:      true,
			TenantColumn: "tenant_id",
			TenantID:     "12345",
			SharedTables: []string{"countries"},
		},
	}

	sql := "SELECT code, name FROM countries"
	parser := &PostgresParser{}
	rewritten, _, err := parser.ApplyRules(sql, rules, nil)
	if err != nil {
		t.Fatalf("Failed: %v", err)
	}

	expected := "SELECT code, name FROM countries"
	if rewritten != expected {
		t.Errorf("Expected: %s, got: %s", expected, rewritten)
	}
}

func TestTenantIsolation_Joins(t *testing.T) {
	rules := Rules{
		AllowedStatements: []string{"SELECT"},
		TenantIsolation: &TenantIsolationRule{
			Enabled:      true,
			TenantColumn: "tenant_id",
			TenantID:     "12345",
			SharedTables: []string{"countries"},
		},
	}

	sql := "SELECT u.name, o.total FROM users u LEFT JOIN orders o ON u.id = o.user_id"
	parser := &PostgresParser{}
	rewritten, _, err := parser.ApplyRules(sql, rules, nil)
	if err != nil {
		t.Fatalf("Failed: %v", err)
	}

	expected := "SELECT u.name, o.total FROM (SELECT * FROM users WHERE tenant_id = '12345') u LEFT JOIN (SELECT * FROM orders WHERE tenant_id = '12345') o ON u.id = o.user_id"
	if rewritten != expected {
		t.Errorf("Expected: %s, got: %s", expected, rewritten)
	}
}

func TestTenantIsolation_Update(t *testing.T) {
	rules := Rules{
		AllowedStatements: []string{"UPDATE"},
		TenantIsolation: &TenantIsolationRule{
			Enabled:      true,
			TenantColumn: "tenant_id",
			TenantID:     "12345",
			SharedTables: []string{"countries"},
		},
	}

	sql := "UPDATE users SET name = 'test' WHERE id = 1"
	parser := &PostgresParser{}
	rewritten, _, err := parser.ApplyRules(sql, rules, nil)
	if err != nil {
		t.Fatalf("Failed: %v", err)
	}

	expected := "UPDATE users SET name = 'test' WHERE id = 1 AND tenant_id = '12345'"
	if rewritten != expected {
		t.Errorf("Expected: %s, got: %s", expected, rewritten)
	}
}

func TestTenantIsolation_Delete(t *testing.T) {
	rules := Rules{
		AllowedStatements: []string{"DELETE"},
		TenantIsolation: &TenantIsolationRule{
			Enabled:      true,
			TenantColumn: "tenant_id",
			TenantID:     "12345",
			SharedTables: []string{"countries"},
		},
	}

	sql := "DELETE FROM users"
	parser := &PostgresParser{}
	rewritten, _, err := parser.ApplyRules(sql, rules, nil)
	if err != nil {
		t.Fatalf("Failed: %v", err)
	}

	expected := "DELETE FROM users WHERE tenant_id = '12345'"
	if rewritten != expected {
		t.Errorf("Expected: %s, got: %s", expected, rewritten)
	}
}

func TestTenantIsolation_InsertBlocked(t *testing.T) {
	rules := Rules{
		AllowedStatements: []string{"INSERT"},
		TenantIsolation: &TenantIsolationRule{
			Enabled:      true,
			TenantColumn: "tenant_id",
			TenantID:     "12345",
			SharedTables: []string{"countries"},
		},
	}

	sql := "INSERT INTO users (name) VALUES ('test')"
	parser := &PostgresParser{}
	_, _, err := parser.ApplyRules(sql, rules, nil)
	if err == nil {
		t.Fatalf("Expected error blocking INSERT, got nil")
	}
}


func TestTenantIsolation_Update_TenantColumnProhibited(t *testing.T) {
	rules := Rules{
		AllowedStatements: []string{"UPDATE", "SELECT"},
		TenantIsolation: &TenantIsolationRule{
			Enabled:      true,
			TenantColumn: "tenant_id",
			TenantID:     "12345",
			SharedTables: []string{"countries"},
		},
	}
	parser := &PostgresParser{}

	failTests := []struct {
		name string
		sql  string
	}{
		{
			name: "direct assignment to tenant column",
			sql:  "UPDATE users SET tenant_id = '99999' WHERE id = 1",
		},
		{
			name: "quoted identifier tenant column",
			sql:  `UPDATE users SET "tenant_id" = '99999' WHERE id = 1`,
		},
		{
			name: "case-insensitive uppercase tenant column",
			sql:  "UPDATE users SET TENANT_ID = '99999' WHERE id = 1",
		},
		{
			name: "table-qualified tenant column",
			sql:  "UPDATE users SET users.tenant_id = '99999' WHERE id = 1",
		},
		{
			name: "alias-qualified tenant column",
			sql:  "UPDATE users u SET u.tenant_id = '99999' WHERE u.id = 1",
		},
		{
			name: "quoted alias and quoted tenant column",
			sql:  `UPDATE users u SET "u"."tenant_id" = '99999' WHERE u.id = 1`,
		},
		{
			name: "mixed valid and prohibited assignments",
			sql:  "UPDATE users SET name = 'alice', tenant_id = '99999' WHERE id = 1",
		},
		{
			name: "multi-column tuple assignment containing tenant column",
			sql:  "UPDATE users SET (name, tenant_id) = ('alice', '99999') WHERE id = 1",
		},
		{
			name: "array subscript assignment to tenant column",
			sql:  "UPDATE users SET tenant_id[1] = '99999' WHERE id = 1",
		},
		{
			name: "alias-qualified array subscript assignment to tenant column",
			sql:  "UPDATE users u SET u.tenant_id[1] = '99999' WHERE u.id = 1",
		},
		{
			name: "nested CTE update attempting tenant column modification",
			sql:  "WITH moved AS (UPDATE users SET tenant_id = '99999' WHERE id = 1 RETURNING id) SELECT * FROM moved",
		},
	}

	for _, tt := range failTests {
		t.Run("Fail_"+tt.name, func(t *testing.T) {
			_, _, err := parser.ApplyRules(tt.sql, rules, nil)
			if err == nil {
				t.Fatalf("expected error blocking tenant column modification, but query succeeded for: %s", tt.sql)
			}
			if !strings.Contains(err.Error(), "modifying tenant isolation column 'tenant_id' is prohibited") {
				t.Errorf("expected prohibited tenant column error, got: %v", err)
			}
		})
	}

	passTests := []struct {
		name     string
		sql      string
		expected string
	}{
		{
			name:     "unrelated column update",
			sql:      "UPDATE users SET name = 'alice', email = 'a@b.com' WHERE id = 1",
			expected: "UPDATE users SET name = 'alice', email = 'a@b.com' WHERE id = 1 AND tenant_id = '12345'",
		},
		{
			name:     "aliased table updating unrelated column",
			sql:      "UPDATE users u SET name = 'bob' WHERE u.id = 1",
			expected: "UPDATE users u SET name = 'bob' WHERE u.id = 1 AND tenant_id = '12345'",
		},
		{
			name:     "shared table update bypasses tenant isolation",
			sql:      "UPDATE countries SET name = 'Canada' WHERE code = 'CA'",
			expected: "UPDATE countries SET name = 'Canada' WHERE code = 'CA'",
		},
	}

	for _, tt := range passTests {
		t.Run("Pass_"+tt.name, func(t *testing.T) {
			rewritten, _, err := parser.ApplyRules(tt.sql, rules, nil)
			if err != nil {
				t.Fatalf("unexpected error for permitted update: %v", err)
			}
			if rewritten != tt.expected {
				t.Errorf("expected: %s, got: %s", tt.expected, rewritten)
			}
		})
	}

	t.Run("Pass_tenant_isolation_disabled", func(t *testing.T) {
		disabledRules := Rules{
			AllowedStatements: []string{"UPDATE"},
			TenantIsolation: &TenantIsolationRule{
				Enabled: false,
			},
		}
		sql := "UPDATE users SET tenant_id = '99999' WHERE id = 1"
		rewritten, _, err := parser.ApplyRules(sql, disabledRules, nil)
		if err != nil {
			t.Fatalf("unexpected error when tenant isolation is disabled: %v", err)
		}
		expected := "UPDATE users SET tenant_id = '99999' WHERE id = 1"
		if rewritten != expected {
			t.Errorf("expected: %s, got: %s", expected, rewritten)
		}
	})
}
