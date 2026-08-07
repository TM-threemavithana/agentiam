package ast

import (
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
