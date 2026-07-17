package ast

import (
	"strings"
	"testing"

	"github.com/tm-threemavithana/agentiam/internal/cache"
)

func TestSnowflakeParser_ApplyRules(t *testing.T) {
	parser := &SnowflakeParser{}
	c, _ := cache.NewLocalCache(10)

	rules := Rules{
		AllowedStatements:  []string{"SELECT"},
		AllowedTables:      []string{"users"},
		EnforceSelectLimit: 1000,
	}

	// 1. Valid query using Snowflake double-colon cast and colon JSON query
	sql := "SELECT id::integer, profile:name FROM users"
	_, _, err := parser.ApplyRules(sql, rules, c)
	if err != nil {
		t.Fatalf("unexpected Snowflake parsing failure: %v", err)
	}

	// 2. Query trying to access blocked table
	sqlBlocked := "SELECT id::integer, profile:name FROM passwords"
	_, _, err = parser.ApplyRules(sqlBlocked, rules, c)
	if err == nil {
		t.Fatal("expected policy violation for table passwords, got nil")
	}
}

func TestBigQueryParser_ApplyRules(t *testing.T) {
	parser := &BigQueryParser{}
	c, _ := cache.NewLocalCache(10)

	rules := Rules{
		AllowedStatements:  []string{"SELECT"},
		AllowedTables:      []string{"my-project.my_dataset.users"},
		EnforceSelectLimit: 1000,
	}

	// 1. Valid BigQuery table reference using backticks and hyphens/dots
	sql := "SELECT id FROM `my-project.my_dataset.users`"
	_, _, err := parser.ApplyRules(sql, rules, c)
	if err != nil {
		t.Fatalf("unexpected BigQuery parsing failure: %v", err)
	}

	// 2. Query trying to access blocked table
	sqlBlocked := "SELECT id FROM `my-project.my_dataset.passwords`"
	_, _, err = parser.ApplyRules(sqlBlocked, rules, c)
	if err == nil {
		t.Fatal("expected policy violation for table passwords, got nil")
	}
}

// TestSnowflakeParser_CastTranslation verifies that ::type is rewritten to CAST(col AS type).
func TestSnowflakeParser_CastTranslation(t *testing.T) {
	parser := &SnowflakeParser{}
	c, _ := cache.NewLocalCache(10)
	rules := Rules{AllowedStatements: []string{"SELECT"}, AllowedTables: []string{"t"}, EnforceSelectLimit: 1000}

	out, _, err := parser.ApplyRules("SELECT col::int FROM t", rules, c)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(out, "CAST") {
		t.Errorf("expected CAST in output, got: %q", out)
	}
}

// TestSnowflakeParser_BlockedFunction ensures function blocking works through the Snowflake dialect.
func TestSnowflakeParser_BlockedFunction(t *testing.T) {
	parser := &SnowflakeParser{}
	c, _ := cache.NewLocalCache(10)
	rules := Rules{
		AllowedStatements: []string{"SELECT"},
		BlockedFunctions:  []string{"sleep"},
		EnforceSelectLimit: 100,
	}
	_, _, err := parser.ApplyRules("SELECT sleep(10) FROM t", rules, c)
	if err == nil {
		t.Error("expected sleep() to be blocked, got nil error")
	}
}

// TestSnowflakeParser_BlockedStatement ensures DELETE is blocked through the Snowflake dialect.
func TestSnowflakeParser_BlockedStatement(t *testing.T) {
	parser := &SnowflakeParser{}
	c, _ := cache.NewLocalCache(10)
	rules := Rules{AllowedStatements: []string{"SELECT"}, EnforceSelectLimit: 100}

	_, _, err := parser.ApplyRules("DELETE FROM t WHERE 1=1", rules, c)
	if err == nil {
		t.Error("expected DELETE to be blocked via Snowflake parser, got nil")
	}
}

// TestDatabricksParser_PassThrough verifies that Databricks SQL is treated as standard ANSI.
func TestDatabricksParser_PassThrough(t *testing.T) {
	parser := &DatabricksParser{}
	c, _ := cache.NewLocalCache(10)
	rules := Rules{AllowedStatements: []string{"SELECT"}, AllowedTables: []string{"users"}, EnforceSelectLimit: 100}

	_, _, err := parser.ApplyRules("SELECT id, name FROM users WHERE active = 1", rules, c)
	if err != nil {
		t.Errorf("expected Databricks SELECT to pass, got: %v", err)
	}
}

// TestDatabricksParser_BlockedStatement verifies DELETE is still blocked via Databricks parser.
func TestDatabricksParser_BlockedStatement(t *testing.T) {
	parser := &DatabricksParser{}
	c, _ := cache.NewLocalCache(10)
	rules := Rules{AllowedStatements: []string{"SELECT"}, EnforceSelectLimit: 100}

	_, _, err := parser.ApplyRules("DELETE FROM users WHERE id = 1", rules, c)
	if err == nil {
		t.Error("expected DELETE to be blocked via Databricks parser, got nil")
	}
}
