package ast

import (
	"testing"

	"github.com/tm-threemavithana/agentiam/internal/cache"
)

func TestSnowflakeParser_ApplyRules(t *testing.T) {
	parser := &SnowflakeParser{}
	c, _ := cache.NewLocalCache(10)

	rules := Rules{
		AllowedStatements: []string{"SELECT"},
		AllowedTables:     []string{"users"},
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
		AllowedStatements: []string{"SELECT"},
		AllowedTables:     []string{"my-project.my_dataset.users"},
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
