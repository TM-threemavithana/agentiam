package main

import (
	"fmt"
	"github.com/tm-threemavithana/agentiam/internal/ast"
)

func main() {
	sql := "SELECT * FROM users WHERE id = 1 AND (SELECT pg_sleep(10)) IS NULL;"
	rules := ast.Rules{
		AllowedStatements: []string{"SELECT"},
		AllowedTables:     []string{"users"},
		BlockedFunctions:  []string{"pg_sleep"},
	}
	parser := ast.NewPostgresParser()
	_, _, err := parser.ApplyRules(sql, rules, nil)
	fmt.Printf("Error: %v\n", err)
}
