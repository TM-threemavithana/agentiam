package main

import (
	"fmt"
	"log"

	"github.com/tm-threemavithana/agentiam/internal/ast"
)

func main() {
	sql := `SELECT pg_catalog.pg_class.relname FROM pg_catalog.pg_class JOIN pg_catalog.pg_namespace ON pg_catalog.pg_namespace.oid = pg_catalog.pg_class.relnamespace WHERE pg_catalog.pg_class.relkind = ANY (ARRAY['r', 'p']) AND pg_catalog.pg_class.relpersistence != 't' AND pg_catalog.pg_table_is_visible(pg_catalog.pg_class.oid) AND pg_catalog.pg_namespace.nspname != 'pg_catalog'`
	
	rules := ast.Rules{
		AllowedStatements: []string{"SelectStmt"},
		AllowedTables:     []string{"*"},
		EnforceSelectLimit: 100,
	}
	
	parser := &ast.PostgresParser{}
	deparsed, _, err := parser.ApplyRules(sql, rules, nil)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Deparsed:")
	fmt.Println(deparsed)
}
