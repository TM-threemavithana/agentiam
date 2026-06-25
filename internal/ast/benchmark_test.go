package ast

import (
	"testing"
)

func BenchmarkFilterAST(b *testing.B) {
	stmt := "SELECT id, name, email FROM users WHERE active = true"
	rules := Rules{
		EnforceSelectLimit: 50,
		AllowedStatements:  []string{"SELECT"},
	}

	// Ensure the WASM is initialized and cache is hit
	_, _ = (&PostgresParser{}).ApplyRules(stmt, rules, nil)

	b.Run("WithoutCache", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			// Change query slightly to avoid cache hits
			query := stmt + " -- " + string(rune(i%10000))
			_, _ = (&PostgresParser{}).ApplyRules(query, rules, nil)
		}
	})

	b.Run("WithCache", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			// Exact same query hits cache
			_, _ = (&PostgresParser{}).ApplyRules(stmt, rules, nil)
		}
	})
}


