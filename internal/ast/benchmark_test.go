package ast

import (
	"testing"
	"github.com/tm-threemavithana/agentiam/internal/cache"
)

func BenchmarkFilterAST(b *testing.B) {
	stmt := "SELECT id, name, email FROM users WHERE active = true"
	rules := Rules{
		EnforceSelectLimit: 50,
		AllowedStatements:  []string{"SELECT"},
	}

	// Ensure the WASM is initialized and cache is hit
	c, _ := cache.NewLocalCache(100)
	_, _, _ = (&PostgresParser{}).ApplyRules(stmt, rules, c)

	b.Run("WithoutCache", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			// Change query slightly to avoid cache hits
			query := stmt + " -- " + string(rune(i%10000))
			_, _, _ = (&PostgresParser{}).ApplyRules(query, rules, c)
		}
	})

	b.Run("WithCache", func(b *testing.B) {
		b.ResetTimer()
		for i := 0; i < b.N; i++ {
			// Exact same query hits cache
			_, _, _ = (&PostgresParser{}).ApplyRules(stmt, rules, c)
		}
	})
}
