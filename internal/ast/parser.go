package ast

import "agentiam/internal/cache"

// ASTParser defines a generic interface for SQL dialect parsers to validate and rewrite queries against AgentIAM rules.
type ASTParser interface {
	ApplyRules(sql string, rules Rules, astCache cache.ASTCache) (string, error)
}
