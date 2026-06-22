package ast

// Rules defines the AST filtering rules to be applied to an incoming SQL statement.
type Rules struct {
	BlockedStatements  []string // e.g., ["INSERT", "UPDATE", "DELETE", "DROP", "ALTER", "TRUNCATE"]
	EnforceSelectLimit int      // e.g., 100
}
