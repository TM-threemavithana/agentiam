package ast

// Rules defines the AST filtering rules to be applied to an incoming SQL statement.
type Rules struct {
	AllowedStatements  []string // e.g. "SELECT", "INSERT", "DROP"
	EnforceSelectLimit int      // 0 means no limit
}
