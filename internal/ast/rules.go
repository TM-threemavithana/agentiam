package ast

// Rules defines the AST filtering rules to be applied to an incoming SQL statement.
type Rules struct {
	AllowedStatements  []string
	AllowedTables      []string
	EnforceSelectLimit int
	MaxExecutionTimeMs int
	PoolMode           string
}
