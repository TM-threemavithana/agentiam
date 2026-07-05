package ast

// Rules defines the AST filtering rules to be applied to an incoming SQL statement.
type Rules struct {
	AllowedStatements  []string `yaml:"allowed_statements"`
	AllowedTables      []string            `yaml:"allowed_tables"`
	BlockedFunctions   []string            `yaml:"blocked_functions"`
	MaskedColumns      map[string][]string `yaml:"masked_columns"`
	EnforceSelectLimit int                 `yaml:"enforce_select_limit"`
	MaxExecutionTimeMs int      `yaml:"max_execution_time_ms"`
	PoolMode           string   `yaml:"pool_mode"`
}
