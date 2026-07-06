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
	Dialect            string   `yaml:"dialect"`
	MaxComplexity      int      `yaml:"max_complexity"`
	TenantIsolation    *TenantIsolationRule `yaml:"tenant_isolation,omitempty"`
}

type TenantIsolationRule struct {
	Enabled      bool     `yaml:"enabled"`
	TenantColumn string   `yaml:"tenant_column"` // e.g., "tenant_id"
	TenantID     string   `yaml:"tenant_id"`     // Injected dynamically per agent session
	SharedTables []string `yaml:"shared_tables"` // Tables that DO NOT have a tenant column
}
