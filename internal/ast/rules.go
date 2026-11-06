package ast

// ViewPolicy defines an explicitly approved database view, its underlying base table,
// column mappings, and column masking rules.
type ViewPolicy struct {
	Name                  string            `yaml:"name" json:"name"`
	BaseTable             string            `yaml:"base_table" json:"base_table"`
	ColumnMappings        map[string]string `yaml:"column_mappings" json:"column_mappings"`               // view_column -> base_column
	MaskedColumns         []string          `yaml:"masked_columns" json:"masked_columns"`                 // explicit view columns to mask
	UnexposedColumns      []string          `yaml:"unexposed_columns" json:"unexposed_columns"`           // base table sensitive columns confirmed NOT projected by view
	DefinitionFingerprint string            `yaml:"definition_fingerprint" json:"definition_fingerprint"` // expected view definition SHA-256 hash or canonical SQL
}

// Rules defines the AST filtering rules to be applied to an incoming SQL statement.
type Rules struct {
	AllowedStatements          []string             `yaml:"allowed_statements"`
	AllowedTables              []string             `yaml:"allowed_tables"`
	Views                      []ViewPolicy         `yaml:"views"`
	BlockedFunctions           []string             `yaml:"blocked_functions"`
	MaskedColumns              map[string][]string  `yaml:"masked_columns"`
	EnforceSelectLimit         int                  `yaml:"enforce_select_limit"`
	MaxExecutionTimeMs         int                  `yaml:"max_execution_time_ms"`
	PoolMode                   string               `yaml:"pool_mode"`
	Dialect                    string               `yaml:"dialect"`
	MaxComplexity              int                  `yaml:"max_complexity"`
	TenantIsolation            *TenantIsolationRule `yaml:"tenant_isolation,omitempty"`
	RequireCatalogVerification bool                 `yaml:"require_catalog_verification,omitempty"`
	VerifiedViews              map[string]bool      `yaml:"verified_views,omitempty"`
}

type TenantIsolationRule struct {
	Enabled      bool     `yaml:"enabled"`
	TenantColumn string   `yaml:"tenant_column"` // e.g., "tenant_id"
	TenantID     string   `yaml:"tenant_id"`     // Injected dynamically per agent session
	SharedTables []string `yaml:"shared_tables"` // Tables that DO NOT have a tenant column
}
