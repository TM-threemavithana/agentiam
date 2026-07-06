package ast

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/tm-threemavithana/agentiam/internal/cache"
)

type SnowflakeParser struct {
	mysqlParser MySQLParser
}

var (
	// Translate col::type to CAST(col AS type)
	snowflakeCastRegex = regexp.MustCompile(`([a-zA-Z0-9_\.]+)::([a-zA-Z0-9_]+)`)
	// Translate col:field to col.field (so ANSI parser understands it as object reference)
	snowflakeJsonRegex = regexp.MustCompile(`([a-zA-Z0-9_\.]+):([a-zA-Z0-9_]+)`)
)

func (p *SnowflakeParser) ApplyRules(sql string, rules Rules, astCache cache.ASTCache) (string, []int, error) {
	// Pre-sanitize Snowflake dialect to ANSI SQL
	sanitized := sql
	sanitized = snowflakeCastRegex.ReplaceAllStringFunc(sanitized, func(match string) string {
		parts := strings.Split(match, "::")
		col := parts[0]
		t := strings.ToLower(parts[1])

		switch t {
		case "int", "integer", "number":
			t = "SIGNED"
		case "varchar", "text", "string":
			t = "CHAR"
		case "float", "double":
			t = "DECIMAL"
		default:
			t = "CHAR"
		}
		return fmt.Sprintf("CAST(%s AS %s)", col, t)
	})
	sanitized = snowflakeJsonRegex.ReplaceAllString(sanitized, "$1.$2")

	// Apply standard MySQL/ANSI rules
	rewritten, stmtType, err := p.mysqlParser.ApplyRules(sanitized, rules, astCache)
	if err != nil {
		return "", nil, fmt.Errorf("Snowflake dialect parse error: %w", err)
	}

	return rewritten, stmtType, nil
}

type BigQueryParser struct {
	mysqlParser MySQLParser
}

var (
	// Translate `project.dataset.table` or `dataset.table` to a flat `project_dataset_table`
	// so the parser can check it against allowed tables without failing on dot notation or hyphens.
	bqTableRegex = regexp.MustCompile("`([a-zA-Z0-9\\-_\\.]+)\\.([a-zA-Z0-9\\-_\\.]+)\\.([a-zA-Z0-9\\-_\\.]+)`|`([a-zA-Z0-9\\-_\\.]+)\\.([a-zA-Z0-9\\-_\\.]+)`|`([a-zA-Z0-9\\-_]+)`")
)

func (p *BigQueryParser) ApplyRules(sql string, rules Rules, astCache cache.ASTCache) (string, []int, error) {
	sanitizedRules := rules
	if len(rules.AllowedTables) > 0 {
		sanitizedRules.AllowedTables = make([]string, len(rules.AllowedTables))
		for i, tbl := range rules.AllowedTables {
			sanitizedRules.AllowedTables[i] = cleanBQIdentifier(tbl)
		}
	}

	// Sanitize BigQuery identifiers in the SQL query
	sanitized := bqTableRegex.ReplaceAllStringFunc(sql, func(match string) string {
		cleaned := strings.Trim(match, "`")
		return "`" + cleanBQIdentifier(cleaned) + "`"
	})

	rewritten, stmtType, err := p.mysqlParser.ApplyRules(sanitized, sanitizedRules, astCache)
	if err != nil {
		return "", nil, fmt.Errorf("BigQuery dialect parse error: %w", err)
	}

	return rewritten, stmtType, nil
}

func cleanBQIdentifier(id string) string {
	r := strings.NewReplacer(".", "_", "-", "_")
	return r.Replace(id)
}

type DatabricksParser struct {
	mysqlParser MySQLParser
}

func (p *DatabricksParser) ApplyRules(sql string, rules Rules, astCache cache.ASTCache) (string, []int, error) {
	// Databricks SQL is fully ANSI/MySQL compliant but can support custom analytics syntax
	// We pass it directly to the MySQL/ANSI parser.
	return p.mysqlParser.ApplyRules(sql, rules, astCache)
}
