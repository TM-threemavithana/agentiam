package ast

import (
	"bytes"
	"fmt"

	"agentiam/internal/cache"

	"github.com/pingcap/tidb/pkg/parser"
	"github.com/pingcap/tidb/pkg/parser/ast"
	"github.com/pingcap/tidb/pkg/parser/format"
	_ "github.com/pingcap/tidb/pkg/parser/test_driver"
)

// MySQLParser implements the ASTParser interface for MySQL dialects using pingcap/tidb.
type MySQLParser struct{}

func (p *MySQLParser) ApplyRules(sql string, rules Rules, astCache cache.ASTCache) (string, error) {
	// For production, the parser instance should be pooled, but this works for POC
	pr := parser.New()
	stmtNodes, _, err := pr.Parse(sql, "", "")
	if err != nil {
		return "", fmt.Errorf("MySQL syntax error: %w", err)
	}

	if len(stmtNodes) == 0 {
		return "", fmt.Errorf("no statements found")
	}
	if len(stmtNodes) > 1 {
		return "", fmt.Errorf("policy violation: multiple statements not allowed")
	}

	stmt := stmtNodes[0]

	v := &mysqlVisitor{rules: rules}
	stmt.Accept(v)

	if v.blocked {
		return "", v.blockErr
	}

	// Policy enforcement: check if statement type is allowed
	if !isAllowed(v.stmtType, rules.AllowedStatements) {
		return "", fmt.Errorf("policy violation: statement %s not allowed", v.stmtType)
	}

	// Policy enforcement: check if tables are allowed
	for _, table := range v.tables {
		if !isAllowed(table, rules.AllowedTables) {
			return "", fmt.Errorf("policy violation: access to table %s denied", table)
		}
	}

	// Format and return the transformed SQL
	var sb bytes.Buffer
	ctx := format.NewRestoreCtx(format.DefaultRestoreFlags, &sb)
	if err := stmt.Restore(ctx); err != nil {
		return "", fmt.Errorf("failed to restore AST: %w", err)
	}

	return sb.String(), nil
}

type mysqlVisitor struct {
	rules    Rules
	blocked  bool
	blockErr error
	stmtType string
	tables   []string
}

func (v *mysqlVisitor) Enter(in ast.Node) (ast.Node, bool) {
	if v.blocked {
		return in, true // skip processing
	}

	switch node := in.(type) {
	case *ast.SelectStmt:
		if v.stmtType == "" {
			v.stmtType = "SELECT"
		}
		// Inject limit if missing and enforce is configured
		if v.rules.EnforceSelectLimit > 0 && node.Limit == nil {
			// Note: properly injecting AST nodes into pingcap requires constructing ValueExprs.
			// For simplicity in this roadmap step, we'll track but not full-inject here.
			// A full implementation would inject `node.Limit = &ast.Limit{...}`
		}
	case *ast.InsertStmt:
		if v.stmtType == "" {
			v.stmtType = "INSERT"
		}
	case *ast.UpdateStmt:
		if v.stmtType == "" {
			v.stmtType = "UPDATE"
		}
	case *ast.DeleteStmt:
		if v.stmtType == "" {
			v.stmtType = "DELETE"
		}
	case *ast.TableName:
		// Extract table names
		v.tables = append(v.tables, node.Name.O)
	}
	return in, false
}

func (v *mysqlVisitor) Leave(in ast.Node) (ast.Node, bool) {
	return in, true
}



