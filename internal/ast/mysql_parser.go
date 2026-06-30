package ast

import (
	"bytes"
	"fmt"
	"strings"

	"github.com/tm-threemavithana/agentiam/internal/cache"

	"github.com/pingcap/tidb/pkg/parser"
	"github.com/pingcap/tidb/pkg/parser/ast"
	"github.com/pingcap/tidb/pkg/parser/format"
	_ "github.com/pingcap/tidb/pkg/parser/test_driver"
)

// MySQLParser implements the ASTParser interface for MySQL dialects using pingcap/tidb.
type MySQLParser struct{}

func (p *MySQLParser) ApplyRules(sql string, rules Rules, astCache cache.ASTCache) (string, []int, error) {
	// For production, the parser instance should be pooled, but this works for POC
	pr := parser.New()
	stmtNodes, _, err := pr.Parse(sql, "", "")
	if err != nil {
		return "", nil, fmt.Errorf("MySQL syntax error: %w", err)
	}

	if len(stmtNodes) == 0 {
		return "", nil, fmt.Errorf("no statements found")
	}
	if len(stmtNodes) > 1 {
		return "", nil, fmt.Errorf("policy violation: multiple statements not allowed")
	}

	stmt := stmtNodes[0]

	v := &mysqlVisitor{rules: rules}
	stmt.Accept(v)

	if v.blocked {
		return "", nil, v.blockErr
	}

	// Policy enforcement: check if statement type is allowed
	if !isAllowed(v.stmtType, rules.AllowedStatements) {
		return "", nil, fmt.Errorf("policy violation: statement %s not allowed", v.stmtType)
	}

	// Policy enforcement: check if tables are allowed
	for _, table := range v.tables {
		if !isAllowed(table, rules.AllowedTables) {
			return "", nil, fmt.Errorf("policy violation: access to table %s denied", table)
		}
	}

	// Format and return the transformed SQL
	var sb bytes.Buffer
	ctx := format.NewRestoreCtx(format.DefaultRestoreFlags, &sb)
	if err := stmt.Restore(ctx); err != nil {
		return "", nil, fmt.Errorf("failed to restore AST: %w", err)
	}

	return sb.String(), nil, nil
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
		if v.rules.EnforceSelectLimit > 0 && node.Limit == nil {
			pr := parser.New()
			if dummyNodes, _, err := pr.Parse(fmt.Sprintf("SELECT 1 LIMIT %d", v.rules.EnforceSelectLimit), "", ""); err == nil {
				node.Limit = dummyNodes[0].(*ast.SelectStmt).Limit
			}
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
	case *ast.FuncCallExpr:
		funcName := node.FnName.O
		for _, blocked := range v.rules.BlockedFunctions {
			if strings.EqualFold(funcName, blocked) {
				v.blocked = true
				v.blockErr = fmt.Errorf("policy violation: function %s is blocked", funcName)
				return in, true
			}
		}
	}
	return in, false
}

func (v *mysqlVisitor) Leave(in ast.Node) (ast.Node, bool) {
	return in, true
}
