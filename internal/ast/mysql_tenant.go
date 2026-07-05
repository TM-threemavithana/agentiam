package ast

import (
	"fmt"

	"github.com/pingcap/tidb/pkg/parser"
	"github.com/pingcap/tidb/pkg/parser/ast"
	"github.com/pingcap/tidb/pkg/parser/opcode"
)

// InjectMySQLTenantIsolation visits the AST and rewrites it to enforce tenant isolation.
func InjectMySQLTenantIsolation(stmt ast.Node, rules Rules) error {
	if rules.TenantIsolation == nil || !rules.TenantIsolation.Enabled {
		return nil
	}

	v := &mysqlTenantVisitor{
		rule:     rules.TenantIsolation,
		injected: make(map[ast.Node]bool),
	}
	stmt.Accept(v)

	if v.err != nil {
		return v.err
	}
	return nil
}

type mysqlTenantVisitor struct {
	rule     *TenantIsolationRule
	err      error
	injected map[ast.Node]bool
}

func (v *mysqlTenantVisitor) Enter(in ast.Node) (ast.Node, bool) {
	if v.err != nil {
		return in, true // abort
	}

	if v.injected[in] {
		return in, true // already processed, don't recurse
	}
	v.injected[in] = true

	switch node := in.(type) {
	case *ast.TableSource:
		// 1. SELECTs and JOINs (TableSource wrapping TableName)
		if tblName, ok := node.Source.(*ast.TableName); ok {
			if !isSharedTable(tblName.Name.O, v.rule.SharedTables) {
				subSQL := fmt.Sprintf("SELECT * FROM %s WHERE %s = '%s'", tblName.Name.O, v.rule.TenantColumn, v.rule.TenantID)
				pr := parser.New()
				stmtNodes, _, err := pr.Parse(subSQL, "", "")
				if err != nil {
					v.err = fmt.Errorf("failed to parse injected tenant subquery: %w", err)
					return in, true
				}
				subSelect := stmtNodes[0].(*ast.SelectStmt)
				// Prevent infinite recursion on the injected subquery
				v.injected[subSelect] = true
				v.injected[subSelect.From] = true
				v.injected[subSelect.From.TableRefs] = true
				v.injected[subSelect.From.TableRefs.Left] = true
				if ts, ok := subSelect.From.TableRefs.Left.(*ast.TableSource); ok {
					v.injected[ts.Source] = true
				}

				// Replace Source with subquery
				node.Source = subSelect
				// If there's no alias, use the original table name as the alias to preserve outer references
				if node.AsName.O == "" {
					node.AsName = tblName.Name
				}
			}
		}

	case *ast.UpdateStmt:
		// 2. UPDATEs
		if node.TableRefs != nil && node.TableRefs.TableRefs != nil {
			if ts, ok := node.TableRefs.TableRefs.Left.(*ast.TableSource); ok {
				v.injected[ts] = true // Don't rewrite as subquery
				if tblName, ok := ts.Source.(*ast.TableName); ok {
					if !isSharedTable(tblName.Name.O, v.rule.SharedTables) {
						node.Where = appendTenantConditionMySQL(node.Where, v.rule)
					}
				}
			}
		}

	case *ast.DeleteStmt:
		// 3. DELETEs
		if node.TableRefs != nil && node.TableRefs.TableRefs != nil {
			if ts, ok := node.TableRefs.TableRefs.Left.(*ast.TableSource); ok {
				v.injected[ts] = true // Don't rewrite as subquery
				if tblName, ok := ts.Source.(*ast.TableName); ok {
					if !isSharedTable(tblName.Name.O, v.rule.SharedTables) {
						node.Where = appendTenantConditionMySQL(node.Where, v.rule)
					}
				}
			}
		}

	case *ast.InsertStmt:
		// 4. INSERTs
		if node.Table != nil && node.Table.TableRefs != nil && node.Table.TableRefs.Left != nil {
			if ts, ok := node.Table.TableRefs.Left.(*ast.TableSource); ok {
				if tblName, ok := ts.Source.(*ast.TableName); ok {
					if !isSharedTable(tblName.Name.O, v.rule.SharedTables) {
						v.err = fmt.Errorf("INSERT statements into tenant-bound tables are not supported while TenantIsolation is enabled")
						return in, true
					}
				}
			}
		}
	}

	return in, false
}

func (v *mysqlTenantVisitor) Leave(in ast.Node) (ast.Node, bool) {
	return in, true
}

func appendTenantConditionMySQL(where ast.ExprNode, rule *TenantIsolationRule) ast.ExprNode {
	tenantCondStr := fmt.Sprintf("%s = '%s'", rule.TenantColumn, rule.TenantID)
	pr := parser.New()
	// Parse a dummy select to extract the WHERE condition
	stmtNodes, _, err := pr.Parse(fmt.Sprintf("SELECT 1 WHERE %s", tenantCondStr), "", "")
	if err != nil {
		return where
	}
	sel := stmtNodes[0].(*ast.SelectStmt)
	newCond := sel.Where

	if where == nil {
		return newCond
	}

	// Wrap in a binary operation (AND)
	return &ast.BinaryOperationExpr{
		Op: opcode.LogicAnd,
		L:  where,
		R:  newCond,
	}
}
