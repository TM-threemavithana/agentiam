package ast

import (
	"fmt"
	"strings"

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
				subSQL := fmt.Sprintf("SELECT * FROM %s WHERE %s = 'dummy'", tblName.Name.O, v.rule.TenantColumn)
				pr := parser.New()
				stmtNodes, _, err := pr.Parse(subSQL, "", "")
				if err != nil {
					v.err = fmt.Errorf("failed to parse injected tenant subquery: %w", err)
					return in, true
				}
				subSelect := stmtNodes[0].(*ast.SelectStmt)

				if binOp, ok := subSelect.Where.(*ast.BinaryOperationExpr); ok {
					if valExpr, ok := binOp.R.(ast.ValueExpr); ok {
						valExpr.SetValue(v.rule.TenantID)
					}
				}

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
		if node.TableRefs == nil || node.TableRefs.TableRefs == nil {
			v.err = fmt.Errorf("policy violation: invalid UPDATE statement without table references")
			return in, true
		}

		join := node.TableRefs.TableRefs

		// Multi-table UPDATE check
		if join.Right != nil {
			tables := extractMySQLJoinTables(join)
			hasTenantTable := false
			for _, t := range tables {
				if !isSharedTable(t, v.rule.SharedTables) {
				hasTenantTable = true
				break
				}
			}
			if hasTenantTable {
				if v.rule.TenantColumn != "" {
					for _, a := range node.List {
						if a != nil && a.Column != nil {
							if strings.EqualFold(a.Column.Name.O, v.rule.TenantColumn) || strings.EqualFold(a.Column.Name.L, v.rule.TenantColumn) {
								v.err = fmt.Errorf("policy violation: modifying tenant isolation column '%s' is prohibited", v.rule.TenantColumn)
								return in, true
							}
						}
					}
				}
				v.err = fmt.Errorf("policy violation: multi-table UPDATE statements are not supported while TenantIsolation is enabled")
				return in, true
			}
			return in, true
		}

		ts, ok := join.Left.(*ast.TableSource)
		if !ok {
			v.err = fmt.Errorf("policy violation: unsupported UPDATE table source structure")
			return in, true
		}

		v.injected[ts] = true // Don't rewrite as subquery

		tblName, ok := ts.Source.(*ast.TableName)
		if !ok {
			v.err = fmt.Errorf("policy violation: unsupported UPDATE target table")
			return in, true
		}

		if !isSharedTable(tblName.Name.O, v.rule.SharedTables) {
			if v.rule.TenantColumn != "" {
				for _, a := range node.List {
					if a != nil && a.Column != nil {
						if strings.EqualFold(a.Column.Name.O, v.rule.TenantColumn) || strings.EqualFold(a.Column.Name.L, v.rule.TenantColumn) {
							v.err = fmt.Errorf("policy violation: modifying tenant isolation column '%s' is prohibited", v.rule.TenantColumn)
							return in, true
						}
					}
				}
			}

			node.Where = appendTenantConditionMySQL(node.Where, v.rule)
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

func buildTenantConditionMySQL(rule *TenantIsolationRule) ast.ExprNode {
	tenantCondStr := fmt.Sprintf("%s = 'dummy'", rule.TenantColumn)
	pr := parser.New()
	// Parse a dummy select to extract the WHERE condition
	stmtNodes, _, err := pr.Parse(fmt.Sprintf("SELECT 1 WHERE %s", tenantCondStr), "", "")
	if err != nil {
		return nil
	}
	sel := stmtNodes[0].(*ast.SelectStmt)
	newCond := sel.Where

	if binOp, ok := newCond.(*ast.BinaryOperationExpr); ok {
		if valExpr, ok := binOp.R.(ast.ValueExpr); ok {
			valExpr.SetValue(rule.TenantID)
		}
	}
	return newCond
}

func appendTenantConditionMySQL(where ast.ExprNode, rule *TenantIsolationRule) ast.ExprNode {
	newCond := buildTenantConditionMySQL(rule)
	if newCond == nil {
		return where
	}

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


func extractMySQLJoinTables(node ast.ResultSetNode) []string {
	if node == nil {
		return nil
	}
	var tables []string
	switch n := node.(type) {
	case *ast.Join:
		if n.Left != nil {
			tables = append(tables, extractMySQLJoinTables(n.Left)...)
		}
		if n.Right != nil {
			tables = append(tables, extractMySQLJoinTables(n.Right)...)
		}
	case *ast.TableSource:
		if tblName, ok := n.Source.(*ast.TableName); ok && tblName != nil {
			tables = append(tables, tblName.Name.O)
		}
	}
	return tables
}
