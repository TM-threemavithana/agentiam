package ast

import (
	"fmt"
	"reflect"
	"strings"

	pg_query "github.com/pganalyze/pg_query_go/v6"
)

func InjectTenantIsolation(stmt *pg_query.Node, rules Rules) error {
	if rules.TenantIsolation == nil || !rules.TenantIsolation.Enabled {
		return nil
	}

	injected := make(map[*pg_query.Node]bool)
	return walkTenantNode(stmt, rules.TenantIsolation, injected)
}

func walkTenantNode(node *pg_query.Node, rule *TenantIsolationRule, injected map[*pg_query.Node]bool) error {
	if node == nil || injected[node] {
		return nil
	}
	injected[node] = true

	switch n := node.Node.(type) {
	case *pg_query.Node_SelectStmt:
		sel := n.SelectStmt
		for i, fromItem := range sel.FromClause {
			sel.FromClause[i] = rewriteFromItem(fromItem, rule, injected)
		}
	case *pg_query.Node_UpdateStmt:
		rel := n.UpdateStmt.Relation
		if rel != nil && !isSharedTable(rel.Relname, rule.SharedTables) {
			newCond := buildTenantWhereClause(rule)
			if n.UpdateStmt.WhereClause == nil {
				n.UpdateStmt.WhereClause = newCond
			} else {
				n.UpdateStmt.WhereClause = wrapWithAnd(n.UpdateStmt.WhereClause, newCond)
			}
		}
	case *pg_query.Node_DeleteStmt:
		rel := n.DeleteStmt.Relation
		if rel != nil && !isSharedTable(rel.Relname, rule.SharedTables) {
			newCond := buildTenantWhereClause(rule)
			if n.DeleteStmt.WhereClause == nil {
				n.DeleteStmt.WhereClause = newCond
			} else {
				n.DeleteStmt.WhereClause = wrapWithAnd(n.DeleteStmt.WhereClause, newCond)
			}
		}
	case *pg_query.Node_InsertStmt:
		rel := n.InsertStmt.Relation
		if rel != nil && !isSharedTable(rel.Relname, rule.SharedTables) {
			return fmt.Errorf("INSERT statements into tenant-bound tables are not supported while TenantIsolation is enabled")
		}
	}

	return walkChildrenTenant(node.Node, rule, injected)
}

func walkChildrenTenant(v interface{}, rule *TenantIsolationRule, injected map[*pg_query.Node]bool) error {
	if v == nil {
		return nil
	}
	val := reflect.ValueOf(v)
	if !val.IsValid() {
		return nil
	}
	if val.Kind() == reflect.Ptr || val.Kind() == reflect.Interface {
		if val.IsNil() {
			return nil
		}
		return walkChildrenTenant(val.Elem().Interface(), rule, injected)
	}

	if val.Kind() == reflect.Struct {
		for i := 0; i < val.NumField(); i++ {
			field := val.Field(i)
			if !field.CanInterface() {
				continue
			}
			if field.Kind() == reflect.Ptr && !field.IsNil() {
				if n, ok := field.Interface().(*pg_query.Node); ok {
					if err := walkTenantNode(n, rule, injected); err != nil {
						return err
					}
					continue
				}
			}
			if err := walkChildrenTenant(field.Interface(), rule, injected); err != nil {
				return err
			}
		}
	} else if val.Kind() == reflect.Slice {
		for i := 0; i < val.Len(); i++ {
			elem := val.Index(i)
			if elem.Kind() == reflect.Ptr && !elem.IsNil() {
				if n, ok := elem.Interface().(*pg_query.Node); ok {
					if err := walkTenantNode(n, rule, injected); err != nil {
						return err
					}
					continue
				}
			}
			if err := walkChildrenTenant(elem.Interface(), rule, injected); err != nil {
				return err
			}
		}
	}
	return nil
}

func rewriteFromItem(node *pg_query.Node, rule *TenantIsolationRule, injected map[*pg_query.Node]bool) *pg_query.Node {
	if node == nil {
		return nil
	}
	switch n := node.Node.(type) {
	case *pg_query.Node_RangeVar:
		return replaceRangeVarWithSubselect(n, rule, injected)
	case *pg_query.Node_JoinExpr:
		n.JoinExpr.Larg = rewriteFromItem(n.JoinExpr.Larg, rule, injected)
		n.JoinExpr.Rarg = rewriteFromItem(n.JoinExpr.Rarg, rule, injected)
		return node
	}
	return node
}

func replaceRangeVarWithSubselect(n *pg_query.Node_RangeVar, rule *TenantIsolationRule, injected map[*pg_query.Node]bool) *pg_query.Node {
	relName := n.RangeVar.Relname
	if isSharedTable(relName, rule.SharedTables) {
		return &pg_query.Node{Node: n}
	}

	aliasName := relName
	if n.RangeVar.Alias != nil {
		aliasName = n.RangeVar.Alias.Aliasname
	}

	// Build the inner range var
	innerRv := &pg_query.Node{
		Node: &pg_query.Node_RangeVar{
			RangeVar: &pg_query.RangeVar{
				Relname: relName,
				Inh:     true,
			},
		},
	}
	// Mark the inner range var as injected so we don't process it and loop infinitely
	injected[innerRv] = true

	subquery := &pg_query.SelectStmt{
		TargetList: []*pg_query.Node{
			{
				Node: &pg_query.Node_ResTarget{
					ResTarget: &pg_query.ResTarget{
						Val: &pg_query.Node{
							Node: &pg_query.Node_ColumnRef{
								ColumnRef: &pg_query.ColumnRef{
									Fields: []*pg_query.Node{
										{Node: &pg_query.Node_AStar{AStar: &pg_query.A_Star{}}},
									},
								},
							},
						},
					},
				},
			},
		},
		FromClause: []*pg_query.Node{
			innerRv,
		},
		WhereClause: buildTenantWhereClause(rule),
	}

	subqueryNode := &pg_query.Node{
		Node: &pg_query.Node_SelectStmt{SelectStmt: subquery},
	}
	// Mark the injected subquery select statement to prevent loop
	injected[subqueryNode] = true

	return &pg_query.Node{
		Node: &pg_query.Node_RangeSubselect{
			RangeSubselect: &pg_query.RangeSubselect{
				Subquery: subqueryNode,
				Alias: &pg_query.Alias{
					Aliasname: aliasName,
				},
			},
		},
	}
}

func buildTenantWhereClause(rule *TenantIsolationRule) *pg_query.Node {
	return &pg_query.Node{
		Node: &pg_query.Node_AExpr{
			AExpr: &pg_query.A_Expr{
				Kind: pg_query.A_Expr_Kind_AEXPR_OP,
				Name: []*pg_query.Node{
					{Node: &pg_query.Node_String_{String_: &pg_query.String{Sval: "="}}},
				},
				Lexpr: &pg_query.Node{
					Node: &pg_query.Node_ColumnRef{
						ColumnRef: &pg_query.ColumnRef{
							Fields: []*pg_query.Node{
								{Node: &pg_query.Node_String_{String_: &pg_query.String{Sval: rule.TenantColumn}}},
							},
						},
					},
				},
				Rexpr: &pg_query.Node{
					Node: &pg_query.Node_AConst{
						AConst: &pg_query.A_Const{
							Val: &pg_query.A_Const_Sval{
								Sval: &pg_query.String{Sval: rule.TenantID},
							},
							Isnull: false,
						},
					},
				},
			},
		},
	}
}

func wrapWithAnd(existing, newCond *pg_query.Node) *pg_query.Node {
	return &pg_query.Node{
		Node: &pg_query.Node_BoolExpr{
			BoolExpr: &pg_query.BoolExpr{
				Boolop: pg_query.BoolExprType_AND_EXPR,
				Args: []*pg_query.Node{
					existing,
					newCond,
				},
			},
		},
	}
}

func isSharedTable(relName string, sharedTables []string) bool {
	for _, t := range sharedTables {
		if strings.EqualFold(t, relName) {
			return true
		}
	}
	return false
}
