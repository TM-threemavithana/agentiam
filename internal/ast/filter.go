package ast

import (
	"fmt"
	"strings"

	pg_query "github.com/pganalyze/pg_query_go/v5"
)

// ApplyRules parses the SQL, checks against the rules, and returns the potentially modified SQL (e.g. with LIMIT appended).
func ApplyRules(sql string, rules Rules) (string, error) {
	tree, err := pg_query.Parse(sql)
	if err != nil {
		return "", fmt.Errorf("failed to parse SQL: %w", err)
	}

	for _, stmt := range tree.Stmts {
		err = enforceRules(stmt.Stmt, rules)
		if err != nil {
			return "", err
		}
	}

	deparsed, err := pg_query.Deparse(tree)
	if err != nil {
		return "", fmt.Errorf("failed to deparse SQL: %w", err)
	}
	return deparsed, nil
}

func enforceRules(node *pg_query.Node, rules Rules) error {
	if len(rules.AllowedStatements) == 0 {
		return fmt.Errorf("policy has no allowed statements")
	}

	var withClause *pg_query.WithClause

	switch n := node.Node.(type) {
	case *pg_query.Node_SelectStmt:
		sel := n.SelectStmt
		withClause = sel.WithClause
		if len(sel.LockingClause) > 0 {
			return fmt.Errorf("SELECT ... FOR UPDATE/SHARE is not allowed by policy")
		}

		if rules.EnforceSelectLimit > 0 {
			var isNoLimit bool
			if sel.LimitCount == nil {
				isNoLimit = true
			} else if aconst, ok := sel.LimitCount.Node.(*pg_query.Node_AConst); ok && aconst.AConst.Isnull {
				isNoLimit = true // LIMIT ALL
			}

			if isNoLimit {
				// No limit, or LIMIT ALL
				sel.LimitCount = &pg_query.Node{
					Node: &pg_query.Node_AConst{
						AConst: &pg_query.A_Const{
							Val: &pg_query.A_Const_Ival{
								Ival: &pg_query.Integer{
									Ival: int32(rules.EnforceSelectLimit),
								},
							},
						},
					},
				}
				// Force standard limit syntax
				sel.LimitOption = pg_query.LimitOption_LIMIT_OPTION_COUNT
			} else {
				// A limit is specified. We must ensure it's not dynamic, and cap it.
				switch n := sel.LimitCount.Node.(type) {
				case *pg_query.Node_AConst:
					// Cap existing limit using 'lesser of'
					if ival, ok := n.AConst.Val.(*pg_query.A_Const_Ival); ok {
						if ival.Ival.Ival > int32(rules.EnforceSelectLimit) {
							ival.Ival.Ival = int32(rules.EnforceSelectLimit)
						}
					}
				case *pg_query.Node_ParamRef:
					return fmt.Errorf("parameterized limits (e.g. LIMIT $1) are not allowed by policy")
				default:
					return fmt.Errorf("dynamic limits are not allowed by policy")
				}
			}
		}
	case *pg_query.Node_InsertStmt:
		withClause = n.InsertStmt.WithClause
		if !isAllowed("INSERT", rules.AllowedStatements) {
			return fmt.Errorf("INSERT statements are not allowed by policy")
		}
	case *pg_query.Node_UpdateStmt:
		withClause = n.UpdateStmt.WithClause
		if !isAllowed("UPDATE", rules.AllowedStatements) {
			return fmt.Errorf("UPDATE statements are not allowed by policy")
		}
	case *pg_query.Node_DeleteStmt:
		withClause = n.DeleteStmt.WithClause
		if !isAllowed("DELETE", rules.AllowedStatements) {
			return fmt.Errorf("DELETE statements are not allowed by policy")
		}
	case *pg_query.Node_DropStmt:
		if !isAllowed("DROP", rules.AllowedStatements) {
			return fmt.Errorf("DROP statements are not allowed by policy")
		}
	case *pg_query.Node_TruncateStmt:
		if !isAllowed("TRUNCATE", rules.AllowedStatements) {
			return fmt.Errorf("TRUNCATE statements are not allowed by policy")
		}
	case *pg_query.Node_CreateStmt, *pg_query.Node_IndexStmt:
		if !isAllowed("CREATE", rules.AllowedStatements) {
			return fmt.Errorf("CREATE statements are not allowed by policy")
		}
	case *pg_query.Node_AlterTableStmt, *pg_query.Node_AlterRoleStmt, *pg_query.Node_AlterSystemStmt, *pg_query.Node_AlterDatabaseStmt:
		if !isAllowed("ALTER", rules.AllowedStatements) {
			return fmt.Errorf("ALTER statements are not allowed by policy")
		}
	case *pg_query.Node_TransactionStmt:
		// Always allow BEGIN/COMMIT/ROLLBACK as PgBouncer handles them and connection pooling relies on it.
		return nil
	case *pg_query.Node_VariableSetStmt:
		return fmt.Errorf("SET statements are not allowed by policy")
	case *pg_query.Node_ExplainStmt:
		for _, opt := range n.ExplainStmt.Options {
			if defElem, ok := opt.Node.(*pg_query.Node_DefElem); ok && defElem.DefElem.Defname == "analyze" {
				if defElem.DefElem.Arg == nil {
					return fmt.Errorf("EXPLAIN ANALYZE is not allowed by policy")
				}
				if strNode, ok := defElem.DefElem.Arg.Node.(*pg_query.Node_String_); ok {
					if isPostgresBoolFalse(strNode.String_.Sval) {
						continue // EXPLAIN (ANALYZE false) is planning only
					}
				}
				return fmt.Errorf("EXPLAIN ANALYZE is not allowed by policy")
			}
		}
		// Pure EXPLAIN or EXPLAIN (ANALYZE false)
		return enforceRules(n.ExplainStmt.Query, rules)
	default:
		return fmt.Errorf("statement type %T is not allowed by policy (Default Deny)", n)
	}

	if withClause != nil {
		for _, cte := range withClause.Ctes {
			if cteNode, ok := cte.Node.(*pg_query.Node_CommonTableExpr); ok {
				if err := enforceRules(cteNode.CommonTableExpr.Ctequery, rules); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

func isAllowed(stmtType string, allowed []string) bool {
	for _, a := range allowed {
		if strings.EqualFold(a, stmtType) {
			return true
		}
	}
	return false
}

func isPostgresBoolFalse(sval string) bool {
	switch strings.ToLower(sval) {
	case "false", "off", "no", "0":
		return true
	}
	return false
}
