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
	switch n := node.Node.(type) {
	case *pg_query.Node_SelectStmt:
		sel := n.SelectStmt
		if rules.EnforceSelectLimit > 0 {
			if sel.LimitCount == nil {
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
				sel.LimitOption = pg_query.LimitOption_LIMIT_OPTION_COUNT
			} else {
				// Try to cap existing limit
				if aconst, ok := sel.LimitCount.Node.(*pg_query.Node_AConst); ok {
					if ival, ok := aconst.AConst.Val.(*pg_query.A_Const_Ival); ok {
						if ival.Ival.Ival > int32(rules.EnforceSelectLimit) {
							ival.Ival.Ival = int32(rules.EnforceSelectLimit)
						}
					}
				}
			}
		}
	case *pg_query.Node_InsertStmt:
		if isBlocked("INSERT", rules.BlockedStatements) {
			return fmt.Errorf("INSERT statements are not allowed by policy")
		}
	case *pg_query.Node_UpdateStmt:
		if isBlocked("UPDATE", rules.BlockedStatements) {
			return fmt.Errorf("UPDATE statements are not allowed by policy")
		}
	case *pg_query.Node_DeleteStmt:
		if isBlocked("DELETE", rules.BlockedStatements) {
			return fmt.Errorf("DELETE statements are not allowed by policy")
		}
	case *pg_query.Node_DropStmt:
		if isBlocked("DROP", rules.BlockedStatements) {
			return fmt.Errorf("DROP statements are not allowed by policy")
		}
	case *pg_query.Node_TruncateStmt:
		if isBlocked("TRUNCATE", rules.BlockedStatements) {
			return fmt.Errorf("TRUNCATE statements are not allowed by policy")
		}
	case *pg_query.Node_AlterTableStmt, *pg_query.Node_AlterRoleStmt, *pg_query.Node_AlterSystemStmt, *pg_query.Node_AlterDatabaseStmt:
		if isBlocked("ALTER", rules.BlockedStatements) {
			return fmt.Errorf("ALTER statements are not allowed by policy")
		}
	}
	return nil
}

func isBlocked(stmtType string, blocked []string) bool {
	for _, b := range blocked {
		if strings.EqualFold(b, stmtType) {
			return true
		}
	}
	return false
}
