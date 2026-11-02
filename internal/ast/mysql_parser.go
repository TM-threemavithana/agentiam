package ast

import (
	"bytes"
	"fmt"
	"sort"
	"strings"

	"github.com/tm-threemavithana/agentiam/internal/cache"

	"github.com/pingcap/tidb/pkg/parser"
	"github.com/pingcap/tidb/pkg/parser/ast"
	"github.com/pingcap/tidb/pkg/parser/format"
	"github.com/pingcap/tidb/pkg/parser/test_driver"
)

// MySQLParser implements the ASTParser interface for MySQL dialects using pingcap/tidb.
type MySQLParser struct{}

func (p *MySQLParser) ApplyRules(sql string, rules Rules, astCache cache.ASTCache) (string, []int, error) {
	// Note on astCache: MySQLParser is intentionally stateless and executes fresh AST transformations
	// per query rather than caching deparsed ASTs. This avoids cross-tenant cache contamination,
	// policy-drift desynchronization, and cache poisoning risks across multi-tenant agent sessions.
	// The astCache parameter is retained to satisfy the ASTParser interface.

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

	if err := InjectMySQLTenantIsolation(stmt, rules); err != nil {
		return "", nil, fmt.Errorf("tenant isolation failed: %w", err)
	}

	if rules.MaxComplexity > 0 {
		cv := &complexityVisitor{}
		stmt.Accept(cv)
		if cv.score > rules.MaxComplexity {
			return "", nil, fmt.Errorf("policy violation: query complexity %d exceeds maximum of %d", cv.score, rules.MaxComplexity)
		}
	}

	v := &mysqlVisitor{rules: rules}
	stmt.Accept(v)

	if v.blocked {
		return "", nil, v.blockErr
	}
	v.resolveLimitParams()

	// Policy enforcement: fail-closed rejection of statements that require stateful sessions
	// regardless of what rules.AllowedStatements contains. In a stateless proxy, transaction control,
	// session variable/configuration mutation, and table locks cannot be executed safely.
	switch v.stmtType {
	case "BEGIN", "COMMIT", "ROLLBACK":
		return "", nil, fmt.Errorf("policy violation: statement %s not allowed: transaction control unsupported in stateless proxy", v.stmtType)
	case "SET":
		return "", nil, fmt.Errorf("policy violation: statement SET not allowed: session configuration mutation unsupported in stateless proxy")
	case "LOCK":
		return "", nil, fmt.Errorf("policy violation: statement LOCK not allowed: table locking unsupported in stateless proxy")
	}

	// Policy enforcement: check if statement type is allowed
	if !isAllowed(v.stmtType, rules.AllowedStatements) {
		if v.stmtType == "" {
			return "", nil, fmt.Errorf("policy violation: statement not allowed")
		}
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

	return sb.String(), v.limitParams, nil
}

type mysqlVisitor struct {
	rules             Rules
	blocked           bool
	blockErr          error
	stmtType          string
	tables            []string
	limitParams       []int
	allMarkers        []*test_driver.ParamMarkerExpr
	limitCountMarkers []*test_driver.ParamMarkerExpr
}

func extractLimitUint(val interface{}) (uint64, bool) {
	switch v := val.(type) {
	case uint64:
		return v, true
	case int64:
		if v < 0 {
			return 0, false
		}
		return uint64(v), true
	case int:
		if v < 0 {
			return 0, false
		}
		return uint64(v), true
	case uint:
		return uint64(v), true
	default:
		return 0, false
	}
}

func (v *mysqlVisitor) resolveLimitParams() {
	if len(v.limitCountMarkers) == 0 {
		return
	}
	// Sort all parameter markers by byte offset ascending to determine their 1-based index
	sort.Slice(v.allMarkers, func(i, j int) bool {
		return v.allMarkers[i].Offset < v.allMarkers[j].Offset
	})

	for _, limitPm := range v.limitCountMarkers {
		for idx, m := range v.allMarkers {
			if m == limitPm {
				v.limitParams = append(v.limitParams, idx+1)
				break
			}
		}
	}
}

func (v *mysqlVisitor) Enter(in ast.Node) (ast.Node, bool) {
	if v.blocked {
		return in, true // skip processing
	}

	if pm, ok := in.(*test_driver.ParamMarkerExpr); ok {
		v.allMarkers = append(v.allMarkers, pm)
	}

	switch node := in.(type) {
	case *ast.SelectStmt:
		if v.stmtType == "" {
			v.stmtType = "SELECT"
		}
		if v.rules.EnforceSelectLimit > 0 {
			if node.Limit == nil {
				pr := parser.New()
				if dummyNodes, _, err := pr.Parse(fmt.Sprintf("SELECT 1 LIMIT %d", v.rules.EnforceSelectLimit), "", ""); err == nil {
					node.Limit = dummyNodes[0].(*ast.SelectStmt).Limit
				}
			} else {
				if node.Limit.Count == nil {
					v.blocked = true
					v.blockErr = fmt.Errorf("policy violation: invalid LIMIT count")
					return in, true
				}
				if pm, ok := node.Limit.Count.(*test_driver.ParamMarkerExpr); ok {
					v.limitCountMarkers = append(v.limitCountMarkers, pm)
				} else if valExpr, ok := node.Limit.Count.(ast.ValueExpr); ok {
					limitVal, valid := extractLimitUint(valExpr.GetValue())
					if !valid {
						v.blocked = true
						v.blockErr = fmt.Errorf("policy violation: invalid LIMIT value")
						return in, true
					}
					if limitVal > uint64(v.rules.EnforceSelectLimit) {
						valExpr.SetValue(uint64(v.rules.EnforceSelectLimit))
					}
				} else {
					v.blocked = true
					v.blockErr = fmt.Errorf("policy violation: unsupported or dynamic LIMIT expression")
					return in, true
				}
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
	case *ast.BeginStmt:
		if v.stmtType == "" {
			v.stmtType = "BEGIN"
		}
		v.blocked = true
		v.blockErr = fmt.Errorf("policy violation: statement BEGIN not allowed: transaction control unsupported in stateless proxy")
		return in, true
	case *ast.CommitStmt:
		if v.stmtType == "" {
			v.stmtType = "COMMIT"
		}
		v.blocked = true
		v.blockErr = fmt.Errorf("policy violation: statement COMMIT not allowed: transaction control unsupported in stateless proxy")
		return in, true
	case *ast.RollbackStmt:
		if v.stmtType == "" {
			v.stmtType = "ROLLBACK"
		}
		v.blocked = true
		v.blockErr = fmt.Errorf("policy violation: statement ROLLBACK not allowed: transaction control unsupported in stateless proxy")
		return in, true
	case *ast.SetStmt:
		if v.stmtType == "" {
			v.stmtType = "SET"
		}
		v.blocked = true
		v.blockErr = fmt.Errorf("policy violation: statement SET not allowed: session configuration mutation unsupported in stateless proxy")
		return in, true
	case *ast.LockTablesStmt, *ast.UnlockTablesStmt:
		if v.stmtType == "" {
			v.stmtType = "LOCK"
		}
		v.blocked = true
		v.blockErr = fmt.Errorf("policy violation: statement LOCK not allowed: table locking unsupported in stateless proxy")
		return in, true
	case *ast.CreateTableStmt:
		if node.TemporaryKeyword != ast.TemporaryNone {
			v.blocked = true
			v.blockErr = fmt.Errorf("policy violation: statement CREATE TEMPORARY TABLE not allowed: temporary tables unsupported in stateless proxy")
			return in, true
		}
		if v.stmtType == "" {
			v.stmtType = "CREATE"
		}
	case *ast.VariableExpr:
		if node.Value != nil {
			v.blocked = true
			v.blockErr = fmt.Errorf("policy violation: variable assignment not allowed: session variables unsupported in stateless proxy")
			return in, true
		}
	case *ast.VariableAssignment:
		v.blocked = true
		v.blockErr = fmt.Errorf("policy violation: variable assignment not allowed: session variables unsupported in stateless proxy")
		return in, true
	case *ast.TableName:
		// Extract table names
		v.tables = append(v.tables, node.Name.O)
	case *ast.FuncCallExpr:
		funcName := strings.ToLower(node.FnName.O)
		switch funcName {
		case "get_lock", "release_lock", "release_all_locks":
			v.blocked = true
			v.blockErr = fmt.Errorf("policy violation: function %s is blocked: advisory locking unsupported in stateless proxy", strings.ToUpper(node.FnName.O))
			return in, true
		}
		if funcName == "last_insert_id" && len(node.Args) > 0 {
			v.blocked = true
			v.blockErr = fmt.Errorf("policy violation: function LAST_INSERT_ID with argument not allowed: session mutation unsupported in stateless proxy")
			return in, true
		}
		for _, blocked := range v.rules.BlockedFunctions {
			if strings.EqualFold(funcName, blocked) {
				v.blocked = true
				v.blockErr = fmt.Errorf("policy violation: function %s is blocked", node.FnName.O)
				return in, true
			}
		}
	}
	return in, false
}

func (v *mysqlVisitor) Leave(in ast.Node) (ast.Node, bool) {
	return in, true
}

type complexityVisitor struct {
	score int
}

func (v *complexityVisitor) Enter(in ast.Node) (ast.Node, bool) {
	switch node := in.(type) {
	case *ast.Join:
		if node.Right != nil {
			v.score += 5
		}
	case *ast.SelectStmt:
		v.score += 2
		if node.Where != nil {
			v.score += 1
		}
		if node.OrderBy != nil {
			v.score += 2
		}
		if node.GroupBy != nil {
			v.score += 3
		}
	}
	return in, false
}

func (v *complexityVisitor) Leave(in ast.Node) (ast.Node, bool) {
	return in, true
}
