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
	cacheKey := sql + fmt.Sprintf("%v", rules)
	if astCache != nil {
		if cached, ok := astCache.Get(cacheKey); ok {
			return cached.SQL, cached.LimitParams, nil
		}
	}

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

	deparsed := sb.String()
	if astCache != nil && isCacheable(sql) {
		astCache.Add(cacheKey, cache.CachedAST{
			SQL:         deparsed,
			LimitParams: v.limitParams,
		})
	}

	return deparsed, v.limitParams, nil
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
