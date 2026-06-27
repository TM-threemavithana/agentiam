package ast

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"

	"github.com/tm-threemavithana/agentiam/internal/cache"
	pg_query "github.com/pganalyze/pg_query_go/v6"
	"github.com/wasilibs/go-pgquery/parser"
	"google.golang.org/protobuf/proto"
)

var ErrComplexityExceeded = fmt.Errorf("Policy Violation: Maximum AST complexity exceeded")

type PostgresParser struct{}

// ApplyRules parses the SQL into an AST, checks it against the rules, injects limits, and returns the rewritten SQL.
func (p *PostgresParser) ApplyRules(sql string, rules Rules, astCache cache.ASTCache) (string, []int, error) {
	_, span := otel.Tracer("agentiam/ast").Start(context.Background(), "ApplyRules")
	defer span.End()

	start := time.Now()
	defer func() {
		ParsingDuration.Observe(time.Since(start).Seconds())
	}()

	cacheKey := fmt.Sprintf("%d:%s", rules.EnforceSelectLimit, sql)
	if astCache != nil {
		if cached, ok := astCache.Get(cacheKey); ok {
			AstCacheHitsTotal.Inc()
			span.SetAttributes(attribute.Bool("cache.hit", true))
			return cached, nil, nil // Cache does not store limitParams currently, but they shouldn't hit cache often if parameterized. TODO: cache limitparams
		}
	}
	AstCacheMissesTotal.Inc()
	span.SetAttributes(attribute.Bool("cache.hit", false))

	b, err := parser.ParseToProtobuf(sql)
	if err != nil {
		return "", nil, fmt.Errorf("failed to parse SQL: %w", err)
	}
	var tree pg_query.ParseResult
	if err := proto.Unmarshal(b, &tree); err != nil {
		return "", nil, fmt.Errorf("failed to unmarshal AST: %w", err)
	}

	var limitParams []int

	for _, stmt := range tree.Stmts {
		err = enforceRules(stmt.Stmt, rules, 0, &limitParams)
		if err != nil {
			return "", nil, err
		}
	}

	deparseBytes, err := proto.Marshal(&tree)
	if err != nil {
		return "", nil, fmt.Errorf("failed to marshal AST: %w", err)
	}
	deparsed, err := parser.DeparseFromProtobuf(deparseBytes)
	if err != nil {
		return "", nil, fmt.Errorf("failed to deparse SQL: %w", err)
	}

	if astCache != nil {
		astCache.Add(cacheKey, deparsed)
	}
	return deparsed, limitParams, nil
}

func enforceRules(node *pg_query.Node, rules Rules, depth int, limitParams *[]int) error {
	if depth > 50 {
		return ErrComplexityExceeded
	}

	if len(rules.AllowedStatements) == 0 {
		return fmt.Errorf("policy has no allowed statements")
	}

	// Policy Checking for Statements
	// We only strictly deny if the node is a Statement type and not allowed.
	// We check this via the switch, and a fallback check for '*Stmt' suffix.
	switch n := node.Node.(type) {
	case *pg_query.Node_SelectStmt:
		sel := n.SelectStmt
		if len(sel.LockingClause) > 0 {
			return fmt.Errorf("SELECT ... FOR UPDATE/SHARE is not allowed by policy")
		}

		if rules.EnforceSelectLimit > 0 {
			// Smart LIMIT: Skip injection for analytical queries
			isAnalytical := len(sel.GroupClause) > 0 || hasAnalyticalNodes(sel.TargetList)
			if !isAnalytical {
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
						*limitParams = append(*limitParams, int(n.ParamRef.Number))
					default:
						return fmt.Errorf("dynamic limits are not allowed by policy")
					}
				}
			}
		}
	case *pg_query.Node_InsertStmt:
		if !isAllowed("INSERT", rules.AllowedStatements) {
			return fmt.Errorf("INSERT statements are not allowed by policy")
		}
	case *pg_query.Node_UpdateStmt:
		if !isAllowed("UPDATE", rules.AllowedStatements) {
			return fmt.Errorf("UPDATE statements are not allowed by policy")
		}
	case *pg_query.Node_DeleteStmt:
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
		if !isAllowed("SET", rules.AllowedStatements) {
			return fmt.Errorf("SET statements are not allowed by policy")
		}
	case *pg_query.Node_VariableShowStmt:
		if !isAllowed("SHOW", rules.AllowedStatements) {
			return fmt.Errorf("SHOW statements are not allowed by policy")
		}
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
		// It will be recursed automatically below
	default:
		// To maintain strict deny, we only deny if the node is a recognized statement type that we haven't explicitly allowed above.
		if strings.HasSuffix(fmt.Sprintf("%T", n), "Stmt") {
			return fmt.Errorf("statement type %T is not allowed by policy (Default Deny)", n)
		}
	}

	// Recurse into all child nodes generically to enforce complexity limits and find nested statements
	return walkChildren(node.Node, rules, depth+1, limitParams)
}

func walkChildren(v interface{}, rules Rules, depth int, limitParams *[]int) error {
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
		return walkChildren(val.Elem().Interface(), rules, depth, limitParams)
	}

	if val.Kind() == reflect.Struct {
		for i := 0; i < val.NumField(); i++ {
			field := val.Field(i)
			if !field.CanInterface() {
				continue
			}
			if field.Kind() == reflect.Ptr && !field.IsNil() {
				if n, ok := field.Interface().(*pg_query.Node); ok {
					if err := enforceRules(n, rules, depth, limitParams); err != nil {
						return err
					}
					continue
				}
			}
			if err := walkChildren(field.Interface(), rules, depth, limitParams); err != nil {
				return err
			}
		}
	} else if val.Kind() == reflect.Slice {
		for i := 0; i < val.Len(); i++ {
			elem := val.Index(i)
			if elem.Kind() == reflect.Ptr && !elem.IsNil() {
				if n, ok := elem.Interface().(*pg_query.Node); ok {
					if err := enforceRules(n, rules, depth, limitParams); err != nil {
						return err
					}
					continue
				}
			}
			if err := walkChildren(elem.Interface(), rules, depth, limitParams); err != nil {
				return err
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

func hasAnalyticalNodes(v interface{}) bool {
	if v == nil {
		return false
	}
	val := reflect.ValueOf(v)
	if !val.IsValid() {
		return false
	}
	if val.Kind() == reflect.Ptr || val.Kind() == reflect.Interface {
		if val.IsNil() {
			return false
		}
		return hasAnalyticalNodes(val.Elem().Interface())
	}

	if val.Kind() == reflect.Struct {
		for i := 0; i < val.NumField(); i++ {
			field := val.Field(i)
			if !field.CanInterface() {
				continue
			}
			if field.Kind() == reflect.Ptr && !field.IsNil() {
				if n, ok := field.Interface().(*pg_query.Node); ok {
					switch node := n.Node.(type) {
					case *pg_query.Node_FuncCall:
						fc := node.FuncCall
						if fc.Over != nil || fc.AggStar || fc.AggDistinct {
							return true
						}
						for _, fn := range fc.Funcname {
							if strNode, ok := fn.Node.(*pg_query.Node_String_); ok {
								name := strings.ToLower(strNode.String_.Sval)
								if name == "count" || name == "sum" || name == "avg" || name == "min" || name == "max" {
									return true
								}
							}
						}
					}
				}
			}
			if hasAnalyticalNodes(field.Interface()) {
				return true
			}
		}
	} else if val.Kind() == reflect.Slice {
		for i := 0; i < val.Len(); i++ {
			elem := val.Index(i)
			if elem.Kind() == reflect.Ptr && !elem.IsNil() {
				if n, ok := elem.Interface().(*pg_query.Node); ok {
					switch node := n.Node.(type) {
					case *pg_query.Node_FuncCall:
						fc := node.FuncCall
						if fc.Over != nil || fc.AggStar || fc.AggDistinct {
							return true
						}
						for _, fn := range fc.Funcname {
							if strNode, ok := fn.Node.(*pg_query.Node_String_); ok {
								name := strings.ToLower(strNode.String_.Sval)
								if name == "count" || name == "sum" || name == "avg" || name == "min" || name == "max" {
									return true
								}
							}
						}
					}
				}
			}
			if hasAnalyticalNodes(elem.Interface()) {
				return true
			}
		}
	}
	return false
}
