package ast

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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

func policyFingerprint(rules Rules) string {
	b, _ := json.Marshal(rules)
	hash := sha256.Sum256(b)
	return hex.EncodeToString(hash[:])
}

// ApplyRules parses the SQL into an AST, checks it against the rules, injects limits, and returns the rewritten SQL.
func (p *PostgresParser) ApplyRules(sql string, rules Rules, astCache cache.ASTCache) (string, []int, error) {
	_, span := otel.Tracer("agentiam/ast").Start(context.Background(), "ApplyRules")
	defer span.End()

	start := time.Now()
	defer func() {
		ParsingDuration.Observe(time.Since(start).Seconds())
	}()

	cacheKey := fmt.Sprintf("%s:%s", policyFingerprint(rules), sql)
	if astCache != nil {
		if cached, ok := astCache.Get(cacheKey); ok {
			AstCacheHitsTotal.Inc()
			span.SetAttributes(attribute.Bool("cache.hit", true))
			return cached.SQL, cached.LimitParams, nil
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
		if rules.MaxComplexity > 0 {
			complexity := CalculatePostgresComplexity(stmt.Stmt)
			if complexity > rules.MaxComplexity {
				return "", nil, fmt.Errorf("policy violation: query complexity %d exceeds maximum of %d", complexity, rules.MaxComplexity)
			}
		}
		// Enforce relation-level access control (default-deny for tables and views)
		if err := enforceRelationAccess(stmt.Stmt, rules); err != nil {
			return "", nil, err
		}
		if err := CanonicalizeRelationSchemas(stmt.Stmt, rules); err != nil {
			return "", nil, err
		}
		if err := InjectTenantIsolation(stmt.Stmt, rules); err != nil {
			return "", nil, fmt.Errorf("tenant isolation blocked query: %w", err)
		}
		if err := MaskData(stmt.Stmt, rules); err != nil {
			return "", nil, fmt.Errorf("masking blocked query: %w", err)
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

	if astCache != nil && isCacheable(sql) {
		astCache.Add(cacheKey, cache.CachedAST{
			SQL:         deparsed,
			LimitParams: limitParams,
		})
	}
	return deparsed, limitParams, nil
}

// isCacheable determines if a query should be cached.
// To prevent LRU thrashing, we skip caching queries with hardcoded string literals
// unless they are explicitly parameterized.
func isCacheable(sql string) bool {
	// If it uses parameters, it's a prepared statement template. Highly reusable.
	if strings.Contains(sql, "$") || strings.Contains(sql, "?") {
		return true
	}
	// If it contains single quotes, it's likely a one-off literal query from an AI agent.
	// Bypassing the cache prevents LRU eviction thrashing.
	if strings.Contains(sql, "'") {
		return false
	}
	// Default to cacheable
	return true
}

// RelationRef represents a referenced relation, optionally schema-qualified.
type RelationRef struct {
	Schema string
	Name   string
}

// collectCTENames collects all Common Table Expression (CTE) names defined within a statement.
// These are query-local aliases and should not be treated as database tables.
func collectCTENames(node *pg_query.Node) map[string]bool {
	ctes := make(map[string]bool)
	collectCTEsRecursive(node, ctes)
	return ctes
}

func collectCTEsRecursive(node *pg_query.Node, ctes map[string]bool) {
	if node == nil {
		return
	}
	if sel, ok := node.Node.(*pg_query.Node_SelectStmt); ok && sel.SelectStmt != nil {
		if sel.SelectStmt.WithClause != nil {
			for _, cteNode := range sel.SelectStmt.WithClause.Ctes {
				if cte, ok2 := cteNode.Node.(*pg_query.Node_CommonTableExpr); ok2 && cte.CommonTableExpr != nil {
					ctes[strings.ToLower(cte.CommonTableExpr.Ctename)] = true
					collectCTEsRecursive(cte.CommonTableExpr.Ctequery, ctes)
				}
			}
		}
	}
	if ins, ok := node.Node.(*pg_query.Node_InsertStmt); ok && ins.InsertStmt != nil && ins.InsertStmt.WithClause != nil {
		for _, cteNode := range ins.InsertStmt.WithClause.Ctes {
			if cte, ok2 := cteNode.Node.(*pg_query.Node_CommonTableExpr); ok2 && cte.CommonTableExpr != nil {
				ctes[strings.ToLower(cte.CommonTableExpr.Ctename)] = true
				collectCTEsRecursive(cte.CommonTableExpr.Ctequery, ctes)
			}
		}
	}
	if upd, ok := node.Node.(*pg_query.Node_UpdateStmt); ok && upd.UpdateStmt != nil && upd.UpdateStmt.WithClause != nil {
		for _, cteNode := range upd.UpdateStmt.WithClause.Ctes {
			if cte, ok2 := cteNode.Node.(*pg_query.Node_CommonTableExpr); ok2 && cte.CommonTableExpr != nil {
				ctes[strings.ToLower(cte.CommonTableExpr.Ctename)] = true
				collectCTEsRecursive(cte.CommonTableExpr.Ctequery, ctes)
			}
		}
	}
	if del, ok := node.Node.(*pg_query.Node_DeleteStmt); ok && del.DeleteStmt != nil && del.DeleteStmt.WithClause != nil {
		for _, cteNode := range del.DeleteStmt.WithClause.Ctes {
			if cte, ok2 := cteNode.Node.(*pg_query.Node_CommonTableExpr); ok2 && cte.CommonTableExpr != nil {
				ctes[strings.ToLower(cte.CommonTableExpr.Ctename)] = true
				collectCTEsRecursive(cte.CommonTableExpr.Ctequery, ctes)
			}
		}
	}
}

// ExtractReferencedRelations parses SQL and extracts all relation names (RangeVar) referenced in it,
// returning lowercase canonical identifiers (e.g. "public.customers" or "customers").
func ExtractReferencedRelations(sql string) ([]string, error) {
	b, err := parser.ParseToProtobuf(sql)
	if err != nil {
		return nil, fmt.Errorf("failed to parse SQL: %w", err)
	}
	var tree pg_query.ParseResult
	if err := proto.Unmarshal(b, &tree); err != nil {
		return nil, fmt.Errorf("failed to unmarshal AST: %w", err)
	}
	var rels []string
	seen := make(map[string]bool)
	for _, stmt := range tree.Stmts {
		refs := extractPostgresRelationRefs(stmt.Stmt)
		for _, r := range refs {
			name := strings.ToLower(r.Name)
			if r.Schema != "" {
				name = strings.ToLower(r.Schema) + "." + name
			}
			if !seen[name] {
				seen[name] = true
				rels = append(rels, name)
			}
		}
	}
	return rels, nil
}

// extractPostgresRelationRefs walks an AST node and collects all referenced relations (RangeVar),
// ignoring query-local CTE names.
func extractPostgresRelationRefs(node *pg_query.Node) []RelationRef {
	if node == nil {
		return nil
	}
	cteNames := collectCTENames(node)
	var refs []RelationRef
	seen := make(map[string]bool)

	collectRelationRefs(node.Node, cteNames, &refs, seen)
	return refs
}

func collectRelationRefs(v interface{}, cteNames map[string]bool, refs *[]RelationRef, seen map[string]bool) {
	if v == nil {
		return
	}

	switch n := v.(type) {
	case *pg_query.Node_RangeVar:
		rv := n.RangeVar
		if rv != nil && rv.Relname != "" {
			nameLower := strings.ToLower(rv.Relname)
			if rv.Schemaname == "" && cteNames[nameLower] {
				return
			}
			key := strings.ToLower(rv.Schemaname) + "." + nameLower
			if !seen[key] {
				seen[key] = true
				*refs = append(*refs, RelationRef{
					Schema: rv.Schemaname,
					Name:   rv.Relname,
				})
			}
		}
		return
	case *pg_query.RangeVar:
		rv := n
		if rv != nil && rv.Relname != "" {
			nameLower := strings.ToLower(rv.Relname)
			if rv.Schemaname == "" && cteNames[nameLower] {
				return
			}
			key := strings.ToLower(rv.Schemaname) + "." + nameLower
			if !seen[key] {
				seen[key] = true
				*refs = append(*refs, RelationRef{
					Schema: rv.Schemaname,
					Name:   rv.Relname,
				})
			}
		}
		return
	case *pg_query.Node_SelectStmt:
		sel := n.SelectStmt
		if sel == nil {
			return
		}
		collectRelationRefsNodeSlice(sel.TargetList, cteNames, refs, seen)
		collectRelationRefsNodeSlice(sel.FromClause, cteNames, refs, seen)
		collectRelationRefs(sel.WhereClause, cteNames, refs, seen)
		collectRelationRefs(sel.WithClause, cteNames, refs, seen)
		return
	case *pg_query.Node_JoinExpr:
		join := n.JoinExpr
		if join == nil {
			return
		}
		collectRelationRefs(join.Larg, cteNames, refs, seen)
		collectRelationRefs(join.Rarg, cteNames, refs, seen)
		collectRelationRefs(join.Quals, cteNames, refs, seen)
		return
	case *pg_query.Node_InsertStmt:
		ins := n.InsertStmt
		if ins == nil {
			return
		}
		collectRelationRefs(ins.Relation, cteNames, refs, seen)
		collectRelationRefs(ins.SelectStmt, cteNames, refs, seen)
		collectRelationRefs(ins.WithClause, cteNames, refs, seen)
		return
	case *pg_query.Node_UpdateStmt:
		upd := n.UpdateStmt
		if upd == nil {
			return
		}
		collectRelationRefs(upd.Relation, cteNames, refs, seen)
		collectRelationRefsNodeSlice(upd.FromClause, cteNames, refs, seen)
		collectRelationRefs(upd.WhereClause, cteNames, refs, seen)
		collectRelationRefs(upd.WithClause, cteNames, refs, seen)
		return
	case *pg_query.Node_DeleteStmt:
		del := n.DeleteStmt
		if del == nil {
			return
		}
		collectRelationRefs(del.Relation, cteNames, refs, seen)
		collectRelationRefsNodeSlice(del.UsingClause, cteNames, refs, seen)
		collectRelationRefs(del.WhereClause, cteNames, refs, seen)
		collectRelationRefs(del.WithClause, cteNames, refs, seen)
		return
	case *pg_query.Node_AConst, *pg_query.Node_ColumnRef, *pg_query.Node_ParamRef:
		return
	}

	val := reflect.ValueOf(v)
	if !val.IsValid() {
		return
	}
	if val.Kind() == reflect.Ptr || val.Kind() == reflect.Interface {
		if val.IsNil() {
			return
		}
		collectRelationRefs(val.Elem().Interface(), cteNames, refs, seen)
		return
	}
	if rv, ok := v.(*pg_query.Node_RangeVar); ok {
		if rv.RangeVar != nil && rv.RangeVar.Relname != "" {
			nameLower := strings.ToLower(rv.RangeVar.Relname)
			if rv.RangeVar.Schemaname == "" && cteNames[nameLower] {
				return
			}
			key := strings.ToLower(rv.RangeVar.Schemaname) + "." + nameLower
			if !seen[key] {
				seen[key] = true
				*refs = append(*refs, RelationRef{
					Schema: rv.RangeVar.Schemaname,
					Name:   rv.RangeVar.Relname,
				})
			}
		}
		return
	}
	if val.Kind() == reflect.Struct {
		for i := 0; i < val.NumField(); i++ {
			field := val.Field(i)
			if !field.CanInterface() {
				continue
			}
			if field.Kind() == reflect.Ptr && !field.IsNil() {
				if n, ok := field.Interface().(*pg_query.Node); ok {
					collectRelationRefs(n.Node, cteNames, refs, seen)
					continue
				}
			}
			collectRelationRefs(field.Interface(), cteNames, refs, seen)
		}
	} else if val.Kind() == reflect.Slice {
		for i := 0; i < val.Len(); i++ {
			elem := val.Index(i)
			if elem.Kind() == reflect.Ptr && !elem.IsNil() {
				if n, ok := elem.Interface().(*pg_query.Node); ok {
					collectRelationRefs(n.Node, cteNames, refs, seen)
					continue
				}
			}
			collectRelationRefs(elem.Interface(), cteNames, refs, seen)
		}
	}
}

func collectRelationRefsNode(node *pg_query.Node, cteNames map[string]bool, refs *[]RelationRef, seen map[string]bool) {
	if node != nil {
		collectRelationRefs(node.Node, cteNames, refs, seen)
	}
}

func collectRelationRefsNodeSlice(nodes []*pg_query.Node, cteNames map[string]bool, refs *[]RelationRef, seen map[string]bool) {
	for _, n := range nodes {
		if n != nil {
			collectRelationRefs(n.Node, cteNames, refs, seen)
		}
	}
}

// matchesRelation determines if an extracted RelationRef matches an allowed relation pattern.
// Handles bare names (implying public/default schema) and explicit schema qualification.
func matchesRelation(ref RelationRef, allowed string) bool {
	allowedLower := strings.ToLower(strings.TrimSpace(allowed))
	refNameLower := strings.ToLower(strings.TrimSpace(ref.Name))
	refSchemaLower := strings.ToLower(strings.TrimSpace(ref.Schema))

	if allowedLower == "*" {
		return true
	}

	var allowedSchema, allowedName string
	if idx := strings.Index(allowedLower, "."); idx != -1 {
		allowedSchema = allowedLower[:idx]
		allowedName = allowedLower[idx+1:]
	} else {
		allowedName = allowedLower
	}

	// 1. If allowed specifies schema (e.g. "public.users" or "analytics.report")
	if allowedSchema != "" {
		if refSchemaLower != "" {
			return strings.EqualFold(refSchemaLower, allowedSchema) && strings.EqualFold(refNameLower, allowedName)
		}
		// Query omitted schema: matches only if allowedSchema is "public"
		return allowedSchema == "public" && strings.EqualFold(refNameLower, allowedName)
	}

	// 2. If allowed did NOT specify schema (e.g. "users")
	// Matches if query omitted schema OR query specified "public"
	if refSchemaLower == "" || refSchemaLower == "public" {
		return strings.EqualFold(refNameLower, allowedName)
	}

	// Query specified non-public schema (e.g. "private.users") while policy did not: reject
	return false
}

// enforceRelationAccess checks that every relation referenced in stmt is explicitly authorized.
// When sensitive column masking is active, default-deny is strictly enforced: wildcard '*' is prohibited,
// and relations must match explicitly authorized base tables or approved views.
func enforceRelationAccess(stmt *pg_query.Node, rules Rules) error {
	hasMasking := len(rules.MaskedColumns) > 0 || len(rules.Views) > 0

	// If no masking and allowed_tables allows all, nothing to restrict
	if !hasMasking && (len(rules.AllowedTables) == 0 || isAllowed("*", rules.AllowedTables)) {
		return nil
	}

	// When masking is enabled, a wildcard '*' in allowed_tables is forbidden (default-deny requirement)
	if hasMasking && isAllowed("*", rules.AllowedTables) {
		return fmt.Errorf("policy configuration error: wildcard '*' in allowed_tables is not permitted when sensitive-column masking is enabled (explicit allowed-relation policy required)")
	}

	refs := extractPostgresRelationRefs(stmt)
	for _, ref := range refs {
		allowed := false

		// 1. Check if ref matches an explicitly authorized base table
		for _, tbl := range rules.AllowedTables {
			if tbl == "*" && !hasMasking {
				allowed = true
				break
			}
			if matchesRelation(ref, tbl) {
				allowed = true
				break
			}
		}

		// 2. Check if ref matches an explicitly approved view
		if !allowed && len(rules.Views) > 0 {
			for _, v := range rules.Views {
				if matchesRelation(ref, v.Name) {
					if rules.RequireCatalogVerification {
						normView := strings.ToLower(v.Name)
						bareView := normView
						if idx := strings.Index(bareView, "."); idx != -1 {
							bareView = bareView[idx+1:]
						}
						isVerified := false
						if rules.VerifiedViews != nil {
							isVerified = rules.VerifiedViews[normView] || rules.VerifiedViews[bareView]
						}
						if !isVerified {
							relStr := ref.Name
							if ref.Schema != "" {
								relStr = ref.Schema + "." + ref.Name
							}
							return fmt.Errorf("policy violation: approved view '%s' has not been verified against PostgreSQL catalog definition or verification failed (fail-closed)", relStr)
						}
					}
					allowed = true
					break
				}
			}
		}

		if !allowed {
			relStr := ref.Name
			if ref.Schema != "" {
				relStr = ref.Schema + "." + ref.Name
			}
			return fmt.Errorf("policy violation: access to relation '%s' is not allowed by policy (default-deny)", relStr)
		}
	}
	return nil
}

// CanonicalizeRelationSchemas canonicalizes unqualified RangeVar relations to their explicit
// schema-qualified identity based on policy (defaulting to "public"), preventing search_path shadowing attacks.
func CanonicalizeRelationSchemas(node *pg_query.Node, rules Rules) error {
	if node == nil || node.Node == nil {
		return nil
	}

	cteNames := collectCTENames(node)

	canonicalSchemas := make(map[string]string)
	for _, v := range rules.Views {
		schema, name := splitSchemaName(v.Name)
		canonicalSchemas[strings.ToLower(name)] = schema
		canonicalSchemas[strings.ToLower(schema+"."+name)] = schema
	}
	for _, tbl := range rules.AllowedTables {
		if tbl == "*" {
			continue
		}
		schema, name := splitSchemaName(tbl)
		canonicalSchemas[strings.ToLower(name)] = schema
		canonicalSchemas[strings.ToLower(schema+"."+name)] = schema
	}

	walkRangeVars(node, func(rv *pg_query.RangeVar) {
		if rv == nil || rv.Relname == "" {
			return
		}
		nameLower := strings.ToLower(rv.Relname)
		if rv.Schemaname == "" && !cteNames[nameLower] {
			if canonicalSchema, ok := canonicalSchemas[nameLower]; ok && canonicalSchema != "" {
				rv.Schemaname = canonicalSchema
			}
		}
	})

	return nil
}

func walkRangeVars(v interface{}, fn func(rv *pg_query.RangeVar)) {
	if v == nil {
		return
	}

	switch n := v.(type) {
	case *pg_query.Node:
		if n != nil && n.Node != nil {
			walkRangeVars(n.Node, fn)
		}
		return
	case *pg_query.Node_RangeVar:
		if n.RangeVar != nil {
			fn(n.RangeVar)
		}
		return
	case *pg_query.RangeVar:
		fn(n)
		return
	case *pg_query.Node_SelectStmt:
		sel := n.SelectStmt
		if sel == nil {
			return
		}
		for _, item := range sel.TargetList {
			walkRangeVars(item, fn)
		}
		for _, item := range sel.FromClause {
			walkRangeVars(item, fn)
		}
		walkRangeVars(sel.WhereClause, fn)
		walkRangeVars(sel.WithClause, fn)
		if sel.Larg != nil {
			walkRangeVars(sel.Larg, fn)
		}
		if sel.Rarg != nil {
			walkRangeVars(sel.Rarg, fn)
		}
		return
	case *pg_query.SelectStmt:
		sel := n
		if sel == nil {
			return
		}
		for _, item := range sel.TargetList {
			walkRangeVars(item, fn)
		}
		for _, item := range sel.FromClause {
			walkRangeVars(item, fn)
		}
		walkRangeVars(sel.WhereClause, fn)
		walkRangeVars(sel.WithClause, fn)
		if sel.Larg != nil {
			walkRangeVars(sel.Larg, fn)
		}
		if sel.Rarg != nil {
			walkRangeVars(sel.Rarg, fn)
		}
		return
	case *pg_query.Node_JoinExpr:
		join := n.JoinExpr
		if join == nil {
			return
		}
		walkRangeVars(join.Larg, fn)
		walkRangeVars(join.Rarg, fn)
		walkRangeVars(join.Quals, fn)
		return
	case *pg_query.JoinExpr:
		join := n
		if join == nil {
			return
		}
		walkRangeVars(join.Larg, fn)
		walkRangeVars(join.Rarg, fn)
		walkRangeVars(join.Quals, fn)
		return
	case *pg_query.Node_RangeSubselect:
		sub := n.RangeSubselect
		if sub != nil {
			walkRangeVars(sub.Subquery, fn)
		}
		return
	case *pg_query.RangeSubselect:
		sub := n
		if sub != nil {
			walkRangeVars(sub.Subquery, fn)
		}
		return
	case *pg_query.Node_InsertStmt:
		ins := n.InsertStmt
		if ins != nil {
			walkRangeVars(ins.Relation, fn)
			walkRangeVars(ins.SelectStmt, fn)
			walkRangeVars(ins.WithClause, fn)
		}
		return
	case *pg_query.Node_UpdateStmt:
		upd := n.UpdateStmt
		if upd != nil {
			walkRangeVars(upd.Relation, fn)
			for _, item := range upd.FromClause {
				walkRangeVars(item, fn)
			}
			walkRangeVars(upd.WhereClause, fn)
			walkRangeVars(upd.WithClause, fn)
		}
		return
	case *pg_query.Node_DeleteStmt:
		del := n.DeleteStmt
		if del != nil {
			walkRangeVars(del.Relation, fn)
			for _, item := range del.UsingClause {
				walkRangeVars(item, fn)
			}
			walkRangeVars(del.WhereClause, fn)
			walkRangeVars(del.WithClause, fn)
		}
		return
	case *pg_query.Node_CommonTableExpr:
		cte := n.CommonTableExpr
		if cte != nil {
			walkRangeVars(cte.Ctequery, fn)
		}
		return
	case *pg_query.CommonTableExpr:
		cte := n
		if cte != nil {
			walkRangeVars(cte.Ctequery, fn)
		}
		return
	case *pg_query.Node_WithClause:
		wc := n.WithClause
		if wc != nil {
			for _, cte := range wc.Ctes {
				walkRangeVars(cte, fn)
			}
		}
		return
	case []*pg_query.Node:
		for _, item := range n {
			walkRangeVars(item, fn)
		}
		return
	}

	val := reflect.ValueOf(v)
	if !val.IsValid() {
		return
	}
	if val.Kind() == reflect.Ptr || val.Kind() == reflect.Interface {
		if val.IsNil() {
			return
		}
		walkRangeVars(val.Elem().Interface(), fn)
		return
	}
	if val.Kind() == reflect.Slice {
		for i := 0; i < val.Len(); i++ {
			walkRangeVars(val.Index(i).Interface(), fn)
		}
		return
	}
	if val.Kind() == reflect.Struct {
		for i := 0; i < val.NumField(); i++ {
			field := val.Field(i)
			if !field.CanInterface() {
				continue
			}
			walkRangeVars(field.Interface(), fn)
		}
	}
}

func splitSchemaName(rel string) (string, string) {
	parts := strings.Split(rel, ".")
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	return "public", rel
}

// extractPostgresTables walks an AST node and collects all referenced table names (RangeVar).
func extractPostgresTables(node *pg_query.Node) []string {
	refs := extractPostgresRelationRefs(node)
	var tables []string
	for _, r := range refs {
		tables = append(tables, r.Name)
	}
	return tables
}



func enforceRules(node *pg_query.Node, rules Rules, depth int, limitParams *[]int) error {
	if node == nil || node.Node == nil {
		return nil
	}
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
		if !isAllowed("SELECT", rules.AllowedStatements) {
			return fmt.Errorf("SELECT statements are not allowed by policy")
		}
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
	case *pg_query.Node_CreateStmt, *pg_query.Node_IndexStmt, *pg_query.Node_ViewStmt:
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
		if n.VariableSetStmt.Kind == pg_query.VariableSetKind_VAR_RESET_ALL {
			return fmt.Errorf("RESET ALL is not allowed by policy")
		}
		if strings.EqualFold(n.VariableSetStmt.Name, "statement_timeout") {
			return fmt.Errorf("overriding statement_timeout is not allowed by policy")
		}
		if !isAllowed("SET", rules.AllowedStatements) {
			return fmt.Errorf("SET statements are not allowed by policy")
		}
		if strings.EqualFold(n.VariableSetStmt.Name, "statement_timeout") {
			return fmt.Errorf("overriding statement_timeout is not allowed by policy")
		}
	case *pg_query.Node_VariableShowStmt:
		if !isAllowed("SHOW", rules.AllowedStatements) {
			return fmt.Errorf("SHOW statements are not allowed by policy")
		}
	case *pg_query.Node_FuncCall:
		for _, fn := range n.FuncCall.Funcname {
			if strNode, ok := fn.Node.(*pg_query.Node_String_); ok {
				fnName := strNode.String_.Sval

				if strings.EqualFold(fnName, "set_config") {
					if len(n.FuncCall.Args) > 0 {
						arg0 := n.FuncCall.Args[0]
						if aconst, ok := arg0.Node.(*pg_query.Node_AConst); ok {
							if sval, ok := aconst.AConst.Val.(*pg_query.A_Const_Sval); ok {
								if strings.EqualFold(sval.Sval.Sval, "statement_timeout") {
									return fmt.Errorf("overriding statement_timeout via set_config is not allowed by policy")
								}
							}
						} else if _, ok := arg0.Node.(*pg_query.Node_ParamRef); ok {
							return fmt.Errorf("dynamic configuration of parameters via set_config with bind variables is not allowed by policy")
						}
					}
				}

				for _, blocked := range rules.BlockedFunctions {
					if strings.EqualFold(fnName, blocked) {
						return fmt.Errorf("function '%s' is not allowed by policy", fnName)
					}
				}
			}
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

	// Hybrid Fast Path
	switch n := v.(type) {
	case *pg_query.Node_SelectStmt:
		sel := n.SelectStmt
		if sel == nil { return nil }
		if err := filterWalkNodeSlice(sel.TargetList, rules, depth, limitParams); err != nil { return err }
		if err := filterWalkNodeSlice(sel.FromClause, rules, depth, limitParams); err != nil { return err }
		if err := filterWalkNode(sel.WhereClause, rules, depth, limitParams); err != nil { return err }
		if err := filterWalkNodeSlice(sel.GroupClause, rules, depth, limitParams); err != nil { return err }
		if err := filterWalkNode(sel.HavingClause, rules, depth, limitParams); err != nil { return err }
		if err := filterWalkNodeSlice(sel.WindowClause, rules, depth, limitParams); err != nil { return err }
		if err := filterWalkNodeSlice(sel.SortClause, rules, depth, limitParams); err != nil { return err }
		if err := filterWalkNode(sel.LimitOffset, rules, depth, limitParams); err != nil { return err }
		if err := filterWalkNode(sel.LimitCount, rules, depth, limitParams); err != nil { return err }
		if err := filterWalkNodeSlice(sel.LockingClause, rules, depth, limitParams); err != nil { return err }
		if err := filterWalkNode(sel.WithClause, rules, depth, limitParams); err != nil { return err }
		return nil
	case *pg_query.Node_InsertStmt:
		ins := n.InsertStmt
		if ins == nil { return nil }
		if err := filterWalkNode(ins.Relation, rules, depth, limitParams); err != nil { return err }
		if err := filterWalkNodeSlice(ins.Cols, rules, depth, limitParams); err != nil { return err }
		if err := filterWalkNode(ins.SelectStmt, rules, depth, limitParams); err != nil { return err }
		if err := filterWalkNode(ins.OnConflictClause, rules, depth, limitParams); err != nil { return err }
		if err := filterWalkNodeSlice(ins.ReturningList, rules, depth, limitParams); err != nil { return err }
		if err := filterWalkNode(ins.WithClause, rules, depth, limitParams); err != nil { return err }
		return nil
	case *pg_query.Node_UpdateStmt:
		upd := n.UpdateStmt
		if upd == nil { return nil }
		if err := filterWalkNode(upd.Relation, rules, depth, limitParams); err != nil { return err }
		if err := filterWalkNodeSlice(upd.TargetList, rules, depth, limitParams); err != nil { return err }
		if err := filterWalkNode(upd.WhereClause, rules, depth, limitParams); err != nil { return err }
		if err := filterWalkNodeSlice(upd.FromClause, rules, depth, limitParams); err != nil { return err }
		if err := filterWalkNodeSlice(upd.ReturningList, rules, depth, limitParams); err != nil { return err }
		if err := filterWalkNode(upd.WithClause, rules, depth, limitParams); err != nil { return err }
		return nil
	case *pg_query.Node_DeleteStmt:
		del := n.DeleteStmt
		if del == nil { return nil }
		if err := filterWalkNode(del.Relation, rules, depth, limitParams); err != nil { return err }
		if err := filterWalkNodeSlice(del.UsingClause, rules, depth, limitParams); err != nil { return err }
		if err := filterWalkNode(del.WhereClause, rules, depth, limitParams); err != nil { return err }
		if err := filterWalkNodeSlice(del.ReturningList, rules, depth, limitParams); err != nil { return err }
		if err := filterWalkNode(del.WithClause, rules, depth, limitParams); err != nil { return err }
		return nil
	case *pg_query.Node_JoinExpr:
		join := n.JoinExpr
		if join == nil { return nil }
		if err := filterWalkNode(join.Larg, rules, depth, limitParams); err != nil { return err }
		if err := filterWalkNode(join.Rarg, rules, depth, limitParams); err != nil { return err }
		if err := filterWalkNode(join.Quals, rules, depth, limitParams); err != nil { return err }
		return nil
	case *pg_query.Node_FuncCall:
		fc := n.FuncCall
		if fc == nil { return nil }
		if err := filterWalkNodeSlice(fc.Funcname, rules, depth, limitParams); err != nil { return err }
		if err := filterWalkNodeSlice(fc.Args, rules, depth, limitParams); err != nil { return err }
		if err := filterWalkNodeSlice(fc.AggOrder, rules, depth, limitParams); err != nil { return err }
		if err := filterWalkNode(fc.AggFilter, rules, depth, limitParams); err != nil { return err }
		if err := filterWalkNode(fc.Over, rules, depth, limitParams); err != nil { return err }
		return nil
	case *pg_query.Node_AExpr:
		aexpr := n.AExpr
		if aexpr == nil { return nil }
		if err := filterWalkNodeSlice(aexpr.Name, rules, depth, limitParams); err != nil { return err }
		if err := filterWalkNode(aexpr.Lexpr, rules, depth, limitParams); err != nil { return err }
		if err := filterWalkNode(aexpr.Rexpr, rules, depth, limitParams); err != nil { return err }
		return nil
	case *pg_query.Node_BoolExpr:
		bexpr := n.BoolExpr
		if bexpr == nil { return nil }
		if err := filterWalkNodeSlice(bexpr.Args, rules, depth, limitParams); err != nil { return err }
		return nil
	case *pg_query.Node_ResTarget:
		rt := n.ResTarget
		if rt == nil { return nil }
		if err := filterWalkNodeSlice(rt.Indirection, rules, depth, limitParams); err != nil { return err }
		if err := filterWalkNode(rt.Val, rules, depth, limitParams); err != nil { return err }
		return nil
	case *pg_query.Node_TypeCast:
		tc := n.TypeCast
		if tc == nil { return nil }
		if err := filterWalkNode(tc.Arg, rules, depth, limitParams); err != nil { return err }
		if err := filterWalkNode(tc.TypeName, rules, depth, limitParams); err != nil { return err }
		return nil
	case *pg_query.Node_ColumnRef:
		cr := n.ColumnRef
		if cr == nil { return nil }
		return filterWalkNodeSlice(cr.Fields, rules, depth, limitParams)
	case *pg_query.Node_RangeVar, *pg_query.Node_AConst, *pg_query.Node_ParamRef, *pg_query.Node_String_, *pg_query.Node_Integer:
		return nil // Leaf nodes
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

// filterWalkNode safely extracts the inner Node from a pg_query.Node wrapper and walks it.
func filterWalkNode(n interface{}, rules Rules, depth int, limitParams *[]int) error {
	if n == nil {
		return nil
	}
	if node, ok := n.(*pg_query.Node); ok {
		return enforceRules(node, rules, depth, limitParams)
	}
	return walkChildren(n, rules, depth, limitParams)
}

func filterWalkNodeSlice(nodes []*pg_query.Node, rules Rules, depth int, limitParams *[]int) error {
	for _, n := range nodes {
		if n != nil {
			if err := enforceRules(n, rules, depth, limitParams); err != nil {
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

	// Fast Path
	switch n := v.(type) {
	case *pg_query.Node_FuncCall:
		fc := n.FuncCall
		if fc == nil { return false }
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
		if hasAnalyticalNodesNodeSlice(fc.Args) || hasAnalyticalNodesNode(fc.AggFilter) || hasAnalyticalNodesNode(fc.Over) {
			return true
		}
		return false
	case *pg_query.Node_SelectStmt:
		sel := n.SelectStmt
		if sel == nil { return false }
		if hasAnalyticalNodesNodeSlice(sel.TargetList) || hasAnalyticalNodesNodeSlice(sel.FromClause) || hasAnalyticalNodesNode(sel.WhereClause) || hasAnalyticalNodesNodeSlice(sel.GroupClause) || hasAnalyticalNodesNode(sel.HavingClause) || hasAnalyticalNodesNodeSlice(sel.WindowClause) || hasAnalyticalNodesNodeSlice(sel.SortClause) {
			return true
		}
		return false
	case *pg_query.Node_JoinExpr:
		join := n.JoinExpr
		if join == nil { return false }
		if hasAnalyticalNodesNode(join.Larg) || hasAnalyticalNodesNode(join.Rarg) || hasAnalyticalNodesNode(join.Quals) {
			return true
		}
		return false
	case *pg_query.Node_AExpr:
		aexpr := n.AExpr
		if aexpr == nil { return false }
		if hasAnalyticalNodesNode(aexpr.Lexpr) || hasAnalyticalNodesNode(aexpr.Rexpr) { return true }
		return false
	case *pg_query.Node_BoolExpr:
		bexpr := n.BoolExpr
		if bexpr == nil { return false }
		if hasAnalyticalNodesNodeSlice(bexpr.Args) { return true }
		return false
	case *pg_query.Node_ResTarget:
		rt := n.ResTarget
		if rt == nil { return false }
		if hasAnalyticalNodesNode(rt.Val) { return true }
		return false
	case *pg_query.Node_RangeVar, *pg_query.Node_ColumnRef, *pg_query.Node_AConst, *pg_query.Node_ParamRef, *pg_query.Node_String_, *pg_query.Node_Integer:
		return false // Leaf nodes
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

func hasAnalyticalNodesNode(n interface{}) bool {
	if n == nil {
		return false
	}
	if node, ok := n.(*pg_query.Node); ok {
		if node != nil {
			return hasAnalyticalNodes(node.Node)
		}
		return false
	}
	return hasAnalyticalNodes(n)
}

func hasAnalyticalNodesNodeSlice(nodes []*pg_query.Node) bool {
	for _, n := range nodes {
		if n != nil && hasAnalyticalNodes(n.Node) {
			return true
		}
	}
	return false
}

func CalculatePostgresComplexity(node *pg_query.Node) int {
	if node == nil || node.Node == nil {
		return 0
	}

	score := 0

	switch n := node.Node.(type) {
	case *pg_query.Node_JoinExpr:
		score += 5
	case *pg_query.Node_SelectStmt:
		sel := n.SelectStmt
		if len(sel.FromClause) > 1 {
			score += (len(sel.FromClause) - 1) * 5
		}
		if sel.WhereClause != nil {
			score += 1
		}
		if len(sel.SortClause) > 0 {
			score += 2
		}
		if len(sel.GroupClause) > 0 {
			score += 3
		}
	case *pg_query.Node_FuncCall:
		fc := n.FuncCall
		if fc.Over != nil {
			score += 4
		}
	}

	val := reflect.ValueOf(node.Node)
	if val.Kind() == reflect.Ptr && !val.IsNil() {
		val = val.Elem()
	}
	if val.Kind() == reflect.Struct {
		for i := 0; i < val.NumField(); i++ {
			field := val.Field(i)
			if !field.CanInterface() {
				continue
			}
			if field.Kind() == reflect.Ptr && !field.IsNil() {
				if childNode, ok := field.Interface().(*pg_query.Node); ok {
					score += CalculatePostgresComplexity(childNode)
				} else {
					score += calculateGenericReflectComplexity(field.Interface())
				}
			} else {
				score += calculateGenericReflectComplexity(field.Interface())
			}
		}
	}

	return score
}

func calculateGenericReflectComplexity(valInterface interface{}) int {
	if valInterface == nil {
		return 0
	}

	// Fast Path
	switch n := valInterface.(type) {
	case *pg_query.Node_SelectStmt:
		sel := n.SelectStmt
		if sel == nil { return 0 }
		score := 0
		if len(sel.FromClause) > 1 { score += (len(sel.FromClause) - 1) * 5 }
		if sel.WhereClause != nil { score += 1 }
		if len(sel.SortClause) > 0 { score += 2 }
		if len(sel.GroupClause) > 0 { score += 3 }
		score += calculateGenericReflectComplexityNodeSlice(sel.TargetList)
		score += calculateGenericReflectComplexityNodeSlice(sel.FromClause)
		score += calculateGenericReflectComplexityNode(sel.WhereClause)
		score += calculateGenericReflectComplexityNodeSlice(sel.GroupClause)
		score += calculateGenericReflectComplexityNode(sel.HavingClause)
		return score
	case *pg_query.Node_JoinExpr:
		join := n.JoinExpr
		if join == nil { return 0 }
		return 5 + calculateGenericReflectComplexityNode(join.Larg) + calculateGenericReflectComplexityNode(join.Rarg) + calculateGenericReflectComplexityNode(join.Quals)
	case *pg_query.Node_FuncCall:
		fc := n.FuncCall
		if fc == nil { return 0 }
		score := 0
		if fc.Over != nil { score += 4 }
		score += calculateGenericReflectComplexityNodeSlice(fc.Args)
		return score
	case *pg_query.Node_InsertStmt:
		ins := n.InsertStmt
		if ins == nil { return 0 }
		return calculateGenericReflectComplexityNode(ins.SelectStmt) + calculateGenericReflectComplexityNode(ins.OnConflictClause)
	case *pg_query.Node_UpdateStmt:
		upd := n.UpdateStmt
		if upd == nil { return 0 }
		return calculateGenericReflectComplexityNodeSlice(upd.TargetList) + calculateGenericReflectComplexityNode(upd.WhereClause) + calculateGenericReflectComplexityNodeSlice(upd.FromClause)
	case *pg_query.Node_DeleteStmt:
		del := n.DeleteStmt
		if del == nil { return 0 }
		return calculateGenericReflectComplexityNodeSlice(del.UsingClause) + calculateGenericReflectComplexityNode(del.WhereClause)
	case *pg_query.Node_AExpr:
		aexpr := n.AExpr
		if aexpr == nil { return 0 }
		return calculateGenericReflectComplexityNode(aexpr.Lexpr) + calculateGenericReflectComplexityNode(aexpr.Rexpr)
	case *pg_query.Node_BoolExpr:
		bexpr := n.BoolExpr
		if bexpr == nil { return 0 }
		return calculateGenericReflectComplexityNodeSlice(bexpr.Args)
	case *pg_query.Node_ResTarget:
		rt := n.ResTarget
		if rt == nil { return 0 }
		return calculateGenericReflectComplexityNode(rt.Val)
	case *pg_query.Node_RangeVar, *pg_query.Node_ColumnRef, *pg_query.Node_AConst, *pg_query.Node_ParamRef, *pg_query.Node_String_, *pg_query.Node_Integer:
		return 0
	}

	val := reflect.ValueOf(valInterface)
	if val.Kind() == reflect.Ptr || val.Kind() == reflect.Interface {
		if val.IsNil() {
			return 0
		}
		return calculateGenericReflectComplexity(val.Elem().Interface())
	}

	score := 0
	if val.Kind() == reflect.Struct {
		for i := 0; i < val.NumField(); i++ {
			field := val.Field(i)
			if !field.CanInterface() {
				continue
			}
			if field.Kind() == reflect.Ptr && !field.IsNil() {
				if childNode, ok := field.Interface().(*pg_query.Node); ok {
					score += CalculatePostgresComplexity(childNode)
				}
			}
			score += calculateGenericReflectComplexity(field.Interface())
		}
	} else if val.Kind() == reflect.Slice {
		for i := 0; i < val.Len(); i++ {
			elem := val.Index(i)
			if elem.Kind() == reflect.Ptr && !elem.IsNil() {
				if childNode, ok := elem.Interface().(*pg_query.Node); ok {
					score += CalculatePostgresComplexity(childNode)
				}
			}
			score += calculateGenericReflectComplexity(elem.Interface())
		}
	}
	return score
}

func calculateGenericReflectComplexityNode(n interface{}) int {
	if n == nil {
		return 0
	}
	if node, ok := n.(*pg_query.Node); ok {
		return CalculatePostgresComplexity(node)
	}
	return calculateGenericReflectComplexity(n)
}

func calculateGenericReflectComplexityNodeSlice(nodes []*pg_query.Node) int {
	score := 0
	for _, n := range nodes {
		if n != nil {
			score += CalculatePostgresComplexity(n)
		}
	}
	return score
}
