package ast

import (
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"reflect"
	"regexp"
	"strings"

	pg_query "github.com/pganalyze/pg_query_go/v6"
	"github.com/wasilibs/go-pgquery/parser"
	"google.golang.org/protobuf/proto"
)

var whitespaceRegex = regexp.MustCompile(`\s+`)

// NormalizeViewDefinitionSQL returns a canonical SQL representation of a view definition.
// It parses the definition into a PostgreSQL AST and deparses it, eliminating variations
// in indentation, whitespace, and formatting. If deparsing fails, it falls back to
// normalized whitespace and semicolon stripping.
func NormalizeViewDefinitionSQL(definitionSQL string) (string, error) {
	trimmed := strings.TrimSpace(definitionSQL)
	trimmed = strings.TrimSuffix(trimmed, ";")
	trimmed = strings.TrimSpace(trimmed)
	if trimmed == "" {
		return "", fmt.Errorf("view definition is empty")
	}

	b, err := parser.ParseToProtobuf(trimmed)
	if err == nil {
		deparsed, errDeparse := parser.DeparseFromProtobuf(b)
		if errDeparse == nil && strings.TrimSpace(deparsed) != "" {
			return strings.TrimSpace(deparsed), nil
		}
	}

	// Fallback whitespace normalization
	normalized := whitespaceRegex.ReplaceAllString(trimmed, " ")
	return strings.TrimSpace(normalized), nil
}

// ComputeViewFingerprint computes an owner-approved SHA-256 fingerprint for a canonical view definition.
// The output format is "sha256:<64-hex-characters>".
func ComputeViewFingerprint(definitionSQL string) (string, error) {
	canonical, err := NormalizeViewDefinitionSQL(definitionSQL)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256([]byte(canonical))
	return fmt.Sprintf("sha256:%x", hash), nil
}

// CompareFingerprints compares an expected fingerprint against an actual fingerprint.
// It handles optional "sha256:" prefixes and performs a case-insensitive constant-time comparison.
func CompareFingerprints(expected, actual string) bool {
	normExpected := strings.ToLower(strings.TrimSpace(expected))
	normExpected = strings.TrimPrefix(normExpected, "sha256:")

	normActual := strings.ToLower(strings.TrimSpace(actual))
	normActual = strings.TrimPrefix(normActual, "sha256:")

	if len(normExpected) == 0 || len(normActual) == 0 {
		return false
	}
	if len(normExpected) != len(normActual) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(normExpected), []byte(normActual)) == 1
}

// ValidateViewProvenance inspects a view's PostgreSQL definition AST and validates
// that sensitive columns, computed expressions, renames, and unexposed column declarations
// strictly conform to the security policy (SEC-P2-05).
func ValidateViewProvenance(viewDef string, v ViewPolicy, maskedColumns map[string][]string) error {
	trimmed := strings.TrimSpace(viewDef)
	if trimmed == "" {
		return fmt.Errorf("view '%s' definition is empty (fail-closed)", v.Name)
	}

	b, err := parser.ParseToProtobuf(trimmed)
	if err != nil {
		return fmt.Errorf("failed to parse view '%s' definition: %w", v.Name, err)
	}

	var tree pg_query.ParseResult
	if err := proto.Unmarshal(b, &tree); err != nil {
		return fmt.Errorf("failed to unmarshal view '%s' AST: %w", v.Name, err)
	}

	if len(tree.Stmts) != 1 {
		return fmt.Errorf("view '%s' definition must contain exactly one SELECT statement", v.Name)
	}

	rawStmt := tree.Stmts[0].Stmt
	if rawStmt == nil || rawStmt.Node == nil {
		return fmt.Errorf("view '%s' definition contains empty AST statement", v.Name)
	}

	selNode, ok := rawStmt.Node.(*pg_query.Node_SelectStmt)
	if !ok {
		return fmt.Errorf("view '%s' definition must be a SELECT statement, got %T", v.Name, rawStmt.Node)
	}
	sel := selNode.SelectStmt

	// Reject set operations (UNION, INTERSECT, EXCEPT) in view definitions unless explicitly verified
	if sel.Op != pg_query.SetOperation_SETOP_NONE {
		return fmt.Errorf("view '%s' uses set operations (UNION/INTERSECT/EXCEPT) which cannot be statically verified (fail-closed)", v.Name)
	}

	// Verify base table from FROM clause
	fromTables := extractTablesFromFromClause(sel.FromClause)
	if len(fromTables) == 0 {
		return fmt.Errorf("view '%s' does not reference any FROM relation", v.Name)
	}

	baseTableNorm := strings.ToLower(v.BaseTable)
	bareBaseTable := baseTableNorm
	if idx := strings.Index(bareBaseTable, "."); idx != -1 {
		bareBaseTable = bareBaseTable[idx+1:]
	}

	// Verify that the view references the expected base table
	matchedBase := false
	for _, tbl := range fromTables {
		tblNorm := strings.ToLower(tbl)
		bareTbl := tblNorm
		if idx := strings.Index(bareTbl, "."); idx != -1 {
			bareTbl = bareTbl[idx+1:]
		}
		if tblNorm == baseTableNorm || bareTbl == bareBaseTable {
			matchedBase = true
			break
		}
	}
	if !matchedBase {
		return fmt.Errorf("view '%s' definition queries tables %v which do not match configured base table '%s' (fail-closed)", v.Name, fromTables, v.BaseTable)
	}

	// Resolve sensitive columns for the base table
	sensitiveCols := make(map[string]bool)
	for _, tblKey := range []string{baseTableNorm, bareBaseTable} {
		if cols, ok := maskedColumns[tblKey]; ok {
			for _, c := range cols {
				if c != "" && c != "*" {
					sensitiveCols[strings.ToLower(c)] = true
				}
			}
		}
	}

	unexposedCols := make(map[string]bool)
	for _, uc := range v.UnexposedColumns {
		unexposedCols[strings.ToLower(uc)] = true
	}

	mappedCols := make(map[string]string) // outputColLower -> baseColLower
	for outCol, inCol := range v.ColumnMappings {
		mappedCols[strings.ToLower(outCol)] = strings.ToLower(inCol)
	}

	explicitMaskedCols := make(map[string]bool)
	for _, mc := range v.MaskedColumns {
		explicitMaskedCols[strings.ToLower(mc)] = true
	}

	referencedSensitiveCols := make(map[string]bool)

	// Inspect each output column in TargetList
	for _, targetNode := range sel.TargetList {
		resTarget, ok := targetNode.Node.(*pg_query.Node_ResTarget)
		if !ok || resTarget.ResTarget == nil {
			continue
		}
		val := resTarget.ResTarget.Val
		if val == nil {
			continue
		}

		// Check for wildcard projection (SELECT *)
		if colRef, isCol := val.Node.(*pg_query.Node_ColumnRef); isCol {
			for _, field := range colRef.ColumnRef.Fields {
				if _, isStar := field.Node.(*pg_query.Node_AStar); isStar {
					return fmt.Errorf("view '%s' uses wildcard projection 'SELECT *' which cannot be statically verified against sensitive column policy (fail-closed)", v.Name)
				}
			}
		}

		// Determine output column name
		outputCol := resTarget.ResTarget.Name
		if outputCol == "" {
			if colRef, isCol := val.Node.(*pg_query.Node_ColumnRef); isCol {
				fields := colRef.ColumnRef.Fields
				if len(fields) > 0 {
					if s, ok := fields[len(fields)-1].Node.(*pg_query.Node_String_); ok {
						outputCol = s.String_.Sval
					}
				}
			}
		}
		if outputCol == "" {
			return fmt.Errorf("view '%s' has an output column without an explicit name or alias (fail-closed)", v.Name)
		}
		outputColNorm := strings.ToLower(outputCol)

		// Check whether target is a direct ColumnRef or a derived/computed expression
		if colRef, isDirect := val.Node.(*pg_query.Node_ColumnRef); isDirect {
			// Direct 1:1 projection
			sourceCol := extractColumnNameFromRef(colRef.ColumnRef)
			sourceColNorm := strings.ToLower(sourceCol)

			if sensitiveCols[sourceColNorm] {
				referencedSensitiveCols[sourceColNorm] = true

				// 1. If declared in unexposed_columns, fail closed (false declaration)
				if unexposedCols[sourceColNorm] {
					return fmt.Errorf("policy error: view '%s' declared sensitive column '%s' in unexposed_columns, but definition directly projects it as '%s' (fail-closed)", v.Name, sourceCol, outputCol)
				}

				// 2. Must be mapped to sourceCol or explicitly masked
				mappedBase, hasMapping := mappedCols[outputColNorm]
				isMaskedInView := explicitMaskedCols[outputColNorm] || explicitMaskedCols["*"]

				if !isMaskedInView && (!hasMapping || mappedBase != sourceColNorm) {
					return fmt.Errorf("security violation: view '%s' projects sensitive column '%s' as '%s' without explicit masking mapping or view masked_columns (attempt to expose sensitive column under unmapped alias)", v.Name, sourceCol, outputCol)
				}
			}
		} else {
			// Computed expression, function call, cast, concatenation, arithmetic, case, etc.
			referencedInExpr := extractColumnsFromNode(val)
			hasSensitiveRef := false
			var sensitiveRefCol string

			for _, refCol := range referencedInExpr {
				refColNorm := strings.ToLower(refCol)
				if sensitiveCols[refColNorm] {
					hasSensitiveRef = true
					sensitiveRefCol = refCol
					referencedSensitiveCols[refColNorm] = true
					break
				}
			}

			if hasSensitiveRef {
				// 1. If declared in unexposed_columns, fail closed (cannot hide derived sensitive value)
				if unexposedCols[strings.ToLower(sensitiveRefCol)] {
					return fmt.Errorf("policy error: view '%s' declared sensitive column '%s' in unexposed_columns, but definition references it in computed output '%s' (fail-closed)", v.Name, sensitiveRefCol, outputCol)
				}

				// 2. Computed output deriving from sensitive data MUST be explicitly classified as masked
				isMaskedInView := explicitMaskedCols[outputColNorm] || explicitMaskedCols["*"]
				if !isMaskedInView {
					return fmt.Errorf("security violation: view '%s' output column '%s' derives from sensitive column '%s' via computed expression, but is not explicitly declared in masked_columns (SEC-P2-05 fail-closed)", v.Name, outputCol, sensitiveRefCol)
				}
			}
		}

		// Completeness check: Output column must be classified
		if len(v.ColumnMappings) > 0 {
			_, inMapping := mappedCols[outputColNorm]
			inMasked := explicitMaskedCols[outputColNorm]
			if !inMapping && !inMasked {
				return fmt.Errorf("policy configuration error: view '%s' has output column '%s' not classified in column_mappings or masked_columns (incomplete classification)", v.Name, outputCol)
			}
		}
	}

	// Inspect WHERE, HAVING, GROUP BY, ORDER BY, WINDOW clauses and JOIN qualifiers
	// for sensitive column leakage/inference (SEC-P2-07 fail-closed)
	if err := checkClauseNoSensitiveColumns(sel.WhereClause, sensitiveCols, "WHERE clause", v.Name); err != nil {
		return err
	}
	if err := checkClauseNoSensitiveColumns(sel.HavingClause, sensitiveCols, "HAVING clause", v.Name); err != nil {
		return err
	}
	for _, item := range sel.GroupClause {
		if err := checkClauseNoSensitiveColumns(item, sensitiveCols, "GROUP BY clause", v.Name); err != nil {
			return err
		}
	}
	for _, item := range sel.SortClause {
		if err := checkClauseNoSensitiveColumns(item, sensitiveCols, "ORDER BY clause", v.Name); err != nil {
			return err
		}
	}
	for _, item := range sel.WindowClause {
		if err := checkClauseNoSensitiveColumns(item, sensitiveCols, "WINDOW clause", v.Name); err != nil {
			return err
		}
	}
	if err := checkJoinQualsNoSensitiveColumns(sel.FromClause, sensitiveCols, v.Name); err != nil {
		return err
	}

	return nil
}

func checkClauseNoSensitiveColumns(node *pg_query.Node, sensitiveCols map[string]bool, clauseName, viewName string) error {
	if node == nil {
		return nil
	}
	cols := extractColumnsFromNode(node)
	for _, c := range cols {
		cNorm := strings.ToLower(c)
		if sensitiveCols[cNorm] {
			return fmt.Errorf("security violation: view '%s' references sensitive column '%s' in %s (sensitive predicate/inference prohibited, SEC-P2-07 fail-closed)", viewName, c, clauseName)
		}
	}
	return nil
}

func checkJoinQualsNoSensitiveColumns(fromList []*pg_query.Node, sensitiveCols map[string]bool, viewName string) error {
	for _, n := range fromList {
		if n == nil || n.Node == nil {
			continue
		}
		if err := walkJoinQuals(n, func(quals *pg_query.Node) error {
			return checkClauseNoSensitiveColumns(quals, sensitiveCols, "JOIN ON clause", viewName)
		}); err != nil {
			return err
		}
	}
	return nil
}

func walkJoinQuals(node *pg_query.Node, fn func(quals *pg_query.Node) error) error {
	if node == nil || node.Node == nil {
		return nil
	}
	switch n := node.Node.(type) {
	case *pg_query.Node_JoinExpr:
		je := n.JoinExpr
		if je != nil {
			if je.Quals != nil {
				if err := fn(je.Quals); err != nil {
					return err
				}
			}
			if je.Larg != nil {
				if err := walkJoinQuals(je.Larg, fn); err != nil {
					return err
				}
			}
			if je.Rarg != nil {
				if err := walkJoinQuals(je.Rarg, fn); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// ExtractViewDependencies parses a view definition SQL and extracts all table/view names referenced in it,
// excluding query-local CTE names, and preserving exact PostgreSQL canonical relation names.
func ExtractViewDependencies(viewDef string) ([]string, error) {
	trimmed := strings.TrimSpace(viewDef)
	if trimmed == "" {
		return nil, fmt.Errorf("empty view definition (fail-closed)")
	}
	b, err := parser.ParseToProtobuf(trimmed)
	if err != nil {
		return nil, fmt.Errorf("failed to parse view definition: %w (fail-closed)", err)
	}
	var tree pg_query.ParseResult
	if err := proto.Unmarshal(b, &tree); err != nil {
		return nil, fmt.Errorf("failed to unmarshal view AST: %w (fail-closed)", err)
	}
	if len(tree.Stmts) != 1 || tree.Stmts[0].Stmt == nil {
		return nil, fmt.Errorf("view definition must contain exactly one statement (fail-closed)")
	}
	selNode, ok := tree.Stmts[0].Stmt.Node.(*pg_query.Node_SelectStmt)
	if !ok || selNode.SelectStmt == nil {
		return nil, fmt.Errorf("view definition is not a SELECT statement (fail-closed)")
	}

	refs := extractPostgresRelationRefs(tree.Stmts[0].Stmt)
	var deps []string
	seen := make(map[string]bool)
	for _, r := range refs {
		ident := QuoteIdentIfNeeded(r.Name)
		if r.Schema != "" {
			ident = QuoteIdentIfNeeded(r.Schema) + "." + ident
		}
		if !seen[ident] {
			seen[ident] = true
			deps = append(deps, ident)
		}
	}
	return deps, nil
}

func extractColumnNameFromRef(colRef *pg_query.ColumnRef) string {
	if colRef == nil || len(colRef.Fields) == 0 {
		return ""
	}
	last := colRef.Fields[len(colRef.Fields)-1]
	if s, ok := last.Node.(*pg_query.Node_String_); ok {
		return s.String_.Sval
	}
	return ""
}

func extractTablesFromFromClause(fromList []*pg_query.Node) []string {
	var tables []string
	for _, n := range fromList {
		if n == nil || n.Node == nil {
			continue
		}
		switch node := n.Node.(type) {
		case *pg_query.Node_RangeVar:
			if node.RangeVar != nil {
				tables = append(tables, node.RangeVar.Relname)
			}
		case *pg_query.Node_JoinExpr:
			tables = append(tables, extractTablesFromJoin(node.JoinExpr)...)
		}
	}
	return tables
}

func extractTablesFromJoin(join *pg_query.JoinExpr) []string {
	if join == nil {
		return nil
	}
	var tables []string
	if join.Larg != nil {
		if rv, ok := join.Larg.Node.(*pg_query.Node_RangeVar); ok && rv.RangeVar != nil {
			tables = append(tables, rv.RangeVar.Relname)
		} else if je, ok := join.Larg.Node.(*pg_query.Node_JoinExpr); ok {
			tables = append(tables, extractTablesFromJoin(je.JoinExpr)...)
		}
	}
	if join.Rarg != nil {
		if rv, ok := join.Rarg.Node.(*pg_query.Node_RangeVar); ok && rv.RangeVar != nil {
			tables = append(tables, rv.RangeVar.Relname)
		} else if je, ok := join.Rarg.Node.(*pg_query.Node_JoinExpr); ok {
			tables = append(tables, extractTablesFromJoin(je.JoinExpr)...)
		}
	}
	return tables
}

// extractColumnsFromNode recursively inspects any AST expression to find all referenced column names.
func extractColumnsFromNode(node *pg_query.Node) []string {
	if node == nil || node.Node == nil {
		return nil
	}

	var cols []string

	switch n := node.Node.(type) {
	case *pg_query.Node_ColumnRef:
		colName := extractColumnNameFromRef(n.ColumnRef)
		if colName != "" && colName != "*" {
			cols = append(cols, colName)
		}
		return cols

	case *pg_query.Node_FuncCall:
		if n.FuncCall != nil {
			for _, arg := range n.FuncCall.Args {
				cols = append(cols, extractColumnsFromNode(arg)...)
			}
		}

	case *pg_query.Node_AExpr:
		if n.AExpr != nil {
			cols = append(cols, extractColumnsFromNode(n.AExpr.Lexpr)...)
			cols = append(cols, extractColumnsFromNode(n.AExpr.Rexpr)...)
		}

	case *pg_query.Node_TypeCast:
		if n.TypeCast != nil {
			cols = append(cols, extractColumnsFromNode(n.TypeCast.Arg)...)
		}

	case *pg_query.Node_NullTest:
		if n.NullTest != nil {
			cols = append(cols, extractColumnsFromNode(n.NullTest.Arg)...)
		}

	case *pg_query.Node_CaseExpr:
		if n.CaseExpr != nil {
			cols = append(cols, extractColumnsFromNode(n.CaseExpr.Arg)...)
			for _, w := range n.CaseExpr.Args {
				cols = append(cols, extractColumnsFromNode(w)...)
			}
			cols = append(cols, extractColumnsFromNode(n.CaseExpr.Defresult)...)
		}

	case *pg_query.Node_CaseWhen:
		if n.CaseWhen != nil {
			cols = append(cols, extractColumnsFromNode(n.CaseWhen.Expr)...)
			cols = append(cols, extractColumnsFromNode(n.CaseWhen.Result)...)
		}

	case *pg_query.Node_CoalesceExpr:
		if n.CoalesceExpr != nil {
			for _, arg := range n.CoalesceExpr.Args {
				cols = append(cols, extractColumnsFromNode(arg)...)
			}
		}

	case *pg_query.Node_SubLink:
		if n.SubLink != nil {
			cols = append(cols, extractColumnsFromNode(n.SubLink.Testexpr)...)
			if n.SubLink.Subselect != nil {
				cols = append(cols, extractColumnsFromNode(n.SubLink.Subselect)...)
			}
		}

	case *pg_query.Node_SelectStmt:
		if n.SelectStmt != nil {
			for _, item := range n.SelectStmt.TargetList {
				cols = append(cols, extractColumnsFromNode(item)...)
			}
			for _, item := range n.SelectStmt.FromClause {
				cols = append(cols, extractColumnsFromNode(item)...)
			}
			cols = append(cols, extractColumnsFromNode(n.SelectStmt.WhereClause)...)
			cols = append(cols, extractColumnsFromNode(n.SelectStmt.HavingClause)...)
		}

	default:
		// Generic reflection walk for any unhandled compound expression nodes
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
				if childNode, ok := field.Interface().(*pg_query.Node); ok && childNode != nil {
					cols = append(cols, extractColumnsFromNode(childNode)...)
				} else if childSlice, ok := field.Interface().([]*pg_query.Node); ok {
					for _, item := range childSlice {
						cols = append(cols, extractColumnsFromNode(item)...)
					}
				}
			}
		}
	}

	return cols
}
