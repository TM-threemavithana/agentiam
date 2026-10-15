package ast

import (
	"fmt"
	"strings"

	pg_query "github.com/pganalyze/pg_query_go/v6"
)

// Scope maps aliases/table names to their underlying table names.
type Scope struct {
	Tables         map[string]string // alias -> real table name (or real table name -> real table name)
	Parent         *Scope
	Children       []*Scope
	MaskedColumns  map[string][]string
	MaskedAccessed bool
}

func (s *Scope) allTables() map[string]string {
	result := make(map[string]string)
	for k, v := range s.Tables {
		result[k] = v
	}
	for _, child := range s.Children {
		for k, v := range child.allTables() {
			result[k] = v
		}
	}
	return result
}

func (s *Scope) markMasked() {
	curr := s
	for curr != nil {
		curr.MaskedAccessed = true
		curr = curr.Parent
	}
}

// hasMaskedTable returns true if any table in the scope (or parents) has masked columns.
func (s *Scope) hasMaskedTable() bool {
	curr := s
	for curr != nil {
		if curr.MaskedAccessed {
			return true
		}
		for _, realTable := range curr.Tables {
			if s.tableHasMasking(realTable) {
				return true
			}
		}
		curr = curr.Parent
	}
	return false
}

func (s *Scope) tableHasMasking(realTable string) bool {
	realTableLower := strings.ToLower(realTable)
	bareTable := realTableLower
	if idx := strings.Index(bareTable, "."); idx != -1 {
		bareTable = bareTable[idx+1:]
	}

	for _, tbl := range []string{realTableLower, bareTable} {
		if cols, ok := s.MaskedColumns[tbl]; ok && len(cols) > 0 {
			return true
		}
	}
	return false
}

// isMaskedColumn checks if a column is masked for a given alias/table reference.
// If alias is empty, it checks all tables in scope.
func (s *Scope) isMaskedColumn(alias, col string) bool {
	curr := s
	colLower := strings.ToLower(col)
	for curr != nil {
		if alias != "" {
			aliasLower := strings.ToLower(alias)
			bareAlias := aliasLower
			if idx := strings.Index(bareAlias, "."); idx != -1 {
				bareAlias = bareAlias[idx+1:]
			}
			if realTable, ok := curr.Tables[bareAlias]; ok {
				if s.checkTableCols(realTable, colLower) {
					return true
				}
			}
			if realTable, ok := curr.Tables[aliasLower]; ok {
				if s.checkTableCols(realTable, colLower) {
					return true
				}
			}
		} else {
			// Check all tables in scope
			for _, realTable := range curr.Tables {
				if s.checkTableCols(realTable, colLower) {
					return true
				}
			}
		}
		curr = curr.Parent
	}
	return false
}

func (s *Scope) checkTableCols(realTable, colLower string) bool {
	realTableLower := strings.ToLower(realTable)
	bareTable := realTableLower
	if idx := strings.Index(bareTable, "."); idx != -1 {
		bareTable = bareTable[idx+1:]
	}

	for _, tbl := range []string{realTableLower, bareTable} {
		if cols, ok := s.MaskedColumns[tbl]; ok {
			for _, c := range cols {
				if c == "*" || strings.EqualFold(c, colLower) {
					return true
				}
			}
		}
	}
	return false
}

// ResolveEffectiveMaskedColumns builds a unified map of relation name -> []string of masked columns,
// resolving view column mappings across the view inheritance hierarchy.
// Fails closed if a view definition references a masked table without column mappings.
func ResolveEffectiveMaskedColumns(rules Rules) (map[string][]string, error) {
	effective := make(map[string][]string)

	// 1. Seed with base table masked columns (normalized to lowercase)
	for table, cols := range rules.MaskedColumns {
		normTable := strings.ToLower(table)
		for _, c := range cols {
			effective[normTable] = append(effective[normTable], strings.ToLower(c))
		}
		if idx := strings.Index(normTable, "."); idx != -1 {
			bare := normTable[idx+1:]
			for _, c := range cols {
				effective[bare] = append(effective[bare], strings.ToLower(c))
			}
		}
	}

	if len(rules.Views) == 0 {
		return effective, nil
	}

	viewByName := make(map[string]ViewPolicy)
	for _, v := range rules.Views {
		viewByName[strings.ToLower(v.Name)] = v
		if idx := strings.Index(v.Name, "."); idx != -1 {
			viewByName[strings.ToLower(v.Name[idx+1:])] = v
		}
	}

	// 2. Resolve each view with cycle detection and inheritance
	resolved := make(map[string]bool)
	visiting := make(map[string]bool)

	var resolveView func(viewName string) error
	resolveView = func(viewName string) error {
		normName := strings.ToLower(viewName)
		if resolved[normName] {
			return nil
		}
		if visiting[normName] {
			return fmt.Errorf("circular view dependency detected involving view '%s'", viewName)
		}
		visiting[normName] = true
		defer func() { visiting[normName] = false }()

		v, exists := viewByName[normName]
		if !exists {
			return nil
		}

		normBase := strings.ToLower(v.BaseTable)
		bareBase := normBase
		if idx := strings.Index(bareBase, "."); idx != -1 {
			bareBase = bareBase[idx+1:]
		}

		// If base table is another view, resolve it first
		if _, isParentView := viewByName[normBase]; isParentView {
			if err := resolveView(normBase); err != nil {
				return err
			}
		} else if _, isParentView2 := viewByName[bareBase]; isParentView2 {
			if err := resolveView(bareBase); err != nil {
				return err
			}
		}

		var baseMaskedCols []string
		if cols, ok := effective[normBase]; ok {
			baseMaskedCols = cols
		} else if cols, ok2 := effective[bareBase]; ok2 {
			baseMaskedCols = cols
		}

		// Add direct explicitly masked columns on this view
		for _, col := range v.MaskedColumns {
			effective[normName] = append(effective[normName], strings.ToLower(col))
		}

		// Map columns from base table / parent view
		if len(baseMaskedCols) > 0 {
			if len(v.ColumnMappings) == 0 && len(v.MaskedColumns) == 0 && len(v.UnexposedColumns) == 0 {
				// Conservative Fail-Closed: view references masked base table without defining column mappings, masked columns, or unexposed columns
				return fmt.Errorf("policy configuration error: approved view '%s' references masked base table '%s' without explicit column mappings, view masked_columns, or unexposed_columns (fail-closed)", v.Name, v.BaseTable)
			}

			// Build set of unexposed columns (declared not projected by view)
			unexposedSet := make(map[string]bool)
			for _, uc := range v.UnexposedColumns {
				unexposedSet[strings.ToLower(uc)] = true
			}

			hasWildcardMask := false
			for _, mc := range v.MaskedColumns {
				if mc == "*" {
					hasWildcardMask = true
					break
				}
			}

			mappedBaseCols := make(map[string]bool)

			// Map renamed columns
			for viewCol, baseCol := range v.ColumnMappings {
				normBaseCol := strings.ToLower(baseCol)
				for _, bmc := range baseMaskedCols {
					if bmc == normBaseCol {
						effective[normName] = append(effective[normName], strings.ToLower(viewCol))
						mappedBaseCols[bmc] = true
					}
				}
			}

			// Also check for identity mappings where column name is unchanged in view
			for _, bmc := range baseMaskedCols {
				if mappedBase, hasMapping := v.ColumnMappings[bmc]; hasMapping && strings.ToLower(mappedBase) == bmc {
					effective[normName] = append(effective[normName], bmc)
					mappedBaseCols[bmc] = true
				}
			}

			// Completeness check: EVERY masked base-table column must be accounted for
			if !hasWildcardMask {
				for _, bmc := range baseMaskedCols {
					if !mappedBaseCols[bmc] && !unexposedSet[bmc] {
						directlyMasked := false
						for _, mc := range v.MaskedColumns {
							if strings.EqualFold(mc, bmc) {
								directlyMasked = true
								break
							}
						}
						if !directlyMasked {
							return fmt.Errorf("policy configuration error: approved view '%s' references masked base table '%s' with unmapped sensitive column '%s' (must be mapped in column_mappings, declared in unexposed_columns, or masked in view)", v.Name, v.BaseTable, bmc)
						}
					}
				}
			}
		}

		// Also mirror bare name if view is schema-qualified
		if idx := strings.Index(normName, "."); idx != -1 {
			bare := normName[idx+1:]
			effective[bare] = append(effective[bare], effective[normName]...)
		}

		resolved[normName] = true
		return nil
	}

	for _, v := range rules.Views {
		if err := resolveView(v.Name); err != nil {
			return nil, err
		}
	}

	return effective, nil
}

func MaskData(stmt *pg_query.Node, rules Rules) error {
	effective, err := ResolveEffectiveMaskedColumns(rules)
	if err != nil {
		return err
	}
	if len(effective) == 0 {
		return nil
	}

	scope := &Scope{
		Tables:        make(map[string]string),
		MaskedColumns: effective,
	}

	return walkNode(stmt, scope)
}

func walkNode(node *pg_query.Node, scope *Scope) error {
	if node == nil {
		return nil
	}

	switch n := node.Node.(type) {
	case *pg_query.Node_SelectStmt:
		sel := n.SelectStmt

		// New scope for this SELECT
		subScope := &Scope{
			Tables:        make(map[string]string),
			Parent:        scope,
			MaskedColumns: scope.MaskedColumns,
		}
		if scope != nil {
			scope.Children = append(scope.Children, subScope)
		}

		// Process WITH clause before SetOperations so CTEs are available to the union arms
		if sel.WithClause != nil {
			for _, cteNode := range sel.WithClause.Ctes {
				cte, ok := cteNode.Node.(*pg_query.Node_CommonTableExpr)
				if !ok {
					continue
				}
				cteScope := &Scope{
					Tables:        make(map[string]string),
					Parent:        subScope,
					MaskedColumns: subScope.MaskedColumns,
				}
				if err := walkNode(cte.CommonTableExpr.Ctequery, cteScope); err != nil {
					return err
				}
				if cteScope.hasMaskedTable() || cteScope.MaskedAccessed {
					cteName := strings.ToLower(cte.CommonTableExpr.Ctename)
					subScope.Tables[cteName] = cteName
					var cteCols []string
					for _, tbl := range cteScope.allTables() {
						normTbl := strings.ToLower(tbl)
						if idx := strings.Index(normTbl, "."); idx != -1 {
							normTbl = normTbl[idx+1:]
						}
						if cols, ok := cteScope.MaskedColumns[normTbl]; ok {
							cteCols = append(cteCols, cols...)
						}
					}
					if len(cteCols) == 0 {
						cteCols = []string{"*"}
					}
					subScope.MaskedColumns[cteName] = cteCols
					subScope.markMasked()
				}
			}
		}

		// Handle UNION/INTERSECT/EXCEPT
		if sel.Op != pg_query.SetOperation_SETOP_NONE {
			if sel.Larg != nil {
				if err := walkNode(&pg_query.Node{Node: &pg_query.Node_SelectStmt{SelectStmt: sel.Larg}}, subScope); err != nil {
					return err
				}
			}
			if sel.Rarg != nil {
				if err := walkNode(&pg_query.Node{Node: &pg_query.Node_SelectStmt{SelectStmt: sel.Rarg}}, subScope); err != nil {
					return err
				}
			}
			return nil
		}

		// 1. Process FROM clause
		for _, fromClause := range sel.FromClause {
			if err := processFromClause(fromClause, subScope); err != nil {
				return err
			}
		}

		// 2. Process Target List (SELECT clause)
		for _, targetNode := range sel.TargetList {
			if err := processTarget(targetNode, subScope); err != nil {
				return err
			}
		}

		// 3. Process Where, Group, Having, Sort, Window (Fail-Closed on sensitive columns)
		if sel.WhereClause != nil {
			if err := checkNoMaskedColumns(sel.WhereClause, subScope, "WHERE clause"); err != nil {
				return err
			}
		}
		for _, node := range sel.GroupClause {
			if err := checkNoMaskedColumns(node, subScope, "GROUP BY clause"); err != nil {
				return err
			}
		}
		if sel.HavingClause != nil {
			if err := checkNoMaskedColumns(sel.HavingClause, subScope, "HAVING clause"); err != nil {
				return err
			}
		}
		for _, node := range sel.SortClause {
			if err := checkNoMaskedColumns(node, subScope, "ORDER BY clause"); err != nil {
				return err
			}
		}
		for _, node := range sel.WindowClause {
			if err := checkNoMaskedColumns(node, subScope, "WINDOW clause"); err != nil {
				return err
			}
		}

	case *pg_query.Node_UpdateStmt:
		subScope := &Scope{
			Tables:        make(map[string]string),
			Parent:        scope,
			MaskedColumns: scope.MaskedColumns,
		}
		if n.UpdateStmt.Relation != nil {
			relName := n.UpdateStmt.Relation.Relname
			alias := relName
			if n.UpdateStmt.Relation.Alias != nil {
				alias = n.UpdateStmt.Relation.Alias.Aliasname
			}
			subScope.Tables[strings.ToLower(alias)] = relName
			if n.UpdateStmt.Relation.Schemaname != "" {
				subScope.Tables[strings.ToLower(n.UpdateStmt.Relation.Schemaname+"."+alias)] = relName
			}
		}
		for _, targetNode := range n.UpdateStmt.TargetList {
			if err := processTarget(targetNode, subScope); err != nil {
				return err
			}
		}
		for _, fromClause := range n.UpdateStmt.FromClause {
			if err := processFromClause(fromClause, subScope); err != nil {
				return err
			}
		}
		if n.UpdateStmt.WhereClause != nil {
			if err := checkNoMaskedColumns(n.UpdateStmt.WhereClause, subScope, "WHERE clause"); err != nil {
				return err
			}
		}
		for _, targetNode := range n.UpdateStmt.ReturningList {
			if err := processTarget(targetNode, subScope); err != nil {
				return err
			}
		}

	case *pg_query.Node_InsertStmt:
		subScope := &Scope{
			Tables:        make(map[string]string),
			Parent:        scope,
			MaskedColumns: scope.MaskedColumns,
		}
		if n.InsertStmt.Relation != nil {
			relName := n.InsertStmt.Relation.Relname
			alias := relName
			if n.InsertStmt.Relation.Alias != nil {
				alias = n.InsertStmt.Relation.Alias.Aliasname
			}
			subScope.Tables[strings.ToLower(alias)] = relName
			if n.InsertStmt.Relation.Schemaname != "" {
				subScope.Tables[strings.ToLower(n.InsertStmt.Relation.Schemaname+"."+alias)] = relName
			}
		}
		if n.InsertStmt.SelectStmt != nil {
			if err := walkNode(n.InsertStmt.SelectStmt, subScope); err != nil {
				return err
			}
		}
		if n.InsertStmt.OnConflictClause != nil {
			if n.InsertStmt.OnConflictClause.WhereClause != nil {
				if err := checkNoMaskedColumns(n.InsertStmt.OnConflictClause.WhereClause, subScope, "ON CONFLICT WHERE clause"); err != nil {
					return err
				}
			}
			for _, targetNode := range n.InsertStmt.OnConflictClause.TargetList {
				if err := processTarget(targetNode, subScope); err != nil {
					return err
				}
			}
		}
		for _, targetNode := range n.InsertStmt.ReturningList {
			if err := processTarget(targetNode, subScope); err != nil {
				return err
			}
		}

	case *pg_query.Node_DeleteStmt:
		subScope := &Scope{
			Tables:        make(map[string]string),
			Parent:        scope,
			MaskedColumns: scope.MaskedColumns,
		}
		if n.DeleteStmt.Relation != nil {
			relName := n.DeleteStmt.Relation.Relname
			alias := relName
			if n.DeleteStmt.Relation.Alias != nil {
				alias = n.DeleteStmt.Relation.Alias.Aliasname
			}
			subScope.Tables[strings.ToLower(alias)] = relName
			if n.DeleteStmt.Relation.Schemaname != "" {
				subScope.Tables[strings.ToLower(n.DeleteStmt.Relation.Schemaname+"."+alias)] = relName
			}
		}
		for _, fromClause := range n.DeleteStmt.UsingClause {
			if err := processFromClause(fromClause, subScope); err != nil {
				return err
			}
		}
		if n.DeleteStmt.WhereClause != nil {
			if err := checkNoMaskedColumns(n.DeleteStmt.WhereClause, subScope, "WHERE clause"); err != nil {
				return err
			}
		}
		for _, targetNode := range n.DeleteStmt.ReturningList {
			if err := processTarget(targetNode, subScope); err != nil {
				return err
			}
		}

	default:
		// FAIL-CLOSED: if it's an unhandled node type and the scope has masked tables, block it.
		if scope.hasMaskedTable() {
			return fmt.Errorf("unhandled AST node type %T in scope with masked tables is not allowed (fail-closed)", node.Node)
		}
	}

	return nil
}

func processFromClause(node *pg_query.Node, scope *Scope) error {
	switch n := node.Node.(type) {
	case *pg_query.Node_RangeVar:
		relName := n.RangeVar.Relname
		alias := relName
		if n.RangeVar.Alias != nil {
			alias = n.RangeVar.Alias.Aliasname
		}
		scope.Tables[strings.ToLower(alias)] = relName
		if n.RangeVar.Schemaname != "" {
			scope.Tables[strings.ToLower(n.RangeVar.Schemaname+"."+alias)] = relName
		}
		if scope.tableHasMasking(relName) {
			scope.markMasked()
		}
	case *pg_query.Node_RangeSubselect:
		alias := ""
		if n.RangeSubselect.Alias != nil {
			alias = n.RangeSubselect.Alias.Aliasname
		}
		subScope := &Scope{
			Tables:        make(map[string]string),
			Parent:        scope,
			MaskedColumns: scope.MaskedColumns,
		}
		if err := walkNode(n.RangeSubselect.Subquery, subScope); err != nil {
			return err
		}
		if subScope.hasMaskedTable() || subScope.MaskedAccessed {
			var subCols []string
			for _, tbl := range subScope.allTables() {
				normTbl := strings.ToLower(tbl)
				if idx := strings.Index(normTbl, "."); idx != -1 {
					normTbl = normTbl[idx+1:]
				}
				if cols, ok := subScope.MaskedColumns[normTbl]; ok {
					subCols = append(subCols, cols...)
				}
			}
			if len(subCols) == 0 {
				subCols = []string{"*"}
			}
			if alias != "" {
				scope.Tables[strings.ToLower(alias)] = strings.ToLower(alias)
				scope.MaskedColumns[strings.ToLower(alias)] = subCols
			}
			scope.Tables["__masked_subquery__"] = "__masked_subquery__"
			scope.MaskedColumns["__masked_subquery__"] = subCols
			scope.markMasked()
		} else {
			if alias != "" {
				scope.Tables[strings.ToLower(alias)] = alias
			}
		}
	case *pg_query.Node_JoinExpr:
		if err := processFromClause(n.JoinExpr.Larg, scope); err != nil {
			return err
		}
		if err := processFromClause(n.JoinExpr.Rarg, scope); err != nil {
			return err
		}
		if n.JoinExpr.Quals != nil {
			if err := checkNoMaskedColumns(n.JoinExpr.Quals, scope, "JOIN ON clause"); err != nil {
				return err
			}
		}
	}
	return nil
}

func processTarget(node *pg_query.Node, scope *Scope) error {
	resTarget, ok := node.Node.(*pg_query.Node_ResTarget)
	if !ok {
		return nil
	}
	if resTarget.ResTarget == nil || resTarget.ResTarget.Val == nil {
		return nil
	}

	// 1. Direct ColumnRef projection:
	if colRef, isCol := resTarget.ResTarget.Val.Node.(*pg_query.Node_ColumnRef); isCol {
		fields := colRef.ColumnRef.Fields
		if len(fields) > 0 {
			for _, field := range fields {
				if _, isStar := field.Node.(*pg_query.Node_AStar); isStar {
					if scope.hasMaskedTable() {
						return fmt.Errorf("implicit row expansion (SELECT *) is blocked in strict mode when querying masked tables")
					}
					return nil
				}
			}

			var colName, alias string
			if len(fields) == 1 {
				if s, ok := fields[0].Node.(*pg_query.Node_String_); ok {
					colName = s.String_.Sval
				}
			} else if len(fields) == 2 {
				if s, ok := fields[0].Node.(*pg_query.Node_String_); ok {
					alias = s.String_.Sval
				}
				if s, ok := fields[1].Node.(*pg_query.Node_String_); ok {
					colName = s.String_.Sval
				}
			} else if len(fields) >= 3 {
				if s, ok := fields[1].Node.(*pg_query.Node_String_); ok {
					alias = s.String_.Sval
				}
				if s, ok := fields[len(fields)-1].Node.(*pg_query.Node_String_); ok {
					colName = s.String_.Sval
				}
			}

			if colName != "" && scope.isMaskedColumn(alias, colName) {
				// Directly projected sensitive column: safely redact to constant string
				replaceWithStringConst(resTarget.ResTarget.Val, "[REDACTED]")
				if resTarget.ResTarget.Name == "" {
					resTarget.ResTarget.Name = colName
				}
				return nil
			}
		}
		return nil
	}

	// 2. SubLink (scalar subquery in target list): walk the inner subquery
	if subLink, isSub := resTarget.ResTarget.Val.Node.(*pg_query.Node_SubLink); isSub {
		if subLink.SubLink.Subselect != nil {
			if err := walkNode(subLink.SubLink.Subselect, scope); err != nil {
				return err
			}
		}
		if subLink.SubLink.Testexpr != nil {
			if err := checkNoMaskedColumns(subLink.SubLink.Testexpr, scope, "scalar subquery expression"); err != nil {
				return err
			}
		}
		return nil
	}

	// 3. Derived expression (function call, arithmetic, cast, concatenation, case, coalesce, etc.):
	// Under active masking policy, referencing a sensitive column in a derived expression is strictly forbidden (Fail-Closed).
	return checkNoMaskedColumns(resTarget.ResTarget.Val, scope, "derived SELECT expression")
}

// checkNoMaskedColumns traverses an AST expression and returns an error if any masked column is referenced.
func checkNoMaskedColumns(expr *pg_query.Node, scope *Scope, clauseName string) error {
	if expr == nil || expr.Node == nil {
		return nil
	}

	switch n := expr.Node.(type) {
	case *pg_query.Node_ColumnRef:
		fields := n.ColumnRef.Fields
		if len(fields) == 0 {
			return nil
		}

		for _, field := range fields {
			if _, isStar := field.Node.(*pg_query.Node_AStar); isStar {
				if scope.hasMaskedTable() {
					return fmt.Errorf("implicit row expansion (SELECT *) is blocked in strict mode when querying masked tables")
				}
				return nil
			}
		}

		var colName, alias string
		if len(fields) == 1 {
			if s, ok := fields[0].Node.(*pg_query.Node_String_); ok {
				colName = s.String_.Sval
			}
		} else if len(fields) == 2 {
			if s, ok := fields[0].Node.(*pg_query.Node_String_); ok {
				alias = s.String_.Sval
			}
			if s, ok := fields[1].Node.(*pg_query.Node_String_); ok {
				colName = s.String_.Sval
			}
		} else if len(fields) >= 3 {
			if s, ok := fields[1].Node.(*pg_query.Node_String_); ok {
				alias = s.String_.Sval
			}
			if s, ok := fields[len(fields)-1].Node.(*pg_query.Node_String_); ok {
				colName = s.String_.Sval
			}
		}

		if colName != "" && scope.isMaskedColumn(alias, colName) {
			return fmt.Errorf("policy violation: sensitive column '%s' cannot be referenced in %s under active masking policy", colName, clauseName)
		}
		return nil

	case *pg_query.Node_FuncCall:
		if n.FuncCall.Over != nil {
			if err := checkNoMaskedColumns(&pg_query.Node{Node: &pg_query.Node_WindowDef{WindowDef: n.FuncCall.Over}}, scope, clauseName); err != nil {
				return err
			}
		}
		// Check for whole-row references in function calls (e.g. row_to_json(users))
		for _, arg := range n.FuncCall.Args {
			if argNode, ok := arg.Node.(*pg_query.Node_ColumnRef); ok {
				if len(argNode.ColumnRef.Fields) == 1 {
					if s, isStr := argNode.ColumnRef.Fields[0].Node.(*pg_query.Node_String_); isStr {
						if _, exists := scope.Tables[strings.ToLower(s.String_.Sval)]; exists {
							if scope.hasMaskedTable() {
								return fmt.Errorf("whole-row references in functions are blocked in strict mode when querying masked tables")
							}
						}
					}
				}
			}
			if err := checkNoMaskedColumns(arg, scope, clauseName); err != nil {
				return err
			}
		}
		return nil

	case *pg_query.Node_TypeCast:
		return checkNoMaskedColumns(n.TypeCast.Arg, scope, clauseName)

	case *pg_query.Node_AStar:
		if scope.hasMaskedTable() {
			return fmt.Errorf("implicit row expansion (SELECT *) is blocked in strict mode when querying masked tables")
		}
		return nil

	case *pg_query.Node_SubLink:
		if n.SubLink.Subselect != nil {
			if err := walkNode(n.SubLink.Subselect, scope); err != nil {
				return err
			}
		}
		if n.SubLink.Testexpr != nil {
			if err := checkNoMaskedColumns(n.SubLink.Testexpr, scope, clauseName); err != nil {
				return err
			}
		}
		return nil

	case *pg_query.Node_BoolExpr:
		for _, arg := range n.BoolExpr.Args {
			if err := checkNoMaskedColumns(arg, scope, clauseName); err != nil {
				return err
			}
		}
		return nil

	case *pg_query.Node_AExpr:
		if err := checkNoMaskedColumns(n.AExpr.Lexpr, scope, clauseName); err != nil {
			return err
		}
		return checkNoMaskedColumns(n.AExpr.Rexpr, scope, clauseName)

	case *pg_query.Node_NullTest:
		return checkNoMaskedColumns(n.NullTest.Arg, scope, clauseName)

	case *pg_query.Node_CaseExpr:
		if err := checkNoMaskedColumns(n.CaseExpr.Arg, scope, clauseName); err != nil {
			return err
		}
		for _, w := range n.CaseExpr.Args {
			if whenClause, ok := w.Node.(*pg_query.Node_CaseWhen); ok {
				if err := checkNoMaskedColumns(whenClause.CaseWhen.Expr, scope, clauseName); err != nil {
					return err
				}
				if err := checkNoMaskedColumns(whenClause.CaseWhen.Result, scope, clauseName); err != nil {
					return err
				}
			}
		}
		return checkNoMaskedColumns(n.CaseExpr.Defresult, scope, clauseName)

	case *pg_query.Node_CoalesceExpr:
		for _, arg := range n.CoalesceExpr.Args {
			if err := checkNoMaskedColumns(arg, scope, clauseName); err != nil {
				return err
			}
		}
		return nil

	case *pg_query.Node_ScalarArrayOpExpr:
		for _, arg := range n.ScalarArrayOpExpr.Args {
			if err := checkNoMaskedColumns(arg, scope, clauseName); err != nil {
				return err
			}
		}
		return nil

	case *pg_query.Node_SortBy:
		return checkNoMaskedColumns(n.SortBy.Node, scope, clauseName)

	case *pg_query.Node_WindowDef:
		for _, part := range n.WindowDef.PartitionClause {
			if err := checkNoMaskedColumns(part, scope, clauseName); err != nil {
				return err
			}
		}
		for _, sort := range n.WindowDef.OrderClause {
			if err := checkNoMaskedColumns(sort, scope, clauseName); err != nil {
				return err
			}
		}
		return nil

	case *pg_query.Node_ResTarget:
		return checkNoMaskedColumns(n.ResTarget.Val, scope, clauseName)

	case *pg_query.Node_AConst, *pg_query.Node_ParamRef:
		return nil

	default:
		if scope.hasMaskedTable() {
			return fmt.Errorf("unhandled AST node type %T in %s with masked tables is not allowed (fail-closed)", expr.Node, clauseName)
		}
		return nil
	}
}

func replaceWithStringConst(node *pg_query.Node, val string) {
	node.Node = &pg_query.Node_AConst{
		AConst: &pg_query.A_Const{
			Val: &pg_query.A_Const_Sval{
				Sval: &pg_query.String{
					Sval: val,
				},
			},
			Isnull: false,
		},
	}
}
