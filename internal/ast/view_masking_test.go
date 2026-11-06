package ast

import (
	"strings"
	"testing"
)

func TestViewMasking_AuthorizedBaseTable_Masking(t *testing.T) {
	rules := Rules{
		AllowedStatements: []string{"SELECT"},
		AllowedTables:     []string{"users"},
		MaskedColumns: map[string][]string{
			"users": {"ssn", "credit_card"},
		},
	}
	parser := &PostgresParser{}

	sql := "SELECT id, ssn, credit_card FROM users"
	rewritten, _, err := parser.ApplyRules(sql, rules, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if strings.Contains(rewritten, "ssn") && !strings.Contains(rewritten, "'[REDACTED]'") {
		t.Fatalf("expected ssn to be replaced by string constant, got: %s", rewritten)
	}
	if !strings.Contains(rewritten, "'[REDACTED]'") {
		t.Fatalf("expected '[REDACTED]' in rewritten query, got: %s", rewritten)
	}
}

func TestViewMasking_UnauthorizedBaseTable_DefaultDeny(t *testing.T) {
	rules := Rules{
		AllowedStatements: []string{"SELECT"},
		AllowedTables:     []string{"users"},
		MaskedColumns: map[string][]string{
			"users": {"ssn"},
		},
	}
	parser := &PostgresParser{}

	sql := "SELECT id, secret_data FROM private_records"
	_, _, err := parser.ApplyRules(sql, rules, nil)
	if err == nil {
		t.Fatalf("expected unauthorized base table 'private_records' to be denied, but succeeded")
	}
	if !strings.Contains(err.Error(), "policy violation: access to relation 'private_records' is not allowed") {
		t.Fatalf("expected default-deny error, got: %v", err)
	}
}

func TestViewMasking_WildcardForbiddenWhenMaskingEnabled(t *testing.T) {
	rules := Rules{
		AllowedStatements: []string{"SELECT"},
		AllowedTables:     []string{"*"},
		MaskedColumns: map[string][]string{
			"users": {"ssn"},
		},
	}
	parser := &PostgresParser{}

	sql := "SELECT id FROM users"
	_, _, err := parser.ApplyRules(sql, rules, nil)
	if err == nil {
		t.Fatalf("expected wildcard '*' in allowed_tables to be rejected when masking is enabled")
	}
	if !strings.Contains(err.Error(), "wildcard '*' in allowed_tables is not permitted") {
		t.Fatalf("expected wildcard rejection error, got: %v", err)
	}
}

func TestViewMasking_AuthorizedView_DirectColumnMapping(t *testing.T) {
	rules := Rules{
		AllowedStatements: []string{"SELECT"},
		AllowedTables:     []string{"users"},
		Views: []ViewPolicy{
			{
				Name:      "user_public_view",
				BaseTable: "users",
				ColumnMappings: map[string]string{
					"id":   "id",
					"ssn":  "ssn",
					"name": "name",
				},
			},
		},
		MaskedColumns: map[string][]string{
			"users": {"ssn"},
		},
	}
	parser := &PostgresParser{}

	sql := "SELECT id, ssn, name FROM user_public_view"
	rewritten, _, err := parser.ApplyRules(sql, rules, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(rewritten, "'[REDACTED]'") {
		t.Fatalf("expected ssn on user_public_view to be masked, got: %s", rewritten)
	}
}

func TestViewMasking_AuthorizedView_RenamedSensitiveColumn(t *testing.T) {
	rules := Rules{
		AllowedStatements: []string{"SELECT"},
		AllowedTables:     []string{"users"},
		Views: []ViewPolicy{
			{
				Name:      "user_summary_view",
				BaseTable: "users",
				ColumnMappings: map[string]string{
					"user_id":     "id",
					"national_id": "ssn",
					"card_number": "credit_card",
				},
			},
		},
		MaskedColumns: map[string][]string{
			"users": {"ssn", "credit_card"},
		},
	}
	parser := &PostgresParser{}

	sql := "SELECT user_id, national_id, card_number FROM user_summary_view"
	rewritten, _, err := parser.ApplyRules(sql, rules, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(rewritten, "'[REDACTED]'") {
		t.Fatalf("expected national_id and card_number to be masked, got: %s", rewritten)
	}
}

func TestViewMasking_UnauthorizedView_RejectedEvenIfBaseTableAllowed(t *testing.T) {
	rules := Rules{
		AllowedStatements: []string{"SELECT"},
		AllowedTables:     []string{"users"},
		Views: []ViewPolicy{
			{
				Name:      "approved_view",
				BaseTable: "users",
				ColumnMappings: map[string]string{
					"name": "name",
				},
			},
		},
		MaskedColumns: map[string][]string{
			"users": {"ssn"},
		},
	}
	parser := &PostgresParser{}

	// unapproved_view references users in DB, but is not in policy
	sql := "SELECT ssn FROM unapproved_view"
	_, _, err := parser.ApplyRules(sql, rules, nil)
	if err == nil {
		t.Fatalf("expected unapproved view to be rejected under default-deny")
	}
	if !strings.Contains(err.Error(), "policy violation: access to relation 'unapproved_view' is not allowed") {
		t.Fatalf("expected default-deny error, got: %v", err)
	}
}

func TestViewMasking_NestedView_InheritedMasking(t *testing.T) {
	rules := Rules{
		AllowedStatements: []string{"SELECT"},
		AllowedTables:     []string{"users"},
		Views: []ViewPolicy{
			{
				Name:      "inner_view",
				BaseTable: "users",
				ColumnMappings: map[string]string{
					"id":        "id",
					"inner_ssn": "ssn",
				},
			},
			{
				Name:      "outer_view",
				BaseTable: "inner_view",
				ColumnMappings: map[string]string{
					"id":        "id",
					"outer_ssn": "inner_ssn",
				},
			},
		},
		MaskedColumns: map[string][]string{
			"users": {"ssn"},
		},
	}
	parser := &PostgresParser{}

	sql := "SELECT id, outer_ssn FROM outer_view"
	rewritten, _, err := parser.ApplyRules(sql, rules, nil)
	if err != nil {
		t.Fatalf("unexpected error on nested view query: %v", err)
	}
	if !strings.Contains(rewritten, "'[REDACTED]'") {
		t.Fatalf("expected outer_ssn to inherit ssn masking through inner_view, got: %s", rewritten)
	}
}

func TestViewMasking_CircularView_Fails(t *testing.T) {
	rules := Rules{
		AllowedStatements: []string{"SELECT"},
		AllowedTables:     []string{"users"},
		Views: []ViewPolicy{
			{
				Name:           "v1",
				BaseTable:      "v2",
				ColumnMappings: map[string]string{"a": "b"},
			},
			{
				Name:           "v2",
				BaseTable:      "v1",
				ColumnMappings: map[string]string{"b": "a"},
			},
		},
		MaskedColumns: map[string][]string{
			"users": {"ssn"},
		},
	}
	parser := &PostgresParser{}

	sql := "SELECT a FROM v1"
	_, _, err := parser.ApplyRules(sql, rules, nil)
	if err == nil {
		t.Fatalf("expected circular view definition to fail")
	}
	if !strings.Contains(err.Error(), "circular view dependency detected") {
		t.Fatalf("expected circular dependency error, got: %v", err)
	}
}

func TestViewMasking_FailClosed_ViewWithoutColumnMappingsOnMaskedBaseTable(t *testing.T) {
	rules := Rules{
		AllowedStatements: []string{"SELECT"},
		AllowedTables:     []string{"users"},
		Views: []ViewPolicy{
			{
				Name:      "unmapped_view",
				BaseTable: "users",
				// No column mappings and no masked_columns
			},
		},
		MaskedColumns: map[string][]string{
			"users": {"ssn"},
		},
	}
	parser := &PostgresParser{}

	sql := "SELECT id FROM unmapped_view"
	_, _, err := parser.ApplyRules(sql, rules, nil)
	if err == nil {
		t.Fatalf("expected unmapped view on masked base table to fail closed")
	}
	if !strings.Contains(err.Error(), "references masked base table 'users' without explicit column mappings") {
		t.Fatalf("expected fail-closed configuration error, got: %v", err)
	}
}

func TestViewMasking_JoinBypassAttempt(t *testing.T) {
	rules := Rules{
		AllowedStatements: []string{"SELECT"},
		AllowedTables:     []string{"users", "accounts"},
		Views: []ViewPolicy{
			{
				Name:      "user_view",
				BaseTable: "users",
				ColumnMappings: map[string]string{
					"national_id": "ssn",
				},
			},
		},
		MaskedColumns: map[string][]string{
			"users": {"ssn"},
		},
	}
	parser := &PostgresParser{}

	// Join with unauthorized view
	sqlUnauthorized := "SELECT a.id, v.ssn FROM accounts a JOIN rogue_view v ON a.user_id = v.user_id"
	_, _, err := parser.ApplyRules(sqlUnauthorized, rules, nil)
	if err == nil {
		t.Fatalf("expected JOIN with rogue_view to be rejected")
	}
	if !strings.Contains(err.Error(), "rogue_view") {
		t.Fatalf("expected error mentioning rogue_view, got: %v", err)
	}

	// Join with authorized view: national_id masked
	sqlAuthorized := "SELECT a.id, v.national_id FROM accounts a JOIN user_view v ON a.user_id = v.user_id"
	rewritten, _, err := parser.ApplyRules(sqlAuthorized, rules, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(rewritten, "'[REDACTED]'") {
		t.Fatalf("expected national_id to be redacted in JOIN, got: %s", rewritten)
	}
}

func TestViewMasking_CTEBypassAttempt(t *testing.T) {
	rules := Rules{
		AllowedStatements: []string{"SELECT"},
		AllowedTables:     []string{"users"},
		Views: []ViewPolicy{
			{
				Name:      "user_view",
				BaseTable: "users",
				ColumnMappings: map[string]string{
					"national_id": "ssn",
				},
			},
		},
		MaskedColumns: map[string][]string{
			"users": {"ssn"},
		},
	}
	parser := &PostgresParser{}

	// Attempt 1: Query unauthorized table inside CTE
	sql1 := "WITH stolen AS (SELECT * FROM unauthorized_tbl) SELECT * FROM stolen"
	_, _, err := parser.ApplyRules(sql1, rules, nil)
	if err == nil {
		t.Fatalf("expected unauthorized table inside CTE to be blocked")
	}

	// Attempt 2: SELECT * inside CTE querying masked view
	sql2 := "WITH stolen AS (SELECT * FROM user_view) SELECT * FROM stolen"
	_, _, err = parser.ApplyRules(sql2, rules, nil)
	if err == nil {
		t.Fatalf("expected SELECT * inside CTE querying masked view to be blocked")
	}
	if !strings.Contains(err.Error(), "implicit row expansion (SELECT *) is blocked") {
		t.Fatalf("expected row expansion error, got: %v", err)
	}

	// Attempt 3: Specific column selection inside CTE is masked
	sql3 := "WITH safe_cte AS (SELECT national_id FROM user_view) SELECT national_id FROM safe_cte"
	rewritten, _, err := parser.ApplyRules(sql3, rules, nil)
	if err != nil {
		t.Fatalf("unexpected error on safe CTE: %v", err)
	}
	if !strings.Contains(rewritten, "'[REDACTED]'") {
		t.Fatalf("expected national_id to be masked inside CTE, got: %s", rewritten)
	}
}

func TestViewMasking_SubqueryBypassAttempt(t *testing.T) {
	rules := Rules{
		AllowedStatements: []string{"SELECT"},
		AllowedTables:     []string{"users"},
		Views: []ViewPolicy{
			{
				Name:      "user_view",
				BaseTable: "users",
				ColumnMappings: map[string]string{
					"national_id": "ssn",
				},
			},
		},
		MaskedColumns: map[string][]string{
			"users": {"ssn"},
		},
	}
	parser := &PostgresParser{}

	// Attempt 1: Subquery with unauthorized table
	sql1 := "SELECT * FROM (SELECT id FROM unapproved_secret_tbl) AS sub"
	_, _, err := parser.ApplyRules(sql1, rules, nil)
	if err == nil {
		t.Fatalf("expected unauthorized table inside subquery to be blocked")
	}

	// Attempt 2: Subquery with SELECT * on masked view
	sql2 := "SELECT * FROM (SELECT * FROM user_view) AS sub"
	_, _, err = parser.ApplyRules(sql2, rules, nil)
	if err == nil {
		t.Fatalf("expected SELECT * inside subquery to be blocked")
	}

	// Attempt 3: Subquery selecting masked column is rewritten
	sql3 := "SELECT sub.national_id FROM (SELECT national_id FROM user_view) AS sub"
	rewritten, _, err := parser.ApplyRules(sql3, rules, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(rewritten, "'[REDACTED]'") {
		t.Fatalf("expected national_id to be redacted in subquery, got: %s", rewritten)
	}
}

func TestViewMasking_SelectStar_BlockedOnMaskedView(t *testing.T) {
	rules := Rules{
		AllowedStatements: []string{"SELECT"},
		AllowedTables:     []string{"users"},
		Views: []ViewPolicy{
			{
				Name:      "user_view",
				BaseTable: "users",
				ColumnMappings: map[string]string{
					"national_id": "ssn",
				},
			},
		},
		MaskedColumns: map[string][]string{
			"users": {"ssn"},
		},
	}
	parser := &PostgresParser{}

	// SELECT *
	sql1 := "SELECT * FROM user_view"
	_, _, err := parser.ApplyRules(sql1, rules, nil)
	if err == nil {
		t.Fatalf("expected SELECT * from masked view to be blocked")
	}

	// SELECT v.*
	sql2 := "SELECT v.* FROM user_view v"
	_, _, err = parser.ApplyRules(sql2, rules, nil)
	if err == nil {
		t.Fatalf("expected SELECT v.* from masked view to be blocked")
	}
}

func TestViewMasking_SchemaQualifiedAndQuotedIdentifiers(t *testing.T) {
	rules := Rules{
		AllowedStatements: []string{"SELECT"},
		AllowedTables:     []string{"public.users"},
		Views: []ViewPolicy{
			{
				Name:      "public.user_view",
				BaseTable: "public.users",
				ColumnMappings: map[string]string{
					"national_id": "ssn",
				},
			},
		},
		MaskedColumns: map[string][]string{
			"public.users": {"ssn"},
		},
	}
	parser := &PostgresParser{}

	// Quoted identifiers and schema qualification
	sql := `SELECT "public"."user_view"."national_id" FROM "public"."user_view"`
	rewritten, _, err := parser.ApplyRules(sql, rules, nil)
	if err != nil {
		t.Fatalf("unexpected error with schema-qualified quoted identifiers: %v", err)
	}
	if !strings.Contains(rewritten, "'[REDACTED]'") {
		t.Fatalf("expected national_id to be redacted in schema-qualified quoted query, got: %s", rewritten)
	}
}

func TestViewMasking_PreparedAndParameterizedSQL(t *testing.T) {
	rules := Rules{
		AllowedStatements: []string{"SELECT"},
		AllowedTables:     []string{"users"},
		Views: []ViewPolicy{
			{
				Name:      "user_view",
				BaseTable: "users",
				ColumnMappings: map[string]string{
					"national_id": "ssn",
				},
			},
		},
		MaskedColumns: map[string][]string{
			"users": {"ssn"},
		},
	}
	parser := &PostgresParser{}

	sql := "SELECT national_id FROM user_view WHERE id = $1 AND name = $2"
	rewritten, _, err := parser.ApplyRules(sql, rules, nil)
	if err != nil {
		t.Fatalf("unexpected error with parameterized query: %v", err)
	}
	if !strings.Contains(rewritten, "'[REDACTED]'") {
		t.Fatalf("expected national_id to be redacted in parameterized query, got: %s", rewritten)
	}
	if !strings.Contains(rewritten, "$1") || !strings.Contains(rewritten, "$2") {
		t.Fatalf("expected parameters $1 and $2 to be preserved, got: %s", rewritten)
	}
}

func TestViewMasking_MalformedSQL_FailsClosed(t *testing.T) {
	rules := Rules{
		AllowedStatements: []string{"SELECT"},
		AllowedTables:     []string{"users"},
		MaskedColumns: map[string][]string{
			"users": {"ssn"},
		},
	}
	parser := &PostgresParser{}

	malformed := "SELECT FROM WHERE !!! SELECT SYNTAX ERROR"
	_, _, err := parser.ApplyRules(malformed, rules, nil)
	if err == nil {
		t.Fatalf("expected malformed SQL to fail closed")
	}
}

func TestViewMasking_ReturningClauses_Masked(t *testing.T) {
	rules := Rules{
		AllowedStatements: []string{"UPDATE", "DELETE", "INSERT"},
		AllowedTables:     []string{"users"},
		MaskedColumns: map[string][]string{
			"users": {"ssn"},
		},
	}
	parser := &PostgresParser{}

	// UPDATE RETURNING ssn
	updSQL := "UPDATE users SET name = 'Alice' WHERE id = 1 RETURNING ssn"
	rewrittenUpd, _, err := parser.ApplyRules(updSQL, rules, nil)
	if err != nil {
		t.Fatalf("unexpected error on UPDATE RETURNING: %v", err)
	}
	if !strings.Contains(rewrittenUpd, "'[REDACTED]'") {
		t.Fatalf("expected ssn to be redacted in UPDATE RETURNING, got: %s", rewrittenUpd)
	}

	// DELETE RETURNING ssn
	delSQL := "DELETE FROM users WHERE id = 1 RETURNING ssn"
	rewrittenDel, _, err := parser.ApplyRules(delSQL, rules, nil)
	if err != nil {
		t.Fatalf("unexpected error on DELETE RETURNING: %v", err)
	}
	if !strings.Contains(rewrittenDel, "'[REDACTED]'") {
		t.Fatalf("expected ssn to be redacted in DELETE RETURNING, got: %s", rewrittenDel)
	}
}

func TestViewMasking_TenantIsolation_PreservedWithMasking(t *testing.T) {
	rules := Rules{
		AllowedStatements: []string{"SELECT"},
		AllowedTables:     []string{"users"},
		Views: []ViewPolicy{
			{
				Name:      "user_view",
				BaseTable: "users",
				ColumnMappings: map[string]string{
					"national_id": "ssn",
					"tenant_id":   "tenant_id",
				},
			},
		},
		MaskedColumns: map[string][]string{
			"users": {"ssn"},
		},
		TenantIsolation: &TenantIsolationRule{
			Enabled:      true,
			TenantColumn: "tenant_id",
			TenantID:     "tenant-acme-123",
		},
	}
	parser := &PostgresParser{}

	sql := "SELECT id, national_id FROM user_view"
	rewritten, _, err := parser.ApplyRules(sql, rules, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(rewritten, "'[REDACTED]'") {
		t.Fatalf("expected national_id to be redacted, got: %s", rewritten)
	}
	if !strings.Contains(rewritten, "tenant-acme-123") {
		t.Fatalf("expected tenant filter injection, got: %s", rewritten)
	}
}

func TestViewMasking_SensitiveColumnInWhere_Rejected(t *testing.T) {
	rules := Rules{
		AllowedStatements: []string{"SELECT"},
		AllowedTables:     []string{"users"},
		MaskedColumns: map[string][]string{
			"users": {"ssn"},
		},
	}
	parser := &PostgresParser{}

	queries := []string{
		"SELECT id FROM users WHERE ssn = '123-45-6789'",
		"SELECT id FROM users WHERE ssn IS NOT NULL",
		"SELECT id FROM users WHERE ssn IN ('111', '222')",
		"SELECT id FROM users WHERE ssn LIKE '123%'",
		"SELECT id FROM users WHERE length(ssn) > 5",
	}

	for _, q := range queries {
		_, _, err := parser.ApplyRules(q, rules, nil)
		if err == nil {
			t.Fatalf("expected query '%s' to be rejected due to sensitive column in WHERE, but succeeded", q)
		}
		if !strings.Contains(err.Error(), "sensitive column 'ssn' cannot be referenced in WHERE clause") {
			t.Fatalf("expected specific error for query '%s', got: %v", q, err)
		}
	}
}

func TestViewMasking_SensitiveColumnInJoinOn_Rejected(t *testing.T) {
	rules := Rules{
		AllowedStatements: []string{"SELECT"},
		AllowedTables:     []string{"users", "profiles"},
		MaskedColumns: map[string][]string{
			"users": {"ssn"},
		},
	}
	parser := &PostgresParser{}

	queries := []string{
		"SELECT u.id, p.bio FROM users u JOIN profiles p ON u.ssn = p.ssn_ref",
		"SELECT u.id, p.bio FROM users u LEFT JOIN profiles p ON u.id = p.user_id AND u.ssn = 'secret'",
	}

	for _, q := range queries {
		_, _, err := parser.ApplyRules(q, rules, nil)
		if err == nil {
			t.Fatalf("expected query '%s' to be rejected due to sensitive column in JOIN ON, but succeeded", q)
		}
		if !strings.Contains(err.Error(), "sensitive column 'ssn' cannot be referenced in JOIN ON clause") {
			t.Fatalf("expected specific join error for query '%s', got: %v", q, err)
		}
	}
}

func TestViewMasking_SensitiveColumnInGroupByHavingOrderByWindow_Rejected(t *testing.T) {
	rules := Rules{
		AllowedStatements: []string{"SELECT"},
		AllowedTables:     []string{"users"},
		MaskedColumns: map[string][]string{
			"users": {"ssn"},
		},
	}
	parser := &PostgresParser{}

	cases := []struct {
		sql    string
		clause string
	}{
		{"SELECT count(*) FROM users GROUP BY ssn", "GROUP BY clause"},
		{"SELECT count(*) FROM users GROUP BY id HAVING max(ssn) > '1'", "HAVING clause"},
		{"SELECT id FROM users ORDER BY ssn DESC", "ORDER BY clause"},
		{"SELECT id FROM users WINDOW w AS (PARTITION BY ssn)", "WINDOW clause"},
		{"SELECT id, row_number() OVER (PARTITION BY ssn ORDER BY id) FROM users", "derived SELECT expression"},
		{"SELECT id, row_number() OVER (ORDER BY ssn) FROM users", "derived SELECT expression"},
	}

	for _, tc := range cases {
		_, _, err := parser.ApplyRules(tc.sql, rules, nil)
		if err == nil {
			t.Fatalf("expected query '%s' to be rejected, but succeeded", tc.sql)
		}
		if !strings.Contains(err.Error(), tc.clause) {
			t.Fatalf("expected error mentioning '%s' for '%s', got: %v", tc.clause, tc.sql, err)
		}
	}
}

func TestViewMasking_SensitiveColumnInDerivedExpressions_Rejected(t *testing.T) {
	rules := Rules{
		AllowedStatements: []string{"SELECT"},
		AllowedTables:     []string{"users"},
		MaskedColumns: map[string][]string{
			"users": {"ssn"},
		},
	}
	parser := &PostgresParser{}

	derivedQueries := []string{
		"SELECT upper(ssn) FROM users",
		"SELECT ssn || '-suffix' FROM users",
		"SELECT ssn::text FROM users",
		"SELECT CASE WHEN ssn = '123' THEN 'A' ELSE 'B' END FROM users",
		"SELECT COALESCE(ssn, 'none') FROM users",
	}

	for _, q := range derivedQueries {
		_, _, err := parser.ApplyRules(q, rules, nil)
		if err == nil {
			t.Fatalf("expected query '%s' to be rejected due to sensitive column in derived expression, but succeeded", q)
		}
		if !strings.Contains(err.Error(), "derived SELECT expression") {
			t.Fatalf("expected derived SELECT expression error for '%s', got: %v", q, err)
		}
	}
}

func TestViewMasking_MultipleMaskedBaseColumns_IncompleteMapping_Rejected(t *testing.T) {
	rules := Rules{
		AllowedStatements: []string{"SELECT"},
		AllowedTables:     []string{"users"},
		Views: []ViewPolicy{
			{
				Name:      "user_partial_view",
				BaseTable: "users",
				ColumnMappings: map[string]string{
					"national_id": "ssn",
				},
				// Note: credit_card is NOT mapped and NOT declared in UnexposedColumns
			},
		},
		MaskedColumns: map[string][]string{
			"users": {"ssn", "credit_card"},
		},
	}
	parser := &PostgresParser{}

	sql := "SELECT id, national_id FROM user_partial_view"
	_, _, err := parser.ApplyRules(sql, rules, nil)
	if err == nil {
		t.Fatalf("expected incomplete view mapping across multiple masked columns to fail closed, but succeeded")
	}
	if !strings.Contains(err.Error(), "unmapped sensitive column 'credit_card'") {
		t.Fatalf("expected error complaining about unmapped sensitive column 'credit_card', got: %v", err)
	}
}

func TestViewMasking_MultipleMaskedBaseColumns_WithUnexposedColumns_Allowed(t *testing.T) {
	rules := Rules{
		AllowedStatements: []string{"SELECT"},
		AllowedTables:     []string{"users"},
		Views: []ViewPolicy{
			{
				Name:      "user_audited_view",
				BaseTable: "users",
				ColumnMappings: map[string]string{
					"national_id": "ssn",
				},
				UnexposedColumns: []string{"credit_card"},
			},
		},
		MaskedColumns: map[string][]string{
			"users": {"ssn", "credit_card"},
		},
	}
	parser := &PostgresParser{}

	sql := "SELECT id, national_id FROM user_audited_view"
	rewritten, _, err := parser.ApplyRules(sql, rules, nil)
	if err != nil {
		t.Fatalf("unexpected error with explicit unexposed_columns: %v", err)
	}
	if !strings.Contains(rewritten, "'[REDACTED]'") {
		t.Fatalf("expected national_id to be redacted to '[REDACTED]', got: %s", rewritten)
	}
}

func TestViewMasking_AuthorizedQuery_UnaffectedColumns_Passes(t *testing.T) {
	rules := Rules{
		AllowedStatements: []string{"SELECT"},
		AllowedTables:     []string{"users"},
		MaskedColumns: map[string][]string{
			"users": {"ssn"},
		},
	}
	parser := &PostgresParser{}

	sql := "SELECT id, name, created_at FROM users WHERE id = 42 ORDER BY name ASC"
	rewritten, _, err := parser.ApplyRules(sql, rules, nil)
	if err != nil {
		t.Fatalf("unexpected error on authorized query: %v", err)
	}
	if strings.Contains(rewritten, "'[REDACTED]'") {
		t.Fatalf("unexpected redaction in query with no sensitive columns: %s", rewritten)
	}
	if !strings.Contains(rewritten, "WHERE id = 42") {
		t.Fatalf("expected WHERE clause to be preserved, got: %s", rewritten)
	}
}

func TestViewMasking_SubqueriesAndCTEs_StrictEnforcement(t *testing.T) {
	rules := Rules{
		AllowedStatements: []string{"SELECT"},
		AllowedTables:     []string{"users"},
		MaskedColumns: map[string][]string{
			"users": {"ssn"},
		},
	}
	parser := &PostgresParser{}

	// Subquery where outer WHERE filters on sensitive column
	sq1 := "SELECT * FROM (SELECT ssn FROM users) sub WHERE ssn = '123'"
	_, _, err := parser.ApplyRules(sq1, rules, nil)
	if err == nil {
		t.Fatalf("expected subquery with outer filter on sensitive column to fail closed")
	}

	// CTE where outer query filters on sensitive column
	cte1 := "WITH cte AS (SELECT ssn FROM users) SELECT * FROM cte WHERE ssn = '123'"
	_, _, err = parser.ApplyRules(cte1, rules, nil)
	if err == nil {
		t.Fatalf("expected CTE with outer filter on sensitive column to fail closed")
	}
}
