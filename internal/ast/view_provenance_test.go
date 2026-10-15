package ast_test

import (
	"strings"
	"testing"

	"github.com/tm-threemavithana/agentiam/internal/ast"
)

func TestViewProvenance_ValidApprovedView_FingerprintAndProvenanceMatch(t *testing.T) {
	viewDef := "SELECT id, name, ssn, credit_card, tenant_id FROM customers;"
	fp, err := ast.ComputeViewFingerprint(viewDef)
	if err != nil {
		t.Fatalf("unexpected error computing fingerprint: %v", err)
	}
	if !strings.HasPrefix(fp, "sha256:") {
		t.Fatalf("expected sha256: prefix in fingerprint, got %s", fp)
	}

	vp := ast.ViewPolicy{
		Name:                  "public.customer_public_view",
		BaseTable:             "customers",
		DefinitionFingerprint: fp,
		ColumnMappings: map[string]string{
			"id":          "id",
			"name":        "name",
			"ssn":         "ssn",
			"credit_card": "credit_card",
			"tenant_id":   "tenant_id",
		},
	}
	maskedCols := map[string][]string{
		"customers": {"ssn", "credit_card"},
	}

	if err := ast.ValidateViewProvenance(viewDef, vp, maskedCols); err != nil {
		t.Fatalf("expected valid view to pass provenance check, got: %v", err)
	}
}

func TestViewProvenance_MissingOrInvalidFingerprint(t *testing.T) {
	viewDef := "SELECT id, name FROM customers;"
	actualFP, _ := ast.ComputeViewFingerprint(viewDef)

	// 1. Missing fingerprint
	if ast.CompareFingerprints("", actualFP) {
		t.Fatalf("expected empty expected fingerprint to fail comparison")
	}

	// 2. Incorrect fingerprint
	wrongFP := "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	if ast.CompareFingerprints(wrongFP, actualFP) {
		t.Fatalf("expected mismatched fingerprint to fail comparison")
	}

	// 3. Valid comparison
	if !ast.CompareFingerprints(actualFP, actualFP) {
		t.Fatalf("expected identical fingerprints to match")
	}
}

func TestViewProvenance_ChangedViewDefinitionAfterApproval_Fails(t *testing.T) {
	approvedDef := "SELECT id, name FROM customers;"
	approvedFP, _ := ast.ComputeViewFingerprint(approvedDef)

	alteredDef := "SELECT id, name, ssn FROM customers;"
	alteredFP, _ := ast.ComputeViewFingerprint(alteredDef)

	if ast.CompareFingerprints(approvedFP, alteredFP) {
		t.Fatalf("expected altered view definition to have different fingerprint than approved")
	}
}

func TestViewProvenance_ComputedSensitiveSubstring_Rejected(t *testing.T) {
	// SEC-P2-05 exploit scenario: view derives sensitive substring while claiming ssn is unexposed
	viewDef := "SELECT id, substring(ssn FROM 1 FOR 4) AS identity_prefix FROM customers;"
	fp, _ := ast.ComputeViewFingerprint(viewDef)

	vp := ast.ViewPolicy{
		Name:                  "customer_public",
		BaseTable:             "customers",
		DefinitionFingerprint: fp,
		ColumnMappings: map[string]string{
			"id": "id",
		},
		UnexposedColumns: []string{"ssn"},
	}
	maskedCols := map[string][]string{
		"customers": {"ssn"},
	}

	err := ast.ValidateViewProvenance(viewDef, vp, maskedCols)
	if err == nil {
		t.Fatalf("expected computed sensitive substring projection to be rejected, but succeeded")
	}
	if !strings.Contains(err.Error(), "declared sensitive column 'ssn' in unexposed_columns") {
		t.Fatalf("expected error complaining about false unexposed_columns declaration, got: %v", err)
	}

	// Case 2: Even without unexposed_columns, computed output not in masked_columns must be rejected
	vp2 := ast.ViewPolicy{
		Name:                  "customer_public",
		BaseTable:             "customers",
		DefinitionFingerprint: fp,
		ColumnMappings: map[string]string{
			"id":              "id",
			"identity_prefix": "id", // deceptive mapping
		},
	}
	err2 := ast.ValidateViewProvenance(viewDef, vp2, maskedCols)
	if err2 == nil {
		t.Fatalf("expected computed output deriving from ssn without explicit masking to fail closed")
	}
	if !strings.Contains(err2.Error(), "derives from sensitive column 'ssn' via computed expression") {
		t.Fatalf("expected SEC-P2-05 derived output error, got: %v", err2)
	}
}

func TestViewProvenance_SensitiveColumnRenamedToInnocuousAlias_Rejected(t *testing.T) {
	// Attacker tries to expose ssn under innocent alias "notes" without mapping to ssn or masking
	viewDef := "SELECT id, ssn AS notes FROM customers;"
	fp, _ := ast.ComputeViewFingerprint(viewDef)

	vp := ast.ViewPolicy{
		Name:                  "customer_notes_view",
		BaseTable:             "customers",
		DefinitionFingerprint: fp,
		ColumnMappings: map[string]string{
			"id": "id",
		},
		UnexposedColumns: []string{"ssn"}, // false claim
	}
	maskedCols := map[string][]string{
		"customers": {"ssn"},
	}

	err := ast.ValidateViewProvenance(viewDef, vp, maskedCols)
	if err == nil {
		t.Fatalf("expected renamed sensitive column to fail closed")
	}
	if !strings.Contains(err.Error(), "declared sensitive column 'ssn' in unexposed_columns") {
		t.Fatalf("expected unexposed_columns violation error, got: %v", err)
	}

	// Omit unexposed_columns, but still don't map notes to ssn
	vp2 := ast.ViewPolicy{
		Name:                  "customer_notes_view",
		BaseTable:             "customers",
		DefinitionFingerprint: fp,
		ColumnMappings: map[string]string{
			"id":    "id",
			"notes": "notes", // mapped as if notes is a non-sensitive base column
		},
	}
	err2 := ast.ValidateViewProvenance(viewDef, vp2, maskedCols)
	if err2 == nil {
		t.Fatalf("expected unmapped sensitive rename to be rejected, but succeeded")
	}
	if !strings.Contains(err2.Error(), "projects sensitive column 'ssn' as 'notes' without explicit masking mapping") {
		t.Fatalf("expected unmapped sensitive rename error, got: %v", err2)
	}
}

func TestViewProvenance_IncompleteClassification_Rejected(t *testing.T) {
	viewDef := "SELECT id, name, internal_code FROM customers;"
	fp, _ := ast.ComputeViewFingerprint(viewDef)

	vp := ast.ViewPolicy{
		Name:                  "customer_partial_view",
		BaseTable:             "customers",
		DefinitionFingerprint: fp,
		ColumnMappings: map[string]string{
			"id":   "id",
			"name": "name",
			// internal_code is omitted from column_mappings and masked_columns
		},
	}
	maskedCols := map[string][]string{
		"customers": {"ssn"},
	}

	err := ast.ValidateViewProvenance(viewDef, vp, maskedCols)
	if err == nil {
		t.Fatalf("expected incomplete classification to fail closed")
	}
	if !strings.Contains(err.Error(), "internal_code' not classified in column_mappings") {
		t.Fatalf("expected incomplete classification error, got: %v", err)
	}
}

func TestViewProvenance_WildcardInViewDefinition_Rejected(t *testing.T) {
	viewDef := "SELECT * FROM customers;"
	fp, _ := ast.ComputeViewFingerprint(viewDef)

	vp := ast.ViewPolicy{
		Name:                  "customer_wildcard_view",
		BaseTable:             "customers",
		DefinitionFingerprint: fp,
	}
	maskedCols := map[string][]string{
		"customers": {"ssn"},
	}

	err := ast.ValidateViewProvenance(viewDef, vp, maskedCols)
	if err == nil {
		t.Fatalf("expected wildcard SELECT * in view definition to fail closed")
	}
	if !strings.Contains(err.Error(), "wildcard projection 'SELECT *'") {
		t.Fatalf("expected wildcard rejection error, got: %v", err)
	}
}

func TestViewProvenance_SensitiveColumnInViewWhereClause_FalseUnexposed_Rejected(t *testing.T) {
	viewDef := "SELECT id, name FROM customers WHERE ssn IS NOT NULL;"
	fp, _ := ast.ComputeViewFingerprint(viewDef)

	vp := ast.ViewPolicy{
		Name:                  "customer_active_view",
		BaseTable:             "customers",
		DefinitionFingerprint: fp,
		ColumnMappings: map[string]string{
			"id":   "id",
			"name": "name",
		},
		UnexposedColumns: []string{"ssn"}, // claimed unexposed, but filtered in WHERE
	}
	maskedCols := map[string][]string{
		"customers": {"ssn"},
	}

	err := ast.ValidateViewProvenance(viewDef, vp, maskedCols)
	if err == nil {
		t.Fatalf("expected filter on sensitive column with false unexposed claim to fail closed")
	}
	if !strings.Contains(err.Error(), "filters on it in WHERE clause") {
		t.Fatalf("expected WHERE filter violation error, got: %v", err)
	}
}

func TestViewProvenance_MismatchedBaseTable_Rejected(t *testing.T) {
	viewDef := "SELECT id, name FROM secret_table;"
	fp, _ := ast.ComputeViewFingerprint(viewDef)

	vp := ast.ViewPolicy{
		Name:                  "sneaky_view",
		BaseTable:             "customers", // policy claims customers, view queries secret_table
		DefinitionFingerprint: fp,
		ColumnMappings: map[string]string{
			"id":   "id",
			"name": "name",
		},
	}
	maskedCols := map[string][]string{
		"customers": {"ssn"},
	}

	err := ast.ValidateViewProvenance(viewDef, vp, maskedCols)
	if err == nil {
		t.Fatalf("expected mismatched base table to fail closed")
	}
	if !strings.Contains(err.Error(), "do not match configured base table") {
		t.Fatalf("expected base table mismatch error, got: %v", err)
	}
}

func TestViewProvenance_EnforceRelationAccess_UnverifiedView_Denied(t *testing.T) {
	parser := &ast.PostgresParser{}
	rules := ast.Rules{
		AllowedStatements:          []string{"SELECT"},
		AllowedTables:              []string{"customers"},
		RequireCatalogVerification: true,
		Views: []ast.ViewPolicy{
			{
				Name:      "customer_view",
				BaseTable: "customers",
			},
		},
		VerifiedViews: map[string]bool{
			"customer_view": false, // explicitly unverified
		},
	}

	sql := "SELECT id FROM customer_view;"
	_, _, err := parser.ApplyRules(sql, rules, nil)
	if err == nil {
		t.Fatalf("expected unverified view to be rejected under RequireCatalogVerification")
	}
	if !strings.Contains(err.Error(), "has not been verified against PostgreSQL catalog definition") {
		t.Fatalf("expected catalog verification error, got: %v", err)
	}
}

func TestViewProvenance_EnforceRelationAccess_VerifiedView_Allowed(t *testing.T) {
	parser := &ast.PostgresParser{}
	rules := ast.Rules{
		AllowedStatements:          []string{"SELECT"},
		AllowedTables:              []string{"customers"},
		RequireCatalogVerification: true,
		Views: []ast.ViewPolicy{
			{
				Name:      "customer_view",
				BaseTable: "customers",
				ColumnMappings: map[string]string{
					"id":   "id",
					"name": "name",
					"ssn":  "ssn",
				},
			},
		},
		MaskedColumns: map[string][]string{
			"customers": {"ssn"},
		},
		VerifiedViews: map[string]bool{
			"customer_view": true, // verified!
		},
	}

	// 1. Non-sensitive query
	sql := "SELECT id, name FROM customer_view;"
	rewritten, _, err := parser.ApplyRules(sql, rules, nil)
	if err != nil {
		t.Fatalf("expected verified view query to succeed, got: %v", err)
	}
	if strings.Contains(rewritten, "'[REDACTED]'") {
		t.Fatalf("did not expect non-sensitive query to be redacted: %s", rewritten)
	}

	// 2. Sensitive query on verified view -> masked
	sql2 := "SELECT id, ssn FROM customer_view;"
	rewritten2, _, err2 := parser.ApplyRules(sql2, rules, nil)
	if err2 != nil {
		t.Fatalf("expected verified sensitive query to succeed with masking, got: %v", err2)
	}
	if !strings.Contains(rewritten2, "'[REDACTED]'") {
		t.Fatalf("expected ssn to be redacted on verified view: %s", rewritten2)
	}
}
