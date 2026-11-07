package ast_test

import (
	"reflect"
	"testing"

	"github.com/tm-threemavithana/agentiam/internal/ast"
)

func TestCanonicalizeIdentifier_QuotedPreservesCase(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"\"Reports\"", "Reports"},
		{"\"Public\"", "Public"},
		{"\"CaseSensitiveColumn\"", "CaseSensitiveColumn"},
		{"\"lower\"", "lower"},
		{"\"UPPER\"", "UPPER"},
		{"  \"Spaced\"  ", "Spaced"},
	}

	for _, tc := range tests {
		actual := ast.CanonicalizeIdentifier(tc.input)
		if actual != tc.expected {
			t.Errorf("CanonicalizeIdentifier(%q) = %q, expected %q", tc.input, actual, tc.expected)
		}
	}
}

func TestCanonicalizeIdentifier_UnquotedFoldsToLower(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"Reports", "reports"},
		{"REPORTS", "reports"},
		{"Public", "public"},
		{"CaseSensitiveColumn", "casesensitivecolumn"},
		{"lower", "lower"},
		{"  Customers  ", "customers"},
	}

	for _, tc := range tests {
		actual := ast.CanonicalizeIdentifier(tc.input)
		if actual != tc.expected {
			t.Errorf("CanonicalizeIdentifier(%q) = %q, expected %q", tc.input, actual, tc.expected)
		}
	}
}

func TestSplitQualifiedIdentifier(t *testing.T) {
	tests := []struct {
		input    string
		expected []string
	}{
		{"public.reports", []string{"public", "reports"}},
		{"public.\"Reports\"", []string{"public", "\"Reports\""}},
		{"\"FinanceDB\".\"Transactions\"", []string{"\"FinanceDB\"", "\"Transactions\""}},
		{"\"schema.with.dots\".\"table.name\"", []string{"\"schema.with.dots\"", "\"table.name\""}},
		{"reports", []string{"reports"}},
		{"\"Reports\"", []string{"\"Reports\""}},
		{"", nil},
	}

	for _, tc := range tests {
		actual := ast.SplitQualifiedIdentifier(tc.input)
		if !reflect.DeepEqual(actual, tc.expected) {
			t.Errorf("SplitQualifiedIdentifier(%q) = %v, expected %v", tc.input, actual, tc.expected)
		}
	}
}

func TestCanonicalViewKey(t *testing.T) {
	tests := []struct {
		schema   string
		viewName string
		expected string
	}{
		{"public", "reports", "public.reports"},
		{"public", "\"Reports\"", "public.Reports"},
		{"Public", "Reports", "public.reports"},
		{"\"Public\"", "\"Reports\"", "Public.Reports"},
		{"\"FinanceDB\"", "\"MonthlyRevenue\"", "FinanceDB.MonthlyRevenue"},
		{"", "\"Reports\"", "public.Reports"},
		{"", "reports", "public.reports"},
	}

	for _, tc := range tests {
		actual := ast.CanonicalViewKey(tc.schema, tc.viewName)
		if actual != tc.expected {
			t.Errorf("CanonicalViewKey(%q, %q) = %q, expected %q", tc.schema, tc.viewName, actual, tc.expected)
		}
	}
}

func TestSplitSchemaView(t *testing.T) {
	tests := []struct {
		input          string
		expectedSchema string
		expectedName   string
	}{
		{"public.reports", "public", "reports"},
		{"public.\"Reports\"", "public", "\"Reports\""},
		{"\"Reports\"", "public", "\"Reports\""},
		{"reports", "public", "reports"},
		{"\"FinanceDB\".\"Transactions\"", "\"FinanceDB\"", "\"Transactions\""},
		{"financedb.transactions", "financedb", "transactions"},
	}

	for _, tc := range tests {
		schema, name := ast.SplitSchemaView(tc.input)
		if schema != tc.expectedSchema || name != tc.expectedName {
			t.Errorf("SplitSchemaView(%q) = (%q, %q), expected (%q, %q)", tc.input, schema, name, tc.expectedSchema, tc.expectedName)
		}
	}
}
