package ast

import (
	"strings"
)

// CanonicalizeIdentifier returns the PostgreSQL canonical representation of an identifier:
// - If the identifier is enclosed in double quotes (e.g. `"Reports"`), quotes are removed and exact case is preserved (`Reports`).
// - If the identifier is unquoted (e.g. `Reports` or `reports`), it is folded to lowercase (`reports`).
func CanonicalizeIdentifier(ident string) string {
	ident = strings.TrimSpace(ident)
	if len(ident) >= 2 && ident[0] == '"' && ident[len(ident)-1] == '"' {
		return ident[1 : len(ident)-1]
	}
	return strings.ToLower(ident)
}

// SplitQualifiedIdentifier splits a relation name by unquoted dots, respecting double-quoted identifiers.
func SplitQualifiedIdentifier(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	var parts []string
	inQuotes := false
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '"' {
			inQuotes = !inQuotes
		} else if s[i] == '.' && !inQuotes {
			parts = append(parts, s[start:i])
			start = i + 1
		}
	}
	parts = append(parts, s[start:])
	return parts
}

// CanonicalViewKey returns the canonical "schema.view" identifier string for a view.
func CanonicalViewKey(schema, viewName string) string {
	s := CanonicalizeIdentifier(schema)
	if s == "" {
		s = "public"
	}
	v := CanonicalizeIdentifier(viewName)
	return s + "." + v
}

// SplitSchemaView splits a potentially qualified view name into its schema and view parts,
// preserving quote tokens so that downstream CanonicalViewKey and CanonicalizeIdentifier
// correctly distinguish quoted vs unquoted identifiers.
func SplitSchemaView(name string) (string, string) {
	parts := SplitQualifiedIdentifier(name)
	if len(parts) == 2 {
		return parts[0], parts[1]
	}
	return "public", name
}

// QuoteIdentIfNeeded wraps an identifier in double quotes if it contains uppercase characters,
// preserving the fact that pg_query preserved its case from an original quoted SQL token.
func QuoteIdentIfNeeded(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s
	}
	for _, ch := range s {
		if ch >= 'A' && ch <= 'Z' {
			return "\"" + s + "\""
		}
	}
	return s
}

