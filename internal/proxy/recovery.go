package proxy

import (
	"errors"
	"fmt"
	"io"
	"net"
	"reflect"
	"regexp"
	"runtime"
	"runtime/debug"
	"strings"
)

var (
	// urlSecretRegex redacts user/password combinations embedded in URLs (e.g. postgres://user:pass@host/db).
	urlSecretRegex = regexp.MustCompile(`([a-zA-Z]+://[^:\s@]+):(.*)@([^/\s]+)`)

	// bearerRegex redacts Bearer authorization tokens.
	bearerRegex = regexp.MustCompile(`(?i)(bearer)\s+[a-zA-Z0-9._\-~+/]+=*`)

	// secretKeywordRegex redacts explicitly labeled credentials (password, secret, token, key, credential, auth).
	secretKeywordRegex = regexp.MustCompile(`(?i)(password|secret|token|key|credential|auth)\s*[:=]\s*['"]?[^'"\s]+['"]?`)

	// sqlRegex detects SQL statement fragments to prevent leaking raw queries or database literals.
	sqlRegex = regexp.MustCompile(`(?i)\b(SELECT|INSERT\s+INTO|UPDATE|DELETE\s+FROM|DROP\s+TABLE|CREATE\s+TABLE|ALTER\s+TABLE|TRUNCATE|VALUES|WHERE)\b`)

	// stackArgRegex strips function argument dumps in stack traces.
	stackArgRegex = regexp.MustCompile(`\((0x[0-9a-fA-F]+(?:,\s*0x[0-9a-fA-F]+)*|\.\.\.)?\)`)
)

// panicType extracts the concrete Go type name of a recovered panic value.
func panicType(r any) string {
	if r == nil {
		return "nil"
	}
	return fmt.Sprintf("%T", r)
}

// isTrustedErrorChain verifies that every error in an unwrapping error chain originates from
// standard Go packages (errors or fmt). It returns false for custom user/third-party types
// to avoid invoking untrusted .Error() implementations that could dump sensitive fields.
func isTrustedErrorChain(err error) bool {
	for err != nil {
		t := reflect.TypeOf(err)
		if t.Kind() == reflect.Pointer {
			t = t.Elem()
		}
		pkg := t.PkgPath()
		if pkg != "errors" && pkg != "fmt" {
			return false
		}
		u, ok := err.(interface{ Unwrap() error })
		if !ok {
			break
		}
		err = u.Unwrap()
	}
	return true
}

// safePanicSummary extracts a controlled, secret-free diagnostic summary from a recovered panic value.
// It prioritizes standard runtime error classifications, strictly avoids dumping arbitrary struct
// fields or calling untrusted String() methods, and scrubs recognized credential patterns as defense-in-depth.
func safePanicSummary(r any) string {
	if r == nil {
		return "nil"
	}

	// 1. Standard Go runtime error (e.g. nil pointer dereference, slice bounds out of range).
	// These static strings are emitted by the Go runtime; they never contain user secrets or SQL.
	if re, ok := r.(runtime.Error); ok {
		return re.Error()
	}

	// 2. Standard library sentinel error checks
	if err, ok := r.(error); ok {
		if errors.Is(err, io.EOF) {
			return "EOF"
		}
		if errors.Is(err, net.ErrClosed) {
			return "use of closed network connection"
		}
	}

	// 3. Extract text for trusted primitive strings or standard errors
	var raw string
	switch v := r.(type) {
	case string:
		raw = v
	case error:
		if isTrustedErrorChain(v) {
			raw = v.Error()
		} else {
			return fmt.Sprintf("untrusted panic object of type %T", r)
		}
	default:
		// Reject arbitrary structs, maps, slices, channels, pointers, and custom Stringers
		return fmt.Sprintf("untrusted panic object of type %T", r)
	}

	// Never leak SQL queries or literals
	if sqlRegex.MatchString(raw) {
		return "[SQL statement or query literal redacted]"
	}

	// Apply URL credentials redaction
	scrubbed := urlSecretRegex.ReplaceAllString(raw, "$1:[REDACTED]@$3")

	// Apply Bearer token redaction
	scrubbed = bearerRegex.ReplaceAllString(scrubbed, "$1 [REDACTED]")

	// Apply labeled credential redaction
	scrubbed = secretKeywordRegex.ReplaceAllString(scrubbed, "$1=[REDACTED]")

	// Enforce strict length bound (128 bytes) to prevent log flooding
	if len(scrubbed) > 128 {
		scrubbed = scrubbed[:128] + "... (truncated)"
	}
	return scrubbed
}

// sanitizePanicValue provides backward compatibility, returning safePanicSummary(r).
func sanitizePanicValue(r any) string {
	return safePanicSummary(r)
}

// sanitizedStackTrace captures and formats the current goroutine stack trace,
// bounded to 14 frames and stripping function argument dumps to prevent memory/credential disclosure.
func sanitizedStackTrace() string {
	raw := string(debug.Stack())
	lines := strings.Split(raw, "\n")
	if len(lines) > 14 {
		lines = append(lines[:14], "\t... (stack truncated)")
	}
	// Strip function parameter values like (0x12345, 0x67890) from stack frames
	for i, l := range lines {
		lines[i] = stackArgRegex.ReplaceAllString(l, "(...)")
	}
	return strings.Join(lines, "\n")
}
