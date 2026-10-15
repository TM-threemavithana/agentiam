package proxy

import (
	"fmt"
	"regexp"
	"runtime/debug"
	"strings"
)

var (
	// secretRegex redacts sensitive credentials, passwords, tokens, or auth headers in recovered panic strings.
	secretRegex = regexp.MustCompile(`(?i)(password|secret|token|key|credential|auth)\s*[:=]\s*['"]?[^'"\s]+['"]?`)
)

// sanitizePanicValue extracts a sanitized, diagnostic-safe string from a recovered panic value.
// It redacts common credential patterns and truncates excessive message lengths to prevent log flooding.
func sanitizePanicValue(r any) string {
	if r == nil {
		return "nil"
	}
	var msg string
	switch v := r.(type) {
	case error:
		msg = v.Error()
	case string:
		msg = v
	default:
		msg = fmt.Sprintf("%v", v)
	}

	// Redact sensitive credential patterns
	msg = secretRegex.ReplaceAllString(msg, "$1=[REDACTED]")

	// Truncate to avoid log flooding
	if len(msg) > 256 {
		msg = msg[:256] + "... (truncated)"
	}
	return msg
}

// sanitizedStackTrace captures and formats the current goroutine stack trace,
// bounded to 15 frames to maintain diagnostic utility without log spam.
func sanitizedStackTrace() string {
	raw := string(debug.Stack())
	lines := strings.Split(raw, "\n")
	if len(lines) > 16 {
		return strings.Join(lines[:16], "\n") + "\n\t... (stack truncated)"
	}
	return raw
}
