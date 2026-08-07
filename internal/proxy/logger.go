package proxy

import (
	"io"
	"log/slog"
)

const (
	EventPolicyBlocked  = "policy_blocked"
	EventQueryForwarded = "query_forwarded"
	EventSessionStart   = "session_start"
	EventSessionEnd     = "session_end"
	EventAuthFailed     = "auth_failed"
)

type Logger struct {
	*slog.Logger
}

func NewLogger(w io.Writer) *Logger {
	return &Logger{slog.New(slog.NewJSONHandler(w, nil))}
}
