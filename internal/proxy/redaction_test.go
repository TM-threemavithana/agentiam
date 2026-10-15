package proxy

import (
	"bytes"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"
)

type customSecretStringer struct {
	secret string
}

func (c customSecretStringer) String() string {
	return "customStringer with secret: " + c.secret
}

type customSecretError struct {
	secret string
}

func (e customSecretError) Error() string {
	return "customSecretError with secret: " + e.secret
}

type safeSyncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *safeSyncBuffer) Write(p []byte) (n int, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(p)
}

func (s *safeSyncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.String()
}

// 1. Explicitly labeled passwords
func TestDiagnosticRedaction_LabeledPasswords(t *testing.T) {
	const secret = "synthetic_admin_pass_987"
	input := fmt.Sprintf("database auth error: password='%s'", secret)
	out := safePanicSummary(input)
	if strings.Contains(out, secret) {
		t.Fatalf("Secret leaked in safePanicSummary: %s", out)
	}
	if !strings.Contains(out, "password=[REDACTED]") {
		t.Fatalf("Expected password=[REDACTED], got: %s", out)
	}
}

// 2. Explicitly labeled tokens
func TestDiagnosticRedaction_LabeledTokens(t *testing.T) {
	const secret = "synthetic_api_token_abc123"
	input := fmt.Sprintf("token exchange failed: token=%s", secret)
	out := safePanicSummary(input)
	if strings.Contains(out, secret) {
		t.Fatalf("Secret leaked in safePanicSummary: %s", out)
	}
	if !strings.Contains(out, "token=[REDACTED]") {
		t.Fatalf("Expected token=[REDACTED], got: %s", out)
	}
}

// 3. Wrapped errors containing synthetic secrets
func TestDiagnosticRedaction_WrappedErrors(t *testing.T) {
	const secret = "synthetic_private_key_xyz"
	innerErr := fmt.Errorf("crypto failure for key: %s", secret)
	wrappedErr := fmt.Errorf("connection setup wrapper: %w", innerErr)
	out := safePanicSummary(wrappedErr)
	if strings.Contains(out, secret) {
		t.Fatalf("Secret leaked from wrapped error: %s", out)
	}
	// Struct/pointer error types are safely identified by type without dumping arbitrary fields
	if !strings.Contains(out, "untrusted panic object") && !strings.Contains(out, "key=[REDACTED]") {
		t.Fatalf("Expected safe summary, got: %s", out)
	}
}

// 4. PostgreSQL URLs with embedded credentials
func TestDiagnosticRedaction_PostgresURLs(t *testing.T) {
	const secret = "s3cr3tP@ssw0rd"
	input := fmt.Sprintf("dial failed: postgres://app_user:%s@db.internal:5432/production", secret)
	out := safePanicSummary(input)
	if strings.Contains(out, secret) {
		t.Fatalf("PostgreSQL credential leaked from URL: %s", out)
	}
	if !strings.Contains(out, "postgres://app_user:[REDACTED]@db.internal:5432/production") {
		t.Fatalf("Expected URL credential redaction, got: %s", out)
	}
}

// 5. Bearer authorization headers
func TestDiagnosticRedaction_BearerHeaders(t *testing.T) {
	const secret = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.synthetic_jwt_token_456"
	input := fmt.Sprintf("http header Authorization: Bearer %s", secret)
	out := safePanicSummary(input)
	if strings.Contains(out, secret) {
		t.Fatalf("Bearer token leaked: %s", out)
	}
	if !strings.Contains(out, "Bearer [REDACTED]") {
		t.Fatalf("Expected Bearer [REDACTED], got: %s", out)
	}
}

// 6. SQL statements with synthetic payment or personal data
func TestDiagnosticRedaction_SQLStatementsWithPII(t *testing.T) {
	const cc = "4111-2222-3333-4444"
	const ssn = "000-12-3456"
	input := fmt.Sprintf("syntax error at: INSERT INTO customers (id, cc, ssn) VALUES (1, '%s', '%s')", cc, ssn)
	out := safePanicSummary(input)
	if strings.Contains(out, cc) {
		t.Fatalf("Credit card number leaked from SQL: %s", out)
	}
	if strings.Contains(out, ssn) {
		t.Fatalf("SSN leaked from SQL: %s", out)
	}
	if out != "[SQL statement or query literal redacted]" {
		t.Fatalf("Expected SQL statement to be masked, got: %s", out)
	}
}

// 7. Unlabeled structs containing synthetic secrets
func TestDiagnosticRedaction_UnlabeledStructs(t *testing.T) {
	const secret = "unlabeled_synthetic_secret_777"
	type sensitiveStruct struct {
		AccountID string
		RawSecret string
	}
	val := sensitiveStruct{
		AccountID: "acc_123",
		RawSecret: secret,
	}
	out := safePanicSummary(val)
	if strings.Contains(out, secret) {
		t.Fatalf("Unlabeled struct field leaked: %s", out)
	}
	if !strings.Contains(out, "untrusted panic object of type proxy.sensitiveStruct") {
		t.Fatalf("Expected untrusted panic object classification, got: %s", out)
	}
}

// 8. Custom error and Stringer values containing secrets
func TestDiagnosticRedaction_CustomStringerAndErrors(t *testing.T) {
	const secret1 = "stringer_secret_888"
	stringer := customSecretStringer{secret: secret1}
	outStringer := safePanicSummary(stringer)
	if strings.Contains(outStringer, secret1) {
		t.Fatalf("Secret leaked via custom Stringer: %s", outStringer)
	}
	if !strings.Contains(outStringer, "untrusted panic object") {
		t.Fatalf("Expected untrusted panic object classification for Stringer, got: %s", outStringer)
	}

	const secret2 = "error_secret_999"
	errVal := customSecretError{secret: secret2}
	outErr := safePanicSummary(errVal)
	if strings.Contains(outErr, secret2) {
		t.Fatalf("Secret leaked via custom error: %s", outErr)
	}
}

// 9. Long panic messages exceeding the logging limit
func TestDiagnosticRedaction_LongPanicMessages(t *testing.T) {
	hugeMsg := "diagnostic_prefix_" + strings.Repeat("A", 250)
	out := safePanicSummary(hugeMsg)
	if len(out) > 150 {
		t.Fatalf("Expected message to be bounded, got len=%d: %s", len(out), out)
	}
	if !strings.HasSuffix(out, "... (truncated)") {
		t.Fatalf("Expected truncation suffix, got: %s", out)
	}
}

// 10. Concurrent session panics and sanitized structured logs on a real logging boundary
func TestDiagnosticRedaction_RealPanicLoggingBoundary_Concurrent(t *testing.T) {
	logBuf := &safeSyncBuffer{}
	logger := NewLogger(logBuf)

	const poolSize = 4
	server, pool, _, proxyAddr, cleanup := setupTeardownTestServer(t, poolSize, nil)
	defer cleanup()
	// Direct server and session logging to our safeSyncBuffer
	server.logger = logger
	if h, ok := server.handlers[ProtocolPostgres].(*PostgresProtocolHandler); ok {
		h.logger = logger
	}

	const numSessions = 4
	var wg sync.WaitGroup
	wg.Add(numSessions)

	secrets := []string{
		"postgres_url_secret_pass_111",
		"unlabeled_struct_secret_222",
		"bearer_jwt_secret_token_333",
		"sql_literal_card_4444_5555",
	}

	for i := 0; i < numSessions; i++ {
		go func(idx int) {
			defer wg.Done()
			conn, fe := connectTestClient(t, proxyAddr, "test_agent")
			if conn == nil {
				return
			}
			defer conn.Close()

			// Configure hook for this session index
			panicValForIndex := func() any {
				switch idx {
				case 0:
					return fmt.Sprintf("upstream failed: postgres://admin:%s@internal.db:5432/core", secrets[0])
				case 1:
					return struct{ Token string }{Token: secrets[1]}
				case 2:
					return fmt.Sprintf("auth failure: Authorization: Bearer %s", secrets[2])
				case 3:
					return fmt.Sprintf("invalid query: INSERT INTO logs VALUES ('%s')", secrets[3])
				default:
					return "simple error"
				}
			}

			// Hook into handleQueryMsg
			SetTestPanicHook(func() {
				panic(panicValForIndex())
			})

			fe.Send(&pgproto3.Query{String: "SELECT 1;"})
			_ = fe.Flush()

			// Read response (session will recover panic and terminate connection)
			_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
			buf := make([]byte, 512)
			_, _ = conn.Read(buf)
		}(i)
	}

	wg.Wait()
	time.Sleep(300 * time.Millisecond)

	capturedLogs := logBuf.String()

	// Assert: none of the synthetic secrets appear ANYWHERE in the emitted application logs
	for i, sec := range secrets {
		if strings.Contains(capturedLogs, sec) {
			t.Errorf("Synthetic secret %d (%s) was leaked in application logs!\nLogs:\n%s", i+1, sec, capturedLogs)
		}
	}

	// Assert: structured fields are logged
	if !strings.Contains(capturedLogs, "session_worker_panic") && !strings.Contains(capturedLogs, "Panic recovered") {
		t.Errorf("Expected structured panic event in logs, got:\n%s", capturedLogs)
	}
	if !strings.Contains(capturedLogs, "panic_type") {
		t.Errorf("Expected panic_type attribute in structured logs, got:\n%s", capturedLogs)
	}

	// Invariant: Pool capacity must still be intact after all concurrent panics
	if pool.GetActiveCount() != 0 {
		t.Errorf("Expected active count 0 after panics, got %d", pool.GetActiveCount())
	}
}
