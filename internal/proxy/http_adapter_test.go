package proxy

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tm-threemavithana/agentiam/internal/cache"
	"github.com/tm-threemavithana/agentiam/internal/policy"
	"golang.org/x/crypto/bcrypt"
)

func setupTestStore(t *testing.T, password string, allowedStatements []string, selectLimit int) *policy.Store {
	t.Helper()
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		t.Fatalf("Failed to hash password: %v", err)
	}

	tempDir := t.TempDir()
	policyPath := filepath.Join(tempDir, "policies.yaml")

	allowedJSON, _ := json.Marshal(allowedStatements)

	yamlContent := fmt.Sprintf(`agents:
  - name: test-agent
    key: "%s"
    allowed_statements: %s
    select_limit: %d
`, string(hash), string(allowedJSON), selectLimit)

	if err := os.WriteFile(policyPath, []byte(yamlContent), 0644); err != nil {
		t.Fatalf("Failed to write test policies: %v", err)
	}

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	store, err := policy.NewStore(policyPath, "", logger)
	if err != nil {
		t.Fatalf("Failed to create policy store: %v", err)
	}
	return store
}

func TestHTTPInterceptor_Authentication(t *testing.T) {
	upstreamReceivedAuth := ""
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamReceivedAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	}))
	defer upstream.Close()

	store := setupTestStore(t, "correct-password", []string{"SELECT"}, 100)
	lc, _ := cache.NewLocalCache(10)
	interceptor, err := NewHTTPInterceptorProxy(upstream.URL, store, NewLogger(io.Discard), lc, "Bearer UPSTREAM_SECRET")
	if err != nil {
		t.Fatalf("Failed to init HTTP proxy: %v", err)
	}

	server := httptest.NewServer(interceptor)
	defer server.Close()

	ctx := context.Background()

	// 1. Missing Basic Auth -> 401
	req1, _ := http.NewRequestWithContext(ctx, "GET", server.URL+"/api/v2/status", nil)
	resp1, err := http.DefaultClient.Do(req1)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	_ = resp1.Body.Close()
	if resp1.StatusCode != http.StatusUnauthorized {
		t.Fatalf("Expected 401 Unauthorized for missing auth, got: %d", resp1.StatusCode)
	}

	// 2. Invalid Password -> 401
	req2, _ := http.NewRequestWithContext(ctx, "GET", server.URL+"/api/v2/status", nil)
	req2.SetBasicAuth("test-agent", "wrong-password")
	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	_ = resp2.Body.Close()
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("Expected 401 Unauthorized for wrong password, got: %d", resp2.StatusCode)
	}

	// 3. Valid Credentials on non-statement endpoint -> 200 and upstream auth injected
	req3, _ := http.NewRequestWithContext(ctx, "GET", server.URL+"/api/v2/status", nil)
	req3.SetBasicAuth("test-agent", "correct-password")
	resp3, err := http.DefaultClient.Do(req3)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	_ = resp3.Body.Close()
	if resp3.StatusCode != http.StatusOK {
		t.Fatalf("Expected 200 OK for valid auth, got: %d", resp3.StatusCode)
	}
	if upstreamReceivedAuth != "Bearer UPSTREAM_SECRET" {
		t.Fatalf("Expected upstream Authorization 'Bearer UPSTREAM_SECRET', got: %s", upstreamReceivedAuth)
	}
}

func TestHTTPInterceptor_StatementInterceptionAndPolicyEnforcement(t *testing.T) {
	var receivedUpstreamBody []byte
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var err error
		receivedUpstreamBody, err = io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"statementHandle":"stmt-123","status":"SUCCEEDED"}`))
	}))
	defer upstream.Close()

	// Only SELECT allowed, LIMIT 50
	store := setupTestStore(t, "agent-secret", []string{"SELECT"}, 50)
	lc, _ := cache.NewLocalCache(10)
	interceptor, err := NewHTTPInterceptorProxy(upstream.URL, store, NewLogger(io.Discard), lc, "Bearer UPSTREAM_AUTH")
	if err != nil {
		t.Fatalf("Failed to init HTTP proxy: %v", err)
	}

	server := httptest.NewServer(interceptor)
	defer server.Close()

	ctx := context.Background()

	// 1. Allowed statement -> rewritten with LIMIT 50
	sqlPayload := map[string]interface{}{
		"statement": "SELECT id, name FROM users",
		"warehouse": "compute_wh",
	}
	payloadBytes, _ := json.Marshal(sqlPayload)

	req1, _ := http.NewRequestWithContext(ctx, "POST", server.URL+"/api/v2/statements", bytes.NewReader(payloadBytes))
	req1.SetBasicAuth("test-agent", "agent-secret")
	req1.Header.Set("Content-Type", "application/json")

	resp1, err := http.DefaultClient.Do(req1)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	body1, _ := io.ReadAll(resp1.Body)
	_ = resp1.Body.Close()
	if resp1.StatusCode != http.StatusOK {
		t.Fatalf("Expected 200 OK for allowed statement, got: %d: %s", resp1.StatusCode, string(body1))
	}

	var upstreamMap map[string]interface{}
	if err := json.Unmarshal(receivedUpstreamBody, &upstreamMap); err != nil {
		t.Fatalf("Failed to parse upstream body: %v", err)
	}
	rewrittenStmt, ok := upstreamMap["statement"].(string)
	if !ok || !strings.Contains(strings.ToUpper(rewrittenStmt), "LIMIT") {
		t.Fatalf("Expected rewritten SQL to enforce LIMIT 50, got: %v", upstreamMap["statement"])
	}

	// 2. Blocked statement (DROP TABLE) -> 403 Forbidden
	blockedPayload := map[string]interface{}{
		"statement": "DROP TABLE users",
	}
	blockedBytes, _ := json.Marshal(blockedPayload)

	req2, _ := http.NewRequestWithContext(ctx, "POST", server.URL+"/api/v2/statements", bytes.NewReader(blockedBytes))
	req2.SetBasicAuth("test-agent", "agent-secret")
	req2.Header.Set("Content-Type", "application/json")

	resp2, err := http.DefaultClient.Do(req2)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	_ = resp2.Body.Close()
	if resp2.StatusCode != http.StatusForbidden {
		t.Fatalf("Expected 403 Forbidden for disallowed statement, got: %d", resp2.StatusCode)
	}
}
