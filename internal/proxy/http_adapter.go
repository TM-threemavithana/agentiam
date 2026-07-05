package proxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/tm-threemavithana/agentiam/internal/ast"
	"github.com/tm-threemavithana/agentiam/internal/cache"
	"github.com/tm-threemavithana/agentiam/internal/policy"
)

type HTTPInterceptor struct {
	upstreamURL        *url.URL
	store              *policy.Store
	logger             *Logger
	astCache           cache.ASTCache
	upstreamAuthHeader string
	reverseProxy       *httputil.ReverseProxy
}

func NewHTTPInterceptorProxy(upstream string, store *policy.Store, logger *Logger, astCache cache.ASTCache, upstreamAuthHeader string) (*HTTPInterceptor, error) {
	u, err := url.Parse(upstream)
	if err != nil {
		return nil, fmt.Errorf("invalid upstream URL: %w", err)
	}

	proxy := httputil.NewSingleHostReverseProxy(u)

	interceptor := &HTTPInterceptor{
		upstreamURL:        u,
		store:              store,
		logger:             logger,
		astCache:           astCache,
		upstreamAuthHeader: upstreamAuthHeader,
		reverseProxy:       proxy,
	}

	// Override the Director to inject the correct upstream Host and Auth
	originalDirector := proxy.Director
	proxy.Director = func(req *http.Request) {
		originalDirector(req)
		req.Host = u.Host
		if interceptor.upstreamAuthHeader != "" {
			req.Header.Set("Authorization", interceptor.upstreamAuthHeader)
		}
	}

	return interceptor, nil
}

func (h *HTTPInterceptor) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// 1. Authenticate Downstream Agent
	agentID, password, ok := r.BasicAuth()
	if !ok {
		http.Error(w, "Unauthorized: Basic auth required", http.StatusUnauthorized)
		return
	}

	rules, _, err := h.store.GetRulesForAgent(agentID, password)
	if err != nil {
		h.logger.Warn("Failed HTTP auth", "agent", agentID, "error", err)
		http.Error(w, "Unauthorized: Invalid credentials", http.StatusUnauthorized)
		return
	}

	// 2. Intercept Databricks / Snowflake statement API
	// e.g. Snowflake: /api/v2/statements, Databricks: /api/2.0/sql/statements
	if r.Method == "POST" && strings.Contains(r.URL.Path, "statement") {
		h.interceptSQLPayload(w, r, agentID, rules)
		return
	}

	// Pass through other requests (like checking status of async queries)
	h.reverseProxy.ServeHTTP(w, r)
}

func (h *HTTPInterceptor) interceptSQLPayload(w http.ResponseWriter, r *http.Request, agentID string, rules ast.Rules) {
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read body", http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	var payload map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &payload); err != nil {
		h.logger.Warn("Failed to parse JSON body", "error", err)
		http.Error(w, "Invalid JSON body", http.StatusBadRequest)
		return
	}

	rawSQL, ok := payload["statement"].(string)
	if !ok || rawSQL == "" {
		// Just pass through if no statement field
		r.Body = io.NopCloser(bytes.NewReader(bodyBytes))
		r.ContentLength = int64(len(bodyBytes))
		h.reverseProxy.ServeHTTP(w, r)
		return
	}

	// 3. Parse AST and Apply Policies
	astParser := &ast.PostgresParser{}
	rewrittenSQL, _, err := astParser.ApplyRules(rawSQL, rules, h.astCache)
	if err != nil {
		h.logger.Warn("Policy violation in HTTP proxy", "agent", agentID, "sql", rawSQL, "error", err)
		http.Error(w, fmt.Sprintf("Policy Violation: %v", err), http.StatusForbidden)
		return
	}

	// 4. Reconstruct JSON Payload
	payload["statement"] = rewrittenSQL
	newBodyBytes, err := json.Marshal(payload)
	if err != nil {
		http.Error(w, "Failed to encode rewritten JSON", http.StatusInternalServerError)
		return
	}

	// Setup request for proxying
	r.Body = io.NopCloser(bytes.NewReader(newBodyBytes))
	r.ContentLength = int64(len(newBodyBytes))
	r.Header.Set("Content-Length", fmt.Sprintf("%d", len(newBodyBytes)))
	
	h.logger.Info("HTTP Intercept: SQL Rewritten successfully", "agent", agentID)
	h.reverseProxy.ServeHTTP(w, r)
}
