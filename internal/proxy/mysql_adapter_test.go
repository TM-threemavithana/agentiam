package proxy

import (
	"bytes"
	"io"
	"log/slog"
	"testing"

	"github.com/tm-threemavithana/agentiam/internal/ast"
	"github.com/tm-threemavithana/agentiam/internal/cache"
	"github.com/tm-threemavithana/agentiam/internal/policy"
)

func TestMySQLHandler_HandleQuery_RulesEnforced(t *testing.T) {
	// Setup policy store
	discardLogger := slog.New(slog.NewTextHandler(io.Discard, nil))
	store, _ := policy.NewStore("", "", discardLogger)

	// Mock Server
	handlers := make(map[ProtocolType]ProtocolHandler)
	lc, _ := cache.NewLocalCache(10)
	srv := NewServer("127.0.0.1:0", "postgres://dummy", store, nil, NewLogger(io.Discard), lc, handlers, false, ":0", 5, nil, nil)

	handler := &AgentIAMMySQLHandler{
		db:       nil, // we won't query unless rules pass
		logger:   NewLogger(io.Discard),
		server:   srv,
		clientID: "test-agent",
		rules: ast.Rules{
			AllowedStatements: []string{"SELECT"},
			AllowedTables:     []string{"users"},
			BlockedFunctions:  []string{"sleep"},
		},
	}

	// 1. Blocked statement (DELETE)
	_, err := handler.HandleQuery("DELETE FROM users WHERE id = 1")
	if err == nil {
		t.Fatal("expected error for blocked DELETE statement, got nil")
	}
	if err.Error() != "policy violation: statement DELETE not allowed" {
		t.Errorf("unexpected error message: %v", err)
	}

	// 2. Blocked table
	_, err = handler.HandleQuery("SELECT * FROM passwords")
	if err == nil {
		t.Fatal("expected error for blocked table passwords, got nil")
	}
	if err.Error() != "policy violation: access to table passwords denied" {
		t.Errorf("unexpected error message: %v", err)
	}

	// 3. Blocked function
	_, err = handler.HandleQuery("SELECT sleep(5)")
	if err == nil {
		t.Fatal("expected error for blocked function sleep, got nil")
	}
	if err.Error() != "policy violation: function sleep is blocked" {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestMySQLAuthHandler_Authenticate(t *testing.T) {
	// Setup policy store
	discardLogger := slog.New(slog.NewTextHandler(io.Discard, nil))
	store, _ := policy.NewStore("", "", discardLogger)
	
	// Create test agent policy
	store.SetAgentPolicy("test-agent", policy.AgentConfig{
		Name:              "test-agent",
		Key:               "$2a$10$Qj2z5r/T5xX3mBveqXg.1.uG0o1o1o1o1o1o1o1o1o1o1o1o1o1o1", // mock bcrypt
		AllowedStatements: []string{"SELECT"},
	})

	proxyHandler := &AgentIAMMySQLHandler{}
	authHandler := &AgentIAMAuthHandler{
		store:        store,
		logger:       NewLogger(bytes.NewBuffer(nil)),
		insecureAuth: true,
		mysqlHandler: proxyHandler,
	}

	// Verify GetCredential for root fallback
	cred, found, err := authHandler.GetCredential("root")
	if err != nil {
		t.Fatalf("unexpected GetCredential error: %v", err)
	}
	if !found {
		t.Fatal("expected root user to be found")
	}
	if cred.AuthPluginName != "mysql_native_password" {
		t.Errorf("expected mysql_native_password, got %s", cred.AuthPluginName)
	}
}
