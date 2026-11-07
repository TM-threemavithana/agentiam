package policy

import (
	"io"
	"log/slog"
	"testing"
	"time"
)

func TestStore_TimingOracleProtection(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	store, _ := NewStore("", "", logger)

	store.SetAgentPolicy("test-agent", AgentConfig{
		Name: "test-agent",
		Key:  "$2a$10$Qj2z5r/T5xX3mBveqXg.1.uG0o1o1o1o1o1o1o1o1o1o1o1o1o1o1", // mock bcrypt
	})

	// 1. Password authentication for non-existent client (timing attack target)
	start := time.Now()
	_, _, err := store.GetRulesForAgent("non-existent", "wrong-password", false)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if elapsed < 145*time.Millisecond {
		t.Errorf("timing oracle vulnerability: invalid user check was too fast (%v)", elapsed)
	}

	// 2. Password authentication for existing client with wrong password
	start = time.Now()
	_, _, err = store.GetRulesForAgent("test-agent", "wrong-password", false)
	elapsed = time.Since(start)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if elapsed < 145*time.Millisecond {
		t.Errorf("timing oracle vulnerability: invalid password check was too fast (%v)", elapsed)
	}

	// 3. mTLS verification (should be fast/immediate)
	start = time.Now()
	_, _, err = store.GetRulesForAgent("test-agent", "", true)
	elapsed = time.Since(start)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if elapsed > 10*time.Millisecond {
		t.Errorf("mTLS verification was too slow (%v)", elapsed)
	}
}

func TestStore_ViewsConversionAndLoading(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	store, _ := NewStore("", "", logger)

	agentCfg := AgentConfig{
		Name:              "data-analyst",
		Key:               "$2a$10$Qj2z5r/T5xX3mBveqXg.1.uG0o1o1o1o1o1o1o1o1o1o1o1o1o1o1",
		AllowedStatements: []string{"SELECT"},
		AllowedTables:     []string{"users"},
		Views: []ViewConfig{
			{
				Name:      "user_public_view",
				BaseTable: "users",
				ColumnMappings: map[string]string{
					"national_id": "ssn",
				},
				MaskedColumns: []string{"national_id"},
			},
		},
		MaskedColumns: map[string][]string{
			"users": {"ssn"},
		},
	}
	store.SetAgentPolicy("data-analyst", agentCfg)

	rules, _, err := store.GetRulesForAgent("data-analyst", "", true)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(rules.Views) != 1 {
		t.Fatalf("expected 1 view, got %d", len(rules.Views))
	}
	view := rules.Views[0]
	if view.Name != "user_public_view" {
		t.Errorf("expected view name 'user_public_view', got '%s'", view.Name)
	}
	if view.BaseTable != "users" {
		t.Errorf("expected base_table 'users', got '%s'", view.BaseTable)
	}
	if view.ColumnMappings["national_id"] != "ssn" {
		t.Errorf("expected column mapping national_id -> ssn, got '%s'", view.ColumnMappings["national_id"])
	}
	if len(view.MaskedColumns) != 1 || view.MaskedColumns[0] != "national_id" {
		t.Errorf("expected masked column national_id, got %v", view.MaskedColumns)
	}
}
