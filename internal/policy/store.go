package policy

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"agentiam/internal/ast"

	_ "github.com/mattn/go-sqlite3"
)

type Store struct {
	db *sql.DB
}

type AgentPolicy struct {
	APIKey     string
	Label      string
	AllowedOps []string
}

func NewStore(dbPath string) (*Store, error) {
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		return nil, err
	}

	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS agents (
			api_key TEXT PRIMARY KEY,
			label TEXT,
			allowed_ops TEXT
		);
	`)
	if err != nil {
		return nil, err
	}

	return &Store{db: db}, nil
}

// GetRulesForAgent looks up an API key and returns the AST rules.
func (s *Store) GetRulesForAgent(apiKey string) (ast.Rules, error) {
	var allowedOpsStr string
	err := s.db.QueryRow("SELECT allowed_ops FROM agents WHERE api_key = ?", apiKey).Scan(&allowedOpsStr)
	if err != nil {
		if err == sql.ErrNoRows {
			return ast.Rules{}, fmt.Errorf("invalid agent API key")
		}
		return ast.Rules{}, err
	}

	var allowedOps []string
	if err := json.Unmarshal([]byte(allowedOpsStr), &allowedOps); err != nil {
		return ast.Rules{}, fmt.Errorf("failed to parse policy: %w", err)
	}

	// Calculate blocked statements based on allowed. For MVP, we maintain a master list of dangerous ops.
	dangerousOps := []string{"INSERT", "UPDATE", "DELETE", "DROP", "TRUNCATE", "ALTER"}
	var blocked []string
	
	for _, op := range dangerousOps {
		allowed := false
		for _, a := range allowedOps {
			if a == op {
				allowed = true
				break
			}
		}
		if !allowed {
			blocked = append(blocked, op)
		}
	}

	return ast.Rules{
		BlockedStatements:  blocked,
		EnforceSelectLimit: 100, // Hardcoded for MVP
	}, nil
}

// AddAgent is a helper to seed the database
func (s *Store) AddAgent(apiKey, label string, allowedOps []string) error {
	b, _ := json.Marshal(allowedOps)
	_, err := s.db.Exec("INSERT OR REPLACE INTO agents (api_key, label, allowed_ops) VALUES (?, ?, ?)", apiKey, label, string(b))
	return err
}
