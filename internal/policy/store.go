package policy

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"agentiam/internal/ast"

	_ "github.com/mattn/go-sqlite3"
	"golang.org/x/crypto/bcrypt"
)

type Store struct {
	db        *sql.DB
	dummyHash []byte
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
			client_id TEXT PRIMARY KEY,
			api_key_hash TEXT,
			allowed_ops TEXT
		);
	`)
	if err != nil {
		return nil, err
	}

	dummyHash, _ := bcrypt.GenerateFromPassword([]byte("dummy"), bcrypt.DefaultCost)

	return &Store{
		db:        db,
		dummyHash: dummyHash,
	}, nil
}

// GetRulesForAgent looks up a client ID, verifies the bcrypt password, and returns AST rules.
func (s *Store) GetRulesForAgent(clientID string, suppliedPassword string) (ast.Rules, error) {
	var allowedOpsStr string
	var apiKeyHash string
	
	err := s.db.QueryRow("SELECT api_key_hash, allowed_ops FROM agents WHERE client_id = ?", clientID).Scan(&apiKeyHash, &allowedOpsStr)
	if err != nil {
		// DUMMY BCRYPT TO EQUALIZE TIMING (Mitigates User Enumeration)
		bcrypt.CompareHashAndPassword(s.dummyHash, []byte(suppliedPassword))
		return ast.Rules{}, fmt.Errorf("invalid client ID or password")
	}

	// ALWAYS call CompareHashAndPassword without any length pre-checks to avoid timing oracles
	if err := bcrypt.CompareHashAndPassword([]byte(apiKeyHash), []byte(suppliedPassword)); err != nil {
		return ast.Rules{}, fmt.Errorf("invalid client ID or password")
	}

	var allowedOps []string
	if err := json.Unmarshal([]byte(allowedOpsStr), &allowedOps); err != nil {
		return ast.Rules{}, fmt.Errorf("failed to parse policy: %w", err)
	}

	return ast.Rules{
		AllowedStatements:  allowedOps,
		EnforceSelectLimit: 100, // Hardcoded for MVP
	}, nil
}

// AddAgent is a helper to seed the database
func (s *Store) AddAgent(clientID, plaintextPassword string, allowedOps []string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(plaintextPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	
	b, _ := json.Marshal(allowedOps)
	_, err = s.db.Exec("INSERT OR REPLACE INTO agents (client_id, api_key_hash, allowed_ops) VALUES (?, ?, ?)", clientID, string(hash), string(b))
	return err
}
