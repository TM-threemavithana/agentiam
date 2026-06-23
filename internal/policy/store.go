package policy

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"

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
			allowed_ops TEXT,
			version INTEGER DEFAULT 1
		);
	`)
	if err != nil {
		return nil, err
	}

	// TODO(Phase 6): Replace with golang-migrate integration
	// This error-ignore block ensures backwards compatibility for existing deployments
	_, err = db.Exec(`ALTER TABLE agents ADD COLUMN version INTEGER DEFAULT 1;`)
	if err == nil {
		slog.Info("schema: ensured version column exists", "table", "agents")
	}

	dummyHash, _ := bcrypt.GenerateFromPassword([]byte("dummy"), bcrypt.DefaultCost)

	return &Store{
		db:        db,
		dummyHash: dummyHash,
	}, nil
}

// GetRulesForAgent looks up a client ID, verifies the bcrypt password, and returns AST rules and the version.
func (s *Store) GetRulesForAgent(clientID string, suppliedPassword string) (ast.Rules, int, error) {
	var allowedOpsStr string
	var apiKeyHash string
	var version int
	
	err := s.db.QueryRow("SELECT api_key_hash, allowed_ops, version FROM agents WHERE client_id = ?", clientID).Scan(&apiKeyHash, &allowedOpsStr, &version)
	if err != nil {
		// DUMMY BCRYPT TO EQUALIZE TIMING (Mitigates User Enumeration)
		bcrypt.CompareHashAndPassword(s.dummyHash, []byte(suppliedPassword))
		return ast.Rules{}, 0, fmt.Errorf("invalid client ID or password")
	}

	// ALWAYS call CompareHashAndPassword without any length pre-checks to avoid timing oracles
	if err := bcrypt.CompareHashAndPassword([]byte(apiKeyHash), []byte(suppliedPassword)); err != nil {
		return ast.Rules{}, 0, fmt.Errorf("invalid client ID or password")
	}

	var allowedOps []string
	if err := json.Unmarshal([]byte(allowedOpsStr), &allowedOps); err != nil {
		return ast.Rules{}, 0, fmt.Errorf("failed to parse policy: %w", err)
	}

	return ast.Rules{
		AllowedStatements:  allowedOps,
		EnforceSelectLimit: 100, // Hardcoded for MVP
	}, version, nil
}

// GetAgentVersions fetches the current policy version for all registered agents.
func (s *Store) GetAgentVersions() (map[string]int, error) {
	rows, err := s.db.Query("SELECT client_id, version FROM agents")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	versions := make(map[string]int)
	for rows.Next() {
		var clientID string
		var version int
		if err := rows.Scan(&clientID, &version); err != nil {
			return nil, err
		}
		versions[clientID] = version
	}
	return versions, nil
}

// AddAgent is a helper to seed the database
func (s *Store) AddAgent(clientID, plaintextPassword string, allowedOps []string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(plaintextPassword), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	
	b, _ := json.Marshal(allowedOps)
	_, err = s.db.Exec(`
		INSERT INTO agents (client_id, api_key_hash, allowed_ops, version) 
		VALUES (?, ?, ?, 1)
		ON CONFLICT(client_id) DO UPDATE SET 
			api_key_hash = excluded.api_key_hash, 
			allowed_ops = excluded.allowed_ops,
			version = agents.version + 1
	`, clientID, string(hash), string(b))
	return err
}

// RemoveAgent deletes an agent's policy from the store, revoking their access immediately.
func (s *Store) RemoveAgent(clientID string) error {
	_, err := s.db.Exec("DELETE FROM agents WHERE client_id = ?", clientID)
	return err
}
