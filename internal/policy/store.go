package policy

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"log/slog"
	"os"
	"sync"
	"time"

	"agentiam/internal/ast"

	"github.com/fsnotify/fsnotify"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/yaml.v3"
)

type AgentConfig struct {
	Name              string   `yaml:"name"`
	Key               string   `yaml:"key"` // bcrypt hash
	AllowedStatements []string `yaml:"allowed_statements"`
	AllowedTables     []string `yaml:"allowed_tables"`
	SelectLimit       int      `yaml:"select_limit"`
	CreatedAt         string   `yaml:"created_at"`
}

type PoliciesYAML struct {
	Version string        `yaml:"version"`
	Agents  []AgentConfig `yaml:"agents"`
}

type agentState struct {
	config        AgentConfig
	version       int
	cachedPwdHash [32]byte
	hasCache      bool
}

type Store struct {
	mu        sync.RWMutex
	agents    map[string]agentState
	dummyHash []byte
	filePath  string
	logger    *slog.Logger
}

func NewStore(filePath string, logger *slog.Logger) (*Store, error) {
	dummyHash, _ := bcrypt.GenerateFromPassword([]byte("dummy"), bcrypt.DefaultCost)

	s := &Store{
		agents:    make(map[string]agentState),
		dummyHash: dummyHash,
		filePath:  filePath,
		logger:    logger,
	}

	if err := s.loadYAML(); err != nil {
		if os.IsNotExist(err) {
			s.logger.Warn("Policy file does not exist, starting with empty policies", "file", filePath)
		} else {
			return nil, fmt.Errorf("failed to load initial policies: %w", err)
		}
	}

	return s, nil
}

func (s *Store) loadYAML() error {
	b, err := os.ReadFile(s.filePath)
	if err != nil {
		return err
	}

	var py PoliciesYAML
	if err := yaml.Unmarshal(b, &py); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	newAgents := make(map[string]agentState)

	for _, a := range py.Agents {
		oldState, exists := s.agents[a.Name]

		version := 1
		hasCache := false
		var cachedPwdHash [32]byte

		if exists {
			version = oldState.version
			// If the hash changed, bump version and drop cache
			if oldState.config.Key != a.Key {
				version++
			} else {
				// Keep cache if key is exactly the same
				hasCache = oldState.hasCache
				cachedPwdHash = oldState.cachedPwdHash
			}
			// If policies changed, bump version (so tightened policies take effect via RWMutex immediately for new queries, but we also want version bump so poller triggers if needed? Wait, poller triggers revocation. We only bump version to trigger full session drop. The user requested: tightened policy takes effect next query, but key changes/deletions trigger immediate drop.)
			// For simplicity, we bump version if *anything* changes.
			// Wait, the user said: "tightening takes effect on next query, key deletion is immediate".
			// The poller checks `dbVersion != meta.authVersion`. If version bumps, session drops!
			// So we MUST NOT bump version for policy tightening, ONLY for key rotation.
			// The in-memory map update automatically applies tightening on next query!
		}

		newAgents[a.Name] = agentState{
			config:        a,
			version:       version,
			hasCache:      hasCache,
			cachedPwdHash: cachedPwdHash,
		}
	}

	s.agents = newAgents
	s.logger.Info("Loaded policies", "count", len(s.agents))
	return nil
}

func (s *Store) Watch(ctx context.Context) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		s.logger.Error("Failed to start fsnotify watcher", "error", err)
		return
	}
	defer watcher.Close()

	if err := watcher.Add(s.filePath); err != nil {
		s.logger.Error("Failed to watch policy file", "error", err, "file", s.filePath)
		// We continue, perhaps the file will be created later.
	}

	for {
		select {
		case <-ctx.Done():
			return
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}
			if event.Op&fsnotify.Write == fsnotify.Write || event.Op&fsnotify.Create == fsnotify.Create {
				time.Sleep(50 * time.Millisecond) // wait for write to complete
				if err := s.loadYAML(); err != nil {
					s.logger.Error("policy reload failed, keeping current policies", "error", err, "file", s.filePath)
				} else {
					s.logger.Info("Policies hot-reloaded successfully")
				}
			}
		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			s.logger.Error("fsnotify error", "error", err)
		}
	}
}

func (s *Store) GetRulesForAgent(clientID string, suppliedPassword string) (ast.Rules, int, error) {
	s.mu.RLock()
	state, exists := s.agents[clientID]
	s.mu.RUnlock()

	pwdHash := sha256.Sum256([]byte(suppliedPassword))

	if !exists {
		bcrypt.CompareHashAndPassword(s.dummyHash, []byte(suppliedPassword)) // mitigates timing oracle
		return ast.Rules{}, 0, fmt.Errorf("invalid client ID or password")
	}

	// Fast path: cached validation
	if state.hasCache && subtle.ConstantTimeCompare(state.cachedPwdHash[:], pwdHash[:]) == 1 {
		// Valid!
	} else {
		// Slow path: bcrypt
		if err := bcrypt.CompareHashAndPassword([]byte(state.config.Key), []byte(suppliedPassword)); err != nil {
			return ast.Rules{}, 0, fmt.Errorf("invalid client ID or password")
		}

		// Update cache
		s.mu.Lock()
		if st, ok := s.agents[clientID]; ok {
			st.hasCache = true
			st.cachedPwdHash = pwdHash
			s.agents[clientID] = st
		}
		s.mu.Unlock()
	}

	// Always get the LATEST rules from memory (even if auth was cached) to ensure mid-session policy tightening applies on the next query.
	s.mu.RLock()
	state = s.agents[clientID]
	s.mu.RUnlock()

	limit := state.config.SelectLimit
	if limit <= 0 {
		limit = 100 // default fallback
	}

	return ast.Rules{
		AllowedStatements:  state.config.AllowedStatements,
		EnforceSelectLimit: limit,
	}, state.version, nil
}

func (s *Store) GetAgentVersions() (map[string]int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	versions := make(map[string]int)
	for k, v := range s.agents {
		versions[k] = v.version
	}
	return versions, nil
}
