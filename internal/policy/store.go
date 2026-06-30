package policy

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/tm-threemavithana/agentiam/internal/ast"

	"github.com/fsnotify/fsnotify"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/time/rate"
	"gopkg.in/yaml.v3"
)

type AgentConfig struct {
	Name               string   `yaml:"name" json:"name"`
	Key                string   `yaml:"key" json:"key"` // bcrypt hash or SCRAM verifier
	AllowedStatements  []string `yaml:"allowed_statements" json:"allowed_statements"`
	AllowedTables      []string `yaml:"allowed_tables" json:"allowed_tables"`
	BlockedFunctions   []string `yaml:"blocked_functions" json:"blocked_functions"`
	SelectLimit        int      `yaml:"select_limit" json:"select_limit"`
	MaxExecutionTimeMs int      `yaml:"max_execution_time_ms" json:"max_execution_time_ms"`
	RateLimitRPM       int      `yaml:"rate_limit_rpm" json:"rate_limit_rpm"`
	RateLimitBurst     int      `yaml:"rate_limit_burst" json:"rate_limit_burst"`
	PoolMode           string   `yaml:"pool_mode" json:"pool_mode"`
	Dialect            string   `yaml:"dialect" json:"dialect"`
	CreatedAt          string   `yaml:"created_at" json:"created_at"`
}

type PoliciesYAML struct {
	Version string        `yaml:"version" json:"version"`
	Agents  []AgentConfig `yaml:"agents" json:"agents"`
}

type agentState struct {
	config        AgentConfig
	version       int
	cachedPwdHash [32]byte
	hasCache      bool
	limiter       *rate.Limiter
}

type Store struct {
	mu         sync.RWMutex
	agents     map[string]agentState
	dummyHash  []byte
	filePath   string
	apiUrl     string
	logger     *slog.Logger
	httpClient *http.Client
}

func NewStore(filePath string, apiUrl string, logger *slog.Logger) (*Store, error) {
	dummyHash, _ := bcrypt.GenerateFromPassword([]byte("dummy"), bcrypt.DefaultCost)

	s := &Store{
		agents:     make(map[string]agentState),
		dummyHash:  dummyHash,
		filePath:   filePath,
		apiUrl:     apiUrl,
		logger:     logger,
		httpClient: &http.Client{Timeout: 5 * time.Second},
	}

	if err := s.loadPolicies(); err != nil {
		if os.IsNotExist(err) && apiUrl == "" {
			s.logger.Warn("Policy file does not exist, starting with empty policies", "file", filePath)
		} else {
			return nil, fmt.Errorf("failed to load initial policies: %w", err)
		}
	}

	return s, nil
}

func (s *Store) loadPolicies() error {
	var py PoliciesYAML

	// 2. Try HTTP API if Redis didn't yield agents
	if len(py.Agents) == 0 && s.apiUrl != "" {
		req, err := http.NewRequestWithContext(context.Background(), "GET", s.apiUrl, nil)
		if err != nil {
			return fmt.Errorf("failed to create request: %w", err)
		}

		resp, err := s.httpClient.Do(req)
		if err == nil {
			defer resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				body, _ := io.ReadAll(resp.Body)
				if err := json.Unmarshal(body, &py); err != nil {
					// fallback to yaml
					if err := yaml.Unmarshal(body, &py); err != nil {
						s.logger.Error("Failed to decode remote policies", "error", err)
					}
				}
			} else {
				s.logger.Error("Remote IAM returned non-200", "status", resp.StatusCode)
			}
		} else {
			s.logger.Error("Failed to fetch from IAM API", "error", err)
		}
	}

	// 3. Fallback to local file
	if len(py.Agents) == 0 && s.filePath != "" {
		b, err := os.ReadFile(s.filePath)
		if err != nil {
			return err
		}
		if err := yaml.Unmarshal(b, &py); err != nil {
			return err
		}
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
			if oldState.config.Key != a.Key {
				version++
			} else {
				hasCache = oldState.hasCache
				cachedPwdHash = oldState.cachedPwdHash
			}
		}

		var limiter *rate.Limiter
		if exists && oldState.config.RateLimitRPM == a.RateLimitRPM && oldState.config.RateLimitBurst == a.RateLimitBurst {
			limiter = oldState.limiter
		} else if a.RateLimitRPM > 0 {
			burst := a.RateLimitBurst
			if burst <= 0 {
				burst = 1 // Default burst
			}
			limiter = rate.NewLimiter(rate.Limit(float64(a.RateLimitRPM)/60.0), burst)
		}

		newAgents[a.Name] = agentState{
			config:        a,
			version:       version,
			hasCache:      hasCache,
			cachedPwdHash: cachedPwdHash,
			limiter:       limiter,
		}
	}

	s.agents = newAgents
	s.logger.Info("Loaded policies", "count", len(s.agents), "source", s.apiUrl)
	return nil
}

func (s *Store) Watch(ctx context.Context) {

	// Legacy Watchers
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		s.logger.Error("Failed to start fsnotify watcher", "error", err)
		return
	}
	defer watcher.Close()

	if s.filePath != "" {
		if err := watcher.Add(s.filePath); err != nil {
			s.logger.Error("Failed to watch policy file", "error", err, "file", s.filePath)
		}
	}

	pollInterval := 10 * time.Second
	if s.apiUrl == "" {
		pollInterval = 24 * time.Hour // effectively disabled if no API
	}
	ticker := time.NewTicker(pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if s.apiUrl != "" {
				if err := s.loadPolicies(); err != nil {
					s.logger.Error("Remote policy reload failed", "error", err)
				}
			}
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}
			if event.Op&fsnotify.Write == fsnotify.Write || event.Op&fsnotify.Create == fsnotify.Create {
				time.Sleep(50 * time.Millisecond) // wait for write to complete
				if err := s.loadPolicies(); err != nil {
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

	// Fast path: Auth verified securely via SCRAM or mTLS in session layer
	if suppliedPassword == "SCRAM_VERIFIED" || suppliedPassword == "mTLS_VERIFIED" {
		// Valid!
	} else if state.hasCache && subtle.ConstantTimeCompare(state.cachedPwdHash[:], pwdHash[:]) == 1 {
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

	timeoutMs := state.config.MaxExecutionTimeMs
	if timeoutMs <= 0 {
		timeoutMs = 5000 // default 5 seconds
	}

	// Return fully assembled AST rules
	return ast.Rules{
		AllowedStatements:  state.config.AllowedStatements,
		AllowedTables:      state.config.AllowedTables,
		BlockedFunctions:   state.config.BlockedFunctions,
		EnforceSelectLimit: limit,
		MaxExecutionTimeMs: timeoutMs,
		PoolMode:           state.config.PoolMode,
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

func (s *Store) SetAgentPolicy(clientID string, config AgentConfig) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.agents[clientID] = agentState{
		config:  config,
		version: 1,
	}
}

// GetAgentKey returns the stored authentication key material (e.g. SCRAM verifier or bcrypt hash) for the given clientID.
// This is used for SCRAM-SHA-256 authentication where the proxy needs the key material to verify the client.
func (s *Store) GetAgentKey(clientID string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if state, exists := s.agents[clientID]; exists {
		return state.config.Key, nil
	}
	return "", fmt.Errorf("invalid client ID")
}

// CheckRateLimit deducts one token from the agent's bucket. Returns an error if the limit is exceeded.
func (s *Store) CheckRateLimit(clientID string) error {
	s.mu.RLock()
	state, exists := s.agents[clientID]
	s.mu.RUnlock()

	if !exists {
		return fmt.Errorf("invalid client ID")
	}

	if state.limiter != nil {
		if !state.limiter.Allow() {
			return fmt.Errorf("rate limit exceeded for agent %s", clientID)
		}
	}
	return nil
}
