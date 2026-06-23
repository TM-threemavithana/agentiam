package proxy

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"sync"
	"time"

	"agentiam/internal/policy"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type sessionMeta struct {
	authVersion int
	cancel      context.CancelFunc
}

type Server struct {
	listenAddr  string
	upstreamDSN string
	store       *policy.Store
	tlsConfig   *tls.Config
	logger      *Logger

	maxConns int
	sem      chan struct{}
	wg       sync.WaitGroup

	mu             sync.RWMutex
	activeSessions map[string]map[*Session]sessionMeta
}

func NewServer(listenAddr, upstreamDSN string, store *policy.Store, tlsConfig *tls.Config, logger *Logger) *Server {
	maxConns := 10000
	return &Server{
		listenAddr:     listenAddr,
		upstreamDSN:    upstreamDSN,
		store:          store,
		tlsConfig:      tlsConfig,
		logger:         logger,
		maxConns:       maxConns,
		sem:            make(chan struct{}, maxConns),
		activeSessions: make(map[string]map[*Session]sessionMeta),
	}
}

// RegisterSession registers an active session for dynamic policy revocation.
func (s *Server) RegisterSession(clientID string, session *Session, authVersion int, cancel context.CancelFunc) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.activeSessions[clientID]; !exists {
		s.activeSessions[clientID] = make(map[*Session]sessionMeta)
	}
	s.activeSessions[clientID][session] = sessionMeta{
		authVersion: authVersion,
		cancel:      cancel,
	}
}

// UnregisterSession removes a session from the dynamic revocation registry.
func (s *Server) UnregisterSession(clientID string, session *Session) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if sessions, exists := s.activeSessions[clientID]; exists {
		delete(sessions, session)
		if len(sessions) == 0 {
			delete(s.activeSessions, clientID)
		}
	}
}

func (s *Server) pollPolicyUpdates() {
	interval := 5 * time.Second
	if v := os.Getenv("AGENTIAM_POLL_INTERVAL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			interval = d
		}
	}

	s.logger.Info("Starting policy revocation poller", "interval", interval.String())
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for range ticker.C {
		dbVersions, err := s.store.GetAgentVersions()
		if err != nil {
			s.logger.Error("Poller failed to fetch agent versions", "error", err)
			continue
		}

		s.mu.RLock()
		var toRevoke []context.CancelFunc
		for clientID, sessions := range s.activeSessions {
			dbVersion, exists := dbVersions[clientID]
			for _, meta := range sessions {
				if !exists || dbVersion != meta.authVersion {
					toRevoke = append(toRevoke, meta.cancel)
				}
			}
		}
		s.mu.RUnlock()

		for _, cancel := range toRevoke {
			cancel()
		}
	}
}

func (s *Server) Start() error {
	// Start metrics server explicitly on localhost
	go func() {
		mux := http.NewServeMux()
		mux.Handle("/metrics", promhttp.Handler())
		s.logger.Info("Starting Prometheus metrics endpoint", "addr", "127.0.0.1:9090")
		if err := http.ListenAndServe("127.0.0.1:9090", mux); err != nil {
			s.logger.Error("Metrics server failed", "error", err)
		}
	}()

	// Start policy revocation poller
	go s.pollPolicyUpdates()

	l, err := net.Listen("tcp", s.listenAddr)
	if err != nil {
		return fmt.Errorf("failed to bind to %s: %w", s.listenAddr, err)
	}
	defer l.Close()

	s.logger.Info("AgentIAM Proxy Listening", "addr", s.listenAddr)

	for {
		conn, err := l.Accept()
		if err != nil {
			s.logger.Error("Failed to accept connection", "error", err)
			continue
		}

		select {
		case s.sem <- struct{}{}:
			s.wg.Add(1)
			go s.handleConnection(conn)
		default:
			s.logger.Error("Max connections reached, rejecting", "addr", conn.RemoteAddr())
			conn.Close()
		}
	}
}

func (s *Server) handleConnection(clientConn net.Conn) {
	defer s.wg.Done()
	defer func() { <-s.sem }()

	session := NewSession(clientConn, s.upstreamDSN, s.store, s.tlsConfig, s.logger, s)
	defer session.Close()

	if err := session.Run(); err != nil {
		s.logger.Error("Session error", "addr", clientConn.RemoteAddr(), "error", err)
	}
}
