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

	"agentiam/internal/cache"
	"agentiam/internal/policy"

	"github.com/jackc/pgproto3/v2"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type sessionMeta struct {
	authVersion int
	cancel      context.CancelFunc
}

// Server represents the core TCP multiplexer and protocol router.
// It listens for incoming connections, sniffs their protocol, and routes them to the appropriate ProtocolHandler.
type Server struct {
	listenAddr  string
	upstreamDSN string
	store       *policy.Store
	tlsConfig   *tls.Config
	logger      *Logger

	maxConns int
	pool     *Pool
	sem      chan struct{}
	wg       sync.WaitGroup

	mu             sync.RWMutex
	astCache       cache.ASTCache
	handlers       map[ProtocolType]ProtocolHandler
	activeSessions map[string]map[*Session]sessionMeta
	sessionByPID   map[uint32]*Session
	nextPID        uint32
}

// NewServer initializes a new Server instance.
// It requires a pre-configured policy.Store, logger, AST cache, and a map of ProtocolHandlers.
func NewServer(listenAddr, upstreamDSN string, store *policy.Store, tlsConfig *tls.Config, logger *Logger, astCache cache.ASTCache, handlers map[ProtocolType]ProtocolHandler) *Server {
	maxConns := 10000
	return &Server{
		listenAddr:     listenAddr,
		upstreamDSN:    upstreamDSN,
		store:          store,
		tlsConfig:      tlsConfig,
		logger:         logger,
		maxConns:       maxConns,
		pool:           NewPool(upstreamDSN, 50, logger),
		astCache:       astCache,
		handlers:       handlers,
		sem:            make(chan struct{}, maxConns),
		activeSessions: make(map[string]map[*Session]sessionMeta),
		sessionByPID:   make(map[uint32]*Session),
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

// InitPool initializes the upstream connection pool.
func (s *Server) InitPool(ctx context.Context) error {
	return s.pool.Init(ctx)
}

// SetHandler resolves the circular dependency when setting up the protocol handler.
func (s *Server) SetHandler(ptype ProtocolType, handler ProtocolHandler) {
	if s.handlers == nil {
		s.handlers = make(map[ProtocolType]ProtocolHandler)
	}
	s.handlers[ptype] = handler
}

// Start begins listening on the configured TCP address.
// It also spins up background goroutines for Prometheus metrics and policy revocation polling.
func (s *Server) Start() error {
	// Start metrics server explicitly on localhost
	go func() {
		http.Handle("/metrics", promhttp.Handler())
		s.logger.Info("Starting Prometheus metrics endpoint", "addr", ":9090")
		if err := http.ListenAndServe(":9090", nil); err != nil {
			s.logger.Error("Metrics server failed", "error", err)
		}
	}()

	// Start policy revocation poller
	go s.pollPolicyUpdates()

	if err := s.InitPool(context.Background()); err != nil {
		s.logger.Error("failed to init upstream pool", "error", err)
	}

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
	defer clientConn.Close()

	ptype, sniffedConn, err := SniffProtocol(clientConn, 100*time.Millisecond)
	if err != nil {
		s.logger.Error("Failed to sniff protocol", "addr", clientConn.RemoteAddr(), "error", err)
		return
	}

	s.logger.Info("Protocol detected", "protocol", string(ptype), "addr", clientConn.RemoteAddr())

	handler, exists := s.handlers[ptype]
	if !exists {
		s.logger.Error("No protocol handler registered for detected protocol", "protocol", string(ptype))
		return
	}

	if err := handler.HandleSession(context.Background(), sniffedConn); err != nil {
		s.logger.Error("Session error", "addr", clientConn.RemoteAddr(), "protocol", string(ptype), "error", err)
	}
}

// AllocateVirtualPID assigns a unique virtual process ID to an active session.
// This allows the proxy to intercept and route out-of-band CancelRequests (like pg_cancel_backend) correctly.
func (s *Server) AllocateVirtualPID(session *Session) (uint32, uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.nextPID++
	pid := s.nextPID
	secret := uint32(123456) // Simple for now
	if s.sessionByPID == nil {
		s.sessionByPID = make(map[uint32]*Session)
	}
	s.sessionByPID[pid] = session
	return pid, secret
}

// DeallocateVirtualPID removes a session's virtual process ID from the registry.
func (s *Server) DeallocateVirtualPID(pid uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sessionByPID != nil {
		delete(s.sessionByPID, pid)
	}
}

func (s *Server) handleCancelRequest(conn net.Conn, msg *pgproto3.CancelRequest) {
	s.mu.RLock()
	session, ok := s.sessionByPID[msg.ProcessID]
	s.mu.RUnlock()

	if ok {
		s.logger.Info("Routing CancelRequest", "virtual_pid", msg.ProcessID)
		session.CancelQuery()
	} else {
		s.logger.Error("CancelRequest for unknown Virtual PID", "pid", msg.ProcessID)
	}
	conn.Close()
}
