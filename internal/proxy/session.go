package proxy

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tm-threemavithana/agentiam/internal/ast"
	"github.com/tm-threemavithana/agentiam/internal/policy"

	"github.com/jackc/pgx/v5/pgproto3"
)

// DefaultMaxProtocolBodyLen defines the maximum permitted message body size (64MB)
// to defend against memory exhaustion attacks from corrupt or malicious peers.
const DefaultMaxProtocolBodyLen = 64 * 1024 * 1024

var (
	setCmdRegex = regexp.MustCompile(`(?i)^\s*SET\s+([a-zA-Z0-9_]+)\s*(?:TO|=)\s*(.+)$`)

	testPanicMu                sync.RWMutex
	testPanicHook              func()
	testPanicOnUpstreamReceive func()
)

func SetTestPanicHook(fn func()) {
	testPanicMu.Lock()
	defer testPanicMu.Unlock()
	testPanicHook = fn
}

func getTestPanicHook() func() {
	testPanicMu.RLock()
	defer testPanicMu.RUnlock()
	return testPanicHook
}

func SetTestPanicOnUpstreamReceive(fn func()) {
	testPanicMu.Lock()
	defer testPanicMu.Unlock()
	testPanicOnUpstreamReceive = fn
}

func getTestPanicOnUpstreamReceive() func() {
	testPanicMu.RLock()
	defer testPanicMu.RUnlock()
	return testPanicOnUpstreamReceive
}

type PreparedStatement struct {
	SQL           string
	ParameterOIDs []uint32
	LimitParams   []int
}

type PostgresProtocolHandler struct {
	upstreamDSN  string
	store        *policy.Store
	tlsConfig    *tls.Config
	logger       *Logger
	server       *Server
	insecureAuth bool
}

func NewPostgresProtocolHandler(upstreamDSN string, store *policy.Store, tlsConfig *tls.Config, logger *Logger, server *Server, insecureAuth bool) *PostgresProtocolHandler {
	return &PostgresProtocolHandler{
		upstreamDSN:  upstreamDSN,
		store:        store,
		tlsConfig:    tlsConfig,
		logger:       logger,
		server:       server,
		insecureAuth: insecureAuth,
	}
}

func (h *PostgresProtocolHandler) HandleSession(ctx context.Context, clientConn net.Conn) error {
	clientBackend := pgproto3.NewBackend(clientConn, clientConn)
	clientBackend.SetMaxBodyLen(DefaultMaxProtocolBodyLen)
	clientConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	startupMsg, err := clientBackend.ReceiveStartupMessage()
	clientConn.SetReadDeadline(time.Time{})

	if err != nil {
		var maxLenErr *pgproto3.ExceededMaxBodyLenErr
		if errors.As(err, &maxLenErr) {
			h.logger.Error("Startup message exceeded maximum allowed protocol body length",
				"max", maxLenErr.MaxExpectedBodyLen,
				"actual", maxLenErr.ActualBodyLen,
			)
		} else {
			h.logger.Error("Failed to read startup message", "error", err)
		}
		return err
	}

	if cancelMsg, ok := startupMsg.(*pgproto3.CancelRequest); ok {
		h.server.handleCancelRequest(clientConn, cancelMsg)
		return nil
	}

	session := NewSession(clientConn, h.upstreamDSN, h.store, h.tlsConfig, h.logger, h.server, h.insecureAuth)
	session.clientBackend = clientBackend
	session.startupMsg = startupMsg
	defer session.Close()

	return session.Run()
}

type Session struct {
	clientConn  net.Conn
	uconn       *UpstreamConn
	upstreamDSN string
	uconnMu     sync.Mutex

	store        *policy.Store
	logger       *Logger
	server       *Server
	insecureAuth bool

	clientBackend *pgproto3.Backend

	errorDiscard atomic.Bool
	invalidated  atomic.Bool
	authVersion  int
	rules        ast.Rules
	tlsConfig    *tls.Config
	closeOnce    sync.Once
	cancel       context.CancelFunc

	startupMsg pgproto3.FrontendMessage
	virtualPID uint32
	virtualSec uint32

	lastClientActivity atomic.Int64
	queryRunning       atomic.Bool
	queryStartTime     atomic.Int64

	preparedStatements map[string]PreparedStatement
	sessionVars        map[string]string
	clientID           string
}

func (s *Session) isPolicyRevoked() bool {
	if s.invalidated.Load() {
		return true
	}
	if s.store != nil && s.clientID != "" {
		currentVer := s.store.GetAgentVersion(s.clientID)
		if currentVer != -1 && currentVer != s.authVersion {
			s.invalidated.Store(true)
			return true
		}
	}
	return false
}

func NewSession(clientConn net.Conn, upstreamDSN string, store *policy.Store, tlsConfig *tls.Config, logger *Logger, server *Server, insecureAuth bool) *Session {
	be := pgproto3.NewBackend(clientConn, clientConn)
	be.SetMaxBodyLen(DefaultMaxProtocolBodyLen)
	return &Session{
		clientConn:         clientConn,
		upstreamDSN:        upstreamDSN,
		store:              store,
		tlsConfig:          tlsConfig,
		logger:             logger,
		server:             server,
		insecureAuth:       insecureAuth,
		clientBackend:      be,
		preparedStatements: make(map[string]PreparedStatement),
		sessionVars:        make(map[string]string),
	}
}

func (s *Session) CancelQuery() {
	s.uconnMu.Lock()
	u := s.uconn
	s.uconn = nil
	s.uconnMu.Unlock()
	if u != nil {
		u.Broken.Store(true)
		s.server.pool.Release(u)
	}
}

func (s *Session) Run() (err error) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s.cancel = cancel

	defer func() {
		if r := recover(); r != nil {
			s.logger.Error("Panic recovered in session lifecycle",
				"event", "session_worker_panic",
				"client_id", s.clientID,
				"addr", s.clientConn.RemoteAddr(),
				"panic_type", panicType(r),
				"panic_summary", safePanicSummary(r),
				"stack", sanitizedStackTrace(),
			)
			s.recoverBrokenTransaction()
			s.Close()
			err = fmt.Errorf("session terminated due to unexpected panic (%s)", panicType(r))
		}
	}()

	s.lastClientActivity.Store(time.Now().UnixNano())

	go func() {
		defer func() {
			if r := recover(); r != nil {
				s.logger.Error("Panic recovered in idle watchdog",
					"event", "idle_watchdog_panic",
					"client_id", s.clientID,
					"panic_type", panicType(r),
					"panic_summary", safePanicSummary(r),
				)
			}
		}()
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if !s.queryRunning.Load() {
					last := time.Unix(0, s.lastClientActivity.Load())
					if time.Since(last) > 5*time.Minute {
						s.logger.Info("Closing idle connection", "client", s.clientConn.RemoteAddr())
						s.Close()
						return
					}
				}
			}
		}
	}()

	go func() {
		<-ctx.Done()
		s.Close()
	}()

	var clientID string

	for i := 0; i < 3; i++ {
		if s.startupMsg == nil {
			s.clientConn.SetReadDeadline(time.Now().Add(5 * time.Minute))
			s.startupMsg, err = s.clientBackend.ReceiveStartupMessage()
			s.clientConn.SetReadDeadline(time.Time{})
			if err != nil {
				return err
			}
		}

		switch msg := s.startupMsg.(type) {
		case *pgproto3.StartupMessage:
			_, isTLS := s.clientConn.(*tls.Conn)
			if s.tlsConfig != nil && !isTLS {
				s.clientBackend.Send(&pgproto3.ErrorResponse{Severity: "FATAL", Message: "SSL connection is required"})
				_ = s.clientBackend.Flush()
				return fmt.Errorf("client attempted plaintext connection when TLS is enforced")
			}
			clientID = msg.Parameters["user"]

		case *pgproto3.SSLRequest:
			if s.tlsConfig == nil {
				s.clientConn.Write([]byte("N"))
				s.startupMsg = nil
				continue
			}

			if _, err := s.clientConn.Write([]byte("S")); err != nil {
				return err
			}

			tlsConn := tls.Server(s.clientConn, s.tlsConfig)
			if err := tlsConn.Handshake(); err != nil {
				return fmt.Errorf("TLS handshake failed: %w", err)
			}

			s.clientConn = tlsConn
			s.clientBackend = pgproto3.NewBackend(s.clientConn, s.clientConn)
			s.clientBackend.SetMaxBodyLen(DefaultMaxProtocolBodyLen)
			s.startupMsg = nil
			continue

		default:
			return fmt.Errorf("unexpected startup message: %T", s.startupMsg)
		}

		if clientID != "" {
			break
		}
	}

	if clientID == "" {
		return fmt.Errorf("startup sequence failed: maximum iterations exceeded")
	}

	agentKey, err := s.store.GetAgentKey(clientID)
	if err != nil {
		s.logger.Error("Auth failed: invalid client ID", "client", clientID, "error", err)
		s.clientBackend.Send(&pgproto3.ErrorResponse{Severity: "FATAL", Message: "Invalid Agent Credentials"})
		_ = s.clientBackend.Flush()
		return fmt.Errorf("invalid client ID")
	}

	var suppliedPassword string
	var mtlsVerified bool

	if tlsConn, ok := s.clientConn.(*tls.Conn); ok {
		state := tlsConn.ConnectionState()
		if len(state.PeerCertificates) > 0 {
			cert := state.PeerCertificates[0]
			if cert.Subject.CommonName == clientID {
				mtlsVerified = true
			} else {
				s.logger.Error("mTLS CN mismatch", "cn", cert.Subject.CommonName, "clientID", clientID)
			}
		}
	}

	if !mtlsVerified && !s.insecureAuth {
		s.logger.Error("Client attempted cleartext authentication without --insecure-cleartext-auth flag")
		s.clientBackend.Send(&pgproto3.ErrorResponse{Severity: "FATAL", Message: "mTLS is required. Cleartext auth is disabled."})
		_ = s.clientBackend.Flush()
		return fmt.Errorf("insecure auth rejected")
	}

	if !mtlsVerified {
		if strings.HasPrefix(agentKey, "SCRAM-SHA-256$") {
			s.clientBackend.Send(&pgproto3.AuthenticationSASL{AuthMechanisms: []string{"SCRAM-SHA-256"}})
			s.clientBackend.SetAuthType(pgproto3.AuthTypeSASL)
			if err := s.clientBackend.Flush(); err != nil {
				return fmt.Errorf("error flushing SASL mechanisms: %w", err)
			}

			s.clientConn.SetReadDeadline(time.Now().Add(5 * time.Second))
			authMsg, err := s.clientBackend.Receive()
			s.clientConn.SetReadDeadline(time.Time{})
			if err != nil {
				return fmt.Errorf("error receiving SASL Initial Response: %w", err)
			}

			saslInitial, ok := authMsg.(*pgproto3.SASLInitialResponse)
			if !ok || saslInitial.AuthMechanism != "SCRAM-SHA-256" {
				return fmt.Errorf("expected SASLInitialResponse for SCRAM")
			}

			clientFirstBare := string(saslInitial.Data)
			clientFirstBare = strings.TrimPrefix(clientFirstBare, "n,,")

			var clientNonce string
			for _, part := range strings.Split(clientFirstBare, ",") {
				if strings.HasPrefix(part, "r=") {
					clientNonce = part[2:]
					break
				}
			}
			if clientNonce == "" {
				return fmt.Errorf("missing client nonce in SCRAM authentication")
			}

			iters, salt, storedKey, serverKey, err := ParseSCRAMSecret(agentKey)
			if err != nil {
				return err
			}

			nonceBytes := make([]byte, 18)
			rand.Read(nonceBytes)
			serverNonce := clientNonce + base64.StdEncoding.EncodeToString(nonceBytes)

			saltStr := base64.StdEncoding.EncodeToString(salt)
			serverFirst := fmt.Sprintf("r=%s,s=%s,i=%d", serverNonce, saltStr, iters)
			s.clientBackend.Send(&pgproto3.AuthenticationSASLContinue{Data: []byte(serverFirst)})
			if err := s.clientBackend.Flush(); err != nil {
				return fmt.Errorf("error flushing SASL continue: %w", err)
			}

			s.clientConn.SetReadDeadline(time.Now().Add(5 * time.Second))
			authMsg, err = s.clientBackend.Receive()
			s.clientConn.SetReadDeadline(time.Time{})
			if err != nil {
				return err
			}

			saslResp, ok := authMsg.(*pgproto3.SASLResponse)
			if !ok {
				return fmt.Errorf("expected SASLResponse")
			}

			clientFinal := string(saslResp.Data)
			parts := strings.Split(clientFinal, ",p=")
			if len(parts) != 2 {
				return fmt.Errorf("invalid SASLResponse")
			}
			clientFinalWithoutProof := parts[0]
			clientProofStr := parts[1]

			serverSignature, err := VerifySCRAM(clientFirstBare, serverFirst, clientFinalWithoutProof, clientProofStr, storedKey, serverKey)
			if err != nil {
				s.clientBackend.Send(&pgproto3.ErrorResponse{Severity: "FATAL", Message: "Password authentication failed"})
				_ = s.clientBackend.Flush()
				return fmt.Errorf("SCRAM auth failed")
			}

			s.clientBackend.Send(&pgproto3.AuthenticationSASLFinal{Data: []byte("v=" + serverSignature)})
			if err := s.clientBackend.Flush(); err != nil {
				return fmt.Errorf("error flushing SASL final: %w", err)
			}
			mtlsVerified = true // Re-use mtlsVerified to signify pre-verified auth (SCRAM)
		} else {
			s.clientBackend.Send(&pgproto3.AuthenticationCleartextPassword{})
			s.clientBackend.SetAuthType(pgproto3.AuthTypeCleartextPassword)
			if err := s.clientBackend.Flush(); err != nil {
				return fmt.Errorf("error flushing cleartext password request: %w", err)
			}

			s.clientConn.SetReadDeadline(time.Now().Add(5 * time.Second))
			authMsg, err := s.clientBackend.Receive()
			s.clientConn.SetReadDeadline(time.Time{})
			if err != nil {
				return fmt.Errorf("error receiving password: %w", err)
			}

			pwdMsg, ok := authMsg.(*pgproto3.PasswordMessage)
			if !ok {
				return fmt.Errorf("expected password message")
			}
			suppliedPassword = pwdMsg.Password
		}
	}

	rules, authVersion, err := s.store.GetRulesForAgent(clientID, suppliedPassword, mtlsVerified)
	if err != nil {
		s.clientBackend.Send(&pgproto3.ErrorResponse{Severity: "FATAL", Message: "Password authentication failed"})
		_ = s.clientBackend.Flush()
		return fmt.Errorf("password auth failed")
	}
	if s.server != nil && s.server.verifier != nil {
		rules = s.server.verifier.EnrichRulesWithVerifiedViews(rules)
	}
	s.rules = rules
	s.authVersion = authVersion
	s.clientID = clientID

	s.clientBackend.Send(&pgproto3.AuthenticationOk{})

	s.virtualPID, s.virtualSec = s.server.AllocateVirtualPID(s)
	defer s.server.DeallocateVirtualPID(s.virtualPID)

	s.server.RegisterSession(clientID, s, authVersion, cancel)
	defer s.server.UnregisterSession(clientID, s)

	s.clientBackend.Send(&pgproto3.ParameterStatus{Name: "server_version", Value: "15.0"})
	s.clientBackend.Send(&pgproto3.ParameterStatus{Name: "client_encoding", Value: "UTF8"})
	s.clientBackend.Send(&pgproto3.ParameterStatus{Name: "standard_conforming_strings", Value: "on"})

	secBytes := make([]byte, 4)
	binary.BigEndian.PutUint32(secBytes, s.virtualSec)
	s.clientBackend.Send(&pgproto3.BackendKeyData{ProcessID: s.virtualPID, SecretKey: secBytes})
	s.clientBackend.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
	if err := s.clientBackend.Flush(); err != nil {
		return fmt.Errorf("failed to flush startup responses: %w", err)
	}

	return s.proxyLoop(ctx, cancel, clientID)
}

func (s *Session) getOrAcquireUpstream(ctx context.Context, clientWriteCh chan pgproto3.BackendMessage) (*UpstreamConn, error) {
	s.uconnMu.Lock()
	defer s.uconnMu.Unlock()
	if s.uconn != nil {
		return s.uconn, nil
	}
	u, err := s.server.pool.Acquire(ctx)
	if err != nil {
		return nil, err
	}

	// Inject statement timeout
	timeout := s.rules.MaxExecutionTimeMs
	if timeout <= 0 {
		timeout = 5000 // default fallback
	}

	stateQueries := make([]string, 0, len(s.sessionVars)+1)
	stateQueries = append(stateQueries, fmt.Sprintf("SET statement_timeout = '%dms'", timeout))
	for k, v := range s.sessionVars {
		// Prevent attackers from overriding security timeouts
		if strings.EqualFold(k, "statement_timeout") {
			continue
		}
		stateQueries = append(stateQueries, fmt.Sprintf("SET %s = %s", k, v))
	}

	for _, q := range stateQueries {
		u.SwallowSetTimeout.Add(1)
		u.Frontend.Send(&pgproto3.Query{String: q})
	}
	if err := u.Frontend.Flush(); err != nil {
		u.Broken.Store(true)
		s.server.pool.Release(u)
		return nil, fmt.Errorf("failed to flush session state queries: %w", err)
	}

	s.uconn = u

	go func() {
		cleanedUp := false
		defer func() {
			if r := recover(); r != nil {
				s.logger.Error("Panic recovered in upstream response reader",
					"event", "upstream_reader_panic",
					"client_id", s.clientID,
					"panic_type", panicType(r),
					"panic_summary", safePanicSummary(r),
					"stack", sanitizedStackTrace(),
				)
				u.Broken.Store(true)
				s.releaseUpstream()
				if s.cancel != nil {
					s.cancel()
				}
			} else if !cleanedUp {
				u.Broken.Store(true)
				s.releaseUpstream()
			}
		}()

		for {
			if fn := getTestPanicOnUpstreamReceive(); fn != nil {
				fn()
			}
			msg, err := u.Frontend.Receive()
			if err != nil {
				var maxLenErr *pgproto3.ExceededMaxBodyLenErr
				if errors.As(err, &maxLenErr) {
					s.logger.Error("Upstream message exceeded maximum permitted body length",
						"max", maxLenErr.MaxExpectedBodyLen,
						"actual", maxLenErr.ActualBodyLen,
					)
				}
				u.Broken.Store(true)
				cleanedUp = true
				s.releaseUpstream()
				if s.cancel != nil {
					s.cancel()
				}
				return
			}

			if dr, ok := msg.(*pgproto3.DataRow); ok {
				newValues := make([][]byte, len(dr.Values))
				for i, v := range dr.Values {
					if v != nil {
						newValues[i] = append([]byte(nil), v...)
					}
				}
				msg = &pgproto3.DataRow{Values: newValues}
			} else if rd, ok := msg.(*pgproto3.RowDescription); ok {
				newFields := make([]pgproto3.FieldDescription, len(rd.Fields))
				for i, f := range rd.Fields {
					newFields[i] = f
					if f.Name != nil {
						newFields[i].Name = append([]byte(nil), f.Name...)
					}
				}
				msg = &pgproto3.RowDescription{Fields: newFields}
			} else if cc, ok := msg.(*pgproto3.CommandComplete); ok {
				newTag := append([]byte(nil), cc.CommandTag...)
				msg = &pgproto3.CommandComplete{CommandTag: newTag}
			}

			if _, ok := msg.(*pgproto3.ParseComplete); ok {
				swallows := u.SwallowParseComplete.Load()
				if swallows > 0 {
					for {
						if u.SwallowParseComplete.CompareAndSwap(swallows, swallows-1) {
							break
						}
						swallows = u.SwallowParseComplete.Load()
					}
					continue
				}
			}

			if _, ok := msg.(*pgproto3.CommandComplete); ok {
				if u.SwallowSetTimeout.Load() > 0 {
					continue
				}
			}

			if s.errorDiscard.Load() {
				if _, isReady := msg.(*pgproto3.ReadyForQuery); isReady {
					continue
				}
			}

			if rfq, ok := msg.(*pgproto3.ReadyForQuery); ok {
				if u.SwallowSetTimeout.Load() > 0 {
					u.SwallowSetTimeout.Add(-1)
					continue
				}

				s.queryRunning.Store(false)
				s.lastClientActivity.Store(time.Now().UnixNano())

				if start := s.queryStartTime.Load(); start > 0 {
					ms := float64(time.Now().UnixNano()-start) / float64(time.Millisecond)
					s.server.RecordLatency(ms)
					s.queryStartTime.Store(0)
				}

				u.TxStatus = rfq.TxStatus
				if rfq.TxStatus == 'I' {
					if s.rules.PoolMode != "session" {
						select {
						case <-ctx.Done():
							return
						case clientWriteCh <- msg:
						}
						cleanedUp = true
						s.releaseUpstream()
						return
					}
				}
			}

			select {
			case <-ctx.Done():
				return
			case clientWriteCh <- msg:
			}
		}
	}()

	return u, nil
}

func (s *Session) releaseUpstream() {
	s.uconnMu.Lock()
	u := s.uconn
	s.uconn = nil
	s.uconnMu.Unlock()

	if u != nil {
		s.server.pool.Release(u)
	}
}

func (s *Session) recoverBrokenTransaction() {
	s.uconnMu.Lock()
	u := s.uconn
	s.uconn = nil
	s.uconnMu.Unlock()

	if u != nil {
		u.Broken.Store(true)
		s.server.pool.Release(u)
	}
}

// handleParseMsg processes a Parse message (Extended Query Protocol).
// It applies AST rules, stores the prepared statement, and forwards to upstream.
func (s *Session) handleParseMsg(ctx context.Context, v *pgproto3.Parse, clientWriteCh chan pgproto3.BackendMessage) error {
	_, span := Tracer.Start(ctx, "proxy.Parse")
	defer span.End()

	if s.errorDiscard.Load() {
		return nil
	}
	if s.isPolicyRevoked() {
		s.clientBackend.Send(&pgproto3.ErrorResponse{
			Severity: "FATAL",
			Code:     "57P01",
			Message:  "AgentIAM Policy Violation: active session policy was revoked or updated",
		})
		_ = s.clientBackend.Flush()
		s.errorDiscard.Store(true)
		if s.cancel != nil {
			s.cancel()
		}
		return fmt.Errorf("session policy revoked")
	}

	currentRules := s.rules
	if s.server != nil && s.server.verifier != nil {
		currentRules = s.server.verifier.EnrichRulesWithVerifiedViews(s.rules)
	}
	rewrittenSQL, limitParams, err := (&ast.PostgresParser{}).ApplyRules(v.Query, currentRules, s.server.astCache)
	if err != nil {
		s.server.DispatchAudit(AuditEvent{Event: EventPolicyBlocked, ClientID: s.clientID, SQL: v.Query, Status: "blocked", Error: err.Error()})
		BlockedQueriesTotal.WithLabelValues("policy").Inc()
		clientWriteCh <- &pgproto3.ErrorResponse{
			Severity: "ERROR",
			Message:  fmt.Sprintf("AgentIAM Policy Violation: %v", err),
		}
		s.errorDiscard.Store(true)
		return nil
	}

	s.preparedStatements[v.Name] = PreparedStatement{
		SQL:           rewrittenSQL,
		ParameterOIDs: v.ParameterOIDs,
		LimitParams:   limitParams,
	}
	v.Name = ""
	v.Query = rewrittenSQL

	s.server.DispatchAudit(AuditEvent{Event: EventQueryForwarded, ClientID: s.clientID, SQL: v.Query, Status: "success"})
	QueriesTotal.WithLabelValues("allowed").Inc()

	u, err := s.getOrAcquireUpstream(ctx, clientWriteCh)
	if err != nil {
		return err
	}
	u.Frontend.Send(v)
	if err := u.Frontend.Flush(); err != nil {
		return err
	}
	return nil
}

// handleBindMsg processes a Bind message (Extended Query Protocol).
// It applies rate limiting, re-sends the prepared statement Parse, caps parameterized LIMITs, and forwards upstream.
func (s *Session) handleBindMsg(ctx context.Context, v *pgproto3.Bind, clientWriteCh chan pgproto3.BackendMessage) error {
	_, span := Tracer.Start(ctx, "proxy.Bind")
	defer span.End()

	if s.errorDiscard.Load() {
		return nil
	}
	if s.isPolicyRevoked() {
		s.clientBackend.Send(&pgproto3.ErrorResponse{
			Severity: "FATAL",
			Code:     "57P01",
			Message:  "AgentIAM Policy Violation: active session policy was revoked or updated",
		})
		_ = s.clientBackend.Flush()
		s.errorDiscard.Store(true)
		if s.cancel != nil {
			s.cancel()
		}
		return fmt.Errorf("session policy revoked")
	}
	if s.server.pool != nil {
		s.server.store.SetPoolLatency(s.server.pool.GetAvgAcquireDuration())
	}
	if err := s.server.store.CheckRateLimit(s.clientID); err != nil {
		s.server.DispatchAudit(AuditEvent{Event: EventPolicyBlocked, ClientID: s.clientID, Status: "rate_limited", Error: err.Error()})
		BlockedQueriesTotal.WithLabelValues("rate_limit").Inc()
		clientWriteCh <- &pgproto3.ErrorResponse{
			Severity: "ERROR",
			Code:     "53400", // configuration_limit_exceeded
			Message:  fmt.Sprintf("AgentIAM Policy Violation: %v", err),
		}
		s.errorDiscard.Store(true)
		return nil
	}
	u, err := s.getOrAcquireUpstream(ctx, clientWriteCh)
	if err != nil {
		return err
	}

	ps, exists := s.preparedStatements[v.PreparedStatement]
	if exists {
		u.SwallowParseComplete.Add(1)
		u.Frontend.Send(&pgproto3.Parse{
			Name:          "",
			Query:         ps.SQL,
			ParameterOIDs: ps.ParameterOIDs,
		})

		if len(ps.LimitParams) > 0 && s.rules.EnforceSelectLimit > 0 {
			for _, paramIdx := range ps.LimitParams {
				pIdx := paramIdx - 1
				if pIdx >= 0 && pIdx < len(v.Parameters) {
					formatCode := uint16(0)
					if len(v.ParameterFormatCodes) == 1 {
						formatCode = uint16(v.ParameterFormatCodes[0])
					} else if len(v.ParameterFormatCodes) > pIdx {
						formatCode = uint16(v.ParameterFormatCodes[pIdx])
					}

					valBytes := v.Parameters[pIdx]
					if len(valBytes) > 0 {
						if formatCode == 0 { // Text
							val, parseErr := strconv.ParseInt(string(valBytes), 10, 64)
							if parseErr == nil && val > int64(s.rules.EnforceSelectLimit) {
								v.Parameters[pIdx] = []byte(strconv.Itoa(s.rules.EnforceSelectLimit))
							}
						} else if formatCode == 1 { // Binary
							var val int64
							parsed := false
							if len(valBytes) == 2 {
								val = int64(int16(binary.BigEndian.Uint16(valBytes)))
								parsed = true
							} else if len(valBytes) == 4 {
								val = int64(int32(binary.BigEndian.Uint32(valBytes)))
								parsed = true
							} else if len(valBytes) == 8 {
								val = int64(binary.BigEndian.Uint64(valBytes))
								parsed = true
							}
							if parsed && val > int64(s.rules.EnforceSelectLimit) {
								if len(valBytes) == 2 {
									binary.BigEndian.PutUint16(v.Parameters[pIdx], uint16(s.rules.EnforceSelectLimit))
								} else if len(valBytes) == 4 {
									binary.BigEndian.PutUint32(v.Parameters[pIdx], uint32(s.rules.EnforceSelectLimit))
								} else if len(valBytes) == 8 {
									binary.BigEndian.PutUint64(v.Parameters[pIdx], uint64(s.rules.EnforceSelectLimit))
								}
							}
						}
					}
				}
			}
		}
	}

	v.PreparedStatement = ""
	v.DestinationPortal = ""
	u.Frontend.Send(v)
	if err := u.Frontend.Flush(); err != nil {
		return err
	}
	return nil
}

// handleQueryMsg processes a simple Query message (Simple Query Protocol).
// It applies rate limiting, AST rules, tracks SET vars, and forwards upstream.
func (s *Session) handleQueryMsg(ctx context.Context, v *pgproto3.Query, clientWriteCh chan pgproto3.BackendMessage) error {
	if fn := getTestPanicHook(); fn != nil {
		fn()
	}
	s.queryRunning.Store(true)
	s.queryStartTime.Store(time.Now().UnixNano())
	_, span := Tracer.Start(ctx, "proxy.Query")
	defer span.End()

	if s.isPolicyRevoked() {
		s.clientBackend.Send(&pgproto3.ErrorResponse{
			Severity: "FATAL",
			Code:     "57P01",
			Message:  "AgentIAM Policy Violation: active session policy was revoked or updated",
		})
		s.clientBackend.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
		_ = s.clientBackend.Flush()
		s.errorDiscard.Store(true)
		if s.cancel != nil {
			s.cancel()
		}
		return fmt.Errorf("session policy revoked")
	}

	if s.server.pool != nil {
		s.server.store.SetPoolLatency(s.server.pool.GetAvgAcquireDuration())
	}
	if err := s.server.store.CheckRateLimit(s.clientID); err != nil {
		s.server.DispatchAudit(AuditEvent{Event: EventPolicyBlocked, ClientID: s.clientID, SQL: v.String, Status: "rate_limited", Error: err.Error()})
		BlockedQueriesTotal.WithLabelValues("rate_limit").Inc()
		clientWriteCh <- &pgproto3.ErrorResponse{
			Severity: "ERROR",
			Code:     "53400",
			Message:  fmt.Sprintf("AgentIAM Policy Violation: %v", err),
		}
		clientWriteCh <- &pgproto3.ReadyForQuery{TxStatus: 'I'}
		return nil
	}

	currentRules := s.rules
	if s.server != nil && s.server.verifier != nil {
		currentRules = s.server.verifier.EnrichRulesWithVerifiedViews(s.rules)
	}
	rewrittenSQL, _, err := (&ast.PostgresParser{}).ApplyRules(v.String, currentRules, s.server.astCache)
	if err != nil {
		s.server.DispatchAudit(AuditEvent{Event: EventPolicyBlocked, ClientID: s.clientID, SQL: v.String, Status: "blocked", Error: err.Error()})
		BlockedQueriesTotal.WithLabelValues("policy").Inc()
		clientWriteCh <- &pgproto3.ErrorResponse{
			Severity: "ERROR",
			Message:  fmt.Sprintf("AgentIAM Policy Violation: %v", err),
		}
		clientWriteCh <- &pgproto3.ReadyForQuery{TxStatus: 'I'}
		return nil
	}

	v.String = rewrittenSQL

	// Track SET variable changes for session state replay
	if matches := setCmdRegex.FindStringSubmatch(v.String); matches != nil {
		key := matches[1]
		val := strings.TrimRight(matches[2], ";")
		s.uconnMu.Lock()
		s.sessionVars[key] = val
		s.uconnMu.Unlock()
	}

	s.server.DispatchAudit(AuditEvent{Event: EventQueryForwarded, ClientID: s.clientID, SQL: v.String, Status: "success"})
	QueriesTotal.WithLabelValues("allowed").Inc()

	u, err := s.getOrAcquireUpstream(ctx, clientWriteCh)
	if err != nil {
		return err
	}
	u.Frontend.Send(v)
	if err := u.Frontend.Flush(); err != nil {
		return err
	}
	return nil
}

// handleSyncMsg processes a Sync message (Extended Query Protocol).
// On error-discard state it synthesizes a ReadyForQuery to unblock the client.
func (s *Session) handleSyncMsg(ctx context.Context, v *pgproto3.Sync, clientWriteCh chan pgproto3.BackendMessage) error {
	s.queryRunning.Store(true)
	s.queryStartTime.Store(time.Now().UnixNano())
	_, span := Tracer.Start(ctx, "proxy.Sync")
	defer span.End()

	if s.errorDiscard.Load() {
		s.errorDiscard.Store(false)
		clientWriteCh <- &pgproto3.ReadyForQuery{TxStatus: 'I'}
		s.queryRunning.Store(false)
		return nil
	}
	u, err := s.getOrAcquireUpstream(ctx, clientWriteCh)
	if err != nil {
		return err
	}
	u.Frontend.Send(v)
	if err := u.Frontend.Flush(); err != nil {
		return err
	}
	return nil
}

// proxyLoop is the main read loop for a session.
// It reads frontend messages and dispatches them to focused handler methods.
func (s *Session) proxyLoop(ctx context.Context, cancel context.CancelFunc, clientID string) error {
	clientWriteCh := make(chan pgproto3.BackendMessage, 64)

	// Writer goroutine: drains clientWriteCh and sends to the client connection.
	go func() {
		defer cancel()
		defer func() {
			if r := recover(); r != nil {
				s.logger.Error("Panic recovered in client writer goroutine",
					"event", "client_writer_panic",
					"client_id", s.clientID,
					"panic_type", panicType(r),
					"panic_summary", safePanicSummary(r),
					"stack", sanitizedStackTrace(),
				)
				s.recoverBrokenTransaction()
			}
		}()
		for {
			select {
			case <-ctx.Done():
				return
			case msg, ok := <-clientWriteCh:
				if !ok {
					return
				}
				_ = s.clientConn.SetWriteDeadline(time.Now().Add(30 * time.Second))
				s.clientBackend.Send(msg)
				if err := s.clientBackend.Flush(); err != nil {
					_ = s.clientConn.SetWriteDeadline(time.Time{})
					return
				}
				_ = s.clientConn.SetWriteDeadline(time.Time{})
			}
		}
	}()

	ActiveConnections.Inc()
	defer ActiveConnections.Dec()

	for {
		msg, err := s.clientBackend.Receive()

		if err != nil {
			var maxLenErr *pgproto3.ExceededMaxBodyLenErr
			if errors.As(err, &maxLenErr) {
				s.logger.Error("Client message exceeded maximum permitted body length",
					"max", maxLenErr.MaxExpectedBodyLen,
					"actual", maxLenErr.ActualBodyLen,
					"client", s.clientConn.RemoteAddr(),
				)
				s.clientBackend.Send(&pgproto3.ErrorResponse{
					Severity: "FATAL",
					Message:  "Query message exceeded maximum permitted protocol body length",
				})
				_ = s.clientBackend.Flush()
			}
			s.recoverBrokenTransaction()
			return err
		}

		s.lastClientActivity.Store(time.Now().UnixNano())

		select {
		case <-ctx.Done():
			s.recoverBrokenTransaction()
			return ctx.Err()
		default:
		}

		if _, isTerm := msg.(*pgproto3.Terminate); !isTerm && s.isPolicyRevoked() {
			s.clientBackend.Send(&pgproto3.ErrorResponse{
				Severity: "FATAL",
				Code:     "57P01",
				Message:  "AgentIAM Policy Violation: active session policy was revoked or updated",
			})
			_ = s.clientBackend.Flush()
			s.errorDiscard.Store(true)
			if s.cancel != nil {
				s.cancel()
			}
			s.recoverBrokenTransaction()
			return fmt.Errorf("session policy revoked")
		}

		switch v := msg.(type) {
		case *pgproto3.Parse:
			if err := s.handleParseMsg(ctx, v, clientWriteCh); err != nil {
				return err
			}

		case *pgproto3.Bind:
			if err := s.handleBindMsg(ctx, v, clientWriteCh); err != nil {
				return err
			}

		case *pgproto3.Describe:
			_, span := Tracer.Start(ctx, "proxy.Describe")
			if s.errorDiscard.Load() {
				span.End()
				continue
			}
			if s.isPolicyRevoked() {
				span.End()
				s.clientBackend.Send(&pgproto3.ErrorResponse{
					Severity: "FATAL",
					Code:     "57P01",
					Message:  "AgentIAM Policy Violation: active session policy was revoked or updated",
				})
				_ = s.clientBackend.Flush()
				s.errorDiscard.Store(true)
				if s.cancel != nil {
					s.cancel()
				}
				s.recoverBrokenTransaction()
				return fmt.Errorf("session policy revoked")
			}
			u, err := s.getOrAcquireUpstream(ctx, clientWriteCh)
			if err != nil {
				span.End()
				return err
			}
			if v.ObjectType == 'S' {
				ps, exists := s.preparedStatements[v.Name]
				if exists {
					u.SwallowParseComplete.Add(1)
					u.Frontend.Send(&pgproto3.Parse{
						Name:          "",
						Query:         ps.SQL,
						ParameterOIDs: ps.ParameterOIDs,
					})
				}
			}
			v.Name = ""
			u.Frontend.Send(v)
			_ = u.Frontend.Flush()
			span.End()

		case *pgproto3.Execute:
			s.queryRunning.Store(true)
			s.queryStartTime.Store(time.Now().UnixNano())
			_, span := Tracer.Start(ctx, "proxy.Execute")
			if s.errorDiscard.Load() {
				span.End()
				continue
			}
			if s.isPolicyRevoked() {
				span.End()
				s.clientBackend.Send(&pgproto3.ErrorResponse{
					Severity: "FATAL",
					Code:     "57P01",
					Message:  "AgentIAM Policy Violation: active session policy was revoked or updated",
				})
				_ = s.clientBackend.Flush()
				s.errorDiscard.Store(true)
				if s.cancel != nil {
					s.cancel()
				}
				s.recoverBrokenTransaction()
				return fmt.Errorf("session policy revoked")
			}
			u, err := s.getOrAcquireUpstream(ctx, clientWriteCh)
			if err != nil {
				span.End()
				return err
			}
			v.Portal = ""
			u.Frontend.Send(v)
			_ = u.Frontend.Flush()
			span.End()

		case *pgproto3.Close:
			_, span := Tracer.Start(ctx, "proxy.Close")
			if v.ObjectType == 'S' {
				delete(s.preparedStatements, v.Name)
			}
			if !s.errorDiscard.Load() {
				u, err := s.getOrAcquireUpstream(ctx, clientWriteCh)
				if err == nil {
					v.Name = ""
					u.Frontend.Send(v)
					_ = u.Frontend.Flush()
				}
			}
			span.End()

		case *pgproto3.Sync:
			if err := s.handleSyncMsg(ctx, v, clientWriteCh); err != nil {
				return err
			}

		case *pgproto3.Query:
			if err := s.handleQueryMsg(ctx, v, clientWriteCh); err != nil {
				return err
			}

		case *pgproto3.Terminate:
			s.recoverBrokenTransaction()
			return nil

		default:
			if !s.errorDiscard.Load() {
				u, err := s.getOrAcquireUpstream(ctx, clientWriteCh)
				if err != nil {
					return err
				}
				u.Frontend.Send(msg)
				_ = u.Frontend.Flush()
			}
		}
	}
}

func (s *Session) Close() {
	s.closeOnce.Do(func() {
		if s.clientConn != nil {
			s.clientConn.Close()
		}
		s.recoverBrokenTransaction()
	})
}
