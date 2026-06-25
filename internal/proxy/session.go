package proxy

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"agentiam/internal/ast"
	"agentiam/internal/policy"

	"github.com/jackc/pgproto3/v2"
)

type PreparedStatement struct {
	SQL       string
	ParameterOIDs []uint32
}

type PostgresProtocolHandler struct {
	upstreamDSN string
	store       *policy.Store
	tlsConfig   *tls.Config
	logger      *Logger
	server      *Server
}

func NewPostgresProtocolHandler(upstreamDSN string, store *policy.Store, tlsConfig *tls.Config, logger *Logger, server *Server) *PostgresProtocolHandler {
	return &PostgresProtocolHandler{
		upstreamDSN: upstreamDSN,
		store:       store,
		tlsConfig:   tlsConfig,
		logger:      logger,
		server:      server,
	}
}

func (h *PostgresProtocolHandler) HandleSession(ctx context.Context, clientConn net.Conn) error {
	clientBackend := pgproto3.NewBackend(pgproto3.NewChunkReader(clientConn), clientConn)
	clientConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	startupMsg, err := clientBackend.ReceiveStartupMessage()
	clientConn.SetReadDeadline(time.Time{})

	if err != nil {
		h.logger.Error("Failed to read startup message", "error", err)
		return err
	}

	if cancelMsg, ok := startupMsg.(*pgproto3.CancelRequest); ok {
		h.server.handleCancelRequest(clientConn, cancelMsg)
		return nil
	}

	session := NewSession(clientConn, h.upstreamDSN, h.store, h.tlsConfig, h.logger, h.server)
	session.clientBackend = clientBackend
	session.startupMsg = startupMsg
	defer session.Close()

	return session.Run()
}

type Session struct {
	clientConn   net.Conn
	uconn        *UpstreamConn
	upstreamDSN  string
	uconnMu      sync.Mutex

	store  *policy.Store
	logger *Logger
	server *Server

	clientBackend *pgproto3.Backend

	errorDiscard atomic.Bool
	rules        ast.Rules
	tlsConfig    *tls.Config
	closeOnce    sync.Once

	startupMsg pgproto3.FrontendMessage
	virtualPID uint32
	virtualSec uint32

	preparedStatements map[string]PreparedStatement
}

func NewSession(clientConn net.Conn, upstreamDSN string, store *policy.Store, tlsConfig *tls.Config, logger *Logger, server *Server) *Session {
	return &Session{
		clientConn:         clientConn,
		upstreamDSN:        upstreamDSN,
		store:              store,
		tlsConfig:          tlsConfig,
		logger:             logger,
		server:             server,
		preparedStatements: make(map[string]PreparedStatement),
	}
}

func (s *Session) CancelQuery() {
	s.uconnMu.Lock()
	u := s.uconn
	s.uconnMu.Unlock()
	if u != nil {
		u.Broken.Store(true)
		s.server.pool.Release(u)
	}
}

func (s *Session) Run() error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		<-ctx.Done()
		s.Close()
	}()

	s.clientBackend = pgproto3.NewBackend(pgproto3.NewChunkReader(s.clientConn), s.clientConn)

	var clientID string
	var err error

	for i := 0; i < 3; i++ {
		s.clientConn.SetReadDeadline(time.Now().Add(5 * time.Minute))
		s.startupMsg, err = s.clientBackend.ReceiveStartupMessage()
		s.clientConn.SetReadDeadline(time.Time{})
		if err != nil {
			return err
		}

		switch msg := s.startupMsg.(type) {
		case *pgproto3.StartupMessage:
			_, isTLS := s.clientConn.(*tls.Conn)
			if s.tlsConfig != nil && !isTLS {
				s.clientBackend.Send(&pgproto3.ErrorResponse{Severity: "FATAL", Message: "SSL connection is required"})
				return fmt.Errorf("client attempted plaintext connection when TLS is enforced")
			}
			clientID = msg.Parameters["user"]
			break

		case *pgproto3.SSLRequest:
			if s.tlsConfig == nil {
				s.clientConn.Write([]byte("N"))
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
			s.clientBackend = pgproto3.NewBackend(pgproto3.NewChunkReader(s.clientConn), s.clientConn)
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
				suppliedPassword = "mTLS_VERIFIED"
			} else {
				s.logger.Error("mTLS CN mismatch", "cn", cert.Subject.CommonName, "clientID", clientID)
			}
		}
	}

	if !mtlsVerified {
		if strings.HasPrefix(agentKey, "SCRAM-SHA-256$") {
		s.clientBackend.Send(&pgproto3.AuthenticationSASL{AuthMechanisms: []string{"SCRAM-SHA-256"}})
		s.clientBackend.SetAuthType(pgproto3.AuthTypeSASL)

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
		if strings.HasPrefix(clientFirstBare, "n,,") {
			clientFirstBare = clientFirstBare[3:]
		}

		iters, salt, storedKey, serverKey, err := ParseSCRAMSecret(agentKey)
		if err != nil {
			return err
		}

		serverNonce := "r=Oye230"
		saltStr := base64.StdEncoding.EncodeToString(salt)
		serverFirst := fmt.Sprintf("%s,s=%s,i=%d", clientFirstBare[2:]+serverNonce, saltStr, iters)
		s.clientBackend.Send(&pgproto3.AuthenticationSASLContinue{Data: []byte(serverFirst)})

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
			return fmt.Errorf("SCRAM auth failed")
		}

		s.clientBackend.Send(&pgproto3.AuthenticationSASLFinal{Data: []byte("v=" + serverSignature)})
		suppliedPassword = "SCRAM_VERIFIED"
	} else {
		s.clientBackend.Send(&pgproto3.AuthenticationCleartextPassword{})
		s.clientBackend.SetAuthType(pgproto3.AuthTypeCleartextPassword)

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

	rules, authVersion, err := s.store.GetRulesForAgent(clientID, suppliedPassword)
	if err != nil {
		s.clientBackend.Send(&pgproto3.ErrorResponse{Severity: "FATAL", Message: "Password authentication failed"})
		return fmt.Errorf("password auth failed")
	}
	s.rules = rules

	s.clientBackend.Send(&pgproto3.AuthenticationOk{})

	s.virtualPID = uint32(time.Now().UnixNano())
	s.virtualSec = uint32(time.Now().UnixNano() >> 32)

	s.server.RegisterSession(clientID, s, authVersion, cancel)
	defer s.server.UnregisterSession(clientID, s)

	s.clientBackend.Send(&pgproto3.ParameterStatus{Name: "server_version", Value: "15.0"})
	s.clientBackend.Send(&pgproto3.ParameterStatus{Name: "client_encoding", Value: "UTF8"})
	s.clientBackend.Send(&pgproto3.ParameterStatus{Name: "standard_conforming_strings", Value: "on"})

	s.clientBackend.Send(&pgproto3.BackendKeyData{ProcessID: s.virtualPID, SecretKey: s.virtualSec})
	s.clientBackend.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})

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
	u.SwallowSetTimeout.Add(1)
	u.Frontend.Send(&pgproto3.Query{String: fmt.Sprintf("SET statement_timeout = '%dms'", timeout)})
	
	s.uconn = u

	go func() {
		for {
			msg, err := u.Frontend.Receive()
			if err != nil {
				u.Broken.Store(true)
				s.releaseUpstream()
				return
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

			select {
			case <-ctx.Done():
				return
			case clientWriteCh <- msg:
			}

			if rfq, ok := msg.(*pgproto3.ReadyForQuery); ok {
				if u.SwallowSetTimeout.Load() > 0 {
					u.SwallowSetTimeout.Add(-1)
					continue
				}

				u.TxStatus = rfq.TxStatus
				if rfq.TxStatus == 'I' {
					if s.rules.PoolMode != "session" {
						s.releaseUpstream()
						return
					}
				}
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

func (s *Session) proxyLoop(ctx context.Context, cancel context.CancelFunc, clientID string) error {
	clientWriteCh := make(chan pgproto3.BackendMessage, 64)

	go func() {
		defer cancel()
		for {
			select {
			case <-ctx.Done():
				return
			case msg, ok := <-clientWriteCh:
				if !ok {
					return
				}
				s.clientBackend.Send(msg)
			}
		}
	}()

	for {
		s.clientConn.SetReadDeadline(time.Now().Add(5 * time.Minute))
		msg, err := s.clientBackend.Receive()
		s.clientConn.SetReadDeadline(time.Time{})

		if err != nil {
			s.recoverBrokenTransaction()
			return err
		}

		select {
		case <-ctx.Done():
			s.recoverBrokenTransaction()
			return ctx.Err()
		default:
		}

		switch v := msg.(type) {
		case *pgproto3.Parse:
			_, span := Tracer.Start(ctx, "proxy.Parse")
			if s.errorDiscard.Load() {
				span.End()
				continue
			}

			rewrittenSQL, err := (&ast.PostgresParser{}).ApplyRules(v.Query, s.rules, s.server.astCache)
			if err != nil {
				clientWriteCh <- &pgproto3.ErrorResponse{
					Severity: "ERROR",
					Message:  fmt.Sprintf("AgentIAM Policy Violation: %v", err),
				}
				s.errorDiscard.Store(true)
				span.End()
				continue
			}

			s.preparedStatements[v.Name] = PreparedStatement{
				SQL:           rewrittenSQL,
				ParameterOIDs: v.ParameterOIDs,
			}
			v.Name = ""
			v.Query = rewrittenSQL
			u, err := s.getOrAcquireUpstream(ctx, clientWriteCh)
			if err != nil {
				span.End()
				return err
			}
			u.Frontend.Send(v)
			span.End()

		case *pgproto3.Bind:
			_, span := Tracer.Start(ctx, "proxy.Bind")
			if s.errorDiscard.Load() {
				span.End()
				continue
			}
			u, err := s.getOrAcquireUpstream(ctx, clientWriteCh)
			if err != nil {
				span.End()
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
			}
			
			v.PreparedStatement = ""
			v.DestinationPortal = ""
			u.Frontend.Send(v)
			span.End()

		case *pgproto3.Describe:
			_, span := Tracer.Start(ctx, "proxy.Describe")
			if s.errorDiscard.Load() {
				span.End()
				continue
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
			span.End()

		case *pgproto3.Execute:
			_, span := Tracer.Start(ctx, "proxy.Execute")
			if s.errorDiscard.Load() {
				span.End()
				continue
			}
			u, err := s.getOrAcquireUpstream(ctx, clientWriteCh)
			if err != nil {
				span.End()
				return err
			}
			v.Portal = ""
			u.Frontend.Send(v)
			span.End()

		case *pgproto3.Sync:
			_, span := Tracer.Start(ctx, "proxy.Sync")
			if s.errorDiscard.Load() {
				s.errorDiscard.Store(false)
				clientWriteCh <- &pgproto3.ReadyForQuery{TxStatus: 'I'}
			} else {
				u, err := s.getOrAcquireUpstream(ctx, clientWriteCh)
				if err != nil {
					span.End()
					return err
				}
				u.Frontend.Send(v)
			}
			span.End()

		case *pgproto3.Query:
			_, span := Tracer.Start(ctx, "proxy.Query")
			rewrittenSQL, err := (&ast.PostgresParser{}).ApplyRules(v.String, s.rules, s.server.astCache)
			if err != nil {
				clientWriteCh <- &pgproto3.ErrorResponse{
					Severity: "ERROR",
					Message:  fmt.Sprintf("AgentIAM Policy Violation: %v", err),
				}
				clientWriteCh <- &pgproto3.ReadyForQuery{TxStatus: 'I'}
				span.End()
				continue
			}

			v.String = rewrittenSQL
			u, err := s.getOrAcquireUpstream(ctx, clientWriteCh)
			if err != nil {
				span.End()
				return err
			}
			u.Frontend.Send(v)
			span.End()

		case *pgproto3.Terminate:
			s.recoverBrokenTransaction()
			return nil

		default:
			if !s.errorDiscard.Load() {
				u, err := s.getOrAcquireUpstream(ctx, clientWriteCh)
				if err != nil {
					return err
				}
				u.Frontend.Send(msg.(pgproto3.FrontendMessage))
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




