package proxy

import (
	"agentiam/internal/ast"
	"agentiam/internal/policy"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgproto3/v2"
	"github.com/jackc/pgx/v5/pgconn"
)

type Session struct {
	clientConn   net.Conn
	upstreamConn net.Conn
	upstreamDSN  string
	store        *policy.Store
	logger       *Logger
	server       *Server

	clientBackend    *pgproto3.Backend
	upstreamFrontend *pgproto3.Frontend

	errorDiscard atomic.Bool
	rules        ast.Rules
	tlsConfig    *tls.Config
	closeOnce    sync.Once
}

func NewSession(clientConn net.Conn, upstreamDSN string, store *policy.Store, tlsConfig *tls.Config, logger *Logger, server *Server) *Session {
	return &Session{
		clientConn:  clientConn,
		upstreamDSN: upstreamDSN,
		store:       store,
		tlsConfig:   tlsConfig,
		logger:      logger,
		server:      server,
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
	var startupMsg pgproto3.FrontendMessage
	var err error

	for i := 0; i < 3; i++ {
		s.clientConn.SetReadDeadline(time.Now().Add(5 * time.Minute))
		startupMsg, err = s.clientBackend.ReceiveStartupMessage()
		s.clientConn.SetReadDeadline(time.Time{})
		if err != nil {
			return fmt.Errorf("error receiving startup message: %w", err)
		}

		switch msg := startupMsg.(type) {
		case *pgproto3.StartupMessage:
			if s.tlsConfig != nil {
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
			return fmt.Errorf("unexpected startup message: %T", startupMsg)
		}

		if clientID != "" {
			break
		}
	}

	if clientID == "" {
		return fmt.Errorf("startup sequence failed: maximum iterations exceeded")
	}

	s.clientBackend.Send(&pgproto3.AuthenticationCleartextPassword{})

	s.clientConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	authMsg, err := s.clientBackend.Receive()
	s.clientConn.SetReadDeadline(time.Time{})
	if err != nil {
		return fmt.Errorf("error receiving password: %w", err)
	}

	pwdMsg, ok := authMsg.(*pgproto3.PasswordMessage)
	if !ok {
		s.clientBackend.Send(&pgproto3.ErrorResponse{Severity: "FATAL", Message: "Expected PasswordMessage"})
		return fmt.Errorf("expected PasswordMessage, got %T", authMsg)
	}

	rules, authVersion, err := s.store.GetRulesForAgent(clientID, pwdMsg.Password)
	if err != nil {
		s.logger.Error("Auth failed", "client", clientID, "error", err)
		s.clientBackend.Send(&pgproto3.ErrorResponse{Severity: "FATAL", Message: "Invalid Agent Credentials"})
		return fmt.Errorf("auth failed: %w", err)
	}
	s.rules = rules
	s.clientBackend.Send(&pgproto3.AuthenticationOk{})

	// Register session with Server for dynamic revocation
	s.server.RegisterSession(clientID, s, authVersion, cancel)
	defer s.server.UnregisterSession(clientID, s)

	pgConn, err := pgconn.Connect(ctx, s.upstreamDSN)
	if err != nil {
		s.clientBackend.Send(&pgproto3.ErrorResponse{Severity: "FATAL", Message: "Failed to dial upstream database"})
		return fmt.Errorf("upstream dial failed: %w", err)
	}

	hijacked, err := pgConn.Hijack()
	if err != nil {
		return fmt.Errorf("failed to hijack upstream conn: %w", err)
	}
	s.upstreamConn = hijacked.Conn
	defer s.upstreamConn.Close()

	s.upstreamFrontend = pgproto3.NewFrontend(pgproto3.NewChunkReader(s.upstreamConn), s.upstreamConn)

	for k, v := range hijacked.ParameterStatuses {
		s.clientBackend.Send(&pgproto3.ParameterStatus{Name: k, Value: v})
	}

	secretKeyUint := uint32(0)
	if len(hijacked.SecretKey) >= 4 {
		secretKeyUint = uint32(hijacked.SecretKey[0])<<24 | uint32(hijacked.SecretKey[1])<<16 | uint32(hijacked.SecretKey[2])<<8 | uint32(hijacked.SecretKey[3])
	}
	s.clientBackend.Send(&pgproto3.BackendKeyData{ProcessID: hijacked.PID, SecretKey: secretKeyUint})

	s.clientBackend.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})

	return s.proxyLoop(ctx, cancel, clientID)
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
				err := s.clientBackend.Send(msg)
				if err != nil {
					s.logger.Error("Error writing to client", "error", err)
					return
				}
			}
		}
	}()

	go func() {
		defer cancel()
		for {
			msg, err := s.upstreamFrontend.Receive()
			if err != nil {
				if err != io.EOF && err != io.ErrUnexpectedEOF {
					s.logger.Error("Upstream read error", "error", err)
				}
				return
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
		}
	}()

	for {
		s.clientConn.SetReadDeadline(time.Now().Add(5 * time.Minute))
		msg, err := s.clientBackend.Receive()

		s.clientConn.SetReadDeadline(time.Time{})

		if err != nil {
			if err != io.EOF && err != io.ErrUnexpectedEOF {
				s.logger.Error("Client read error", "error", err)
			}
			return err
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		switch v := msg.(type) {
		case *pgproto3.Parse:
			if s.errorDiscard.Load() {
				continue
			}

			rewrittenSQL, err := ast.ApplyRules(v.Query, s.rules)
			if err != nil {
				s.logger.Error("Policy violation", "client", clientID, "query", v.Query, "error", err)

				clientWriteCh <- &pgproto3.ErrorResponse{
					Severity: "ERROR",
					Message:  fmt.Sprintf("AgentIAM Policy Violation: %v", err),
				}

				s.errorDiscard.Store(true)
				continue
			}

			s.logger.Info("Query forwarded", "client", clientID, "query", rewrittenSQL)
			v.Query = rewrittenSQL
			s.upstreamFrontend.Send(v)

		case *pgproto3.Bind, *pgproto3.Execute:
			if s.errorDiscard.Load() {
				continue
			}
			s.upstreamFrontend.Send(v)

		case *pgproto3.Describe:
			if s.errorDiscard.Load() {
				continue
			}
			s.upstreamFrontend.Send(v)

		case *pgproto3.Sync:
			if s.errorDiscard.Load() {
				s.errorDiscard.Store(false)
				clientWriteCh <- &pgproto3.ReadyForQuery{TxStatus: 'I'}
			} else {
				s.upstreamFrontend.Send(v)
			}

		case *pgproto3.Query:
			rewrittenSQL, err := ast.ApplyRules(v.String, s.rules)
			if err != nil {
				s.logger.Error("Policy violation", "client", clientID, "query", v.String, "error", err)
				clientWriteCh <- &pgproto3.ErrorResponse{
					Severity: "ERROR",
					Message:  fmt.Sprintf("AgentIAM Policy Violation: %v", err),
				}
				clientWriteCh <- &pgproto3.ReadyForQuery{TxStatus: 'I'}
				continue
			}
			s.logger.Info("Query forwarded", "client", clientID, "query", rewrittenSQL)
			v.String = rewrittenSQL
			s.upstreamFrontend.Send(v)

		case *pgproto3.Terminate:
			s.upstreamFrontend.Send(v)
			return nil

		default:
			if !s.errorDiscard.Load() {
				s.upstreamFrontend.Send(v)
			}
		}
	}
}

func (s *Session) Close() {
	s.closeOnce.Do(func() {
		if s.clientConn != nil {
			s.clientConn.Close()
		}
		if s.upstreamConn != nil {
			s.upstreamConn.Close()
		}
	})
}
