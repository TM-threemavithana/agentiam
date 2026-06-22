package proxy

import (
	"agentiam/internal/ast"
	"agentiam/internal/policy"
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"sync/atomic"

	"github.com/jackc/pgproto3/v2"
	"github.com/jackc/pgx/v5/pgconn"
)

type Session struct {
	clientConn  net.Conn
	upstreamConn net.Conn
	upstreamDSN string
	store       *policy.Store

	clientBackend    *pgproto3.Backend
	upstreamFrontend *pgproto3.Frontend

	errorDiscard atomic.Bool
	rules        ast.Rules
}

func NewSession(clientConn net.Conn, upstreamDSN string, store *policy.Store) *Session {
	return &Session{
		clientConn:  clientConn,
		upstreamDSN: upstreamDSN,
		store:       store,
	}
}

func (s *Session) Run() error {
	s.clientBackend = pgproto3.NewBackend(pgproto3.NewChunkReader(s.clientConn), s.clientConn)

	// Phase 1: Read Startup Message
	startupMsg, err := s.clientBackend.ReceiveStartupMessage()
	if err != nil {
		return fmt.Errorf("error receiving startup message: %w", err)
	}

	var apiKey string
	switch msg := startupMsg.(type) {
	case *pgproto3.StartupMessage:
		apiKey = msg.Parameters["user"]
	case *pgproto3.SSLRequest:
		s.clientConn.Write([]byte("N"))
		return s.Run()
	default:
		return fmt.Errorf("unexpected startup message: %T", startupMsg)
	}

	// Phase 2: Authenticate via Policy Store
	rules, err := s.store.GetRulesForAgent(apiKey)
	if err != nil {
		s.clientBackend.Send(&pgproto3.ErrorResponse{Severity: "FATAL", Message: "Invalid Agent API Key"})
		return fmt.Errorf("auth failed: %w", err)
	}
	s.rules = rules
	s.clientBackend.Send(&pgproto3.AuthenticationOk{})

	// Phase 3: Dial Upstream via pgconn (Handles SCRAM, MD5, etc.)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	pgConn, err := pgconn.Connect(ctx, s.upstreamDSN)
	if err != nil {
		s.clientBackend.Send(&pgproto3.ErrorResponse{Severity: "FATAL", Message: "Failed to dial upstream database"})
		return fmt.Errorf("upstream dial failed: %w", err)
	}
	
	// Hijack the raw connection
	hijacked, err := pgConn.Hijack()
	if err != nil {
		return fmt.Errorf("failed to hijack upstream conn: %w", err)
	}
	s.upstreamConn = hijacked.Conn
	defer s.upstreamConn.Close()

	s.upstreamFrontend = pgproto3.NewFrontend(pgproto3.NewChunkReader(s.upstreamConn), s.upstreamConn)

	// Forward ParameterStatus from upstream to downstream client
	for k, v := range hijacked.ParameterStatuses {
		s.clientBackend.Send(&pgproto3.ParameterStatus{Name: k, Value: v})
	}
	
	// Forward BackendKeyData (pgconn uses []byte for SecretKey, pgproto3/v2 uses uint32)
	secretKeyUint := uint32(0)
	if len(hijacked.SecretKey) >= 4 {
		secretKeyUint = uint32(hijacked.SecretKey[0])<<24 | uint32(hijacked.SecretKey[1])<<16 | uint32(hijacked.SecretKey[2])<<8 | uint32(hijacked.SecretKey[3])
	}
	s.clientBackend.Send(&pgproto3.BackendKeyData{ProcessID: hijacked.PID, SecretKey: secretKeyUint})
	
	// Complete startup
	s.clientBackend.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})

	// Phase 4: The 3-Goroutine Proxy Loop
	return s.proxyLoop(ctx, cancel, apiKey)
}

func (s *Session) proxyLoop(ctx context.Context, cancel context.CancelFunc, apiKey string) error {
	clientWriteCh := make(chan pgproto3.BackendMessage, 64)

	// Writer Goroutine (owns s.clientBackend exclusively)
	go func() {
		defer cancel() // if writer dies, tear down everything
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
					log.Printf("Error writing to client: %v", err)
					return
				}
			}
		}
	}()

	// Upstream-to-Client Reader Goroutine
	go func() {
		defer cancel()
		for {
			msg, err := s.upstreamFrontend.Receive()
			if err != nil {
				if err != io.EOF && err != io.ErrUnexpectedEOF {
					log.Printf("Upstream read error: %v", err)
				}
				return
			}

			// If we are in discard mode, suppress ReadyForQuery.
			// clientToUpstream will synthesize it on Sync.
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

	// Client-to-Upstream Reader Goroutine (Main Loop)
	for {
		msg, err := s.clientBackend.Receive()
		if err != nil {
			if err != io.EOF && err != io.ErrUnexpectedEOF {
				log.Printf("Client read error: %v", err)
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
				log.Printf("[BLOCKED] Agent %s attempted: %s\nReason: %v", apiKey, v.Query, err)
				
				clientWriteCh <- &pgproto3.ErrorResponse{
					Severity: "ERROR",
					Message:  fmt.Sprintf("AgentIAM Policy Violation: %v", err),
				}
				
				s.errorDiscard.Store(true)
				continue
			}

			log.Printf("[ALLOWED] SQL: %s", rewrittenSQL)
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
				// Recover from discard
				s.errorDiscard.Store(false) // reset FIRST
				clientWriteCh <- &pgproto3.ReadyForQuery{TxStatus: 'I'}
			} else {
				s.upstreamFrontend.Send(v)
			}
		
		case *pgproto3.Query:
			rewrittenSQL, err := ast.ApplyRules(v.String, s.rules)
			if err != nil {
				log.Printf("[BLOCKED SimpleQuery] Agent %s attempted: %s\nReason: %v", apiKey, v.String, err)
				clientWriteCh <- &pgproto3.ErrorResponse{
					Severity: "ERROR",
					Message:  fmt.Sprintf("AgentIAM Policy Violation: %v", err),
				}
				clientWriteCh <- &pgproto3.ReadyForQuery{TxStatus: 'I'}
				continue
			}
			log.Printf("[ALLOWED SimpleQuery] SQL: %s", rewrittenSQL)
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
	if s.clientConn != nil {
		s.clientConn.Close()
	}
	if s.upstreamConn != nil {
		s.upstreamConn.Close()
	}
}
