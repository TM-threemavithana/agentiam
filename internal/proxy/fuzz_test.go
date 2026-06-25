package proxy

import (
	"context"
	"net"
	"os"
	"testing"
	"time"

	"agentiam/internal/ast"

	"github.com/jackc/pgproto3/v2"
)

// mockServer provides a dummy UpstreamConn loop
type mockServer struct{}

func (m *mockServer) start(l net.Listener) {
	for {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		go func(c net.Conn) {
			defer c.Close()
			backend := pgproto3.NewBackend(pgproto3.NewChunkReader(c), c)
			for {
				msg, err := backend.Receive()
				if err != nil {
					return
				}
				if _, ok := msg.(*pgproto3.Terminate); ok {
					return
				}
				// Mock a ready for query after everything
				backend.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
			}
		}(conn)
	}
}

func FuzzProxyLoop(f *testing.F) {
	// Add some seed corpus with valid PG messages
	f.Add([]byte("Q\x00\x00\x00\x11SELECT 1;\x00")) // Query: SELECT 1;
	f.Add([]byte("X\x00\x00\x00\x04"))             // Terminate

	f.Fuzz(func(t *testing.T, data []byte) {
		// Create a local listener for the mock upstream
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Skip("failed to listen", err)
		}
		defer l.Close()

		mock := &mockServer{}
		go mock.start(l)

		// Set up a mock Server and Pool
		logger := NewLogger(os.Stdout)
		pool := NewPool(l.Addr().String(), 1, logger)
		
		server := &Server{
			pool:   pool,
			logger: logger,
		}

		// Create dummy client connection
		clientConn, clientWrite := net.Pipe()
		defer clientConn.Close()
		defer clientWrite.Close()

		session := &Session{
			server:        server,
			clientConn:    clientConn,
			clientBackend: pgproto3.NewBackend(pgproto3.NewChunkReader(clientConn), clientConn),
			logger:        logger,
			rules: ast.Rules{
				EnforceSelectLimit: 10,
				AllowedStatements:  []string{"SELECT"},
			},
		}

		// Feed the fuzz data through a pipe to simulate client sending to proxy
		go func() {
			clientWrite.Write(data)
			clientWrite.Close()
		}()

		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
		defer cancel()

		// Run proxyLoop
		_ = session.proxyLoop(ctx, cancel, "fuzz-client")
		
		// Ensure that when proxyLoop exits, it doesn't leave the pool in a bad state
		session.Close()
	})
}

