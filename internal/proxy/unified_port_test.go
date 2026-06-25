package proxy

import (
	"github.com/tm-threemavithana/agentiam/internal/policy"
	"io"
	"log/slog"
	"net"
	"os"
	"testing"
	"time"
)

func TestUnifiedPortMultiplexer(t *testing.T) {
	tmpFile, _ := os.CreateTemp("", "policies-*.yaml")
	tmpFile.Write([]byte("agents:\n  - name: dummy\n    key: dummy\n"))
	tmpFile.Close()
	defer os.Remove(tmpFile.Name())

	store, _ := policy.NewStore(nil, tmpFile.Name(), "", slog.New(slog.NewTextHandler(io.Discard, nil)))
	logger := NewLogger(io.Discard)

	handlers := make(map[ProtocolType]ProtocolHandler)
	server := NewServer("127.0.0.1:0", "postgres://dummy", store, nil, logger, nil, handlers)

	pgHandler := NewPostgresProtocolHandler("postgres://dummy", store, nil, logger, server)
	mysqlHandler := NewMySQLProtocolHandler(store, logger)

	server.SetHandler(ProtocolPostgres, pgHandler)
	server.SetHandler(ProtocolMySQL, mysqlHandler)

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to listen: %v", err)
	}
	defer l.Close()

	// Replace the listener inside start (simulate)
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				ptype, sniffed, err := SniffProtocol(c, 100*time.Millisecond)
				if err != nil {
					return
				}
				// We won't invoke the full HandleSession because we don't have real upstream DBs mocked.
				// We just want to verify the SniffProtocol routing correctly identifies bytes vs timeout.
				c.Write([]byte(ptype))
				if sniffed != nil {
					// Read the sniffed prefix back out just to drain it
					buf := make([]byte, 4)
					sniffed.Read(buf)
				}
			}(conn)
		}
	}()

	addr := l.Addr().String()

	// 1. Simulate a PostgreSQL client (sends bytes immediately)
	pgConn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("Failed to dial for Postgres: %v", err)
	}
	defer pgConn.Close()

	// Postgres StartupMessage starts with length, e.g. 0x00 0x00 0x00 0x08
	pgConn.Write([]byte{0, 0, 0, 8})
	pgResp := make([]byte, len(ProtocolPostgres))
	pgConn.SetReadDeadline(time.Now().Add(1 * time.Second))
	pgConn.Read(pgResp)
	if string(pgResp) != string(ProtocolPostgres) {
		t.Fatalf("Expected Postgres routing, got: %s", string(pgResp))
	}

	// 2. Simulate a MySQL client (sends nothing, waits for server)
	myConn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("Failed to dial for MySQL: %v", err)
	}
	defer myConn.Close()

	// Write nothing. Wait for Sniffer to timeout (100ms) and route to ProtocolMySQL
	myResp := make([]byte, len(ProtocolMySQL))
	myConn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, err := myConn.Read(myResp)
	if err != nil {
		t.Fatalf("MySQL sniffer read failed: %v", err)
	}
	if string(myResp[:n]) != string(ProtocolMySQL) {
		t.Fatalf("Expected MySQL routing via timeout, got: %s", string(myResp[:n]))
	}
}
