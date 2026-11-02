package proxy

import (
	"context"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-mysql-org/go-mysql/client"
	"github.com/go-mysql-org/go-mysql/mysql"
	"github.com/go-mysql-org/go-mysql/packet"
)

// Helper to construct a mock MySQLUpstreamConn backed by net.Pipe.
func createMockUpstreamConn(clientPipe, serverPipe net.Conn) *MySQLUpstreamConn {
	pktConn := packet.NewConn(clientPipe)
	c := &client.Conn{
		Conn: pktConn,
	}
	return &MySQLUpstreamConn{
		Conn: c,
	}
}

func TestMySQLUpstreamConn_Close_Idempotent(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c2.Close()

	u := createMockUpstreamConn(c1, c2)
	// Concurrent close calls should not panic or race
	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			u.Close()
		}()
	}
	wg.Wait()

	if u.Conn != nil {
		t.Fatal("expected u.Conn to be nil after Close")
	}

	// Calling Close on nil u should not panic
	var nilConn *MySQLUpstreamConn
	nilConn.Close()
}

func TestMySQLUpstreamConn_ResetConnection_Preconditions(t *testing.T) {
	// Nil connection
	var nilConn *MySQLUpstreamConn
	if err := nilConn.ResetConnection(); err == nil {
		t.Fatal("expected error resetting nil connection, got nil")
	}

	// Broken connection
	broken := &MySQLUpstreamConn{}
	broken.Broken.Store(true)
	if err := broken.ResetConnection(); err == nil {
		t.Fatal("expected error resetting broken connection, got nil")
	}

	// Nil client.Conn
	noConn := &MySQLUpstreamConn{}
	if err := noConn.ResetConnection(); err == nil {
		t.Fatal("expected error resetting connection with nil client.Conn, got nil")
	}
}

func TestMySQLUpstreamConn_ResetConnection_Success(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	u := createMockUpstreamConn(c1, c2)

	// Server goroutine: verify COM_RESET_CONNECTION packet and send OK response
	serverErrCh := make(chan error, 1)
	go func() {
		// Read 4-byte header
		header := make([]byte, 4)
		if _, err := io.ReadFull(c2, header); err != nil {
			serverErrCh <- err
			return
		}
		length := int(uint32(header[0]) | uint32(header[1])<<8 | uint32(header[2])<<16)
		payload := make([]byte, length)
		if _, err := io.ReadFull(c2, payload); err != nil {
			serverErrCh <- err
			return
		}
		if len(payload) != 1 || payload[0] != mysql.COM_RESET_CONNECTION {
			serverErrCh <- io.ErrUnexpectedEOF
			return
		}

		// Send OK packet: len=7, seq=1, header=0x00, affected_rows=0, last_insert_id=0, status=0x0002 (SERVER_STATUS_AUTOCOMMIT)
		okPacket := []byte{
			0x07, 0x00, 0x00, 0x01, // 4-byte header (len=7, seq=1)
			0x00,                   // OK header
			0x00,                   // 0 affected rows
			0x00,                   // 0 last insert id
			0x02, 0x00,             // SERVER_STATUS_AUTOCOMMIT
			0x00, 0x00,             // 0 warnings
		}
		_, err := c2.Write(okPacket)
		serverErrCh <- err
	}()

	if err := u.ResetConnection(); err != nil {
		t.Fatalf("expected successful ResetConnection, got: %v", err)
	}

	if err := <-serverErrCh; err != nil {
		t.Fatalf("server mock encountered error: %v", err)
	}

	if u.Broken.Load() {
		t.Fatal("connection should not be marked broken after successful reset")
	}
}

func TestMySQLUpstreamConn_ResetConnection_ErrorPacket_Discards(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	u := createMockUpstreamConn(c1, c2)

	go func() {
		header := make([]byte, 4)
		_, _ = io.ReadFull(c2, header)
		payload := make([]byte, 1)
		_, _ = io.ReadFull(c2, payload)

		// Send MySQL ERR packet: 0xff, error_code=1105 (0x0451), sql_state="#HY000", message="Unknown error"
		// len = 1 (0xff) + 2 (code) + 1 (#) + 5 (state) + 13 (msg) = 22 bytes
		errPacket := []byte{
			0x16, 0x00, 0x00, 0x01, // len=22, seq=1
			0xff,                   // ERR header
			0x51, 0x04,             // error code 1105
			'#', 'H', 'Y', '0', '0', '0', // SQL state
			'U', 'n', 'k', 'n', 'o', 'w', 'n', ' ', 'e', 'r', 'r', 'o', 'r',
		}
		_, _ = c2.Write(errPacket)
	}()

	err := u.ResetConnection()
	if err == nil {
		t.Fatal("expected error on ERR packet response, got nil")
	}
	if !u.Broken.Load() {
		t.Fatal("connection must be marked broken after ERR packet")
	}
}

func TestMySQLUpstreamConn_ResetConnection_MalformedPacket_Discards(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	u := createMockUpstreamConn(c1, c2)

	go func() {
		header := make([]byte, 4)
		_, _ = io.ReadFull(c2, header)
		payload := make([]byte, 1)
		_, _ = io.ReadFull(c2, payload)

		// Send bogus packet header (0x42 instead of 0x00 or 0xff)
		badPacket := []byte{
			0x01, 0x00, 0x00, 0x01,
			0x42,
		}
		_, _ = c2.Write(badPacket)
	}()

	err := u.ResetConnection()
	if err == nil {
		t.Fatal("expected error on malformed packet response, got nil")
	}
	if !u.Broken.Load() {
		t.Fatal("connection must be marked broken after malformed packet")
	}
}

func TestMySQLUpstreamConn_ResetConnection_ServerDisconnect_Discards(t *testing.T) {
	c1, c2 := net.Pipe()
	defer c1.Close()

	u := createMockUpstreamConn(c1, c2)

	go func() {
		header := make([]byte, 4)
		_, _ = io.ReadFull(c2, header)
		payload := make([]byte, 1)
		_, _ = io.ReadFull(c2, payload)
		// Immediately close server side
		c2.Close()
	}()

	err := u.ResetConnection()
	if err == nil {
		t.Fatal("expected error on disconnected server, got nil")
	}
	if !u.Broken.Load() {
		t.Fatal("connection must be marked broken after server disconnect")
	}
}

func TestMySQLPool_Release_DiscardAndReplace(t *testing.T) {
	logger := NewLogger(io.Discard)
	pool := NewMySQLPool("127.0.0.1:3306", "root", "", "testdb", 2, logger)

	// Create mock broken connection
	brokenConn := &MySQLUpstreamConn{}
	brokenConn.Broken.Store(true)

	// Release broken connection into pool
	// discardAndReplace will attempt p.dial(), which fails because no real server on 127.0.0.1:3306
	// but it must insert a placeholder so pool capacity is preserved and no panic occurs
	pool.Release(brokenConn)

	// Channel must have 1 item (placeholder)
	select {
	case item := <-pool.conns:
		if item == brokenConn {
			t.Fatal("dirty/broken connection must NEVER be returned to the pool")
		}
		if !item.Broken.Load() {
			t.Fatal("placeholder connection should be marked broken")
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("pool channel starved: no placeholder inserted after failed replacement")
	}
}

func TestMySQLPool_Concurrency_AcquireReleaseClose(t *testing.T) {
	logger := NewLogger(io.Discard)
	pool := NewMySQLPool("127.0.0.1:3306", "root", "", "testdb", 5, logger)

	// Pre-fill pool with 5 mock connections that succeed on reset
	for i := 0; i < 5; i++ {
		c1, c2 := net.Pipe()
		u := createMockUpstreamConn(c1, c2)
		go func(srv net.Conn) {
			for {
				header := make([]byte, 4)
				if _, err := io.ReadFull(srv, header); err != nil {
					return
				}
				length := int(uint32(header[0]) | uint32(header[1])<<8 | uint32(header[2])<<16)
				payload := make([]byte, length)
				if _, err := io.ReadFull(srv, payload); err != nil {
					return
				}
				// Return OK packet
				okPacket := []byte{0x07, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00}
				if _, err := srv.Write(okPacket); err != nil {
					return
				}
			}
		}(c2)
		pool.conns <- u
	}
	pool.ready.Store(true)

	var ops atomic.Int64
	var wg sync.WaitGroup
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()

	// 10 concurrent worker goroutines
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				default:
					u, err := pool.Acquire(ctx)
					if err != nil {
						return
					}
					ops.Add(1)
					time.Sleep(1 * time.Millisecond)
					pool.Release(u)
				}
			}
		}()
	}

	wg.Wait()
	pool.Close()

	if ops.Load() == 0 {
		t.Fatal("expected concurrent acquire/release operations to execute successfully")
	}
}
