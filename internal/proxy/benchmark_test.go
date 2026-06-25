package proxy

import (
	"bytes"
	"net"
	"testing"
	"time"
)

// mockConn simulates a network connection with pre-filled read buffers.
type mockConn struct {
	readBuf *bytes.Buffer
}

func (m *mockConn) Read(b []byte) (n int, err error) {
	if m.readBuf.Len() == 0 {
		// Simulate a read timeout (no bytes sent by client)
		time.Sleep(1 * time.Microsecond)
		return 0, net.ErrClosed
	}
	return m.readBuf.Read(b)
}

func (m *mockConn) Write(b []byte) (n int, err error) {
	return len(b), nil
}

func (m *mockConn) Close() error {
	return nil
}

func (m *mockConn) LocalAddr() net.Addr {
	return &net.TCPAddr{}
}

func (m *mockConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{}
}

func (m *mockConn) SetDeadline(t time.Time) error {
	return nil
}

func (m *mockConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (m *mockConn) SetWriteDeadline(t time.Time) error {
	return nil
}

// BenchmarkSniffProtocol Postgres measures the overhead of sniffing a Postgres signature.
func BenchmarkSniffProtocol_Postgres(b *testing.B) {
	signature := []byte{0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x2f} // SSLRequest signature

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		conn := &mockConn{readBuf: bytes.NewBuffer(signature)}
		_, sniffedConn, err := SniffProtocol(conn, 100*time.Millisecond)
		if err != nil {
			b.Fatalf("unexpected error: %v", err)
		}
		// Read from the sniffed connection to verify replay doesn't alloc heavily
		buf := make([]byte, 8)
		_, _ = sniffedConn.Read(buf)
	}
}

// BenchmarkSniffProtocol MySQL measures the overhead of sniffing a MySQL connection (timeout-based).
func BenchmarkSniffProtocol_MySQL(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		conn := &mockConn{readBuf: bytes.NewBuffer(nil)}
		// We use a 1 microsecond timeout for the benchmark to prevent the benchmark from hanging for hours
		_, _, err := SniffProtocol(conn, 1*time.Microsecond)
		if err != nil && err != net.ErrClosed {
			b.Fatalf("unexpected error: %v", err)
		}
	}
}
