package proxy

import (
	"bytes"
	"io"
	"net"
	"time"
)

type ProtocolType string

const (
	ProtocolPostgres ProtocolType = "postgres"
	ProtocolMySQL    ProtocolType = "mysql"
	ProtocolUnknown  ProtocolType = "unknown"
)

// PrefixConn wraps a net.Conn and replays a buffered prefix before delegating to the underlying conn.
type PrefixConn struct {
	net.Conn
	prefix io.Reader
}

func (p *PrefixConn) Read(b []byte) (int, error) {
	n, err := p.prefix.Read(b)
	if n > 0 || err != io.EOF {
		return n, err
	}
	return p.Conn.Read(b)
}

// SniffProtocol reads up to 4 bytes with a short timeout to determine the protocol.
// - Postgres clients send a StartupMessage immediately.
// - MySQL servers send a Greeting immediately (so clients send nothing).
func SniffProtocol(conn net.Conn, timeout time.Duration) (ProtocolType, net.Conn, error) {
	conn.SetReadDeadline(time.Now().Add(timeout))

	var buf [4]byte
	n, err := io.ReadAtLeast(conn, buf[:], 1)

	// Clear the deadline for normal operations
	conn.SetReadDeadline(time.Time{})

	if err != nil {
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			// Timeout -> Client sent nothing -> It expects Server Greeting -> MySQL
			return ProtocolMySQL, conn, nil
		}
		// Connection broke or EOF
		return ProtocolUnknown, nil, err
	}

	// Client sent data immediately. It's likely PostgreSQL (or another client-first protocol)
	prefixConn := &PrefixConn{
		Conn:   conn,
		prefix: bytes.NewReader(buf[:n]),
	}

	// Postgres StartupMessage or SSLRequest starts with a length integer.
	// Since max message size is usually < 16MB, the first byte is usually 0x00.
	if buf[0] == 0x00 {
		return ProtocolPostgres, prefixConn, nil
	}

	// Fallback to postgres for now if we read something unexpected,
	// the protocol handler will reject it cleanly.
	return ProtocolPostgres, prefixConn, nil
}
