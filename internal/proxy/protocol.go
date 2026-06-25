package proxy

import (
	"context"
	"net"
)

// ProtocolHandler defines a generic interface for SQL wire-protocol proxies.
// This allows AgentIAM to route MySQL, Postgres, or BigQuery natively by plugging in the appropriate protocol engine.
//
// Protocol Specifications:
// - PostgreSQL: Operates on a Type/Length/Value (TLV) message framing format (e.g. 'Q' for Query, 'P' for Parse).
//   Reference: https://www.postgresql.org/docs/current/protocol-message-formats.html
// - MySQL: Operates on a Packet Length (3 bytes) + Sequence ID (1 byte) + Payload format.
//   Command packets use a 1-byte command type (e.g. 0x03 for COM_QUERY).
//   Reference: https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_basic_packets.html
type ProtocolHandler interface {
	HandleSession(ctx context.Context, conn net.Conn) error
}
