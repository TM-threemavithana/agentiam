package proxy_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"

	"github.com/jackc/pgx/v5/pgproto3"
)

// TestDecoder_GO_2026_4518_MalformedDataRow verifies that malformed DataRow packets
// with invalid column lengths (such as negative lengths other than -1, or truncated data)
// return a clean error from the pgx/v5 decoder without panicking or crashing the process.
func TestDecoder_GO_2026_4518_MalformedDataRow(t *testing.T) {
	testCases := []struct {
		name        string
		payload     []byte
		expectPanic bool
	}{
		{
			name: "DataRow_NegativeFieldLength_MinusTwo",
			payload: func() []byte {
				// Packet type 'D' (DataRow)
				// Length (4 bytes int32 including the length field itself = 4 + 2 + 4 = 10)
				// Field count (int16 = 1)
				// Field length (int32 = -2) -> invalid negative length (only -1 is NULL)
				buf := new(bytes.Buffer)
				buf.WriteByte('D')
				binary.Write(buf, binary.BigEndian, int32(10))
				binary.Write(buf, binary.BigEndian, int16(1))
				binary.Write(buf, binary.BigEndian, int32(-2))
				return buf.Bytes()
			}(),
		},
		{
			name: "DataRow_TruncatedValueBody",
			payload: func() []byte {
				// Field length specifies 20 bytes, but stream ends after 4 bytes
				buf := new(bytes.Buffer)
				buf.WriteByte('D')
				binary.Write(buf, binary.BigEndian, int32(14))
				binary.Write(buf, binary.BigEndian, int16(1))
				binary.Write(buf, binary.BigEndian, int32(20))
				buf.Write([]byte("test"))
				return buf.Bytes()
			}(),
		},
		{
			name: "DataRow_ExcessiveFieldLength_Int32Max",
			payload: func() []byte {
				// Packet length is 10, but field length claims 0x7FFFFFFF
				buf := new(bytes.Buffer)
				buf.WriteByte('D')
				binary.Write(buf, binary.BigEndian, int32(10))
				binary.Write(buf, binary.BigEndian, int16(1))
				binary.Write(buf, binary.BigEndian, int32(0x7FFFFFFF))
				return buf.Bytes()
			}(),
		},
		{
			name: "DataRow_CorruptFieldCount_FieldCountClaimsTen_Truncated",
			payload: func() []byte {
				// Packet claims 10 fields, but payload contains no field descriptors
				buf := new(bytes.Buffer)
				buf.WriteByte('D')
				binary.Write(buf, binary.BigEndian, int32(6))
				binary.Write(buf, binary.BigEndian, int16(10))
				return buf.Bytes()
			}(),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("CRITICAL SECURITY FAILURE: Decoder panicked on malformed packet: %v", r)
				}
			}()

			reader := bytes.NewReader(tc.payload)
			frontend := pgproto3.NewFrontend(reader, io.Discard)

			msg, err := frontend.Receive()
			if err == nil {
				t.Fatalf("Expected error for malformed payload %s, but got valid msg: %T (%+v)", tc.name, msg, msg)
			}
			t.Logf("Malformed packet successfully rejected with safe error: %v", err)
		})
	}
}

// TestDecoder_ExceededMaxBodyLen_Frontend verifies that pgproto3.Frontend.SetMaxBodyLen
// explicitly enforces maximum message size boundaries and returns *pgproto3.ExceededMaxBodyLenErr.
func TestDecoder_ExceededMaxBodyLen_Frontend(t *testing.T) {
	const maxLen = 512

	// Construct an oversized CommandComplete message (type 'C') claiming 1024 bytes body
	oversizedMsg := new(bytes.Buffer)
	oversizedMsg.WriteByte('C')
	binary.Write(oversizedMsg, binary.BigEndian, int32(1028)) // 4 bytes length + 1024 bytes body
	oversizedMsg.Write(make([]byte, 1024))

	frontend := pgproto3.NewFrontend(bytes.NewReader(oversizedMsg.Bytes()), io.Discard)
	frontend.SetMaxBodyLen(maxLen)

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Decoder panicked on oversized message: %v", r)
		}
	}()

	msg, err := frontend.Receive()
	if err == nil {
		t.Fatalf("Expected ExceededMaxBodyLenErr, but got valid msg: %T", msg)
	}

	var maxLenErr *pgproto3.ExceededMaxBodyLenErr
	if !errors.As(err, &maxLenErr) {
		t.Fatalf("Expected error to match *pgproto3.ExceededMaxBodyLenErr, got: %T (%v)", err, err)
	}

	if maxLenErr.MaxExpectedBodyLen != maxLen {
		t.Errorf("Expected MaxExpectedBodyLen %d, got %d", maxLen, maxLenErr.MaxExpectedBodyLen)
	}
	if maxLenErr.ActualBodyLen != 1024 {
		t.Errorf("Expected ActualBodyLen 1024, got %d", maxLenErr.ActualBodyLen)
	}
}

// TestDecoder_ExceededMaxBodyLen_Backend verifies that pgproto3.Backend.SetMaxBodyLen
// explicitly enforces maximum client message size boundaries and returns *pgproto3.ExceededMaxBodyLenErr.
func TestDecoder_ExceededMaxBodyLen_Backend(t *testing.T) {
	const maxLen = 256

	// Construct an oversized Query message (type 'Q') claiming 512 bytes body
	oversizedMsg := new(bytes.Buffer)
	oversizedMsg.WriteByte('Q')
	binary.Write(oversizedMsg, binary.BigEndian, int32(516)) // 4 bytes length + 512 bytes body
	oversizedMsg.Write(make([]byte, 512))

	backend := pgproto3.NewBackend(bytes.NewReader(oversizedMsg.Bytes()), io.Discard)
	backend.SetMaxBodyLen(maxLen)

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Decoder panicked on oversized client message: %v", r)
		}
	}()

	msg, err := backend.Receive()
	if err == nil {
		t.Fatalf("Expected ExceededMaxBodyLenErr, but got valid msg: %T", msg)
	}

	var maxLenErr *pgproto3.ExceededMaxBodyLenErr
	if !errors.As(err, &maxLenErr) {
		t.Fatalf("Expected error to match *pgproto3.ExceededMaxBodyLenErr, got: %T (%v)", err, err)
	}

	if maxLenErr.MaxExpectedBodyLen != maxLen {
		t.Errorf("Expected MaxExpectedBodyLen %d, got %d", maxLen, maxLenErr.MaxExpectedBodyLen)
	}
	if maxLenErr.ActualBodyLen != 512 {
		t.Errorf("Expected ActualBodyLen 512, got %d", maxLenErr.ActualBodyLen)
	}
}

// TestDecoder_ProtocolCompatibility_Lifecycle verifies full bidirectional protocol message
// serialization, buffering, flushing, and decoding between pgx/v5 Backend and Frontend.
func TestDecoder_ProtocolCompatibility_Lifecycle(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	frontend := pgproto3.NewFrontend(clientConn, clientConn)
	frontend.SetMaxBodyLen(1024 * 1024)

	backend := pgproto3.NewBackend(serverConn, serverConn)
	backend.SetMaxBodyLen(1024 * 1024)

	errCh := make(chan error, 1)

	// Client goroutine (runs all frontend operations sequentially)
	go func() {
		frontend.Send(&pgproto3.StartupMessage{
			ProtocolVersion: pgproto3.ProtocolVersionNumber,
			Parameters: map[string]string{
				"user":     "agent-test",
				"database": "production",
			},
		})
		if err := frontend.Flush(); err != nil {
			errCh <- err
			return
		}

		// Receive AuthOk, ParameterStatus, ReadyForQuery
		msg1, err := frontend.Receive()
		if err != nil {
			errCh <- err
			return
		}
		if _, ok := msg1.(*pgproto3.AuthenticationOk); !ok {
			errCh <- errors.New("expected AuthenticationOk")
			return
		}

		msg2, err := frontend.Receive()
		if err != nil {
			errCh <- err
			return
		}
		if _, ok := msg2.(*pgproto3.ParameterStatus); !ok {
			errCh <- errors.New("expected ParameterStatus")
			return
		}

		msg3, err := frontend.Receive()
		if err != nil {
			errCh <- err
			return
		}
		if _, ok := msg3.(*pgproto3.ReadyForQuery); !ok {
			errCh <- errors.New("expected ReadyForQuery")
			return
		}

		// Send extended query messages
		frontend.Send(&pgproto3.Parse{Name: "stmt1", Query: "SELECT $1::int", ParameterOIDs: []uint32{23}})
		frontend.Send(&pgproto3.Bind{PreparedStatement: "stmt1", Parameters: [][]byte{[]byte("42")}})
		frontend.Send(&pgproto3.Describe{ObjectType: 'P'})
		frontend.Send(&pgproto3.Execute{MaxRows: 0})
		frontend.Send(&pgproto3.Sync{})
		if err := frontend.Flush(); err != nil {
			errCh <- err
			return
		}

		errCh <- nil
	}()

	// Server execution (runs all backend operations sequentially in main test goroutine)
	startup, err := backend.ReceiveStartupMessage()
	if err != nil {
		t.Fatalf("Failed to receive startup message: %v", err)
	}
	startMsg, ok := startup.(*pgproto3.StartupMessage)
	if !ok || startMsg.Parameters["user"] != "agent-test" {
		t.Fatalf("Unexpected startup message: %+v", startup)
	}

	backend.Send(&pgproto3.AuthenticationOk{})
	backend.Send(&pgproto3.ParameterStatus{Name: "server_version", Value: "15.0"})
	backend.Send(&pgproto3.ReadyForQuery{TxStatus: 'I'})
	if err := backend.Flush(); err != nil {
		t.Fatalf("Failed to flush server auth messages: %v", err)
	}

	for _, expectedType := range []string{"*pgproto3.Parse", "*pgproto3.Bind", "*pgproto3.Describe", "*pgproto3.Execute", "*pgproto3.Sync"} {
		m, err := backend.Receive()
		if err != nil {
			t.Fatalf("Failed receiving %s: %v", expectedType, err)
		}
		typeName := ""
		switch m.(type) {
		case *pgproto3.Parse:
			typeName = "*pgproto3.Parse"
		case *pgproto3.Bind:
			typeName = "*pgproto3.Bind"
		case *pgproto3.Describe:
			typeName = "*pgproto3.Describe"
		case *pgproto3.Execute:
			typeName = "*pgproto3.Execute"
		case *pgproto3.Sync:
			typeName = "*pgproto3.Sync"
		default:
			t.Fatalf("Unexpected message type: %T", m)
		}
		if typeName != expectedType {
			t.Errorf("Expected %s, got %s", expectedType, typeName)
		}
	}

	if err := <-errCh; err != nil {
		t.Fatalf("Client error: %v", err)
	}
}
