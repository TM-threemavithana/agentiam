package proxy

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestFileAuditSink(t *testing.T) {
	tmpDir := t.TempDir()
	logPath := filepath.Join(tmpDir, "audit.json")

	sink, err := NewFileAuditSink(logPath)
	if err != nil {
		t.Fatalf("failed to create FileAuditSink: %v", err)
	}
	defer sink.Close()

	evt := AuditEvent{
		Event:     "test_event",
		ClientID:  "agent_1",
		SQL:       "SELECT 1",
		Status:    "success",
		Timestamp: "2026-07-06T12:00:00Z",
	}

	if err := sink.Write(evt); err != nil {
		t.Fatalf("failed to write event: %v", err)
	}

	sink.Close()

	content, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("failed to read log path: %v", err)
	}

	var readEvt AuditEvent
	if err := json.Unmarshal(content, &readEvt); err != nil {
		t.Fatalf("failed to parse log line: %v", err)
	}

	if readEvt.Event != evt.Event || readEvt.ClientID != evt.ClientID || readEvt.SQL != evt.SQL {
		t.Errorf("mismatched log contents: %+v", readEvt)
	}
}

func TestNetworkAuditSinkUDP(t *testing.T) {
	// Start a local UDP listener
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to resolve UDP address: %v", err)
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		t.Fatalf("failed to listen UDP: %v", err)
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().String()

	sink, err := NewNetworkAuditSink("udp", localAddr)
	if err != nil {
		t.Fatalf("failed to create NetworkAuditSink: %v", err)
	}
	defer sink.Close()

	evt := AuditEvent{
		Event:     "net_event",
		ClientID:  "agent_net",
		SQL:       "SELECT net",
		Status:    "allowed",
		Timestamp: "2026-07-06T12:00:01Z",
	}

	if err := sink.Write(evt); err != nil {
		t.Fatalf("failed to write net event: %v", err)
	}

	// Read UDP packet
	buf := make([]byte, 1024)
	n, _, err := conn.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("failed to read from UDP: %v", err)
	}

	var readEvt AuditEvent
	if err := json.Unmarshal(buf[:n], &readEvt); err != nil {
		t.Fatalf("failed to unmarshal read net event: %v", err)
	}

	if readEvt.ClientID != evt.ClientID || readEvt.SQL != evt.SQL {
		t.Errorf("mismatched UDP log: %+v", readEvt)
	}
}
