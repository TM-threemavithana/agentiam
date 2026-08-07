package proxy

import (
	"encoding/json"
	"net"
	"os"
	"sync"
)

type AuditSink interface {
	Write(event AuditEvent) error
	Close() error
}

type FileAuditSink struct {
	file *os.File
	mu   sync.Mutex
}

func NewFileAuditSink(path string) (*FileAuditSink, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
	if err != nil {
		return nil, err
	}
	return &FileAuditSink{file: f}, nil
}

func (s *FileAuditSink) Write(event AuditEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	b, err := json.Marshal(event)
	if err != nil {
		return err
	}
	_, err = s.file.Write(append(b, '\n'))
	return err
}

func (s *FileAuditSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.file != nil {
		return s.file.Close()
	}
	return nil
}

type NetworkAuditSink struct {
	network string
	address string
	conn    net.Conn
	mu      sync.Mutex
}

func NewNetworkAuditSink(network, address string) (*NetworkAuditSink, error) {
	conn, err := net.Dial(network, address)
	if err != nil {
		return nil, err
	}
	return &NetworkAuditSink{network: network, address: address, conn: conn}, nil
}

func (s *NetworkAuditSink) Write(event AuditEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	b, err := json.Marshal(event)
	if err != nil {
		return err
	}

	if s.conn == nil {
		conn, err := net.Dial(s.network, s.address)
		if err != nil {
			return err
		}
		s.conn = conn
	}

	_, err = s.conn.Write(append(b, '\n'))
	if err != nil {
		s.conn.Close()
		s.conn = nil
		return err
	}
	return nil
}

func (s *NetworkAuditSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.conn != nil {
		return s.conn.Close()
	}
	return nil
}
