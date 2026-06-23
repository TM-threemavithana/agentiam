package proxy

import (
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	
	"agentiam/internal/policy"
)

type Server struct {
	addr        string
	upstreamDSN string
	store       *policy.Store
	maxConns    int
	sem         chan struct{}
	tlsConfig   *tls.Config
}

func NewServer(addr, upstreamDSN string, store *policy.Store) *Server {
	maxConns := 100
	if envMax := os.Getenv("AGENTIAM_MAX_CONNECTIONS"); envMax != "" {
		if val, err := strconv.Atoi(envMax); err == nil && val > 0 {
			maxConns = val
		}
	}
	return &Server{
		addr:        addr,
		upstreamDSN: upstreamDSN,
		store:       store,
		maxConns:    maxConns,
		sem:         make(chan struct{}, maxConns),
	}
}

func (s *Server) Start() error {
	var l net.Listener
	var err error

	certPath := os.Getenv("AGENTIAM_TLS_CERT")
	keyPath := os.Getenv("AGENTIAM_TLS_KEY")

	if certPath != "" && keyPath != "" {
		cert, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			return fmt.Errorf("failed to load TLS pair: %w", err)
		}
		s.tlsConfig = &tls.Config{Certificates: []tls.Certificate{cert}}
		log.Printf("Starting proxy on %s with TLS REQUIRED (Max Conns: %d)", s.addr, s.maxConns)
	} else {
		log.Printf("Starting proxy on %s in PLAINTEXT mode (Max Conns: %d)", s.addr, s.maxConns)
	}

	l, err = net.Listen("tcp", s.addr)
	if err != nil {
		return err
	}
	defer l.Close()

	for {
		conn, err := l.Accept()
		if err != nil {
			log.Printf("Accept error: %v", err)
			continue
		}
		
		select {
		case s.sem <- struct{}{}:
			go s.handleConnection(conn)
		default:
			log.Printf("Max connections reached (%d), rejecting %s", s.maxConns, conn.RemoteAddr())
			conn.Close()
		}
	}
}

func (s *Server) handleConnection(clientConn net.Conn) {
	defer func() { <-s.sem }() // Release semaphore
	log.Printf("New connection from %s", clientConn.RemoteAddr())
	
	session := NewSession(clientConn, s.upstreamDSN, s.store, s.tlsConfig)
	defer session.Close()

	if err := session.Run(); err != nil {
		log.Printf("Session error for %s: %v", clientConn.RemoteAddr(), err)
	}
}
