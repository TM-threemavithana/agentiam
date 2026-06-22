package proxy

import (
	"log"
	"net"
	"agentiam/internal/policy"
)

type Server struct {
	addr        string
	upstreamDSN string
	store       *policy.Store
}

func NewServer(addr, upstreamDSN string, store *policy.Store) *Server {
	return &Server{
		addr:        addr,
		upstreamDSN: upstreamDSN,
		store:       store,
	}
}

func (s *Server) Start() error {
	l, err := net.Listen("tcp", s.addr)
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
		go s.handleConnection(conn)
	}
}

func (s *Server) handleConnection(clientConn net.Conn) {
	log.Printf("New connection from %s", clientConn.RemoteAddr())
	
	session := NewSession(clientConn, s.upstreamDSN, s.store)
	defer session.Close()

	if err := session.Run(); err != nil {
		log.Printf("Session error for %s: %v", clientConn.RemoteAddr(), err)
	}
}
