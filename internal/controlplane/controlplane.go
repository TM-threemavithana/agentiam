package controlplane

import (
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"
)

// Server coordinates configuration pushes to connected gateway client nodes.
type Server struct {
	addr     string
	logger   *slog.Logger
	listener net.Listener
	mu       sync.Mutex
	clients  map[net.Conn]struct{}
	stopCh   chan struct{}
}

func NewServer(addr string, logger *slog.Logger) *Server {
	return &Server{
		addr:    addr,
		logger:  logger,
		clients: make(map[net.Conn]struct{}),
		stopCh:  make(chan struct{}),
	}
}

func (s *Server) Start() error {
	l, err := net.Listen("tcp", s.addr)
	if err != nil {
		return err
	}
	s.listener = l
	s.logger.Info("Control Plane Server listening", "addr", s.addr)

	go func() {
		for {
			conn, err := s.listener.Accept()
			if err != nil {
				select {
				case <-s.stopCh:
					return
				default:
					s.logger.Error("Control Plane Server accept error", "error", err)
					continue
				}
			}
			s.registerClient(conn)
			go s.handleClient(conn)
		}
	}()
	return nil
}

func (s *Server) registerClient(conn net.Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clients[conn] = struct{}{}
	s.logger.Info("Control Plane Client connected", "remote", conn.RemoteAddr().String())
}

func (s *Server) unregisterClient(conn net.Conn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.clients, conn)
	conn.Close()
	s.logger.Info("Control Plane Client disconnected", "remote", conn.RemoteAddr().String())
}

func (s *Server) handleClient(conn net.Conn) {
	defer s.unregisterClient(conn)
	// We only need to check if the client closes the connection.
	// Keep-alive checks or read loops can check for EOF.
	buf := make([]byte, 1)
	for {
		_, err := conn.Read(buf)
		if err != nil {
			return
		}
	}
}

// BroadcastConfig pushes a new configuration payload to all connected clients.
func (s *Server) BroadcastConfig(configBytes []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.logger.Info("Broadcasting new config to clients", "count", len(s.clients), "size", len(configBytes))
	length := uint32(len(configBytes))
	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, length)

	for conn := range s.clients {
		go func(c net.Conn) {
			c.SetWriteDeadline(time.Now().Add(5 * time.Second))
			_, err := c.Write(header)
			if err != nil {
				s.logger.Error("Failed to write header to client", "error", err)
				s.unregisterClient(c)
				return
			}
			_, err = c.Write(configBytes)
			if err != nil {
				s.logger.Error("Failed to write payload to client", "error", err)
				s.unregisterClient(c)
				return
			}
		}(conn)
	}
}

func (s *Server) Close() {
	close(s.stopCh)
	if s.listener != nil {
		s.listener.Close()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for conn := range s.clients {
		conn.Close()
	}
}

// Client connects to the control plane and reads configuration stream.
type Client struct {
	addr     string
	logger   *slog.Logger
	onUpdate func([]byte)
	stopCh   chan struct{}
}

func NewClient(addr string, logger *slog.Logger, onUpdate func([]byte)) *Client {
	return &Client{
		addr:     addr,
		logger:   logger,
		onUpdate: onUpdate,
		stopCh:   make(chan struct{}),
	}
}

func (c *Client) Start() {
	go func() {
		for {
			select {
			case <-c.stopCh:
				return
			default:
			}

			conn, err := net.Dial("tcp", c.addr)
			if err != nil {
				c.logger.Error("Control Plane Client failed to connect, retrying in 2s", "addr", c.addr, "error", err)
				time.Sleep(2 * time.Second)
				continue
			}

			c.logger.Info("Control Plane Client connected to server", "addr", c.addr)
			err = c.readStream(conn)
			if err != nil {
				c.logger.Error("Control Plane Client stream error", "error", err)
			}
			conn.Close()
			time.Sleep(2 * time.Second) // backoff before reconnecting
		}
	}()
}

func (c *Client) readStream(conn net.Conn) error {
	header := make([]byte, 4)
	for {
		_, err := io.ReadFull(conn, header)
		if err != nil {
			return err
		}

		length := binary.BigEndian.Uint32(header)
		payload := make([]byte, length)
		_, err = io.ReadFull(conn, payload)
		if err != nil {
			return err
		}

		c.logger.Info("Control Plane Client received configuration update", "size", length)
		c.onUpdate(payload)
	}
}

func (c *Client) Close() {
	close(c.stopCh)
}
