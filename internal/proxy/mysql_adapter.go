package proxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"strings"

	"github.com/tm-threemavithana/agentiam/internal/ast"
	"github.com/tm-threemavithana/agentiam/internal/policy"

	"github.com/go-mysql-org/go-mysql/mysql"
	"github.com/go-mysql-org/go-mysql/server"
	driver "github.com/go-sql-driver/mysql"
)

// MySQLProtocolHandler implements the ProtocolHandler interface for the MySQL wire protocol.
type MySQLProtocolHandler struct {
	store        *policy.Store
	logger       *Logger
	upstreamDSN  string
	pool         *MySQLPool
	server       *Server
	insecureAuth bool
}

// NewMySQLProtocolHandler creates a new handler capable of routing and parsing MySQL client connections.
func NewMySQLProtocolHandler(store *policy.Store, logger *Logger, server *Server, insecureAuth bool) *MySQLProtocolHandler {
	return &MySQLProtocolHandler{store: store, logger: logger, upstreamDSN: "root@tcp(127.0.0.1:3306)/", server: server, insecureAuth: insecureAuth}
}

// InitPool initializes the upstream *sql.DB connection pool.
func (h *MySQLProtocolHandler) InitPool() error {
	dsn := h.upstreamDSN
	if h.server != nil && h.server.upstreamDSN != "" {
		dsn = h.server.upstreamDSN
	}

	start := strings.Index(dsn, "(")
	end := strings.Index(dsn, ")")
	if start == -1 || end <= start+1 || strings.TrimSpace(dsn[start+1:end]) == "" {
		return fmt.Errorf("invalid upstream MySQL DSN: missing explicit network address")
	}

	cfg, err := driver.ParseDSN(dsn)
	if err != nil {
		return fmt.Errorf("failed to parse upstream MySQL DSN: %w", err)
	}

	p := NewMySQLPool(cfg.Addr, cfg.User, cfg.Passwd, cfg.DBName, 50, h.logger)
	if err := p.Init(context.Background()); err != nil {
		return err
	}
	h.pool = p
	return nil
}

// SetPool sets a custom upstream connection pool on the handler (useful for testing pool isolation).
func (h *MySQLProtocolHandler) SetPool(p *MySQLPool) {
	h.pool = p
}

// Close releases the MySQL connection pool resources.
func (h *MySQLProtocolHandler) Close() error {
	if h.pool != nil {
		h.pool.Close()
	}
	return nil
}

// HandleSession implements the ProtocolHandler interface.
// It proxies the raw net.Conn through the go-mysql-org server implementation.
func (h *MySQLProtocolHandler) HandleSession(ctx context.Context, clientConn net.Conn) error {
	h.logger.Info("MySQL connection accepted", "remote_addr", clientConn.RemoteAddr().String())

	// Initialize the MySQL Proxy handler if not already initialized
	if h.pool == nil {
		if err := h.InitPool(); err != nil {
			h.logger.Error("Failed to initialize MySQL upstream pool", "error", err)
			return fmt.Errorf("upstream unavailable: %w", err)
		}
	}

	proxyHandler := &AgentIAMMySQLHandler{
		pool:   h.pool,
		logger: h.logger,
		server: h.server,
	}

	authHandler := &AgentIAMAuthHandler{
		store:        h.store,
		logger:       h.logger,
		insecureAuth: h.insecureAuth,
		mysqlHandler: proxyHandler,
	}

	var tlsCfg *tls.Config
	if h.server != nil && h.server.tlsConfig != nil {
		tlsCfg = h.server.tlsConfig
	}
	serverConf := server.NewServerWithAuth("8.0.11", 255, "mysql_native_password", nil, tlsCfg, authHandler)

	conn, err := serverConf.NewCustomizedConn(clientConn, authHandler, proxyHandler)
	if err != nil {
		h.logger.Error("MySQL Handshake failed", "error", err)
		return err
	}
	defer func() {
		if conn != nil && !conn.Closed() {
			conn.Close()
		}
	}()

	for {
		err := conn.HandleCommand()
		if err != nil {
			return err
		}
	}
}

// AgentIAMAuthHandler implements the MySQL server authentication interface.
type AgentIAMAuthHandler struct {
	store        *policy.Store
	logger       *Logger
	insecureAuth bool
	mysqlHandler *AgentIAMMySQLHandler
}

// Authenticate implements server.AuthenticationProvider.
func (a *AgentIAMAuthHandler) Authenticate(c *server.Conn, authPluginName string, clientAuthData []byte) error {
	clientID := c.GetUser()
	a.logger.Info("MySQL Authenticate attempt", "user", clientID, "plugin", authPluginName)

	var mtlsVerified bool
	var suppliedPassword string

	if c.Conn != nil && c.Conn.Conn != nil {
		if tlsConn, ok := c.Conn.Conn.(*tls.Conn); ok {
			state := tlsConn.ConnectionState()
			if len(state.PeerCertificates) > 0 {
				cert := state.PeerCertificates[0]
				if cert.Subject.CommonName == clientID {
					mtlsVerified = true
					suppliedPassword = ""
				} else {
					a.logger.Error("MySQL mTLS CN mismatch", "cn", cert.Subject.CommonName, "clientID", clientID)
				}
			}
		}
	}

	if !mtlsVerified && !a.insecureAuth {
		a.logger.Error("Client attempted cleartext authentication without --insecure-cleartext-auth flag")
		return fmt.Errorf("mTLS is required. Cleartext auth is disabled.")
	}

	if !mtlsVerified {
		if authPluginName == "mysql_clear_password" {
			suppliedPassword = string(bytes.TrimRight(clientAuthData, "\x00"))
		} else if authPluginName == "mysql_native_password" {
			if a.insecureAuth {
				if len(clientAuthData) == 0 || (len(clientAuthData) == 1 && clientAuthData[0] == 0) {
					suppliedPassword = ""
					mtlsVerified = true
				} else {
					return mysql.NewDefaultError(mysql.ER_ACCESS_DENIED_ERROR, clientID, c.RemoteAddr().String(), "YES")
				}
			} else {
				return fmt.Errorf("authentication plugin %s not supported without mTLS (use mysql_clear_password for password auth)", authPluginName)
			}
		} else {
			return fmt.Errorf("authentication plugin %s not supported", authPluginName)
		}
	}

	rules, _, err := a.store.GetRulesForAgent(clientID, suppliedPassword, mtlsVerified)
	if err != nil {
		a.logger.Error("MySQL Authentication failed", "user", clientID, "error", err)
		return fmt.Errorf("invalid Agent Credentials: %w", err)
	}

	if a.mysqlHandler != nil {
		a.mysqlHandler.clientID = clientID
		a.mysqlHandler.rules = rules
	}

	a.logger.Info("MySQL Authentication successful", "user", clientID)
	return nil
}

// Validate implements server.AuthenticationProvider.
func (a *AgentIAMAuthHandler) Validate(authPluginName string) bool {
	return authPluginName == "mysql_native_password" || authPluginName == "mysql_clear_password"
}

// GetCredential retrieves the password for a given user.
func (a *AgentIAMAuthHandler) GetCredential(username string) (server.Credential, bool, error) {
	if a.insecureAuth && username == "root" {
		return server.Credential{Passwords: []string{""}, AuthPluginName: "mysql_native_password"}, true, nil
	}
	if a.store != nil {
		if _, err := a.store.GetAgentKey(username); err == nil {
			return server.Credential{Passwords: []string{""}, AuthPluginName: "mysql_native_password"}, true, nil
		}
	}
	return server.Credential{}, false, nil
}

// OnAuthSuccess is called after a successful password authentication.
func (a *AgentIAMAuthHandler) OnAuthSuccess(conn *server.Conn) error {
	clientID := conn.GetUser()
	a.logger.Info("MySQL Auth Success", "user", clientID)

	if a.mysqlHandler != nil {
		a.mysqlHandler.clientID = clientID
		if a.store != nil {
			rules, _, err := a.store.GetRulesForAgent(clientID, "", true)
			if err != nil {
				a.logger.Error("MySQL failed to load rules after auth success", "user", clientID, "error", err)
				return fmt.Errorf("invalid Agent Credentials: %w", err)
			}
			a.mysqlHandler.rules = rules
		}
	}
	return nil
}

// OnAuthFailure is called after a failed password authentication.
func (a *AgentIAMAuthHandler) OnAuthFailure(conn *server.Conn, err error) {
	a.logger.Info("MySQL Auth Failed", "user", conn.GetUser(), "error", err)
}

// AgentIAMMySQLHandler intercepts COM_QUERY and proxies it upstream.
//
// Protocol Context (MySQL Client/Server Protocol):
//   - Command Packets: Sent by the client to the server. The first byte of the payload defines the command type.
//     0x03 = COM_QUERY (Text Protocol).
//     Reference: https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_com_query.html
//
// - Text Resultset: The server responds to COM_QUERY with a Text Resultset, which consists of:
//  1. Column Count Packet (Length-Encoded Integer)
//  2. Column Definition Packets (One per column)
//  3. EOF Packet (if CLIENT_DEPRECATE_EOF is not set)
//  4. Row Data Packets (One per row, values are length-encoded strings)
//  5. EOF Packet or OK Packet.
//     Reference: https://dev.mysql.com/doc/dev/mysql-server/latest/page_protocol_com_query_response_text_resultset.html
type AgentIAMMySQLHandler struct {
	server.EmptyHandler
	pool     *MySQLPool
	logger   *Logger
	server   *Server
	clientID string
	rules    ast.Rules
}

// HandleQuery processes a raw SQL string received via COM_QUERY, applying policy rules, executing it upstream, and returning the result.
func (h *AgentIAMMySQLHandler) HandleQuery(query string) (*mysql.Result, error) {
	// 0x03 COM_QUERY handler. The proxy framework automatically strips the 0x03 command byte
	// and hands us the raw SQL query string from the payload.
	h.logger.Info("Intercepted COM_QUERY", "query", query)

	var rewritten string
	var err error

	if h.server != nil && h.server.store != nil {
		if h.server.pool != nil {
			h.server.store.SetPoolLatency(h.server.pool.GetAvgAcquireDuration())
		}
		if err := h.server.store.CheckRateLimit(h.clientID); err != nil {
			h.server.DispatchAudit(AuditEvent{
				Event:    EventPolicyBlocked,
				ClientID: h.clientID,
				SQL:      query,
				Status:   "rate_limited",
				Error:    err.Error(),
			})
			return nil, err
		}
	}

	if h.server != nil {
		parser := &ast.MySQLParser{}
		rewritten, _, err = parser.ApplyRules(query, h.rules, h.server.astCache)
		if err != nil {
			h.server.DispatchAudit(AuditEvent{
				Event:    EventPolicyBlocked,
				ClientID: h.clientID,
				SQL:      query,
				Status:   "blocked",
				Error:    err.Error(),
			})
			return nil, err
		}
		h.server.DispatchAudit(AuditEvent{
			Event:    EventQueryForwarded,
			ClientID: h.clientID,
			SQL:      rewritten,
			Status:   "success",
		})
	} else {
		rewritten = query
	}

	// Execute on upstream using custom pool
	conn, err := h.pool.Acquire(context.Background())
	if err != nil {
		return nil, err
	}
	defer h.pool.Release(conn)

	res, err := conn.Conn.Execute(rewritten)
	if err != nil {
		return nil, err
	}

	return res, nil
}
