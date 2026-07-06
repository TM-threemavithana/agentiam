package proxy

import (
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/tls"
	"database/sql"
	"encoding/hex"
	"fmt"
	"net"
	"reflect"
	"strings"
	"unsafe"

	"github.com/tm-threemavithana/agentiam/internal/ast"
	"github.com/tm-threemavithana/agentiam/internal/policy"

	"github.com/go-mysql-org/go-mysql/mysql"
	"github.com/go-mysql-org/go-mysql/server"
	_ "github.com/go-sql-driver/mysql"
)

// MySQLProtocolHandler implements the ProtocolHandler interface for the MySQL wire protocol.
type MySQLProtocolHandler struct {
	store        *policy.Store
	logger       *Logger
	upstreamDSN  string
	db           *sql.DB
	server       *Server
	insecureAuth bool
}

// NewMySQLProtocolHandler creates a new handler capable of routing and parsing MySQL client connections.
func NewMySQLProtocolHandler(store *policy.Store, logger *Logger, server *Server, insecureAuth bool) *MySQLProtocolHandler {
	return &MySQLProtocolHandler{store: store, logger: logger, upstreamDSN: "root@tcp(127.0.0.1:3306)/", server: server, insecureAuth: insecureAuth}
}

// InitPool initializes the upstream *sql.DB connection pool.
func (h *MySQLProtocolHandler) InitPool() error {
	db, err := sql.Open("mysql", h.upstreamDSN)
	if err != nil {
		return err
	}
	db.SetMaxOpenConns(50)
	h.db = db
	return nil
}

// HandleSession implements the ProtocolHandler interface.
// It proxies the raw net.Conn through the go-mysql-org server implementation.
func (h *MySQLProtocolHandler) HandleSession(ctx context.Context, clientConn net.Conn) error {
	h.logger.Info("MySQL connection accepted", "remote_addr", clientConn.RemoteAddr().String())

	proxyHandler := &AgentIAMMySQLHandler{
		db:     h.db,
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
	serverConf := server.NewServer("8.0.11", 255, "mysql_native_password", nil, tlsCfg)

	// Initialize the MySQL Proxy handler
	if h.db == nil {
		_ = h.InitPool()
	}

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
					suppliedPassword = "mTLS_VERIFIED"
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
		var isNativeAuth bool
		// Attempt challenge-response verification if key matches format
		if authPluginName == "mysql_native_password" || authPluginName == "caching_sha2_password" {
			key, keyErr := a.store.GetAgentKey(clientID)
			if keyErr == nil {
				var salt []byte
				v := reflect.ValueOf(c).Elem()
				saltField := v.FieldByName("salt")
				if saltField.IsValid() {
					ptr := unsafe.Pointer(saltField.UnsafeAddr())
					salt = *(*[]byte)(ptr)
				}

				if authPluginName == "mysql_native_password" && strings.HasPrefix(key, "mysql_native_password$") {
					hexHash := strings.TrimPrefix(key, "mysql_native_password$")
					doubleSHA1, decodeErr := hex.DecodeString(hexHash)
					if decodeErr == nil && len(salt) >= 20 && len(clientAuthData) >= 20 {
						h := sha1.New()
						h.Write(salt[:20])
						h.Write(doubleSHA1)
						saltHash := h.Sum(nil)

						sha1Password := make([]byte, 20)
						for i := 0; i < 20; i++ {
							sha1Password[i] = clientAuthData[i] ^ saltHash[i]
						}

						h2 := sha1.New()
						h2.Write(sha1Password)
						calculatedDoubleSHA1 := h2.Sum(nil)

						if bytes.Equal(calculatedDoubleSHA1, doubleSHA1) {
							isNativeAuth = true
							suppliedPassword = "mTLS_VERIFIED"
						}
					}
				} else if authPluginName == "caching_sha2_password" && strings.HasPrefix(key, "caching_sha2_password$") {
					hexHash := strings.TrimPrefix(key, "caching_sha2_password$")
					doubleSHA256, decodeErr := hex.DecodeString(hexHash)
					if decodeErr == nil && len(salt) >= 20 && len(clientAuthData) >= 32 {
						h := sha256.New()
						h.Write(doubleSHA256)
						h.Write(salt[:20])
						saltHash := h.Sum(nil)

						sha256Password := make([]byte, 32)
						for i := 0; i < 32; i++ {
							sha256Password[i] = clientAuthData[i] ^ saltHash[i]
						}

						h2 := sha256.New()
						h2.Write(sha256Password)
						calculatedDoubleSHA256 := h2.Sum(nil)

						if bytes.Equal(calculatedDoubleSHA256, doubleSHA256) {
							isNativeAuth = true
							suppliedPassword = "mTLS_VERIFIED"
						}
					}
				}
			}
		}

		if !isNativeAuth {
			if authPluginName == "mysql_clear_password" {
				suppliedPassword = string(bytes.TrimRight(clientAuthData, "\x00"))
			} else if authPluginName == "mysql_native_password" {
				if clientID == "root" && len(clientAuthData) == 0 {
					suppliedPassword = ""
				} else {
					return fmt.Errorf("authentication plugin %s not supported without mTLS (use mysql_clear_password for password auth)", authPluginName)
				}
			} else {
				return fmt.Errorf("authentication plugin %s not supported", authPluginName)
			}
		}
	}

	rules, _, err := a.store.GetRulesForAgent(clientID, suppliedPassword)
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

// GetCredential retrieves the password for a given user.
func (a *AgentIAMAuthHandler) GetCredential(username string) (server.Credential, bool, error) {
	if a.insecureAuth && username == "root" {
		return server.Credential{Passwords: []string{""}, AuthPluginName: "mysql_native_password"}, true, nil
	}
	return server.Credential{}, false, nil
}

// OnAuthSuccess is called after a successful password authentication.
func (a *AgentIAMAuthHandler) OnAuthSuccess(conn *server.Conn) error {
	a.logger.Info("MySQL Auth Success", "user", conn.GetUser())
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
	db       *sql.DB
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

	// Execute on upstream
	rows, err := h.db.Query(rewritten)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	cols, _ := rows.Columns()
	var values [][]interface{}

	for rows.Next() {
		columns := make([]interface{}, len(cols))
		columnPointers := make([]interface{}, len(cols))
		for i := range columns {
			columnPointers[i] = &columns[i]
		}

		if err := rows.Scan(columnPointers...); err != nil {
			return nil, err
		}

		rowValues := make([]interface{}, len(cols))
		for i, val := range columns {
			b, ok := val.([]byte)
			if ok {
				rowValues[i] = string(b)
			} else {
				rowValues[i] = val
			}
		}
		values = append(values, rowValues)
	}

	// Construct the Text Resultset response stream.
	// This generates the Column Definition block, encodes the strings, and handles the trailing OK/EOF.
	resultset, err := mysql.BuildSimpleTextResultset(cols, values)
	if err != nil {
		return nil, err
	}

	return mysql.NewResult(resultset), nil
}
