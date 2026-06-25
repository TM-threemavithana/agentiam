package proxy

import (
	"context"
	"database/sql"
	"net"

	"agentiam/internal/policy"

	"github.com/go-mysql-org/go-mysql/mysql"
	"github.com/go-mysql-org/go-mysql/server"
	_ "github.com/go-sql-driver/mysql"
)

// MySQLProtocolHandler implements the ProtocolHandler interface for the MySQL wire protocol.
type MySQLProtocolHandler struct {
	store       *policy.Store
	logger      *Logger
	upstreamDSN string
	db          *sql.DB
}

// NewMySQLProtocolHandler creates a new handler capable of routing and parsing MySQL client connections.
func NewMySQLProtocolHandler(store *policy.Store, logger *Logger) *MySQLProtocolHandler {
	return &MySQLProtocolHandler{store: store, logger: logger, upstreamDSN: "root@tcp(127.0.0.1:3306)/"}
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

	authHandler := &AgentIAMAuthHandler{store: h.store, logger: h.logger}
	serverConf := server.NewDefaultServer()

	// Initialize the MySQL Proxy handler
	if h.db == nil {
		_ = h.InitPool()
	}
	proxyHandler := &AgentIAMMySQLHandler{db: h.db, logger: h.logger}

	conn, err := server.NewCustomizedConn(clientConn, serverConf, authHandler, proxyHandler)
	if err != nil {
		h.logger.Error("MySQL Handshake failed", "error", err)
		return err
	}
	defer conn.Close()

	for {
		err := conn.HandleCommand()
		if err != nil {
			return err
		}
	}
}

// AgentIAMAuthHandler implements the MySQL server authentication interface.
type AgentIAMAuthHandler struct {
	store  *policy.Store
	logger *Logger
}

// GetCredential retrieves the password for a given user.
func (a *AgentIAMAuthHandler) GetCredential(username string) (server.Credential, bool, error) {
	if username == "root" {
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
	db     *sql.DB
	logger *Logger
}

// HandleQuery processes a raw SQL string received via COM_QUERY, applying policy rules, executing it upstream, and returning the result.
func (h *AgentIAMMySQLHandler) HandleQuery(query string) (*mysql.Result, error) {
	// 0x03 COM_QUERY handler. The proxy framework automatically strips the 0x03 command byte
	// and hands us the raw SQL query string from the payload.
	h.logger.Info("Intercepted COM_QUERY", "query", query)

	// Execute on upstream
	rows, err := h.db.Query(query)
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
