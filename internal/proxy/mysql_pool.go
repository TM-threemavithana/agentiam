package proxy

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-mysql-org/go-mysql/client"
	"github.com/go-mysql-org/go-mysql/mysql"
)

// ResetTimeout defines the network I/O deadline for COM_RESET_CONNECTION command and response.
const ResetTimeout = 5 * time.Second

type MySQLUpstreamConn struct {
	Conn   *client.Conn
	InUse  atomic.Bool
	Broken atomic.Bool
	mu     sync.Mutex
}

// Close closes the underlying MySQL connection. It is idempotent and safe for concurrent calls.
func (u *MySQLUpstreamConn) Close() {
	if u == nil {
		return
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.Conn != nil {
		_ = u.Conn.Close()
		u.Conn = nil
	}
}

// Execute executes a command over the connection with mutex protection against concurrent reset or close.
// Network errors automatically mark the connection broken so it will be discarded upon release.
func (u *MySQLUpstreamConn) Execute(command string, args ...any) (*mysql.Result, error) {
	if u == nil {
		return nil, fmt.Errorf("cannot execute query on nil connection")
	}
	u.mu.Lock()
	defer u.mu.Unlock()

	if u.Broken.Load() || u.Conn == nil {
		return nil, fmt.Errorf("connection is broken or closed")
	}

	res, err := u.Conn.Execute(command, args...)
	if err != nil && isBadConn(err) {
		u.Broken.Store(true)
	}
	return res, err
}

func isBadConn(err error) bool {
	if err == nil {
		return false
	}
	// If the server responded with a valid MySQL application error packet (*mysql.MyError),
	// the wire protocol is synchronized and healthy.
	if _, ok := err.(*mysql.MyError); ok {
		return false
	}
	// Any non-MyError (I/O error, closed pipe, timeout, EOF) indicates a compromised socket.
	return true
}

// ResetConnection sends a COM_RESET_CONNECTION (0x1f) packet over the wire to
// sanitize the upstream MySQL session state before the connection can be returned
// to the idle pool. It sets an explicit I/O deadline, handles packet sequencing,
// asserts a successful OK packet response, and marks the connection broken if an
// ERR packet, malformed response, timeout, or disconnection occurs.
func (u *MySQLUpstreamConn) ResetConnection() error {
	if u == nil {
		return fmt.Errorf("cannot reset nil connection")
	}
	u.mu.Lock()
	defer u.mu.Unlock()

	if u.Broken.Load() || u.Conn == nil {
		return fmt.Errorf("cannot reset broken or closed connection")
	}

	// 1. Set explicit I/O deadline on the connection socket
	if err := u.Conn.SetDeadline(time.Now().Add(ResetTimeout)); err != nil {
		u.Broken.Store(true)
		return fmt.Errorf("failed to set deadline for COM_RESET_CONNECTION: %w", err)
	}
	defer func() {
		if u.Conn != nil {
			_ = u.Conn.SetDeadline(time.Time{})
		}
	}()

	// 2. Reset client packet sequence ID to 0 for a new command packet
	u.Conn.ResetSequence()

	// 3. Construct and write the 5-byte command packet:
	// 4 bytes header (allocated for in-place population by go-mysql WritePacket)
	// followed by the 1-byte command code (mysql.COM_RESET_CONNECTION = 0x1f)
	pkt := []byte{0x00, 0x00, 0x00, 0x00, mysql.COM_RESET_CONNECTION}
	if err := u.Conn.WritePacket(pkt); err != nil {
		u.Broken.Store(true)
		return fmt.Errorf("failed to write COM_RESET_CONNECTION packet: %w", err)
	}

	// 4. Read and verify the OK response packet.
	// ReadOKPacket handles OK_HEADER (0x00), ERR_HEADER (0xff), and malformed packets.
	if _, err := u.Conn.ReadOKPacket(); err != nil {
		u.Broken.Store(true)
		return fmt.Errorf("COM_RESET_CONNECTION failed: %w", err)
	}

	return nil
}

type MySQLPool struct {
	addr                 string
	user                 string
	pass                 string
	dbName               string
	initSQL              string
	size                 int
	logger               *Logger
	conns                chan *MySQLUpstreamConn
	ready                atomic.Bool
	closed               atomic.Bool
	closeOnce            sync.Once
	closeMu              sync.RWMutex
	avgAcquireDurationNs atomic.Int64
}

func NewMySQLPool(addr, user, pass, dbName string, size int, logger *Logger) *MySQLPool {
	return &MySQLPool{
		addr:   addr,
		user:   user,
		pass:   pass,
		dbName: dbName,
		size:   size,
		logger: logger,
		conns:  make(chan *MySQLUpstreamConn, size),
	}
}

// SetInitSQL configures a session initialization SQL statement (e.g. custom timezone, sql_mode, or charset)
// to be executed on new connections and re-applied after each COM_RESET_CONNECTION.
func (p *MySQLPool) SetInitSQL(sql string) {
	p.initSQL = sql
}

func (p *MySQLPool) Init(ctx context.Context) error {
	for i := 0; i < p.size; i++ {
		u, err := p.dial(ctx)
		if err != nil {
			return fmt.Errorf("failed to dial upstream during pool init: %w", err)
		}
		p.conns <- u
		if i == 0 {
			p.ready.Store(true)
		}
	}
	p.logger.Info("MySQL Upstream connection pool initialized", "size", p.size)
	PoolTotalConnections.Set(float64(p.size))
	PoolIdleConnections.Set(float64(p.size))
	return nil
}

func (p *MySQLPool) dial(ctx context.Context) (*MySQLUpstreamConn, error) {
	if p.closed.Load() {
		return nil, fmt.Errorf("pool is closed")
	}
	conn, err := client.ConnectWithContext(ctx, p.addr, p.user, p.pass, p.dbName, 10*time.Second)
	if err != nil {
		return nil, err
	}

	u := &MySQLUpstreamConn{
		Conn: conn,
	}

	if p.initSQL != "" {
		if _, err := u.Execute(p.initSQL); err != nil {
			u.Close()
			return nil, fmt.Errorf("failed to execute pool initSQL on dial: %w", err)
		}
	}

	return u, nil
}

func (p *MySQLPool) updateAvgAcquireDuration(d time.Duration) {
	ns := d.Nanoseconds()
	for {
		current := p.avgAcquireDurationNs.Load()
		var next int64
		if current == 0 {
			next = ns
		} else {
			next = int64(float64(current)*0.9 + float64(ns)*0.1)
		}
		if p.avgAcquireDurationNs.CompareAndSwap(current, next) {
			break
		}
	}
}

func (p *MySQLPool) Acquire(ctx context.Context) (*MySQLUpstreamConn, error) {
	if p.closed.Load() {
		return nil, fmt.Errorf("pool is closed")
	}

	start := time.Now()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case u := <-p.conns:
		duration := time.Since(start)
		p.updateAvgAcquireDuration(duration)
		PoolIdleConnections.Dec()

		if p.closed.Load() {
			if u != nil {
				u.Close()
			}
			return nil, fmt.Errorf("pool is closed")
		}

		if u.Broken.Load() || u.Conn == nil {
			u.Close()
			newU, err := p.dial(ctx)
			if err != nil {
				// Reconnection failed. Return a broken placeholder so pool slot invariant is maintained
				p.closeMu.RLock()
				defer p.closeMu.RUnlock()
				if !p.closed.Load() {
					placeholder := &MySQLUpstreamConn{}
					placeholder.Broken.Store(true)
					select {
					case p.conns <- placeholder:
						PoolIdleConnections.Inc()
					default:
						PoolTotalConnections.Dec()
					}
				}
				return nil, err
			}
			newU.InUse.Store(true)
			return newU, nil
		}

		u.InUse.Store(true)
		return u, nil
	}
}

// Release sanitizes the connection using COM_RESET_CONNECTION before returning it to the idle pool.
// If the reset fails or the connection is broken, it is closed, discarded, and replaced so that
// dirty session state is never leaked to another client.
func (p *MySQLPool) Release(u *MySQLUpstreamConn) {
	if u == nil {
		return
	}
	u.InUse.Store(false)

	p.closeMu.RLock()
	defer p.closeMu.RUnlock()

	// If pool is closed, close connection immediately and return
	if p.closed.Load() {
		u.Close()
		return
	}

	// If connection was marked broken during query execution, discard and replace
	if u.Broken.Load() || u.Conn == nil {
		p.discardAndReplace(u)
		return
	}

	// Sanitize session state via COM_RESET_CONNECTION
	if err := u.ResetConnection(); err != nil {
		p.logger.Warn("Failed to reset MySQL connection on release, discarding", "error", err)
		p.discardAndReplace(u)
		return
	}

	// If pool has nondefault session initialization, re-apply it after COM_RESET_CONNECTION
	if p.initSQL != "" {
		if _, err := u.Conn.Execute(p.initSQL); err != nil {
			p.logger.Warn("Failed to re-apply pool initSQL after reset, discarding", "error", err)
			p.discardAndReplace(u)
			return
		}
	}

	// Re-check pool closed under RLock before enqueuing
	if p.closed.Load() {
		u.Close()
		return
	}

	// Sanitization succeeded: return to idle pool
	select {
	case p.conns <- u:
		PoolIdleConnections.Inc()
	default:
		u.Close()
		PoolTotalConnections.Dec()
	}
}

// discardAndReplace closes a dirty or broken connection, discards it, and attempts
// to create a fresh replacement to preserve the configured pool capacity.
func (p *MySQLPool) discardAndReplace(u *MySQLUpstreamConn) {
	u.Broken.Store(true)
	u.Close()

	if p.closed.Load() {
		return
	}

	dialCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	newU, err := p.dial(dialCtx)
	if err != nil {
		p.logger.Error("Failed to dial replacement MySQL connection", "error", err)
		if p.closed.Load() {
			return
		}
		// Insert an explicitly broken placeholder so pool capacity slot is preserved
		// for future Acquire() calls when upstream database recovers
		placeholder := &MySQLUpstreamConn{}
		placeholder.Broken.Store(true)
		select {
		case p.conns <- placeholder:
			PoolIdleConnections.Inc()
		default:
			PoolTotalConnections.Dec()
		}
		return
	}

	if p.closed.Load() {
		newU.Close()
		return
	}

	select {
	case p.conns <- newU:
		PoolIdleConnections.Inc()
	default:
		newU.Close()
		PoolTotalConnections.Dec()
	}
}

func (p *MySQLPool) Close() {
	p.closeOnce.Do(func() {
		p.closed.Store(true)
		p.ready.Store(false)

		p.closeMu.Lock()
		defer p.closeMu.Unlock()

		for {
			select {
			case u := <-p.conns:
				if u != nil {
					u.Close()
				}
			default:
				return
			}
		}
	})
}
