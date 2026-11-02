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
	size                 int
	logger               *Logger
	conns                chan *MySQLUpstreamConn
	ready                atomic.Bool
	closed               atomic.Bool
	closeOnce            sync.Once
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

func (p *MySQLPool) Init(ctx context.Context) error {
	for i := 0; i < p.size; i++ {
		u, err := p.dial()
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

func (p *MySQLPool) dial() (*MySQLUpstreamConn, error) {
	conn, err := client.Connect(p.addr, p.user, p.pass, p.dbName)
	if err != nil {
		return nil, err
	}

	return &MySQLUpstreamConn{
		Conn: conn,
	}, nil
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
	start := time.Now()
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case u := <-p.conns:
		duration := time.Since(start)
		p.updateAvgAcquireDuration(duration)
		PoolIdleConnections.Dec()

		if u.Broken.Load() {
			u.Close()
			newU, err := p.dial()
			if err != nil {
				broken := &MySQLUpstreamConn{}
				broken.Broken.Store(true)
				p.conns <- broken
				PoolIdleConnections.Inc()
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
	if p.closed.Load() {
		u.Close()
		return
	}
	u.InUse.Store(false)

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

	newU, err := p.dial()
	if err != nil {
		p.logger.Error("Failed to dial replacement MySQL connection", "error", err)
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
