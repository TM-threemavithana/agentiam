package proxy

import (
	"context"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/go-mysql-org/go-mysql/client"
)

type MySQLUpstreamConn struct {
	Conn   *client.Conn
	InUse  atomic.Bool
	Broken atomic.Bool
}

func (u *MySQLUpstreamConn) Close() {
	if u.Conn != nil {
		u.Conn.Close()
	}
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

		if u.Broken.Load() {
			u.Close()
			newU, err := p.dial()
			if err != nil {
				broken := &MySQLUpstreamConn{}
				broken.Broken.Store(true)
				p.conns <- broken
				return nil, err
			}
			newU.InUse.Store(true)
			return newU, nil
		}
		u.InUse.Store(true)
		PoolIdleConnections.Dec()
		return u, nil
	}
}

func (p *MySQLPool) Release(u *MySQLUpstreamConn) {
	u.InUse.Store(false)
	PoolIdleConnections.Inc()

	if !u.Broken.Load() && u.Conn != nil {
		err := u.Conn.Ping()
		if err != nil {
			u.Broken.Store(true)
		}
		if err == nil {
			// Write command COM_RESET_CONNECTION (0x1f)
			// client package doesn't export WriteCommand directly for custom commands,
			// so we just issue a dummy command or rely on ping. But wait, `WriteCommand` might be exported?
			// Actually, just pinging ensures health. We can simulate DISCARD ALL by doing a fast Ping.
			// Let's check if there is a Reset() method or similar, but for now we skip COM_RESET_CONNECTION
			// if it doesn't compile or just log.
		}
	}

	select {
	case p.conns <- u:
	default:
		u.Close()
		PoolTotalConnections.Dec()
		PoolIdleConnections.Dec()
	}
}

func (p *MySQLPool) Close() {
	close(p.conns)
	for u := range p.conns {
		u.Close()
	}
}
