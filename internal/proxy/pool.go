package proxy

import (
	"context"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/jackc/pgx/v5/pgconn"
)

type UpstreamConn struct {
	mu                   sync.Mutex
	Conn                 net.Conn
	Frontend             *pgproto3.Frontend
	PID                  uint32
	SecretKey            uint32
	InUse                atomic.Bool
	Broken               atomic.Bool
	replaced             atomic.Bool
	SwallowParseComplete atomic.Int32
	SwallowSetTimeout    atomic.Int32
	TxStatus             byte
}

func (u *UpstreamConn) Close() {
	if u.Conn != nil {
		u.Conn.Close()
	}
}

// SendAndFlush sends the provided messages and flushes the frontend buffer under a mutex lock,
// preventing concurrent write races on the wire protocol encoder.
func (u *UpstreamConn) SendAndFlush(msgs ...pgproto3.FrontendMessage) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	for _, msg := range msgs {
		u.Frontend.Send(msg)
	}
	return u.Frontend.Flush()
}

type Pool struct {
	dsn                  string
	size                 int
	logger               *Logger
	conns                chan *UpstreamConn
	ready                atomic.Bool
	closed               atomic.Bool
	closeOnce            sync.Once
	closeMu              sync.RWMutex
	avgAcquireDurationNs atomic.Int64
}

func NewPool(dsn string, size int, logger *Logger) *Pool {
	return &Pool{
		dsn:    dsn,
		size:   size,
		logger: logger,
		conns:  make(chan *UpstreamConn, size),
	}
}

func (p *Pool) IsReady() bool {
	return p.ready.Load()
}

func (p *Pool) GetActiveCount() int {
	if p == nil || p.conns == nil {
		return 0
	}
	return p.size - len(p.conns)
}

func (p *Pool) Init(ctx context.Context) error {
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
	p.logger.Info("Upstream connection pool initialized", "size", p.size)
	PoolTotalConnections.Set(float64(p.size))
	PoolIdleConnections.Set(float64(p.size))
	return nil
}

func (p *Pool) dial(ctx context.Context) (*UpstreamConn, error) {
	if p.closed.Load() {
		return nil, fmt.Errorf("pool is closed")
	}

	pgConn, err := pgconn.Connect(ctx, p.dsn)
	if err != nil {
		return nil, err
	}

	hijacked, err := pgConn.Hijack()
	if err != nil {
		pgConn.Close(ctx)
		return nil, err
	}

	if p.closed.Load() {
		hijacked.Conn.Close()
		return nil, fmt.Errorf("pool is closed")
	}

	secretKeyUint := uint32(0)
	if len(hijacked.SecretKey) >= 4 {
		secretKeyUint = uint32(hijacked.SecretKey[0])<<24 | uint32(hijacked.SecretKey[1])<<16 | uint32(hijacked.SecretKey[2])<<8 | uint32(hijacked.SecretKey[3])
	}

	return &UpstreamConn{
		Conn:      hijacked.Conn,
		Frontend:  pgproto3.NewFrontend(hijacked.Conn, hijacked.Conn),
		PID:       hijacked.PID,
		SecretKey: secretKeyUint,
	}, nil
}

func (p *Pool) GetAvgAcquireDuration() time.Duration {
	return time.Duration(p.avgAcquireDurationNs.Load())
}

func (p *Pool) updateAvgAcquireDuration(d time.Duration) {
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

func (p *Pool) Acquire(ctx context.Context) (*UpstreamConn, error) {
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
				p.closeMu.RLock()
				defer p.closeMu.RUnlock()
				if !p.closed.Load() {
					broken := &UpstreamConn{}
					broken.Broken.Store(true)
					select {
					case p.conns <- broken:
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

func (p *Pool) Release(u *UpstreamConn) {
	if u == nil {
		return
	}
	if !u.InUse.CompareAndSwap(true, false) {
		return
	}
	u.SwallowParseComplete.Store(0)
	u.SwallowSetTimeout.Store(0)

	p.closeMu.RLock()
	defer p.closeMu.RUnlock()

	if p.closed.Load() {
		u.Close()
		return
	}

	if u.Broken.Load() || u.Conn == nil {
		p.discardAndReplace(u)
		return
	}

	// Proactively clean the connection state before putting it back in the pool
	go func() {
		defer func() {
			if r := recover(); r != nil {
				p.logger.Error("Uncaught panic in pool release reader; discarding connection", "panic", r)
				p.discardAndReplace(u)
			}
		}()

		if p.closed.Load() {
			u.Close()
			return
		}

		if err := u.SendAndFlush(&pgproto3.Query{String: "DISCARD ALL"}); err != nil {
			p.logger.Error("Failed to flush DISCARD ALL on release", "error", err)
			p.discardAndReplace(u)
			return
		}
		for {
			msg, err := u.Frontend.Receive()
			if err != nil {
				p.logger.Error("Failed to DISCARD ALL on release", "error", err)
				p.discardAndReplace(u)
				return
			}
			if _, ok := msg.(*pgproto3.ReadyForQuery); ok {
				break
			}
		}

		p.closeMu.RLock()
		defer p.closeMu.RUnlock()

		if p.closed.Load() {
			u.Close()
			return
		}
		select {
		case p.conns <- u:
			PoolIdleConnections.Inc()
		default:
			u.Close()
			PoolTotalConnections.Dec()
		}
	}()
}

func (p *Pool) discardAndReplace(u *UpstreamConn) {
	u.Broken.Store(true)
	u.Close()

	if p.closed.Load() {
		return
	}

	if !u.replaced.CompareAndSwap(false, true) {
		return
	}

	go func() {
		dialCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		newU, err := p.dial(dialCtx)
		if err != nil {
			p.logger.Error("Failed to re-dial broken connection", "error", err)
			p.closeMu.RLock()
			defer p.closeMu.RUnlock()
			if p.closed.Load() {
				return
			}
			broken := &UpstreamConn{}
			broken.Broken.Store(true)
			select {
			case p.conns <- broken:
				PoolIdleConnections.Inc()
			default:
				PoolTotalConnections.Dec()
			}
			return
		}

		p.closeMu.RLock()
		defer p.closeMu.RUnlock()

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
	}()
}

func (p *Pool) Close() {
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
