package proxy

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgproto3"
)

var (
	ErrPoolClosed    = errors.New("connection pool is closed")
	ErrPoolExhausted = errors.New("connection pool exhausted")
)

// ConnState represents the explicit lifecycle state of an UpstreamConn.
type ConnState int32

const (
	ConnStateIdle     ConnState = iota // Resting in pool channel, ready for lease
	ConnStateInUse                     // Leased to an active client session
	ConnStateCleaning                  // Returned by client, currently executing DISCARD ALL
	ConnStateClosed                    // Permanently closed or broken
)

func (s ConnState) String() string {
	switch s {
	case ConnStateIdle:
		return "idle"
	case ConnStateInUse:
		return "in-use"
	case ConnStateCleaning:
		return "cleaning"
	case ConnStateClosed:
		return "closed"
	default:
		return "unknown"
	}
}

type UpstreamConn struct {
	Conn                 net.Conn
	Frontend             *pgproto3.Frontend
	PID                  uint32
	SecretKey            uint32
	InUse                atomic.Bool
	Broken               atomic.Bool
	state                atomic.Int32
	SwallowParseComplete atomic.Int32
	SwallowSetTimeout    atomic.Int32
	TxStatus             byte
}

func (u *UpstreamConn) Close() {
	if u.Conn != nil {
		u.Conn.Close()
	}
}

func (u *UpstreamConn) State() ConnState {
	return ConnState(u.state.Load())
}

type Pool struct {
	dsn                  string
	size                 int
	logger               *Logger
	conns                chan *UpstreamConn
	ready                atomic.Bool
	closed               atomic.Bool
	closeOnce            sync.Once
	avgAcquireDurationNs atomic.Int64
	activeCount          atomic.Int32
	cleaningCount        atomic.Int32

	ctx       context.Context
	cancel    context.CancelFunc
	workersWg sync.WaitGroup
}

func NewPool(dsn string, size int, logger *Logger) *Pool {
	ctx, cancel := context.WithCancel(context.Background())
	return &Pool{
		dsn:    dsn,
		size:   size,
		logger: logger,
		conns:  make(chan *UpstreamConn, size),
		ctx:    ctx,
		cancel: cancel,
	}
}

func (p *Pool) IsReady() bool {
	return p.ready.Load()
}

func (p *Pool) GetActiveCount() int {
	return int(p.activeCount.Load())
}

func (p *Pool) GetCleaningCount() int {
	return int(p.cleaningCount.Load())
}

func (p *Pool) GetIdleCount() int {
	if p == nil || p.conns == nil {
		return 0
	}
	return len(p.conns)
}

func (p *Pool) Init(ctx context.Context) error {
	if p.closed.Load() {
		return ErrPoolClosed
	}
	for i := 0; i < p.size; i++ {
		u, err := p.dial(ctx)
		if err != nil {
			return fmt.Errorf("failed to dial upstream during pool init: %w", err)
		}
		u.InUse.Store(false)
		u.state.Store(int32(ConnStateIdle))
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
	pgConn, err := pgconn.Connect(ctx, p.dsn)
	if err != nil {
		return nil, err
	}

	hijacked, err := pgConn.Hijack()
	if err != nil {
		pgConn.Close(ctx)
		return nil, err
	}

	secretKeyUint := uint32(0)
	if len(hijacked.SecretKey) >= 4 {
		secretKeyUint = uint32(hijacked.SecretKey[0])<<24 | uint32(hijacked.SecretKey[1])<<16 | uint32(hijacked.SecretKey[2])<<8 | uint32(hijacked.SecretKey[3])
	}

	fe := pgproto3.NewFrontend(hijacked.Conn, hijacked.Conn)
	fe.SetMaxBodyLen(DefaultMaxProtocolBodyLen)

	u := &UpstreamConn{
		Conn:      hijacked.Conn,
		Frontend:  fe,
		PID:       hijacked.PID,
		SecretKey: secretKeyUint,
		TxStatus:  'I',
	}
	u.state.Store(int32(ConnStateClosed))
	return u, nil
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
		return nil, ErrPoolClosed
	}

	start := time.Now()
	var u *UpstreamConn

	select {
	case <-p.ctx.Done():
		return nil, ErrPoolClosed
	case <-ctx.Done():
		return nil, ctx.Err()
	case conn, ok := <-p.conns:
		if !ok || p.closed.Load() {
			if conn != nil {
				conn.Close()
				conn.state.Store(int32(ConnStateClosed))
			}
			return nil, ErrPoolClosed
		}
		u = conn
	}

	duration := time.Since(start)
	p.updateAvgAcquireDuration(duration)
	PoolIdleConnections.Dec()

	if u == nil {
		u = &UpstreamConn{}
		u.Broken.Store(true)
	}

	// If connection was marked broken or is a synthetic broken stub: redial
	if u.Broken.Load() || u.Conn == nil {
		u.Close()
		u.InUse.Store(false)
		u.state.Store(int32(ConnStateClosed))

		newU, err := p.dial(ctx)
		if err != nil {
			// Re-enqueue broken stub so capacity slot is not permanently lost
			if !p.closed.Load() {
				broken := &UpstreamConn{}
				broken.Broken.Store(true)
				broken.state.Store(int32(ConnStateClosed))
				p.conns <- broken
				PoolIdleConnections.Inc()
			}
			return nil, err
		}

		newU.InUse.Store(true)
		newU.state.Store(int32(ConnStateInUse))
		p.activeCount.Add(1)
		return newU, nil
	}

	u.InUse.Store(true)
	u.state.Store(int32(ConnStateInUse))
	p.activeCount.Add(1)
	return u, nil
}

func (p *Pool) Release(u *UpstreamConn) {
	if u == nil {
		return
	}

	// Double-release prevention: only an InUse connection can transition to Cleaning
	if !u.state.CompareAndSwap(int32(ConnStateInUse), int32(ConnStateCleaning)) {
		return
	}

	p.activeCount.Add(-1)

	if p.closed.Load() {
		u.Close()
		u.InUse.Store(false)
		u.state.Store(int32(ConnStateClosed))
		return
	}

	u.SwallowParseComplete.Store(0)
	u.SwallowSetTimeout.Store(0)

	// If connection was marked broken: redial in background or return broken stub
	if u.Broken.Load() || u.Conn == nil {
		u.Close()
		u.InUse.Store(false)
		u.state.Store(int32(ConnStateClosed))

		p.workersWg.Add(1)
		go func() {
			defer p.workersWg.Done()

			if p.closed.Load() {
				return
			}

			dialCtx, dialCancel := context.WithTimeout(p.ctx, 5*time.Second)
			defer dialCancel()

			newU, err := p.dial(dialCtx)
			if err != nil {
				p.logger.Error("Failed to re-dial broken connection on release", "error", err)
				if p.closed.Load() {
					return
				}
				broken := &UpstreamConn{}
				broken.Broken.Store(true)
				broken.state.Store(int32(ConnStateClosed))
				p.conns <- broken
				PoolIdleConnections.Inc()
				return
			}

			if p.closed.Load() {
				newU.Close()
				newU.state.Store(int32(ConnStateClosed))
				return
			}

			newU.InUse.Store(false)
			newU.state.Store(int32(ConnStateIdle))
			p.conns <- newU
			PoolIdleConnections.Inc()
		}()
		return
	}

	// Healthy connection: sanitize session state via DISCARD ALL
	p.cleaningCount.Add(1)
	p.workersWg.Add(1)
	go func() {
		defer p.workersWg.Done()
		defer p.cleaningCount.Add(-1)

		if p.closed.Load() {
			u.Close()
			u.InUse.Store(false)
			u.state.Store(int32(ConnStateClosed))
			return
		}

		cleanCtx, cleanCancel := context.WithTimeout(p.ctx, 5*time.Second)
		defer cleanCancel()

		u.Frontend.Send(&pgproto3.Query{String: "DISCARD ALL"})
		if err := u.Frontend.Flush(); err != nil {
			p.logger.Error("Failed to flush DISCARD ALL on release", "error", err)
			p.handleCleaningFailure(u)
			return
		}

		discardDone := make(chan error, 1)
		go func() {
			for {
				msg, err := u.Frontend.Receive()
				if err != nil {
					discardDone <- err
					return
				}
				if rfq, ok := msg.(*pgproto3.ReadyForQuery); ok {
					u.TxStatus = rfq.TxStatus
					discardDone <- nil
					return
				}
			}
		}()

		select {
		case <-cleanCtx.Done():
			p.logger.Error("DISCARD ALL timed out or pool closed during release", "error", cleanCtx.Err())
			p.handleCleaningFailure(u)
			return
		case err := <-discardDone:
			if err != nil {
				var maxLenErr *pgproto3.ExceededMaxBodyLenErr
				if errors.As(err, &maxLenErr) {
					p.logger.Error("DISCARD ALL received message exceeding maximum length limit",
						"max", maxLenErr.MaxExpectedBodyLen,
						"actual", maxLenErr.ActualBodyLen,
					)
				} else {
					p.logger.Error("Failed to DISCARD ALL on release", "error", err)
				}
				p.handleCleaningFailure(u)
				return
			}
		}

		if p.closed.Load() {
			u.Close()
			u.InUse.Store(false)
			u.state.Store(int32(ConnStateClosed))
			return
		}

		// Cleanup completed successfully: mark Idle and return to pool channel
		u.InUse.Store(false)
		u.state.Store(int32(ConnStateIdle))
		p.conns <- u
		PoolIdleConnections.Inc()
	}()
}

func (p *Pool) handleCleaningFailure(u *UpstreamConn) {
	u.Broken.Store(true)
	u.Close()
	u.InUse.Store(false)
	u.state.Store(int32(ConnStateClosed))

	if p.closed.Load() {
		return
	}

	broken := &UpstreamConn{}
	broken.Broken.Store(true)
	broken.state.Store(int32(ConnStateClosed))
	p.conns <- broken
	PoolIdleConnections.Inc()
}

func (p *Pool) Close() {
	p.closeOnce.Do(func() {
		p.closed.Store(true)
		p.ready.Store(false)
		if p.cancel != nil {
			p.cancel()
		}

		// Drain currently idle connections
		for {
			select {
			case u := <-p.conns:
				if u != nil {
					u.Close()
					u.InUse.Store(false)
					u.state.Store(int32(ConnStateClosed))
				}
			default:
				goto drained
			}
		}

	drained:
		// Wait for active workers to complete
		p.workersWg.Wait()

		// Final drain pass
		for {
			select {
			case u := <-p.conns:
				if u != nil {
					u.Close()
					u.InUse.Store(false)
					u.state.Store(int32(ConnStateClosed))
				}
			default:
				return
			}
		}
	})
}
