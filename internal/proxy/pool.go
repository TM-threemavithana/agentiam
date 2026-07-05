package proxy

import (
	"context"
	"fmt"
	"net"
	"sync/atomic"

	"github.com/jackc/pgproto3/v2"
	"github.com/jackc/pgx/v5/pgconn"
)

type UpstreamConn struct {
	Conn                 net.Conn
	Frontend             *pgproto3.Frontend
	PID                  uint32
	SecretKey            uint32
	InUse                atomic.Bool
	Broken               atomic.Bool
	SwallowParseComplete atomic.Int32
	SwallowSetTimeout    atomic.Int32
	TxStatus             byte
}

func (u *UpstreamConn) Close() {
	if u.Conn != nil {
		u.Conn.Close()
	}
}

type Pool struct {
	dsn    string
	size   int
	logger *Logger
	conns  chan *UpstreamConn
	ready  atomic.Bool
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

	return &UpstreamConn{
		Conn:      hijacked.Conn,
		Frontend:  pgproto3.NewFrontend(pgproto3.NewChunkReader(hijacked.Conn), hijacked.Conn),
		PID:       hijacked.PID,
		SecretKey: secretKeyUint,
	}, nil
}

func (p *Pool) Acquire(ctx context.Context) (*UpstreamConn, error) {
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case u := <-p.conns:
		if u.Broken.Load() {
			u.Close()
			newU, err := p.dial(ctx)
			if err != nil {
				broken := &UpstreamConn{}
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

func (p *Pool) Release(u *UpstreamConn) {
	if u == nil {
		return
	}
	u.InUse.Store(false)
	u.SwallowParseComplete.Store(0)
	u.SwallowSetTimeout.Store(0)
	if u.Broken.Load() {
		u.Close()
		// Re-dial in background
		go func() {
			newU, err := p.dial(context.Background())
			if err != nil {
				p.logger.Error("Failed to re-dial broken connection", "error", err)
				// Put a explicitly broken one back so next acquire will retry dialing safely
				broken := &UpstreamConn{}
				broken.Broken.Store(true)
				p.conns <- broken
				return
			}
			p.conns <- newU
		}()
		return
	}

	// Proactively clean the connection state before putting it back in the pool
	go func() {
		u.Frontend.Send(&pgproto3.Query{String: "DISCARD ALL"})
		for {
			msg, err := u.Frontend.Receive()
			if err != nil {
				p.logger.Error("Failed to DISCARD ALL on release", "error", err)
				u.Broken.Store(true)
				u.Close()
				broken := &UpstreamConn{}
				broken.Broken.Store(true)
				p.conns <- broken
				return
			}
			if _, ok := msg.(*pgproto3.ReadyForQuery); ok {
				break
			}
		}
		p.conns <- u
		PoolIdleConnections.Inc()
	}()
}
