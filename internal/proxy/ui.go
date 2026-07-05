package proxy

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"
)

type UIAuditEvent struct {
	Time     string `json:"time"`
	ClientID string `json:"client_id"`
	SQL      string `json:"sql"`
	Status   string `json:"status"`
	Reason   string `json:"reason,omitempty"`
}

type UIRingBuffer struct {
	mu     sync.RWMutex
	events []UIAuditEvent
	size   int
	head   int
	count  int
}

func NewUIRingBuffer(size int) *UIRingBuffer {
	return &UIRingBuffer{
		events: make([]UIAuditEvent, size),
		size:   size,
	}
}

func (r *UIRingBuffer) Add(evt UIAuditEvent) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if evt.Time == "" {
		evt.Time = time.Now().UTC().Format(time.RFC3339)
	}
	r.events[r.head] = evt
	r.head = (r.head + 1) % r.size
	if r.count < r.size {
		r.count++
	}
}

func (r *UIRingBuffer) Get() []UIAuditEvent {
	r.mu.RLock()
	defer r.mu.RUnlock()
	res := make([]UIAuditEvent, 0, r.count)
	idx := r.head
	if r.count < r.size {
		idx = 0
	}
	for i := 0; i < r.count; i++ {
		res = append(res, r.events[idx])
		idx = (idx + 1) % r.size
	}
	return res
}

type UILatencyPoint struct {
	Time    string  `json:"time"`
	ValueMs float64 `json:"value"`
}

type UILatencyRingBuffer struct {
	mu     sync.RWMutex
	points []UILatencyPoint
	size   int
	head   int
	count  int
	currentSecond string
	currentSum    float64
	currentCount  int
}

func NewUILatencyRingBuffer(size int) *UILatencyRingBuffer {
	return &UILatencyRingBuffer{
		points: make([]UILatencyPoint, size),
		size:   size,
	}
}

func (r *UILatencyRingBuffer) Add(ms float64) {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now().UTC()
	sec := now.Format("15:04:05")

	if r.currentSecond == "" {
		r.currentSecond = sec
	}

	if sec != r.currentSecond {
		// Flush previous second
		avg := 0.0
		if r.currentCount > 0 {
			avg = r.currentSum / float64(r.currentCount)
		}
		
		r.points[r.head] = UILatencyPoint{
			Time:    r.currentSecond,
			ValueMs: avg,
		}
		r.head = (r.head + 1) % r.size
		if r.count < r.size {
			r.count++
		}

		// Reset for new second
		r.currentSecond = sec
		r.currentSum = 0
		r.currentCount = 0
	}

	r.currentSum += ms
	r.currentCount++
}

func (r *UILatencyRingBuffer) Get() []UILatencyPoint {
	r.mu.RLock()
	defer r.mu.RUnlock()
	res := make([]UILatencyPoint, 0, r.count+1)
	
	idx := r.head
	if r.count < r.size {
		idx = 0
	}
	for i := 0; i < r.count; i++ {
		res = append(res, r.points[idx])
		idx = (idx + 1) % r.size
	}
	
	// Append the currently aggregating second
	if r.currentCount > 0 {
		res = append(res, UILatencyPoint{
			Time:    r.currentSecond,
			ValueMs: r.currentSum / float64(r.currentCount),
		})
	}
	
	return res
}

func (s *Server) HandleUIStatus(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	activeConns := len(s.activeSessions)
	s.mu.RUnlock()

	status := map[string]interface{}{
		"active_connections": activeConns,
		"pool_connections":   s.pool.GetActiveCount(),
		"pool_ready":         s.pool.IsReady(),
		"events":             s.uiBuffer.Get(),
		"latency_series":     s.latencyBuffer.Get(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
}

func (s *Server) RecordLatency(ms float64) {
	if s.latencyBuffer != nil {
		s.latencyBuffer.Add(ms)
	}
}

// DispatchAudit pushes an event to the local UI ring buffer and the remote webhook
func (s *Server) DispatchAudit(event AuditEvent) {
	s.uiBuffer.Add(UIAuditEvent{
		Time:     event.Timestamp, // might be empty, UI buffer will set it
		ClientID: event.ClientID,
		SQL:      event.SQL,
		Status:   event.Status,
		Reason:   event.Error,
	})

	if s.Webhook != nil {
		s.Webhook.Dispatch(event)
	}
}
