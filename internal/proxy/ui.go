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
	// Iterate from oldest to newest, but wait, UI might want newest to oldest?
	// The frontend appends to bottom, so it expects oldest to newest.
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

func (s *Server) HandleUIStatus(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	activeConns := len(s.activeSessions)
	s.mu.RUnlock()

	status := map[string]interface{}{
		"active_connections": activeConns,
		"pool_connections":   s.pool.GetActiveCount(),
		"pool_ready":         s.pool.IsReady(),
		"events":             s.uiBuffer.Get(),
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(status)
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
