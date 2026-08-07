package proxy

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/pbkdf2"
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

func (s *Server) HandleGenerateCredentials(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// S2: Require admin token authentication.
	// Set AGENTIAM_ADMIN_TOKEN in the environment to secure this endpoint.
	adminToken := os.Getenv("AGENTIAM_ADMIN_TOKEN")
	if adminToken == "" {
		http.Error(w, "credential generation is disabled: AGENTIAM_ADMIN_TOKEN is not set", http.StatusServiceUnavailable)
		return
	}
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
		s.logger.Warn("Unauthenticated credential generation attempt", "remote", r.RemoteAddr)
		AuthFailuresTotal.Inc()
		http.Error(w, "unauthorized: Bearer token required", http.StatusUnauthorized)
		return
	}
	supplied := strings.TrimPrefix(authHeader, "Bearer ")
	if subtle.ConstantTimeCompare([]byte(supplied), []byte(adminToken)) != 1 {
		s.logger.Warn("Invalid admin token in credential generation attempt", "remote", r.RemoteAddr)
		AuthFailuresTotal.Inc()
		http.Error(w, "unauthorized: invalid token", http.StatusUnauthorized)
		return
	}

	var req struct {
		AgentID    string `json:"agent_id"`
		TTLSeconds int    `json:"ttl_seconds,omitempty"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	if req.AgentID == "" {
		http.Error(w, "agent_id is required", http.StatusBadRequest)
		return
	}
	
	ttl := req.TTLSeconds
	if ttl <= 0 {
		ttl = 3600 // Default 1 hour
	}

	// Generate a secure random password for the agent
	passwordBytes := make([]byte, 16)
	_, _ = rand.Read(passwordBytes)
	password := base64.URLEncoding.EncodeToString(passwordBytes)

	// Create SCRAM secret
	salt := make([]byte, 16)
	_, _ = rand.Read(salt)
	iters := 4096
	
	// pbkdf2
	saltedPassword := pbkdf2.Key([]byte(password), salt, iters, 32, sha256.New)
	
	// ClientKey = HMAC(SaltedPassword, "Client Key")
	macClient := hmac.New(sha256.New, saltedPassword)
	macClient.Write([]byte("Client Key"))
	clientKey := macClient.Sum(nil)
	
	// StoredKey = HASH(ClientKey)
	hashStored := sha256.New()
	hashStored.Write(clientKey)
	storedKey := hashStored.Sum(nil)
	
	// ServerKey = HMAC(SaltedPassword, "Server Key")
	macServer := hmac.New(sha256.New, saltedPassword)
	macServer.Write([]byte("Server Key"))
	serverKey := macServer.Sum(nil)

	scramSecret := fmt.Sprintf("SCRAM-SHA-256$%d:%s$%s:%s", 
		iters, 
		base64.StdEncoding.EncodeToString(salt), 
		base64.StdEncoding.EncodeToString(storedKey), 
		base64.StdEncoding.EncodeToString(serverKey))

	s.store.AddEphemeralAgent(req.AgentID, scramSecret, ttl)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"agent_id": req.AgentID,
		"password": password,
		"ttl_seconds": ttl,
	})
}

// DispatchAudit pushes an event to the local UI ring buffer and the remote webhook
func (s *Server) DispatchAudit(event AuditEvent) {
	if event.Timestamp == "" {
		event.Timestamp = time.Now().Format(time.RFC3339)
	}

	s.uiBuffer.Add(UIAuditEvent{
		Time:     event.Timestamp,
		ClientID: event.ClientID,
		SQL:      event.SQL,
		Status:   event.Status,
		Reason:   event.Error,
	})

	if s.Webhook != nil {
		s.Webhook.Dispatch(event)
	}

	for _, sink := range s.auditSinks {
		go func(sk AuditSink) {
			if err := sk.Write(event); err != nil {
				s.logger.Error("Failed to write to audit sink", "error", err)
			}
		}(sink)
	}
}
