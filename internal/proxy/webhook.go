package proxy

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"
)

type AuditEvent struct {
	Event     string `json:"event"`
	ClientID  string `json:"client_id"`
	SQL       string `json:"sql,omitempty"`
	Status    string `json:"status,omitempty"`
	Error     string `json:"error,omitempty"`
	Timestamp string `json:"timestamp"`
}

type WebhookDispatcher struct {
	url     string
	eventCh chan AuditEvent
	client  *http.Client
	logger  *slog.Logger
}

func NewWebhookDispatcher(url string, logger *slog.Logger) *WebhookDispatcher {
	if url == "" {
		return nil
	}

	d := &WebhookDispatcher{
		url:     url,
		eventCh: make(chan AuditEvent, 10000), // Buffer to absorb spikes
		client: &http.Client{
			Timeout: 3 * time.Second, // Fast timeout for SIEM
		},
		logger: logger,
	}

	// Start 5 worker goroutines for webhook dispatching
	for i := 0; i < 5; i++ {
		go d.worker()
	}

	return d
}

func (d *WebhookDispatcher) Dispatch(event AuditEvent) {
	if d == nil {
		return
	}

	event.Timestamp = time.Now().UTC().Format(time.RFC3339)

	select {
	case d.eventCh <- event:
		// Successfully queued
	default:
		// Queue full, drop the event to prevent blocking the proxy
		WebhookDroppedEventsTotal.Inc()
		d.logger.Warn("Audit webhook queue full, dropping event", "client_id", event.ClientID)
	}
}

func (d *WebhookDispatcher) worker() {
	for event := range d.eventCh {
		payload, err := json.Marshal(event)
		if err != nil {
			d.logger.Error("Failed to marshal audit event", "error", err)
			continue
		}

		resp, err := d.client.Post(d.url, "application/json", bytes.NewBuffer(payload))
		if err != nil {
			d.logger.Error("Failed to send audit webhook", "error", err, "url", d.url)
			continue
		}
		resp.Body.Close()

		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			d.logger.Error("Audit webhook returned non-200 status", "status", resp.StatusCode)
		}
	}
}
