package proxy

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestInitTracer_StdoutFallback(t *testing.T) {
	os.Unsetenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	os.Setenv("OTEL_SERVICE_NAME", "agentiam-test")
	defer os.Unsetenv("OTEL_SERVICE_NAME")

	tp, err := InitTracer()
	if err != nil {
		t.Fatalf("InitTracer failed: %v", err)
	}
	if tp == nil {
		t.Fatal("Expected non-nil TracerProvider")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	tr := tp.Tracer("test")
	_, span := tr.Start(ctx, "test-span")
	span.End()

	if err := tp.Shutdown(ctx); err != nil {
		t.Fatalf("Failed to shut down tracer: %v", err)
	}
}

// TestInitTracer_OTLPExport_Success validates that AgentIAM can successfully initialize
// an OTLP HTTP trace exporter and deterministically flush traces to a local collector.
func TestInitTracer_OTLPExport_Success(t *testing.T) {
	var receivedCount int32
	var receivedBytes int64
	var receivedPath string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "traces") {
			atomic.AddInt32(&receivedCount, 1)
			receivedPath = r.URL.Path
			body, _ := io.ReadAll(r.Body)
			atomic.StoreInt64(&receivedBytes, int64(len(body)))
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{}`))
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	os.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", server.URL)
	os.Setenv("OTEL_EXPORTER_OTLP_INSECURE", "true")
	os.Setenv("OTEL_SERVICE_NAME", "agentiam-otlp-test")
	defer func() {
		os.Unsetenv("OTEL_EXPORTER_OTLP_ENDPOINT")
		os.Unsetenv("OTEL_EXPORTER_OTLP_INSECURE")
		os.Unsetenv("OTEL_SERVICE_NAME")
	}()

	tp, err := InitTracer()
	if err != nil {
		t.Fatalf("InitTracer with OTLP failed: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	tr := tp.Tracer("agentiam/proxy/test")
	_, span := tr.Start(ctx, "query-execution")
	span.End()

	// Explicit ForceFlush ensures deterministic synchronous export rather than relying on background timers
	if err := tp.ForceFlush(ctx); err != nil {
		t.Fatalf("tp.ForceFlush returned unexpected error: %v", err)
	}

	if err := tp.Shutdown(ctx); err != nil {
		t.Fatalf("tp.Shutdown returned unexpected error: %v", err)
	}

	// Deterministic assertion: fail if zero requests reached the collector
	if count := atomic.LoadInt32(&receivedCount); count == 0 {
		t.Fatalf("Expected at least 1 trace export request to reach collector, got 0")
	}

	// Verify that non-empty serialized trace data was received
	if b := atomic.LoadInt64(&receivedBytes); b == 0 {
		t.Fatalf("Expected non-empty serialized trace body, got 0 bytes")
	}

	if !strings.HasSuffix(receivedPath, "/v1/traces") {
		t.Fatalf("Expected export path to end in /v1/traces, got: %s", receivedPath)
	}
}

// TestInitTracer_OTLPExport_CollectorError_500 verifies exporter error handling when the collector returns HTTP 500.
func TestInitTracer_OTLPExport_CollectorError_500(t *testing.T) {
	var receivedCount int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&receivedCount, 1)
		http.Error(w, "Collector Internal Error 500", http.StatusInternalServerError)
	}))
	defer server.Close()

	os.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", server.URL)
	os.Setenv("OTEL_EXPORTER_OTLP_INSECURE", "true")
	defer func() {
		os.Unsetenv("OTEL_EXPORTER_OTLP_ENDPOINT")
		os.Unsetenv("OTEL_EXPORTER_OTLP_INSECURE")
	}()

	tp, err := InitTracer()
	if err != nil {
		t.Fatalf("InitTracer failed: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	tr := tp.Tracer("test-500")
	_, span := tr.Start(ctx, "test-500-span")
	span.End()

	// Verify that exporter error is returned and captured deterministically on flush
	flushErr := tp.ForceFlush(ctx)
	if flushErr == nil {
		t.Fatal("Expected export error when collector returns HTTP 500, got nil")
	}
	if !strings.Contains(flushErr.Error(), "500") {
		t.Fatalf("Expected error message to mention 500 status, got: %v", flushErr)
	}

	// Verify that a request was actually delivered to the collector
	if count := atomic.LoadInt32(&receivedCount); count == 0 {
		t.Fatal("Expected request to be delivered to collector before failure, got 0")
	}

	// Process must not terminate; shutdown completes without hanging using fresh bounded cleanup context.
	// We do not require successful export after an intentional collector failure.
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer shutdownCancel()
	if err := tp.Shutdown(shutdownCtx); err != nil {
		t.Logf("Shutdown completed with expected cleanup status after intentional 500 error: %v", err)
	}
}

// TestInitTracer_OTLPExport_CollectorError_429 verifies exporter behavior when the collector returns HTTP 429 Too Many Requests.
func TestInitTracer_OTLPExport_CollectorError_429(t *testing.T) {
	var receivedCount int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&receivedCount, 1)
		w.Header().Set("Retry-After", "30")
		http.Error(w, "Rate limited", http.StatusTooManyRequests)
	}))
	defer server.Close()

	os.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", server.URL)
	os.Setenv("OTEL_EXPORTER_OTLP_INSECURE", "true")
	defer func() {
		os.Unsetenv("OTEL_EXPORTER_OTLP_ENDPOINT")
		os.Unsetenv("OTEL_EXPORTER_OTLP_INSECURE")
	}()

	tp, err := InitTracer()
	if err != nil {
		t.Fatalf("InitTracer failed: %v", err)
	}

	// 429 triggers exponential backoff retry; bounded context ensures timeout without indefinite hang
	ctx, cancel := context.WithTimeout(context.Background(), 1500*time.Millisecond)
	defer cancel()

	tr := tp.Tracer("test-429")
	_, span := tr.Start(ctx, "test-429-span")
	span.End()

	flushErr := tp.ForceFlush(ctx)
	if flushErr == nil {
		t.Fatal("Expected export error or timeout when collector returns HTTP 429, got nil")
	}

	// Verify request was actually sent
	if count := atomic.LoadInt32(&receivedCount); count == 0 {
		t.Fatal("Expected request to be delivered to collector before 429 response, got 0")
	}

	// Process must not terminate; shutdown completes without hanging using fresh bounded cleanup context.
	// We do not require successful export after an intentional collector failure.
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer shutdownCancel()
	if err := tp.Shutdown(shutdownCtx); err != nil {
		t.Logf("Shutdown completed with expected cleanup status after intentional 429 error: %v", err)
	}
}

// TestInitTracer_OTLPExport_OversizedResponse verifies bounded response reading on collector error.
//
// Security Guarantee Documentation:
//   - Upstream Fix (CVE-2026-27616 / GO-2026-4985): Patched go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp
//     v1.47.0 bounds HTTP response body reading to 4 MB (4194304 bytes), preventing unbounded allocation / OOM when interacting
//     with misconfigured or hostile telemetry backends.
//   - Local Regression Test: Verifies that AgentIAM's tracer integration completes within bounded time, captures the
//     "response body too large" error condition predictably, and does not crash or terminate the process.
func TestInitTracer_OTLPExport_OversizedResponse(t *testing.T) {
	var receivedCount int32
	// 5 MB response payload exceeding the 4 MB limit in otlptracehttp v1.47.0
	oversizedData := strings.Repeat("E", 5*1024*1024)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&receivedCount, 1)
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(oversizedData))
	}))
	defer server.Close()

	os.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", server.URL)
	os.Setenv("OTEL_EXPORTER_OTLP_INSECURE", "true")
	defer func() {
		os.Unsetenv("OTEL_EXPORTER_OTLP_ENDPOINT")
		os.Unsetenv("OTEL_EXPORTER_OTLP_INSECURE")
	}()

	tp, err := InitTracer()
	if err != nil {
		t.Fatalf("InitTracer failed: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	tr := tp.Tracer("test-oversized")
	_, span := tr.Start(ctx, "test-oversized-span")
	span.End()

	flushErr := tp.ForceFlush(ctx)
	if flushErr == nil {
		t.Fatal("Expected error when collector returns oversized response body, got nil")
	}

	// Fatal assertion: The test must fail unless the exporter returns the expected response-body-size-limit error
	if !strings.Contains(flushErr.Error(), "response body too large") && !strings.Contains(flushErr.Error(), "4194304") {
		t.Fatalf("Expected response-body-size-limit error ('response body too large' or '4194304'), got: %v", flushErr)
	}

	if count := atomic.LoadInt32(&receivedCount); count == 0 {
		t.Fatal("Expected request to be delivered to collector, got 0")
	}

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer shutdownCancel()
	_ = tp.Shutdown(shutdownCtx)
}

func TestApplicationStartup_ToolchainVerification(t *testing.T) {
	cert, err := GenerateEphemeralCert()
	if err != nil {
		t.Fatalf("GenerateEphemeralCert failed: %v", err)
	}
	if len(cert.Certificate) == 0 {
		t.Fatal("Expected valid certificate slice")
	}

	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
	}
	if len(cfg.Certificates) != 1 {
		t.Fatalf("Expected 1 certificate in TLS config, got: %d", len(cfg.Certificates))
	}
}
