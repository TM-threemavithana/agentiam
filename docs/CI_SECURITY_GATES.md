# AgentIAM CI Security Quality Gates

This document defines the automated CI security gates, local developer execution procedures, tool pinnings, and active threat-model boundaries enforced across AgentIAM.

---

## 1. Automated Quality Gates Overview

The continuous integration pipeline (`.github/workflows/ci.yml`) enforces nine mandatory quality and security gates on every push and pull request:

| Gate | Purpose & Command | Enforcement Threshold |
|---|---|---|
| **1. Go Formatting** | `gofmt -l .` / `make fmt-check` | **Fail-closed:** Any unformatted Go file aborts the build. |
| **2. Dependency Verification** | `go mod verify` / `make verify` | Verifies SHA-256 sums of all downloaded modules against `go.sum`. |
| **3. Legacy Dependency Guard** | `make check-pgproto` | Prevents re-introduction of vulnerable `github.com/jackc/pgproto3` (GO-2026-4518). |
| **4. Static Analysis** | `go vet ./...` / `make vet` | Detects suspicious constructs, lock/mutex copies, and unreachable branches. |
| **5. Build Verification** | `go build -v ./cmd/...` / `make build-all` | Compiles all AgentIAM binaries (`agentiam`, `agentiam-cp`, `agentiamctl`). |
| **6. Unit & Regression Tests** | `go test -count=1 ./...` / `make test` | Executes all package unit and policy regression tests with cache disabled. |
| **7. Concurrency & Race Detection**| `go test -race -count=1 ./...` / `make race` | Exercises thread-safety across connection pools and catalog cache verifiers. |
| **8. Vulnerability Analysis** | `govulncheck ./...` / `make vulncheck` | Scans call graphs against the official Go vulnerability database (`vuln.go.dev`). |
| **9. PostgreSQL 15 Integration** | `go test -v -tags=integration ./internal/proxy` | Executes the complete live PostgreSQL 15 integration and view-masking suite. |

---

## 2. GitHub Actions Security & Least-Privilege Architecture

The workflow configuration applies defense-in-depth principles:
- **Top-Level Read-Only Permissions:** `permissions: contents: read` ensures compromised runner processes cannot modify repository state, create releases, or overwrite tags.
- **Action Pinning:** Third-party actions are pinned to reviewed immutable commit SHAs with version comments:
  - `actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683` (`# v4.2.2`) with `persist-credentials: false`.
  - `actions/setup-go@3041ec5666fa9f4fa7b6b0c6395b0606f7fb7e6d` (`# v5.3.0`).
- **Secret Isolation:** Pull-request runs from untrusted forks do not have access to production deployment secrets.
- **PostgreSQL 15 Integration Isolation:** The integration test job spins up an ephemeral PostgreSQL 15 container with isolated credentials (`POSTGRES_USER: postgres`, `POSTGRES_DB: testdb`) and health checks before test dispatch.
- **Job Timeouts:** Bounded timeouts (`timeout-minutes: 20` for unit, `timeout-minutes: 25` for integration) prevent hung processes from blocking runners.

---

## 3. Local Developer Verification Workflow

Developers must run the exact quality gates locally before pushing changes:

```bash
# 1. Check formatting
make fmt-check

# 2. Automatically format Go code
make fmt

# 3. Verify module dependencies
make verify

# 4. Check for retired pgproto3/v2 dependency
make check-pgproto

# 5. Run static analysis
make vet

# 6. Build all binaries
make build-all

# 7. Run unit test suite
make test

# 8. Run race detector
make race

# 9. Run local CI pipeline bundle
make ci-local

# 10. Run live PostgreSQL integration tests (requires Docker / PostgreSQL 15)
make test-integration

# 11. Run Go vulnerability scanner
make vulncheck
```

---

## 4. Vulnerability Audit & Transitive Findings

A scan with `govulncheck@v1.9.0` (DB updated 2026-11-05) reveals findings categorized as follows:

1. **Retired Vulnerability Confirmed Absent:**
   - `github.com/jackc/pgproto3/v2` (GO-2026-4518 / CVE-2026-32286): **RESOLVED.** The dependency is completely eliminated from `go.mod` and `go.sum`. All PostgreSQL wire protocol frames are handled via `pgx/v5`.
2. **Standard Library Go 1.25.11 Findings:**
   - Vulnerabilities in standard library packages (`crypto/x509`, `crypto/tls`, `net/http`, `encoding/xml`, `encoding/asn1`) exist in Go toolchain `go1.25.11` (fixed in patch releases `go1.25.13` and `go1.26.10`).
   - *Remediation Boundary:* A planned toolchain bump to Go 1.26.10 (as tracked in PR 20 / upstream hardening) resolves standard library CVEs without modifying core proxy code.
3. **Transitive Dependency Findings:**
   - `github.com/klauspost/compress` (GO-2026-6865, fixed in v1.20.2): Indirect dependency via OTLP/HTTP.
   - `golang.org/x/net` (GO-2026-6617, fixed in v0.60.0): Transitive HTTP/2 HPACK encoder.
   - `golang.org/x/text` (GO-2026-6629, fixed in v0.41.0): Stringprep/SASL dependency.
   - `go.opentelemetry.io/otel/exporters/otlp` (GO-2026-4985, fixed in v1.43.0): OTLP exporter body limits.

---

## 5. Active Security Risk Register Boundaries

The following security risks remain active and must remain visible in all deployment reviews:

### RISK-VIEW-02: Direct PostgreSQL Access Bypass (SEC-P2-01)
- **Status:** **OPEN (RELEASE BLOCKER)**
- **Boundary:** If a client or agent can reach PostgreSQL port 5432 directly, all proxy-level AST masking, view provenance, and table filtering are completely bypassed.
- **Requirement:** Network-level isolation (private VPC subnets, firewall rules, security groups) and strict database user privilege separation (revoking raw table access from application roles) are required before production sign-off.

### Runtime Catalog Verification TOCTOU Multi-Connection Limitation
- **Status:** **DOCUMENTED BOUNDARY**
- **Boundary:** Catalog verification (`EnsureFreshness`) runs over a dedicated proxy catalog connection, while client SQL runs over an upstream pool connection. A concurrent `CREATE OR REPLACE VIEW` committing between catalog check and query execution represents an inherent multi-connection Time-of-Check to Time-of-Use gap.
- **Mitigation:** Production TTL is bounded to 50ms; database maintenance windows or DDL migration locks must be enforced for zero-window safety.

### RISK-LOG-01: Panic Diagnostic Secret Exposure
- **Status:** **MITIGATED**
- **Boundary:** Diagnostic stack traces and panic handlers could inadvertently leak sensitive credentials (tokens, connection strings) to system logs.
- **Mitigation:** Bounded sanitized stack traces and regex credential redaction (`safePanicSummary`, `sanitizedStackTrace`).

### RISK-POOL-01: Terminal CAS Transition Cleanup Failure
- **Status:** **MITIGATED**
- **Boundary:** Upstream connection pool cleanup failure after terminal CAS state transitions could lead to connection leakage or dirty session state.
- **Mitigation:** Atomic state transitions, idempotent double-release safeguards, and active connection health checks on checkout failure.
