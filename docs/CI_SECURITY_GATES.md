# AgentIAM CI Security Quality Gates

This document defines the automated CI security gates, local developer execution procedures, tool pinnings, dependency verification mechanics, and active threat-model boundaries enforced across AgentIAM.

---

## 1. Automated Quality Gates Overview

The continuous integration pipeline (`.github/workflows/ci.yml`) enforces ten mandatory quality and security gates on every push and pull request:

| Gate | Purpose & Command | Enforcement Threshold |
|---|---|---|
| **1. Go Formatting** | `gofmt -l .` / `make fmt-check` | **Fail-closed:** Any unformatted Go source file aborts the workflow. |
| **2. Cryptographic Dependency Verification** | `go mod verify` / `make verify` | **Fail-closed:** Validates SHA-256 sums of all downloaded modules against `go.sum` to guarantee supply-chain integrity (see Section 3 for scope clarification). |
| **3. Legacy Dependency Guard** | `make check-pgproto` | **Fail-closed:** Prevents re-introduction of retired `github.com/jackc/pgproto3/v2` (GO-2026-4518). |
| **4. Static Analysis** | `go vet ./...` / `make vet` | **Fail-closed:** Detects suspicious constructs, lock/mutex copies, and unreachable branches. |
| **5. Comprehensive Linting** | `golangci-lint run ./...` / `make lint` | **Fail-closed:** Pinned to `v1.64.6` with zero tolerated warnings across active linters (`govet`, `ineffassign`, `staticcheck`, `gosimple`, `unused`, `typecheck`, `bodyclose`, `nilerr`, `noctx`). |
| **6. Build Verification** | `go build -v ./cmd/...` / `make build-all` | **Fail-closed:** Compiles all AgentIAM binaries (`agentiam`, `agentiam-cp`, `agentiamctl`). |
| **7. Unit & Regression Tests** | `go test -count=1 ./...` / `make test` | **Fail-closed:** Executes all package unit and policy regression tests with cache disabled. |
| **8. Concurrency & Race Detection**| `go test -race -count=1 ./...` / `make race` | **Fail-closed:** Exercises thread-safety across connection pools and catalog cache verifiers. |
| **9. Vulnerability Analysis** | `govulncheck ./...` / `make vulncheck` | **Fail-closed:** Scans call graphs against the official Go vulnerability database (`vuln.go.dev`). Pinned uniformly to `v1.9.0` across both CI and local developer environments. Any non-zero exit code halts the pipeline with no error swallowing. |
| **10. PostgreSQL 15 Integration** | `go test -v -tags=integration ./internal/proxy` | **Fail-closed:** Executes the complete live PostgreSQL 15 integration and view-masking suite with container cleanup safeguards (`TESTCONTAINERS_RYUK_DISABLED: "false"`). |

---

## 2. GitHub Actions Security & Least-Privilege Architecture

The workflow configurations (`.github/workflows/ci.yml` and `.github/workflows/release.yml`) adhere to strict defense-in-depth principles:

- **Workflow-Level Read-Only Permissions:**
  Both workflows define top-level `permissions: contents: read`. Compromised runner steps cannot push commits, modify repository files, or tamper with release artifacts.
- **Job-Level Scoped Permissions:**
  In `release.yml`, elevated permissions (`contents: write`, `packages: write`) are strictly confined to the `goreleaser` job and are never granted globally.
- **Immutable Action Pinning:**
  All third-party GitHub Actions are pinned to full immutable 40-character commit SHAs with clarifying version comments:
  - `actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683` (`# v4.2.2`) with `persist-credentials: false`.
  - `actions/setup-go@3041ec5666fa9f4fa7b6b0c6395b0606f7fb7e6d` (`# v5.3.0`) targeting `go-version: '1.26.x'`.
  - `docker/login-action@9780b0c442fbb1117ed29e0efdff1e18412f7567` (`# v3.3.0`).
  - `goreleaser/goreleaser-action@90a305d81324da521f68220170f3167e60523447` (`# v6.2.1`).
- **Tool Version Pinning:**
  - `golangci-lint`: pinned to `v1.64.6` (compiled with the Go 1.26 toolchain).
  - `govulncheck`: pinned to `v1.9.0` uniformly across CI workflows and local developer environments.
- **Strict Failure Propagation:**
  Security scanners (`govulncheck`, `golangci-lint`, `go vet`, `go mod verify`) execute directly without fallback `||` handlers or `continue-on-error` directives. Non-zero exit codes fail the step immediately.
- **Ephemeral Integration Isolation via Testcontainers:**
  The PostgreSQL integration job runs on standard `ubuntu-latest` runners with direct Docker daemon access (`/var/run/docker.sock`), where Testcontainers spins up isolated ephemeral `postgres:15-alpine` instances with active reaper container safeguards (`TESTCONTAINERS_RYUK_DISABLED: "false"`).
- **Execution Timeouts:**
  Bounded timeouts (`timeout-minutes: 20` for unit/lint, `timeout-minutes: 25` for integration) prevent hung processes from exhausting CI runners.

---

## 3. Dependency Integrity vs. Vulnerability Analysis Mechanics

A critical distinction exists between module verification and vulnerability scanning:

1. **`go mod verify` (Cryptographic Checksum Verification):**
   - **Purpose:** Verifies that the downloaded module files on disk match the recorded cryptographic SHA-256 hashes (`h1:...`) in `go.sum`.
   - **Threat Addressed:** Detects supply-chain tampering, unauthorized cache mutations, corrupted downloads, or repository man-in-the-middle attacks.
   - **Limitation:** `go mod verify` does **NOT** inspect code for security flaws, CVEs, or design defects. A module can pass `go mod verify` with 100% integrity while harboring critical known vulnerabilities.
2. **`govulncheck` (Code-Level Vulnerability Analysis):**
   - **Purpose:** Analyzes the actual AST and call graphs of the application against the curated Go vulnerability database (`vuln.go.dev`).
   - **Distinction:** Distinguishes between merely required modules, imported packages, and actually reachable vulnerable call symbols.

---

## 4. Vulnerability Audit & Toolchain Upgrade

### Toolchain Upgrade to Go 1.26.10
AgentIAM upgraded its `go.mod` directive from `go 1.25.11` to `go 1.26.10`. This eliminates 34 standard-library vulnerabilities affecting `crypto/x509`, `crypto/tls`, `net/http`, `encoding/xml`, and `encoding/asn1` present in the older unpatched toolchain release.

### Targeted Module Upgrades
Reachable and transitive module findings identified during security auditing were remediated via minimal, non-breaking upgrades:
- **`github.com/klauspost/compress` (upgraded to `v1.20.2`):** Resolves GO-2026-6865.
- **`golang.org/x/net` (upgraded to `v0.62.0`):** Resolves GO-2026-6617 and GO-2026-5026.
- **`golang.org/x/text` (upgraded to `v0.43.0`):** Resolves GO-2026-6629 and GO-2026-5970.
- **`go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp` (upgraded to `v1.47.0`):** Resolves GO-2026-4985.
- **`google.golang.org/grpc` (upgraded to `v1.85.0`):** Resolves GO-2026-6061.
- **`golang.org/x/crypto` (upgraded to `v0.58.1-0.20261009181718-2f1f834330b2`):** Resolves module-level advisory GO-2026-5932 in unused `openpgp` subpackages.

### Audit Summary
- **Symbol Results (Reachable Vulnerabilities):** **0**
- **Package Results (Imported Packages):** **0**
- **Module Results (Required Modules):** **0**
- **Scanner Exit Code:** **0**

---

## 5. Active Security Risk Register Boundaries

The following security risks remain active and must remain visible in all architectural reviews:

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
