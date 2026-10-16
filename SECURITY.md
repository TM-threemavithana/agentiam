# Security Policy

## Fixed & Remediated Vulnerabilities

### GO-2026-4518 (Denial of Service in `pgproto3/v2`)
- **Status:** RESOLVED / REMEDIATED
- **Components:** `go.mod`, `internal/proxy/malformed_wire_test.go`
- **Resolution:**
  The vulnerable legacy dependency `github.com/jackc/pgproto3/v2` has been completely eliminated from the module dependency graph. AgentIAM now relies exclusively on `github.com/jackc/pgx/v5/pgproto3` via `pgx/v5 v5.11.0`. In addition, strict packet body length bounds and field count validation are enforced in `internal/proxy/decoder.go`, preventing memory exhaustion and panic attacks on corrupt wire frames (verified via `TestDecoder_GO_2026_4518_MalformedDataRow`).

### SELECT bypass in Postgres AllowedStatements
- **Status:** FIXED
- **Component:** `internal/ast/filter.go`
- `SELECT` statements were not checked against `AllowedStatements`. An agent configured with only `INSERT` permission could execute arbitrary SELECT queries. Now enforced with the same `isAllowed()` check applied to INSERT/UPDATE/DELETE.

### Unauthenticated Credential Endpoint
- **Status:** FIXED
- **Component:** `internal/proxy/ui.go`
- `POST /api/credentials` previously had no authentication. Now requires a `Bearer <token>` header matching `AGENTIAM_ADMIN_TOKEN`. Returns 503 if the env var is unset.

### AllowedTables not enforced for Postgres
- **Status:** FIXED
- **Component:** `internal/ast/filter.go`
- Table-level ACL was only enforced for MySQL. Now enforced for Postgres via a post-rule AST walk that collects all `RangeVar` references and checks them against `allowed_tables`.

### Metrics/Dashboard bound to all interfaces
- **Status:** FIXED
- **Component:** `cmd/agentiam/main.go`
- Default `AGENTIAM_METRICS_ADDR` changed from `:9090` (all interfaces) to `127.0.0.1:9090` (loopback only). Override with `AGENTIAM_METRICS_ADDR=":9090"` if you need external access behind a VPN.

---

## AST Security Controls & View Provenance (Phase 2 Hardening)

### Data Masking & View Provenance
- **Status:** ENFORCED (Runtime & AST Verification)
- **Components:** `internal/ast/view_provenance.go`, `internal/proxy/catalog_verifier.go`, `internal/proxy/session.go`

View masking operates via AST semantic analysis with live PostgreSQL catalog provenance tracking:
1. **Relation Whitelisting & Provenance:** Views querying masked tables must be explicitly declared in policy with column mappings. Incomplete column mappings on masked tables fail closed.
2. **Fail-Closed Expression Semantics (SEC-P2-07):** Sensitive columns can only be directly projected for string constant redaction (`'[REDACTED]'`). Any reference inside `WHERE`, `JOIN ON`, `GROUP BY`, `ORDER BY`, `HAVING`, window, subqueries, or derived expressions (`UPPER()`, concatenations, casts) is strictly rejected before database execution, regardless of whether the column is declared in `unexposed_columns`.
3. **Cross-Client Verified-View Cache Isolation (SEC-P2-06):** Verified view decisions are strictly partitioned by composite keys (`clientID:policyVersion:schema.viewName`). Verification for Client A never authorizes Client B. A failed verification for Client B never invalidates Client A's authorization.
4. **Runtime Schema Drift Enforcement (RISK-VIEW-01):** Catalog verification is integrated directly into query-time dispatch (`handleQueryMsg`, `handleParseMsg`, and `handleBindMsg`). Out-of-band DDL alters fail closed immediately (`SQLSTATE 57P01`) on existing sessions, new connections, and prepared statements.
5. **Nested View Dependency Validation (SEC-P2-08):** Outer view authorization recursively verifies all underlying view dependencies against approved policy definitions. Any alteration to an inner view invalidates dependent outer view authorizations.
6. **Immediate Policy Revocation:** Prepared statements and active sessions are dynamically revoked (Postgres `57P01`) on policy modification via synchronous notification hooks and version tracking.
7. **Direct Access Boundary:** For direct connection isolation requirements and deployment constraints, refer to [DEPLOYMENT_SECURITY.md](docs/DEPLOYMENT_SECURITY.md).

---

## Known Limitations & Security Risks

### RISK-VIEW-02: Direct PostgreSQL Access Bypass (SEC-P2-01)
- **Status:** OPEN (RELEASE BLOCKER)
- **Impact:** Direct client connections to PostgreSQL port 5432 bypass all proxy-level masking and AST rules.
- **Requirement:** Production sign-off requires independent verification of infrastructure network isolation (non-routable port 5432 from agent networks).

### RISK-LOG-01: Panic Diagnostic Secret Exposure
- **Status:** MITIGATED
- **Impact:** Diagnostic logs or panic handlers could expose sensitive credentials (tokens, passwords, connection strings) in stack traces.
- **Mitigation:** Panic handlers enforce sanitized stack traces and regex credential redaction (`sanitizedStackTrace`, `safePanicSummary`).

### RISK-POOL-01: Terminal CAS Transition Cleanup Failure
- **Status:** MITIGATED
- **Impact:** Upstream connection pool cleanup failure after terminal CAS state transitions could lead to connection leakage or state contamination.
- **Mitigation:** Atomic state transitions, idempotent double-release safeguards, and active connection health checks.

### RISK-AUDIT-01: Audit Sink Delivery Failure
- **Status:** MITIGATED
- **Impact:** Network failures in UDP/file audit sinks could result in dropped security audit records.

### RISK-POOL-02: Upstream Session Variable Sanitization
- **Status:** MITIGATED
- **Impact:** Dirty session variables from previous queries lingering on pooled connections.
- **Mitigation:** Connection discard on checkout failure and session state replay.

### Schema-Qualified Function Shadowing
- **Status:** Known Limitation
- **Component:** `internal/ast/filter.go`
- If a custom function shares a name with a blocked system function (e.g. `my_schema.pg_sleep`), it will be conservatively blocked.

### Time-Based Injection (pg_sleep)
- **Mitigation:** `AgentConfig.MaxExecutionTimeMs` forces context cancellation on slow queries.

### Warehouse Parser Regex Dialect Translation
- **Status:** Known Limitation
- **Component:** `internal/ast/warehouse_parsers.go`
- Snowflake and BigQuery dialect adapters use regex substitution before passing SQL to the MySQL/ANSI parser. Untrusted complex expressions should be avoided until full dialect AST parsers are implemented.
