# AgentIAM Deployment Security Architecture & Privilege Boundary Guide

## 1. Executive Summary & Threat Model Boundary

AgentIAM is an application-level, AST-analyzing database security proxy. It enforces default-deny table whitelisting, view masking, tenant isolation predicates, rate limits, and prepared statement authorization.

**Critical Security Boundary (SEC-P2-01 / RISK-VIEW-02):**
> **AgentIAM proxy-level masking and AST security rules ONLY protect connections routed through the AgentIAM proxy listener.**
>
> If an untrusted agent or compromised client process can directly establish a TCP connection to the PostgreSQL database listener (default port 5432) using credentials with `SELECT` privileges on PostgreSQL definer views, **all proxy masking is completely bypassed**. In standard PostgreSQL semantics, definer views execute with the privileges of the view owner, exposing raw underlying table columns to any role permitted to query the view.

Therefore, proxy-level software controls alone **CANNOT** guarantee data confidentiality without strict physical and network deployment controls.

---

## 2. Mandatory Network Isolation Deployment Model

To ensure security invariants hold in production, downstream deployments **MUST** enforce the following isolation architecture:

```
[ Client / AI Agent ]
         │ (Only allowed connection path)
         ▼ (Port 5433: mTLS / Agent IAM Token)
┌──────────────────────────────────────────────┐
│           AgentIAM Security Proxy            │
│  - AST Parsing & Strict Fail-Closed Redaction│
│  - View Mapping Provenance & Whitelisting    │
│  - Client Cache Isolation (SEC-P2-06)        │
│  - Runtime Drift Detection (RISK-VIEW-01)    │
│  - Sensitive Predicate Check (SEC-P2-07)     │
│  - Nested Dependency Check (SEC-P2-08)       │
│  - Immediate Dynamic Revocation (57P01)      │
│  - Tenant Isolation Predicate Injection      │
└──────────────────────────────────────────────┘
         │ (Internal Private VPC / Loopback / WireGuard)
         ▼ (Port 5432: Isolated Upstream Listener)
┌──────────────────────────────────────────────┐
│              PostgreSQL Database             │
│  - Bind to 127.0.0.1 or Private VPC subnet   │
│  - Ingress Firewall: Drop all except Proxy IP│
│  - Database Credentials stored in Vault      │
└──────────────────────────────────────────────┘
         ▲
         │ (BLOCKED BY FIREWALL & ACCESS CONTROL)
[ Direct Client Access to Port 5432: REJECTED ]
```

### Mandatory Production Controls:
1. **Network Firewall / Security Groups:**
   The PostgreSQL listener port (`5432`) must be unreachable from client or agent networks. Ingress rules must strictly allow connections solely from the AgentIAM proxy instance IP / security group.
2. **Credential Separation:**
   Client agents must never receive PostgreSQL upstream credentials. Client agents only authenticate to AgentIAM using their designated AgentIAM credentials (mTLS certificate or AgentIAM token). Upstream database passwords must be stored exclusively in secret managers (e.g., Vault, AWS Secrets Manager, GCP Secret Manager) and mounted directly into the AgentIAM proxy daemon.
3. **Loopback / Unix Domain Sockets for Colocated Containers:**
   In containerized or Kubernetes environments, AgentIAM should run as a sidecar container sharing a localhost or Unix domain socket with the database or client pod, preventing any ingress routing from outside the pod network namespace.

---

## 3. Database Privilege Hardening (Defense-in-Depth)

While network isolation prevents unauthorized direct connections, defense-in-depth within PostgreSQL should be implemented to minimize blast radius in the event of lateral network movement.

### Safe vs Unsafe Configurations

| Configuration Area | Unsafe / Vulnerable Pattern | Safe / Hardened Pattern |
|---|---|---|
| **Definer Views** | Views created by `postgres` or `superuser` exposing raw sensitive columns (`SELECT ssn FROM customers`) with `GRANT SELECT ON view TO agent_role`. If direct access is obtained, raw PII leaks immediately. | Views created with database-side redaction (e.g., `SELECT '[REDACTED]' AS ssn`) OR combined with strict proxy masking. |
| **Row Level Security (RLS)** | Assuming PostgreSQL RLS provides column masking. **PostgreSQL RLS provides row-level visibility filtering, not column-level data masking.** | Understand that RLS enforces which rows a role can see, but does NOT redact or mask sensitive columns in visible rows. Proxy AST masking or view projections must be used for column redaction. |
| **Direct Table Grants** | Granting `agent_db_role` SELECT privileges on raw sensitive base tables. | Denying / revoking SELECT on base tables with sensitive columns from application roles (`REVOKE SELECT ON customers FROM agent_db_role`). |
| **Search Path Hijacking** | Leaving `search_path` set to user-writable schemas (e.g. `public`), allowing function shadowing. | Explicitly locking `search_path = pg_catalog, public` and enforcing qualified schema references in view definitions. |
| **View Alteration & Drift** | Allowing database developers to alter approved view definitions without re-approving the AgentIAM policy. | Setting `definition_fingerprint` in AgentIAM policy; any view definition change causes immediate fail-closed denial via runtime freshness check. |

---

## 4. Runtime Verification Guarantees & Operational Trade-offs

### Freshness Verification Lifecycle (RISK-VIEW-01)
- **Invocation Path:** Query-time catalog freshness verification is invoked on every simple query (`handleQueryMsg`), extended query parse (`handleParseMsg`), and prepared statement bind (`handleBindMsg`) whenever an approved view or dependent relation is referenced.
- **Fail-Closed Semantics:** If catalog verification times out, connection to `pg_catalog` is lost, or the view fingerprint does not match the approved definition, the query is rejected immediately with `SQLSTATE 57P01`. Old trusted results are never retained on error.
- **Freshness Window & TTL Trade-off:**
  - When `TTL = 0` (strict mode): Catalog definitions are verified synchronously against `pg_catalog.pg_views` on every query dispatch. The stale-authorization window is 0 (immediate drift detection). Operational cost: One catalog query per client query referencing views.
  - When `TTL > 0` (cached mode): Catalog definitions are cached for up to the configured duration (e.g. 5 seconds). The maximum potential stale-authorization window is bounded by the TTL value. High-volume read environments may choose a small non-zero TTL to balance database catalog load.
- **TOCTOU Considerations:** Time-of-check to time-of-use (TOCTOU) gap is bounded by PostgreSQL transaction commit serialization. If a DDL transaction commits concurrently with a running query, the change takes effect on the next query or bind. Zero-window atomicity across concurrent DDL requires database-level advisory locking or deployment freeze windows.

### Cross-Client Cache Isolation (SEC-P2-06)
- **Isolation Boundary:** Verified decisions are indexed by `clientID:policyVersion:schema.viewName`.
- Verification performed for Client A is cryptographically isolated and never applied to Client B.
- Conflicting fingerprints or verification errors for Client B do not invalidate Client A's cached authorization.

### Nested View Dependency Verification (SEC-P2-08)
- Outer views automatically resolve and verify all underlying view dependencies recursively up to depth 5.
- Circular dependencies, missing dependencies, or alterations to inner views trigger cascading fail-closed denial on the outer view.

---

## 5. Formal Risk Register Status

| Risk ID | Title | Component | Status | Mitigation / Operational Boundary |
|---|---|---|---|---|
| **RISK-VIEW-02** (SEC-P2-01) | Direct PostgreSQL Access Bypass | Network / Infra | **OPEN (RELEASE BLOCKER)** | Requires physical/VPC network isolation and credential separation. Cannot be resolved by proxy alone. |
| **RISK-VIEW-01** | Database-View Definition Drift | `CatalogVerifier` / `Session` | **RESOLVED / MITIGATED** | Query-time freshness checks (`EnsureFreshness`) on `Query`, `Parse`, and `Bind`. Fail-closed on mismatch. |
| **SEC-P2-06** | Cross-Client Cache Pollution | `CatalogVerifier` | **RESOLVED** | Cache keys partitioned by `clientID:policyVersion:schema.viewName`. Total tenant isolation. |
| **SEC-P2-07** | Sensitive View Predicates | `ast.ValidateViewProvenance` | **RESOLVED** | Strict rejection of sensitive columns in WHERE, JOIN ON, HAVING, GROUP BY, ORDER BY, WINDOW, and subqueries. |
| **SEC-P2-08** | Nested View Dependency Drift | `CatalogVerifier` / `ast` | **RESOLVED** | Recursive dependency resolution and cascading drift invalidation. Depth capped at 5; cycles rejected. |
| **RISK-LOG-01** | Panic Diagnostic Secret Exposure | `Session` / `Logger` | **RESOLVED** | Sanitized stack traces, safe panic summaries, regex credential redaction. |
| **RISK-POOL-01** | Terminal CAS Cleanup Failure | `Pool` / `Worker` | **RESOLVED** | Atomic CAS state transitions, idempotent release, connection discarding on failure. |
| **RISK-AUDIT-01** | External Audit Sink Delivery Drops | `AuditSink` | **MONITORED** | Asynchronous buffered delivery; errors logged to local system logger. |
| **RISK-POOL-02** | Session Variable Sanitization | `Session` / `Pool` | **RESOLVED** | Connection discard on acquire failure and explicit session state replay (`SET`). |

---

## 6. Integration Test Suite Verification

The Phase 2 integration test suite (`internal/proxy/view_masking_integration_test.go`) contains **33 automated integration subtests** running against live PostgreSQL 15 containers:
- **26 Baseline Phase 2 Subtests:**
  - 15 Core view masking, renaming, CTE, JOIN, subquery, identifier, and transaction isolation tests.
  - 11 Initial adversarial tests covering search_path shadowing, policy reload revocation, concurrent sessions, direct connection demonstration, and computed substrings (SEC-P2-05).
- **7 New Adversarial Subtests (Phase 2 Final Patch):**
  - `Adversarial_CrossClientCache_ClientAValid_ClientBInvalid` (SEC-P2-06)
  - `Adversarial_CrossClientCache_ReverseVerificationOrder` (SEC-P2-06)
  - `Adversarial_AutomaticRuntimeSchemaDrift_WithoutPolicyReload` (RISK-VIEW-01)
  - `Adversarial_PreparedStatement_FailsAfterRuntimeDrift` (RISK-VIEW-01)
  - `Adversarial_SensitiveWherePredicate_InViewDefinition_Denied` (SEC-P2-07)
  - `Adversarial_SensitiveJoinPredicate_InViewDefinition_Denied` (SEC-P2-07)
  - `Adversarial_NestedView_AlteredInnerView_FailsOuterQuery` (SEC-P2-08)

All 33 subtests pass cleanly (100% pass rate).
