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

### Freshness Verification Lifecycle (RISK-VIEW-01 & Priority D)
- **Invocation Points:** Freshness verification is enforced at query-time on every simple query (`handleQueryMsg`), extended query parse (`handleParseMsg`), and prepared statement bind (`handleBindMsg`) via `EnsureFreshness` whenever an approved view or dependent relation is referenced. Freshness is enforced on-demand during query processing; there is no periodic background polling ticker.
- **Production TTL Default:** The default production cache TTL is **50ms** (`CatalogVerifier.ttl = 50 * time.Millisecond`), chosen to provide rapid drift mitigation while shielding system catalogs from connection saturation during tight query loops.
- **Behavior of TTL = 0:** Setting `TTL = 0` forces `EnsureFreshness` to bypass the cache and query live system catalogs synchronously on every query/bind dispatch.
  > [!IMPORTANT]
  > **No Transactional Cross-Connection Atomicity:** Even with `TTL = 0`, catalog checking and client SQL execution are **NOT transactionally atomic**. The catalog check executes on a dedicated proxy connection to `pg_catalog`, while the client's query subsequently executes over an upstream pool connection. A concurrent PostgreSQL DDL transaction (e.g. `CREATE OR REPLACE VIEW`) committing between the catalog check and execution creates an inherent Time-of-Check to Time-of-Use (TOCTOU) gap. PostgreSQL DDL commit serialization does not provide cross-connection transactional atomicity. Zero-window atomicity against concurrent DDL requires database-level migration maintenance windows or advisory locks.
- **Catalog Verification Failures:** If a catalog query fails (timeout, connection loss, missing relation, or corrupted catalog), `EnsureFreshness` fails closed immediately with `SQLSTATE 57P01`. Cached `StatusVerified` authorizations are never restored after newer failures.
- **Prepared Statements & Existing Sessions:** Prepared statements do not bypass drift detection; `handleBindMsg` re-evaluates `EnsureFreshness` against current catalog snapshots before execution.
- **Database Connection & Catalog Overhead:** `TTL = 0` adds a synchronous catalog round-trip (`pg_views` and `pg_class.relkind`) per query. The default 50ms TTL amortizes this overhead by establishing when cached verification decisions become eligible for re-querying. However, cached metadata freshness is distinct from the interval between catalog verification and subsequent SQL execution. Because catalog validation and statement execution occur over separate physical database connections, concurrent DDL can commit after a fresh check but immediately before query execution begins; setting `TTL = 0` does not eliminate this race window. Production safety against untrusted concurrent DDL cannot be achieved through proxy polling alone and requires appropriately enforced operational maintenance windows or database-level DDL privilege restrictions.

### Concurrency Ordering & Generation Safeguards (Priority B)
- **Generation Counters:** Both catalog snapshots and client authorizations maintain monotonic generation counters (`catalogGens`, `clientGens`).
- **Out-of-Order Rejection:** An in-flight verification or catalog snapshot started before an invalidation or newer failed verification cannot write `StatusVerified` back into cache upon completion.
- **Barrier Hooks:** Deterministic synchronization barriers (`SetBeforeAuthWriteHook`, `SetBeforeSnapshotWriteHook`) verify that out-of-order completions fail closed without race conditions.

### Canonical Identity & Client Isolation (Priority C & SEC-P2-06)
- **PostgreSQL Identifier Semantics:** Quoted identifiers (e.g. `public."Reports"`) preserve exact case, while unquoted identifiers (e.g. `public.reports`) fold to lowercase. They are treated as distinct database relations in both catalog snapshots and policy lookups.
- **Client Identity Isolation:** Authenticated client IDs are case-sensitive. Client `agent-alpha` and `AGENT-ALPHA` maintain completely separate authorization caches (`clientID:policyVersion:schema.viewName`).
- **Nested View Provenance (SEC-P2-08 & Priority A):** All dependencies must be explicitly approved views (relkind `'v'`) or base tables (relkind `'r'`, `'p'`). Unapproved inner views, extraction failures, unknown relations, or unsupported relation kinds (`'m'`, `'f'`) strictly fail closed.

---

## 5. Formal Risk Register Status

| Risk ID | Title | Component | Status | Mitigation / Operational Boundary |
|---|---|---|---|---|
| **RISK-VIEW-02** (SEC-P2-01) | Direct PostgreSQL Access Bypass | Network / Infra | **OPEN (RELEASE BLOCKER)** | Requires physical/VPC network isolation and credential separation. Cannot be resolved by proxy software alone. |
| **RISK-VIEW-01** | Database-View Definition Drift | `CatalogVerifier` / `Session` | **MITIGATED (Operational TOCTOU Boundary)** | Query-time freshness checks (`EnsureFreshness`) with 50ms default refresh eligibility TTL. Multi-connection TOCTOU race window documented; requires database DDL access controls for absolute serialization. |
| **SEC-P2-06** | Cross-Client Cache Pollution | `CatalogVerifier` | **RESOLVED** | Cache keys partitioned by `clientID:policyVersion:schema.viewName`. Case-sensitive client isolation. |
| **SEC-P2-07** | Sensitive View Predicates | `ast.ValidateViewProvenance` | **RESOLVED** | Strict rejection of sensitive columns in WHERE, JOIN ON, HAVING, GROUP BY, ORDER BY, WINDOW, and subqueries. |
| **SEC-P2-08** | Nested View Dependency Drift | `CatalogVerifier` / `ast` | **RESOLVED (Fail-Closed)** | Recursive dependency extraction and classification. Unapproved views, extraction errors, and drift trigger immediate fail-closed denial. |
| **RISK-LOG-01** | Panic Diagnostic Secret Exposure | `Session` / `Logger` | **MITIGATED** | Sanitized stack traces, safe panic summaries, regex credential redaction in panic handlers. |
| **RISK-POOL-01** | Terminal CAS Cleanup Failure | `Pool` / `Worker` | **MITIGATED** | Atomic CAS state transitions, idempotent release, connection discarding on failure. |
| **RISK-AUDIT-01** | External Audit Sink Delivery Drops | `AuditSink` | **MONITORED** | Asynchronous buffered delivery; errors logged to local system logger. |
| **RISK-POOL-02** | Session Variable Sanitization | `Session` / `Pool` | **MITIGATED** | Connection discard on acquire failure and explicit session state replay (`SET`). |

---

## 6. Integration Test Suite Verification

The Phase 2 integration test suite (`internal/proxy/view_masking_integration_test.go`) contains **35 automated integration subtests** running against live PostgreSQL 15 containers:
- **26 Baseline Phase 2 Subtests:**
  - 15 Core view masking, renaming, CTE, JOIN, subquery, identifier, and transaction isolation tests.
  - 11 Initial adversarial tests covering search_path shadowing, policy reload revocation, concurrent sessions, direct connection demonstration, and computed substrings (SEC-P2-05).
- **9 Adversarial Subtests (Phase 2 Final Correctness Suite):**
  - `Adversarial_CrossClientCache_ClientAValid_ClientBInvalid` (SEC-P2-06)
  - `Adversarial_CrossClientCache_ReverseVerificationOrder` (SEC-P2-06)
  - `Adversarial_AutomaticRuntimeSchemaDrift_WithoutPolicyReload` (RISK-VIEW-01)
  - `Adversarial_PreparedStatement_FailsAfterRuntimeDrift` (RISK-VIEW-01)
  - `Adversarial_SensitiveWherePredicate_InViewDefinition_Denied` (SEC-P2-07)
  - `Adversarial_SensitiveJoinPredicate_InViewDefinition_Denied` (SEC-P2-07)
  - `Adversarial_NestedView_AlteredInnerView_FailsOuterQuery` (SEC-P2-08)
  - `Adversarial_NestedView_UnapprovedInnerView_FailsClosed` (Priority A)
  - `Adversarial_QuotedVsUnquoted_LiveIsolation` (Priority C)

All 35 subtests pass cleanly (100% pass rate). In addition, 14 dedicated deterministic concurrency barrier and unit tests in `internal/proxy/catalog_verifier_unit_test.go` verify forced out-of-order completion, generation invalidation, and fail-closed edge cases.
