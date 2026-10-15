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
| **Definer Views** | Views created by `postgres` or `superuser` exposing raw sensitive columns (`SELECT ssn FROM customers`) with `GRANT SELECT ON view TO agent_role`. If direct access is obtained, raw PII leaks immediately. | Views created with database-side redaction (e.g., `SELECT '[REDACTED]' AS ssn`) OR views utilizing PostgreSQL Row Level Security (RLS) policies. |
| **Direct Table Grants** | Granting `agent_db_role` SELECT privileges on raw sensitive base tables. | Denying / revoking SELECT on base tables with sensitive columns from application roles (`REVOKE SELECT ON customers FROM agent_db_role`). |
| **Search Path Hijacking** | Leaving `search_path` set to user-writable schemas (e.g. `public`), allowing function shadowing. | Explicitly locking `search_path = pg_catalog, public` and enforcing qualified schema references in view definitions. |
| **View Alteration & Drift** | Allowing database developers to alter approved view definitions without re-approving the AgentIAM policy. | Setting `definition_fingerprint` in AgentIAM policy; any view definition change causes immediate fail-closed denial. |

---

## 4. Formal Risk Status & Release Blocker Declaration

### RISK-VIEW-02: Direct PostgreSQL Connection Bypass (SEC-P2-01)
- **Classification:** Architectural / Network Deployment Constraint
- **Mitigation Status:** Code-level demonstration and regression verified in synthetic test `Adversarial_DirectPostgreSQLViewAccess_PrivilegeBoundary`.
- **Release Status:** **OPEN (FORMAL RELEASE BLOCKER)**
- **Requirement for Production Sign-off:**
  Before production deployment or portfolio security sign-off, network isolation of the PostgreSQL listener must be independently verified by automated infrastructure verification (e.g. Terraform compliance, AWS Inspector, or nmap audit proving port 5432 is non-routable from agent networks). Documentation alone does not close this risk.
