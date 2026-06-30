# Security Policy

## Known Vulnerabilities

### GO-2026-4518 (Denial of Service in `pgproto3/v2`)
- **Status:** Unpatched / Known Risk
- **Dependency:** `github.com/jackc/pgproto3/v2@v2.3.3`
- **Advisory:** https://pkg.go.dev/vuln/GO-2026-4518

**Details:**
The `govulncheck` tool flags a known denial-of-service vulnerability in `github.com/jackc/pgproto3/v2`. AgentIAM directly depends on this module for handling raw PostgreSQL wire protocol connections (specifically, using `pgproto3.Frontend.Receive` within the connection pool logic).

**Mitigation & Future Work:**
Currently, there is no upstream fix available for `v2.3.3`. We cannot simply drop the dependency without entirely rewriting the proxy's connection pool to utilize `pgx/v5` internal implementations. Until an upstream patch is released or the connection pool is rewritten, this remains an accepted known risk. Downstream deployments are advised to mitigate DoS risks using strict rate-limiting and a connection pooler like PgBouncer in front of the database.

## AST Security Controls Limitations

### Schema-Qualified Function Shadowing
- **Status:** Known Limitation
- **Component:** `internal/ast/filter.go`

**Details:**
The AST parser's `Funcname` slice iteration correctly catches deeply nested and schema-qualified function calls (e.g., `pg_catalog.pg_sleep`) by comparing any segment of the function name against the `blocked_functions` list in the policy configuration. 
However, this means that if a user-defined function in a different schema shares a name with a blocked function (e.g., `my_schema.pg_sleep`), it will also be blocked. 

**Mitigation:**
For most security-critical deployments, this conservative blocking is acceptable and preferred over allowing a potentially dangerous system function. Users are advised to avoid naming custom functions identically to restricted Postgres internals.

### Time-Based Injection (pg_sleep)
If an agent is granted `SELECT` access without query timeout enforcement, they can execute `SELECT pg_sleep(10)` or computationally expensive queries to exhaust upstream connection pools.
**Mitigation:** `AgentConfig.MaxExecutionTimeMs` forces context cancellation on slow queries. Ensure this is configured appropriately for your upstream database tier.

### Data Masking Bypass via Views
- **Status:** UNRESOLVED (v0.3.0)

Data Masking in AgentIAM operates strictly via AST semantic analysis. Because the proxy does not actively query Postgres internal catalogs to resolve view dependencies, it cannot trace an unrestricted view back to a masked base table.

For example, if the `users` table masks `ssn`, but a DBA creates `CREATE VIEW users_view AS SELECT * FROM users`, an agent querying `SELECT ssn FROM users_view` **will successfully extract the unmasked SSN** because `users_view` is not configured as a masked table in the policy.

**Mitigation:** Do not grant agents access to views or materialized views that wrap masked tables. Use standard Postgres `GRANT/REVOKE` permissions to ensure agents cannot query sensitive views directly.
