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
