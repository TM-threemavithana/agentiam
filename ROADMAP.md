# AgentIAM Roadmap

This roadmap outlines the planned features and architectural changes for AgentIAM. Our focus is on removing friction for enterprise deployments while maintaining strict zero-dependency semantics for the core proxy.

## Short Term (Next 1-2 Releases)
- **OpenTelemetry Native Distributed Tracing**: Full native integration for end-to-end trace propagation, linking the AI Agent's thought process (LangChain traces) with the AST interception trace and the upstream database latency.
- **GoReleaser Integration**: Fully automated CI/CD pipelines to build binaries for Linux, Windows, and macOS (amd64/arm64) and push tagged Docker images directly to GitHub Container Registry.
- **Improved PostgreSQL Protocol Support**: Better handling of binary protocol encodings and complex prepared statements.

## Medium Term (Next 3-6 Months)
- **JWT-based RBAC Authentication**: Allow AgentIAM to validate external JWTs (e.g., from an Identity Provider) instead of relying solely on localized `bcrypt` hashes, enabling ephemeral, identity-aware connections.
- **Row-Level Security (RLS) Injection**: Explore dynamically injecting tenant IDs and RLS claims directly into the parsed AST before forwarding to the database, removing the need for external session configuration queries.
- **Enhanced MySQL Support**: Complete coverage for MySQL 8.0 specific features and connection properties.

## Long Term (Future Explorations)
- **Native PgBouncer-like Connection Pooling**: Currently, AgentIAM maps 1:1 to upstream connections, requiring a downstream PgBouncer sidecar. Long term, we will evaluate implementing a robust native transaction-level pooling mechanism.
- **Dynamic Data Masking**: Intercepting result sets and applying PII masking policies before returning data to the AI Agent.
