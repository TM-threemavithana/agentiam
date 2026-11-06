# Contributing to AgentIAM

Welcome! Thank you for considering contributing to AgentIAM. We welcome bug reports, feature requests, and pull requests.

## Development Setup

AgentIAM is written in Go and uses standard Go tooling.

1. Install Go 1.25.11+ (or current toolchain specified in `go.mod`).
2. Install Docker (required for live PostgreSQL integration tests).
3. Clone the repository: `git clone https://github.com/TM-threemavithana/agentiam.git`
4. Run `go mod download` and `make verify` to check module integrity.

## Testing & Quality Gates

AgentIAM enforces automated quality gates in continuous integration. For full specifications, refer to [docs/CI_SECURITY_GATES.md](docs/CI_SECURITY_GATES.md).

- **Local Pre-Commit Pipeline:**
  ```bash
  make ci-local
  ```
  This runs `gofmt` compliance, `go mod verify`, retired `pgproto3/v2` guard, `go vet`, unit tests, and command builds.

- **Race Detection:**
  ```bash
  make race
  ```

- **PostgreSQL 15 Integration Tests:**
  ```bash
  make test-integration
  ```
  *(Note: Docker must be running for integration tests to succeed).*

- **Vulnerability Scanning:**
  ```bash
  make vulncheck
  ```

## Making Changes

Before submitting a Pull Request, please ensure the following:
1. **Format Code**: Run `make fmt` before committing. CI enforces strict `gofmt` cleanliness.
2. **Static Analysis**: Run `make vet` and `make lint`.
3. **Verify Dependencies**: Ensure `go mod verify` passes and no retired or vulnerable dependencies are introduced.
4. **Integration Coverage**: New features or security fixes must include unit and integration tests under `internal/proxy` or `internal/ast`.

## Architecture

AgentIAM is an AST-filtering wire proxy. It parses PostgreSQL wire-protocol frames via `github.com/jackc/pgx/v5/pgproto3`, intercepts queries, performs semantic analysis via `wasilibs/go-pgquery`, validates view provenance and schema drift against live catalogs, and proxies sanitized queries upstream.

Please read the [Architecture section in the README](README.md#%EF%B8%8F-architecture) and [docs/DEPLOYMENT_SECURITY.md](docs/DEPLOYMENT_SECURITY.md) before making changes to session dispatch or catalog verification.
