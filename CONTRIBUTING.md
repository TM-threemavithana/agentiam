# Contributing to AgentIAM

Welcome! Thank you for considering contributing to AgentIAM. We welcome bug reports, feature requests, and pull requests.

## Development Setup

AgentIAM is written in Go and uses standard Go tooling.

1. Install Go 1.22+.
2. Install Docker (required for integration tests).
3. Clone the repository: `git clone https://github.com/yourusername/agentiam.git`
4. Run `go mod tidy` to download dependencies.

## Testing

AgentIAM has a comprehensive test suite, including integration tests that spin up a real PostgreSQL database using Docker.

- To run all tests (including integration tests):
  ```bash
  go test -v -race ./...
  ```
  *(Note: Docker must be running for the integration tests to succeed).*

## Making Changes

Before submitting a Pull Request, please ensure the following:
1. **Format Code**: Run `go fmt ./...` before committing. CI will fail if the code is unformatted.
2. **Add Tests**: If you fix a bug or add a new feature, add a corresponding test. Integration tests are preferred for proxy-level behavior changes.
3. **Check CI**: Our GitHub Actions workflow checks formatting, module dependencies (`go.sum`), and runs the full test suite with the Go `-race` detector enabled.

## Architecture

AgentIAM is an AST-filtering wire proxy. It parses the PostgreSQL wire protocol (`pgproto3`), intercepts queries, parses the AST using `pg_query_go`, applies YAML-based policies, and proxies safe queries upstream. 

Please read the [Architecture section in the README](README.md#%EF%B8%8F-architecture) for details on the goroutine multiplexing and PgBouncer topology before making deep changes to `internal/proxy/session.go`.
