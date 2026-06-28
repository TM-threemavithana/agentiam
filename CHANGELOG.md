# Changelog

## [2026-06-28] - Security, Performance, and Coverage Overhaul

### Security
- **Patched Standard Library Vulnerabilities**: Updated Go toolchain from `1.25.0` to `1.25.11` in `go.mod`.
  - **Before**: 22 CVEs flagged by `govulncheck`, including critical vulnerabilities like `GO-2026-4340` (incorrect encryption level handling in `crypto/tls`).
  - **After**: 1 remaining CVE (`GO-2026-4518` in `pgproto3/v2`, which is an unpatched upstream dependency and documented as a known risk in `SECURITY.md`). All Go standard library CVEs are fully resolved.

### Performance
- **Fixed AST Caching Flaw**: Discovered and resolved a critical flaw where the AST cache was being entirely bypassed during parsing, forcing a `parser.ParseToProtobuf` C-Go allocation on every single query.
  - **Before**: `BenchmarkFilterAST/WithCache` ran at ~219,205 ns/op and allocated ~498,295 B/op (identical to the un-cached performance).
  - **After**: `BenchmarkFilterAST/WithCache` runs at ~426 ns/op and allocates only ~384 B/op.
  - **Impact**: Cache hits are now ~500x faster and use ~1300x less memory per operation, massively reducing GC pressure under real load.

### Testing & Coverage
- **MySQL Parser Coverage**: The MySQL AST rules engine (`internal/ast/mysql_parser.go`) had zero test coverage for its core security enforcement paths.
  - **Before**: `ApplyRules` 0.0%, `Enter` 0.0%.
  - **After**: `ApplyRules` 87.0%, `Enter` 84.6%, `Leave` 100.0%.
- **PostgreSQL Filter Coverage**: Expanded rule enforcement tests in `internal/ast/filter.go` to explicitly cover branches for `INSERT`, `UPDATE`, `DELETE`, `DROP`, `TRUNCATE`, `CREATE`, `ALTER`, and `SHOW` statements, as well as syntax errors and explicit cache hit/miss assertions.
  - **Before**: `enforceRules` coverage was 69.1%, `ApplyRules` was 72.7%.
  - **After**: `enforceRules` coverage is 94.5%, `ApplyRules` is 90.9%.
  - **Total AST Package Coverage**: Increased from 62.6% to 87.7%.

### Documentation
- **Honest Architecture Reporting**: Updated `README.md` to remove inaccurate claims of "zero external infrastructure dependencies". Explicitly documented the remote control plane HTTP polling architecture, removing obsolete references to the localized policy store configuration.
