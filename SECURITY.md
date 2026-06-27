# Security Policy

## Supported Versions

AgentIAM is currently in active development. Only the latest `main` branch and the most recent numbered release are officially supported for security updates. 

| Version | Supported          |
| ------- | ------------------ |
| v0.x.x  | :white_check_mark: |
| main    | :white_check_mark: |

## Reporting a Vulnerability

If you discover a security vulnerability in AgentIAM, please DO NOT report it by opening a public GitHub issue.

Instead, please send an email to `security@agentiam.io` with a description of the issue and the steps to reproduce it. We will acknowledge your email within 48 hours and provide a timeline for triage and resolution.

## Threat Model & Security Boundaries

AgentIAM operates as a strict semantic firewall designed to block specific classes of SQL attacks (e.g., destructive statements, unlimited `SELECT` queries, unauthorized table access). However, please note the following security boundaries:

- **Authentication Timing Oracles:** We do not currently obfuscate latency during authentication. Timing attacks could theoretically deduce valid agent keys via `bcrypt` comparison time.
- **Row-Level Security:** AgentIAM does not currently enforce RLS (Row-Level Security) natively; rely on your upstream database for row isolation.
- **Connection Security:** AgentIAM supports `AuthenticationCleartextPassword`, but deploying it in production without `mTLS` or a secure internal boundary network is highly discouraged. You must explicitly opt in to cleartext authentication via the `--insecure-cleartext-auth` flag.
