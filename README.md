# AgentIAM

**A Postgres wire-proxy that blocks SQL injection from AI agents at the AST level.**

Connecting Large Language Models (LLMs) directly to your database for "Text-to-SQL" functionality is incredibly dangerous. AgentIAM sits between your LangChain/LlamaIndex agent and your database, intercepting network traffic to parse and block destructive queries before they can execute.

[![CI](https://github.com/yourusername/agentiam/actions/workflows/ci.yml/badge.svg)](https://github.com/yourusername/agentiam/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/yourusername/agentiam)](https://goreportcard.com/report/github.com/yourusername/agentiam)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)
[![Version: v0.1.0-beta](https://img.shields.io/badge/Version-v0.1.0--beta-green.svg)]()

> *Demo GIF showing LangChain agent getting blocked by AgentIAM when attempting to DELETE FROM users goes here.*

---

## 🛑 The Problem

If you give an AI Agent a database connection, it *will* eventually try to delete data. 

- **Prompt Injection:** An attacker can easily trick the LLM into generating `DELETE FROM users;` instead of a harmless query.
- **Denial of Service (DoS):** An LLM might accidentally run `SELECT * FROM massive_table;`, attempting to fetch millions of rows and crashing your database server.

Relying on "prompt engineering" or LLM safety rails to prevent this does not work. Giving the AI a read-only database user prevents deletion, but it does not stop massive, un-paginated queries from taking down the server.

---

## 🚀 How It Works

**AgentIAM** is a high-performance proxy written in Go.

1. The AI Agent connects to AgentIAM (port `5433`).
2. AgentIAM intercepts the incoming `Parse` network packets using the Postgres Extended Query protocol.
3. The SQL is parsed into an Abstract Syntax Tree (AST) using `pg_query_go` (the actual Postgres C-parser). 
4. If a blocked node (like a `DeleteStmt`) is detected, AgentIAM instantly drops the query and returns a native protocol error to the AI.
5. If it's a `SelectStmt` without a limit, AgentIAM rewrites the AST to enforce a hard `LIMIT 100`, deparses it back to SQL, and forwards it to the real database.

Because it uses AST parsing, AgentIAM cannot be bypassed by clever SQL formatting, whitespace injection, or regex evasion.

---

## 🏃 Quickstart (5 Minutes)

You can try the full Go-To-Market demo locally using Docker Compose. It spins up a test database, AgentIAM, and a Python LangChain script that tries safe, malicious, and prompt-injected SQL generation.

```bash
cd demo/
docker-compose up --build
```
*Note: The demo runs in `AGENTIAM_DEMO_MOCK=true` mode by default so you don't need an OpenAI API key to see it work. To use a real LLM, `export OPENAI_API_KEY="sk-..."` before running.*

---

## ⚙️ Configuration (`policies.yaml`)

AgentIAM is configured via a declarative YAML file. When starting the proxy, pass the path to your policy file. It supports live hot-reloading.

```yaml
version: "1"
agents:
  - name: "langchain-bot"
    key: "$2a$10$..." # bcrypt hash of the agent's password
    allowed_statements:
      - SELECT
      - SHOW
    allowed_tables:
      - users
      - orders
    select_limit: 100
```

When your AI connects, it uses `langchain-bot` as the database user and the plaintext password. AgentIAM verifies the password, reads the policy, and establishes a session.

---

## 🏗️ Architecture

AgentIAM uses a highly concurrent 3-goroutine model per connection. It hijacks the native `pgconn` dialer to handle SSL and authentication, and then takes over the raw TCP socket to multiplex `pgproto3` messages.

### ⚠️ Topology Warning: PgBouncer & Upstream Pooling
AgentIAM natively protects itself from Denial of Service attacks by enforcing a strict maximum concurrency limit. However, this does **not** reduce upstream Postgres connection pressure. 

To prevent overwhelming your database, you should deploy **PgBouncer** *behind* AgentIAM:
`AI Agent -> AgentIAM Proxy -> PgBouncer -> Postgres`

**CRITICAL CONSTRAINT:** If you use PgBouncer in **Transaction Pooling** mode, you **must disable Server-Side Prepared Statements** in your AI Agent's database driver.

---

## 🔮 Roadmap (V2)

- **PII Data Masking:** Dynamic AST rewriting to automatically mask sensitive columns (e.g., rewriting `ssn` to `'***-**-' || RIGHT(ssn, 4)`).
- **Compliance Streaming:** Forwarding structured audit logs directly to Datadog, Splunk, or SIEM platforms.
- **Tenant Injection:** Automatically injecting `WHERE tenant_id = $x` into the AST to prevent cross-tenant data leakage in multi-tenant RAG applications.

---

## 🤝 Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for instructions on setting up your development environment, running integration tests, and submitting Pull Requests.
