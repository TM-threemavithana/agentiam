# 🛡️ AgentIAM

**A zero-dependency, Postgres-aware security proxy for AI Agents.**

---

## 🛑 The Problem
Connecting Large Language Models (LLMs) directly to your database for "Text-to-SQL" functionality is incredibly dangerous. 
- **Prompt Injection:** An attacker can easily trick the LLM into generating `DELETE FROM users;` instead of a harmless query.
- **Denial of Service (DoS):** An LLM might accidentally run `SELECT * FROM massive_table;`, attempting to fetch millions of rows and crashing your database server.

Relying on "prompt engineering" to tell the AI not to do these things does not work. Giving the AI a read-only database user prevents deletion, but it does not stop massive, un-paginated queries from taking down the server.

## 🚀 The Solution
**AgentIAM** is a high-performance wire proxy that sits directly between your AI application (like LangChain, LlamaIndex, or raw OpenAI API calls) and your PostgreSQL database.

It intercepts raw Postgres wire-protocol traffic and uses **AST (Abstract Syntax Tree) parsing** to inspect and rewrite queries *before* they ever reach the database.

### Core Features:
- **Zero-Friction Integration:** No SDK changes required. Just change your database connection port from `5432` to `5433`.
- **AST-Level Blocking:** Blocks mutating commands (`DELETE`, `UPDATE`, `INSERT`, `DROP`, etc.) at the parsing level. It uses the exact same C-parser as Postgres itself (`pg_query_go`), meaning it cannot be bypassed by clever SQL formatting or regex evasion.
- **Automatic Query Throttling:** Automatically injects a hard `LIMIT 100` onto every unguarded `SELECT` statement, guaranteeing the LLM can never crash your system with a massive read.
- **Protocol Pipelining Support:** Flawlessly handles the Postgres Extended Query Protocol, ensuring that modern drivers like `psycopg2`, `pgx`, and `asyncpg` stay perfectly synchronized even when queries are blocked.

---

## 🛠️ How it Works

1. The AI Agent connects to AgentIAM (`port 5433`).
2. AgentIAM intercepts the incoming `Parse` network packets.
3. The SQL is parsed into a syntax tree. 
4. If a blocked node (like a `DeleteStmt`) is detected, AgentIAM instantly drops the query and returns an `ErrorResponse` to the AI.
5. If it's a `SelectStmt` without a limit, AgentIAM rewrites the AST to enforce `LIMIT 100`, deparses it back to SQL, and forwards it to the real database.

---

## 🏃 Quickstart

You can test AgentIAM locally using Docker Compose.

### 1. Start the Proxy and Database
```bash
docker compose up -d --build
```
*This spins up a vanilla Postgres 15 database on port 5434, and the AgentIAM proxy on port 5433.*

### 2. Connect your AI Agent
Point your LangChain agent, Python script, or SQL client to the proxy port:
```python
import psycopg2

# Connect via AgentIAM
DSN = "postgres://test-agent-key:ignored@127.0.0.1:5433/mydb?sslmode=disable"
conn = psycopg2.connect(DSN)
cursor = conn.cursor()

# This is allowed, but will be safely rewritten to have a LIMIT 100
cursor.execute("SELECT * FROM users")

# This will be instantly BLOCKED by the proxy
cursor.execute("DELETE FROM users")
```

---

## 🏗️ Architecture

AgentIAM uses a highly concurrent 3-goroutine model per connection. It hijacks the native `pgconn` dialer to handle SSL and authentication (SCRAM/MD5), and then takes over the raw TCP socket to multiplex `pgproto3` messages.

### ⚠️ Topology Warning: PgBouncer & Upstream Pooling
AgentIAM natively protects itself from Denial of Service attacks by enforcing a strict maximum concurrency limit (default 100 connections via `AGENTIAM_MAX_CONNECTIONS`). However, this does **not** reduce upstream Postgres connection pressure. 100 agent connections = 100 upstream connections.

To prevent overwhelming your database, you should deploy **PgBouncer** *behind* AgentIAM (`Client -> AgentIAM -> PgBouncer -> Postgres`).

**CRITICAL CONSTRAINT:** If you use PgBouncer in **Transaction Pooling** mode, you **must disable Server-Side Prepared Statements** in your AI Agent's database driver. The Postgres Extended Query Protocol uses session-scoped named statements, which will break under transaction pooling.
- **Python (psycopg3):** Use `prepared_statements=off`
- **Python (SQLAlchemy):** Use `use_insertmanyvalues=False`

---

## 🔮 Roadmap (V2)
- **PII Data Masking:** Dynamic AST rewriting to automatically mask sensitive columns (e.g., rewriting `ssn` to `'***-**-' || RIGHT(ssn, 4)`).
- **Connection Pooling:** PgBouncer-style upstream pooling to reduce connection overhead for high-throughput AI fleets.
