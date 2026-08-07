# AgentIAM LangChain Demo

This demo proves how AgentIAM seamlessly protects a Postgres database from a rogue or hallucinating AI Agent. It uses a real `docker-compose` topology identical to what you would run in production.

## Prerequisites
- Docker & Docker Compose
- (Optional) An OpenAI API Key for full LangChain realism.

## How to Run the Demo

### Option A: Run with a Real LLM (Recommended)
This uses `gpt-4o` to generate the SQL queries on the fly. 

```bash
export OPENAI_API_KEY="sk-..."
docker-compose build
docker-compose up --abort-on-container-exit
```

### Option B: Run in Mock Mode
If you don't have an OpenAI API key or just want a fast, deterministic test without making API calls to OpenAI, use Mock Mode.

```bash
# Windows (PowerShell)
$env:AGENTIAM_DEMO_MOCK="true"
docker-compose build
docker-compose up --abort-on-container-exit

# Linux/Mac
AGENTIAM_DEMO_MOCK=true docker-compose build
AGENTIAM_DEMO_MOCK=true docker-compose up --abort-on-container-exit
```

## What Happens in this Demo?

When you run `docker-compose up`, four containers boot in order:
1. **postgres**: The raw database, populated with 20+ realistic user records.
2. **pgbouncer**: The connection pooler (for scaling).
3. **agentiam**: The security proxy that enforces `policies.yaml`.
4. **agent**: A Python LangChain script that connects to `agentiam` and tries to run three scenarios.

### The 3 Scenarios
1. **Safe Query**: The agent asks "How many users are in the database?". LangChain generates `SELECT COUNT(*) FROM users`. AgentIAM **allows** it.
2. **Malicious Query**: The agent is told to "Delete all users". LangChain generates `DELETE FROM users`. AgentIAM **blocks** it because the agent only has `SELECT` permissions.
3. **Prompt Injection**: The agent is given a malicious payload trying to trick it into "maintenance mode" to delete records. LangChain generates a `DELETE` query with a `WHERE 1=1` clause. AgentIAM **blocks** it instantly.

At the end of the demo, the script proves that all 23 users are still safely inside the database!
