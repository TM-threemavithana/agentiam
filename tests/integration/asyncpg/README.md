# asyncpg Integration Tests

These tests verify AgentIAM's compatibility with Python's asyncpg driver,
specifically under Extended Query Protocol pipelining.

## Prerequisites
- Docker and docker-compose
- Python 3.11+

## Running

```bash
cd tests/integration/asyncpg
./run_asyncpg_test.sh
```

## What's Being Tested
- Named vs unnamed statement handling during discard state
- Pipelined Parse/Bind/Execute with blocked statements
- Connection recovery after policy violations
