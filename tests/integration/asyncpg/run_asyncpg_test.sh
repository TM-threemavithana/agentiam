#!/bin/bash
set -e

echo "Installing dependencies..."
apt-get update && apt-get install -y docker.io docker-compose-v2 python3 python3-venv

echo "Starting Docker Compose stack (AgentIAM + PgBouncer + Postgres)..."
docker compose up -d --build

echo "Waiting for stack to be fully healthy..."
sleep 15

echo "Installing Python asyncpg..."
python3 -m venv /tmp/venv
/tmp/venv/bin/pip install asyncpg

echo "Running asyncpg Python integration tests (including PgBouncer concurrency)..."
# Connect to AgentIAM, which listens on 5432 (mapped from docker compose)
/tmp/venv/bin/python test_asyncpg.py postgres://test-agent-key:Test%20Agent@127.0.0.1:15432/agentiam?sslmode=disable

echo "Tests passed!"

echo "Verifying network isolation..."
if docker compose exec -T agentiam sh -c 'nc -z -w 2 postgres 5432 2>/dev/null'; then
  echo "FAIL: AgentIAM can reach postgres directly (bypassing PgBouncer)!"
  exit 1
else
  echo "SUCCESS: AgentIAM is isolated from postgres."
fi

echo "Cleaning up stack..."
docker compose down
