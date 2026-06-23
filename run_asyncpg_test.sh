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
/tmp/venv/bin/python test_asyncpg.py postgres://test-agent-key:Test%20Agent@127.0.0.1:5432/agentiam?sslmode=disable

echo "Tests passed! Cleaning up stack..."
docker compose down
