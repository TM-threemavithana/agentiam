python -m venv venv
.\venv\Scripts\Activate.ps1
pip install asyncpg
python test_asyncpg.py "postgres://test-agent-key:Test%20Agent@127.0.0.1:15432/agentiam?sslmode=disable"
