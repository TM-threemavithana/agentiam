import os
from sqlalchemy import create_engine, text
from sqlalchemy.exc import DatabaseError

def run_attack(name, query):
    print(f"\n[Attack Scenario] {name}")
    print(f"→ Executing Payload:\n{query}")
    try:
        with engine.connect() as conn:
            result = conn.execute(text(query))
            print("❌ VULNERABILITY! Query succeeded.")
            if result.returns_rows:
                for row in result:
                    print(row)
    except DatabaseError as e:
        if "AgentIAM Policy Violation" in str(e):
            print("✅ BLOCKED by AgentIAM AST Parser!")
            print(f"   Reason: {str(e).splitlines()[0]}")
        else:
            print(f"⚠️ Failed for other reason: {e}")

if __name__ == "__main__":
    droplet_ip = os.environ.get("DROPLET_IP", "127.0.0.1")
    port = os.environ.get("AGENTIAM_PORT", "5433")
    
    # We connect as langchain-bot, which only has SELECT/SHOW/SET/ROLLBACK on users/orders
    dsn = f"postgresql://langchain-bot:test-agent-key@{droplet_ip}:{port}/postgres"
    engine = create_engine(dsn, pool_pre_ping=True)
    
    print("🔌 Connecting to AgentIAM Proxy for Security Audit...")
    
    # Attack 1: CTE hiding a DELETE
    # The AST parser should catch the DELETE statement inside the WITH clause.
    attack1 = """
    WITH deleted_users AS (
        DELETE FROM users WHERE id = 1 RETURNING *
    )
    SELECT * FROM deleted_users;
    """
    
    # Attack 2: Time-based side channel exfiltration
    # The AST parser should block the pg_sleep() function call.
    attack2 = """
    SELECT * FROM users 
    WHERE id = 1 AND (SELECT pg_sleep(10)) IS NULL;
    """
    
    # Attack 3: Window functions across unauthorized tables
    # The AST parser should block access to the 'reviews' table, even in complex window partitions.
    attack3 = """
    SELECT 
        u.id, 
        u.name, 
        AVG(r.rating) OVER (PARTITION BY u.id) as avg_rating
    FROM users u
    JOIN reviews r ON u.id = r.user_id;
    """

    # We also do a successful query to prove it works
    success_query = """
    SELECT id, name FROM users LIMIT 2;
    """

    print("\n--- BEGIN SECURITY AUDIT ---")
    
    print("\n[Baseline] Valid Query")
    try:
        with engine.connect() as conn:
            result = conn.execute(text(success_query))
            print("✓ Baseline Query Succeeded.")
    except Exception as e:
        print(f"❌ Baseline Failed: {e}")

    run_attack("CTE hiding a DELETE", attack1)
    run_attack("Time-based side channel exfiltration", attack2)
    run_attack("Window functions across unauthorized tables", attack3)
