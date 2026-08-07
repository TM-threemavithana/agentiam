import asyncio
import asyncpg
import sys
import os

async def setup_db(conn):
    print("Setting up target schema (users, orders, users_view)...")
    await conn.execute("DROP VIEW IF EXISTS users_view")
    await conn.execute("DROP TABLE IF EXISTS orders CASCADE")
    await conn.execute("DROP TABLE IF EXISTS users CASCADE")
    
    await conn.execute("""
        CREATE TABLE users (
            id SERIAL PRIMARY KEY,
            username VARCHAR(255),
            email VARCHAR(255),
            ssn VARCHAR(255)
        )
    """)
    await conn.execute("""
        CREATE TABLE orders (
            id SERIAL PRIMARY KEY,
            user_id INT,
            total INT
        )
    """)
    await conn.execute("CREATE VIEW users_view AS SELECT * FROM users")
    
    await conn.execute("INSERT INTO users (username, email, ssn) VALUES ('admin', 'admin@corp.com', '999-99-9999')")
    await conn.execute("INSERT INTO orders (user_id, total) VALUES (1, 500)")

async def verify_blocked(conn, name, query):
    try:
        await conn.fetch(query)
        print(f"FAILED (Leaked): {name} - Query executed successfully when it should have been blocked.")
        return False
    except asyncpg.exceptions.PostgresError as e:
        if e.sqlstate == '53400' or 'Policy Violation' in str(e):
            print(f"PASSED (Blocked): {name} - {str(e)}")
            return True
        else:
            print(f"FAILED (Unexpected Error): {name} - {str(e)}")
            return False

async def verify_masked(conn, name, query, column_idx=0):
    try:
        rows = await conn.fetch(query)
        if len(rows) > 0:
            val = rows[0][column_idx]
            if val == '[REDACTED]' or (name == "Substring" and val == '[RED'):
                print(f"PASSED (Masked): {name}")
                return True
            else:
                print(f"FAILED (Leaked): {name} - Value returned as '{val}' instead of [REDACTED]")
                return False
        return False
    except Exception as e:
        print(f"FAILED (Error): {name} - {str(e)}")
        return False

async def run_suite():
    dsn = "postgres://test-agent:test-agent-secret@127.0.0.1:5433/postgres?sslmode=disable"
    import ssl
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE

    print("Connecting to proxy for bypass suite...")
    try:
        conn = await asyncpg.connect(dsn, ssl=ssl_context)
    except Exception as e:
        print(f"FAILED to connect: {e}")
        sys.exit(1)

    await setup_db(conn)

    print("\n--- Running Adversarial Bypass Suite ---")
    
    passed = 0
    total = 0

    def record(res):
        nonlocal passed, total
        total += 1
        if res: passed += 1

    # 1. Direct Aliasing
    record(await verify_masked(conn, "Direct Aliasing", "SELECT ssn AS score FROM users"))

    # 2. Table Aliasing
    record(await verify_masked(conn, "Table Aliasing", "SELECT u.ssn FROM users u"))

    # 3. Subqueries
    record(await verify_masked(conn, "Subqueries", "SELECT score FROM (SELECT ssn AS score FROM users) sub"))

    # 4. CTEs
    record(await verify_masked(conn, "CTEs", "WITH target AS (SELECT ssn FROM users) SELECT * FROM target"))

    # 5. Set Operations
    record(await verify_masked(conn, "Set Operations", "SELECT ssn FROM users UNION SELECT email FROM users"))

    # 6. String Functions
    record(await verify_masked(conn, "String Functions", "SELECT concat(ssn, '') FROM users"))
    record(await verify_masked(conn, "Substring", "SELECT substring(ssn from 1 for 4) FROM users"))

    # 7. Type Casting
    record(await verify_masked(conn, "Type Casting", "SELECT ssn::text FROM users"))

    # 8. Implicit Row Expansion (Strict Mode - should BLOCK)
    record(await verify_blocked(conn, "Implicit Expansion (*)", "SELECT * FROM users"))
    
    # 9. JSON/Record Extraction (Strict Mode - should BLOCK)
    record(await verify_blocked(conn, "JSON Extraction", "SELECT row_to_json(users)->>'ssn' FROM users"))

    # 10. DML RETURNING
    record(await verify_masked(conn, "DML RETURNING", "UPDATE users SET email = 'b@corp.com' RETURNING ssn"))

    # 11. Wildcard table-qualified expansion with JOIN (Strict Mode - should BLOCK)
    record(await verify_blocked(conn, "Table-Qualified Wildcard (u.*)", "SELECT u.*, o.id FROM users u JOIN orders o ON u.id = o.user_id"))

    # 12. Views wrapping masked table (Out of scope for v0.3.0, but let's test if it's explicitly documented)
    # The proxy will allow this since 'users_view' is not in the policy. It will LEAK the SSN.
    # We expect this to fail the test (leak), proving it's out of scope until we enforce view permissions.
    print("\n[NOTE] Vector 12 (Views) is explicitly OUT OF SCOPE for v0.3.0. We expect it to leak (fail).")
    record(await verify_masked(conn, "View Wrapper", "SELECT ssn FROM users_view"))

    # 13. Fail-closed Default on Unknown Node (GROUPING SETS)
    record(await verify_blocked(conn, "Fail-Closed (GROUPING SETS)", "SELECT ssn FROM users GROUP BY GROUPING SETS ((ssn))"))

    print(f"\nSuite complete: {passed}/{total} tests passed (masked or blocked).")
    if passed >= total - 1: # View Wrapper is expected to leak
        print("GREEN PHASE: Masking logic successfully defeated the adversarial suite!")
    else:
        print("RED PHASE: Bypass suite successfully defeated the proxy. Masking logic required.")
    
    await conn.close()

async def main():
    env = os.environ.copy()
    env["AGENTIAM_POLICY_FILE"] = "policies_masking.yaml"
    env["AGENTIAM_UPSTREAM_DSN"] = "postgres://postgres:postgres@127.0.0.1:5434/postgres?sslmode=disable"
    env["AGENTIAM_DEV_MODE"] = "true"
    env["AGENTIAM_INSECURE_CLEARTEXT_AUTH"] = "true"
    
    print("Starting proxy...")
    import subprocess
    import time
    proxy = subprocess.Popen(["./agentiam.exe"], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(0.5)
    
    try:
        await run_suite()
    finally:
        proxy.terminate()
        proxy.wait()

if __name__ == "__main__":
    asyncio.run(main())
