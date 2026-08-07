import psycopg2
import sys
import os
import subprocess
import time

DSN = "postgres://test-agent:test-agent-secret@127.0.0.1:5433/postgres?sslmode=require"
ADMIN_DSN = "postgres://postgres:postgres@127.0.0.1:5434/postgres?sslmode=disable"

def run_test():
    print("🤖 [LLM Agent] Connecting to Database via AgentIAM Proxy...")
    try:
        conn = psycopg2.connect(DSN)
        conn.autocommit = True
        cursor = conn.cursor()
        print("✅ Connected successfully!")
    except Exception as e:
        print(f"❌ Connection failed: {e}")
        sys.exit(1)

    print("\n📝 [Initialization] Setting up test table via ADMIN connection (Port 5434)...")
    try:
        admin_conn = psycopg2.connect(ADMIN_DSN)
        admin_conn.autocommit = True
        admin_cursor = admin_conn.cursor()
        admin_cursor.execute("DROP TABLE IF EXISTS users CASCADE;")
        admin_cursor.execute("CREATE TABLE users (id SERIAL PRIMARY KEY, name TEXT);")
        admin_cursor.execute("INSERT INTO users (name) VALUES ('Alice'), ('Bob');")
        admin_conn.close()
        print("✅ Initialization complete. Database populated!")
    except Exception as e:
        print(f"❌ Error during init: {e}")
        sys.exit(1)

    # Attempt an authorized query
    print("\n🔍 [Authorized Action] Agent attempts to read users:")
    try:
        cursor.execute("SELECT * FROM users")
        users = cursor.fetchall()
        print(f"✅ Allowed! Retrieved users: {users}")
    except Exception as e:
        print(f"❌ Blocked! Error: {e}")
        sys.exit(1)

    # Attempt an unauthorized query (DELETE)
    print("\n🔥 [Malicious Action] Agent goes rogue and attempts to delete users:")
    try:
        cursor.execute("DELETE FROM users")
        print("❌ Success! Deleted all users. (WAIT, THIS SHOULD HAVE BEEN BLOCKED!)")
        sys.exit(1)
    except Exception as e:
        print(f"🛡️ BLOCKED BY AgentIAM! Error returned to agent:\n=> {e}")

    conn.close()

if __name__ == "__main__":
    env = os.environ.copy()
    env["AGENTIAM_POLICY_FILE"] = "policies_test.yaml"
    env["AGENTIAM_UPSTREAM_DSN"] = "postgres://postgres:postgres@127.0.0.1:5434/postgres?sslmode=disable"
    env["AGENTIAM_DEV_MODE"] = "true"
    env["AGENTIAM_INSECURE_CLEARTEXT_AUTH"] = "true"
    
    print("Starting proxy...")
    proxy = subprocess.Popen(["./agentiam.exe"], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(0.5)
    
    try:
        run_test()
    finally:
        proxy.terminate()
        proxy.wait()
