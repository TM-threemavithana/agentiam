import psycopg2
import sys

DSN = "postgres://test-agent-key:ignored@127.0.0.1:5433/mydb?sslmode=disable"

print("🤖 [LLM Agent] Connecting to Database via AgentIAM Proxy...")
try:
    conn = psycopg2.connect(DSN)
    conn.autocommit = True
    cursor = conn.cursor()
    print("✅ Connected successfully!")
except Exception as e:
    print(f"❌ Connection failed: {e}")
    sys.exit(1)

# Connect directly to Postgres on 5432 to set up test data (Admin)
ADMIN_DSN = "postgres://app_user:supersecretpassword@127.0.0.1:5434/mydb?sslmode=disable"
print("\n📝 [Initialization] Setting up test table via ADMIN connection (Port 5434)...")
try:
    admin_conn = psycopg2.connect(ADMIN_DSN)
    admin_conn.autocommit = True
    admin_cursor = admin_conn.cursor()
    admin_cursor.execute("CREATE TABLE IF NOT EXISTS users (id SERIAL PRIMARY KEY, name TEXT);")
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

# Attempt an unauthorized query (DELETE)
print("\n🔥 [Malicious Action] Agent goes rogue and attempts to delete users:")
try:
    cursor.execute("DELETE FROM users")
    print("✅ Success! Deleted all users. (WAIT, THIS SHOULD HAVE BEEN BLOCKED!)")
except Exception as e:
    print(f"🛡️ BLOCKED BY AgentIAM! Error returned to agent:\n=> {e}")

conn.close()
