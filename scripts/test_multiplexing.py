import psycopg2
import time
import sys
import subprocess

DSN = "postgres://test-agent:test-agent-secret@127.0.0.1:5433/postgres?sslmode=require"

def main():
    try:
        print("Connecting to AgentIAM...")
        conn = psycopg2.connect(DSN)
        conn.autocommit = True
        cur = conn.cursor()
        
        print("Setting Timezone to 'Antarctica/Troll'...")
        cur.execute("SET timezone TO 'Antarctica/Troll'")
        
        # We wait a bit. In a highly concurrent environment, this connection might get returned to the pool and reused!
        time.sleep(0.5)
        
        print("Querying current timezone...")
        cur.execute("SHOW timezone")
        row = cur.fetchone()
        
        print(f"Current timezone is: {row[0]}")
        
        if row[0] != 'Antarctica/Troll':
            print("FAILED: Session state was lost!")
            sys.exit(1)
            
        print("SUCCESS: Session state was successfully replayed across multiplexed transactions!")
        
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
