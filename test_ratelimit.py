import asyncio
import asyncpg
import sys
import os
import subprocess
import time
import ssl

async def fetch_query(conn, i):
    try:
        val = await conn.fetchval("SELECT $1::int", i)
        return {"status": "success", "val": val, "id": i}
    except Exception as e:
        return {"status": "error", "error": str(e), "id": i}

async def run_burst_test():
    dsn = "postgres://test-agent:test-agent-secret@127.0.0.1:5433/postgres?sslmode=disable"
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE

    conns = []
    # Create 11 connections
    for _ in range(11):
        c = await asyncpg.connect(dsn, ssl=ssl_context)
        conns.append(c)
        
    tasks = []
    for i in range(11):
        tasks.append(fetch_query(conns[i], i))
        
    results = await asyncio.gather(*tasks)
    
    for c in conns:
        await c.close()
        
    successes = [r for r in results if r["status"] == "success"]
    errors = [r for r in results if r["status"] == "error"]
    
    return len(successes), len(errors), errors

async def main():
    print("Starting rigor test: 20 iterations of 11 concurrent requests...")
    
    env = os.environ.copy()
    env["AGENTIAM_POLICY_FILE"] = "policies_test.yaml"
    env["AGENTIAM_UPSTREAM_DSN"] = "postgres://postgres:postgres@127.0.0.1:5434/postgres?sslmode=disable"
    env["AGENTIAM_DEV_MODE"] = "true"
    env["AGENTIAM_INSECURE_CLEARTEXT_AUTH"] = "true"
    
    for iteration in range(20):
        # Start proxy
        proxy = subprocess.Popen(["./agentiam.exe"], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(0.5) # Wait for proxy to bind port
        
        try:
            succ, err_count, errors = await run_burst_test()
            if succ != 10 or err_count != 1:
                print(f"FAILED on iteration {iteration}: Expected 10 successes / 1 failure, got {succ}/{err_count}")
                proxy.kill()
                sys.exit(1)
            
            err_msg = errors[0]["error"]
            if "rate limit exceeded" not in err_msg:
                print(f"FAILED on iteration {iteration}: Wrong error message: {err_msg}")
                proxy.kill()
                sys.exit(1)
                
            print(f"Iteration {iteration + 1}/20: PERFECT (10 succ, 1 fail).")
        finally:
            proxy.terminate()
            proxy.wait()
            
    print("\nSUCCESS: All 20 iterations returned exactly 10/1. No races detected.")

if __name__ == "__main__":
    asyncio.run(main())
