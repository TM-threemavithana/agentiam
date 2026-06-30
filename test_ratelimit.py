import asyncio
import asyncpg
import sys
import time

async def fetch_query(conn, i):
    try:
        # A simple query that doesn't need a table
        val = await conn.fetchval("SELECT $1::int", i)
        return {"status": "success", "val": val, "id": i}
    except Exception as e:
        return {"status": "error", "error": str(e), "id": i}

async def run_test():
    # Connect to the proxy
    # Since agentiam runs on 5433, we use that.
    dsn = "postgres://test-agent:test-agent-secret@127.0.0.1:5433/postgres?sslmode=disable"
    
    import ssl
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE

    print("Connecting to proxy for rate limit test...")
    try:
        conn = await asyncpg.connect(dsn, ssl=ssl_context)
    except Exception as e:
        print(f"FAILED to connect: {e}")
        sys.exit(1)
        
    print("Connected. Firing exactly 11 concurrent requests in a tight loop...")
    
    # We will use prepared statements or direct queries.
    # We want exactly 11 requests. We'll use 11 independent connections to avoid asyncpg's
    # "another operation is in progress" lock, OR we can pipeline them via executemany?
    # Wait, rate limits apply PER STATEMENT. If we do executemany with 11 items, that is 1 Parse and 11 Executes?
    # No, rate limit checks *Parse* and *Query*. For prepared statements, `Parse` costs 1 token.
    # If we use 1 connection and do 11 simple Queries, we can't do concurrent simple Queries on one connection.
    # We can open 11 connections and execute them all concurrently!
    
    conns = []
    for _ in range(11):
        c = await asyncpg.connect(dsn, ssl=ssl_context)
        conns.append(c)
        
    tasks = []
    for i in range(11):
        tasks.append(fetch_query(conns[i], i))
        
    results = await asyncio.gather(*tasks)
    
    successes = [r for r in results if r["status"] == "success"]
    errors = [r for r in results if r["status"] == "error"]
    
    print(f"Results: {len(successes)} succeeded, {len(errors)} failed.")
    
    if len(successes) != 10:
        print(f"FAILED: Expected exactly 10 successes, got {len(successes)}.")
        sys.exit(1)
        
    if len(errors) != 1:
        print(f"FAILED: Expected exactly 1 failure, got {len(errors)}.")
        sys.exit(1)
        
    err_msg = errors[0]["error"]
    print(f"Failure message: {err_msg}")
    
    if "rate limit exceeded" not in err_msg:
        print(f"FAILED: Expected 'rate limit exceeded' error, got '{err_msg}'")
        sys.exit(1)
        
    print("Burst test passed! Now waiting 1.1 seconds for 1 token to refill...")
    await asyncio.sleep(1.1)
    
    print("Firing 1 more request...")
    res = await fetch_query(conns[0], 999)
    if res["status"] != "success":
        print(f"FAILED: Expected refill token to allow 1 request, got error: {res['error']}")
        sys.exit(1)
        
    print("SUCCESS: Token refilled successfully.")
    
    for c in conns:
        await c.close()
    await conn.close()
    print("ALL TESTS PASSED")

if __name__ == "__main__":
    asyncio.run(run_test())
