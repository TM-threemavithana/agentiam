import asyncio
import asyncpg
import sys

async def test_auth(dsn):
    print("Running test_auth...")
    conn = None
    try:
        # Use simple connect
        conn = await asyncpg.connect(dsn)
        
        # Test 1: Basic parameterized query
        val = await conn.fetchval('SELECT $1::int', 42)
        assert val == 42, f"Expected 42, got {val}"
        
        # Test 2: Intentional policy violation (discard recovery)
        try:
            await conn.execute('DELETE FROM test_table')
            assert False, "Expected DELETE to be blocked by policy!"
        except asyncpg.exceptions.PostgresError as e:
            if "AgentIAM Policy Violation" not in str(e):
                raise e
            print("Successfully blocked DELETE and caught exception.")

        # Test 3: Named statement reuse after blocking
        # asyncpg caches prepared statements. We will prepare a blocked statement,
        # and then prepare an allowed statement with the exact same text structure but different table
        # to ensure the proxy doesn't corrupt the portal/statement namespace mapping.
        
        # Since asyncpg abstracts statement names, we can force a prepared statement cache hit by repeating queries.
        # But wait, asyncpg caches by query text. We can use a direct prepare:
        stmt1 = await conn.prepare('SELECT 100')
        val1 = await stmt1.fetchval()
        assert val1 == 100, f"Expected 100, got {val1}"

        try:
            # Blocked statement
            await conn.prepare('DROP TABLE users')
            assert False, "Expected DROP to be blocked during prepare"
        except asyncpg.exceptions.PostgresError as e:
            pass
        
        # Now reuse a statement that is allowed
        stmt2 = await conn.prepare('SELECT 200')
        val2 = await stmt2.fetchval()
        assert val2 == 200, f"Expected 200, got {val2}"

        await conn.close()
        print("asyncpg authentication and pipelining successful")
    except Exception as e:
        print(f"asyncpg failed: {e}")
        if conn and not conn.is_closed():
            await conn.close()
        sys.exit(1)

async def test_transaction_isolation(dsn, num_clients=50):
    print(f"Running transaction isolation test with {num_clients} clients...")
    
    # Pre-create test table
    conn = await asyncpg.connect(dsn)
    await conn.execute('CREATE TABLE IF NOT EXISTS test_table (id serial PRIMARY KEY, val text)')
    await conn.execute('TRUNCATE TABLE test_table')
    await conn.close()

    async def client_task(client_id):
        conn = await asyncpg.connect(dsn)
        try:
            async with conn.transaction(isolation='repeatable_read'):
                count1 = await conn.fetchval('SELECT count(*) FROM test_table')
                await conn.execute('INSERT INTO test_table(val) VALUES ($1)', f'client_{client_id}')
                # Simulate work
                await asyncio.sleep(0.1)
                count2 = await conn.fetchval('SELECT count(*) FROM test_table')
                
                assert count2 == count1 + 1, f"Transaction isolation leak! Expected {count1 + 1}, got {count2}"
        finally:
            await conn.close()

    await asyncio.gather(*(client_task(i) for i in range(num_clients)))
    print("Transaction isolation test passed.")

async def test_multiplexing_scale(dsn, num_clients=100):
    print(f"Running multiplexing scale test with {num_clients} clients...")
    
    async def fast_query():
        conn = await asyncpg.connect(dsn)
        try:
            val = await conn.fetchval('SELECT 1')
            assert val == 1
        finally:
            await conn.close()
            
    await asyncio.gather(*(fast_query() for _ in range(num_clients)))
    print("Multiplexing scale test passed.")

async def main():
    if len(sys.argv) < 2:
        print("Usage: test_asyncpg.py <dsn>")
        sys.exit(1)
    dsn = sys.argv[1]
    
    await test_auth(dsn)
    await test_transaction_isolation(dsn, 50)
    await test_multiplexing_scale(dsn, 100)
    print("All tests passed!")

if __name__ == '__main__':
    asyncio.run(main())
