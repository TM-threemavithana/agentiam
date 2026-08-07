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

async def test_deep_nesting(dsn):
    print("Running deep nesting DoS test (100 sequential CTEs)...")
    conn = await asyncpg.connect(dsn)
    try:
        query = "SELECT 1 as val"
        for i in range(1, 100):
            query = f"SELECT * FROM ({query}) AS t_{i}"
        
        try:
            await conn.execute(query)
            assert False, "Expected deep nesting query to be blocked!"
        except asyncpg.exceptions.PostgresError as e:
            if "Maximum AST complexity exceeded" not in str(e):
                raise e
            print("Successfully blocked deep nesting DoS attempt.")
    finally:
        await conn.close()

async def main():
    if len(sys.argv) < 2:
        print("Usage: test_asyncpg.py <dsn>")
        sys.exit(1)
    dsn = sys.argv[1]
    
    await test_auth(dsn)
    await test_deep_nesting(dsn)
    await test_transaction_isolation(dsn, 50)
    await test_multiplexing_scale(dsn, 100)
    await test_cancellation(dsn)
    await test_mid_transaction_disconnect(dsn)
    print("All tests passed!")



async def test_cancellation(dsn):
    print("Running cancellation test...")
    conn = await asyncpg.connect(dsn)
    try:
        # Expected to be cancelled
        await conn.execute('SELECT pg_sleep(10)', timeout=1.0)
        assert False, "Expected timeout/cancellation error"
    except asyncio.TimeoutError:
        print("Cancellation successful via timeout.")
    finally:
        if not conn.is_closed():
            await conn.close()

async def test_mid_transaction_disconnect(dsn):
    print("Running mid-transaction disconnect test...")
    conn = await asyncpg.connect(dsn)
    
    # Start a transaction and mutate state
    await conn.execute('BEGIN')
    await conn.execute('CREATE TABLE IF NOT EXISTS disconnect_test (val int)')
    await conn.execute('INSERT INTO disconnect_test VALUES (1)')
    
    # Forcefully close the socket to simulate a crash/disconnect mid-transaction
    # conn.terminate() abruptly closes the socket without sending a clean terminate message
    await conn.execute("SELECT pg_sleep(1)") # Wait for the insert to commit? No, it's a transaction
    
    # We use loop.call_soon to abruptly terminate it while something is running
    conn.terminate()
    
    # Wait a bit for the proxy to detect EOF and rollback
    await asyncio.sleep(1)
    
    # Open a new connection and verify the table or row doesn't exist (it should have rolled back)
    conn2 = await asyncpg.connect(dsn)
    try:
        # Table might exist if created before, but the row definitely shouldn't be there 
        # Actually, DDL in postgres is transactional! 
        val = await conn2.fetchval("SELECT count(*) FROM pg_tables WHERE tablename = 'disconnect_test'")
        assert val == 0, "Table should not exist because the transaction was rolled back!"
        print("Mid-transaction disconnect recovery successful.")
    finally:
        await conn2.close()


if __name__ == '__main__':
    asyncio.run(main())

