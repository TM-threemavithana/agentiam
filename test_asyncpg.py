import asyncio
import asyncpg
import sys

async def run_pipeline():
    try:
        print("Connecting to proxy...")
        conn = await asyncpg.connect(
            user='test-agent',
            password='test-agent-secret',
            database='postgres',
            host='127.0.0.1',
            port=5433
        )
        print("Connected.")

        # This pipelines Parse, Bind, Describe, Execute, Sync in a single flight.
        # It's an extended query with binary parameter encoding.
        val = await conn.fetchval('SELECT $1::int', 42)
        print(f"Single query returned: {val}")
        if val != 42:
            print("FAILED: Value mismatch!")
            sys.exit(1)

        # Now let's try multiple pipelined queries aggressively.
        # We'll use a transaction block and queue them up rapidly.
        async with conn.transaction():
            print("Testing prepared statement reuse...")
            stmt1 = await conn.prepare("SELECT $1::text")
            
            val1 = await stmt1.fetchval("test_string_1")
            val2 = await stmt1.fetchval("test_string_2")
            print(f"Prepared statement results: {val1}, {val2}")
            
            if val1 != "test_string_1" or val2 != "test_string_2":
                print("FAILED: Prepared results mismatch!")
                sys.exit(1)
                
            print("Testing executemany (heavy pipelining)...")
            await conn.execute("DROP TABLE IF EXISTS users CASCADE")
            await conn.execute("CREATE TABLE users (id SERIAL PRIMARY KEY, username VARCHAR(255), email VARCHAR(255))")
            
            # Insert 10,000 rows to create a massive DataRow pipeline
            print("Inserting 10,000 rows for DataRow alias testing...")
            values = [(f"user_{i}", f"user{i}@example.com") for i in range(10000)]
            await conn.executemany(
                "INSERT INTO users (username, email) VALUES ($1, $2)",
                values
            )
            
            # Now trigger the massive outbound pipeline
            print("Fetching 10,000 rows...")
            rows = await conn.fetch("SELECT username FROM users ORDER BY id ASC")
            print(f"Fetched {len(rows)} rows.")
            
            # Verify no data corruption / aliasing occurred
            corrupted = 0
            for i, row in enumerate(rows):
                expected = f"user_{i}"
                if row['username'] != expected:
                    corrupted += 1
                    if corrupted < 5:
                        print(f"Corruption at row {i}: Expected {expected}, got {row['username']}")
            
            if corrupted > 0:
                print(f"FAILED: Found {corrupted} corrupted rows due to DataRow aliasing!")
                sys.exit(1)
            else:
                print("SUCCESS: No DataRow aliasing detected.")
        
        print("ALL TESTS PASSED")
        await conn.close()

    except Exception as e:
        print(f"FAILED with exception: {e}")
        sys.exit(1)

if __name__ == '__main__':
    asyncio.run(run_pipeline())
