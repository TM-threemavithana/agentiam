import asyncio
import asyncpg
import sys

async def test_auth():
    dsn = sys.argv[1]
    try:
        # Use simple connect
        conn = await asyncpg.connect(dsn)
        
        # Test basic query
        val = await conn.fetchval('SELECT 1')
        assert val == 1, f"Expected 1, got {val}"
        
        await conn.close()
        print("asyncpg authentication successful")
        sys.exit(0)
    except Exception as e:
        print(f"asyncpg failed: {e}")
        sys.exit(1)

asyncio.run(test_auth())
