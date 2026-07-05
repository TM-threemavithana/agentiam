import asyncio
import asyncpg
import sys
import os
import subprocess
import time
import ssl
import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

# Global list to capture webhook payloads
captured_events = []

class WebhookHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length)
        
        try:
            payload = json.loads(post_data.decode('utf-8'))
            captured_events.append(payload)
        except Exception as e:
            print(f"Failed to decode webhook payload: {e}")
            
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"OK")
        
    def log_message(self, format, *args):
        # Suppress HTTP server logging
        pass

def run_http_server(server):
    server.serve_forever()

async def run_queries():
    dsn = "postgres://test-agent:test-agent-secret@127.0.0.1:5433/postgres?sslmode=disable"
    ssl_context = ssl.create_default_context()
    ssl_context.check_hostname = False
    ssl_context.verify_mode = ssl.CERT_NONE

    print("Connecting to proxy...")
    conn = await asyncpg.connect(dsn, ssl=ssl_context)
    
    # Valid query -> should generate 'query_forwarded' webhook
    print("Executing allowed query...")
    try:
        await conn.execute("SELECT 1")
    except Exception as e:
        print(f"Failed valid query: {e}")
        
    # Blocked query -> should generate 'policy_blocked' webhook
    print("Executing blocked query...")
    try:
        await conn.execute("UPDATE pg_class SET relname = 'foo'")
    except Exception as e:
        print(f"Expected failure for blocked query: {e}")
        
    await conn.close()

async def main():
    print("Starting dummy SIEM HTTP server on port 8081...")
    server = HTTPServer(('127.0.0.1', 8081), WebhookHandler)
    server_thread = threading.Thread(target=run_http_server, args=(server,))
    server_thread.daemon = True
    server_thread.start()
    
    env = os.environ.copy()
    env["AGENTIAM_POLICY_FILE"] = "policies_test.yaml"
    env["AGENTIAM_UPSTREAM_DSN"] = "postgres://postgres:postgres@127.0.0.1:5434/postgres?sslmode=disable"
    env["AGENTIAM_DEV_MODE"] = "true"
    env["AGENTIAM_INSECURE_CLEARTEXT_AUTH"] = "true"
    env["AGENTIAM_WEBHOOK_URL"] = "http://127.0.0.1:8081"
    
    print("Starting proxy...")
    proxy = subprocess.Popen(["./agentiam.exe"], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(0.5) # Wait for proxy to bind
    
    try:
        await run_queries()
        
        # Wait a moment for async dispatch to complete
        time.sleep(0.5)
        
        print("\nChecking captured webhook events:")
        if len(captured_events) == 0:
            print("FAILED: No webhooks were captured.")
            sys.exit(1)
            
        success_found = False
        blocked_found = False
        
        for idx, evt in enumerate(captured_events):
            print(f"Event {idx+1}: {json.dumps(evt)}")
            
            if evt.get("event") == "query_forwarded" and evt.get("status") == "success":
                success_found = True
            elif evt.get("event") == "policy_blocked" and evt.get("status") == "blocked":
                blocked_found = True
                
        if not success_found:
            print("FAILED: Did not find 'query_forwarded' event.")
            sys.exit(1)
            
        if not blocked_found:
            print("FAILED: Did not find 'policy_blocked' event.")
            sys.exit(1)
            
        print("\nSUCCESS: All expected audit webhook payloads were successfully streamed and captured.")
        
    finally:
        proxy.terminate()
        proxy.wait()
        server.shutdown()

if __name__ == "__main__":
    asyncio.run(main())
