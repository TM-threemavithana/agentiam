# I built a Postgres AST proxy to secure LLMs, and it immediately corrupted my database schemas

I ran a LangChain agent against my proxy and it immediately corrupted table names before the first query ran.

I've been building **AgentIAM**, a Go-based proxy that sits between your database and your LLMs. The premise was simple: regex firewalls aren't enough to stop LLM prompt injections. If you want to prevent a hallucinating agent from dropping your production tables, you need to intercept the wire protocol and parse the actual SQL AST (Abstract Syntax Tree) before it reaches the database.

It looked great on paper. I had a README claiming "zero external infrastructure dependencies," theoretical benchmarks, and it passed all my mock tests with flying colors. 

Then I plugged it into a real environment. I connected a LangChain agent (driven by an Ollama 3B model) to a Postgres 15 database running through my proxy.

It immediately crashed. Not the LLM—LangChain's SQLAlchemy introspection.

When LangChain tried to discover the available tables in the database, it threw a `table not found` error for `users`. It complained the table didn't exist, even though querying the proxy directly via `psql` showed both `users` and `orders`.

## The Ghost in the Machine

By dumping the Extended Query protocol packets, I realized the AST parser wasn't the problem at all. It was a classic Go memory aliasing bug in my proxy's concurrency model. 

The underlying driver I was using (`pgproto3/v2`) famously reuses connection read buffers for performance. My proxy was reading `DataRow` messages (which contain pointers to that read buffer) and shoving them into an asynchronous Go channel (`clientWriteCh`) to multiplex the responses back to the client.

By the time the background writer routine pulled the first row (`users`) out of the channel, the reader routine had already reused the exact same memory address for the second row (`orders`). It was literally overwriting the previous row in memory before sending it to the client.

SQLAlchemy was receiving `[('orders',), ('orders',)]`. It saw duplicates, got confused, and silently failed to reflect the `users` table. If this had made it to production, the ORM would have reflected the wrong schema, and queries would have targeted the wrong tables without throwing explicit protocol errors.

## The Fix

The fix was humbling. I had to explicitly deep-copy the `[]byte` slices inside the upstream read loop right before queueing them. 

Here is the exact diff that saved my database schemas:

```diff
  			if err != nil {
  				u.Broken.Store(true)
  				s.releaseUpstream()
  				return
  			}
  
+ 			if dr, ok := msg.(*pgproto3.DataRow); ok {
+ 				newValues := make([][]byte, len(dr.Values))
+ 				for i, v := range dr.Values {
+ 					if v != nil {
+ 						newValues[i] = append([]byte(nil), v...)
+ 					}
+ 				}
+ 				msg = &pgproto3.DataRow{Values: newValues}
+ 			} else if rd, ok := msg.(*pgproto3.RowDescription); ok {
+ 				newFields := make([]pgproto3.FieldDescription, len(rd.Fields))
+ 				for i, f := range rd.Fields {
+ 					newFields[i] = f
+ 					if f.Name != nil {
+ 						newFields[i].Name = append([]byte(nil), f.Name...)
+ 					}
+ 				}
+ 				msg = &pgproto3.RowDescription{Fields: newFields}
+ 			} else if cc, ok := msg.(*pgproto3.CommandComplete); ok {
+ 				newTag := append([]byte(nil), cc.CommandTag...)
+ 				msg = &pgproto3.CommandComplete{CommandTag: newTag}
+ 			}
+ 
  			if _, ok := msg.(*pgproto3.ParseComplete); ok {
  				swallows := u.SwallowParseComplete.Load()
```

As soon as I deployed this fix, the bug vanished. LangChain finally saw both tables, and successfully executed a `SELECT COUNT(*) FROM users;` (which AgentIAM correctly allowed and injected a `LIMIT 100` onto).

## Skeletons in the Closet

That wasn't the only reality check I got when I stopped relying on synthetic tests. When I finally forced myself to run real profilers and security scanners on the codebase, the "10/10 AI-generated code reviews" I had been proud of melted away:

1. **The Cache That Did Nothing:** My AST cache was supposed to make parsing blazingly fast. Instead, profiling showed it was allocating 507KB and taking 210µs per query. Why? Because of a flawed implementation that bypassed the cache entirely and kept hitting the C-Go protobuf bridge. Fixing this dropped allocations to 384 Bytes and made the cache 500x faster.
2. **The Vulnerabilities:** Running a real `govulncheck` exposed 22 unpatched CVEs because I was running an outdated Go toolchain (`1.25.0`), leaving the proxy open to critical TLS handshake exploits. I bumped to `1.25.11` to patch 21 of them, and explicitly documented the remaining unfixable upstream dependency CVE (`GO-2026-4518`) in a `SECURITY.md` file rather than hiding it.
3. **The Untested Core:** My MySQL AST parser, despite being a headline feature, had exactly 0.0% test coverage on its rule enforcement path. It's now at 87%+.

## The Real Takeaway

There's a massive difference between building a repository that *looks* impressive for GitHub stars (with clean READMEs and AI-generated praise) and building a system that actually survives contact with a real ORM, a real LLM, and real infrastructure.

Synthetic benchmarks and mock tests will lie to you. They will hide memory corruption bugs that will destroy data integrity silently in deployment. 

AgentIAM is open-source, and it's finally ready for real scrutiny. Check it out, break it, and tell me what else I missed.
