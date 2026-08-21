# Iterative DNS Resolver

A DNS message parser and a caching, concurrent **iterative** resolver, written in Python with nothing but the standard library — no `dnspython`, no shelling out to `dig`. Every byte on the wire is encoded and decoded by hand.

This was an individual coursework project for **Computer Networks and Applications** during my postgraduate study at the University of New South Wales. The resolver answers real queries against the live root servers: point `dig` at it and it walks the delegation chain from the root down to the authoritative server itself.

## What it does

Two programs share one protocol library (`toolbox.py`).

**`parser.py`** reads a binary DNS message from a file and prints it in a readable form — header ID, every flag, the four section counts, the question, and each resource record. It handles **name compression pointers**, which is what makes the format awkward: a name can be spelled out, or be a pointer back to an earlier offset, or be a few labels followed by a pointer.

**`resolver.py`** is a UDP server that resolves names the way a real recursive resolver does:

- It starts from the **root hints file** and asks a root server with **RD=0** — "tell me who to ask", not "do it for me".
- The answer is usually a **referral**: a set of NS records for the next zone down, plus glue A records giving their addresses. It picks up the glue and repeats one level deeper.
- When the referral carries **no glue** (the NS names live outside the zone), it runs a **nested resolution** for those names first, then continues.
- **CNAME chains** are followed — within a single reply where possible, otherwise by restarting from the root with the new name.
- Every answer goes into a **TTL cache**, so a repeat query is served from memory with no packet sent at all.
- Each request is handled on its own thread, so a slow lookup never holds up the ones beside it.

Supported query types: **A, NS, CNAME, PTR, MX**. Anything else is refused rather than mishandled.

## How a query is answered

`resolver.py` sorts an incoming query into one of three cases:

| Case | Condition | Where the answer comes from |
| --- | --- | --- |
| 1 | `. NS` | The root hints file directly — no packet leaves the machine |
| 2 | `A` for a root server's own name | The glue in the root hints file |
| 3 | Everything else | The TTL cache, and on a miss, an iterative walk from the roots |

The walk is bounded on three axes so a malicious or broken zone cannot spin it forever: at most **50 outbound queries**, **10 referral levels**, and **10 CNAME hops** per request, under an overall deadline of `min(30, 50 × timeout)` seconds. The budget is a single dict threaded through the recursion, so the nested CNAME and no-glue lookups draw from the same allowance rather than each getting a fresh one.

## Design notes

**Name compression was not optional.** An uncompressed root NS response measures **862 bytes** — over the 512-byte ceiling for a non-EDNS(0) UDP DNS message, and the records may not be dropped to fit. With compression the same response is **436 bytes**. This forces two structural choices: every record must be written into one shared `bytearray` (pointer offsets are relative to the whole message, so separately-encoded sections have no common coordinate system), and `RDLENGTH` must be reserved and backfilled.

**Resolution logic is kept apart from protocol encoding.** `resolve()` returns a `(status, ...)` tuple and never touches transaction IDs, flags, or bytes; `handle_query()` — which holds the client context — translates that status into an RCODE and encodes it. The split proves itself in CNAME chasing and glueless referrals, where `resolve()` recurses into itself: an inner level neither should nor could know the outermost client's transaction ID.

**Upstream queries use a fresh random transaction ID, not the client's.** The client's ID is visible on the wire; reusing it would publish the credential used to match responses. `ask_server()` also leaves its socket unbound, so the OS picks an ephemeral source port and forging a reply gets harder still.

**Malformed names raise rather than exit.** An early version called `exit()` on a bad name. That is tolerable in the parser, but the same function is reused by the resolver, where a malformed upstream reply must mean "drop this candidate and try the next one" — killing the process would take down the whole server.

**Responses are built in two passes:** collect the records to return as ordinary Python tuples, then encode. Section counts come from `len(list)`, so they cannot disagree with what was actually written.

**Concurrency came last, but the ground was prepared early.** Threads make bugs hard to reproduce, so none were introduced until the single-threaded path worked end to end. But no per-request state was ever kept in a global, so the final step was moving the loop body into `handle_query()` and starting a thread — no business logic changed.

## Requirements

Python 3.9 or newer. Nothing to install — the standard library is the whole dependency list.

`dig` is used for testing (`brew install bind` on macOS, `apt install dnsutils` on Debian/Ubuntu).

## Run

### The parser

```bash
python3 parser.py resources/example.com-NS-12000-response.bin
```

```
ID: 12000
--- FLAGS ---
QR: True
...
--- ANSWERS ---
example.com. 3600 IN NS ns1.example.com.
example.com. 3600 IN NS ns2.example.com.
--- ADDITIONAL ---
ns1.example.com. 3600 IN A 192.0.2.53
ns2.example.com. 3600 IN A 192.0.2.54
```

### The resolver

```bash
python3 resolver.py resources/named.root 5 53000
```

The three arguments are the root hints file, the per-upstream-query timeout in seconds, and the UDP port to listen on. It binds `127.0.0.1` only. Then, from another shell:

```bash
dig +noedns @127.0.0.1 -p 53000 unsw.edu.au A
dig +noedns @127.0.0.1 -p 53000 gmail.com MX
dig +noedns @127.0.0.1 -p 53000 8.8.8.8.in-addr.arpa PTR
dig +noedns @127.0.0.1 -p 53000 . NS
```

`+noedns` matters: the resolver speaks plain 512-byte UDP, and `dig` advertises EDNS(0) by default.

`resources/named.root` is the root hints file as published by [InterNIC](https://www.internic.net/domain/named.root), unmodified.

## Test

```bash
./test.sh 53000
```

Checks the cache (the same query cold, then warm), each supported record type, and that concurrent queries overlap rather than queue.

```bash
python3 perf_test.py 53000
```

A measurement harness: it sends a fixed set of 30 queries to this resolver and to a public recursive resolver, sequentially and concurrently, with a cold and a warm cache, and prints summary statistics.

## Performance

Measured on macOS (arm64), Python 3.9.6, home broadband; 30 queries over 24 distinct names and 4 query types. Times in milliseconds.

| Scenario | n | NOERROR | median | mean | p95 |
| --- | --- | --- | --- | --- | --- |
| This resolver, cold cache, sequential | 30 | 26 | 415.0 | 1071.4 | 3766.4 |
| This resolver, warm cache, sequential | 30 | 26 | **0.4** | 555.6 | 2726.4 |
| `1.1.1.1`, sequential | 30 | 30 | 11.1 | 79.3 | 320.7 |

**The cache is worth about 1000×** at the median (415.0 → 0.4 ms). The mean barely moves, because the four failing queries are never cached and re-run the full walk every round — which is exactly why the median is the honest number here.

**Concurrency works.** Warm, the per-query times sum to 16667.8 ms, while the concurrent batch finishes in 6687.1 ms of wall clock — essentially the time of the single slowest query (6685.6 ms). A cleaner control: six distinct uncached names sum to 3905 ms sequentially and finish in 1596 ms concurrently, again matching the slowest one.

**Against `1.1.1.1`, read the comparison carefully.** It wins on cold queries for three reasons that are not about implementation quality: these are popular names already in its cache, so this is *its warm cache against our cold one*; it speaks EDNS(0) and is not bound by 512 bytes; and its anycast footprint puts it closer to the authoritative servers. Warm against warm, 0.4 ms beats its 11.1 ms — ours is a local memory lookup and its is still a network round trip.

## Known limitations

1. **No TCP fallback and no EDNS(0).** When an upstream referral exceeds 512 bytes and comes back truncated (`TC=1`), that candidate has to be treated as failed, and if every candidate at a level truncates, the request returns SERVFAIL. Four names failed this way in the measurements above: the `.com` and `.net` root referrals carry 13 NS records with dual-stack glue and routinely overflow, while `mozilla.org`'s `.org` referral ships no glue at all (its NS records live under `akam.net.`), so the nested lookup runs straight into the `.net` truncation and exhausts the query budget. The same 30 queries succeed 30/30 on a resolver that speaks EDNS(0).
2. **No IPv6 transport, and AAAA glue is ignored.** A referral whose additional section holds only AAAA records counts as having no glue.
3. **NXDOMAIN is not checked for authority.** Any `RCODE=3` is accepted. Tightening this risks rejecting real servers that do not set AA.
4. **The cache stores positive answers only** — no referrals, no glue, no negative caching. Failed lookups therefore repeat the whole walk every time.
5. **The cache has no size limit or eviction policy**, only lazy expiry when a TTL runs out. It grows without bound over a long run.
6. **Unsupported query types return SERVFAIL** (`RCODE=2`) where `NOTIMP` (`RCODE=4`) would describe the situation better.
7. **A CNAME chain inside a single reply is matched owner by owner**, so an unusually ordered reply can cost one extra upstream query. The result is still correct, just not minimal.

## Project structure

```
toolbox.py     # the protocol library: byte order, name encode/decode with
               # compression, message parse and build, upstream I/O, TTL cache
parser.py      # Stage 1 - read a message file, print it
resolver.py    # Stage 2/3 - root hints, UDP server, per-request threads
perf_test.py   # measurement harness behind the numbers above
test.sh        # smoke check: cache, record types, concurrency
resources/
  named.root   # root hints, as published by InterNIC
  *.bin        # sample DNS queries and responses for the parser
```

## License

[MIT](LICENSE)

## Author

**Tianshu Shen** — this was an individual assignment, written and tested by me.
