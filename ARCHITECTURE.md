# PSob Indexer — Architecture

## 1. Trust model

The indexer is an **untrusted caching and discovery layer**. Its outputs are
one of several inputs to a settlement system; a dishonest or incomplete
indexer can at most cause a *liveness stall*, never a forgery:

- Every block response carries the **verbatim CAuxPow wire payload** — the
  80-byte aux header followed by the CAuxPow serialization. Any client can
  re-run the complete PSob verification locally without re-contacting us.
- The expensive scrypt proof-of-work is deliberately **not** evaluated here:
  the ZK guest does it in-circuit, and on-chain verifiers re-check everything
  before escrow funds move.
- The indexer's own writes go through the same checks it exports — if a row is
  read back and fails verification, the `/block/:chain/:height` response
  carries the failing report so the client can see it.

## 2. Data flow

```
Electrs endpoints (8+ aux chains)
   │  GET /block-height/:h → hash
   │  GET /block/:hash/header → raw wire (80B header ‖ CAuxPow)
   ▼
ingest()  ── per-chain tokio task ──────────────────────────────
   1. cursor = stored chain cursor (or configured START_HEIGHT)
   2. fetch batch window hashes + wires concurrently (semaphore)
   3. for each height, IN ORDER:
        light_verify()  → Proof 1 + Proof 2 + anti-grind + nBits + chain-id
        prev_hash linkage vs the block one below (reorg-safe)
   4. batch insert (redb) + cursor advance
   5. resolve unclassified parents vs the parent explorer API
   ▶ on failure: warn + exponential backoff (per-chain only)
   ▼
Database (redb + DashMap L1)
   aux_blocks  (chain_id, height) → StoredBlock { hash, header, wire_hex }
   parent_blocks (parent_hash LE) → StoredParent { state, ltc_height, work }
   sibling_index (parent, chain_id, height) → ()
   meta (cursors, chain registry, schema_version)
   ▼
REST API (axum)                  P2P (libp2p gossipsub)
   /api/v1/… self-verifiable        /psob/headers/v1
   OpenAPI at /docs                 /psob/siblings/v1
   error envelope, pagination       /psob/intents/v1
```

## 3. Verification semantics

The verification primitives live in two places by design:

- `crates/common` — no_std, dependency-free, shared with the ZK guest and the
  SDK port. Owns the **CAuxPow wire parser** (`cauxpow::parse_auxpow`), the
  merkle fold, `verify_auxpow_commitment` and `expand_target`/`target_leq`.
- `src/verify.rs` — the indexer's pure (no I/O) wrapper that produces a
  **per-step `VerificationReport`** rather than a bare bool, so API consumers
  get reasons.

A valid block must satisfy, all-at-once:

1. **Header format**: 80 bytes, `nVersion >> 16 == chain_id`, `nBits` decodes
   to a compact target with a valid size/sign/mantissa (`SetCompact` rules),
   and `target ≤ powLimit` (the consensus difficulty floor).
2. **Proof 1** (coinbase → parent root): coinbase is at `parentIndex == 0`
   (the generation tx), the parent header's own chain id differs from ours (a
   chain cannot merge-mine itself), and
   `fold(sha256d(coinbase), parentBranch) == parentHeader[36..68]`.
3. **Proof 2** (aux → chain root): `fold(auxHeaderHash, chainBranch,
   chainIndex)` equals the 32 bytes that sit immediately after exactly one
   `fa be 6d 6d` magic (little-endian order) in the coinbase.
4. **Anti-grind**: the 4-byte size right after the committed root equals
   `2^depth`, and the 4-byte nonce pins the slot:
   `chainIndex == LCG(nonce, chain_id, depth)`. One parent block therefore
   commits each chain at exactly one slot.

Chain linkage (each header's `prev_hash` equals the previous stored hash) is
enforced during ingestion, and a broken link triggers a scoped rollback
(`rollback_from`), never a global halt.

### Why no scrypt here

Verifying `scrypt(parentHeader) ≤ target` costs one scrypt per block and is the
thing a ZK verifier proves *inside* the circuit. The indexer is a discovery
layer: it filters out garbage, groups siblings, and hands over witnesses. It
never vouches for PoW.

## 4. Storage & indexing

- **redb** (ACID, log-structured, single-file) is the durable store. Values
  are bincode-serialized; the full wire payload is kept verbatim.
- A **DashMap L1** mirrors hot tables for µs reads; it is warmed at open. The
  indexer's working set is bounded by the ingestion window (`PSOB_MAX_BATCH`
  per tick) — the store is prunable via `rollback_from`.
- The `sibling_index` key order (`(parent, chain, height)`) makes
  "all blocks under one parent" a range seek instead of a scan. The same
  ordering backs `blocks_range` (`(chain, height)`) and the epoch queries
  (memory-indexed over classified parents).
- `schema_version` in the meta table gates compatibility: an old DB refuses to
  open with a clear message (it is a disposable cache — delete & re-ingest).

## 5. Ingestion resilience

- One task per chain (`Ingestor::spawn_all`); each has its own retry state.
  A failing chain cannot kill the process.
- HTTP layer: bounded client timeouts, exponential backoff with full jitter,
  retry on transport errors / 429 / 5xx, and an optional minimum inter-request
  interval (rate limiting) for fragile public endpoints.
- Concurrent batch fetches with a bounded semaphore; verification still runs
  strictly in height order so the linkage gate stays sound.

## 6. P2P

Optional libp2p swarm (falls back gracefully if it cannot start). The ingest
loop publishes verified data — headers on every batch, sibling groups when a
parent becomes mainnet-shared — through the same typed channel used for
intents:

| Topic | Emitted when | Payload |
|---|---|---|
| `/psob/headers/v1` | each ingest batch | batch tip + `auxpow_hex` (self-verifiable) |
| `/psob/siblings/v1` | parent classified mainnet, ≥2 legs | parent, `ltc_height`, legs |
| `/psob/intents/v1` | `POST /api/v1/p2p/broadcast` | signed swap intent |

## 6.1 Observability

`GET /metrics` (Prometheus text exposition):

- `http_requests_total{method,route}`, `http_request_seconds{method,route}` —
  per-route counters and histograms from the axum middleware layer
  (`MatchedPath` labels, unmatched → raw path).
- `ingest_blocks_total{chain_id}`, `ingest_ticks_total{chain_id}`,
  `ingest_errors_total{chain_id}`, `prune_blocks_total{chain_id}`,
  `parent_resolves_total{state}` — per-chain ingest health.
- `indexed_blocks{chain_id}`, `chain_cursor{chain_id}`, `sibling_groups`,
  `indexed_parents`, `uptime_seconds` — DB gauges refreshed at scrape time
  from the L1 cache.

A ready-made Grafana dashboard ships in `grafana/psob-indexer-dashboard.json`
(ingest, prune, classification, and HTTP latency panels).

## 6.2 Bounded-window pruning

When `PSOB_MAX_KEPT_BLOCKS` is set, each tick compares the stored minimum
height against `cursor - max_kept + 1` and issues a range prune
(`prune_before`) that deletes blocks **and** their sibling-index entries in
one write transaction (the L1 cache is re-synced afterwards). The cursor is
never touched; parent classifications outlive the pruned window (they are the
smallest, most reusable part of the store).

## 6.3 WASM

`crates/psob-wasm` compiles the `common` verification path to
`wasm32-unknown-unknown` (plain `extern "C"` ABI, no wasm-bindgen CLI) — the
SDK's test suite drives it against the same live fixture and asserts
byte-exact agreement with the TS port. Build: `cargo build -p psob-wasm
--target wasm32-unknown-unknown --release`.

## 7. API design rules

1. **Self-verifiability**: `auxpow_hex` on every block-level response.
2. **One error envelope**: `{"error": {"code", "message"}}`.
3. **Consistent pagination**: `limit`/`offset` params, `total` + `items` in
   list responses.
4. **Documented**: utoipa OpenAPI served at `/api/v1/openapi.json` + Swagger UI
   at `/docs`.
5. **Endianness**: display hex (`block_hash`, `parent_hash`) vs wire hex
   (merkle branches) — never mixed, always documented (see API.md).

## 8. Extension points

- **New chain**: add an entry to `PSOB_CHAINS` (or `[[chains]]` in TOML) —
  hashes, powLimit, chain-id, and start height. No code change.
- **Different parent chain**: point `PSOB_PARENT_ELECTRS` / `PSOB_PARENT_CHAIN`
  at another explorer. (PSob is *generic* across AuxPoW parents.)
- **Gossip beyond intents**: subscribe to the two other topics and publish
  verified data from the ingest path.
- **New indexer node**: run N replicas; they gossip via mDNS/`PSOB_BOOTSTRAP_NODES`.
