# PSob Indexer API Reference

Interactive docs: `GET /docs` (Swagger UI) or `GET /api/v1/openapi.json`.

Base URL: `http://<indexer>:8080`.

## Conventions

- All responses are JSON. Errors always use one envelope:
  `{"error": {"code": "bad_request|not_found|internal_error", "message": "…"}}`.
- List endpoints paginate with `limit` (default 20, max 200) and `offset`;
  list responses carry `total`.
- **Endianness contract** (crucial for verifiers):
  - `block_hash`, `parent_hash`, `coinbase_txid` — display (big-endian) hex.
  - `chain_merkle_branch[]`, `parent_merkle_branch[]` — raw wire
    (little-endian) hex, exactly as serialized in CAuxPow. This is the byte
    order the merkle fold takes (matching `common/src/lib.rs` and the SDK).
  - `auxpow_hex` — the verbatim wire payload (80-byte header ‖ CAuxPow).
  - `parent_header` — the parent block's 80 bytes, raw wire hex.

## Endpoints

### GET /metrics
Prometheus text exposition (always served, `psob_indexer_*` namespace):
HTTP counters/histograms by route, per-chain ingest counters and gauges
(`ingest_blocks_total`, `indexed_blocks`, `chain_cursor`), sibling/parent
gauges, and prune counters. Point a Prometheus scrape job at it.

### GET /api/v1/health
Liveness + schema info.

```json
{
  "status": "ok", "service": "psob-indexer", "version": "0.1.0",
  "schema_version": 2, "configured_chains": 8,
  "total_blocks": 47321, "p2p_enabled": true
}
```

### GET /api/v1/chains
```json
{
  "count": 2,
  "chains": [{
    "chain_id": 8224, "name": "JKC", "electrs_url": "https://junk-api.s3na.xyz",
    "cursor_height": 1095603, "pow_limit_bits": "0x1e0fffff",
    "blocks": 3, "min_height": 1095601, "max_height": 1095603
  }]
}
```

### GET /api/v1/stats
```json
{
  "version": "0.1.0", "uptime_seconds": 142,
  "total_blocks": 47321, "total_parents": 4510, "sibling_groups": 210,
  "chains": [{"chain_id": 8224, "name": "JKC", "cursor_height": 1095603,
              "blocks": 47321, "min_height": 1095301, "max_height": 1095603}]
}
```

### GET /api/v1/siblings

Query: `min_legs` (default 2), `chain_id`, `limit`, `offset`.

```json
{
  "total": 210, "limit": 1, "offset": 0,
  "items": [{
    "parent_hash": "fded3204ed055790c36bf0f3e048652102670cdcd2b4eaa9e9c93d400dab5e02",
    "ltc_height": 3547005,
    "legs_count": 2,
    "legs": [
      {"chain_id": 8224, "name": "JKC",  "height": 1095600, "block_hash": ""},
      {"chain_id": 50,   "name": "DINGO", "height": 2717300, "block_hash": ""}
    ]
  }]
}
```

### GET /api/v1/siblings/:parent_hash

Query: `include_auxpow=true` appends `auxpow_hex` per sibling.

```json
{
  "parent_hash": "fded3204…5e02", "ltc_height": 3547005, "parent_state": 1,
  "sibling_count": 2,
  "siblings": [
    {"chain_id": 8224, "height": 1095600,
     "block_hash": "216ccca027bde174293a775e52d861dabe4e45028847189d100d9e75d0c6fbf4"},
    {"chain_id": 50, "height": 2717300, "block_hash": "…"}
  ]
}
```

### GET /api/v1/blocks
Query: `chain_id` (required), `from`, `to`, `limit`, `offset`.

### GET /api/v1/block/:chain_id/:height
Always self-verifiable — includes the store's own re-verification step report:

```json
{
  "block_hash": "216ccca0…fbf4", "parent_hash": "fded3204…5e02",
  "parent_state": 1, "has_auxpow": true,
  "header_len": 80, "wire_len": 818,
  "raw_auxpow_hex": "04012020…",
  "verification": {
    "valid": true,
    "proof1_coinbase_to_parent_root": {"ok": true, "error": null},
    "proof2_aux_to_chain_root": {"ok": true, "error": null},
    "anti_grind_lcg_slot": {"ok": true, "error": null},
    "header_format": {"ok": true, "error": null},
    "chain_branch_depth": 5, "chain_index": 14, "n_size": 32, "nonce": 2677055472,
    "parent_chain_id": 8192, "coinbase_root_hex": "eaab4996…6785"
  }
}
```

### GET /api/v1/proof/:chain_id/:height

The complete witness for client-side `verifyPsobProof` equivalents:

```json
{
  "chain_id": 8224, "height": 1095600,
  "block_hash": "216ccca0…fbf4", "parent_hash": "fded3204…5e02",
  "parent_chain_id": 8192,
  "parent_merkle_branch": [], "parent_index": 0,
  "chain_merkle_branch": ["…44 bytes hex…"], "chain_index": 14,
  "coinbase_tx": "01000000…", "parent_header": "…160 hex…",
  "auxpow_hex": "04012020…", "coinbase_txid": "…"
}
```

### GET /api/v1/epoch/:ltc_start/:ltc_end
Query: `chain_id`, `limit`, `offset`.

### GET /api/v1/epoch/latest
Query: `min_legs` (default 2). 404 if none indexed.

### POST /api/v1/verify

Request: `{"chain_id": 8224, "wire_hex": "<full wire payload hex>"}`.
`pow_limit_bits` is required only when the chain isn't configured on this node.

```json
{
  "valid": true, "chain_id": 8224,
  "block_hash": "216ccca0…fbf4", "parent_hash": "fded3204…5e02",
  "parent_chain_id": 8192,
  "coinbase_root_hex": "eaab4996…6785", "n_size": 32, "nonce": 2677055472,
  "chain_branch_depth": 5, "chain_index": 14,
  "verification": { "valid": true, "…steps…": "…" }
}
```

### P2P endpoints
`GET /api/v1/p2p/status`, `GET /api/v1/p2p/peers`,
`POST /api/v1/p2p/broadcast` (body = swap intent JSON). All 503 when P2P is
disabled.

## Serving raw blocks & helpers

- The `SDK` (`@dedoo/psob-sdk`) wraps every endpoint above with typed
  responses and a TS port of the verification logic — use it, or port the
  rules from `crates/common/src/lib.rs` / `src/verify.rs`.
- `cargo run --bin psob-explain -- <db> --legs 2 --ltc-start N --ltc-end M`
  prints a human-readable sibling/epoch report from a local DB.
