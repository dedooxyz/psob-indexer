# Proof-of-Sibling (PSob) Multichain Indexer

High-performance Rust indexer for the Litecoin AuxPoW ecosystem: it ingests
merge-mined block headers from **Junkcoin (JKC), Dingocoin (DINGO), Luckycoin
(LKY), Shibacoin (SHIC), TrumPOW (TRMP), Craftcoin (CRC), B1tcore (B1T), and
Lebowskis (LBW)**, light-verifies their PSob consensus proofs, and indexes the
shared Litecoin parent anchors that make trust-minimized cross-chain
verification possible.

```
       aux chains                     parent chain (Litecoin)
 ┌───────────────────────┐         ┌───────────────────────┐
 │ JKC  DINGO  LKY  SHIC │         │  block L               │
 │ TRMP  CRC  B1T  LBW   │  ─────► │  coinbase commits      │
 │ (merge-mined blocks)  │ CAuxPow │  aux merkle root R     │
 │  one shared parent ?  │         └───────────────────────┘
 └───────────────────────┘
```

**Proof-of-Sibling**: several aux chains' blocks that embed the *same* Litecoin
parent header are "siblings" — because the parent coinbase commits to exactly
one aux-chain merkle root per anti-grind slot, and that root folds every
sibling block. The indexer groups blocks by shared parent hash and exposes the
raw, self-verifiable CAuxPow witness for every one of them.

- **The indexer is an untrusted caching & discovery layer.** It decides nothing
  about funds. Every response carries the verbatim wire CAuxPow, and any client
  (the [@dedoo/psob-sdk] or a custom verifier) re-runs the full PSob checks
  locally.
- **Light verification, no scrypt.** The indexer checks Proof 1 (coinbase →
  parent merkle root), Proof 2 (aux hash → chain root committed in coinbase),
  the anti-grind LCG slot rule, chain-id, and the nBits/powLimit floor. Scrypt
  PoW stays in the ZK guest where it belongs (see ARCHITECTURE.md).

## Quick start

```bash
# Clone & configure
git clone https://github.com/dedooxyz/psob-indexer.git
cd psob-indexer
cp .env.example .env

# Run (ingest + REST API + P2P gossip)
cargo run --release --bin psob-indexer

# Interact
curl http://localhost:8080/api/v1/health
curl http://localhost:8080/api/v1/stats
# Docs (Swagger UI):
open http://localhost:8080/docs
```

### Configurable without touching code

All configuration comes from `.env` → an optional `psob-indexer.toml` →
process environment (later wins). Every aux chain and its Electrs endpoint,
powLimit, cursors, HTTP timeouts, retries, CORS, bind address, and P2P settings
are configurable — nothing is hardcoded. See config.example.toml.

The chain registry format is:

```
NAME|CHAIN_ID|ELECTRS_URL|POWLIMIT_BITS_HEX[|START_HEIGHT]
```

| Field | Meaning |
|---|---|
| `CHAIN_ID` | `nVersion >> 16` of the chain (e.g. 8224 = Junkcoin) |
| `ELECTRS_URL` | Esplora-style Electrs base URL (serves `raw` CAuxPow headers) |
| `POWLIMIT_BITS_HEX` | consensus powLimit in compact nBits (`0x1e0fffff` = scrypt family) |
| `START_HEIGHT` | cursor seed for fresh DBs — the walk ingests `START_HEIGHT+1..tip` |

### Tooling

```bash
cargo test --workspace --lib --bins --test api   # 40+ tests incl. live fixture
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
cargo run --bin psob-explain -- psob-indexer.redb --ltc-start 3547000 --ltc-end 3547100
```

## REST API (summary)

Full docs: [API.md](API.md), interactive at `/docs`.

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/v1/health` | Liveness + schema version + block count |
| `GET` | `/api/v1/chains` | Configured chains, cursors, indexed ranges |
| `GET` | `/api/v1/stats` | Indexer stats (totals, per-chain, sibling groups) |
| `GET` | `/api/v1/siblings` | Paged sibling groups (shared LTC parents) |
| `GET` | `/api/v1/siblings/:parent_hash` | One group incl. self-verifiable auxpows |
| `GET` | `/api/v1/blocks?chain_id=…&from=…&to=…` | Paged block range |
| `GET` | `/api/v1/block/:chain_id/:height` | Stored block + re-verification report |
| `GET` | `/api/v1/proof/:chain_id/:height` | Full PSob proof witness |
| `GET` | `/api/v1/epoch/:ltc_start/:ltc_end` | Paged epoch witness blocks |
| `GET` | `/api/v1/epoch/latest` | Latest sibling group |
| `POST` | `/api/v1/verify` | Client-driven full verification of any wire |
| `GET` | `/api/v1/p2p/*`, `POST /api/v1/p2p/broadcast` | Gossip mesh queries |

**Endianness contract** (also in API.md): `block_hash` / `parent_hash` are
display (big-endian) hex; `chain_merkle_branch` / `parent_merkle_branch` are
raw wire (little-endian) hex; `auxpow_hex` is the verbatim wire payload.

## Verification guarantees (what the indexer checks)

| Check | Rule | Ports |
|---|---|---|
| Header format | 80 bytes, `nVersion >> 16 == chain_id`, nBits valid + target ≤ powLimit | `src/verify.rs` |
| Proof 1 | coinbase at parent index 0, parent chain-id ≠ aux chain-id, `fold(sha256d(coinbase), parentBranch) == parentRoot` | `src/verify.rs`, `common::verify_auxpow_commitment` |
| Proof 2 | `fold(auxBlockHash, chainBranch, chainIndex) == committedRoot` right after exactly one `fabe6d6d` magic in the coinbase | `src/verify.rs` |
| Anti-grind | the 4-byte size after the root = `2^depth` AND `chainIndex == getExpectedIndex(nonce, chainId, depth)` (LCG) | `src/verify.rs` |
| Chain linkage | each header's `prev_hash` equals the stored previous block (hash, never a trust-me height claim) | `src/ingest.rs` |
| Scrypt PoW | NOT checked — the ZK guest's job, in-circuit | — |

## Architecture

See [ARCHITECTURE.md](ARCHITECTURE.md) for the full story: trust boundary,
data flow, storage layout, P2P topics, and the verify/API/storage separation.

```
┌──────────────────────── psob-indexer ─────────────────────────┐
│ ingest (per-chain tasks, retry/backoff, concurrent fetch)      │
│   └─ verify (pure functions — no I/O)                         │
│ db (redb + memory cache — sibling index, self-verifiable)     │
│ server (axum — OpenAPI /docs, error envelope, pagination)     │
│ p2p (libp2p gossipsub — /psob/headers|siblings|intents/v1)    │
└────────────────────────────────────────────────────────────────┘
        │ REST (self-verifiable)
        ▼
explorers · @dedoo/psob-sdk · bridges / ZK provers
```

## License

Licensed under either [MIT](LICENSE-MIT) or [Apache 2.0](LICENSE-APACHE) at
your option (dual license).

[@dedoo/psob-sdk]: https://github.com/dedooxyz/psob-sdk
