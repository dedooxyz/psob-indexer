# Proof-of-Sibling (PSob) Multichain Indexer

High-performance Rust multichain indexer and P2P gossip mesh for the Litecoin AuxPoW ecosystem.

The **PSob Indexer** ingests AuxPoW block headers with merge-mining witnesses from live Electrs / Esplora endpoints across multiple auxiliary blockchains, light-verifies their consensus proofs, indexes shared Litecoin parent anchors, and powers trust-minimized cross-chain atomic swaps via REST and Libp2p gossip.

---

## 🌟 Key Features

- **8-Chain Continuous Ingestion:** Concurrently polls and indexes headers from Junkcoin (JKC), Dingocoin (DINGO), Luckycoin (LKY), Shibacoin (SHIC), TrumPOW (TRMP), Craftcoin (CRC), B1tcore (B1T), and Lebowskis (LBW).
- **Consensus Light Verification:** Verifies Proof 1 (Coinbase to Parent Merkle Root), Proof 2 (Aux Block to Chain Merkle Root), and the Anti-Grind LCG invariant ($2^d$ size & deterministic slot assignment) before indexing.
- **Shared Sibling Deduplication:** Automatically groups auxiliary blocks mined under identical Litecoin parent headers into shared sibling epochs.
- **REST API:** High-throughput JSON endpoints for querying sibling groups, block headers, chain status, and epoch witnesses.
- **Libp2p P2P Network:** Built-in GossipSub topic `/psob/intents/v1` for decentralized cross-chain swap intent discovery and maker/taker coordination.
- **Embedded Redb / SQLite Storage:** Fast local state caching for epoch resolution and swap witness assembly.

---

## 🚀 Quick Start

### Prerequisites
- Rust 1.75+ (Cargo)

### Build & Run
```bash
# Clone the repository
git clone https://github.com/dedooxyz/psob-indexer.git
cd psob-indexer

# Copy example environment configuration
cp .env.example .env

# Run indexer
cargo run --release
```

---

## 📡 REST API Reference

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/api/v1/health` | Service health and indexed chain status |
| `GET` | `/api/v1/sibling/:parent_hash` | Get all auxiliary blocks under a shared LTC parent |
| `GET` | `/api/v1/header/:chain_id/:hash` | Get verified 882-byte CAuxPow header and parsed witness |
| `GET` | `/api/v1/epoch/latest` | Get latest verified multi-chain sibling epoch |
| `POST` | `/api/v1/intents` | Publish cross-chain swap intent to P2P mesh |
| `GET` | `/api/v1/intents` | List active swap intents in local mempool |

---

## 🔒 Security Architecture

The PSob Indexer operates as an **untrusted caching and discovery layer**:
- Indexer responses are self-verifiable using the raw 882-byte `CAuxPow` wire format.
- On-chain settlements (via EVM covenants, Bitcoin Computer, or ZK verifiers) cryptographically re-verify the full AuxPoW Merkle branches before releasing escrow funds.

---

## 📜 License

Licensed under either [MIT](LICENSE-MIT) or [Apache 2.0](LICENSE-APACHE) at your option.
