//! `psob-indexer` — PSob light client / multi-chain indexer.
//!
//! Role: a *cache and discovery layer* over the Litecoin AuxPoW family. It
//! ingests auxiliary chain blocks (raw 80-byte header + CAuxPow witness) from
//! Esplora-style Electrs endpoints, light-verifies each header against the
//! same consensus checks the ZK guest performs (chain-id, target range +
//! powLimit floor, AuxPoW commitment, prev-hash linkage — *without* scrypt,
//! which stays the guest's job), and classifies the embedded Litecoin parent
//! header as either a **mainnet** block or a **trial** block.
//!
//! The mainnet/trial classification is the value-add the light client
//! provides beyond a raw header mirror: PSob epochs `[L_start, L_end]` must
//! bound to Litecoin *mainnet* blocks, while trial parents (>&nbsp;⇠ 100% of
//! JKC/CRC parents per the sibling paper) are still provable by the guest via
//! independent scrypt against their own `nBits`, but cannot anchor an epoch.
//!
//! Trust boundary: this crate decides *nothing* about funds. The SP1 guest
//! re-verifies every header and commitment before anything settles; a
//! malicious or incomplete indexer can at most cause a liveness stall.

pub mod config;
pub mod db;
pub mod ingest;
pub mod p2p;
pub mod resolve;
pub mod server;

pub use config::Config;
pub use db::{Database, SharedParent, StoredBlock, StoredParent};