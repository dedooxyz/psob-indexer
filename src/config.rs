//! Runtime configuration — **100% env-driven**. No endpoints, no chains, no
//! settings are hardcoded in code; a missing or malformed value fails loudly at
//! startup rather than silently deploying against the wrong chain.

use std::time::Duration;

/// One aux chain we can ingest. Registry comes entirely from `PSOB_CHAINS`.
#[derive(Clone, Debug)]
pub struct AuxChain {
    /// `nVersion >> 16` chain id, e.g. 8224 for Junkcoin.
    pub chain_id: u32,
    /// Display ticker, e.g. "JKC".
    pub name: String,
    /// Electrs base URL serving raw CAuxPow headers (from env).
    pub electrs: String,
    /// Consensus powLimit bits for this chain (target floor check; the guest
    /// pins the authoritative one in its journal, this is the indexer's own
    /// cheap sanity gate). Taken from env, never hardcoded.
    pub pow_limit_bits: u32,
    /// Where a fresh DB begins the walk for THIS chain. Optional per chain;
    /// falls back to the global `PSOB_START_HEIGHT`.
    pub start_height: Option<u64>,
}

#[derive(Clone, Debug)]
pub struct Config {
    /// Aux chains configured in `PSOB_CHAINS`.
    pub chains: Vec<AuxChain>,
    /// SQLite database path (`PSOB_DB_PATH`).
    pub db_path: String,
    /// ccnodes.net explorer API base (`PSOB_CCNODES_BASE`).
    pub ccnodes_base: String,
    /// Bearer token for the explorer API (`CCNODES_API_KEY`).
    pub ccnodes_api_key: String,
    /// ccnodes chain slug of the parent chain to classify against
    /// (`PSOB_PARENT_CHAIN`), e.g. "litecoin".
    pub parent_chain: String,
    /// Max blocks per ingest tick (`PSOB_MAX_BATCH`).
    pub max_batch: u64,
    /// Where to begin a fresh DB's walk (`PSOB_START_HEIGHT`). REQUIRED on a
    /// cold start — the ingest loop refuses to guess (genesis-era blocks on
    /// aux chains may predate AuxPoW and would break the linkage walk).
    pub start_height: Option<u64>,
    /// Poll interval for the continuous loop (`PSOB_POLL_INTERVAL_SECS`).
    pub poll_interval: Duration,
}

impl Config {
    /// Load strict config from env. Every field is required; exceptions are
    /// only `PSOB_MAX_BATCH` / `PSOB_POLL_INTERVAL_SECS` which are bounded,
    /// non-security-relevant tuning knobs.
    pub fn from_env() -> anyhow::Result<Self> {
        let chains_raw = env_required("PSOB_CHAINS")?;
        let mut chains = Vec::new();
        for spec in chains_raw.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()) {
            // Format: NAME|CHAIN_ID|ELECTRS_URL|POWLIMIT_BITS_HEX[|START_HEIGHT]
            // `|` is safe as a field separator around URLs; `:` would collide
            // with the URL scheme. START_HEIGHT is optional per-chain (fresh
            // DBs; else the global PSOB_START_HEIGHT is used).
            let mut parts = spec.splitn(5, '|');
            let name = parts.next().filter(|s| !s.is_empty()).ok_or_else(|| {
                anyhow::anyhow!("PSOB_CHAINS entry {spec:?} missing NAME")
            })?;
            let chain_id: u32 = parts
                .next()
                .ok_or_else(|| anyhow::anyhow!("PSOB_CHAINS entry {spec:?} missing CHAIN_ID"))?
                .parse()
                .map_err(|_| anyhow::anyhow!("PSOB_CHAINS {spec:?}: bad CHAIN_ID"))?;
            let electrs = parts
                .next()
                .filter(|s| !s.is_empty())
                .ok_or_else(|| anyhow::anyhow!("PSOB_CHAINS entry {spec:?} missing ELECTRS_URL"))?
                .trim_end_matches('/')
                .to_string();
            let pow_limit_raw = parts.next().filter(|s| !s.is_empty()).ok_or_else(|| {
                anyhow::anyhow!("PSOB_CHAINS entry {spec:?} missing POWLIMIT_BITS_HEX")
            })?;
            let pow_limit_bits = u32::from_str_radix(pow_limit_raw.trim_start_matches("0x"), 16)
                .map_err(|_| anyhow::anyhow!("PSOB_CHAINS {spec:?}: bad POWLIMIT_BITS_HEX"))?;
            let start_height = parts.next().and_then(|s| s.parse().ok());
            chains.push(AuxChain {
                chain_id,
                name: name.to_string(),
                electrs,
                pow_limit_bits,
                start_height,
            });
        }
        if chains.is_empty() {
            anyhow::bail!("PSOB_CHAINS is empty — nothing to ingest");
        }

        let max_batch = std::env::var("PSOB_MAX_BATCH")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(64);
        let start_height = std::env::var("PSOB_START_HEIGHT")
            .ok()
            .and_then(|v| v.parse().ok());
        let poll_interval = std::env::var("PSOB_POLL_INTERVAL_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(30);

        let db_path = std::env::var("PSOB_DB_PATH").unwrap_or_else(|_| "psob-indexer.redb".to_string());
        let ccnodes_base = std::env::var("PSOB_CCNODES_BASE").unwrap_or_else(|_| "https://litecoinspace.org/api".to_string());
        let ccnodes_api_key = std::env::var("CCNODES_API_KEY").unwrap_or_default();
        let parent_chain = std::env::var("PSOB_PARENT_CHAIN").unwrap_or_else(|_| "litecoin".to_string());

        Ok(Self {
            chains,
            db_path,
            ccnodes_base,
            ccnodes_api_key,
            parent_chain,
            max_batch,
            start_height,
            poll_interval: Duration::from_secs(poll_interval),
        })
    }
}

fn env_required(key: &str) -> anyhow::Result<String> {
    std::env::var(key).map_err(|_| anyhow::anyhow!("required env var {key} is not set"))
}