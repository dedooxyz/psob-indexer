//! Runtime configuration — env-driven, with an optional TOML config file.
//!
//! Load order (later wins on conflicts):
//!
//! 1. `.env` in the working directory is loaded first if present (via dotenvy).
//! 2. An optional TOML file is parsed: `$PSOB_CONFIG`, or `./psob-indexer.toml`
//!    if that file exists (see `config.example.toml`).
//! 3. Environment variables override every file value (e.g. `PSOB_CHAINS` beats
//!    `[chains]` in the file).
//!
//! Nothing chain-specific is ever hardcoded: a missing or malformed value fails
//! loudly at startup instead of silently polling the wrong chain.

use std::time::Duration;

use serde::Deserialize;

/// One aux chain we can ingest. Registry comes from `PSOB_CHAINS` or `[chains]`.
#[derive(Clone, Debug)]
pub struct AuxChain {
    /// `nVersion >> 16` chain id, e.g. 8224 for Junkcoin.
    pub chain_id: u32,
    /// Display ticker, e.g. "JKC".
    pub name: String,
    /// Electrs base URL serving raw CAuxPow headers.
    pub electrs: String,
    /// Consensus powLimit bits for this chain (compact target floor). The ZK
    /// guest pins the authoritative bound in its journal; this is the indexer's
    /// cheap sanity gate.
    pub pow_limit_bits: u32,
    /// Where a fresh DB begins the walk for THIS chain. Falls back to the
    /// global `PSOB_START_HEIGHT`.
    pub start_height: Option<u64>,
}

/// Parent-chain resolver config (classifies embedded parents as mainnet/trial).
#[derive(Clone, Debug)]
pub struct ResolverConfig {
    /// Explorer API base, e.g. `https://litecoinspace.org/api`.
    pub base: String,
    /// Bearer token for the explorer API (optional).
    pub api_key: String,
    /// Chain slug of the parent chain, e.g. "litecoin".
    pub chain_slug: String,
    /// Optional secondary explorer used ONLY on transport failure of the
    /// primary (`PSOB_PARENT_ELECTRS_FALLBACK`). Never hardcoded.
    pub fallback_base: Option<String>,
}

/// HTTP retry/backoff policy applied to every Electrs / resolver request.
#[derive(Clone, Debug)]
pub struct RetryConfig {
    /// Max retries per request (excluding the initial attempt).
    pub max_retries: u32,
    /// Initial backoff, doubled per attempt (with jitter).
    pub base_backoff: Duration,
    /// Backoff cap.
    pub max_backoff: Duration,
    /// Minimum gap between requests to a single host (rate limit).
    pub min_request_interval: Duration,
}

#[derive(Clone, Debug)]
pub struct HttpConfig {
    pub timeout: Duration,
    /// Max concurrent header fetches per chain during back-fill.
    pub concurrency: usize,
}

#[derive(Clone, Debug)]
pub struct Config {
    pub chains: Vec<AuxChain>,
    /// Redb database path.
    pub db_path: String,
    pub resolver: ResolverConfig,
    /// Max blocks per ingest batch tick.
    pub max_batch: u64,
    /// Global start height for fresh DBs (per-chain overrides win).
    pub start_height: Option<u64>,
    /// Poll interval for the continuous loop.
    pub poll_interval: Duration,
    /// Keep only the most recent N blocks per chain; `None` (default) = keep all.
    /// Pruning keeps the DB bounded on long-running nodes; old epoch windows
    /// simply return fewer rows.
    pub max_kept_blocks: Option<u64>,
    pub retry: RetryConfig,
    pub http: HttpConfig,
    /// Allowed CORS origins (`PSOB_CORS_ORIGINS`, comma-separated; `*` = all).
    pub cors_origins: Vec<String>,
    /// Bind address of the REST API (default 0.0.0.0:8080).
    pub bind_addr: String,
    /// Libp2p parameters.
    pub p2p: crate::p2p::P2pConfig,
}

/// TOML file shape — mirrors the env schema 1:1, all fields optional.
#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct ConfigFile {
    chains: Vec<ChainEntry>,
    db_path: Option<String>,
    resolver: ResolverFile,
    max_batch: Option<u64>,
    start_height: Option<u64>,
    poll_interval_secs: Option<u64>,
    max_kept_blocks: Option<u64>,
    retry: RetryFile,
    http: HttpFile,
    cors_origins: Option<String>,
    bind_addr: Option<String>,
    p2p: P2pFile,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct ChainEntry {
    name: String,
    chain_id: u32,
    electrs_url: String,
    /// Pow limit as hex (with or without `0x` prefix).
    pow_limit_bits: String,
    start_height: Option<u64>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct ResolverFile {
    base: Option<String>,
    api_key: Option<String>,
    parent_chain: Option<String>,
    fallback_base: Option<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct RetryFile {
    max_retries: Option<u32>,
    base_backoff_ms: Option<u64>,
    max_backoff_ms: Option<u64>,
    min_request_interval_ms: Option<u64>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct HttpFile {
    timeout_secs: Option<u64>,
    concurrency: Option<usize>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default)]
struct P2pFile {
    port: Option<u16>,
    bind: Option<String>,
    bootstrap_nodes: Option<String>,
    disable_mdns: Option<bool>,
}

/// Known parent-chain slugs for the resolver.
///
/// The parent is identified by a *free-text* slug (`PSOB_PARENT_CHAIN`), not a
/// numeric id, and is interpolated straight into the explorer URL
/// (`{base}/{slug}/block/{hash}`). A typo'd or wrong-cased slug therefore
/// builds a wrong URL and silently mis-classifies parents as "trial" — breaking
/// epoch anchors with no error. We validate it loudly at startup instead of
/// failing quietly.
pub const KNOWN_PARENT_CHAINS: &[&str] = &["litecoin", "bitcoin"];

/// Normalize + validate the parent-chain slug. Lowercases/trims and rejects
/// anything not in [`KNOWN_PARENT_CHAINS`], so a spelling/case mistake fails
/// fast instead of poisoning parent classification.
fn normalize_parent_chain(slug: String) -> anyhow::Result<String> {
    let norm = slug.trim().to_lowercase();
    if !KNOWN_PARENT_CHAINS.contains(&norm.as_str()) {
        anyhow::bail!(
            "unknown PSOB_PARENT_CHAIN {slug:?}; must be one of: {}",
            KNOWN_PARENT_CHAINS.join(", ")
        );
    }
    Ok(norm)
}

/// Display-only ticker. Trims; an empty name is derived from the (authoritative)
/// AuxPoW `chain_id`, reinforcing that the numeric id is the canonical key — not
/// the human label — for every lookup.
fn normalize_chain_name(name: &str, chain_id: u32) -> String {
    let n = name.trim().to_string();
    if n.is_empty() {
        format!("chain{chain_id}")
    } else {
        n
    }
}

impl Config {
    /// Load config: `.env` → optional TOML file → environment overrides.
    pub fn load() -> anyhow::Result<Self> {
        let _ = dotenvy::dotenv(); // best-effort; missing `.env` is not an error
        let file = load_file()?;

        let chains = match env_var("PSOB_CHAINS")? {
            Some(raw) => parse_chain_specs(&raw)?,
            None => match file.as_ref() {
                Some(f) => parse_file_chains(&f.chains)?,
                None => {
                    anyhow::bail!("PSOB_CHAINS is not set and no config file provides [chains]")
                }
            },
        };
        if chains.is_empty() {
            anyhow::bail!("PSOB_CHAINS is empty — nothing to ingest");
        }

        let db_path = env_var("PSOB_DB_PATH")?
            .or_else(|| file.as_ref().and_then(|f| f.db_path.clone()))
            .unwrap_or_else(|| "psob-indexer.redb".to_string());

        // Generic parent-explorer envs (PSOB_PARENT_ELECTRS/*). The legacy
        // CCNODES-named aliases are kept as a deprecated fallback.
        let resolver_base = env_first(&["PSOB_PARENT_ELECTRS", "PSOB_CCNODES_BASE"])?
            .or_else(|| file.as_ref().and_then(|f| f.resolver.base.clone()))
            .unwrap_or_else(|| "https://litecoinspace.org/api".to_string());
        let resolver_key = env_first(&["PSOB_PARENT_API_KEY", "CCNODES_API_KEY"])?
            .or_else(|| file.as_ref().and_then(|f| f.resolver.api_key.clone()))
            .unwrap_or_default();
        let parent_chain = env_var("PSOB_PARENT_CHAIN")?
            .or_else(|| file.as_ref().and_then(|f| f.resolver.parent_chain.clone()))
            .unwrap_or_else(|| "litecoin".to_string());
        let parent_chain = normalize_parent_chain(parent_chain)?;
        let fallback_base = env_first(&["PSOB_PARENT_ELECTRS_FALLBACK", "PSOB_CCNODES_FALLBACK_BASE"])?
            .or_else(|| file.as_ref().and_then(|f| f.resolver.fallback_base.clone()))
            .filter(|b| !b.is_empty());

        let max_batch = env_num("PSOB_MAX_BATCH")?
            .or_else(|| file.as_ref().and_then(|f| f.max_batch))
            .unwrap_or(64);
        let start_height =
            env_num("PSOB_START_HEIGHT")?.or_else(|| file.as_ref().and_then(|f| f.start_height));
        let poll_interval = env_num("PSOB_POLL_INTERVAL_SECS")?
            .or_else(|| file.as_ref().and_then(|f| f.poll_interval_secs))
            .unwrap_or(30);
        let max_kept_blocks = env_num("PSOB_MAX_KEPT_BLOCKS")?
            .or_else(|| file.as_ref().and_then(|f| f.max_kept_blocks))
            .filter(|v| *v > 0);

        let max_retries = env_num("PSOB_MAX_RETRIES")?
            .or_else(|| file.as_ref().and_then(|f| f.retry.max_retries))
            .unwrap_or(5);
        let base_backoff = env_num("PSOB_RETRY_BASE_MS")?
            .or_else(|| file.as_ref().and_then(|f| f.retry.base_backoff_ms))
            .unwrap_or(500);
        let max_backoff = env_num("PSOB_RETRY_MAX_MS")?
            .or_else(|| file.as_ref().and_then(|f| f.retry.max_backoff_ms))
            .unwrap_or(30_000);
        let min_interval = env_num("PSOB_RATE_LIMIT_MS")?
            .or_else(|| file.as_ref().and_then(|f| f.retry.min_request_interval_ms))
            .unwrap_or(0);

        let http_timeout = env_num("PSOB_HTTP_TIMEOUT_SECS")?
            .or_else(|| file.as_ref().and_then(|f| f.http.timeout_secs))
            .unwrap_or(30);
        let concurrency = env_num("PSOB_HTTP_CONCURRENCY")?
            .or_else(|| file.as_ref().and_then(|f| f.http.concurrency))
            .unwrap_or(8);

        let cors = env_var("PSOB_CORS_ORIGINS")?
            .or_else(|| file.as_ref().and_then(|f| f.cors_origins.clone()))
            .unwrap_or_else(|| "*".to_string())
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        let bind_addr = env_var("PSOB_BIND_ADDR")?
            .or_else(|| file.as_ref().and_then(|f| f.bind_addr.clone()))
            .unwrap_or_else(|| {
                let port = env_var("PSOB_PORT")
                    .ok()
                    .flatten()
                    .unwrap_or_else(|| "8080".to_string());
                format!("0.0.0.0:{port}")
            });

        let p2p = crate::p2p::P2pConfig::from_parts(
            env_num("PSOB_P2P_PORT")?.or_else(|| file.as_ref().and_then(|f| f.p2p.port)),
            env_var("PSOB_P2P_BIND")?.or_else(|| file.as_ref().and_then(|f| f.p2p.bind.clone())),
            env_var("PSOB_BOOTSTRAP_NODES")?
                .or_else(|| file.as_ref().and_then(|f| f.p2p.bootstrap_nodes.clone())),
            env_var("PSOB_DISABLE_MDNS")?.or_else(|| {
                file.as_ref()
                    .and_then(|f| f.p2p.disable_mdns.map(|b| b.to_string()))
            }),
        );

        Ok(Self {
            chains,
            db_path,
            resolver: ResolverConfig {
                base: resolver_base,
                api_key: resolver_key,
                chain_slug: parent_chain,
                fallback_base,
            },
            max_batch: max_batch.max(1),
            start_height,
            poll_interval: Duration::from_secs(poll_interval.max(1)),
            max_kept_blocks,
            retry: RetryConfig {
                max_retries,
                base_backoff: Duration::from_millis(base_backoff),
                max_backoff: Duration::from_millis(max_backoff.max(base_backoff)),
                min_request_interval: Duration::from_millis(min_interval),
            },
            http: HttpConfig {
                timeout: Duration::from_secs(http_timeout),
                concurrency: concurrency.max(1),
            },
            cors_origins: cors,
            bind_addr,
            p2p,
        })
    }
}

/// Parse the canonical env-var chain spec:
/// `NAME|CHAIN_ID|ELECTRS_URL|POWLIMIT_BITS_HEX[|START_HEIGHT]` (comma-separated).
fn parse_chain_specs(raw: &str) -> anyhow::Result<Vec<AuxChain>> {
    let mut chains = Vec::new();
    for spec in raw.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()) {
        // `|` is safe as a field separator around URLs; `:` would collide with
        // the URL scheme. START_HEIGHT is optional per-chain; fall back to the
        // global PSOB_START_HEIGHT for fresh DBs.
        let mut parts = spec.splitn(5, '|');
        let name = parts
            .next()
            .filter(|s| !s.is_empty())
            .ok_or_else(|| anyhow::anyhow!("PSOB_CHAINS entry {spec:?} missing NAME"))?;
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
            name: normalize_chain_name(name, chain_id),
            electrs,
            pow_limit_bits,
            start_height,
        });
    }
    check_unique_chain_ids(&chains)?;
    Ok(chains)
}

/// Two chains sharing a `chain_id` would spawn two ingest tasks writing to the
/// same `(chain_id, height)` Redb table and clobber each other. Reject that at
/// parse time so the misconfiguration fails loudly, not silently.
fn check_unique_chain_ids(chains: &[AuxChain]) -> anyhow::Result<()> {
    let mut seen = std::collections::HashSet::new();
    for c in chains {
        if !seen.insert(c.chain_id) {
            anyhow::bail!(
                "duplicate chain_id {id} in PSOB_CHAINS / [chains] — each chain needs a unique AuxPoW id",
                id = c.chain_id
            );
        }
    }
    Ok(())
}

fn parse_file_chains(entries: &[ChainEntry]) -> anyhow::Result<Vec<AuxChain>> {
    let mut chains = Vec::new();
    for e in entries {
        let pow_limit_bits = u32::from_str_radix(e.pow_limit_bits.trim_start_matches("0x"), 16)
            .map_err(|_| {
                anyhow::anyhow!(
                    "config file: chain {} has bad pow_limit_bits {:?}",
                    e.name,
                    e.pow_limit_bits
                )
            })?;
        chains.push(AuxChain {
            chain_id: e.chain_id,
            name: normalize_chain_name(&e.name, e.chain_id),
            electrs: e.electrs_url.trim_end_matches('/').to_string(),
            pow_limit_bits,
            start_height: e.start_height,
        });
    }
    check_unique_chain_ids(&chains)?;
    Ok(chains)
}

fn load_file() -> anyhow::Result<Option<ConfigFile>> {
    let path = match std::env::var("PSOB_CONFIG") {
        Ok(p) => Some(std::path::PathBuf::from(p)),
        Err(_) => {
            let default = std::path::PathBuf::from("psob-indexer.toml");
            if default.exists() {
                Some(default)
            } else {
                None
            }
        }
    };
    match path {
        Some(p) if p.exists() => {
            let raw = std::fs::read_to_string(&p)
                .map_err(|e| anyhow::anyhow!("cannot read config file {}: {e}", p.display()))?;
            let cfg: ConfigFile = toml::from_str(&raw)
                .map_err(|e| anyhow::anyhow!("cannot parse config file {}: {e}", p.display()))?;
            Ok(Some(cfg))
        }
        _ => Ok(None),
    }
}

/// Env value if set AND non-empty.
fn env_var(key: &str) -> anyhow::Result<Option<String>> {
    match std::env::var(key) {
        Ok(v) if !v.is_empty() => Ok(Some(v)),
        Ok(_) => Ok(None),
        Err(_) => Ok(None),
    }
}

/// First set value among the given env names (deprecated aliases allowed).
fn env_first(names: &[&str]) -> anyhow::Result<Option<String>> {
    for n in names {
        if let Ok(Some(v)) = env_var(n) {
            return Ok(Some(v));
        }
    }
    Ok(None)
}

/// Parse a numeric env value; malformed or empty values are treated as unset
/// (a broken tuning knob must not brick startup).
fn env_num<T: std::str::FromStr>(key: &str) -> anyhow::Result<Option<T>> {
    Ok(env_var(key)?.and_then(|v| v.parse::<T>().ok()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_chain_spec_with_optional_start_height() {
        let chains = parse_chain_specs(
            "JKC|8224|https://junk-api.s3na.xyz|0x1e0fffff|1095300,DINGO|50|https://dingo-api.s3na.xyz|0x1e0fffff",
        )
        .expect("parses");
        assert_eq!(chains.len(), 2);
        assert_eq!(chains[0].chain_id, 8224);
        assert_eq!(chains[0].start_height, Some(1095300));
        assert_eq!(chains[1].start_height, None);
        assert_eq!(chains[0].pow_limit_bits, 0x1e0f_ffff);
    }

    #[test]
    fn rejects_malformed_entries() {
        assert!(parse_chain_specs("JKC|not_a_number|url|0x1e0fffff").is_err());
        assert!(parse_chain_specs("JKC|8224||0x1e0fffff").is_err());
        assert!(parse_chain_specs("").unwrap().is_empty());
    }

    #[test]
    fn resolver_fallback_is_optional_and_parseable() {
        // env-based (values are set by the test harness): simulate via the
        // parse helpers when the env is absent — the file path is what matters.
        #[derive(Deserialize)]
        struct Min {
            resolver: ResolverFile,
        }
        let m: Min = toml::from_str(
            r#"
            [resolver]
            fallback_base = "https://fallback.example/api"
            "#,
        )
        .expect("toml");
        assert_eq!(
            m.resolver.fallback_base.as_deref(),
            Some("https://fallback.example/api")
        );

        let m2: Min = toml::from_str("[resolver]").expect("defaults");
        assert!(m2.resolver.fallback_base.is_none());
    }

    #[test]
    fn parses_file_chains() {
        #[derive(Deserialize)]
        struct Minimal {
            chains: Vec<ChainEntry>,
        }
        let m: Minimal = toml::from_str(
            r#"
            [[chains]]
            name = "JKC"
            chain_id = 8224
            electrs_url = "https://junk-api.s3na.xyz"
            pow_limit_bits = "0x1e0fffff"
            start_height = 1095300
            "#,
        )
        .expect("toml");
        let chains = parse_file_chains(&m.chains).expect("chains");
        assert_eq!(chains.len(), 1);
        assert_eq!(chains[0].chain_id, 8224);
        assert_eq!(chains[0].start_height, Some(1095300));
    }

    #[test]
    fn parent_chain_slug_is_normalized_and_validated() {
        // Wrong case / whitespace is accepted and normalized.
        assert_eq!(
            normalize_parent_chain("  Litecoin ".into()).unwrap(),
            "litecoin"
        );
        // Unknown slug fails loudly instead of silently mis-resolving.
        assert!(normalize_parent_chain("ltccoin".into()).is_err());
        assert!(normalize_parent_chain("BITCOIN".into()).is_ok());
    }

    #[test]
    fn chain_name_is_trimmed_and_derived_when_empty() {
        assert_eq!(normalize_chain_name("  JKC ", 8224), "JKC");
        // Empty name falls back to the numeric chain id (the canonical key).
        assert_eq!(normalize_chain_name("", 8224), "chain8224");
    }

    #[test]
    fn rejects_duplicate_chain_ids() {
        let specs = "JKC|8224|https://a|0x1e0fffff,DINGO|8224|https://b|0x1e0fffff";
        let err = parse_chain_specs(specs).unwrap_err();
        assert!(err.to_string().contains("duplicate chain_id"));
    }
}
