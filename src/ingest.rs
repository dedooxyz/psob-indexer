//! Aux-chain ingestion into the light-client store.
//!
//! Each configured chain runs its OWN infinite task with exponential backoff
//! and error isolation, so one flaky Electrs endpoint can never take the
//! process down — the previous implementation polled chains sequentially and a
//! single `?` in the loop killed the whole indexer.
//!
//! Per tick the ingestor walks the aux chain's stored cursor toward the live
//! tip (bounded by `max_batch`), fetching hashes and raw header wire payloads
//! concurrently with a bounded limit, then runs the cheap consensus checks the
//! ZK guest re-runs *in-circuit*:
//!
//!   1. header is exactly 80 bytes;
//!   2. `nVersion >> 16 == chain_id`;
//!   3. `expand_target(nBits)` is valid (consensus range) and `<= powLimit`;
//!   4. `verify_auxpow_commitment` (Proof 1 + Proof 2 + anti-grind; no scrypt);
//!   5. header `prev_hash` links to the hash of the block one below (linkage by
//!      hash, never by a trust-in-the-indexer height claim).
//!
//! **No scrypt is run here** — that is the guest's expensive job and must not
//! move off-circuit. A header failing a cheap check is logged and the chain
//! scan stops at that height (a reorg or a malformed block should halt the walk
//! rather than poison the store).
//!
//! After a successful tick the ingestor optionally: (a) prunes the chain to a
//! bounded window (`PSOB_MAX_KEPT_BLOCKS`), (b) resolves newly seen parent
//! headers against the parent chain, and (c) gossips the batch tip on
//! `/psob/headers/v1` and newly found sibling groups on `/psob/siblings/v1`.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Context;
use chain_rpc::ElectrsClient;
use tokio::task::JoinHandle;

use crate::config::{AuxChain, Config};
use crate::db::{Database, StoredBlock};
use crate::metrics::Metrics;
use crate::p2p::P2pHandle;
use crate::resolve::ParentResolver;
use crate::verify::{light_verify, AuxBlock};

/// One successful (or partially halted) ingest tick.
pub struct IngestBatch {
    pub blocks: Vec<StoredBlock>,
    /// Fully resolved LTC parents that just became mainnet during this tick.
    pub new_mainnet_parents: Vec<[u8; 32]>,
}

impl IngestBatch {
    /// The tallest block of the batch (the new chain head, if any).
    pub fn head(&self) -> Option<&StoredBlock> {
        self.blocks.last()
    }
}

/// Runs the ingest loops for every configured chain. Long-lived; spawned per
/// chain so failures stay chain-scoped.
pub struct Ingestor {
    config: Config,
    db: Arc<Database>,
    resolver: ParentResolver,
    metrics: Arc<Metrics>,
    p2p: Option<P2pHandle>,
    /// Parents already gossiped on /psob/siblings/v1. Shared by ALL chain tasks
    /// so a parent shared by several chains is announced exactly once; the
    /// first classifying task wins (memory-only: a restart re-announces, which
    /// gossip-level dedup absorbs).
    announced: Arc<std::sync::Mutex<HashSet<[u8; 32]>>>,
}

impl Ingestor {
    pub fn new(config: Config, db: Arc<Database>) -> anyhow::Result<Self> {
        Self::with_services(config, db, Metrics::new(), None)
    }

    pub fn with_services(
        config: Config,
        db: Arc<Database>,
        metrics: Arc<Metrics>,
        p2p: Option<P2pHandle>,
    ) -> anyhow::Result<Self> {
        let resolver = ParentResolver::new(
            &config.resolver.base,
            &config.resolver.api_key,
            &config.resolver.chain_slug,
        )?;
        Ok(Self {
            config,
            db,
            resolver,
            metrics,
            p2p,
            announced: std::sync::Arc::new(std::sync::Mutex::new(HashSet::new())),
        })
    }

    /// Spawn one long-running task per chain. Returns handles so the caller can
    /// abort them all on shutdown.
    pub fn spawn_all(&self) -> Vec<JoinHandle<()>> {
        self.config
            .chains
            .iter()
            .cloned()
            .map(|chain| {
                let db = Arc::clone(&self.db);
                let resolver = self.resolver.clone();
                let config = self.config.clone();
                let metrics = Arc::clone(&self.metrics);
                let p2p = self.p2p.clone();
                let announced = Arc::clone(&self.announced);
                tokio::spawn(async move {
                    chain_loop(config, db, resolver, metrics, p2p, announced, chain).await;
                })
            })
            .collect()
    }
}

fn display_hash(le: &[u8; 32]) -> String {
    let mut b = *le;
    b.reverse();
    hex::encode(b)
}

fn parent_hash_of(block: &StoredBlock) -> [u8; 32] {
    common::sha256d(
        &block
            .header
            .aux
            .as_ref()
            .expect("stored blocks always carry auxpow")
            .parent_header,
    )
}

/// One chain's infinite loop: tick → poll → backoff on error → retry.
async fn chain_loop(
    config: Config,
    db: Arc<Database>,
    resolver: ParentResolver,
    metrics: Arc<Metrics>,
    p2p: Option<P2pHandle>,
    announced: Arc<std::sync::Mutex<HashSet<[u8; 32]>>>,
    chain: AuxChain,
) {
    tracing::info!(
        chain = %chain.name,
        chain_id = chain.chain_id,
        url = %chain.electrs,
        "ingest loop started"
    );
    let client = ElectrsClient::with_policy(
        &chain.electrs,
        chain_rpc::HttpPolicy {
            timeout: config.http.timeout,
            max_retries: config.retry.max_retries,
            base_backoff: config.retry.base_backoff,
            max_backoff: config.retry.max_backoff,
            min_request_interval: config.retry.min_request_interval,
        },
    );

    let mut consecutive_failures = 0u32;

    loop {
        let chain_label = chain.chain_id.to_string();
        metrics
            .ingest_ticks
            .with_label_values(&[&chain_label])
            .inc();
        match ingest_chain(
            &config,
            &chain,
            &client,
            &db,
            &resolver,
            &metrics,
            config.max_batch,
        )
        .await
        {
            Ok(batch) => {
                consecutive_failures = 0;
                let ingested = batch.blocks.len();
                if ingested > 0 {
                    metrics
                        .ingest_blocks
                        .with_label_values(&[&chain_label])
                        .inc_by(ingested as u64);
                    tracing::info!(chain = %chain.name, ingested, "ingest batch");
                    announce_batch_tip(&db, &p2p, &chain, &batch).await;
                }
                for parent in &batch.new_mainnet_parents {
                    announce_sibling_group(&db, &p2p, &announced, parent).await;
                }
            }
            Err(e) => {
                consecutive_failures += 1;
                metrics
                    .ingest_errors
                    .with_label_values(&[&chain_label])
                    .inc();
                let delay = backoff_delay(&config, consecutive_failures);
                tracing::warn!(
                    chain = %chain.name,
                    failures = consecutive_failures,
                    retry_in_ms = delay.as_millis(),
                    err = %e,
                    "ingest tick failed; backing off",
                );
                tokio::time::sleep(delay).await;
                continue;
            }
        }
        tokio::time::sleep(config.poll_interval).await;
    }
}

/// Gossip the tallest block of the batch on `/psob/headers/v1`.
async fn announce_batch_tip(
    db: &Database,
    p2p: &Option<P2pHandle>,
    chain: &AuxChain,
    batch: &IngestBatch,
) {
    let (Some(head), Some(handle)) = (batch.head(), p2p) else {
        return;
    };
    let parent = parent_hash_of(head);
    let ltc_height = db
        .get_parent(&parent)
        .ok()
        .flatten()
        .and_then(|p| p.ltc_height);
    handle
        .announce_header(
            chain.chain_id,
            head.height,
            display_hash(&head.hash_le),
            display_hash(&parent),
            ltc_height,
            head.wire_hex.clone(),
        )
        .await;
}

/// Gossip a newly discovered sibling group on `/psob/siblings/v1`.
async fn announce_sibling_group(
    db: &Database,
    p2p: &Option<P2pHandle>,
    announced: &Arc<std::sync::Mutex<HashSet<[u8; 32]>>>,
    parent: &[u8; 32],
) {
    let Some(handle) = p2p else { return };
    // One announcement per parent, across ALL chain tasks.
    let first_time = {
        let mut set = announced.lock().expect("announced mutex poisoned");
        set.insert(*parent)
    };
    if !first_time {
        tracing::debug!(parent = %display_hash(parent), "sibling group already announced");
        return;
    }
    // Only advertise provable groups: mainnet parent, >= 2 distinct chains.
    let Ok(Some(parent_info)) = db.get_parent(parent) else {
        return;
    };
    let Some(ltc_height) = parent_info.ltc_height else {
        return;
    };
    let Ok(siblings) = db.siblings_for_parent(parent) else {
        return;
    };
    let mut chains: std::collections::BTreeMap<u32, u64> = Default::default();
    for s in &siblings {
        chains
            .entry(s.chain_id)
            .and_modify(|h| *h = (*h).min(s.height))
            .or_insert(s.height);
    }
    if chains.len() < 2 {
        return;
    }
    let legs: Vec<(u32, u64, String)> = siblings
        .iter()
        .filter_map(|s| {
            chains
                .get(&s.chain_id)
                .filter(|h| **h == s.height)
                .map(|_| (s.chain_id, s.height, display_hash(&s.hash_le)))
        })
        .collect();
    handle
        .announce_sibling(display_hash(parent), ltc_height, legs)
        .await;
}

/// Exponential backoff with full jitter, capped (shared shape with the RPC client).
fn backoff_delay(config: &Config, failures: u32) -> Duration {
    let exp = config
        .retry
        .base_backoff
        .saturating_mul(2u32.saturating_pow(failures.min(12)));
    let capped = exp.min(config.retry.max_backoff);
    if capped.is_zero() {
        Duration::from_millis(250)
    } else {
        Duration::from_millis(fastrand::u64(0..capped.as_millis() as u64 + 1))
    }
}

/// Ingest one batch for one chain: `[cursor+1, min(tip, cursor+max_batch)]`.
async fn ingest_chain(
    config: &Config,
    chain: &AuxChain,
    electrs: &ElectrsClient,
    db: &Database,
    resolver: &ParentResolver,
    metrics: &Metrics,
    max_batch: u64,
) -> anyhow::Result<IngestBatch> {
    db.upsert_chain(chain.chain_id, &chain.name, &chain.electrs)?;

    let tip_height = electrs.tip_height().await.context("tip_height")?;
    let cursor = db.cursor_height(chain.chain_id)?;

    // A fresh DB must be told where the walk starts — refusing to guess from
    // block 0 (genesis-era aux blocks predate AuxPoW and would break the walk).
    // Per-chain start wins; else the global PSOB_START_HEIGHT.
    let cursor = match cursor {
        Some(c) => c,
        None => match chain.start_height.or(config.start_height) {
            Some(h) => h,
            None => anyhow::bail!(
                "fresh DB: PSOB_START_HEIGHT must be set (or per-chain in PSOB_CHAINS) for chain {} ({})",
                chain.name,
                chain.chain_id
            ),
        },
    };

    if cursor > tip_height {
        tracing::warn!(
            chain = %chain.name,
            cursor,
            tip_height,
            "DB cursor is above the node tip (node pruned or reorged?)"
        );
        return Ok(IngestBatch {
            blocks: vec![],
            new_mainnet_parents: vec![],
        });
    }

    let start = cursor.saturating_add(1);
    let end = (cursor + max_batch).min(tip_height);
    if start > end {
        return Ok(IngestBatch {
            blocks: vec![],
            new_mainnet_parents: vec![],
        }); // up to date
    }
    let window: Vec<u64> = (start..=end).collect();

    // Fetch locator hashes concurrently (bounded). By-height is ONLY a fetch
    // locator; linkage is verified against the stored previous block hash.
    let hashes: Vec<String> = {
        let list = join_all(window.iter().map(|h| {
            let c = electrs.clone();
            async move { (*h, c.block_hash_at(*h).await) }
        }))
        .await;
        let mut by_h = std::collections::HashMap::new();
        for (h, res) in list {
            by_h.insert(h, res.with_context(|| format!("block_hash_at #{h}"))?);
        }
        window
            .iter()
            .map(|h| by_h.remove(h).expect("every height fetched"))
            .collect()
    };

    // Fetch wire payloads concurrently, collecting by height so verification can
    // run STRICTLY in height order (the linkage check depends on it).
    let wires: std::collections::HashMap<u64, Vec<u8>> = {
        let list = join_all(window.iter().zip(hashes.iter()).map(|(h, hx)| {
            let c = electrs.clone();
            let hx = hx.clone();
            let h = *h;
            async move { (h, c.header_wire(&hx).await) }
        }))
        .await;
        let mut by_h = std::collections::HashMap::new();
        for (h, res) in list {
            let wire = res.with_context(|| format!("header fetch #{h}"))?;
            by_h.insert(h, wire);
        }
        by_h
    };

    // Sequential, height-ordered verification + linkage gate.
    let mut prev_hash: Option<[u8; 32]> = match cursor {
        0 => None,
        c => db.block_at(chain.chain_id, c)?.map(|b| b.hash_le),
    };

    let mut pending: Vec<StoredBlock> = Vec::new();

    for height in window {
        let Some(wire) = wires.get(&height) else {
            continue;
        };
        let aux_block = match AuxBlock::from_wire(wire.clone()) {
            Ok(b) => b,
            Err(e) => {
                tracing::warn!(chain = %chain.name, height, err = %e, "auxpow parse failed at height; halting walk");
                break;
            }
        };

        // Cheap consensus checks (no scrypt) — full PSob gate.
        let id = match light_verify(
            &aux_block.base,
            &aux_block.aux,
            chain.chain_id,
            chain.pow_limit_bits,
        ) {
            Ok(id) => id,
            Err(e) => {
                tracing::warn!(
                    chain = %chain.name,
                    height,
                    err = %e,
                    "light verify failed at height; halting walk"
                );
                break;
            }
        };

        // Linkage gate: this header's prev_hash must equal the previous (lower)
        // block. Guards against reorgs mid-walk and against a fork-hopping
        // indexer silently merging two chains.
        if let Some(p) = prev_hash {
            if aux_block.base[4..36] != p {
                tracing::warn!(
                    chain = %chain.name,
                    height,
                    "prev_hash linkage broken at {height} (reorg?) — rolling back and halting"
                );
                db.rollback_from(chain.chain_id, height)?;
                break;
            }
        }

        prev_hash = Some(id);
        pending.push(StoredBlock {
            hash_le: id,
            chain_id: chain.chain_id,
            height,
            header: aux_block.header(),
            wire_hex: hex::encode(&aux_block.wire),
        });
    }

    if !pending.is_empty() {
        let rows: Vec<(u32, u64, StoredBlock)> = pending
            .iter()
            .map(|b| (b.chain_id, b.height, b.clone()))
            .collect();
        db.insert_blocks(&rows)?;
        let last = pending
            .last()
            .map(|b| b.height)
            .unwrap_or(start.saturating_sub(1));
        db.set_cursor_height(chain.chain_id, last)?;

        // Bounded-window policy: drop history older than max_kept_blocks so a
        // long-running node stays small. Runs when the window is exceeded;
        // cheap because it's a range remove that only activates on drift.
        if let Some(max_kept) = config.max_kept_blocks {
            let below = last.saturating_sub(max_kept).saturating_add(1);
            if below > 1 {
                let stats = db.stats()?;
                if let Some(min) = stats
                    .chains
                    .iter()
                    .find(|c| c.chain_id == chain.chain_id)
                    .and_then(|c| c.min_height)
                {
                    if min < below {
                        let removed = db.prune_before(chain.chain_id, below)?;
                        metrics
                            .prune_blocks
                            .with_label_values(&[&chain.chain_id.to_string()])
                            .inc_by(removed);
                        tracing::info!(
                            chain = %chain.name,
                            window = max_kept,
                            pruned = removed,
                            "pruned old blocks to bounded window"
                        );
                    }
                }
            }
        }
    }

    // Classify any previously unseen parents against the parent chain (mainnet).
    let new_mainnet = classify_pending_parents(db, resolver, metrics, config).await?;

    Ok(IngestBatch {
        blocks: pending,
        new_mainnet_parents: new_mainnet,
    })
}

/// Resolve unclassified parents concurrently (bounded). Classifications are
/// best-effort — a resolver that is down is retried next tick, never fatal.
/// Returns the parents that JUST became confirmed mainnet (for gossip).
async fn classify_pending_parents(
    db: &Database,
    resolver: &ParentResolver,
    metrics: &Metrics,
    _config: &Config,
) -> anyhow::Result<Vec<[u8; 32]>> {
    let unclassified = db.unclassified_parents();
    if unclassified.is_empty() {
        return Ok(Vec::new());
    }
    let results = join_all(unclassified.into_iter().map(|parent| {
        let resolver = resolver.clone();
        async move { (parent, resolver.resolve(&parent).await) }
    }))
    .await;

    let mut new_mainnet = Vec::new();
    for (parent, resolved) in results {
        let ltc_height = resolved.ok().flatten();
        db.classify_parent(&parent, ltc_height)?;
        let parent_display = display_hash(&parent);
        match ltc_height {
            Some(h) => {
                metrics
                    .family_resolves
                    .with_label_values(&["mainnet"])
                    .inc();
                tracing::info!(parent = %parent_display, ltc_height = h, "parent is mainnet block");
                new_mainnet.push(parent);
            }
            None => {
                metrics.family_resolves.with_label_values(&["trial"]).inc();
                tracing::debug!(parent = %parent_display, "parent not on mainnet (trial)");
            }
        }
    }
    Ok(new_mainnet)
}

use futures::future::join_all;

/// Continuous ingest for all chains from a shared DB (kept for CLI/tests).
pub async fn run(config: Config, db: Arc<Database>) -> anyhow::Result<()> {
    let ingestor = Ingestor::new(config, db)?;
    let handles = ingestor.spawn_all();
    for h in handles {
        let _ = h.await;
    }
    Ok(())
}
