//! Aux chain ingestion into the light-client store.
//!
//! The ingestor walks the aux chain tip down to its stored cursor, fetching
//! each raw `/block/:hash/header` (80 bytes + CAuxPow) and running the cheap
//! consensus checks the ZK guest will re-run *in-circuit*:
//!
//!   1. header is exactly 80 bytes;
//!   2. `nVersion >> 16 == chain_id`;
//!   3. `expand_target(nBits)` is valid (consensus range) and `≤ powLimit`;
//!   4. `verify_auxpow_commitment` (sibling-TX + sibling-block + anti-grind);
//!   5. header `prev_hash` links to the hash of the block one above (prev by
//!      linkage, never by a trust-in-the-indexer height claim).
//!
//! **No scrypt is run here** — that is the guest's expensive job and must not
//! move off-circuit. A header failing a cheap check is logged and the chain
//! scan stops at that height (a reorg or a malformed block should halt the
//! walk rather than poison the store).

use anyhow::Context;

use chain_rpc::ElectrsClient;
use common::{target_leq, AuxPow, BlockHeader};
use tokio::time::sleep;

use crate::config::AuxChain;
use crate::db::{Database, StoredBlock};
use crate::resolve::ParentResolver;

fn sha256d(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut out = [0u8; 32];
    out.copy_from_slice(&Sha256::digest(Sha256::digest(data)));
    out
}

/// Validate the parts of a header the light client can check without scrypt.
/// Returns the aux-block hash (sha256d of the 80-byte header).
fn light_verify(base: &[u8], aux: &AuxPow, chain_id: u32, pow_limit_bits: u32) -> anyhow::Result<[u8; 32]> {
    if base.len() != 80 {
        anyhow::bail!("light_verify: header not 80 bytes");
    }
    let version = u32::from_le_bytes([base[0], base[1], base[2], base[3]]);
    if version >> 16 != chain_id {
        anyhow::bail!("chain id {} != expected {}", version >> 16, chain_id);
    }
    let bits = u32::from_le_bytes([base[72], base[73], base[74], base[75]]);
    let target = common::expand_target(bits)
        .ok_or_else(|| anyhow::anyhow!("invalid nBits {bits:#010x}"))?;
    let pow_limit = common::expand_target(pow_limit_bits)
        .ok_or_else(|| anyhow::anyhow!("invalid powLimitBits"))?;
    if !target_leq(&target, &pow_limit) {
        anyhow::bail!("target easier than powLimit");
    }
    if aux.parent_header.len() != 80 {
        anyhow::bail!("auxpow parent header not 80 bytes");
    }
    let id = sha256d(base);
    if !common::verify_auxpow_commitment(&id, aux, chain_id) {
        anyhow::bail!("auxpow commitment invalid");
    }
    Ok(id)
}

/// Ingest one aux chain from its Electrs endpoint, walking from the live tip
/// down (reorg-safe: only back-fill a contiguous window whose linkage checks).
pub async fn ingest_chain(
    config: &crate::Config,
    chain: &AuxChain,
    electrs: &ElectrsClient,
    db: &Database,
    resolver: &ParentResolver,
    max_batch: u64,
) -> anyhow::Result<u64> {
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
                chain.chain_id,
            ),
        },
    };

    // Validate the configured start is behind the tip before walking.
    if cursor > tip_height {
        anyhow::bail!(
            "PSOB cursor height {} for {} is above tip {}",
            cursor,
            chain.name,
            tip_height
        );
    }

    // Advance cursor to tip (ingest blocks above it). Never re-verify history
    // that is already stored unless the next block's prev-hash disagrees.
    let mut ingested = 0u64;
    let start = cursor.saturating_add(1);
    let mut height = start;

    // The block hash AT height — from Electrs, by height — must equal the hash
    // of the stored block at height-1's next-in-line. We instead trust the
    // linkage check below: stored height-1's hash must equal this header's
    // prev_hash. Electrs by-height is just the fetch locator.
    let mut prev_hash: Option<[u8; 32]> = if cursor > 0 {
        db.block_at(chain.chain_id, cursor)?.map(|b| b.hash_le)
    } else {
        None
    };

    let mut pending: Vec<(u64, [u8; 32], BlockHeader)> = Vec::new();

    while height <= tip_height && ingested < max_batch {
        let display_hash = electrs.block_hash_at(height).await?;
        let (base, aux) = electrs.header_with_auxpow(&display_hash).await?;

        let first_pass = light_verify(
            &base,
            &aux,
            chain.chain_id,
            // The indexer's own sanity floor, configured per-chain from env;
            // the ZK guest + contract pin the authoritative one in the journal.
            chain.pow_limit_bits,
        );
        let id = match first_pass {
            Ok(id) => id,
            Err(e) => {
                tracing::warn!(chain = %chain.name, height, err = %e, "light verify failed at height; halting walk");
                break;
            }
        };

        // Linkage gate: this header's prev_hash must equal the previous (higher)
        // block we stored. Guards against reorgs mid-walk and against a
        // fork-hopping indexer silently merging two chains.
        if let Some(p) = prev_hash {
            let prev_field: [u8; 32] = base[4..36].try_into().unwrap();
            if prev_field != p {
                tracing::warn!(chain = %chain.name, height, "prev_hash linkage broken at {height} (reorg?)");
                db.rollback_from(chain.chain_id, height)?;
                break;
            }
        }

        pending.push((height, id, BlockHeader { raw: base.to_vec(), aux: Some(aux) }));
        prev_hash = Some(id);
        height += 1;
        ingested += 1;
    }

    // Persist in height order, then advance cursor to the tallest stored height
    // so the next tick only walks the fresh frontier (not the re-ingest window).
    let last = pending.last().map(|(h, _, _)| *h);
    for (h, id, header) in pending.into_iter() {
        let block = StoredBlock { hash_le: id, chain_id: chain.chain_id, height: h, header };
        db.insert_block(chain.chain_id, h, &block)?;
    }
    if let Some(h) = last {
        db.set_cursor_height(chain.chain_id, h)?;
    }

    // Classify any previously unseen parents against Litecoin mainnet.
    for p in db.unclassified_parents()? {
        let ltc_height = resolver.resolve(&p).await?;
        db.classify_parent(&p, ltc_height)?;
        if let Some(h) = ltc_height {
            tracing::info!(parent = hex::encode(p), ltc_height = h, "parent is Litecoin mainnet block");
        } else {
            tracing::debug!(parent = hex::encode(p), "parent not on Litecoin mainnet (trial)");
        }
    }

    Ok(ingested)
}

/// Continuous ingest loop for all configured chains using a shared Database instance.
pub async fn run_with_db(config: crate::Config, db: std::sync::Arc<Database>) -> anyhow::Result<()> {
    let resolver =
        ParentResolver::new(&config.ccnodes_base, &config.ccnodes_api_key, &config.parent_chain)?;

    loop {
        for chain in &config.chains {
            let electrs = ElectrsClient::new(&chain.electrs);
            // A batch per tick is bounded so a huge tip-diff doesn't snapshot the
            // whole window at once (bounded by config.max_batch from env).
            let batch = ingest_chain(&config, chain, &electrs, &db, &resolver, config.max_batch).await?;
            if batch > 0 {
                tracing::info!(chain = %chain.name, ingested = batch, "ingest batch");
            }
        }
        sleep(config.poll_interval).await;
    }
}

/// Continuous ingest loop for all configured chains (opens DB from path).
pub async fn run(config: crate::Config) -> anyhow::Result<()> {
    let db = std::sync::Arc::new(Database::open(&config.db_path)?);
    run_with_db(config, db).await
}