//! `psob-explain` — reproduce a PSob proof-witness from the cached indexer.
//!
//! It answers, for a real on-chain window:
//!   1. how many Litecoin parents are shared between ≥2 aux chains (siblings);
//!   2. for one sibling group, the *invariant check* — fold each chain's block
//!      hash up its own chain Merkle branch: all must reach the same root R
//!      (and R is what the ZK guest commits to);
//!   3. the epoch witness `[L_start..L_end]` a swap prover would consume.
//!
//! Usage:
//!   psob-explain <DB_PATH> [--ltc-start N] [--ltc-end N] [--legs 2]
//!
//! Everything chain-specific stays in the DB created by the ingestor.

use anyhow::Context;
use common::merkle_fold_branch;
use psob_indexer::Database;
use std::process::ExitCode;

fn sha256d(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut out = [0u8; 32];
    out.copy_from_slice(&Sha256::digest(Sha256::digest(data)));
    out
}

fn hex_le(h: &[u8; 32]) -> String {
    let mut b = *h;
    b.reverse();
    hex::encode(b)
}

const AUXPOW_MAGIC: [u8; 4] = [0xfa, 0xbe, 0x6d, 0x6d];

/// Proof-of-sibling-BLOCK: the chain root must be committed in the LTC
/// coinbase right after the `fabe6d6d` magic (reversed display order).
fn root_committed_in_coinbase(coinbase_tx: &[u8], chain_root: &[u8; 32]) -> bool {
    let Some(magic_at) = coinbase_tx.windows(4).position(|w| w == AUXPOW_MAGIC) else {
        return false;
    };
    let Some(tail) = coinbase_tx.get(magic_at + 4..magic_at + 4 + 32) else {
        return false;
    };
    let mut stored = [0u8; 32];
    stored.copy_from_slice(tail);
    stored.reverse();
    &stored == chain_root
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        eprintln!("usage: psob-explain <DB_PATH> [--ltc-start N] [--ltc-end N] [--legs N]");
        return ExitCode::FAILURE;
    }
    let mut ltc_start = None;
    let mut ltc_end = None;
    let mut min_legs = 2usize;
    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "--ltc-start" => {
                i += 1;
                ltc_start = args.get(i).and_then(|v| v.parse().ok());
            }
            "--ltc-end" => {
                i += 1;
                ltc_end = args.get(i).and_then(|v| v.parse().ok());
            }
            "--legs" => {
                i += 1;
                if let Some(v) = args.get(i).and_then(|v| v.parse().ok()) {
                    min_legs = v;
                }
            }
            other => {
                eprintln!("unknown flag: {other}");
                return ExitCode::FAILURE;
            }
        }
        i += 1;
    }

    let db = Database::open(&args[1]).unwrap_or_else(|e| {
        eprintln!("cannot open db: {e:#}");
        std::process::exit(2);
    });

    // ── 1. Shared (sibling) parents ───────────────────────────────────────────
    println!("=== 1. Cross-chain sibling parents (≥{min_legs} legs, mainnet only) ===");
    let shared = db
        .shared_mainnet_parents(
            min_legs,
            psob_indexer::db::Page::new(Some(10), Some(0)),
            None,
        )
        .context("shared_mainnet_parents")
        .unwrap_or_else(|e| {
            eprintln!("{e:#}");
            std::process::exit(2);
        });
    if shared.is_empty() {
        println!("  (none yet — ingest more blocks first)");
    }
    for s in &shared {
        let legs: Vec<String> = s
            .legs
            .iter()
            .map(|(cid, h)| format!("chain:{cid}@#{h}"))
            .collect();
        println!(
            "  LTC #{:<9} parent {}  legs=[{}]",
            s.ltc_height,
            hex_le(&s.parent_hash_le),
            legs.join(", ")
        );
    }

    // ── 2. Invariant check on the top sibling group ───────────────────────────
    if let Some(top) = shared.first() {
        println!();
        println!(
            "=== 2. PSob invariant check (top sibling group @ LTC #{}) ===",
            top.ltc_height
        );
        let siblings = db
            .siblings_for_parent(&top.parent_hash_le)
            .context("siblings_for_parent")
            .unwrap_or_else(|e| {
                eprintln!("{e:#}");
                std::process::exit(2);
            });
        let mut roots: Vec<(u32, u64, [u8; 32])> = Vec::new();
        for b in &siblings {
            let aux = b.header.aux.as_ref().expect("stored blocks carry auxpow");
            let id = sha256d(&b.header.raw);
            let root = merkle_fold_branch(&id, &aux.chain_merkle_branch, aux.chain_index);
            roots.push((b.chain_id, b.height, root));
            println!(
                "  chain {:>4} @ #{:<9} depth {:<2} idx {:<3} → root {}",
                b.chain_id,
                b.height,
                aux.chain_merkle_branch.len(),
                aux.chain_index,
                hex_le(&root),
            );
        }
        let first = roots[0].2;
        let all_same = roots.iter().all(|(_, _, r)| *r == first);
        println!(
            "  ⇒ all {} siblings fold to the SAME chain root: {}",
            roots.len(),
            if all_same { "YES ✓" } else { "NO ✗" }
        );
        // And with the coinbase: the root must be committed after the magic.
        let aux = siblings[0].header.aux.as_ref().unwrap();
        match root_committed_in_coinbase(&aux.coinbase_tx, &first) {
            true => println!("  ⇒ root committed in LTC coinbase after fabe6d6d: YES ✓"),
            false => {
                println!("  ⇒ root committed in LTC coinbase: NO ✗ (indexer data inconsistent!)")
            }
        }
    }

    // ── 3. Epoch witness ──────────────────────────────────────────────────────
    if let (Some(a), Some(b)) = (ltc_start, ltc_end) {
        println!();
        println!("=== 3. Epoch witness [LTC #{a} .. LTC #{b}] ===");
        let rows = db
            .epoch_blocks(a, b, None, psob_indexer::db::Page::default())
            .context("epoch_blocks")
            .unwrap_or_else(|e| {
                eprintln!("{e:#}");
                std::process::exit(2);
            });
        if rows.is_empty() {
            println!("  (no blocks anchored inside this epoch in the cache)");
        }
        let mut by_chain: std::collections::BTreeMap<u32, Vec<(u64, u64, [u8; 32])>> =
            Default::default();
        for (chain_id, height, ltc_h, hash_le) in rows {
            by_chain
                .entry(chain_id)
                .or_default()
                .push((height, ltc_h, hash_le));
        }
        for (chain_id, vec) in by_chain {
            println!("  chain {chain_id}: {} blocks anchored in epoch", vec.len());
            for (height, ltc_h, hash_le) in vec {
                println!(
                    "    aux #{height:<9} LTC parent #{ltc_h:<9} {}",
                    hex_le(&hash_le)
                );
            }
        }
    }

    ExitCode::SUCCESS
}
