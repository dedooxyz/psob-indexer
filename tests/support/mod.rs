//! Shared test fixtures: a real JKC block wire-bytes and a deterministic
//! generator for synthetic siblings bound to the same Litecoin parent.
//!
//! The generator mutates a REAL block's wire payload (header version/nonce,
//! committed chain root, parent merkle root) keeping every field that proofs
//! depend on internally consistent — so `verify` re-passes on the synthetic
//! blocks exactly as it passes on the original.

use common::cauxpow::parse_auxpow;
use common::BlockHeader;
use psob_indexer::db::{sha256d, StoredBlock};

/// Real Junkcoin block #1095600 (live from junk-api.s3na.xyz) — verified by the
/// same rules the indexer runs.
pub const JKC_FIXTURE: &str =
    include_str!("../../crates/common/tests/fixtures/jkc_1095600_header.hex");
pub const JKC: u32 = 8224;
pub const DINGO: u32 = 50;

fn push_varint(out: &mut Vec<u8>, v: u64) {
    match v {
        0..=0xfc => out.push(v as u8),
        0xfd..=0xffff => {
            out.push(0xfd);
            out.extend_from_slice(&(v as u16).to_le_bytes());
        }
        0x10000..=0xffff_ffff => {
            out.push(0xfe);
            out.extend_from_slice(&(v as u32).to_le_bytes());
        }
        _ => {
            out.push(0xff);
            out.extend_from_slice(&v.to_le_bytes());
        }
    }
}

/// Re-serialize a mutated AuxPoW witness + base header into full wire bytes
/// (header ‖ coinbase ‖ hashBlock ‖ parentBranch ‖ parentIndex ‖ chainBranch ‖
/// chainIndex ‖ parentHeader) — identical to `common::cauxpow`'s inverse.
fn reserialize_wire(hdr: &[u8; 80], aux: &common::AuxPow, hash_block: &[u8; 32]) -> Vec<u8> {
    let mut out = hdr.to_vec();
    out.extend_from_slice(&aux.coinbase_tx);
    out.extend_from_slice(hash_block);
    push_varint(&mut out, aux.parent_merkle_branch.len() as u64);
    for h in &aux.parent_merkle_branch {
        out.extend_from_slice(h);
    }
    out.extend_from_slice(&aux.parent_index.to_le_bytes());
    push_varint(&mut out, aux.chain_merkle_branch.len() as u64);
    for h in &aux.chain_merkle_branch {
        out.extend_from_slice(h);
    }
    out.extend_from_slice(&aux.chain_index.to_le_bytes());
    out.extend_from_slice(&aux.parent_header);
    out
}

/// Parse the real fixture and rebind it: new chain id and height (header
/// version + nonce), recompute the block hash, rewrite the committed chain root
/// and the parent merkle root so proofs 1 & 2 stay internally consistent.
fn fixture_block(chain_id: u32, height: u64, mask: u8) -> StoredBlock {
    let wire = hex::decode(JKC_FIXTURE.trim()).expect("fixture hex");
    let (base, mut aux) = parse_auxpow(&wire).expect("parses");
    let hash_block: [u8; 32] = wire[80 + aux.coinbase_tx.len()..80 + aux.coinbase_tx.len() + 32]
        .try_into()
        .expect("hashBlock");

    let version = u32::from_le_bytes(base[0..4].try_into().unwrap());
    let mut hdr = base;
    hdr[0..4]
        .copy_from_slice(&((chain_id << 16) | (version & 0xffff) | (mask as u32)).to_le_bytes());
    hdr[76..80].copy_from_slice(&(height as u32 ^ mask as u32).to_le_bytes());
    let hash = sha256d(&hdr);

    // Rewrite the committed root (bytes after the magic): the chain merkle fold
    // of the NEW hash through the real chain branch, byte-reversed per CAuxPow.
    let committed = common::merkle_fold_branch(&hash, &aux.chain_merkle_branch, aux.chain_index);
    if let Some(pos) = aux
        .coinbase_tx
        .windows(4)
        .position(|w| w == common::AUXPOW_MAGIC)
    {
        let mut rev = committed;
        rev.reverse();
        let start = pos + common::AUXPOW_MAGIC.len();
        aux.coinbase_tx[start..start + 32].copy_from_slice(&rev);
    }
    // …and the parent block's merkle root for the new coinbase txid.
    let cb_txid = common::sha256d(&aux.coinbase_tx);
    let parent_root =
        common::merkle_fold_branch(&cb_txid, &aux.parent_merkle_branch, aux.parent_index);
    aux.parent_header[36..68].copy_from_slice(&parent_root);

    StoredBlock {
        hash_le: hash,
        chain_id,
        height,
        header: BlockHeader {
            raw: hdr.to_vec(),
            aux: Some(aux.clone()),
        },
        wire_hex: hex::encode(reserialize_wire(&hdr, &aux, &hash_block)),
    }
}

/// A JKC block + a DINGO block under the fixture's shared Litecoin parent.
/// The JKC leg is a true positive; the DINGO leg reuses the exact parent header
/// bytes (same parent hash) so it appears in sibling listings — its client-side
/// verification isn't asserted anywhere.
pub fn sibling_pair(jkc_height: u64, dingo_height: u64) -> (StoredBlock, StoredBlock) {
    let jkc = fixture_block(JKC, jkc_height, 1);
    let mut dingo = fixture_block(DINGO, dingo_height, 2);
    dingo.header.aux.as_mut().unwrap().parent_header =
        jkc.header.aux.as_ref().unwrap().parent_header.clone();
    let hash_block = [0x55u8; 32];
    let aux = dingo.header.aux.as_ref().unwrap();
    let mut hdr = [0u8; 80];
    hdr.copy_from_slice(&dingo.header.raw);
    dingo.wire_hex = hex::encode(reserialize_wire(&hdr, aux, &hash_block));
    (jkc, dingo)
}

/// A JKC block bound to a DIFFERENT (single-block) parent — for range scans
/// where sharing the fixture parent would pollute sibling groups.
pub fn fixture_jkc() -> StoredBlock {
    let mut b = fixture_block(JKC, 1095600, 1);
    // Mutate the embedded parent header's nonce so the parent hash differs,
    // recompute the block hash, and re-commit it in the coinbase.
    {
        let aux = b.header.aux.as_mut().unwrap();
        let n = aux.parent_header.len() - 1;
        aux.parent_header[n] ^= 0x5a;
        b.hash_le = sha256d(&b.header.raw);
        let committed =
            common::merkle_fold_branch(&b.hash_le, &aux.chain_merkle_branch, aux.chain_index);
        if let Some(pos) = aux
            .coinbase_tx
            .windows(4)
            .position(|w| w == common::AUXPOW_MAGIC)
        {
            let mut rev = committed;
            rev.reverse();
            let start = pos + common::AUXPOW_MAGIC.len();
            aux.coinbase_tx[start..start + 32].copy_from_slice(&rev);
        }
        // parent merkle root already patched by fixture_block (proof 1 consistent)
    }
    // Reserialize the wire with the same in-memory mutations.
    let mut hdr = [0u8; 80];
    hdr.copy_from_slice(&b.header.raw);
    let aux = b.header.aux.as_ref().unwrap();
    let hash_block = [0x55u8; 32]; // placeholder — not consumed by verification
    b.wire_hex = hex::encode(reserialize_wire(&hdr, aux, &hash_block));
    b
}

pub fn tmp_db_path(name: &str) -> std::path::PathBuf {
    static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    std::env::temp_dir().join(format!("psob-api-test-{name}-{}-{}", std::process::id(), n))
}
