//! PSob light verification — pure, per-step, and independently testable.
//!
//! Everything here mirrors the consensus checks the ZK guest (and the on-chain
//! verifier) run in-circuit, except scrypt, which is deliberately NOT evaluated
//! here (see `crates/common` for the guest's role):
//!
//! 1. **Header format** — exactly 80 bytes, chain-id `nVersion >> 16`,
//!    `nBits` decodes to a valid compact target `<= powLimit`.
//! 2. **Proof 1 (coinbase → parent root)** — `parent_index == 0`, the parent
//!    header belongs to a *foreign* chain (strict chain-id guard), and folding
//!    the coinbase txid up the parent merkle branch reaches the parent block's
//!    merkle root.
//! 3. **Proof 2 (aux → chain root)** — folding the aux block hash up the chain
//!    merkle branch reaches a root that is committed in the parent coinbase
//!    immediately after the `fabe6d6d` merged-mining magic (exactly one
//!    commitment, byte-reversed).
//! 4. **Anti-grind** — the 4-byte size after the committed root equals
//!    `2^depth` and the 4-byte nonce pins `chain_index` via the LCG in
//!    [`common::verify_auxpow_commitment`], so one parent block commits each
//!    chain at exactly one slot.
//!
//! All functions are pure (no I/O) and return a detailed
//! [`VerificationReport`] rather than a bare bool so API consumers and the
//! explorer can surface *why* a block was rejected.

use serde::Serialize;

use common::cauxpow::{hash_display, parse_auxpow, AuxPowParseError};
use common::{AuxPow, BlockHeader};

/// Generic per-step check outcome for the report.
#[derive(Debug, Clone, Serialize)]
pub struct StepResult {
    pub ok: bool,
    pub error: Option<String>,
}

impl StepResult {
    pub fn ok() -> Self {
        Self {
            ok: true,
            error: None,
        }
    }

    pub fn err(msg: impl Into<String>) -> Self {
        Self {
            ok: false,
            error: Some(msg.into()),
        }
    }
}

/// Outcome of the two proof-2 sub-checks plus the parsed commitment fields.
struct Proof2Outcome {
    proof2: StepResult,
    anti_grind: StepResult,
    /// The committed bytes (as stored in the coinbase, reversed wire order).
    committed: Option<[u8; 32]>,
    n_size: u32,
    nonce: u32,
}

/// Detailed result of verifying one aux block against PSob rules.
///
/// `valid == true` iff every step passes and there is no fatal error. All hex
/// fields use display (big-endian) order, matching the REST API.
#[derive(Debug, Clone, Serialize)]
pub struct VerificationReport {
    pub valid: bool,
    pub chain_id: u32,
    /// sha256d of the 80-byte aux header (display hex).
    pub block_hash: String,
    /// sha256d of the auxpow parent header (display hex) — the Litecoin anchor.
    pub parent_hash: String,
    /// `nVersion >> 16` of the parent header, if it parsed.
    pub parent_chain_id: Option<u32>,
    pub header_format: StepResult,
    pub proof1_coinbase_to_parent_root: StepResult,
    pub proof2_aux_to_chain_root: StepResult,
    pub anti_grind_lcg_slot: StepResult,
    /// The folded chain root (display hex) — must equal `coinbase_root_hex`.
    pub chain_root_hex: String,
    /// The root bytes actually committed after the magic in the coinbase.
    pub coinbase_root_hex: String,
    pub chain_branch_depth: usize,
    pub chain_index: u32,
    /// `2^depth` — the size field directly after the committed root.
    pub n_size: u32,
    /// Anti-grind nonce read from the coinbase tail (bytes after root+size).
    pub nonce: u32,
    /// Parse-level failure (malformed wire) — if set, all steps are `false`.
    pub fatal_error: Option<String>,
}

impl VerificationReport {
    fn failed(chain_id: u32, fatal: impl Into<String>) -> Self {
        let fatal = fatal.into();
        Self {
            valid: false,
            chain_id,
            block_hash: String::new(),
            parent_hash: String::new(),
            parent_chain_id: None,
            header_format: StepResult::err(&fatal),
            proof1_coinbase_to_parent_root: StepResult::err("skipped: fatal parse error"),
            proof2_aux_to_chain_root: StepResult::err("skipped: fatal parse error"),
            anti_grind_lcg_slot: StepResult::err("skipped: fatal parse error"),
            chain_root_hex: String::new(),
            coinbase_root_hex: String::new(),
            chain_branch_depth: 0,
            chain_index: 0,
            n_size: 0,
            nonce: 0,
            fatal_error: Some(fatal),
        }
    }
}

/// Verify a parsed header + AuxPoW witness against the PSob rules for `chain_id`.
///
/// Pure: `base` must be exactly 80 consensus bytes, `aux` the parsed CAuxPow.
pub fn verify_aux_header(
    base: &[u8],
    aux: &AuxPow,
    chain_id: u32,
    pow_limit_bits: u32,
) -> VerificationReport {
    let mut report = VerificationReport {
        valid: false,
        chain_id,
        block_hash: String::new(),
        parent_hash: String::new(),
        parent_chain_id: None,
        header_format: check_header_format(base, chain_id, pow_limit_bits),
        proof1_coinbase_to_parent_root: StepResult::ok(),
        proof2_aux_to_chain_root: StepResult::ok(),
        anti_grind_lcg_slot: StepResult::ok(),
        chain_root_hex: String::new(),
        coinbase_root_hex: String::new(),
        chain_branch_depth: aux.chain_merkle_branch.len(),
        chain_index: aux.chain_index,
        n_size: 0,
        nonce: 0,
        fatal_error: None,
    };
    if !report.header_format.ok {
        report.valid = false;
        return report;
    }

    let block_hash = common::sha256d(base);
    report.block_hash = hash_display(&block_hash);
    report.parent_hash = hash_display(&common::sha256d(&aux.parent_header));
    report.parent_chain_id = aux.parent_chain_id();

    // Proof 1: coinbase is the generation tx AND included in the parent block.
    report.proof1_coinbase_to_parent_root = verify_proof1(aux, chain_id);

    // Proof 2 + anti-grind: the chain root must fold and be committed in the
    // parent coinbase, with the LCG pinning the slot.
    let out = verify_proof2(&block_hash, aux, chain_id);
    report.proof2_aux_to_chain_root = out.proof2;
    report.anti_grind_lcg_slot = out.anti_grind;
    report.n_size = out.n_size;
    report.nonce = out.nonce;
    if let Some(committed) = out.committed {
        let mut display = committed;
        display.reverse(); // stored bytes are reversed wire order → display hex
        report.coinbase_root_hex = hex::encode(display);
        report.chain_root_hex = report.coinbase_root_hex.clone();
    }

    report.valid = report.header_format.ok
        && report.proof1_coinbase_to_parent_root.ok
        && report.proof2_aux_to_chain_root.ok
        && report.anti_grind_lcg_slot.ok;
    report
}

/// Verify the raw wire payload (80-byte header ‖ CAuxPow).
///
/// The parser is shared with the guest and the SDK port
/// ([`common::cauxpow::parse_auxpow`]).
pub fn verify_auxpow_wire(
    wire: &[u8],
    chain_id: u32,
    pow_limit_bits: u32,
) -> Result<VerificationReport, AuxPowParseError> {
    let (base, aux) = parse_auxpow(wire)?;
    Ok(verify_aux_header(&base, &aux, chain_id, pow_limit_bits))
}

/// Fast-path light verification used by the ingestor: same checks, but a single
/// `Ok(hash) / Err(reason)` result, no report allocation.
pub fn light_verify(
    base: &[u8],
    aux: &AuxPow,
    chain_id: u32,
    pow_limit_bits: u32,
) -> Result<[u8; 32], String> {
    if !check_header_format(base, chain_id, pow_limit_bits).ok {
        return Err(String::from("header format checks failed"));
    }
    let block_hash = common::sha256d(base);
    if !verify_proof1(aux, chain_id).ok {
        return Err(String::from("proof 1 (coinbase → parent root) failed"));
    }
    let out = verify_proof2(&block_hash, aux, chain_id);
    if !out.proof2.ok {
        return Err(String::from("proof 2 (aux → chain root) failed"));
    }
    if !out.anti_grind.ok {
        return Err(String::from("anti-grind LCG slot check failed"));
    }
    Ok(block_hash)
}

/// Verify the assembled header (raw aux bytes + parsed witness) — the form used
/// by the store path.
pub fn verify_header(
    header: &BlockHeader,
    chain_id: u32,
    pow_limit_bits: u32,
) -> VerificationReport {
    match &header.aux {
        Some(aux) => verify_aux_header(&header.raw, aux, chain_id, pow_limit_bits),
        None => VerificationReport::failed(
            chain_id,
            "header has no AuxPoW witness (PSob requires merge-mined blocks)",
        ),
    }
}

/// Header format: exactly 80 bytes, chain-id match, valid compact target
/// within the powLimit floor. No cryptographic work performed here.
fn check_header_format(base: &[u8], chain_id: u32, pow_limit_bits: u32) -> StepResult {
    if base.len() != 80 {
        return StepResult::err(format!("header must be 80 bytes, got {}", base.len()));
    }
    let version = u32::from_le_bytes([base[0], base[1], base[2], base[3]]);
    let got_chain = version >> 16;
    if got_chain != chain_id {
        return StepResult::err(format!("chain id {got_chain} != expected {chain_id}"));
    }
    let bits = u32::from_le_bytes([base[72], base[73], base[74], base[75]]);
    let Some(target) = common::expand_target(bits) else {
        return StepResult::err(format!("invalid nBits 0x{bits:08x} (cannot decode)"));
    };
    let Some(pow_limit) = common::expand_target(pow_limit_bits) else {
        return StepResult::err(format!("invalid powLimitBits 0x{pow_limit_bits:08x}"));
    };
    if !common::target_leq(&target, &pow_limit) {
        return StepResult::err(format!("target easier than powLimit (nBits 0x{bits:08x})"));
    }
    StepResult::ok()
}

/// Proof 1 — the coinbase is the parent's generation transaction and is
/// included in the parent block.
fn verify_proof1(aux: &AuxPow, chain_id: u32) -> StepResult {
    if aux.parent_index != 0 {
        return StepResult::err(format!(
            "coinbase must be at parent index 0, got {}",
            aux.parent_index
        ));
    }
    // Strict chain-id guard: the parent must not claim our aux chain id — a chain
    // cannot merge-mine itself (JunkCoin Core `CAuxPow::check`).
    match aux.parent_chain_id() {
        Some(pid) if pid != chain_id => {}
        _ => {
            let pid = aux
                .parent_chain_id()
                .map(|p| p.to_string())
                .unwrap_or_else(|| "unparseable".into());
            return StepResult::err(format!(
                "parent chain id {pid} equals aux chain id — self-merge rejected"
            ));
        }
    }
    let Some(parent_root) = aux.parent_merkle_root() else {
        return StepResult::err("parent header too short for merkle root");
    };
    let cb_txid = common::sha256d(&aux.coinbase_tx);
    let folded = common::merkle_fold_branch(&cb_txid, &aux.parent_merkle_branch, aux.parent_index);
    if folded != parent_root {
        return StepResult::err("coinbase txid does not fold to the parent block's merkle root");
    }
    StepResult::ok()
}

/// Proof 2 + anti-grind:
///
/// * fold `aux_block_hash` up the chain merkle branch → chain root;
/// * the chain root must appear (reversed) in the coinbase immediately after
///   exactly one `fabe6d6d` magic;
/// * the 4-byte size after the committed root must be `2^depth`;
/// * the 4-byte nonce must pin `chain_index` via the LCG.
fn verify_proof2(aux_block_hash: &[u8; 32], aux: &AuxPow, chain_id: u32) -> Proof2Outcome {
    let depth = aux.chain_merkle_branch.len();
    let chain_root =
        common::merkle_fold_branch(aux_block_hash, &aux.chain_merkle_branch, aux.chain_index);
    let mut root_reversed = chain_root;
    root_reversed.reverse();

    let cb = &aux.coinbase_tx;
    let Some(magic_at) = find_subslice(cb, &common::AUXPOW_MAGIC) else {
        return Proof2Outcome {
            proof2: StepResult::err("merged-mining magic fabe6d6d not found in coinbase"),
            anti_grind: StepResult::err("skipped: coinbase has no AuxPoW commitment"),
            committed: None,
            n_size: 0,
            nonce: 0,
        };
    };
    // Exactly one commitment — no second header after the first.
    if find_subslice(&cb[magic_at + 1..], &common::AUXPOW_MAGIC).is_some() {
        return Proof2Outcome {
            proof2: StepResult::err("more than one merged-mining magic in the coinbase"),
            anti_grind: StepResult::err("ambiguous AuxPoW commitment"),
            committed: None,
            n_size: 0,
            nonce: 0,
        };
    }
    let root_pos = magic_at + common::AUXPOW_MAGIC.len();
    let Some(tail) = cb.get(root_pos..root_pos + 40) else {
        return Proof2Outcome {
            proof2: StepResult::err("truncated AuxPoW commitment after magic"),
            anti_grind: StepResult::err("skipped"),
            committed: None,
            n_size: 0,
            nonce: 0,
        };
    };
    let committed: [u8; 32] = tail[..32].try_into().expect("32 bytes");
    let n_size = u32::from_le_bytes(tail[32..36].try_into().expect("4 bytes"));
    let nonce = u32::from_le_bytes(tail[36..40].try_into().expect("4 bytes"));

    if committed != root_reversed {
        return Proof2Outcome {
            proof2: StepResult::err("computed chain root ≠ root committed in parent coinbase"),
            anti_grind: StepResult::err("skipped"),
            committed: None,
            n_size,
            nonce,
        };
    }

    let grill = if n_size != (1u32 << depth) {
        StepResult::err(format!("anti-grind size {n_size} != 2^{depth}"))
    } else if aux.chain_index != expected_index(nonce, chain_id, depth as u32) {
        StepResult::err(format!(
            "chain index {} violates LCG slot (nonce {nonce}, chain_id {chain_id}, depth {depth})",
            aux.chain_index
        ))
    } else {
        StepResult::ok()
    };

    Proof2Outcome {
        proof2: StepResult::ok(),
        anti_grind: grill,
        committed: Some(committed),
        n_size,
        nonce,
    }
}

/// Verbatim port of the LCG slot derivation (`CAuxPow::getExpectedIndex`); the
/// canonical implementation lives in [`common::verify_auxpow_commitment`].
fn expected_index(nonce: u32, chain_id: u32, height: u32) -> u32 {
    let mut rand = nonce;
    rand = rand.wrapping_mul(1103515245).wrapping_add(12345);
    rand = rand.wrapping_add(chain_id);
    rand = rand.wrapping_mul(1103515245).wrapping_add(12345);
    rand % (1u32 << height)
}

fn find_subslice(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

/// A block kept with its full wire payload so it stays self-verifiable.
#[derive(Debug, Clone)]
pub struct AuxBlock {
    /// The 80-byte aux header (wire order, little-endian).
    pub base: [u8; 80],
    /// Parsed CAuxPow witness.
    pub aux: AuxPow,
    /// The full wire payload (80-byte header + CAuxPow).
    pub wire: Vec<u8>,
}

impl AuxBlock {
    pub fn from_wire(wire: Vec<u8>) -> Result<Self, AuxPowParseError> {
        let (base, aux) = parse_auxpow(&wire)?;
        Ok(Self { base, aux, wire })
    }

    pub fn header(&self) -> BlockHeader {
        BlockHeader {
            raw: self.base.to_vec(),
            aux: Some(self.aux.clone()),
        }
    }

    pub fn block_hash(&self) -> [u8; 32] {
        common::sha256d(&self.base)
    }

    pub fn parent_hash(&self) -> [u8; 32] {
        common::sha256d(&self.aux.parent_header)
    }

    pub fn block_hash_display(&self) -> String {
        hash_display(&self.block_hash())
    }

    pub fn parent_hash_display(&self) -> String {
        hash_display(&self.parent_hash())
    }
}

/// Verify a full wire payload as an [`AuxBlock`] — the single-entry API used by
/// the REST `/verify` endpoint and the ingestor.
pub fn verify_wire_block(
    wire: &[u8],
    chain_id: u32,
    pow_limit_bits: u32,
) -> Result<(AuxBlock, VerificationReport), AuxPowParseError> {
    let aux_block = AuxBlock::from_wire(wire.to_vec())?;
    let report = verify_aux_header(&aux_block.base, &aux_block.aux, chain_id, pow_limit_bits);
    Ok((aux_block, report))
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::cauxpow::parse_auxpow;

    const FIXTURE: &str = include_str!("../crates/common/tests/fixtures/jkc_1095600_header.hex");
    const POW_LIMIT: u32 = common::CHAIN_POW_LIMIT_BITS;
    const JKC: u32 = 8224;

    #[test]
    fn live_jkc_block_fully_verifies() {
        let wire = hex::decode(FIXTURE.trim()).expect("fixture hex");
        let report = verify_auxpow_wire(&wire, JKC, POW_LIMIT).expect("parses");
        assert!(report.valid, "live block must pass every PSob check");
        assert_eq!(
            report.block_hash,
            "216ccca027bde174293a775e52d861dabe4e45028847189d100d9e75d0c6fbf4"
        );
        assert!(report.header_format.ok && report.proof1_coinbase_to_parent_root.ok);
        assert!(report.proof2_aux_to_chain_root.ok && report.anti_grind_lcg_slot.ok);
        assert_eq!(report.chain_root_hex, report.coinbase_root_hex);
        assert_eq!(report.n_size, 1u32 << report.chain_branch_depth);
    }

    #[test]
    fn tampered_commitment_is_detected_step_by_step() {
        let wire = hex::decode(FIXTURE.trim()).expect("fixture hex");
        let (_base, mut aux) = parse_auxpow(&wire).expect("parses");
        // Flip a chain-branch sibling so the fold diverges.
        let idx = aux.chain_merkle_branch.len() - 1;
        aux.chain_merkle_branch[idx][0] ^= 1;
        let report = verify_aux_header(&wire[..80], &aux, JKC, POW_LIMIT);
        assert!(!report.valid);
        assert!(!report.proof2_aux_to_chain_root.ok);
        assert!(
            report.proof1_coinbase_to_parent_root.ok,
            "proof 1 is untouched"
        );
    }

    #[test]
    fn wrong_chain_id_is_rejected() {
        let wire = hex::decode(FIXTURE.trim()).expect("fixture hex");
        let report = verify_auxpow_wire(&wire, 50, POW_LIMIT).expect("parses");
        assert!(!report.valid);
        assert!(!report.header_format.ok);
    }

    #[test]
    fn truncated_wire_is_rejected() {
        let wire = hex::decode(FIXTURE.trim()).expect("fixture hex");
        assert!(verify_auxpow_wire(&wire[..40], JKC, POW_LIMIT).is_err());
    }

    #[test]
    fn non_auxpow_payload_is_rejected() {
        let mut wire = [0u8; 80];
        wire[0..4].copy_from_slice(&((JKC << 16) | 1).to_le_bytes());
        assert!(verify_auxpow_wire(&wire, JKC, POW_LIMIT).is_err());
    }
}
