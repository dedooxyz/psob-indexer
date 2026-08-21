//! Shared types between the zkVM guest, the host prover, and on-chain calldata.
//!
//! Junkcoin is a *pure legacy UTXO* chain (Litecoin-family): 80-byte block
//! headers, scrypt(N=1024, r=1, p=1) proof-of-work, double-SHA256 tx ids, and
//! P2PKH addresses. No SegWit / Taproot / covenants — so all "smart" logic lives
//! off-chain (ZK on Base, covenant vault on JKC).

#![cfg_attr(not(feature = "std"), no_std)]
extern crate alloc;
use alloc::vec::Vec;
use serde::{Deserialize, Serialize};

/// Scrypt parameters for the Junkcoin/Litecoin PoW hash.
pub const SCRYPT_LOG_N: u8 = 10; // N = 1024
pub const SCRYPT_R: u32 = 1;
pub const SCRYPT_P: u32 = 1;

/// Junkcoin mainnet proof-of-work limit (the *easiest* difficulty the consensus
/// rules allow), as compact `nBits`. Junkcoin Core's `powLimit` is
/// `0x00000fffff…ff` whose `GetCompact()` is `0x1e0fffff` (genesis is `0x1e0ffff0`).
/// Every header's expanded target MUST be `<=` this; a header claiming an easier
/// target is invalid PoW. This is the on-chain-pinned bound the guest enforces so a
/// prover cannot forge a cheap low-difficulty fork from the checkpoint. See
/// [`expand_target`] and Junkcoin Core `src/pow.cpp::CheckProofOfWork`.
pub const CHAIN_POW_LIMIT_BITS: u32 = 0x1e0f_ffff;

/// Litecoin (the AuxPoW parent chain) proof-of-work limit, also `0x1e0fffff` —
/// the standard compact powLimit for the whole scrypt/AuxPoW family (LTC, DOGE,
/// JKC…). The PSob guest checks the single verified LTC parent's expanded target
/// against this floor, and the contract pins it. Per-chain powLimits that differ
/// (e.g. a chain that forked its own limit) are handled on-chain per `chainId`.
pub const LTC_POW_LIMIT_BITS: u32 = 0x1e0f_ffff;

/// Merged-mining magic that precedes the aux-chain merkle root in the parent
/// coinbase: `fa be 6d 6d`.
pub const AUXPOW_MAGIC: [u8; 4] = [0xfa, 0xbe, 0x6d, 0x6d];

// ─── AuxPoW (merged mining) ─────────────────────────────────────────────────────
// Junkcoin is merge-mined: a JKC block carries no PoW of its own. Instead a
// *parent* block (scrypt-mined) commits to the JKC block hash inside its coinbase,
// and the parent header satisfies the PoW target. Verifying a JKC block's PoW means
// verifying this AuxPoW linkage + the parent's scrypt PoW. See `verify_auxpow_commitment`.

fn sha256d(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let first = Sha256::digest(data);
    let second = Sha256::digest(first);
    let mut out = [0u8; 32];
    out.copy_from_slice(&second);
    out
}

/// Fold `leaf` up a merkle branch using the low bits of `index` to pick sides
/// (`index` bit 0 → leaf is the left child), double-SHA256 at each level.
pub fn merkle_fold_branch(leaf: &[u8; 32], branch: &[[u8; 32]], index: u32) -> [u8; 32] {
    let mut acc = *leaf;
    let mut idx = index;
    for sib in branch {
        let mut buf = [0u8; 64];
        if idx & 1 == 0 {
            buf[..32].copy_from_slice(&acc);
            buf[32..].copy_from_slice(sib);
        } else {
            buf[..32].copy_from_slice(sib);
            buf[32..].copy_from_slice(&acc);
        }
        acc = sha256d(&buf);
        idx >>= 1;
    }
    acc
}

/// The AuxPoW witness attaching a JKC block to its scrypt-mined parent block.
/// Field order mirrors the consensus serialization (CAuxPow).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuxPow {
    /// The parent block's coinbase transaction (commits to the aux merkle root).
    pub coinbase_tx: Vec<u8>,
    /// Branch linking the coinbase txid to the parent block's merkle root.
    pub parent_merkle_branch: Vec<[u8; 32]>,
    /// Index of the coinbase in the parent block (always 0).
    pub parent_index: u32,
    /// Branch linking this JKC block hash to the aux-chain merkle root.
    pub chain_merkle_branch: Vec<[u8; 32]>,
    /// This chain's index within the aux merkle tree.
    pub chain_index: u32,
    /// The 80-byte parent block header (the one that actually bears the scrypt PoW).
    pub parent_header: Vec<u8>,
}

impl AuxPow {
    /// Parent merkle root committed in `parent_header` (little-endian, offset 36..68).
    pub fn parent_merkle_root(&self) -> Option<[u8; 32]> {
        if self.parent_header.len() < 80 {
            return None;
        }
        let mut r = [0u8; 32];
        r.copy_from_slice(&self.parent_header[36..68]);
        Some(r)
    }

    /// Parent block's AuxPoW chain id (`nVersion >> 16`, version at offset 0..4 LE).
    /// `None` if the parent header is too short to read the version.
    pub fn parent_chain_id(&self) -> Option<u32> {
        let v = self.parent_header.get(0..4)?;
        Some(u32::from_le_bytes([v[0], v[1], v[2], v[3]]) >> 16)
    }
}

/// Verify the merged-mining commitment for `aux_block_hash` (the JKC block id =
/// sha256d of its 80-byte header, little-endian), to JunkCoin Core `CAuxPow::check`
/// parity. `chain_id` is the JKC chain id (the JKC header's `nVersion >> 16`).
///
///   1. coinbase is the parent's generation tx (`parent_index == 0`) and is included
///      in the parent block (fold coinbase txid up the parent branch → parent root);
///   2. the JKC block is committed by the coinbase: folding `aux_block_hash` up the
///      chain branch yields a root whose byte-reverse sits immediately after the one
///      `fabe6d6d` merged-mining magic in the coinbase;
///   3. **strict chain id:** the parent block must NOT belong to our aux chain
///      (`parent.GetChainId() != chain_id`) — `CAuxPow::check`'s `fStrictChainId`
///      guard, stopping a chain from merge-mining itself;
///   4. **anti-grind:** the 4-byte size right after the root equals `2^height`, and
///      the 4-byte nonce after that pins `chain_index == getExpectedIndex(nonce,
///      chain_id, height)` — so one parent block commits each chain at exactly one
///      slot.
///
/// The *parent header's scrypt PoW* is checked separately by the caller (the guest),
/// since scrypt is expensive and lives there. Returns true iff the linkage holds.
pub fn verify_auxpow_commitment(aux_block_hash: &[u8; 32], aux: &AuxPow, chain_id: u32) -> bool {
    // 1. coinbase is the generation tx and is included in the parent block.
    if aux.parent_index != 0 {
        return false;
    }
    // Strict chain id: the parent (scrypt-mined, e.g. Litecoin) must not claim our
    // aux chain id. Enforced unconditionally — a legitimate parent always differs, so
    // this is at most stricter than consensus and never rejects a valid block.
    match aux.parent_chain_id() {
        Some(pid) if pid != chain_id => {}
        _ => return false,
    }
    let Some(parent_root) = aux.parent_merkle_root() else {
        return false;
    };
    let cb_txid = sha256d(&aux.coinbase_tx);
    if merkle_fold_branch(&cb_txid, &aux.parent_merkle_branch, aux.parent_index) != parent_root {
        return false;
    }

    // 2. aux block committed in the coinbase (root stored reversed, after the magic).
    let height = aux.chain_merkle_branch.len();
    if height > 30 {
        return false;
    }
    let chain_root = merkle_fold_branch(aux_block_hash, &aux.chain_merkle_branch, aux.chain_index);
    let mut needle = chain_root;
    needle.reverse();

    let cb = &aux.coinbase_tx;
    let Some(magic_at) = find_subslice(cb, &AUXPOW_MAGIC) else {
        return false;
    };
    // Exactly one merged-mining header (no second instance after the first).
    if find_subslice(&cb[magic_at + 1..], &AUXPOW_MAGIC).is_some() {
        return false;
    }
    let root_pos = magic_at + AUXPOW_MAGIC.len();
    let Some(tail) = cb.get(root_pos..root_pos + 40) else {
        return false;
    };
    if tail[..32] != needle[..] {
        return false;
    }

    // 3. anti-grind: size == 2^height, and index is pinned by the nonce.
    let n_size = u32::from_le_bytes([tail[32], tail[33], tail[34], tail[35]]);
    if n_size != (1u32 << height) {
        return false;
    }
    let n_nonce = u32::from_le_bytes([tail[36], tail[37], tail[38], tail[39]]);
    aux.chain_index == get_expected_index(n_nonce, chain_id, height as u32)
}

/// JunkCoin's deterministic aux-chain slot — a pseudo-random index fixed by the
/// (nonce, chain_id, height) triple, so the same parent work can't be reused for the
/// same chain at a different slot. Verbatim port of `CAuxPow::getExpectedIndex`.
fn get_expected_index(nonce: u32, chain_id: u32, height: u32) -> u32 {
    let mut rand = nonce;
    rand = rand.wrapping_mul(1103515245).wrapping_add(12345);
    rand = rand.wrapping_add(chain_id);
    rand = rand.wrapping_mul(1103515245).wrapping_add(12345);
    rand % (1u32 << height)
}

fn find_subslice(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

/// A raw 80-byte legacy block header, kept in serialized little-endian wire form
/// exactly as it appears on the Junkcoin network so the guest can hash it
/// byte-for-byte without re-serialization ambiguity.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlockHeader {
    /// The 80 consensus bytes (version | prev | merkle_root | time | bits | nonce).
    /// `Vec<u8>` (not `[u8; 80]`) because serde only derives arrays up to len 32;
    /// invariant: `raw.len() == 80`, enforced by the guest before use.
    pub raw: Vec<u8>,
    /// AuxPoW witness — Junkcoin is merge-mined, so the *parent* block holds the
    /// scrypt PoW and commits to this header. Required for PoW verification; `None`
    /// only for non-AuxPoW fixtures. See [`verify_auxpow_commitment`].
    #[serde(default)]
    pub aux: Option<AuxPow>,
}

impl BlockHeader {
    /// Panics if the header is not exactly 80 bytes (guest asserts this up front).
    pub fn assert_len(&self) {
        assert_eq!(self.raw.len(), 80, "block header must be 80 bytes");
    }

    /// Block version, little-endian at offset 0..4.
    pub fn version(&self) -> u32 {
        u32::from_le_bytes([self.raw[0], self.raw[1], self.raw[2], self.raw[3]])
    }
    /// AuxPoW chain id = `version >> 16` (JunkCoin's merge-mining chain identifier).
    pub fn chain_id(&self) -> u32 {
        self.version() >> 16
    }
    /// `nBits` compact difficulty target, little-endian at offset 72..76.
    pub fn bits(&self) -> u32 {
        u32::from_le_bytes([self.raw[72], self.raw[73], self.raw[74], self.raw[75]])
    }
    /// Previous block hash (raw little-endian, offset 4..36).
    pub fn prev_hash(&self) -> [u8; 32] {
        let mut h = [0u8; 32];
        h.copy_from_slice(&self.raw[4..36]);
        h
    }
    /// Transaction merkle root (raw little-endian, offset 36..68).
    pub fn merkle_root(&self) -> [u8; 32] {
        let mut h = [0u8; 32];
        h.copy_from_slice(&self.raw[36..68]);
        h
    }
}

/// One step of a Merkle inclusion path: a sibling hash and which side it is on.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct MerkleStep {
    pub sibling: [u8; 32],
    /// true = sibling is on the right (current node is the left child).
    pub left: bool,
}

/// Proof that a specific transaction is committed in a header's merkle root.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MerkleProof {
    /// double-SHA256 txid of the deposit transaction (raw little-endian).
    pub txid: [u8; 32],
    pub path: Vec<MerkleStep>,
}

/// Private + public inputs handed to the guest. Everything here is *witnessed*;
/// the guest re-derives and constrains it, then commits only the [`Journal`] or [`WithdrawalJournal`].
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProofInput {
    /// The aux chain's chain id (`nVersion >> 16`), e.g. 8224 for Junkcoin.
    /// The guest asserts every header carries this id and commits it to the
    /// journal, so the contract routes the proof to the right wrapped token.
    pub chain_id: u32,
    /// Hash of the on-chain checkpoint header the proof must descend from.
    /// The contract stores this; the guest proves the chain links back to it.
    pub checkpoint_hash: [u8; 32],
    /// Cumulative chain work already finalized at the checkpoint (big-endian U256).
    /// NOTE (I-03): the guest DELIBERATELY IGNORES this — it accumulates `proven_work` from
    /// ZERO across the proof's own window, so a witnessed seed cannot inflate the committed
    /// work (the contract gates that against `minProvenWork`). Kept only as advisory host
    /// context; it constrains nothing in-circuit. Do not "add" it to the committed work.
    pub checkpoint_chainwork: [u8; 32],
    /// Contiguous header chain from the block *after* the checkpoint up to and
    /// including the block that contains the deposit, then `min_confirmations`
    /// more headers burying it.
    pub headers: Vec<BlockHeader>,
    /// Index into `headers` of the block that contains the deposit tx.
    pub deposit_header_index: u32,
    /// Required confirmations (headers on top of the deposit block).
    pub min_confirmations: u32,
    /// Merkle inclusion proof of the deposit tx in `headers[deposit_header_index]`.
    pub merkle_proof: MerkleProof,
    /// The full raw deposit transaction bytes (so the guest can parse the
    /// destination P2PKH output and the OP_RETURN recipient binding).
    pub deposit_tx: Vec<u8>,
    /// The bridge custody P2PKH script-hash (HASH160) the deposit must pay to.
    pub custody_hash160: [u8; 20],
    /// The on-chain custody epoch in force; committed to the [`Journal`] so the contract
    /// rejects proofs produced against a rotated-out custody.
    pub custody_epoch: u64,
    /// Consensus proof-of-work limit (easiest allowed target) as compact `nBits`.
    /// Every header's target must be `<=` this. Committed into the [`Journal`] so
    /// the contract pins it (a prover cannot relax it). For the scrypt/AuxPoW
    /// family this is [`CHAIN_POW_LIMIT_BITS`] == [`LTC_POW_LIMIT_BITS`].
    pub pow_limit_bits: u32,
}


/// Solidity head-ABI word: a value right-aligned in 32 bytes.
fn word_from_be(bytes: &[u8]) -> [u8; 32] {
    let mut w = [0u8; 32];
    w[32 - bytes.len()..].copy_from_slice(bytes);
    w
}

/// One deposit entry within a [`Journal`].
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct DepositEntry {
    pub block_hash: [u8; 32],
    pub txid: [u8; 32],
    pub amount_sats: u64,
    pub recipient: [u8; 20],
}

/// Public outputs for a **per-transaction** peg-in proof. The guest verifies the
/// header chain ONCE (PSob: JKC sha256d linkage + AuxPoW commitments, ONE scrypt
/// on the LTC parent tip) and proves exactly ONE deposit's Merkle inclusion + tx
/// parse. The contract decodes this and mints a single entry.
///
/// ABI: 13 static words / 416 bytes (fixed layout — no dynamic members, no tail).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Journal {
    /// sha256d of the deposit block header (the block that includes `deposit_txid`).
    pub deposit_block_hash: [u8; 32],
    /// double-SHA256 txid of the deposit transaction.
    pub deposit_txid: [u8; 32],
    /// Sum of custody P2PKH outputs the deposit pays, in satoshis.
    pub amount_sats: u64,
    /// The EVM recipient bound in the deposit's OP_RETURN (address, right-aligned).
    pub recipient: [u8; 20],
    /// Number of headers burying the deposit block (headers after it, plus one).
    pub confirmations: u32,
    /// The on-chain checkpoint header this proof descends from.
    pub checkpoint_hash: [u8; 32],
    /// Consensus proof-of-work limit (easiest allowed target) as compact `nBits`.
    pub pow_limit_bits: u32,
    /// Total window work — the work of the single scrypt-verified LTC tip (PSob).
    pub proven_work: [u8; 32],
    /// The bridge custody P2PKH HASH160 the deposit paid to.
    pub custody_hash160: [u8; 20],
    /// The on-chain custody epoch in force when the proof was built.
    pub custody_epoch: u64,
    /// Aux chain id (`nVersion >> 16`) of the proven block chain — the contract
    /// requires it to match its configured chain.
    pub chain_id: u32,
}

impl Journal {
    /// ABI-encode exactly as the contract decodes `abi.decode(bytes, (Journal))`.
    /// All members are static, so the tuple encodes as its words back-to-back:
    ///
    ///   [0..32)    depositBlockHash
    ///   [32..64)   depositTxid
    ///   [64..96)   amountSats (u64 right-aligned)
    ///   [96..128)  recipient (address right-aligned)
    ///   [128..160) confirmations (left-padded)
    ///   [160..192) checkpointHash
    ///   [192..224) powLimitBits (left-padded)
    ///   [224..256) provenWork
    ///   [256..288) custodyHash160 (bytes20 left-aligned + 12 zero pad)
    ///   [288..320) custodyEpoch (right-aligned)
    ///   [320..352) chainId (left-padded u32)
    ///   [352..384) ltcCheckpointHash
    ///   [384..416) ltcTipHash
    ///
    /// 11 static words / 352 bytes.
    pub fn abi_encode(&self) -> [u8; 352] {
        let mut out = [0u8; 352];
        out[..32].copy_from_slice(&self.deposit_block_hash);
        out[32..64].copy_from_slice(&self.deposit_txid);
        // uint64 amount_sats, right-aligned in its word
        out[88..96].copy_from_slice(&self.amount_sats.to_be_bytes());
        // address recipient, right-aligned in its word (left-padded with 12 zero bytes)
        out[108..128].copy_from_slice(&self.recipient);
        // uint32 confirmations, left-padded
        out[156..160].copy_from_slice(&self.confirmations.to_be_bytes());
        out[160..192].copy_from_slice(&self.checkpoint_hash);
        // uint32 powLimitBits, left-padded
        out[220..224].copy_from_slice(&self.pow_limit_bits.to_be_bytes());
        out[224..256].copy_from_slice(&self.proven_work);
        // bytes20 custodyHash160, left-aligned then right-padded
        out[256..276].copy_from_slice(&self.custody_hash160);
        // uint64 custodyEpoch, right-aligned
        out[312..320].copy_from_slice(&self.custody_epoch.to_be_bytes());
        // uint32 chainId, left-padded
        out[348..352].copy_from_slice(&self.chain_id.to_be_bytes());
        out
    }

    /// Decode from the ABI-encoded bytes (inverse of [`Journal::abi_encode`]).
    pub fn abi_decode(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() != 352 {
            return Err("journal must be 352 bytes");
        }
        let arr32 = |o: usize| -> [u8; 32] {
            let mut a = [0u8; 32];
            a.copy_from_slice(&data[o..o + 32]);
            a
        };
        let mut deposit_block_hash = [0u8; 32];
        deposit_block_hash.copy_from_slice(&data[..32]);
        let mut deposit_txid = [0u8; 32];
        deposit_txid.copy_from_slice(&data[32..64]);
        let amount_sats = u64::from_be_bytes(data[88..96].try_into().unwrap());
        let mut recipient = [0u8; 20];
        recipient.copy_from_slice(&data[108..128]);
        let confirmations = u32::from_be_bytes(data[156..160].try_into().unwrap());
        let checkpoint_hash = arr32(160);
        let pow_limit_bits = u32::from_be_bytes(data[220..224].try_into().unwrap());
        let proven_work = arr32(224);
        let mut custody_hash160 = [0u8; 20];
        custody_hash160.copy_from_slice(&data[256..276]);
        let custody_epoch = u64::from_be_bytes(data[312..320].try_into().unwrap());
        let chain_id = u32::from_be_bytes(data[348..352].try_into().unwrap());
        Ok(Self {
            deposit_block_hash,
            deposit_txid,
            amount_sats,
            recipient,
            confirmations,
            checkpoint_hash,
            pow_limit_bits,
            proven_work,
            custody_hash160,
            custody_epoch,
            chain_id,
        })
    }
}

/// Public outputs of the WITHDRAWAL guest (trustless peg-out). Must stay field-for-field
/// identical to the Solidity `ZkBridge.WithdrawalJournal`. Proves a JKC payout (P2PKH to
/// `recipient_hash160` of `payout_sats`, plus `OP_RETURN <withdrawal_id>`) is buried under
/// PSob PoW from `checkpoint_hash` and the `ltc_checkpoint_hash` anchor.
/// ABI: 10 static words / 320 bytes.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct WithdrawalJournal {
    pub withdrawal_id: [u8; 32],
    pub recipient_hash160: [u8; 20],
    pub payout_sats: u64,
    pub checkpoint_hash: [u8; 32],
    pub confirmations: u32,
    pub pow_limit_bits: u32,
    pub proven_work: [u8; 32],
    /// Aux chain id (`nVersion >> 16`) the payout block belongs to. The contract
    /// requires it to match its configured chain.
    pub chain_id: u32,
}

impl WithdrawalJournal {
    /// ABI-encode exactly as the contract decodes `abi.decode(bytes, (WithdrawalJournal))`.
    /// Note `recipient_hash160` is a Solidity `bytes20` ⇒ **left-aligned** in its word
    /// (unlike an `address`, which is right-aligned). The guest commits these bytes.
    /// 8 static words / 256 bytes.
    pub fn abi_encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(256);
        out.extend_from_slice(&self.withdrawal_id);
        out.extend_from_slice(&self.recipient_hash160); // bytes20: left-aligned…
        out.extend_from_slice(&[0u8; 12]); // …then right-padded to a full word
        out.extend_from_slice(&word_from_be(&self.payout_sats.to_be_bytes()));
        out.extend_from_slice(&self.checkpoint_hash);
        out.extend_from_slice(&word_from_be(&self.confirmations.to_be_bytes()));
        out.extend_from_slice(&word_from_be(&self.pow_limit_bits.to_be_bytes()));
        out.extend_from_slice(&self.proven_work);
        out.extend_from_slice(&word_from_be(&self.chain_id.to_be_bytes()));
        out
    }

    /// Inverse of [`WithdrawalJournal::abi_encode`].
    pub fn abi_decode(data: &[u8]) -> Result<Self, &'static str> {
        if data.len() != 256 {
            return Err("withdrawal journal must be 256 bytes");
        }
        let arr32 = |o: usize| -> [u8; 32] {
            let mut a = [0u8; 32];
            a.copy_from_slice(&data[o..o + 32]);
            a
        };
        let mut recipient_hash160 = [0u8; 20];
        recipient_hash160.copy_from_slice(&data[32..52]); // bytes20 left-aligned in word 1
        Ok(WithdrawalJournal {
            withdrawal_id: arr32(0),
            recipient_hash160,
            payout_sats: u64::from_be_bytes(data[88..96].try_into().unwrap()),
            checkpoint_hash: arr32(96),
            confirmations: u32::from_be_bytes(data[156..160].try_into().unwrap()),
            pow_limit_bits: u32::from_be_bytes(data[188..192].try_into().unwrap()),
            proven_work: arr32(192),
            chain_id: u32::from_be_bytes(data[252..256].try_into().unwrap()),
        })
    }
}

// ─── 256-bit big-endian chainwork arithmetic (T5) ─────────────────────────────
// Cumulative proof-of-work lets the contract pick the heaviest valid fork. Per
// header, work = floor(2^256 / (target + 1)). We use Bitcoin Core's identity
//     work = (~target) / (target + 1) + 1
// which stays within 256 bits (2^256 itself does not fit). All values are stored
// big-endian so they match the `bits`-derived target layout used by the guest.

/// `acc += addend`, wrapping (cumulative chainwork cannot realistically overflow
/// 2^256). Big-endian.
pub fn u256_add_be(acc: &mut [u8; 32], addend: &[u8; 32]) {
    let mut carry = 0u16;
    for i in (0..32).rev() {
        let s = acc[i] as u16 + addend[i] as u16 + carry;
        acc[i] = (s & 0xff) as u8;
        carry = s >> 8;
    }
}

/// Per-header work = floor(2^256 / (target + 1)), big-endian.
pub fn block_work(target_be: &[u8; 32]) -> [u8; 32] {
    let (denom, denom_overflow) = u256_add_one(target_be);
    if denom_overflow {
        // target == 2^256 - 1  ⇒  work == floor(2^256 / 2^256) == 1.
        let mut one = [0u8; 32];
        one[31] = 1;
        return one;
    }
    let mut num = *target_be;
    for b in num.iter_mut() {
        *b = !*b; // ~target
    }
    let (q, _r) = u256_divmod(&num, &denom);
    let (work, _overflow) = u256_add_one(&q);
    work
}

/// `value + 1`, big-endian, returning the wrapped result and whether it carried
/// out of the top bit (only when value == 2^256 - 1).
fn u256_add_one(value: &[u8; 32]) -> ([u8; 32], bool) {
    let mut out = *value;
    for byte in out.iter_mut().rev() {
        let (v, carry) = byte.overflowing_add(1);
        *byte = v;
        if !carry {
            return (out, false);
        }
    }
    (out, true)
}

/// Shift a big-endian 256-bit number left by one bit, in place.
fn u256_shl1(v: &mut [u8; 32]) {
    let mut carry = 0u8;
    for byte in v.iter_mut().rev() {
        let new_carry = *byte >> 7;
        *byte = (*byte << 1) | carry;
        carry = new_carry;
    }
}

/// `a >= b` for big-endian 256-bit numbers.
fn u256_ge(a: &[u8; 32], b: &[u8; 32]) -> bool {
    for i in 0..32 {
        if a[i] != b[i] {
            return a[i] > b[i];
        }
    }
    true
}

/// `a -= b`, big-endian. Caller guarantees `a >= b`.
fn u256_sub(a: &mut [u8; 32], b: &[u8; 32]) {
    let mut borrow = 0i16;
    for i in (0..32).rev() {
        let diff = a[i] as i16 - b[i] as i16 - borrow;
        if diff < 0 {
            a[i] = (diff + 256) as u8;
            borrow = 1;
        } else {
            a[i] = diff as u8;
            borrow = 0;
        }
    }
}

/// Schoolbook bit-at-a-time long division of big-endian 256-bit integers.
/// Returns `(quotient, remainder)`. Panics on divide-by-zero.
fn u256_divmod(num: &[u8; 32], den: &[u8; 32]) -> ([u8; 32], [u8; 32]) {
    assert!(*den != [0u8; 32], "u256 divide by zero");
    let mut q = [0u8; 32];
    let mut r = [0u8; 32];
    for i in 0..256 {
        u256_shl1(&mut r);
        let byte = i / 8;
        let bit = 7 - (i % 8);
        if (num[byte] >> bit) & 1 == 1 {
            r[31] |= 1;
        }
        if u256_ge(&r, den) {
            u256_sub(&mut r, den);
            q[byte] |= 1 << bit;
        }
    }
    (q, r)
}

// ─── PoW target expansion + range check (consensus CheckProofOfWork) ──────────
// Junkcoin Core `CheckProofOfWork` rejects a header whose compact `nBits` decodes
// to a negative, zero, or overflowing target, OR a target above `powLimit`. The
// guest previously expanded `nBits` without any of these checks, so a prover could
// pick an arbitrarily easy (or malformed) target and bury a fake deposit cheaply.
// `expand_target` ports `arith_uint256::SetCompact` including its validity rules.

/// Expand compact `nBits` into a 256-bit big-endian target, returning `None` for
/// any encoding consensus treats as invalid PoW: the sign bit set (negative), a
/// zero mantissa (zero target), or an overflowing size. Mirrors Bitcoin/Junkcoin
/// `arith_uint256::SetCompact`'s `fNegative`/`fOverflow`/zero handling.
pub fn expand_target(bits: u32) -> Option<[u8; 32]> {
    let size = (bits >> 24) as usize;
    let word = bits & 0x007f_ffff;
    // Zero target is never valid PoW (also disambiguates negative/overflow).
    if word == 0 {
        return None;
    }
    // Sign bit set ⇒ negative target ⇒ invalid.
    if bits & 0x0080_0000 != 0 {
        return None;
    }
    // Overflow: the mantissa would extend past the 256-bit word.
    if size > 34 || (word > 0xff && size > 33) || (word > 0xffff && size > 32) {
        return None;
    }
    let mut target = [0u8; 32];
    if size <= 3 {
        let w = word >> (8 * (3 - size));
        target[29] = (w >> 16) as u8;
        target[30] = (w >> 8) as u8;
        target[31] = w as u8;
    } else {
        // The mantissa's least-significant byte sits at big-endian index `34 - size`.
        // For size 33/34 the higher mantissa bytes fall off the low end of the array
        // (negative index); the overflow guard above guarantees those bytes are zero,
        // so skipping them matches Bitcoin Core's `SetCompact` (which shifts them out)
        // instead of panicking on an index underflow.
        let lsb = 34 - size;
        target[lsb] = word as u8;
        if lsb >= 1 {
            target[lsb - 1] = (word >> 8) as u8;
        }
        if lsb >= 2 {
            target[lsb - 2] = (word >> 16) as u8;
        }
    }
    Some(target)
}

/// `a <= b` for big-endian 256-bit numbers (e.g. target vs powLimit).
pub fn target_leq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    for i in 0..32 {
        if a[i] != b[i] {
            return a[i] < b[i];
        }
    }
    true
}

// ─── PSob (Proof-of-Sibling) chain verification ────────────────────────────────
// The Proof-of-Sibling technique proves that a JKC block is a "sibling" committed
// within the coinbase of an AuxPoW parent block. This function verifies the JKC 
// chain linkages and the AuxPoW commitments for every header.
//
// The caller (guest) is responsible for then running `scrypt` on the parent block
// of every header to verify its proof-of-work and accumulate the total work.

/// Verify the PSob chain witness without any scrypt. Checks, in order:
///
///   1. `headers` is a contiguous chain descending from `checkpoint_hash`
///      (double-SHA256 prev-hash linkage), every header is 80 bytes, carries
///      `chain_id`, has a valid `nBits` (consensus range + `<= pow_limit`), and a
///      valid AuxPoW commitment (merkle folds + anti-grind — no scrypt);
///   2. every header's LTC parent (from its AuxPoW) is 80 bytes;
///
/// The caller (guest) then verifies `scrypt(aux.parent_header) <= expand_target(bits)`
/// for every header in the chain.
pub fn verify_psob_chain(
    headers: &[BlockHeader],
    checkpoint_hash: &[u8; 32],
    chain_id: u32,
    pow_limit_bits: u32,
) -> Result<(), &'static str> {
    if headers.is_empty() {
        return Err("empty header chain");
    }
    let pow_limit = expand_target(pow_limit_bits).ok_or("invalid pow_limit_bits encoding")?;

    // 1. JKC chain: linkage + per-header consensus checks + AuxPoW commitments.
    let mut parents: Vec<&[u8]> = Vec::with_capacity(headers.len());
    let mut prev_expected = *checkpoint_hash;
    for header in headers {
        if header.raw.len() != 80 {
            return Err("block header must be 80 bytes");
        }
        if header.chain_id() != chain_id {
            return Err("header chain id mismatch");
        }
        if header.prev_hash() != prev_expected {
            return Err("broken header chain link");
        }
        let target = expand_target(header.bits()).ok_or("invalid nBits encoding")?;
        if !target_leq(&target, &pow_limit) {
            return Err("target easier than powLimit");
        }
        let id = sha256d(&header.raw);
        let aux = header.aux.as_ref().ok_or("auxpow witness required for PoW")?;
        if !verify_auxpow_commitment(&id, aux, chain_id) {
            return Err("auxpow commitment invalid");
        }
        if aux.parent_header.len() != 80 {
            return Err("parent header must be 80 bytes");
        }
        parents.push(&aux.parent_header);
        prev_expected = id;
    }

    Ok(())
}

// ─── Deposit transaction parsing (structure-aware) ────────────────────────────
// SECURITY: this MUST walk the real legacy-tx structure and inspect only *output*
// scriptPubKeys. The previous implementation byte-scanned the whole tx for the
// custody P2PKH / OP_RETURN patterns, so an attacker could embed those bytes in an
// input scriptSig or an unrelated OP_RETURN payload — making the guest mint an
// attacker-chosen amount with NO real payment to custody (a total break of
// trustless minting). Junkcoin has no SegWit, so every tx is the legacy
// `version | vin[] | vout[] | locktime` form.

/// Read a Bitcoin CompactSize varint at `p`; returns `(value, next_pos)` or `None`
/// if the buffer is too short.
fn read_varint(tx: &[u8], p: usize) -> Option<(u64, usize)> {
    match *tx.get(p)? {
        0xfd => {
            let b = tx.get(p + 1..p + 3)?;
            Some((u16::from_le_bytes([b[0], b[1]]) as u64, p + 3))
        }
        0xfe => {
            let b = tx.get(p + 1..p + 5)?;
            Some((u32::from_le_bytes([b[0], b[1], b[2], b[3]]) as u64, p + 5))
        }
        0xff => {
            let b = tx.get(p + 1..p + 9)?;
            Some((u64::from_le_bytes(b.try_into().ok()?), p + 9))
        }
        n => Some((n as u64, p + 1)),
    }
}

/// Parse a legacy (non-SegWit) Junkcoin transaction and return
/// `(sats_paid_to_custody, evm_recipient_from_op_return)`.
///
/// Returns `None` unless the bytes parse as **exactly one** well-formed legacy tx
/// (consuming every byte through the locktime), at least one *output* pays the
/// custody P2PKH `OP_DUP OP_HASH160 <custody> OP_EQUALVERIFY OP_CHECKSIG`, and at
/// least one *output* is `OP_RETURN <20-byte recipient>`. Custody output values are
/// summed; the first qualifying OP_RETURN supplies the recipient. Input scriptSigs
/// are skipped, never inspected — they cannot influence the parsed amount/recipient.
pub fn parse_deposit_outputs(tx: &[u8], custody_hash160: &[u8; 20]) -> Option<(u64, [u8; 20])> {
    let mut p = 4usize; // skip version
    if p > tx.len() {
        return None;
    }
    let (vin_count, np) = read_varint(tx, p)?;
    p = np;
    if vin_count == 0 {
        return None; // 0 inputs is not a valid tx (also rejects SegWit 0x00 marker)
    }
    // Reject a COINBASE deposit: a coinbase is the block's single generation input with a
    // null prevout (all-zero txid + 0xffffffff vout). Its outputs pay newly minted coins
    // that are (a) subject to 100-block spend maturity — custody could not spend them for
    // ~100 blocks after we minted the wrapped token — and (b) the most reorg-sensitive tx in a block, so
    // a deep reorg after mint would leave the wrapped token unbacked. Real deposits are ordinary
    // spends; there is no legitimate reason to peg in a coinbase.
    let mut coinbase_prevout = false;
    for i in 0..vin_count {
        if i == 0 {
            let txid = tx.get(p..p + 32)?;
            let vout = u32::from_le_bytes(tx.get(p + 32..p + 36)?.try_into().ok()?);
            coinbase_prevout = vout == 0xffff_ffff && txid.iter().all(|&b| b == 0);
        }
        p = p.checked_add(36)?; // prevout: 32-byte txid + 4-byte vout
        if p > tx.len() {
            return None;
        }
        let (slen, np) = read_varint(tx, p)?;
        p = np.checked_add(slen as usize)?; // skip scriptSig
        p = p.checked_add(4)?; // sequence
        if p > tx.len() {
            return None;
        }
    }
    if vin_count == 1 && coinbase_prevout {
        return None; // coinbase deposit — immature + maximally reorg-sensitive
    }
    let (vout_count, np) = read_varint(tx, p)?;
    p = np;
    if vout_count == 0 {
        return None;
    }
    let mut custody_sats: u64 = 0;
    let mut recipient: Option<[u8; 20]> = None;
    for _ in 0..vout_count {
        let value = u64::from_le_bytes(tx.get(p..p + 8)?.try_into().ok()?);
        p += 8;
        let (slen, np) = read_varint(tx, p)?;
        p = np;
        let end = p.checked_add(slen as usize)?;
        let script = tx.get(p..end)?;
        p = end;
        if script.len() == 25
            && script[0] == 0x76
            && script[1] == 0xa9
            && script[2] == 0x14
            && script[23] == 0x88
            && script[24] == 0xac
            && &script[3..23] == custody_hash160
        {
            custody_sats = custody_sats.checked_add(value)?;
        } else if recipient.is_none()
            && ((script.len() == 22 && script[0] == 0x6a && script[1] == 0x14)
                || (script.len() == 24
                    && script[0] == 0x6a
                    && script[1] == 0x16
                    && script[2] == 0x6a
                    && script[3] == 0x14))
        {
            let mut r = [0u8; 20];
            let offset = if script.len() == 22 { 2 } else { 4 };
            r.copy_from_slice(&script[offset..(offset + 20)]);
            recipient = Some(r);
        }
    }
    p = p.checked_add(4)?; // locktime
    if p != tx.len() {
        return None; // trailing bytes ⇒ not a single clean legacy tx
    }
    if custody_sats == 0 {
        return None; // no payment to custody
    }
    Some((custody_sats, recipient?))
}

/// Parse a legacy (non-SegWit) Junkcoin **payout** transaction and return
/// `(sats_paid_to_recipient, withdrawal_id_from_op_return)` — the structure-aware dual of
/// [`parse_deposit_outputs`] for the trustless peg-out. Returns `None` unless the bytes
/// parse as **exactly one** well-formed legacy tx, at least one *output* pays the
/// `recipient_hash160` P2PKH, and at least one *output* is `OP_RETURN <32-byte withdrawalId>`
/// (`6a 20 <32>`). The first qualifying payout and the first OP_RETURN binding are taken.
/// Only OUTPUT scriptPubKeys are inspected; input scriptSigs cannot forge a payout.
pub fn parse_withdrawal_outputs(tx: &[u8], recipient_hash160: &[u8; 20]) -> Option<(u64, [u8; 32])> {
    let mut p = 4usize; // skip version
    if p > tx.len() {
        return None;
    }
    let (vin_count, np) = read_varint(tx, p)?;
    p = np;
    if vin_count == 0 {
        return None; // 0 inputs is not a valid tx (also rejects SegWit 0x00 marker)
    }
    for _ in 0..vin_count {
        p = p.checked_add(36)?; // prevout
        if p > tx.len() {
            return None;
        }
        let (slen, np) = read_varint(tx, p)?;
        p = np.checked_add(slen as usize)?; // skip scriptSig
        p = p.checked_add(4)?; // sequence
        if p > tx.len() {
            return None;
        }
    }
    let (vout_count, np) = read_varint(tx, p)?;
    p = np;
    if vout_count == 0 {
        return None;
    }
    let mut payout: Option<u64> = None;
    let mut withdrawal_id: Option<[u8; 32]> = None;
    for _ in 0..vout_count {
        let value = u64::from_le_bytes(tx.get(p..p + 8)?.try_into().ok()?);
        p += 8;
        let (slen, np) = read_varint(tx, p)?;
        p = np;
        let end = p.checked_add(slen as usize)?;
        let script = tx.get(p..end)?;
        p = end;
        if payout.is_none()
            && script.len() == 25
            && script[0] == 0x76
            && script[1] == 0xa9
            && script[2] == 0x14
            && script[23] == 0x88
            && script[24] == 0xac
            && &script[3..23] == recipient_hash160
        {
            payout = Some(value);
        } else if withdrawal_id.is_none() && script.len() == 34 && script[0] == 0x6a && script[1] == 0x20 {
            let mut w = [0u8; 32];
            w.copy_from_slice(&script[2..34]);
            withdrawal_id = Some(w);
        }
    }
    p = p.checked_add(4)?; // locktime
    if p != tx.len() {
        return None; // trailing bytes ⇒ not a single clean legacy tx
    }
    Some((payout?, withdrawal_id?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn be(hex_tail: &str) -> [u8; 32] {
        // right-aligned hex into a 32-byte big-endian buffer
        let bytes = hex::decode(hex_tail).expect("valid hex");
        let mut out = [0u8; 32];
        out[32 - bytes.len()..].copy_from_slice(&bytes);
        out
    }

    #[test]
    fn work_target_one_is_2_pow_255() {
        // target = 1 ⇒ work = floor(2^256 / 2) = 2^255 (top bit set).
        let mut expected = [0u8; 32];
        expected[0] = 0x80;
        assert_eq!(block_work(&be("01")), expected);
    }

    #[test]
    fn work_target_ffff_is_2_pow_240() {
        // target = 0xffff ⇒ work = floor(2^256 / 2^16) = 2^240.
        let mut expected = [0u8; 32];
        expected[1] = 0x01; // bit 240
        assert_eq!(block_work(&be("ffff")), expected);
    }

    #[test]
    fn work_target_all_ones_is_one() {
        let mut one = [0u8; 32];
        one[31] = 1;
        assert_eq!(block_work(&[0xff; 32]), one);
    }

    #[test]
    fn add_be_carries_across_bytes() {
        let mut acc = be("ff");
        u256_add_be(&mut acc, &be("01"));
        assert_eq!(acc, be("0100"));
    }

    #[test]
    fn divmod_basic() {
        // 0x100 / 0x10 = 0x10 rem 0
        let (q, r) = u256_divmod(&be("0100"), &be("10"));
        assert_eq!(q, be("10"));
        assert_eq!(r, [0u8; 32]);
        // 0x101 / 0x10 = 0x10 rem 1
        let (q, r) = u256_divmod(&be("0101"), &be("10"));
        assert_eq!(q, be("10"));
        assert_eq!(r, be("01"));
    }

    #[test]
    fn journal_abi_encode_layout() {
        // 13 static words / 416 bytes, fixed layout (no tail).
        let j = Journal {
            deposit_block_hash: [0x11; 32],
            deposit_txid: [0x22; 32],
            amount_sats: 0xdead_beef,
            recipient: [0xab; 20],
            confirmations: 7,
            checkpoint_hash: [0x33; 32],
            pow_limit_bits: 0x1e0f_ffff,
            proven_work: [0x44; 32],
            custody_hash160: [0x55; 20],
            custody_epoch: 3,
            chain_id: 0x2020,
            ltc_checkpoint_hash: [0x66; 32],
            ltc_tip_hash: [0x77; 32],
        };
        let enc = j.abi_encode();
        assert_eq!(enc.len(), 416);
        assert_eq!(&enc[..32], &[0x11u8; 32]);
        assert_eq!(&enc[32..64], &[0x22u8; 32]);
        // uint64 amountSats, right-aligned
        assert_eq!(&enc[64..88], &[0u8; 24]);
        assert_eq!(&enc[88..96], &0xdead_beefu64.to_be_bytes());
        // address recipient, right-aligned
        assert_eq!(&enc[96..108], &[0u8; 12]);
        assert_eq!(&enc[108..128], &[0xabu8; 20]);
        // uint32 confirmations, left-padded
        assert_eq!(&enc[128..156], &[0u8; 28]);
        assert_eq!(&enc[156..160], &7u32.to_be_bytes());
        assert_eq!(&enc[160..192], &[0x33u8; 32]);
        // uint32 powLimitBits, left-padded
        assert_eq!(&enc[192..220], &[0u8; 28]);
        assert_eq!(&enc[220..224], &0x1e0f_ffffu32.to_be_bytes());
        assert_eq!(&enc[224..256], &[0x44u8; 32]);
        // bytes20 custodyHash160, left-aligned then right-padded
        assert_eq!(&enc[256..276], &[0x55u8; 20]);
        assert_eq!(&enc[276..288], &[0u8; 12]);
        // uint64 custodyEpoch, right-aligned
        assert_eq!(&enc[288..312], &[0u8; 24]);
        assert_eq!(&enc[312..320], &3u64.to_be_bytes());
        // uint32 chainId, left-padded
        assert_eq!(&enc[320..348], &[0u8; 28]);
        assert_eq!(&enc[348..352], &0x2020u32.to_be_bytes());
        assert_eq!(&enc[352..384], &[0x66u8; 32]);
        assert_eq!(&enc[384..416], &[0x77u8; 32]);
    }

    // ─── PoW target expansion / range check ───────────────────────────────────
    #[test]
    fn expand_target_matches_powlimit_and_rejects_invalid() {
        // JKC powLimit 0x1e0fffff ⇒ 0x00000fffff000…0 (compact-clean target).
        let pl = expand_target(CHAIN_POW_LIMIT_BITS).expect("powlimit valid");
        assert_eq!(&pl[0..5], &[0x00, 0x00, 0x0f, 0xff, 0xff]);
        assert!(pl[5..].iter().all(|&b| b == 0));

        // Genesis target (0x1e0ffff0) is below powLimit.
        let g = expand_target(0x1e0f_fff0).expect("genesis valid");
        assert!(target_leq(&g, &pl));

        // Negative (sign bit), zero mantissa, and overflow are all rejected.
        assert_eq!(expand_target(0x1e80_0000 | 0x00ff_ffff), None); // sign bit set
        assert_eq!(expand_target(0x1d00_0000), None); // zero mantissa
        assert_eq!(expand_target(0xff7f_ffff), None); // size 0xff ⇒ overflow

        // An "easy" target above powLimit must NOT compare <= powLimit.
        let easy = expand_target(0x2000_ffff).expect("encodable");
        assert!(!target_leq(&easy, &pl));

        // Z2 regression: sizes 33/34 with a small mantissa previously panicked on an
        // index underflow. They must now expand cleanly (matching Core's SetCompact,
        // which shifts the off-array high bytes out) rather than panic. size 33: word at
        // big-endian bytes [0..1]; size 34: word at byte 0.
        let s33 = expand_target(0x2100_00ab).expect("size 33 encodable");
        assert_eq!(s33[1], 0xab);
        assert!(s33.iter().enumerate().all(|(i, &b)| i == 1 || b == 0));
        let s33b = expand_target(0x2100_12ab).expect("size 33 two-byte mantissa");
        assert_eq!(&s33b[0..2], &[0x12, 0xab]);
        let s34 = expand_target(0x2200_00ab).expect("size 34 encodable");
        assert_eq!(s34[0], 0xab);
        assert!(s34[1..].iter().all(|&b| b == 0));
        // size 34 with a >1-byte mantissa still overflows and is rejected.
        assert_eq!(expand_target(0x2200_01ab), None);
    }

    // ─── Structure-aware deposit parser ───────────────────────────────────────
    fn p2pkh_spk(h: &[u8; 20]) -> alloc::vec::Vec<u8> {
        let mut s = alloc::vec![0x76u8, 0xa9, 0x14];
        s.extend_from_slice(h);
        s.extend_from_slice(&[0x88, 0xac]);
        s
    }

    /// Minimal legacy tx: 1 input spending a real (non-coinbase) prevout, then the given
    /// outputs, locktime 0. The prevout txid is deliberately NON-null so the tx is not
    /// mistaken for a coinbase (a null prevout `[0;32]:0xffffffff` is a coinbase and is
    /// rejected by `parse_deposit_outputs`; only a coinbase may legally spend it).
    fn build_tx(outputs: &[(u64, alloc::vec::Vec<u8>)]) -> alloc::vec::Vec<u8> {
        let mut tx = alloc::vec::Vec::new();
        tx.extend_from_slice(&1u32.to_le_bytes()); // version
        tx.push(1); // 1 input
        tx.extend_from_slice(&[0x11u8; 32]); // prevout txid (non-null ⇒ ordinary spend)
        tx.extend_from_slice(&0u32.to_le_bytes()); // prevout vout
        tx.push(0); // empty scriptSig
        tx.extend_from_slice(&0xffff_ffffu32.to_le_bytes()); // sequence
        tx.push(outputs.len() as u8);
        for (val, spk) in outputs {
            tx.extend_from_slice(&val.to_le_bytes());
            tx.push(spk.len() as u8);
            tx.extend_from_slice(spk);
        }
        tx.extend_from_slice(&0u32.to_le_bytes()); // locktime
        tx
    }

    #[test]
    fn parse_deposit_real_tx_test() {
        let custody = hex::decode("21998e2ce990cfc033740d2d5cecd022f9704782").unwrap();
        let mut custody_hash160 = [0u8; 20];
        custody_hash160.copy_from_slice(&custody);
        let tx = hex::decode("0100000001e5e52f6792bb551016736f79b5f274342abe2df31ea1e5d222ebb5a671c7c5ce000000006b483045022100d90733b933d1e4241de865d3a7a4de896ef2c56c17e4e6bfd307904a5bead75d02205267e81d6dda431fa7575827b74842e73198da128f0c92fa3a6adbcaf486147401210371475384443cef0c683ae4ba621581d5c8ae102e56114fc9a6af0014ce3326c0ffffffff0300ca9a3b000000001976a91421998e2ce990cfc033740d2d5cecd022f970478288ac48649211000000001976a91499cf3561c3200eee36f8975be8ad980d1a22222988ac0000000000000000186a166a149583ca25ec7770b1d575d0c4c76b79ce257e664500000000").unwrap();
        let res = parse_deposit_outputs(&tx, &custody_hash160);
        println!("PARSE RESULT: {:?}", res);
        assert!(res.is_some());
    }

    #[test]
    fn parse_deposit_happy_path_and_sums_custody() {
        let custody = [0x11u8; 20];
        let evm = [0x22u8; 20];
        let mut opret = alloc::vec![0x6au8, 0x14];
        opret.extend_from_slice(&evm);
        // two custody outputs (must be summed) + recipient + an unrelated output
        let tx = build_tx(&[
            (300_000_000, p2pkh_spk(&custody)),
            (0, opret),
            (200_000_000, p2pkh_spk(&custody)),
            (1, p2pkh_spk(&[0x99u8; 20])),
        ]);
        let (amount, rcpt) = parse_deposit_outputs(&tx, &custody).expect("parses");
        assert_eq!(amount, 500_000_000);
        assert_eq!(rcpt, evm);
    }

    #[test]
    fn parse_deposit_rejects_custody_pattern_hidden_in_op_return() {
        // ATTACK: no real custody output. Instead an OP_RETURN payload embeds the
        // exact bytes <value><0x19><76 a9 14 custody 88 ac> the old byte-scanner
        // matched. A structure-aware parser must NOT see a custody payment here.
        let custody = [0x11u8; 20];
        let evm = [0x22u8; 20];
        let mut payload = alloc::vec::Vec::new();
        payload.extend_from_slice(&999_000_000u64.to_le_bytes()); // attacker "amount"
        payload.push(0x19); // scriptLen the old scanner keyed on
        payload.extend_from_slice(&p2pkh_spk(&custody)); // fake custody script
        // OP_RETURN with a 1-byte-pushdata-76 carrying the payload (len > 75 ⇒ 0x4c).
        let mut opret = alloc::vec![0x6au8, 0x4c, payload.len() as u8];
        opret.extend_from_slice(&payload);
        // plus a real recipient OP_RETURN, and the attacker pays themselves dust.
        let mut rcpt_opret = alloc::vec![0x6au8, 0x14];
        rcpt_opret.extend_from_slice(&evm);
        let tx = build_tx(&[
            (1, p2pkh_spk(&[0x99u8; 20])), // dust to attacker
            (0, opret),                    // fake custody bytes hidden here
            (0, rcpt_opret),
        ]);
        // No genuine custody output ⇒ None (old scanner would have minted 999 JKC).
        assert_eq!(parse_deposit_outputs(&tx, &custody), None);
    }

    #[test]
    fn parse_deposit_rejects_coinbase() {
        // A coinbase pays newly minted coins (100-block maturity, maximally reorg-sensitive)
        // so it must never mint the wrapped token, even if it pays custody + carries an OP_RETURN.
        let custody = [0x11u8; 20];
        let evm = [0x22u8; 20];
        let mut opret = alloc::vec![0x6au8, 0x14];
        opret.extend_from_slice(&evm);
        let outputs = alloc::vec![(500_000_000u64, p2pkh_spk(&custody)), (0u64, opret)];

        // Same body as `build_tx` but with the coinbase NULL prevout (all-zero txid,
        // vout 0xffffffff) and a non-empty coinbase scriptSig.
        let mut tx = alloc::vec::Vec::new();
        tx.extend_from_slice(&1u32.to_le_bytes()); // version
        tx.push(1); // single (generation) input
        tx.extend_from_slice(&[0u8; 32]); // NULL prevout txid
        tx.extend_from_slice(&0xffff_ffffu32.to_le_bytes()); // NULL prevout vout
        tx.push(3); // coinbase scriptSig (arbitrary)
        tx.extend_from_slice(&[0x03, 0xab, 0xcd]);
        tx.extend_from_slice(&0xffff_ffffu32.to_le_bytes()); // sequence
        tx.push(outputs.len() as u8);
        for (val, spk) in &outputs {
            tx.extend_from_slice(&val.to_le_bytes());
            tx.push(spk.len() as u8);
            tx.extend_from_slice(spk);
        }
        tx.extend_from_slice(&0u32.to_le_bytes()); // locktime

        assert_eq!(parse_deposit_outputs(&tx, &custody), None);
    }

    #[test]
    fn parse_deposit_rejects_trailing_bytes_and_missing_recipient() {
        let custody = [0x11u8; 20];
        // missing OP_RETURN recipient
        let tx = build_tx(&[(500_000_000, p2pkh_spk(&custody))]);
        assert_eq!(parse_deposit_outputs(&tx, &custody), None);
        // trailing garbage after a valid tx
        let mut opret = alloc::vec![0x6au8, 0x14];
        opret.extend_from_slice(&[0x22u8; 20]);
        let mut tx2 = build_tx(&[(500_000_000, p2pkh_spk(&custody)), (0, opret)]);
        tx2.push(0xde);
        assert_eq!(parse_deposit_outputs(&tx2, &custody), None);
    }

    // ─── Withdrawal (peg-out) payout parser + journal ──────────────────────────
    fn op_return32(wid: &[u8; 32]) -> alloc::vec::Vec<u8> {
        let mut s = alloc::vec![0x6au8, 0x20];
        s.extend_from_slice(wid);
        s
    }

    #[test]
    fn parse_withdrawal_happy_path() {
        let recipient = [0x33u8; 20];
        let wid = [0x44u8; 32];
        let tx = build_tx(&[
            (450_000_000, p2pkh_spk(&recipient)),  // payout to user
            (0, op_return32(&wid)),                // withdrawalId binding
            (10_000_000, p2pkh_spk(&[0x99u8; 20])),// change back to custody
        ]);
        let (payout, got) = parse_withdrawal_outputs(&tx, &recipient).expect("parses");
        assert_eq!(payout, 450_000_000);
        assert_eq!(got, wid);
    }

    #[test]
    fn parse_withdrawal_rejects_missing_binding_or_recipient() {
        let recipient = [0x33u8; 20];
        // missing OP_RETURN withdrawalId
        let tx = build_tx(&[(450_000_000, p2pkh_spk(&recipient))]);
        assert_eq!(parse_withdrawal_outputs(&tx, &recipient), None);
        // pays a different recipient (no payout to ours)
        let tx2 = build_tx(&[(450_000_000, p2pkh_spk(&[0x77u8; 20])), (0, op_return32(&[0x44u8; 32]))]);
        assert_eq!(parse_withdrawal_outputs(&tx2, &recipient), None);
    }

    #[test]
    fn withdrawal_journal_abi_layout_and_roundtrip() {
        let j = WithdrawalJournal {
            withdrawal_id: [0x11; 32],
            recipient_hash160: [0xab; 20],
            payout_sats: 0xdead_beef,
            checkpoint_hash: [0x33; 32],
            confirmations: 7,
            pow_limit_bits: 0x1e0f_ffff,
            proven_work: [0x44; 32],
            chain_id: 0x2020,
            ltc_checkpoint_hash: [0x55; 32],
            ltc_tip_hash: [0x66; 32],
        };
        let enc = j.abi_encode();
        assert_eq!(enc.len(), 320);
        assert_eq!(&enc[0..32], &[0x11u8; 32]);
        assert_eq!(&enc[32..52], &[0xabu8; 20]); // bytes20 LEFT-aligned
        assert_eq!(&enc[52..64], &[0u8; 12]);
        assert_eq!(&enc[88..96], &0xdead_beefu64.to_be_bytes());
        assert_eq!(&enc[96..128], &[0x33u8; 32]);
        assert_eq!(&enc[156..160], &7u32.to_be_bytes());
        assert_eq!(&enc[188..192], &0x1e0f_ffffu32.to_be_bytes());
        assert_eq!(&enc[192..224], &[0x44u8; 32]);
        // uint32 chainId, left-padded
        assert_eq!(&enc[224..252], &[0u8; 28]);
        assert_eq!(&enc[252..256], &0x2020u32.to_be_bytes());
        assert_eq!(&enc[256..288], &[0x55u8; 32]);
        assert_eq!(&enc[288..320], &[0x66u8; 32]);
        assert_eq!(WithdrawalJournal::abi_decode(&enc).unwrap(), j);
    }

    #[test]
    fn auxpow_commitment_verifies_and_rejects_tampering() {
        // Build a structurally-valid AuxPoW by hand, to JunkCoin Core parity.
        let aux_block_hash = [0x11u8; 32];
        let chain_id = 0x2020u32;
        let nonce = 0x1234_5678u32;
        let height = 3usize; // 3-deep chain tree ⇒ size 8
        // The chain_index is PINNED by (nonce, chain_id, height) — derive it.
        let chain_index = get_expected_index(nonce, chain_id, height as u32);

        let chain_branch = alloc::vec![[0x22u8; 32], [0x23u8; 32], [0x24u8; 32]];
        let chain_root = merkle_fold_branch(&aux_block_hash, &chain_branch, chain_index);
        let mut committed = chain_root;
        committed.reverse();

        // coinbase: prefix ‖ magic ‖ root ‖ size(=2^height) ‖ nonce ‖ tail
        let mut coinbase = alloc::vec![0xde, 0xad];
        coinbase.extend_from_slice(&AUXPOW_MAGIC);
        coinbase.extend_from_slice(&committed);
        coinbase.extend_from_slice(&(1u32 << height).to_le_bytes());
        coinbase.extend_from_slice(&nonce.to_le_bytes());
        coinbase.extend_from_slice(&[0u8; 4]);

        // parent side: coinbase txid folded with one sibling, index 0.
        let cb_txid = sha256d(&coinbase);
        let parent_sib = [0x33u8; 32];
        let parent_root = merkle_fold_branch(&cb_txid, &[parent_sib], 0);
        let mut parent_header = alloc::vec![0u8; 80];
        parent_header[36..68].copy_from_slice(&parent_root);

        let aux = AuxPow {
            coinbase_tx: coinbase.clone(),
            parent_merkle_branch: alloc::vec![parent_sib],
            parent_index: 0,
            chain_merkle_branch: chain_branch,
            chain_index,
            parent_header,
        };

        assert!(verify_auxpow_commitment(&aux_block_hash, &aux, chain_id));
        // A different aux block is not committed by this coinbase.
        assert!(!verify_auxpow_commitment(&[0x99u8; 32], &aux, chain_id));

        // Anti-grind: under a different chain_id the pinned slot differs, so the
        // same commitment is rejected (getExpectedIndex mismatch).
        let mut other = chain_id ^ 0x1;
        while get_expected_index(nonce, other, height as u32) == chain_index {
            other = other.wrapping_add(1);
        }
        assert!(!verify_auxpow_commitment(&aux_block_hash, &aux, other));

        // Strict chain id: a parent header whose own chain id equals ours is rejected
        // (a chain may not merge-mine itself). Set parent version = chain_id << 16.
        let mut self_mined = aux.clone();
        self_mined.parent_header[0..4].copy_from_slice(&(chain_id << 16).to_le_bytes());
        assert!(!verify_auxpow_commitment(&aux_block_hash, &self_mined, chain_id));
        let _ = &coinbase;
    }

    // ─── Journal tests ───────────────────────────────────────────────────────
    #[test]
    fn journal_abi_roundtrip() {
        let j = Journal {
            deposit_block_hash: [0x11; 32],
            deposit_txid: [0x22; 32],
            amount_sats: 100_000_000,
            recipient: [0xab; 20],
            confirmations: 20,
            checkpoint_hash: [0x33; 32],
            pow_limit_bits: 0x1e0f_ffff,
            proven_work: [0x44; 32],
            custody_hash160: [0x55; 20],
            custody_epoch: 1,
            chain_id: 0x2020,
            ltc_checkpoint_hash: [0x56; 32],
            ltc_tip_hash: [0x57; 32],
        };
        let enc = j.abi_encode();
        let decoded = Journal::abi_decode(&enc).unwrap();
        assert_eq!(decoded, j);
    }

    #[test]
    fn journal_abi_decode_rejects_bad_length() {
        assert!(Journal::abi_decode(&[0u8; 415]).is_err());
        assert!(Journal::abi_decode(&[0u8; 417]).is_err());
        assert!(Journal::abi_decode(&[0u8; 416]).is_ok());
    }

    // ─── PSob chain verification tests ───────────────────────────────────────
    /// Build a self-consistent PSob witness: `n` JKC headers chained from the JKC
    /// checkpoint, each committed by a coinbase in its own LTC parent; the LTC
    /// parents chained from `ltc_checkpoint_hash` with a gap-filler inserted
    /// between parent 0 and parent 1 (so the chain is longer than the parents).
    fn psob_fixture(n: usize) -> (alloc::vec::Vec<BlockHeader>, alloc::vec::Vec<BlockHeader>, [u8; 32], [u8; 32]) {
        let chain_id = 0x2020u32;
        let bits = CHAIN_POW_LIMIT_BITS;
        let checkpoint = [0x33u8; 32];
        let ltc_checkpoint = [0x44u8; 32];

        let mut headers = alloc::vec::Vec::new();
        let mut parents = alloc::vec::Vec::new();
        let mut prev = checkpoint;
        let mut ltc_prev = ltc_checkpoint;

        for i in 0..n {
            let mut hdr = alloc::vec![0u8; 80];
            hdr[0..4].copy_from_slice(&((chain_id << 16) | 1).to_le_bytes());
            hdr[4..36].copy_from_slice(&prev);
            hdr[36..68].copy_from_slice(&[0xaa; 32]); // merkle root (unused here)
            hdr[72..76].copy_from_slice(&bits.to_le_bytes());
            let id = sha256d(&hdr);

            // LTC parent commits this JKC block in its coinbase.
            let mut committed = id;
            committed.reverse();
            let mut coinbase = alloc::vec![0xde, 0xad];
            coinbase.extend_from_slice(&AUXPOW_MAGIC);
            coinbase.extend_from_slice(&committed);
            coinbase.extend_from_slice(&1u32.to_le_bytes()); // size = 2^0
            coinbase.extend_from_slice(&0u32.to_le_bytes()); // nonce
            coinbase.push(0xcc);
            let cb_txid = sha256d(&coinbase);

            if i == 1 {
                // gap-filler LTC block between parent 0 and parent 1
                let mut filler = alloc::vec![0u8; 80];
                filler[4..36].copy_from_slice(&ltc_prev);
                filler[72..76].copy_from_slice(&bits.to_le_bytes());
                ltc_prev = sha256d(&filler);
                parents.push(BlockHeader { raw: filler, aux: None });
            }

            let mut parent = alloc::vec![0u8; 80];
            parent[4..36].copy_from_slice(&ltc_prev);
            parent[36..68].copy_from_slice(&cb_txid);
            parent[72..76].copy_from_slice(&bits.to_le_bytes());

            headers.push(BlockHeader {
                raw: hdr,
                aux: Some(AuxPow {
                    coinbase_tx: coinbase,
                    parent_merkle_branch: alloc::vec![],
                    parent_index: 0,
                    chain_merkle_branch: alloc::vec![],
                    chain_index: 0,
                    parent_header: parent.clone(),
                }),
            });
            parents.push(BlockHeader { raw: parent, aux: None });
            prev = id;
            ltc_prev = sha256d(&parents.last().unwrap().raw);
        }
        (headers, parents, checkpoint, ltc_checkpoint)
    }

    #[test]
    fn psob_chain_verifies_with_gap_filler() {
        let (headers, parents, checkpoint, ltc_checkpoint) = psob_fixture(3);
        let out = verify_psob_chain(&headers, &checkpoint, &parents, &ltc_checkpoint, 0x2020, CHAIN_POW_LIMIT_BITS)
            .expect("valid PSob chain");
        let tip_target = expand_target(CHAIN_POW_LIMIT_BITS).unwrap();
        assert_eq!(out.ltc_tip_hash, sha256d(&parents.last().unwrap().raw));
        assert_eq!(out.ltc_tip_target, tip_target);
        assert_eq!(out.proven_work, block_work(&tip_target));
    }

    #[test]
    fn psob_chain_rejects_broken_jkc_link() {
        let (mut headers, parents, checkpoint, ltc_checkpoint) = psob_fixture(2);
        headers[1].raw[4..36].copy_from_slice(&[0x99; 32]); // break prev-hash link
        assert!(verify_psob_chain(&headers, &checkpoint, &parents, &ltc_checkpoint, 0x2020, CHAIN_POW_LIMIT_BITS).is_err());
    }

    #[test]
    fn psob_chain_rejects_missing_aux_or_wrong_chain_id() {
        let (mut headers, parents, checkpoint, ltc_checkpoint) = psob_fixture(2);
        // missing aux witness
        headers[0].aux = None;
        assert!(verify_psob_chain(&headers, &checkpoint, &parents, &ltc_checkpoint, 0x2020, CHAIN_POW_LIMIT_BITS).is_err());
        // wrong chain id (fixture says 0x2020)
        let (headers, parents, checkpoint, ltc_checkpoint) = psob_fixture(2);
        assert!(verify_psob_chain(&headers, &checkpoint, &parents, &ltc_checkpoint, 0x2021, CHAIN_POW_LIMIT_BITS).is_err());
    }

    #[test]
    fn psob_chain_rejects_ltc_anchor_and_parent_linkage() {
        // wrong LTC checkpoint
        let (headers, parents, checkpoint, _) = psob_fixture(2);
        assert!(verify_psob_chain(&headers, &checkpoint, &parents, &[0x55; 32], 0x2020, CHAIN_POW_LIMIT_BITS).is_err());
        // parent chain must end at the last JKC block's parent
        let (headers, mut parents, checkpoint, ltc_checkpoint) = psob_fixture(2);
        parents.truncate(1);
        assert!(verify_psob_chain(&headers, &checkpoint, &parents, &ltc_checkpoint, 0x2020, CHAIN_POW_LIMIT_BITS).is_err());
        // a parent absent from the LTC chain: replace the first entry with a
        // bogus header that still chains from the anchor, so only the missing
        // parent inclusion check can fail.
        let (headers, parents, checkpoint, ltc_checkpoint) = psob_fixture(2);
        let mut wrong = alloc::vec![BlockHeader { raw: alloc::vec![0xde; 80], aux: None }];
        wrong.extend_from_slice(&parents[1..]);
        assert!(verify_psob_chain(&headers, &checkpoint, &wrong, &ltc_checkpoint, 0x2020, CHAIN_POW_LIMIT_BITS).is_err());
    }

    #[test]
    fn psob_chain_rejects_easy_tip_target() {
        // The tip's nBits at the LTC powLimit is the FLOOR; an easier target is
        // rejected (difficulty-bypass gate). Flip the tip to a relaxed target.
        let (headers, mut parents, checkpoint, ltc_checkpoint) = psob_fixture(2);
        parents.last_mut().unwrap().raw[72..76].copy_from_slice(&0x2000_ffffu32.to_le_bytes());
        assert!(verify_psob_chain(&headers, &checkpoint, &parents, &ltc_checkpoint, 0x2020, CHAIN_POW_LIMIT_BITS).is_err());
    }
}
