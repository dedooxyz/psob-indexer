//! the source chain peg-in data access (T4): build a [`common::ProofInput`] for the zkVM
//! guest from an Electrs (Esplora-style) REST node.
//!
//! The guest proves a contiguous scrypt-PoW header chain from the on-chain
//! checkpoint, burying the deposit by `min_confirmations`, plus the deposit tx's
//! merkle inclusion. This crate fetches exactly that witness:
//!   * raw 80-byte headers from `checkpoint_height+1` up to `deposit + (conf-1)`,
//!   * the deposit tx's merkle path (`/tx/:id/merkle-proof`),
//!   * the raw deposit tx (`/tx/:id/hex`).
//!
//! ── Endianness ──────────────────────────────────────────────────────────────
//! Electrs speaks display (big-endian) hex for txids and merkle hashes; the source chain
//! consensus (and the guest) work in raw little-endian. We reverse on the way in
//! so the guest's `sha256d` folding matches the header's stored merkle root.
//!
//! ── AuxPoW caveat ───────────────────────────────────────────────────────────
//! the source chain is merge-mined: `/block/:hash/header` returns the 80-byte header
//! followed by AuxPoW data, and the scrypt PoW is satisfied by the *parent* block.
//! We return the first 80 bytes (correct for header linking + target/bits). A guest
//! that verifies scrypt over these 80 bytes alone will reject real AuxPoW blocks —
//! closing that gap (verify parent PoW) is tracked separately for the ZK circuit.

use common::{AuxPow, BlockHeader, MerkleProof, MerkleStep, ProofInput};
use serde::Deserialize;
use sha2::{Digest, Sha256};

const HEADER_LEN: usize = 80;

// ─── AuxPoW (merged-mining) parsing ─────────────────────────────────────────────
// `/block/<hash>/header` returns the 80-byte coin header followed by the AuxPoW
// (CAuxPow) serialization. We parse it into a `common::AuxPow` witness so the PoW
// can be verified against the scrypt-mined parent block.

struct Cursor<'a> {
    b: &'a [u8],
    p: usize,
}

impl<'a> Cursor<'a> {
    fn at(b: &'a [u8], p: usize) -> Self {
        Cursor { b, p }
    }
    fn take(&mut self, n: usize) -> anyhow::Result<&'a [u8]> {
        let end = self.p.checked_add(n).ok_or_else(|| anyhow::anyhow!("overflow"))?;
        if end > self.b.len() {
            anyhow::bail!("auxpow truncated at {}..{} of {}", self.p, end, self.b.len());
        }
        let s = &self.b[self.p..end];
        self.p = end;
        Ok(s)
    }
    fn u32_le(&mut self) -> anyhow::Result<u32> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn hash32(&mut self) -> anyhow::Result<[u8; 32]> {
        let mut h = [0u8; 32];
        h.copy_from_slice(self.take(32)?);
        Ok(h)
    }
    fn varint(&mut self) -> anyhow::Result<u64> {
        let n = self.take(1)?[0];
        Ok(match n {
            0xff => u64::from_le_bytes(self.take(8)?.try_into().unwrap()),
            0xfe => u32::from_le_bytes(self.take(4)?.try_into().unwrap()) as u64,
            0xfd => u16::from_le_bytes(self.take(2)?.try_into().unwrap()) as u64,
            v => v as u64,
        })
    }
    /// Advance past one legacy (no-witness) transaction; returns its byte range.
    fn skip_tx(&mut self) -> anyhow::Result<()> {
        self.take(4)?; // version
        let nin = self.varint()?;
        for _ in 0..nin {
            self.take(36)?; // prevout
            let sl = self.varint()? as usize;
            self.take(sl)?; // scriptSig
            self.take(4)?; // sequence
        }
        let nout = self.varint()?;
        for _ in 0..nout {
            self.take(8)?; // value
            let sl = self.varint()? as usize;
            self.take(sl)?; // scriptPubKey
        }
        self.take(4)?; // locktime
        Ok(())
    }
    fn branch(&mut self) -> anyhow::Result<Vec<[u8; 32]>> {
        let n = self.varint()? as usize;
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            out.push(self.hash32()?);
        }
        Ok(out)
    }
}

/// Split a full `/block/:hash/header` response (80-byte header ‖ CAuxPow) into the
/// base header and the parsed [`AuxPow`] witness.
pub fn parse_auxpow(full: &[u8]) -> anyhow::Result<([u8; 80], AuxPow)> {
    if full.len() < HEADER_LEN {
        anyhow::bail!("header shorter than 80 bytes: {}", full.len());
    }
    let mut base = [0u8; 80];
    base.copy_from_slice(&full[..HEADER_LEN]);

    // CAuxPow = CMerkleTx(coinbase) ‖ chainMerkleBranch ‖ chainIndex ‖ parentHeader.
    let mut cur = Cursor::at(full, HEADER_LEN);
    let cb_start = cur.p;
    cur.skip_tx()?;
    let coinbase_tx = full[cb_start..cur.p].to_vec();
    let _parent_block_hash = cur.hash32()?; // CMerkleTx.hashBlock (unused)
    let parent_merkle_branch = cur.branch()?;
    let parent_index = cur.u32_le()?;
    let chain_merkle_branch = cur.branch()?;
    let chain_index = cur.u32_le()?;
    let parent_header = cur.take(HEADER_LEN)?.to_vec();

    Ok((
        base,
        AuxPow {
            coinbase_tx,
            parent_merkle_branch,
            parent_index,
            chain_merkle_branch,
            chain_index,
            parent_header,
        },
    ))
}

#[derive(Clone)]
pub struct ElectrsClient {
    base: String,
    http: reqwest::Client,
}

#[derive(Debug, Deserialize)]
struct MerkleProofResp {
    block_height: u64,
    merkle: Vec<String>,
    pos: usize,
}

/// Esplora tx confirmation status (subset).
#[derive(Debug, Clone, Deserialize)]
pub struct TxStatus {
    pub confirmed: bool,
    pub block_height: Option<u64>,
}

/// One entry of `/address/:addr/txs/chain` (confirmed history).
#[derive(Debug, Clone, Deserialize)]
pub struct AddrTx {
    pub txid: String,
    pub status: TxStatus,
}

/// A located peg-out payout transaction paying the withdrawal recipient and carrying
/// the `OP_RETURN <withdrawalId>` binding. Found by content, never by an expected
/// (malleable) txid — invariant #6.
#[derive(Debug, Clone)]
pub struct PayoutTx {
    /// Display (big-endian) txid, ready to feed to [`build_withdrawal_proof_input`].
    pub txid_display: String,
    /// Sats paid to the recipient P2PKH output.
    pub payout_sats: u64,
    /// Block height the payout confirmed in (`None` if unconfirmed).
    pub block_height: Option<u64>,
}

/// The on-chain checkpoint the proof must descend from (mirrors the contract).
#[derive(Clone, Copy)]
pub struct CheckpointParams {
    /// Checkpoint block hash, raw little-endian (consensus form).
    pub checkpoint_hash: [u8; 32],
    pub checkpoint_height: u64,
    /// Cumulative chain work at the checkpoint, big-endian U256.
    pub checkpoint_chainwork: [u8; 32],
    pub min_confirmations: u32,
    /// Index into the contract's checkpointHistory[] array. 0 = use latest.
    pub checkpoint_index: u32,
    /// Custody P2PKH HASH160 the deposit must pay.
    pub custody_hash160: [u8; 20],
    /// On-chain custody epoch in force (committed to the journal for rotation binding).
    pub custody_epoch: u64,
    /// Aux chain id (`nVersion >> 16`) of the proven block chain — the guest
    /// asserts every header carries it and commits it to the journal for routing.
    pub chain_id: u32,
}

fn sha256d(data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&Sha256::digest(Sha256::digest(data)));
    out
}

/// Reverse a 32-byte hash (display ↔ consensus byte order).
fn rev32(mut b: [u8; 32]) -> [u8; 32] {
    b.reverse();
    b
}

/// Display (big-endian) hex of a consensus little-endian hash.
fn hash_display(le: &[u8; 32]) -> String {
    let mut b = *le;
    b.reverse();
    hex::encode(b)
}

fn hex32(display_hex: &str) -> anyhow::Result<[u8; 32]> {
    let v = hex::decode(display_hex)?;
    if v.len() != 32 {
        anyhow::bail!("expected 32-byte hash, got {}", v.len());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    Ok(out)
}

impl ElectrsClient {
    pub fn new(base_url: impl Into<String>) -> Self {
        // No timeout on `reqwest::Client::new()` means a TCP-connected-but-silent
        // server (junk-api has shown this failure mode live) hangs the call
        // forever with no Err — see the matching fix in mpc-node/src/electrs.rs.
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .expect("reqwest client builder with only a timeout cannot fail");
        Self {
            base: base_url.into().trim_end_matches('/').to_string(),
            http,
        }
    }

    async fn get_text(&self, path: &str) -> anyhow::Result<String> {
        let url = format!("{}{}", self.base, path);
        Ok(self.http.get(&url).send().await?.error_for_status()?.text().await?)
    }

    async fn get_json<T: serde::de::DeserializeOwned>(&self, path: &str) -> anyhow::Result<T> {
        let url = format!("{}{}", self.base, path);
        Ok(self.http.get(&url).send().await?.error_for_status()?.json::<T>().await?)
    }

    pub async fn tip_height(&self) -> anyhow::Result<u64> {
        Ok(self.get_text("/blocks/tip/height").await?.trim().parse()?)
    }

    /// Block hash (display hex) at `height`.
    pub async fn block_hash_at(&self, height: u64) -> anyhow::Result<String> {
        Ok(self.get_text(&format!("/block-height/{height}")).await?.trim().to_string())
    }

    /// Block height for a block hash (display hex). Reverse of [`block_hash_at`].
    pub async fn block_height_for_hash(&self, hash_display: &str) -> anyhow::Result<u64> {
        let v: serde_json::Value = self
            .get_json(&format!("/block/{hash_display}/status"))
            .await?;
        v.get("height")
            .and_then(|h| h.as_u64())
            .ok_or_else(|| anyhow::anyhow!("height not found in block status"))
    }

    /// The raw 80-byte consensus header for `block_hash` (AuxPoW data, if any, is
    /// dropped — see the module note).
    pub async fn header_80(&self, block_hash: &str) -> anyhow::Result<[u8; 80]> {
        let raw = hex::decode(self.get_text(&format!("/block/{block_hash}/header")).await?.trim())?;
        if raw.len() < HEADER_LEN {
            anyhow::bail!("header shorter than 80 bytes: {}", raw.len());
        }
        let mut out = [0u8; 80];
        out.copy_from_slice(&raw[..HEADER_LEN]);
        Ok(out)
    }

    pub async fn tx_bytes(&self, txid_display: &str) -> anyhow::Result<Vec<u8>> {
        Ok(hex::decode(self.get_text(&format!("/tx/{txid_display}/hex")).await?.trim())?)
    }

    /// The base 80-byte header plus its parsed AuxPoW witness for `block_hash`.
    pub async fn header_with_auxpow(&self, block_hash: &str) -> anyhow::Result<([u8; 80], AuxPow)> {
        let raw = hex::decode(self.get_text(&format!("/block/{block_hash}/header")).await?.trim())?;
        parse_auxpow(&raw)
    }

    async fn merkle_proof(&self, txid_display: &str) -> anyhow::Result<MerkleProofResp> {
        self.get_json(&format!("/tx/{txid_display}/merkle-proof")).await
    }

    /// Confirmed txs for `address`, most-recent first (`/address/:addr/txs/chain`).
    /// Esplora returns up to 25 per page; `last_seen` continues after that txid. A
    /// fresh peg-out payout is among the most recent, so the first page normally
    /// suffices for [`find_payout`], which paginates a bounded number of pages.
    pub async fn address_txs_chain(&self, address: &str, last_seen: Option<&str>) -> anyhow::Result<Vec<AddrTx>> {
        let path = match last_seen {
            Some(txid) => format!("/address/{address}/txs/chain/{txid}"),
            None => format!("/address/{address}/txs/chain"),
        };
        self.get_json(&path).await
    }

    /// Locate the confirmed peg-out payout for `withdrawal_id`: a tx paying
    /// `recipient_hash160` (P2PKH) and carrying `OP_RETURN <withdrawalId>`. Scans the
    /// recipient address's confirmed history (bounded to `max_pages` Esplora pages),
    /// matching by CONTENT via [`common::parse_withdrawal_outputs`] — never by an
    /// expected txid, so signature malleability cannot hide the settlement (invariant #6).
    ///
    /// Additionally verifies that the matching tx spends at least one input from
    /// `custody_address` — a non-custody tx with the correct OP_RETURN + amount
    /// cannot close the withdrawal (N4 fix).
    ///
    /// Returns `Ok(None)` if no matching payout is found in the scanned window (e.g. the
    /// publisher set has not paid yet, or it is buried deeper than the scan reached).
    pub async fn find_payouts(
        &self,
        recipient_address: &str,
        recipient_hash160: &[u8; 20],
        withdrawal_id: &[u8; 32],
        max_pages: usize,
        custody_address: &str,
    ) -> anyhow::Result<Vec<PayoutTx>> {
        let mut last_seen: Option<String> = None;
        let mut payouts = Vec::new();
        for _ in 0..max_pages.max(1) {
            let page = self.address_txs_chain(recipient_address, last_seen.as_deref()).await?;
            if page.is_empty() {
                break;
            }
            for t in &page {
                if !t.status.confirmed {
                    continue;
                }
                let raw = self.tx_bytes(&t.txid).await?;
                if let Some((payout_sats, wid)) =
                    common::parse_withdrawal_outputs(&raw, recipient_hash160)
                {
                    if &wid == withdrawal_id {
                        // Verify this tx spends from the custody address.
                        if !self.tx_spends_from(&t.txid, custody_address).await? {
                            eprintln!(
                                "[warn] Payout tx {} matches OP_RETURN + amount but does NOT spend from custody address — skipping",
                                t.txid
                            );
                            continue;
                        }
                        payouts.push(PayoutTx {
                            txid_display: t.txid.clone(),
                            payout_sats,
                            block_height: t.status.block_height,
                        });
                    }
                }
            }
            last_seen = page.last().map(|t| t.txid.clone());
        }
        Ok(payouts)
    }

    /// Check if a transaction spends at least one input from `address`.
    /// Fetches `/tx/:txid` from electrs and inspects `vin[].prevout.scriptpubkey_address`.
    async fn tx_spends_from(&self, txid_display: &str, address: &str) -> anyhow::Result<bool> {
        let tx_info: serde_json::Value = self
            .get_json(&format!("/tx/{txid_display}"))
            .await?;
        let vin = tx_info.get("vin").and_then(|v| v.as_array());
        match vin {
            Some(vin) => {
                for input in vin {
                    let prevout = input.get("prevout");
                    if let Some(addr) = prevout
                        .and_then(|p| p.get("scriptpubkey_address"))
                        .and_then(|a| a.as_str())
                    {
                        if addr == address {
                            return Ok(true);
                        }
                    }
                }
                Ok(false)
            }
            None => Ok(false),
        }
    }
}

/// Fetch one JKC header with its AuxPoW witness. PSob requires every header to be
/// merge-mined (its PoW is carried by the LTC parent), so a missing AuxPoW is an
/// error — not a fallback to the bare 80-byte header (the guest would reject it).
async fn jkc_header_with_auxpow(client: &ElectrsClient, hash: &str) -> anyhow::Result<BlockHeader> {
    let (raw, aux) = client.header_with_auxpow(hash).await.map_err(|e| {
        anyhow::anyhow!(
            "block {hash} has no parseable AuxPoW witness (PSob requires merge-mined blocks): {e}"
        )
    })?;
    Ok(BlockHeader { raw: raw.to_vec(), aux: Some(aux) })
}



/// Assemble the [`ProofInput`] witness for a deposit. `deposit_txid_display` is the
/// usual big-endian txid string.
pub async fn build_proof_input(
    client: &ElectrsClient,
    deposit_txid_display: &str,
    cp: &CheckpointParams,
) -> anyhow::Result<ProofInput> {
    let mp = client.merkle_proof(deposit_txid_display).await?;
    let dep_height = mp.block_height;
    if dep_height <= cp.checkpoint_height {
        anyhow::bail!("deposit height {dep_height} is not above the checkpoint {}", cp.checkpoint_height);
    }

    // Window: checkpoint+1 ..= deposit + (min_confirmations - 1), giving exactly
    // `min_confirmations` headers covering and burying the deposit block.
    let conf = cp.min_confirmations.max(1) as u64;
    let end_height = dep_height + conf - 1;
    let tip = client.tip_height().await?;
    if tip < end_height {
        anyhow::bail!("insufficient confirmations: need height {end_height}, tip is {tip}");
    }

    let mut headers = Vec::with_capacity((end_height - cp.checkpoint_height) as usize);
    for h in (cp.checkpoint_height + 1)..=end_height {
        let hash = client.block_hash_at(h).await?;
        headers.push(jkc_header_with_auxpow(client, &hash).await?);
    }

    let deposit_header_index = (dep_height - (cp.checkpoint_height + 1)) as u32;

    // Merkle path: reverse each display-hex sibling to consensus LE; `left` is true
    // when our node is the left child at that level (bit of `pos`).
    let txid = rev32(hex32(deposit_txid_display)?);
    let mut path = Vec::with_capacity(mp.merkle.len());
    for (level, sib) in mp.merkle.iter().enumerate() {
        path.push(MerkleStep {
            sibling: rev32(hex32(sib)?),
            left: (mp.pos >> level) & 1 == 0,
        });
    }

    let deposit_tx = client.tx_bytes(deposit_txid_display).await?;

    Ok(ProofInput {
        chain_id: cp.chain_id,
        checkpoint_hash: cp.checkpoint_hash,
        checkpoint_chainwork: cp.checkpoint_chainwork,
        headers,
        deposit_header_index,
        min_confirmations: cp.min_confirmations,
        merkle_proof: MerkleProof { txid, path },
        deposit_tx,
        custody_hash160: cp.custody_hash160,
        custody_epoch: cp.custody_epoch,
        // the source chain mainnet consensus powLimit; the guest enforces every header's
        // target <= this and the contract pins the same value (see ZkBridge.powLimitBits).
        pow_limit_bits: common::CHAIN_POW_LIMIT_BITS,
    })
}

/// Assemble the [`ProofInput`] witness for a WITHDRAWAL (peg-out) proof — the dual of
/// [`build_proof_input`]. The withdrawal guest REUSES `ProofInput`: its `deposit_tx`
/// field carries the payout tx and its `custody_hash160` field carries the RECIPIENT's
/// HASH160 that the payout must pay (see the withdrawal guest / `parse_withdrawal_outputs`).
/// So we simply build the standard witness with `custody_hash160` overridden to the
/// recipient; `custody_epoch` is irrelevant to the withdrawal guest (its `WithdrawalJournal`
/// carries no epoch) and is passed through unused.
pub async fn build_withdrawal_proof_input(
    client: &ElectrsClient,
    payout_txid_display: &str,
    recipient_hash160: &[u8; 20],
    cp: &CheckpointParams,
) -> anyhow::Result<ProofInput> {
    let mut cp2 = *cp;
    cp2.custody_hash160 = *recipient_hash160;
    build_proof_input(client, payout_txid_display, &cp2).await
}

/// Fold a merkle path the same way the guest does — exposed so callers (and tests)
/// can sanity-check a built proof before committing to an expensive proving run.
pub fn fold_merkle(proof: &MerkleProof) -> [u8; 32] {
    let mut acc = proof.txid;
    for step in &proof.path {
        let mut buf = [0u8; 64];
        if step.left {
            buf[..32].copy_from_slice(&acc);
            buf[32..].copy_from_slice(&step.sibling);
        } else {
            buf[..32].copy_from_slice(&step.sibling);
            buf[32..].copy_from_slice(&acc);
        }
        acc = sha256d(&buf);
    }
    acc
}

#[cfg(test)]
mod tests {
    use super::*;

    const LIVE: &str = "https://junk-api.s3na.xyz";

    /// The content predicate `find_payout` keys on: a payout tx is matched iff it pays the
    /// recipient P2PKH and carries `OP_RETURN <withdrawalId>`. This locks that a correctly
    /// shaped payout is recognised and a wrong-recipient / wrong-id one is not — the
    /// malleability-safe (txid-independent) matching the finalizer depends on.
    #[test]
    fn payout_content_match_predicate() {
        let recipient = [0x33u8; 20];
        let wid = [0x44u8; 32];
        // legacy tx: 1 real (non-coinbase) input, [payout P2PKH, OP_RETURN(wid), change].
        let p2pkh = |h: &[u8; 20]| {
            let mut s = vec![0x76u8, 0xa9, 0x14];
            s.extend_from_slice(h);
            s.extend_from_slice(&[0x88, 0xac]);
            s
        };
        let mut opret = vec![0x6au8, 0x20];
        opret.extend_from_slice(&wid);
        let outputs: Vec<(u64, Vec<u8>)> = vec![
            (450_000_000, p2pkh(&recipient)),
            (0, opret),
            (10_000_000, p2pkh(&[0x99u8; 20])),
        ];
        let mut tx = Vec::new();
        tx.extend_from_slice(&1u32.to_le_bytes());
        tx.push(1);
        tx.extend_from_slice(&[0x11u8; 32]); // non-null prevout
        tx.extend_from_slice(&0u32.to_le_bytes());
        tx.push(0);
        tx.extend_from_slice(&0xffff_ffffu32.to_le_bytes());
        tx.push(outputs.len() as u8);
        for (v, spk) in &outputs {
            tx.extend_from_slice(&v.to_le_bytes());
            tx.push(spk.len() as u8);
            tx.extend_from_slice(spk);
        }
        tx.extend_from_slice(&0u32.to_le_bytes());

        // Matches: correct recipient + wid.
        assert_eq!(common::parse_withdrawal_outputs(&tx, &recipient), Some((450_000_000, wid)));
        // Non-match: a different recipient is not paid by this tx.
        assert_eq!(common::parse_withdrawal_outputs(&tx, &[0x77u8; 20]), None);
    }

    fn merkle_root_of(h: &BlockHeader) -> [u8; 32] {
        let mut r = [0u8; 32];
        r.copy_from_slice(&h.raw[36..68]);
        r
    }

    /// End-to-end against the live chain: find a recent multi-tx block, build a
    /// ProofInput for one of its txs, and verify (a) the header chain links back to
    /// the checkpoint, (b) each block id is sha256d(header), and (c) the merkle path
    /// folds to the deposit header's stored root. (c) implicitly validates the
    /// endianness handling end-to-end.
    #[tokio::test]
    #[ignore = "hits the live Electrs endpoint"]
    async fn live_build_proof_input_verifies() {
        let c = ElectrsClient::new(LIVE);
        let tip = c.tip_height().await.unwrap();

        // Prefer a block with >1 tx (non-trivial merkle path); fall back to a recent
        // coinbase (empty path) if the low-activity chain has none nearby — either
        // way the three invariants below hold.
        #[derive(serde::Deserialize)]
        struct Blk {
            tx_count: u64,
        }
        let mut dep_height = tip - 10;
        let mut deposit_txid = {
            let hash = c.block_hash_at(dep_height).await.unwrap();
            let txids: Vec<String> = c.get_json(&format!("/block/{hash}/txids")).await.unwrap();
            txids[0].clone()
        };
        for h in (tip.saturating_sub(150)..tip - 5).rev() {
            let hash = c.block_hash_at(h).await.unwrap();
            let blk: Blk = c.get_json(&format!("/block/{hash}")).await.unwrap();
            if blk.tx_count > 1 {
                let txids: Vec<String> = c.get_json(&format!("/block/{hash}/txids")).await.unwrap();
                dep_height = h;
                deposit_txid = txids[1].clone(); // pos >= 1 ⇒ a real sibling path
                break;
            }
        }

        let cp = CheckpointParams {
            checkpoint_hash: rev32(hex32(&c.block_hash_at(dep_height - 3).await.unwrap()).unwrap()),
            checkpoint_height: dep_height - 3,
            checkpoint_chainwork: [0u8; 32],
            min_confirmations: 3,
            checkpoint_index: 0,
            custody_hash160: [0u8; 20],
            custody_epoch: 1,
            chain_id: 0x2020,
        };

        let input = build_proof_input(&c, &deposit_txid, &cp).await.unwrap();

        // (a)+(b): chain links checkpoint → … with id = sha256d(header).
        let mut prev = cp.checkpoint_hash;
        for hdr in &input.headers {
            let mut prev_in_hdr = [0u8; 32];
            prev_in_hdr.copy_from_slice(&hdr.raw[4..36]);
            assert_eq!(prev_in_hdr, prev, "broken header link");
            prev = sha256d(&hdr.raw);
        }

        // (c): merkle path folds to the deposit header's root.
        let dep_hdr = &input.headers[input.deposit_header_index as usize];
        assert_eq!(fold_merkle(&input.merkle_proof), merkle_root_of(dep_hdr), "merkle inclusion");

        // deposit tx hashes to the proven txid.
        assert_eq!(sha256d(&input.deposit_tx), input.merkle_proof.txid, "tx ↔ txid");
    }

    fn target_from_bits(bits: u32) -> [u8; 32] {
        let exponent = (bits >> 24) as usize;
        let mantissa = bits & 0x007f_ffff;
        let mut target = [0u8; 32];
        if exponent <= 3 {
            let m = mantissa >> (8 * (3 - exponent));
            target[29] = (m >> 16) as u8;
            target[30] = (m >> 8) as u8;
            target[31] = m as u8;
        } else {
            let idx = 32 - exponent;
            if idx < 30 {
                target[idx] = (mantissa >> 16) as u8;
                target[idx + 1] = (mantissa >> 8) as u8;
                target[idx + 2] = mantissa as u8;
            }
        }
        target
    }

    fn scrypt_pow(raw: &[u8]) -> [u8; 32] {
        let params = scrypt::Params::new(10, 1, 1, 32).unwrap();
        let mut out = [0u8; 32];
        scrypt::scrypt(raw, raw, &params, &mut out).unwrap();
        out
    }

    fn meets_target(pow_le: &[u8; 32], target_be: &[u8; 32]) -> bool {
        for i in 0..32 {
            let h = pow_le[31 - i];
            let t = target_be[i];
            if h < t {
                return true;
            }
            if h > t {
                return false;
            }
        }
        true
    }

    /// Parse a real coin block's AuxPoW, verify the merged-mining commitment, and
    /// confirm the *parent* block's scrypt PoW meets the coin target — i.e. the
    /// block's real proof-of-work, which the 80-byte header alone cannot show.
    #[tokio::test]
    #[ignore = "hits the live Electrs endpoint"]
    async fn live_auxpow_parent_pow_verifies() {
        let c = ElectrsClient::new(LIVE);
        let tip = c.tip_height().await.unwrap();
        let hash = c.block_hash_at(tip - 12).await.unwrap();

        let (base, aux) = c.header_with_auxpow(&hash).await.unwrap();
        let aux_block_hash = sha256d(&base);
        assert_eq!(aux_block_hash[..], rev32(hex32(&hash).unwrap())[..], "block id");

        // chain_id = coin header nVersion >> 16.
        let chain_id = u32::from_le_bytes(base[0..4].try_into().unwrap()) >> 16;
        assert!(
            common::verify_auxpow_commitment(&aux_block_hash, &aux, chain_id),
            "merged-mining commitment (with anti-grind) must verify"
        );

        let bits = u32::from_le_bytes(base[72..76].try_into().unwrap());
        let target = target_from_bits(bits);
        let pow = scrypt_pow(&aux.parent_header);
        assert!(meets_target(&pow, &target), "parent scrypt PoW must meet the target");
    }
}
