//! CAuxPow wire-format parsing — the raw serialization that makes PSob
//! self-verifiable.
//!
//! An AuxPoW-block's `/block/:hash/header` payload consists of the 80-byte
//! aux-chain block header, immediately followed by the CAuxPow witness:
//!
//! ```text
//! 80-byte aux header
//! ── CAuxPow ────────────────────────────────────────────
//! coinbase tx          (legacy transaction, full wire bytes)
//! hashBlock            (uint256 — CMerkleTx::hashBlock, unused by verification)
//! parentMerkleBranch   (vector<uint256>)
//! parentIndex          (int32 u32 LE)
//! chainMerkleBranch    (vector<uint256>)
//! chainIndex           (int32 u32 LE)
//! parentHeader         (80 bytes)
//! ───────────────────────────────────────────────────────
//! ```
//!
//! This module is `no_std`-friendly (only `alloc`) and dependency-free so the
//! same parser can run in the guest, the host, and the indexer — and so a
//! TypeScript port can be kept exactly in sync field-for-field.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use crate::{AuxPow, BlockHeader};

/// Length of a legacy (pre-BIP34-enforcement-off) block header.
pub const HEADER_LEN: usize = 80;

/// Errors produced while decoding a CAuxPow witness.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuxPowParseError {
    /// Input buffer is shorter than the mandatory 80-byte header.
    TruncatedHeader { len: usize },
    /// The byte cursor ran past the end of the buffer.
    Truncated(String),
    /// The coinbase transaction did not decode as a legacy transaction.
    BadCoinbase(String),
    /// The buffer did not contain the trailing 80-byte parent header.
    MissingParentHeader,
    /// No AuxPoW data was present after the 80-byte header (a non-merge-mined block).
    NoAuxPow,
    /// A merkle-branch length field encoded an absurd count (allocation-DoS guard).
    BadBranch(String),
}

impl core::fmt::Display for AuxPowParseError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TruncatedHeader { len } => {
                write!(f, "header truncated: {len} bytes, need {HEADER_LEN}")
            }
            Self::Truncated(m) => write!(f, "auxpow truncated: {m}"),
            Self::BadCoinbase(m) => write!(f, "bad coinbase transaction: {m}"),
            Self::MissingParentHeader => {
                write!(f, "auxpow wire ends before the 80-byte parent header")
            }
            Self::NoAuxPow => write!(f, "no CAuxPow witness after the 80-byte header"),
            Self::BadBranch(m) => write!(f, "bad auxpow merkle branch: {m}"),
        }
    }
}

impl core::error::Error for AuxPowParseError {}

/// Result alias for CAuxPow parsing.
pub type AuxPowParseResult<T> = Result<T, AuxPowParseError>;

struct Cursor<'a> {
    b: &'a [u8],
    p: usize,
}

impl<'a> Cursor<'a> {
    fn new(b: &'a [u8]) -> Self {
        Self { b, p: 0 }
    }

    fn take(&mut self, n: usize) -> AuxPowParseResult<&'a [u8]> {
        let end = self.p.checked_add(n).ok_or_else(|| {
            AuxPowParseError::Truncated(format!("offset overflow at {}+{n}", self.p))
        })?;
        if end > self.b.len() {
            return Err(AuxPowParseError::Truncated(format!(
                "{}..{} of {}",
                self.p,
                end,
                self.b.len()
            )));
        }
        let s = &self.b[self.p..end];
        self.p = end;
        Ok(s)
    }

    fn u32_le(&mut self) -> AuxPowParseResult<u32> {
        Ok(u32::from_le_bytes(
            self.take(4)?.try_into().expect("4 bytes"),
        ))
    }

    fn hash32(&mut self) -> AuxPowParseResult<[u8; 32]> {
        let mut h = [0u8; 32];
        h.copy_from_slice(self.take(32)?);
        Ok(h)
    }

    fn varint(&mut self) -> AuxPowParseResult<u64> {
        let n = self.take(1)?[0];
        Ok(match n {
            0xff => u64::from_le_bytes(self.take(8)?.try_into().expect("8 bytes")),
            0xfe => u32::from_le_bytes(self.take(4)?.try_into().expect("4 bytes")) as u64,
            0xfd => u16::from_le_bytes(self.take(2)?.try_into().expect("2 bytes")) as u64,
            v => v as u64,
        })
    }

    /// Walk the legacy (no-witness) transaction structure [start..p); returns the
    /// start..end byte range of the whole tx, leaving the cursor after locktime.
    fn take_tx(&mut self) -> AuxPowParseResult<(usize, usize)> {
        let start = self.p;
        self.take(4)?; // version
        let nin = self.varint()?;
        if nin == 0 {
            return Err(AuxPowParseError::BadCoinbase(
                "zero inputs (segwit marker?)".into(),
            ));
        }
        for _ in 0..nin {
            self.take(36)?; // prevout
            let sl = self.varint()? as usize;
            if self.take(sl).is_err() {
                return Err(AuxPowParseError::BadCoinbase("scriptSig overruns".into()));
            }
            self.take(4)?; // sequence
        }
        let nout = self.varint()?;
        for _ in 0..nout {
            self.take(8)?; // value
            let sl = self.varint()? as usize;
            if self.take(sl).is_err() {
                return Err(AuxPowParseError::BadCoinbase(
                    "scriptPubKey overruns".into(),
                ));
            }
        }
        self.take(4)?; // locktime
        Ok((start, self.p))
    }

    fn branch(&mut self) -> AuxPowParseResult<Vec<[u8; 32]>> {
        let n = self.varint()? as usize;
        // A real AuxPoW merkle branch is at most ~32 entries (2^32 leaves). Bound the
        // allocation so a malicious wire (varint up to 0xffffffff → multi-GB
        // `Vec::with_capacity`) cannot crash the indexer via OOM. The loop below is
        // independently bounded by the available bytes (hash32 errors past the end).
        if n > 1 << 20 {
            return Err(AuxPowParseError::BadBranch(format!(
                "branch length {n} exceeds maximum ({}), likely malformed",
                1 << 20
            )));
        }
        let mut out = Vec::with_capacity(n.min(1 << 16));
        for _ in 0..n {
            out.push(self.hash32()?);
        }
        Ok(out)
    }
}

/// Split a full `/block/:hash/header` payload into the 80-byte base header and
/// the parsed [`AuxPow`] witness.
pub fn parse_auxpow(full: &[u8]) -> AuxPowParseResult<([u8; HEADER_LEN], AuxPow)> {
    if full.len() < HEADER_LEN {
        return Err(AuxPowParseError::TruncatedHeader { len: full.len() });
    }
    let mut base = [0u8; HEADER_LEN];
    base.copy_from_slice(&full[..HEADER_LEN]);

    if full.len() == HEADER_LEN {
        return Err(AuxPowParseError::NoAuxPow);
    }

    let mut cur = Cursor::new(full);
    cur.p = HEADER_LEN;

    // CAuxPow = CMerkleTx(coinbase) ‖ chainMerkleBranch ‖ chainIndex ‖ parentHeader.
    let (cb_start, cb_end) = cur.take_tx()?;
    let coinbase_tx = full[cb_start..cb_end].to_vec();
    let _hash_block = cur.hash32()?; // CMerkleTx.hashBlock — not used by verification
    let parent_merkle_branch = cur.branch()?;
    let parent_index = cur.u32_le()?;
    let chain_merkle_branch = cur.branch()?;
    let chain_index = cur.u32_le()?;
    let parent_header = cur
        .take(HEADER_LEN)
        .ok()
        .ok_or(AuxPowParseError::MissingParentHeader);

    Ok((
        base,
        AuxPow {
            coinbase_tx,
            parent_merkle_branch,
            parent_index,
            chain_merkle_branch,
            chain_index,
            parent_header: parent_header?.to_vec(),
        },
    ))
}

/// Split the wire payload into the base 80-byte header (as [`BlockHeader`]) and
/// the parsed [`AuxPow`] — the entry point used by the indexer's ingest path.
pub fn parse_header_with_auxpow(full: &[u8]) -> AuxPowParseResult<(BlockHeader, AuxPow)> {
    let (base, aux) = parse_auxpow(full)?;
    let header = BlockHeader {
        raw: base.to_vec(),
        aux: Some(aux.clone()),
    };
    Ok((header, aux))
}

/// Render a 32-byte hash as the display (big-endian) hex string used by
/// explorers and the REST API.
pub fn hash_display(le: &[u8; 32]) -> String {
    let mut b = *le;
    b.reverse();
    hex::encode(b)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &str = include_str!("../tests/fixtures/jkc_1095600_header.hex");

    #[test]
    fn parses_live_jkc_block() {
        let raw = hex::decode(FIXTURE.trim()).expect("fixture hex");
        let (base, aux) = parse_auxpow(&raw).expect("parse converts");
        assert_eq!(base.len(), HEADER_LEN);

        // JKC chain id = version >> 16 = 0x2020 = 8224.
        let version = u32::from_le_bytes(base[0..4].try_into().unwrap());
        assert_eq!(version >> 16, 8224);

        // Coinbase commitment round-trips: the aux block hash folds up the chain
        // branch and the result is committed after the magic in the coinbase.
        use crate::verify_auxpow_commitment;
        let id = crate::sha256d(&base);
        assert!(
            verify_auxpow_commitment(&id, &aux, 8224),
            "live block must verify"
        );

        // Parent header is a full 80-byte header.
        assert_eq!(aux.parent_header.len(), HEADER_LEN);

        // Parsed fields mirror chain-rpc's interpretation.
        assert_eq!(aux.parent_index, 0, "coinbase is the generation tx");
        assert_ne!(
            aux.parent_chain_id(),
            Some(8224),
            "parent is a foreign chain"
        );
    }

    #[test]
    fn rejects_truncated_and_non_auxpow() {
        assert_eq!(
            parse_auxpow(&[0u8; 8]),
            Err(AuxPowParseError::TruncatedHeader { len: 8 })
        );
        assert_eq!(
            parse_auxpow(&[0u8; HEADER_LEN]),
            Err(AuxPowParseError::NoAuxPow)
        );
    }

    #[test]
    fn rejects_bad_coinbase() {
        let mut raw = vec![0u8; HEADER_LEN];
        // A zero version with a zero-input coinbase marker (segwit style) must not parse.
        raw.extend_from_slice(&[0u8; 8]);
        assert_eq!(
            parse_auxpow(&raw).err(),
            Some(AuxPowParseError::BadCoinbase(
                "zero inputs (segwit marker?)".into()
            ))
        );
    }
}
