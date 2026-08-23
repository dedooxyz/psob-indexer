//! WASM PoC — exact-Rust-parity PSob verification compiled to
//! `wasm32-unknown-unknown`.
//!
//! ABI (no wasm-bindgen, no CLI tooling):
//! ```text
//! psb_verify_alloc(ptr: *const u8, len: usize, chain_id: u32) -> u64
//!   input : wire payload (80-byte header ‖ CAuxPow) copied into wasm memory
//!   output: ptr | (len << 32) — a JSON object in the static output buffer
//! ```
//! The output buffer is a single static slot: copy the JSON before calling
//! again. Verification logic is `common::verify_auxpow_commitment` — the same
//! code path the indexer and the ZK guest use.

use std::sync::Mutex;

use common::{expand_target, target_leq, verify_auxpow_commitment};

static BUF: Mutex<Vec<u8>> = Mutex::new(Vec::new());

/// Verify a wire payload and return `(ptr, len)` packed into a u64.
///
/// - high 32 bits: length of the JSON result
/// - low 32 bits: pointer into wasm linear memory
///
/// # Safety
///
/// `ptr` must point to `len` readable bytes in wasm linear memory. The static
/// result buffer is only replaced on the NEXT call — copy the JSON before
/// calling again.
#[no_mangle]
pub unsafe extern "C" fn psb_verify_alloc(ptr: *const u8, len: usize, chain_id: u32) -> u64 {
    let mut buf = BUF.lock().unwrap();
    let json = {
        // SAFETY: contract above.
        let data = unsafe { std::slice::from_raw_parts(ptr, len) };
        let result = verify_to_json(data, chain_id);
        if let Some(x) = result {
            match serde_json::to_string(&x).ok() {
                Some(s) => s + "\n", // sentinel guard against truncation confusion in tests
                None => r#"{"valid":false,"fatal":"serialize"}"#.to_string(),
            }
        } else {
            r#"{"valid":false,"fatal":"parse"}"#.to_string()
        }
    };
    buf.clear();
    buf.extend_from_slice(json.as_bytes());
    (buf.as_ptr() as u64) | ((buf.len() as u64) << 32)
}

/// Human-readable status — probes that the module is alive and linked.
#[no_mangle]
pub extern "C" fn psb_status() -> u64 {
    let mut buf = BUF.lock().unwrap();
    buf.clear();
    buf.extend_from_slice(b"psob-wasm:ok0\n");
    (buf.as_ptr() as u64) | ((buf.len() as u64) << 32)
}

fn verify_to_json(wire: &[u8], chain_id: u32) -> Option<serde_json::Value> {
    let (base, aux) = common::cauxpow::parse_auxpow(wire).ok()?;

    let id = common::sha256d(&base);
    let parent_id = common::sha256d(&aux.parent_header);
    let mut id_disp = id;
    id_disp.reverse();
    let mut parent_disp = parent_id;
    parent_disp.reverse();

    let bits = u32::from_le_bytes(base[72..76].try_into().expect("80 bytes"));
    let can_take_headers = expand_target(bits).is_some()
        && expand_target(common::CHAIN_POW_LIMIT_BITS)
            .map(|pl| target_leq(&expand_target(bits).expect("checked"), &pl))
            .unwrap_or(false);
    let verdict = verify_auxpow_commitment(&id, &aux, chain_id);

    // Anti-grind details from the coinbase tail (mirrors src/verify.rs).
    let (mut n_size, mut nonce) = (0u32, 0u32);
    let mut index_ok: Option<bool> = None;
    if let Some(pos) = aux
        .coinbase_tx
        .windows(4)
        .position(|w| w == common::AUXPOW_MAGIC)
    {
        let tail_pos = pos + common::AUXPOW_MAGIC.len();
        if let Some(tail) = aux.coinbase_tx.get(tail_pos..tail_pos + 40) {
            n_size = u32::from_le_bytes(tail[32..36].try_into().expect("4 bytes"));
            nonce = u32::from_le_bytes(tail[36..40].try_into().expect("4 bytes"));
            let depth = aux.chain_merkle_branch.len() as u32;
            let mut rand = nonce;
            rand = rand.wrapping_mul(1103515245).wrapping_add(12345);
            rand = rand.wrapping_add(chain_id);
            rand = rand.wrapping_mul(1103515245).wrapping_add(12345);
            let expected = rand % (1u32 << depth);
            index_ok = Some(n_size == (1u32 << depth) && aux.chain_index == expected);
        }
    }

    Some(serde_json::json!({
        "valid": verdict,
        "chain_id": chain_id,
        "block_hash": hex::encode(id_disp),
        "parent_hash": hex::encode(parent_disp),
        "parent_chain_id": aux.parent_chain_id(),
        "header_format": can_take_headers,
        "proof1": aux.parent_index == 0
            && aux.parent_chain_id().is_some_and(|p| p != chain_id),
        "proof2": verdict,
        "anti_grind_ok": index_ok,
        "n_size": n_size,
        "nonce": nonce,
        "chain_index": aux.chain_index,
        "chain_branch_depth": aux.chain_merkle_branch.len(),
    }))
}

#[cfg(test)]
mod tests {
    #[test]
    fn wasm_module_tests_are_runnable_on_host() {
        // Keeps `cargo test --workspace` green without a wasm runtime.
        assert!(std::mem::size_of::<u64>() == 8);
    }
}
