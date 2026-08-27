//! Validation for the `psob-swap/1` order-book standard (§3/§8 of the spec).
//!
//! The indexer is a neutral bulletin board: it validates the *envelope* of a
//! swap intent (protocol/version/settlement, chain-registry membership, sanity
//! of amounts/timestamps/addresses, and — when enforced — the maker signature)
//! but never validates or executes settlement internals.

use std::collections::HashSet;

use crate::p2p::SwapIntentMessage;

pub const SUPPORTED_PROTOCOLS: &[&str] = &["psob-swap"];
pub const SUPPORTED_VERSIONS: &[u32] = &[1];
pub const SUPPORTED_SETTLEMENTS: &[&str] = &["adaptor-v1"];

/// Validate a swap intent against the `psob-swap/1` envelope rules.
///
/// `known_chains` is the indexer's chain registry (chain ids it knows about).
pub fn validate_swap_intent(
    intent: &SwapIntentMessage,
    known_chains: &HashSet<u32>,
) -> anyhow::Result<()> {
    if !SUPPORTED_PROTOCOLS.contains(&intent.protocol.as_str()) {
        anyhow::bail!("unsupported protocol {:?}", intent.protocol);
    }
    if intent.version == 0 || !SUPPORTED_VERSIONS.contains(&intent.version) {
        anyhow::bail!("unsupported version {}", intent.version);
    }
    if !SUPPORTED_SETTLEMENTS.contains(&intent.settlement.as_str()) {
        anyhow::bail!("unsupported settlement {:?}", intent.settlement);
    }
    if intent.from_chain == intent.to_chain {
        anyhow::bail!("from_chain and to_chain must differ");
    }
    if !known_chains.contains(&intent.from_chain) {
        anyhow::bail!("unknown from_chain {}", intent.from_chain);
    }
    if !known_chains.contains(&intent.to_chain) {
        anyhow::bail!("unknown to_chain {}", intent.to_chain);
    }
    if intent.from_amount == 0 || intent.to_amount == 0 {
        anyhow::bail!("amounts must be > 0");
    }

    let now = now_unix();
    if intent.timestamp > now + 300 {
        anyhow::bail!("timestamp too far in the future");
    }
    if intent.expiry <= now {
        anyhow::bail!("intent already expired");
    }
    if intent.expiry.saturating_sub(intent.timestamp) > 60 * 60 * 24 * 30 {
        anyhow::bail!("intent validity window too long (>30d)");
    }

    if intent.maker_receive_address.is_empty() || intent.maker_receive_address.len() > 120 {
        anyhow::bail!("invalid maker_receive_address");
    }
    // maker_pubkey: compressed secp256k1 = 33 bytes = 66 hex chars.
    let pk = hex::decode(&intent.maker_pubkey).map_err(|_| anyhow::anyhow!("maker_pubkey not hex"))?;
    if pk.len() != 33 {
        anyhow::bail!("maker_pubkey must be 33 bytes (compressed secp256k1)");
    }
    // signature: compact 64-byte ECDSA = 128 hex chars.
    let sig = hex::decode(&intent.signature).map_err(|_| anyhow::anyhow!("signature not hex"))?;
    if sig.len() != 64 {
        anyhow::bail!("signature must be 64 bytes (compact ECDSA)");
    }

    verify_intent_signature(intent)
}

/// Verify the maker's signature over the intent.
///
/// **Currently stubbed**: no ECDSA backend is available in the workspace and
/// offline builds cannot pull one in. Verification is gated behind
/// `PSOB_REQUIRE_SIGNATURES=1`; until a `k256`/`secp256k1` dependency is added
/// and the check implemented, the default is to accept structurally-valid
/// intents WITHOUT cryptographic authentication (logged as a warning).
fn verify_intent_signature(intent: &SwapIntentMessage) -> anyhow::Result<()> {
    let enforce = std::env::var("PSOB_REQUIRE_SIGNATURES")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if !enforce {
        tracing::warn!(
            intent_id = %intent.intent_id,
            "swap intent signature NOT verified (set PSOB_REQUIRE_SIGNATURES=1 to enforce; \
             ECDSA backend not yet wired)"
        );
        return Ok(());
    }
    // TODO: compute intent_hash = SHA256(canonical sorted JSON without `signature`)
    // and verify compact ECDSA over it with `maker_pubkey`. Requires a secp256k1
    // crate (add `k256` or `secp256k1` to Cargo.toml).
    anyhow::bail!("signature verification not yet implemented (add a secp256k1 ECDSA backend)")
}

fn now_unix() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
