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
    // adaptor_point: optional, but if present must be a compressed secp256k1
    // point (33 bytes = 66 hex). Full curve validation happens client-side.
    if !intent.adaptor_point.is_empty() {
        let ap = hex::decode(&intent.adaptor_point).map_err(|_| anyhow::anyhow!("adaptor_point not hex"))?;
        if ap.len() != 33 {
            anyhow::bail!("adaptor_point must be 33 bytes (compressed secp256k1)");
        }
    }
    // signature: compact 64-byte ECDSA = 128 hex chars.
    let sig = hex::decode(&intent.signature).map_err(|_| anyhow::anyhow!("signature not hex"))?;
    if sig.len() != 64 {
        anyhow::bail!("signature must be 64 bytes (compact ECDSA)");
    }

    verify_intent_signature(intent)
}

/// Canonical, deterministic JSON serialization of a swap intent used as the
/// signed message. Keys are in a FIXED order with NO whitespace, and the
/// `signature` field is deliberately EXCLUDED (you cannot sign what you are
/// about to produce). This exact byte layout MUST be reproduced by every
/// signing client (the Android wallet mirrors `PsobSwapSigning.canonicalJson`).
fn canonical_intent_json(intent: &SwapIntentMessage) -> String {
    fn esc(s: &str) -> String {
        let mut out = String::with_capacity(s.len() + 2);
        for c in s.chars() {
            match c {
                '\\' => out.push_str("\\\\"),
                '"' => out.push_str("\\\""),
                _ => out.push(c),
            }
        }
        out
    }
    format!(
        "{{\"protocol\":\"{}\",\"version\":{},\"intent_id\":\"{}\",\"maker_pubkey\":\"{}\",\"from_chain\":{},\"to_chain\":{},\"from_amount\":{},\"to_amount\":{},\"maker_receive_address\":\"{}\",\"adaptor_point\":\"{}\",\"maker_npub\":\"{}\",\"maker_refund_address\":\"{}\",\"timestamp\":{},\"expiry\":{},\"settlement\":\"{}\"}}",
        esc(&intent.protocol),
        intent.version,
        esc(&intent.intent_id),
        esc(&intent.maker_pubkey),
        intent.from_chain,
        intent.to_chain,
        intent.from_amount,
        intent.to_amount,
        esc(&intent.maker_receive_address),
        esc(&intent.adaptor_point),
        esc(&intent.maker_npub),
        esc(&intent.maker_refund_address),
        intent.timestamp,
        intent.expiry,
        esc(&intent.settlement),
    )
}

/// Verify the maker's signature over the intent.
///
/// Gated behind `PSOB_REQUIRE_SIGNATURES=1` (default off, so the order book
/// still accepts unsigned intents from clients that don't yet sign). When on,
/// the maker's compact ECDSA signature over `SHA256(canonical JSON without
/// signature)` must verify against `maker_pubkey`.
pub fn verify_intent_signature(intent: &SwapIntentMessage) -> anyhow::Result<()> {
    let enforce = std::env::var("PSOB_REQUIRE_SIGNATURES")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    if !enforce {
        tracing::warn!(
            intent_id = %intent.intent_id,
            "swap intent signature NOT verified (set PSOB_REQUIRE_SIGNATURES=1 to enforce)"
        );
        return Ok(());
    }
    verify_intent_signature_inner(intent)
}

/// The actual cryptographic check (no gating) — also exercised directly by
/// tests. Signature is compact 64-byte ECDSA over the SHA256 of the canonical
/// intent JSON (see `canonical_intent_json`).
fn verify_intent_signature_inner(intent: &SwapIntentMessage) -> anyhow::Result<()> {
    use secp256k1::{ecdsa::Signature, Message, PublicKey, Secp256k1};
    use sha2::{Digest, Sha256};

    let canonical = canonical_intent_json(intent);
    let digest = Sha256::digest(canonical.as_bytes());
    let msg = Message::from_digest_slice(&digest)
        .map_err(|e| anyhow::anyhow!("invalid message digest: {e}"))?;

    let pk_bytes = hex::decode(&intent.maker_pubkey)
        .map_err(|e| anyhow::anyhow!("maker_pubkey not hex: {e}"))?;
    let pk = PublicKey::from_slice(&pk_bytes)
        .map_err(|e| anyhow::anyhow!("invalid maker_pubkey ({} bytes): {e}", pk_bytes.len()))?;

    let sig_bytes = hex::decode(&intent.signature)
        .map_err(|e| anyhow::anyhow!("signature not hex: {e}"))?;
    let sig = Signature::from_compact(&sig_bytes)
        .map_err(|e| anyhow::anyhow!("invalid compact signature: {e}"))?;

    Secp256k1::verification_only()
        .verify_ecdsa(&msg, &sig, &pk)
        .map_err(|e| anyhow::anyhow!("swap intent signature verification failed: {e}"))?;
    tracing::info!(intent_id = %intent.intent_id, "swap intent signature verified");
    Ok(())
}

fn now_unix() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::{Secp256k1, SecretKey, ecdsa::Signature};
    use sha2::{Digest, Sha256};

    fn signed_intent(mut intent: SwapIntentMessage, sk: &SecretKey) -> SwapIntentMessage {
        // maker_pubkey is part of the signed payload; fill it first.
        let pk = secp256k1::PublicKey::from_secret_key(&Secp256k1::new(), sk);
        intent.maker_pubkey = hex::encode(pk.serialize());
        let canonical = canonical_intent_json(&intent);
        let digest = Sha256::digest(canonical.as_bytes());
        let msg = secp256k1::Message::from_digest_slice(&digest).unwrap();
        let sig: Signature = Secp256k1::signing_only().sign_ecdsa(&msg, sk);
        intent.signature = hex::encode(sig.serialize_compact());
        intent
    }

    fn base_intent() -> SwapIntentMessage {
        SwapIntentMessage {
            protocol: "psob-swap".into(),
            version: 1,
            intent_id: "test-intent-1".into(),
            maker_pubkey: String::new(),
            from_chain: 8211,
            to_chain: 63,
            from_amount: 1_000_000,
            to_amount: 2_000_000,
            maker_receive_address: "LUCKYRECEIVEADDRESS".into(),
            timestamp: 1_700_000_000,
            expiry: 1_700_000_000 + 86_400,
            settlement: "adaptor-v1".into(),
            adaptor_point: String::new(),
            maker_npub: String::new(),
            maker_refund_address: String::new(),
            signature: String::new(),
        }
    }

    #[test]
    fn valid_signature_verifies() {
        let sk = SecretKey::from_slice(&[0x11; 32]).unwrap();
        let intent = signed_intent(base_intent(), &sk);
        assert!(verify_intent_signature_inner(&intent).is_ok());
    }

    #[test]
    fn canonical_json_contract() {
        // This literal MUST match the Android `PsobSwapSigning.canonicalJson`
        // output byte-for-byte — it is the cross-implementation contract.
        let intent = SwapIntentMessage {
            maker_pubkey: "02abcdef".into(),
            adaptor_point: "02aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            maker_npub: "npub1testmakernegotiationkeyexample000000000000000000000000000000".into(),
            maker_refund_address: "MAKERREFUNDADDRESS".into(),
            ..base_intent()
        };
        let got = canonical_intent_json(&intent);
        let expected = "{\"protocol\":\"psob-swap\",\"version\":1,\"intent_id\":\"test-intent-1\",\"maker_pubkey\":\"02abcdef\",\"from_chain\":8211,\"to_chain\":63,\"from_amount\":1000000,\"to_amount\":2000000,\"maker_receive_address\":\"LUCKYRECEIVEADDRESS\",\"adaptor_point\":\"02aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\",\"maker_npub\":\"npub1testmakernegotiationkeyexample000000000000000000000000000000\",\"maker_refund_address\":\"MAKERREFUNDADDRESS\",\"timestamp\":1700000000,\"expiry\":1700086400,\"settlement\":\"adaptor-v1\"}";
        assert_eq!(got, expected);
    }

    #[test]
    fn tampered_signature_fails() {
        let sk = SecretKey::from_slice(&[0x22; 32]).unwrap();
        let mut intent = signed_intent(base_intent(), &sk);
        // Flip a byte in the signature.
        intent.signature = intent.signature.chars().take(2).collect::<String>()
            + &intent.signature.chars().skip(2).collect::<String>().replace("0", "f");
        assert!(verify_intent_signature_inner(&intent).is_err());
    }

    #[test]
    fn tampered_payload_fails() {
        let sk = SecretKey::from_slice(&[0x33; 32]).unwrap();
        let mut intent = signed_intent(base_intent(), &sk);
        intent.to_amount = 9_999_999; // changes the signed message
        assert!(verify_intent_signature_inner(&intent).is_err());
    }

    #[test]
    fn wrong_key_fails() {
        let sk = SecretKey::from_slice(&[0x44; 32]).unwrap();
        let other = SecretKey::from_slice(&[0x55; 32]).unwrap();
        let mut intent = signed_intent(base_intent(), &other);
        // Re-sign the canonical payload with the WRONG key but keep maker_pubkey
        // from `other`; verification must fail because sig != key.
        let canonical = canonical_intent_json(&intent);
        let digest = Sha256::digest(canonical.as_bytes());
        let msg = secp256k1::Message::from_digest_slice(&digest).unwrap();
        let sig: Signature = Secp256k1::signing_only().sign_ecdsa(&msg, &sk);
        intent.signature = hex::encode(sig.serialize_compact());
        assert!(verify_intent_signature_inner(&intent).is_err());
    }
}
