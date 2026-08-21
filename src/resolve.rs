//! Litecoin mainnet classification of embedded parent headers.
//!
//! Every aux block embeds an 80-byte LTC (or trial) parent header. This module
//! asks an external resolver — ccnodes.net explorer API — whether that parent
//! exists on the Litecoin **mainnet** chain, and at what height. Parents that
//! resolve get `Some(ltc_height)`; anything else is recorded as `None` (trial
//! block). Only mainnet parents can serve as epoch boundaries `[L_start,
//! L_end]` in a PSob proof.

use reqwest::Client;
use serde::Deserialize;
use std::sync::Arc;

/// A parent-header resolver for *any one* chain (not only Litecoin), driven
/// entirely by config. This crate's oracle-free design checks the target chain
/// at the explorer API; which chain that is comes from `PSOB_PARENT_CHAIN`.
#[derive(Debug, Clone)]
pub struct ParentResolver {
    http: Arc<Client>,
    base: String,
    api_key: String,
    chain_slug: String,
}

/// The subset of the ccnodes `/{chain}/block/{hash}` block-summary payload we
/// need — the explorer returns block *metadata*, not the raw 80-byte header.
#[derive(Debug, Deserialize)]
struct BlockSummary {
    id: String,
    height: u64,
}

impl ParentResolver {
    pub fn new(
        base: impl Into<String>,
        api_key: impl Into<String>,
        chain_slug: impl Into<String>,
    ) -> anyhow::Result<Self> {
        Ok(Self {
            // Timeout mirrors chain-rpc's fix for junk-api's silent-TCP behavior.
            http: Arc::new(
                Client::builder()
                    .timeout(std::time::Duration::from_secs(30))
                    .build()
                    .expect("reqwest client builder cannot fail with just a timeout"),
            ),
            base: base.into().trim_end_matches('/').to_string(),
            api_key: api_key.into(),
            chain_slug: chain_slug.into(),
        })
    }

    /// Resolve `parent_hash_le` (raw little-endian consensus form) against the
    /// configured parent chain. Returns the parent height if the block exists,
    /// else `None` (trial block / orphan / not yet confirmed). The explorer
    /// chain slug is the body of the URL — taken from env, not hardcoded.
    pub async fn resolve(&self, parent_hash_le: &[u8; 32]) -> anyhow::Result<Option<u64>> {
        let mut display = *parent_hash_le;
        display.reverse();
        let hash_hex = hex::encode(&display);

        // Format URL: if base ends with /api (like litecoinspace.org/api), use /block/{hash} directly.
        // If CCNodes, use /{chain_slug}/block/{hash}.
        let url = if self.base.ends_with("/api") || self.base.contains("litecoinspace") {
            format!("{}/block/{}", self.base, hash_hex)
        } else {
            format!("{}/{}/block/{}", self.base, self.chain_slug, hash_hex)
        };

        let mut req = self.http.get(&url);
        if !self.api_key.is_empty() {
            req = req.bearer_auth(&self.api_key);
        }

        let resp = match req.send().await {
            Ok(r) => r,
            Err(e) => {
                tracing::debug!(err = %e, "primary parent resolver failed, trying litecoinspace fallback");
                let fallback_url = format!("https://litecoinspace.org/api/block/{}", hash_hex);
                match self.http.get(&fallback_url).send().await {
                    Ok(r) => r,
                    Err(err) => {
                        tracing::debug!(err = %err, "fallback resolver error");
                        return Ok(None);
                    }
                }
            }
        };

        // A mainnet miss is signalled with 404 / error status
        if resp.status().is_success() {
            if let Ok(s) = resp.json::<BlockSummary>().await {
                let got = s.id.to_lowercase();
                if got == hash_hex {
                    return Ok(Some(s.height));
                }
            }
        }

        Ok(None)
    }
}