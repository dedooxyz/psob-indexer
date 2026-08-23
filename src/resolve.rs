//! Litecoin mainnet classification of embedded parent headers.
//!
//! Every aux block embeds an 80-byte LTC (or trial) parent header. This module
//! asks an external resolver — the ccnodes.net / litecoinspace explorer API —
//! whether that parent exists on the Litecoin **mainnet** chain, and at what
//! height. Parents that resolve get `Some(ltc_height)`; anything else is
//! recorded as `None` (trial block). Only mainnet parents can serve as epoch
//! boundaries `[L_start, L_end]` in a PSob proof.
//!
//! The resolver is *one* external signal, never a trust anchor: classification
//! only improves the indexer's discovery UX. Any client can independently
//! classify a parent header via the same explorer API — or rely on on-chain
//! verification which does not use this at all.

use chain_rpc::HttpPolicy;
use reqwest::Client;
use reqwest::StatusCode;
use serde::Deserialize;
use std::sync::Arc;

/// Exponential backoff with full jitter, capped (mirrors chain-rpc's policy).
async fn backoff(policy: &HttpPolicy, attempt: u32) {
    let exp = policy
        .base_backoff
        .saturating_mul(2u32.saturating_pow(attempt.min(10)));
    let capped = exp.min(policy.max_backoff);
    let jittered = if capped.is_zero() {
        std::time::Duration::from_millis(50)
    } else {
        std::time::Duration::from_millis(fastrand::u64(0..capped.as_millis() as u64 + 1))
    };
    tokio::time::sleep(jittered).await;
}

/// A parent-header resolver for *any one* chain (not only Litecoin), driven
/// entirely by config. This crate's oracle-free design checks the target chain
/// at the explorer API; which chain that is comes from `PSOB_PARENT_CHAIN`.
#[derive(Debug, Clone)]
pub struct ParentResolver {
    http: Arc<Client>,
    base: String,
    api_key: String,
    chain_slug: String,
    policy: HttpPolicy,
    /// Optional secondary explorer used only on transport failure.
    fallback_base: Option<String>,
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
        Ok(Self::with_policy(
            base,
            api_key,
            chain_slug,
            HttpPolicy::default(),
        ))
    }

    pub fn with_policy(
        base: impl Into<String>,
        api_key: impl Into<String>,
        chain_slug: impl Into<String>,
        policy: HttpPolicy,
    ) -> Self {
        Self::with_policy_and_fallback(base, api_key, chain_slug, policy, None)
    }

    pub fn with_policy_and_fallback(
        base: impl Into<String>,
        api_key: impl Into<String>,
        chain_slug: impl Into<String>,
        policy: HttpPolicy,
        fallback_base: Option<String>,
    ) -> Self {
        Self {
            // Timeout mirrors chain-rpc's fix for junk-api's silent-TCP behavior.
            http: Arc::new(
                Client::builder()
                    .timeout(policy.timeout)
                    .build()
                    .expect("reqwest client builder cannot fail with just a timeout"),
            ),
            base: base.into().trim_end_matches('/').to_string(),
            api_key: api_key.into(),
            chain_slug: chain_slug.into(),
            policy,
            fallback_base: fallback_base.map(|b| b.trim_end_matches('/').to_string()),
        }
    }

    /// Resolve `parent_hash_le` (raw little-endian consensus form) against the
    /// configured parent chain. Returns the parent height if the block exists,
    /// else `None` (trial block / orphan / not yet confirmed). Transport errors
    /// are retried with backoff; a definite miss (404) returns `None`.
    pub async fn resolve(&self, parent_hash_le: &[u8; 32]) -> anyhow::Result<Option<u64>> {
        let mut display = *parent_hash_le;
        display.reverse();
        let hash_hex = hex::encode(display);

        // Format URL: if base ends with /api (like litecoinspace.org/api), use
        // /block/{hash} directly. If CCNodes, use /{chain_slug}/block/{hash}.
        let url = if self.base.ends_with("/api") || self.base.contains("litecoinspace") {
            format!("{}/block/{}", self.base, hash_hex)
        } else {
            format!("{}/{}/block/{}", self.base, self.chain_slug, hash_hex)
        };

        let mut attempted_fallback = false;
        for attempt in 0..=self.policy.max_retries {
            let resp = self.request(&url).await;
            match resp {
                Ok(resp) if resp.status().is_success() => {
                    if let Ok(s) = resp.json::<BlockSummary>().await {
                        if s.id.to_lowercase() == hash_hex {
                            return Ok(Some(s.height));
                        }
                        return Ok(None); // hash mismatch — treat as a miss
                    }
                    // Decode failure: retryable transport-ish anomaly.
                    if attempt < self.policy.max_retries {
                        backoff(&self.policy, attempt).await;
                        continue;
                    }
                    return Ok(None);
                }
                Ok(resp) if resp.status() == StatusCode::NOT_FOUND => {
                    // Definite miss: the block is not on the parent chain (trial).
                    return Ok(None);
                }
                Ok(resp) => {
                    // 429/5xx — retry; other 4xx are deterministic misses.
                    if (resp.status() == StatusCode::TOO_MANY_REQUESTS
                        || resp.status().is_server_error())
                        && attempt < self.policy.max_retries
                    {
                        backoff(&self.policy, attempt).await;
                        continue;
                    }
                    return Ok(None);
                }
                Err(_) => {
                    // Transport failure — consult the configured fallback
                    // explorer once (if any), then retry the primary.
                    if let Some(fb_base) = &self.fallback_base {
                        if !attempted_fallback {
                            attempted_fallback = true;
                            let fallback_url =
                                format!("{}/block/{hash_hex}", fb_base.trim_end_matches('/'));
                            if let Ok(fb) = self.request(&fallback_url).await {
                                if fb.status().is_success() {
                                    if let Ok(s) = fb.json::<BlockSummary>().await {
                                        if s.id.to_lowercase() == hash_hex {
                                            return Ok(Some(s.height));
                                        }
                                    }
                                }
                            }
                            continue;
                        }
                    }
                    if attempt < self.policy.max_retries {
                        backoff(&self.policy, attempt).await;
                        continue;
                    }
                    tracing::debug!(url = %url, "parent resolver exhausted retries — treating as trial");
                    return Ok(None); // resolver down ⇒ record as trial; re-probe next round
                }
            }
        }
        Ok(None)
    }

    async fn request(&self, url: &str) -> reqwest::Result<reqwest::Response> {
        let mut req = self.http.get(url);
        if !self.api_key.is_empty() {
            req = req.bearer_auth(&self.api_key);
        }
        req.send().await
    }
}
