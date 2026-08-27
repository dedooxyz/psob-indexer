//! P2P Networking & Gossip Subsystem for PSob Indexer.
//!
//! Provides decentralized discovery and gossiping of:
//! - New AuxPoW block headers (`/psob/headers/v1`)
//! - Discovered Sibling Litecoin parents (`/psob/siblings/v1`)
//! - Cross-chain Swap Intents / Orders (`/psob/intents/v1`)
//!
//! `P2pHandle` is a thin in-process channel: the ingest loop and HTTP server
//! enqueue [`GossipMessage`]s; the swarm loop publishes them on the matching
//! topic. If the swarm is disabled, the channel simply never drains and the
//! senders' callers ignore send failures.

pub mod swarm;

use serde::{Deserialize, Serialize};
use serde_json::json;
use std::sync::Arc;
use tokio::sync::mpsc;

/// One message to publish on a gossip topic.
#[derive(Clone, Debug)]
pub struct GossipMessage {
    /// IdentTopic name, e.g. `/psob/intents/v1`.
    pub topic: String,
    /// Wire payload (JSON).
    pub payload: Vec<u8>,
}

/// Configuration for P2P Node.
#[derive(Clone, Debug)]
pub struct P2pConfig {
    pub p2p_port: u16,
    pub p2p_bind_addr: String,
    pub bootstrap_nodes: Vec<String>,
    pub enable_mdns: bool,
}

impl P2pConfig {
    /// Build from explicit values (`None` = defaults). Env/TOML resolution lives
    /// in [`crate::config::Config::load`] — reading the process env from deep
    /// inside a module was why config was hard to reason about before.
    pub fn from_parts(
        port: Option<u16>,
        bind: Option<String>,
        bootstrap_nodes: Option<String>,
        disable_mdns: Option<String>,
    ) -> Self {
        Self {
            p2p_port: port.unwrap_or(9000),
            p2p_bind_addr: bind.unwrap_or_else(|| "0.0.0.0".to_string()),
            bootstrap_nodes: bootstrap_nodes
                .unwrap_or_default()
                .split(',')
                .filter(|s| !s.trim().is_empty())
                .map(|s| s.trim().to_string())
                .collect(),
            enable_mdns: disable_mdns.is_none(),
        }
    }
}

impl Default for P2pConfig {
    fn default() -> Self {
        Self::from_parts(None, None, None, None)
    }
}

/// Message broadcast over the `/psob/intents/v1` gossip topic, conforming to
/// the `psob-swap/1` order-book standard.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SwapIntentMessage {
    /// Standard identifier, e.g. `"psob-swap"`.
    pub protocol: String,
    /// Standard version, e.g. `1`.
    pub version: u32,
    pub intent_id: String,
    /// Maker's compressed secp256k1 pubkey (hex), authoring & signing the offer.
    pub maker_pubkey: String,
    /// Chain the maker gives/sells (AuxPoW `nVersion >> 16`).
    pub from_chain: u32,
    /// Chain the maker wants/buys.
    pub to_chain: u32,
    pub from_amount: u64,
    pub to_amount: u64,
    /// Address (on `to_chain`) where the maker receives `to_amount`.
    pub maker_receive_address: String,
    /// Unix seconds the intent was created.
    pub timestamp: u64,
    /// Unix seconds after which the intent is invalid.
    pub expiry: u64,
    /// Settlement protocol the maker supports, e.g. `"adaptor-v1"`.
    pub settlement: String,
    /// Compact 64-byte ECDSA secp256k1 signature over the intent (hex).
    pub signature: String,
}

/// Status of the P2P Subsystem for HTTP API.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct P2pStatus {
    pub peer_id: String,
    pub listen_addrs: Vec<String>,
    pub connected_peers_count: usize,
    pub connected_peers: Vec<String>,
    pub subscribed_topics: Vec<String>,
}

/// Handle to interact with the running P2P Swarm from other tasks (HTTP server, ingest loop).
#[derive(Clone)]
pub struct P2pHandle {
    pub tx_gossip: mpsc::Sender<GossipMessage>,
    pub status: Arc<tokio::sync::RwLock<P2pStatus>>,
}

impl P2pHandle {
    /// Publish a JSON payload on a topic. Returns false when the swarm is down.
    pub async fn publish_json(&self, topic: &str, payload: serde_json::Value) -> bool {
        self.tx_gossip
            .send(GossipMessage {
                topic: topic.to_string(),
                payload: payload.to_string().into_bytes(),
            })
            .await
            .is_ok()
    }

    /// Publish a cross-chain swap intent. Wrapper kept for API stability.
    pub async fn broadcast_intent(&self, intent: SwapIntentMessage) -> bool {
        self.publish_json(
            swarm::TOPIC_INTENTS,
            serde_json::to_value(intent).unwrap_or(json!({})),
        )
        .await
    }

    /// Announce a verified aux header (the tallest of a batch per tick).
    pub async fn announce_header(
        &self,
        chain_id: u32,
        height: u64,
        block_hash_display: String,
        parent_hash_display: String,
        ltc_height: Option<u64>,
        auxpow_hex: String,
    ) -> bool {
        self.publish_json(
            swarm::TOPIC_HEADERS,
            json!({
                "type": "header",
                "chain_id": chain_id,
                "height": height,
                "block_hash": block_hash_display,
                "parent_hash": parent_hash_display,
                "ltc_height": ltc_height,
                "auxpow_hex": auxpow_hex,
            }),
        )
        .await
    }

    /// Announce a sibling group discovery (mainnet parent shared by >= 2 chains).
    pub async fn announce_sibling(
        &self,
        parent_hash_display: String,
        ltc_height: u64,
        legs: Vec<(u32, u64, String)>,
    ) -> bool {
        let legs_json: Vec<serde_json::Value> = legs
            .into_iter()
            .map(|(chain_id, height, block_hash)| json!({"chain_id": chain_id, "height": height, "block_hash": block_hash}))
            .collect();
        self.publish_json(
            swarm::TOPIC_SIBLINGS,
            json!({
                "type": "sibling",
                "parent_hash": parent_hash_display,
                "ltc_height": ltc_height,
                "legs": legs_json,
            }),
        )
        .await
    }
}
