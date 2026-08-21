//! P2P Networking & Gossip Subsystem for PSob Indexer.
//!
//! Provides decentralized discovery and gossiping of:
//! - New AuxPoW block headers (`/psob/headers/v1`)
//! - Discovered Sibling Litecoin parents (`/psob/siblings/v1`)
//! - Cross-chain Swap Intents / Orders (`/psob/intents/v1`)

pub mod swarm;

use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::mpsc;

/// Configuration for P2P Node.
#[derive(Clone, Debug)]
pub struct P2pConfig {
    pub p2p_port: u16,
    pub p2p_bind_addr: String,
    pub bootstrap_nodes: Vec<String>,
    pub enable_mdns: bool,
}

impl Default for P2pConfig {
    fn default() -> Self {
        let p2p_port = std::env::var("PSOB_P2P_PORT")
            .ok()
            .and_then(|p| p.parse::<u16>().ok())
            .unwrap_or(9000);
        let p2p_bind_addr = std::env::var("PSOB_P2P_BIND")
            .unwrap_or_else(|_| "0.0.0.0".to_string());
        let bootstrap_nodes = std::env::var("PSOB_BOOTSTRAP_NODES")
            .unwrap_or_default()
            .split(',')
            .filter(|s| !s.trim().is_empty())
            .map(|s| s.trim().to_string())
            .collect();
        let enable_mdns = std::env::var("PSOB_DISABLE_MDNS").is_err();

        Self {
            p2p_port,
            p2p_bind_addr,
            bootstrap_nodes,
            enable_mdns,
        }
    }
}

/// Message broadcast over the `/psob/intents/v1` gossip topic.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SwapIntentMessage {
    pub intent_id: String,
    pub from_chain: u32,
    pub to_chain: u32,
    pub from_amount: u64,
    pub to_amount: u64,
    pub maker_address: String,
    pub desired_address: String,
    pub timestamp: u64,
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
    pub tx_intent: mpsc::Sender<SwapIntentMessage>,
    pub status: Arc<tokio::sync::RwLock<P2pStatus>>,
}
