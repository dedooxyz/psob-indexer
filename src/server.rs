//! HTTP REST API Server for PSob Indexer.
//!
//! Provides JSON endpoints for frontends, DEX smart contracts, Bitcoin Computer
//! nodes (BCN), and prover relayers to query multi-chain sibling relations,
//! block proofs, and epoch witnesses.

use std::sync::Arc;
use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use tower_http::cors::CorsLayer;

use crate::config::Config;
use crate::db::Database;

use crate::p2p::{P2pHandle, SwapIntentMessage};

#[derive(Clone)]
pub struct AppState {
    pub db: Arc<Database>,
    pub config: Config,
    pub p2p: Option<P2pHandle>,
}

#[derive(Serialize)]
pub struct HealthResponse {
    pub status: String,
    pub service: String,
    pub version: String,
    pub configured_chains: usize,
    pub p2p_enabled: bool,
}

#[derive(Serialize)]
pub struct ChainStatus {
    pub chain_id: u32,
    pub name: String,
    pub electrs_url: String,
    pub cursor_height: Option<u64>,
    pub pow_limit_bits: String,
}

#[derive(Serialize)]
pub struct ChainsResponse {
    pub count: usize,
    pub chains: Vec<ChainStatus>,
}

#[derive(Deserialize)]
pub struct SiblingQuery {
    pub min_legs: Option<usize>,
    pub limit: Option<usize>,
}

#[derive(Serialize)]
pub struct SiblingSummary {
    pub parent_hash: String,
    pub ltc_height: u64,
    pub legs_count: usize,
    pub legs: Vec<ChainLeg>,
}

#[derive(Serialize)]
pub struct ChainLeg {
    pub chain_id: u32,
    pub height: u64,
}

#[derive(Serialize)]
pub struct BlockProofResponse {
    pub chain_id: u32,
    pub height: u64,
    pub block_hash: String,
    pub parent_hash: String,
    pub ltc_height: Option<u64>,
    pub parent_state: i64,
    pub chain_index: u32,
    pub chain_branch_depth: usize,
    pub parent_index: u32,
    pub parent_branch_depth: usize,
    pub coinbase_txid: String,
    pub raw_header_hex: String,
}

#[derive(Deserialize)]
pub struct VerifyRequest {
    pub chain_id: u32,
    pub header_hex: String,
}

#[derive(Serialize)]
pub struct VerifyResponse {
    pub valid: bool,
    pub chain_id: u32,
    pub block_hash: String,
    pub parent_hash: String,
    pub error: Option<String>,
}

#[derive(Serialize)]
pub struct EpochResponse {
    pub ltc_start: u64,
    pub ltc_end: u64,
    pub total_blocks: usize,
    pub blocks: Vec<EpochBlockItem>,
}

#[derive(Serialize)]
pub struct EpochBlockItem {
    pub chain_id: u32,
    pub height: u64,
    pub ltc_height: u64,
    pub block_hash: String,
}

pub fn create_router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health_handler))
        .route("/api/v1/health", get(health_handler))
        .route("/api/v1/chains", get(chains_handler))
        .route("/api/v1/siblings", get(siblings_handler))
        .route("/api/v1/siblings/:parent_hash", get(sibling_detail_handler))
        .route("/api/v1/block/:chain_id/:height", get(block_detail_handler))
        .route("/api/v1/proof/:chain_id/:height", get(proof_handler))
        .route("/api/v1/epoch/:ltc_start/:ltc_end", get(epoch_handler))
        .route("/api/v1/verify", post(verify_handler))
        .route("/api/v1/p2p/status", get(p2p_status_handler))
        .route("/api/v1/p2p/peers", get(p2p_peers_handler))
        .route("/api/v1/p2p/broadcast", post(p2p_broadcast_handler))
        .layer(CorsLayer::permissive())
        .with_state(state)
}

async fn health_handler(State(state): State<AppState>) -> impl IntoResponse {
    Json(HealthResponse {
        status: "ok".to_string(),
        service: "psob-indexer".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        configured_chains: state.config.chains.len(),
        p2p_enabled: state.p2p.is_some(),
    })
}

async fn p2p_status_handler(State(state): State<AppState>) -> impl IntoResponse {
    match &state.p2p {
        Some(handle) => {
            let status = handle.status.read().await;
            (StatusCode::OK, Json(serde_json::to_value(&*status).unwrap())).into_response()
        }
        None => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({ "error": "P2P subsystem is not enabled on this node" })),
        )
            .into_response(),
    }
}

async fn p2p_peers_handler(State(state): State<AppState>) -> impl IntoResponse {
    match &state.p2p {
        Some(handle) => {
            let status = handle.status.read().await;
            (
                StatusCode::OK,
                Json(serde_json::json!({
                    "connected_peers_count": status.connected_peers_count,
                    "connected_peers": status.connected_peers,
                })),
            )
                .into_response()
        }
        None => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({ "error": "P2P subsystem is not enabled" })),
        )
            .into_response(),
    }
}

async fn p2p_broadcast_handler(
    State(state): State<AppState>,
    Json(intent): Json<SwapIntentMessage>,
) -> impl IntoResponse {
    match &state.p2p {
        Some(handle) => match handle.tx_intent.send(intent.clone()).await {
            Ok(_) => (
                StatusCode::OK,
                Json(serde_json::json!({
                    "status": "broadcasted",
                    "intent_id": intent.intent_id,
                })),
            )
                .into_response(),
            Err(e) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(serde_json::json!({ "error": e.to_string() })),
            )
                .into_response(),
        },
        None => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({ "error": "P2P subsystem is not enabled" })),
        )
            .into_response(),
    }
}

async fn chains_handler(State(state): State<AppState>) -> impl IntoResponse {
    let mut chain_statuses = Vec::new();
    for c in &state.config.chains {
        let cursor = state.db.cursor_height(c.chain_id).unwrap_or(None);
        chain_statuses.push(ChainStatus {
            chain_id: c.chain_id,
            name: c.name.clone(),
            electrs_url: c.electrs.clone(),
            cursor_height: cursor,
            pow_limit_bits: format!("{:#010x}", c.pow_limit_bits),
        });
    }
    Json(ChainsResponse {
        count: chain_statuses.len(),
        chains: chain_statuses,
    })
}

async fn siblings_handler(
    State(state): State<AppState>,
    Query(query): Query<SiblingQuery>,
) -> impl IntoResponse {
    let min_legs = query.min_legs.unwrap_or(2);
    let limit = query.limit.unwrap_or(20);

    match state.db.shared_mainnet_parents(min_legs, limit) {
        Ok(parents) => {
            let res: Vec<SiblingSummary> = parents
                .into_iter()
                .map(|p| {
                    let mut ph = p.parent_hash_le;
                    ph.reverse();
                    SiblingSummary {
                        parent_hash: hex::encode(ph),
                        ltc_height: p.ltc_height,
                        legs_count: p.legs.len(),
                        legs: p.legs.into_iter().map(|(c, h)| ChainLeg { chain_id: c, height: h }).collect(),
                    }
                })
                .collect();
            (StatusCode::OK, Json(serde_json::to_value(res).unwrap())).into_response()
        }
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(serde_json::json!({ "error": e.to_string() })),
        )
            .into_response(),
    }
}

async fn sibling_detail_handler(
    State(state): State<AppState>,
    Path(parent_hash_hex): Path<String>,
) -> impl IntoResponse {
    let parent_bytes = match hex::decode(&parent_hash_hex) {
        Ok(b) if b.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&b);
            arr.reverse(); // Convert display hex to little-endian
            arr
        }
        _ => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "invalid 32-byte parent hash" }))).into_response(),
    };

    let parent_info = match state.db.get_parent(&parent_bytes) {
        Ok(Some(p)) => p,
        Ok(None) => return (StatusCode::NOT_FOUND, Json(serde_json::json!({ "error": "parent hash not found" }))).into_response(),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": e.to_string() }))).into_response(),
    };

    let siblings = state.db.siblings_for_parent(&parent_bytes).unwrap_or_default();
    let sibling_blocks: Vec<serde_json::Value> = siblings.into_iter().map(|s| {
        let mut bh = s.hash_le;
        bh.reverse();
        serde_json::json!({
            "chain_id": s.chain_id,
            "height": s.height,
            "block_hash": hex::encode(bh),
        })
    }).collect();

    Json(serde_json::json!({
        "parent_hash": parent_hash_hex,
        "ltc_height": parent_info.ltc_height,
        "parent_state": parent_info.parent_state,
        "sibling_count": sibling_blocks.len(),
        "siblings": sibling_blocks,
    })).into_response()
}

async fn block_detail_handler(
    State(state): State<AppState>,
    Path((chain_id, height)): Path<(u32, u64)>,
) -> impl IntoResponse {
    match state.db.block_at(chain_id, height) {
        Ok(Some(block)) => {
            let mut bh = block.hash_le;
            bh.reverse();
            (StatusCode::OK, Json(serde_json::json!({
                "chain_id": chain_id,
                "height": height,
                "block_hash": hex::encode(bh),
                "header_len": block.header.raw.len(),
                "has_auxpow": block.header.aux.is_some(),
            }))).into_response()
        }
        Ok(None) => (StatusCode::NOT_FOUND, Json(serde_json::json!({ "error": "block not found" }))).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": e.to_string() }))).into_response(),
    }
}

async fn proof_handler(
    State(state): State<AppState>,
    Path((chain_id, height)): Path<(u32, u64)>,
) -> impl IntoResponse {
    match state.db.block_at(chain_id, height) {
        Ok(Some(block)) => {
            let aux = match &block.header.aux {
                Some(a) => a,
                None => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({ "error": "block has no AuxPoW witness" }))).into_response(),
            };

            let mut bh = block.hash_le;
            bh.reverse();

            use sha2::{Digest, Sha256};
            let parent_hash_le = Sha256::digest(Sha256::digest(&aux.parent_header));
            let mut ph = [0u8; 32];
            ph.copy_from_slice(&parent_hash_le);
            let mut ph_disp = ph;
            ph_disp.reverse();

            let parent_info = state.db.get_parent(&ph).unwrap_or(None);
            let cb_txid = Sha256::digest(Sha256::digest(&aux.coinbase_tx));
            let mut cb_disp = [0u8; 32];
            cb_disp.copy_from_slice(&cb_txid);
            cb_disp.reverse();

            Json(BlockProofResponse {
                chain_id,
                height,
                block_hash: hex::encode(bh),
                parent_hash: hex::encode(ph_disp),
                ltc_height: parent_info.as_ref().and_then(|p| p.ltc_height),
                parent_state: parent_info.as_ref().map(|p| p.parent_state).unwrap_or(0),
                chain_index: aux.chain_index,
                chain_branch_depth: aux.chain_merkle_branch.len(),
                parent_index: aux.parent_index,
                parent_branch_depth: aux.parent_merkle_branch.len(),
                coinbase_txid: hex::encode(cb_disp),
                raw_header_hex: hex::encode(&block.header.raw),
            }).into_response()
        }
        Ok(None) => (StatusCode::NOT_FOUND, Json(serde_json::json!({ "error": "block not found" }))).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": e.to_string() }))).into_response(),
    }
}

async fn epoch_handler(
    State(state): State<AppState>,
    Path((ltc_start, ltc_end)): Path<(u64, u64)>,
) -> impl IntoResponse {
    match state.db.epoch_blocks(ltc_start, ltc_end) {
        Ok(blocks) => {
            let items: Vec<EpochBlockItem> = blocks
                .into_iter()
                .map(|(chain_id, height, ltc_height, hash_le)| {
                    let mut bh = hash_le;
                    bh.reverse();
                    EpochBlockItem {
                        chain_id,
                        height,
                        ltc_height,
                        block_hash: hex::encode(bh),
                    }
                })
                .collect();
            Json(EpochResponse {
                ltc_start,
                ltc_end,
                total_blocks: items.len(),
                blocks: items,
            }).into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({ "error": e.to_string() }))).into_response(),
    }
}

async fn verify_handler(
    Json(req): Json<VerifyRequest>,
) -> impl IntoResponse {
    let raw = match hex::decode(&req.header_hex) {
        Ok(b) if b.len() >= 80 => b,
        _ => return (StatusCode::BAD_REQUEST, Json(VerifyResponse {
            valid: false,
            chain_id: req.chain_id,
            block_hash: String::new(),
            parent_hash: String::new(),
            error: Some("invalid header hex bytes".to_string()),
        })).into_response(),
    };

    use sha2::{Digest, Sha256};
    let block_hash = Sha256::digest(Sha256::digest(&raw[..80]));
    let mut bh_disp = [0u8; 32];
    bh_disp.copy_from_slice(&block_hash);
    bh_disp.reverse();

    (StatusCode::OK, Json(VerifyResponse {
        valid: true,
        chain_id: req.chain_id,
        block_hash: hex::encode(bh_disp),
        parent_hash: String::new(),
        error: None,
    })).into_response()
}
