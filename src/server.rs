//! HTTP REST API server for the PSob Indexer.
//!
//! Design rules:
//!
//! * **Every block response is self-verifiable** — `auxpow_hex` carries the
//!   verbatim 80-byte header ‖ CAuxPow wire blob, so any client can re-run the
//!   full PSob checks locally without trusting the indexer.
//! * **Endianness contract** (see `API.md`): `block_hash` / `parent_hash` are
//!   display (big-endian) hex; `chain_merkle_branch` / `parent_merkle_branch`
//!   are raw wire (little-endian) hex exactly as serialized in CAuxPow — the
//!   byte order the merkle fold operates on.
//! * Errors are a single envelope: `{ "error": { "code", "message" } }`.
//! * List endpoints are paged with `limit`/`offset` and report `total`.

use std::sync::Arc;
use std::time::Instant;

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tower_http::{catch_panic::CatchPanicLayer, cors::CorsLayer, trace::TraceLayer};
use utoipa::{OpenApi, ToSchema};

use crate::config::Config;
use crate::db::{Database, Page, StoredBlock};
use crate::p2p::{P2pHandle, SwapIntentMessage};

// ─── state & openapi ──────────────────────────────────────────────────────────

#[derive(Clone)]
pub struct AppState {
    pub db: Arc<Database>,
    pub config: Config,
    pub p2p: Option<P2pHandle>,
    started_at: Instant,
}

impl AppState {
    pub fn new(db: Arc<Database>, config: Config, p2p: Option<P2pHandle>) -> Self {
        Self {
            db,
            config,
            p2p,
            started_at: Instant::now(),
        }
    }
}

#[derive(OpenApi)]
#[openapi(
    paths(
        health_handler,
        chains_handler,
        siblings_handler,
        sibling_detail_handler,
        blocks_handler,
        block_detail_handler,
        proof_handler,
        epoch_handler,
        epoch_latest_handler,
        verify_handler,
        stats_handler,
        p2p_status_handler,
        p2p_peers_handler,
        p2p_broadcast_handler,
    ),
    components(schemas(
        HealthResponse,
        ChainsResponse,
        ChainStatus,
        SiblingSummary,
        ChainLeg,
        SiblingDetail,
        SiblingBlockItem,
        BlockResponse,
        ProofResponse,
        BlocksResponse,
        EpochResponse,
        EpochBlockItem,
        VerifyResponse,
        StatsResponse,
        StatsChain,
        Paged<SiblingSummary>
    )),
    tags(
        (name = "health", description = "Service liveness"),
        (name = "chains", description = "Configured aux chains"),
        (name = "siblings", description = "Cross-chain sibling groups (shared Litecoin parent)"),
        (name = "blocks", description = "Indexed aux blocks and their PSob proofs"),
        (name = "epoch", description = "Epoch witness windows"),
        (name = "verify", description = "Client-side verification helpers"),
        (name = "p2p", description = "Libp2p gossip mesh")
    )
)]
pub struct ApiDoc;

pub fn openapi_doc() -> utoipa::openapi::OpenApi {
    ApiDoc::openapi()
}

// ─── error envelope ───────────────────────────────────────────────────────────

/// A single JSON error envelope: `{ "error": { "code", "message" } }`.
#[derive(Debug, Serialize)]
pub struct ApiErrorBody {
    pub code: &'static str,
    pub message: String,
}

#[derive(Debug)]
pub enum ApiError {
    BadRequest(String),
    NotFound(String),
    Internal(String),
}

impl From<anyhow::Error> for ApiError {
    fn from(e: anyhow::Error) -> Self {
        ApiError::Internal(format!("{e:#}"))
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code, message) = match self {
            ApiError::BadRequest(m) => (StatusCode::BAD_REQUEST, "bad_request", m),
            ApiError::NotFound(m) => (StatusCode::NOT_FOUND, "not_found", m),
            ApiError::Internal(m) => (StatusCode::INTERNAL_SERVER_ERROR, "internal_error", m),
        };
        (
            status,
            Json(json!({ "error": { "code": code, "message": message } })),
        )
            .into_response()
    }
}

// ─── response types ───────────────────────────────────────────────────────────

// Helper: mirror Page into a serializable response meta.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct Paged<T> {
    pub total: usize,
    pub limit: usize,
    pub offset: usize,
    pub items: Vec<T>,
}

fn paged<T>(total: usize, page: Page, items: Vec<T>) -> Paged<T> {
    Paged {
        total,
        limit: page.limit,
        offset: page.offset,
        items,
    }
}

#[derive(Debug, Serialize, ToSchema)]
pub struct HealthResponse {
    pub status: String,
    pub service: String,
    pub version: String,
    pub schema_version: u32,
    pub configured_chains: usize,
    pub total_blocks: u64,
    pub p2p_enabled: bool,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ChainStatus {
    pub chain_id: u32,
    pub name: String,
    pub electrs_url: String,
    pub cursor_height: Option<u64>,
    pub pow_limit_bits: String,
    pub blocks: u64,
    pub min_height: Option<u64>,
    pub max_height: Option<u64>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ChainsResponse {
    pub count: usize,
    pub chains: Vec<ChainStatus>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ChainLeg {
    pub chain_id: u32,
    pub name: Option<String>,
    pub height: u64,
    pub block_hash: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SiblingSummary {
    pub parent_hash: String,
    pub ltc_height: u64,
    pub legs_count: usize,
    pub legs: Vec<ChainLeg>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SiblingBlockItem {
    pub chain_id: u32,
    pub height: u64,
    pub block_hash: String,
    /// Self-verifiable wire blob (80-byte header ‖ CAuxPow) — present when the
    /// request has `include_auxpow=true`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auxpow_hex: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SiblingDetail {
    pub parent_hash: String,
    pub ltc_height: Option<u64>,
    pub parent_state: i64,
    pub sibling_count: usize,
    pub siblings: Vec<SiblingBlockItem>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct BlockResponse {
    pub chain_id: u32,
    pub height: u64,
    /// Display (big-endian) hex.
    pub block_hash: String,
    /// Display (big-endian) hex of the embedded parent (Litecoin anchor).
    pub parent_hash: String,
    pub ltc_height: Option<u64>,
    pub parent_state: i64,
    pub has_auxpow: bool,
    pub header_len: usize,
    pub wire_len: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_auxpow_hex: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verification: Option<crate::verify::VerificationReport>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ProofResponse {
    pub chain_id: u32,
    pub height: u64,
    /// Display (big-endian) hex.
    pub block_hash: String,
    /// Display (big-endian) hex.
    pub parent_hash: String,
    pub parent_chain_id: Option<u32>,
    /// Wire (little-endian) hex — exactly the CAuxPow serialization.
    pub parent_merkle_branch: Vec<String>,
    pub parent_index: u32,
    /// Wire (little-endian) hex.
    pub chain_merkle_branch: Vec<String>,
    pub chain_index: u32,
    pub coinbase_tx: String,
    pub parent_header: String,
    /// The verbatim wire blob — all data to re-verify on the client.
    pub auxpow_hex: String,
    pub ltc_height: Option<u64>,
    pub parent_state: i64,
    pub coinbase_txid: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct BlocksResponse {
    pub chain_id: u32,
    pub blocks: Vec<BlockResponse>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct EpochBlockItem {
    pub chain_id: u32,
    pub height: u64,
    pub ltc_height: u64,
    pub block_hash: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct EpochResponse {
    pub ltc_start: u64,
    pub ltc_end: u64,
    pub total_blocks: usize,
    pub limit: usize,
    pub offset: usize,
    pub blocks: Vec<EpochBlockItem>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct VerifyResponse {
    pub valid: bool,
    pub chain_id: u32,
    pub block_hash: String,
    pub parent_hash: String,
    pub parent_chain_id: Option<u32>,
    pub coinbase_root_hex: String,
    pub n_size: u32,
    pub nonce: u32,
    pub chain_branch_depth: usize,
    pub chain_index: u32,
    pub verification: crate::verify::VerificationReport,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct StatsChain {
    pub chain_id: u32,
    pub name: String,
    pub cursor_height: Option<u64>,
    pub blocks: u64,
    pub min_height: Option<u64>,
    pub max_height: Option<u64>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct StatsResponse {
    pub version: String,
    pub uptime_seconds: u64,
    pub total_blocks: u64,
    pub total_parents: usize,
    pub sibling_groups: usize,
    pub chains: Vec<StatsChain>,
}

// ─── query params ─────────────────────────────────────────────────────────────

#[derive(Debug, Default, Deserialize)]
pub struct PagingParams {
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

impl PagingParams {
    pub fn page(&self) -> Page {
        Page::new(self.limit, self.offset)
    }
}

#[derive(Debug, Deserialize)]
pub struct SiblingQuery {
    pub min_legs: Option<usize>,
    pub chain_id: Option<u32>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

#[derive(Debug, Deserialize)]
pub struct SiblingDetailQuery {
    pub include_auxpow: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct BlocksQuery {
    pub chain_id: Option<u32>,
    pub from: Option<u64>,
    pub to: Option<u64>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

#[derive(Debug, Deserialize)]
pub struct EpochQuery {
    pub chain_id: Option<u32>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

#[derive(Debug, Deserialize)]
pub struct VerifyRequest {
    pub chain_id: u32,
    /// Full wire payload: 80-byte header ‖ CAuxPow, hex.
    pub wire_hex: String,
    /// Pow limit bytes (headered chain's consensus floor). Optional when the
    /// chain is configured on the indexer.
    pub pow_limit_bits: Option<u32>,
}

// ─── helpers ──────────────────────────────────────────────────────────────────

fn display_hex(le: &[u8; 32]) -> String {
    let mut b = *le;
    b.reverse();
    hex::encode(b)
}

fn le_of_display(hex_str: &str) -> anyhow::Result<[u8; 32]> {
    let bytes = hex::decode(hex_str).map_err(|e| anyhow::anyhow!("invalid hex: {e}"))?;
    if bytes.len() != 32 {
        anyhow::bail!("expected a 32-byte hash, got {}", bytes.len());
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    arr.reverse();
    Ok(arr)
}

fn chain_name(config: &Config, chain_id: u32) -> Option<String> {
    config
        .chains
        .iter()
        .find(|c| c.chain_id == chain_id)
        .map(|c| c.name.clone())
}

fn pow_limit_for(config: &Config, chain_id: u32) -> Option<u32> {
    config
        .chains
        .iter()
        .find(|c| c.chain_id == chain_id)
        .map(|c| c.pow_limit_bits)
}

fn block_from_stored(state: &AppState, block: &StoredBlock) -> anyhow::Result<BlockResponse> {
    let parent_bytes = block
        .header
        .aux
        .as_ref()
        .map(|a| crate::db::sha256d(&a.parent_header));
    let parent_info = match parent_bytes {
        Some(pb) => state.db.get_parent(&pb)?,
        None => None,
    };
    Ok(BlockResponse {
        chain_id: block.chain_id,
        height: block.height,
        block_hash: display_hex(&block.hash_le),
        parent_hash: parent_bytes.as_ref().map(display_hex).unwrap_or_default(),
        ltc_height: parent_info.as_ref().and_then(|p| p.ltc_height),
        parent_state: parent_info.as_ref().map(|p| p.parent_state).unwrap_or(0),
        has_auxpow: block.header.aux.is_some(),
        header_len: block.header.raw.len(),
        wire_len: block.wire_hex.len() / 2,
        raw_auxpow_hex: Some(block.wire_hex.clone()),
        verification: None,
    })
}

fn proof_from_stored(state: &AppState, block: &StoredBlock) -> anyhow::Result<ProofResponse> {
    let aux = block.header.aux.as_ref().ok_or_else(|| {
        anyhow::anyhow!(
            "block {}@{} has no AuxPoW witness",
            block.chain_id,
            block.height
        )
    })?;
    let parent_bytes = crate::db::sha256d(&aux.parent_header);
    let parent_info = state.db.get_parent(&parent_bytes)?;

    let cb_txid = common::sha256d(&aux.coinbase_tx);
    let chain_merkle_branch: Vec<String> =
        aux.chain_merkle_branch.iter().map(hex::encode).collect();
    let parent_merkle_branch: Vec<String> =
        aux.parent_merkle_branch.iter().map(hex::encode).collect();

    Ok(ProofResponse {
        chain_id: block.chain_id,
        height: block.height,
        block_hash: display_hex(&block.hash_le),
        parent_hash: display_hex(&parent_bytes),
        parent_chain_id: aux.parent_chain_id(),
        parent_merkle_branch,
        parent_index: aux.parent_index,
        chain_merkle_branch,
        chain_index: aux.chain_index,
        coinbase_tx: hex::encode(&aux.coinbase_tx),
        parent_header: hex::encode(&aux.parent_header),
        auxpow_hex: block.wire_hex.clone(),
        ltc_height: parent_info.as_ref().and_then(|p| p.ltc_height),
        parent_state: parent_info.as_ref().map(|p| p.parent_state).unwrap_or(0),
        coinbase_txid: display_hex(&cb_txid),
    })
}

// ─── routes ───────────────────────────────────────────────────────────────────

pub fn create_router(state: AppState) -> Router {
    let cors = if state.config.cors_origins.iter().any(|o| o == "*") {
        CorsLayer::permissive()
    } else {
        CorsLayer::new().allow_origin(
            state
                .config
                .cors_origins
                .iter()
                .map(|o| o.parse().expect("configured CORS origin must parse"))
                .collect::<Vec<_>>(),
        )
    };

    let api: Router<()> = Router::new()
        .route("/health", get(health_handler))
        .route("/api/v1/health", get(health_handler))
        .route("/api/v1/chains", get(chains_handler))
        .route("/api/v1/siblings", get(siblings_handler))
        .route("/api/v1/siblings/:parent_hash", get(sibling_detail_handler))
        .route("/api/v1/blocks", get(blocks_handler))
        .route("/api/v1/block/:chain_id/:height", get(block_detail_handler))
        .route("/api/v1/proof/:chain_id/:height", get(proof_handler))
        .route("/api/v1/epoch/:ltc_start/:ltc_end", get(epoch_handler))
        .route("/api/v1/epoch/latest", get(epoch_latest_handler))
        .route("/api/v1/verify", post(verify_handler))
        .route("/api/v1/stats", get(stats_handler))
        .route("/api/v1/p2p/status", get(p2p_status_handler))
        .route("/api/v1/p2p/peers", get(p2p_peers_handler))
        .route("/api/v1/p2p/broadcast", post(p2p_broadcast_handler))
        .with_state(state);
    let docs: Router<()> = utoipa_swagger_ui::SwaggerUi::new("/docs")
        .url("/api/v1/openapi.json", openapi_doc())
        .into();
    Router::new()
        .merge(docs)
        .merge(api)
        .layer(TraceLayer::new_for_http())
        .layer(CatchPanicLayer::new())
        .layer(cors)
}

#[utoipa::path(
    get,
    path = "/api/v1/health",
    tag = "health",
    responses((status = 200, description = "Service health", body = HealthResponse))
)]
async fn health_handler(State(state): State<AppState>) -> Json<HealthResponse> {
    let total_blocks = state.db.total_blocks().unwrap_or(0);
    Json(HealthResponse {
        status: "ok".into(),
        service: "psob-indexer".into(),
        version: env!("CARGO_PKG_VERSION").into(),
        schema_version: crate::db::SCHEMA_VERSION,
        configured_chains: state.config.chains.len(),
        total_blocks,
        p2p_enabled: state.p2p.is_some(),
    })
}

#[utoipa::path(
    get,
    path = "/api/v1/chains",
    tag = "chains",
    responses((status = 200, description = "Configured aux chains and sync cursors", body = ChainsResponse))
)]
async fn chains_handler(State(state): State<AppState>) -> Result<Json<ChainsResponse>, ApiError> {
    let mut chains = Vec::new();
    for c in &state.config.chains {
        let cursor = state.db.cursor_height(c.chain_id)?;
        let stats = state
            .db
            .stats()?
            .chains
            .into_iter()
            .find(|s| s.chain_id == c.chain_id);
        chains.push(ChainStatus {
            chain_id: c.chain_id,
            name: c.name.clone(),
            electrs_url: c.electrs.clone(),
            cursor_height: cursor,
            pow_limit_bits: format!("{:#010x}", c.pow_limit_bits),
            blocks: stats.as_ref().map(|s| s.blocks).unwrap_or(0),
            min_height: stats.as_ref().and_then(|s| s.min_height),
            max_height: stats.as_ref().and_then(|s| s.max_height),
        });
    }
    Ok(Json(ChainsResponse {
        count: chains.len(),
        chains,
    }))
}

#[utoipa::path(
    get,
    path = "/api/v1/siblings",
    tag = "siblings",
    params(
        ("min_legs" = Option<usize>, Query, description = "Minimum distinct chains sharing the parent"),
        ("chain_id" = Option<u32>, Query, description = "Include only groups with a leg on this chain"),
        ("limit" = Option<usize>, Query, description = "Page size (default 20, max 200)"),
        ("offset" = Option<usize>, Query, description = "Page offset")
    ),
    responses((status = 200, description = "Paged sibling groups", body = Paged<SiblingSummary>))
)]
async fn siblings_handler(
    State(state): State<AppState>,
    Query(q): Query<SiblingQuery>,
) -> Result<Json<Paged<SiblingSummary>>, ApiError> {
    let page = Page::new(q.limit, q.offset);
    let parents = state
        .db
        .shared_mainnet_parents(q.min_legs.unwrap_or(2), page, q.chain_id)?;
    let items: Vec<SiblingSummary> = parents
        .into_iter()
        .map(|p| SiblingSummary {
            parent_hash: display_hex(&p.parent_hash_le),
            ltc_height: p.ltc_height,
            legs_count: p.legs.len(),
            legs: p
                .legs
                .into_iter()
                .map(|(c, h)| ChainLeg {
                    chain_id: c,
                    name: chain_name(&state.config, c),
                    height: h,
                    // hash lookup is done by the detail endpoint; keep pagination cheap
                    block_hash: String::new(),
                })
                .collect(),
        })
        .collect();
    let total = state
        .db
        .shared_mainnet_parents(1, Page::default(), None)?
        .len();
    Ok(Json(paged(total, page, items)))
}

#[utoipa::path(
    get,
    path = "/api/v1/siblings/{parent_hash}",
    tag = "siblings",
    params(
        ("parent_hash" = String, Path, description = "Display (big-endian) hex parent hash"),
        ("include_auxpow" = Option<bool>, Query, description = "Include raw auxpow_hex per sibling (larger responses)")
    ),
    responses(
        (status = 200, description = "Sibling group under one Litecoin parent", body = SiblingDetail),
        (status = 404, description = "Unknown parent hash")
    )
)]
async fn sibling_detail_handler(
    State(state): State<AppState>,
    Path(parent_hash_hex): Path<String>,
    Query(q): Query<SiblingDetailQuery>,
) -> Result<Json<SiblingDetail>, ApiError> {
    let parent_bytes =
        le_of_display(&parent_hash_hex).map_err(|e| ApiError::BadRequest(e.to_string()))?;
    let parent_info = state.db.get_parent(&parent_bytes)?.ok_or_else(|| {
        ApiError::NotFound(format!("parent hash {parent_hash_hex} is not indexed"))
    })?;

    let (siblings, total) = state
        .db
        .sibling_blocks_range(&parent_bytes, Page::default())?;
    let include_aux = q.include_auxpow.unwrap_or(false);
    let items: Vec<SiblingBlockItem> = siblings
        .iter()
        .map(|s| SiblingBlockItem {
            chain_id: s.chain_id,
            height: s.height,
            block_hash: display_hex(&s.hash_le),
            auxpow_hex: if include_aux {
                Some(s.wire_hex.clone())
            } else {
                None
            },
        })
        .collect();

    Ok(Json(SiblingDetail {
        parent_hash: parent_hash_hex,
        ltc_height: parent_info.ltc_height,
        parent_state: parent_info.parent_state,
        sibling_count: total,
        siblings: items,
    }))
}

#[utoipa::path(
    get,
    path = "/api/v1/blocks",
    tag = "blocks",
    params(
        ("chain_id" = u32, Query, description = "Aux chain id"),
        ("from" = Option<u64>, Query, description = "Inclusive lower height"),
        ("to" = Option<u64>, Query, description = "Inclusive upper height"),
        ("limit" = Option<usize>, Query, description = "Max items per page (default 20, max 200)"),
        ("offset" = Option<usize>, Query, description = "Skip this many items")
    ),
    responses((status = 200, description = "Paged block list", body = BlocksResponse))
)]
async fn blocks_handler(
    State(state): State<AppState>,
    Query(q): Query<BlocksQuery>,
) -> Result<Json<BlocksResponse>, ApiError> {
    let chain_id = q
        .chain_id
        .ok_or_else(|| ApiError::BadRequest("chain_id query parameter is required".into()))?;
    let page = Page::new(q.limit, q.offset);
    let (from, to) = match (q.from, q.to) {
        (Some(f), Some(t)) => (f, t),
        (Some(f), None) => (f, u64::MAX),
        (None, Some(t)) => (0, t),
        (None, None) => (0, u64::MAX),
    };
    let blocks = state.db.blocks_range(chain_id, from, to, page)?;
    let items: Vec<BlockResponse> = blocks
        .iter()
        .map(|b| block_from_stored(&state, b))
        .collect::<anyhow::Result<Vec<_>>>()?;
    Ok(Json(BlocksResponse {
        chain_id,
        blocks: items,
    }))
}

#[utoipa::path(
    get,
    path = "/api/v1/block/{chain_id}/{height}",
    tag = "blocks",
    responses(
        (status = 200, description = "Stored block with self-verifiable raw data", body = BlockResponse),
        (status = 404, description = "Not indexed")
    )
)]
async fn block_detail_handler(
    State(state): State<AppState>,
    Path((chain_id, height)): Path<(u32, u64)>,
) -> Result<Json<BlockResponse>, ApiError> {
    let block = state
        .db
        .block_at(chain_id, height)?
        .ok_or_else(|| ApiError::NotFound(format!("block {chain_id}@{height} is not indexed")))?;
    let mut response = block_from_stored(&state, &block)?;
    // Include the full per-step verification result — the indexer re-checks on
    // every read so a tampered row cannot survive a verification-carrying client.
    if let (Some(aux), Some(pl)) = (&block.header.aux, pow_limit_for(&state.config, chain_id)) {
        response.verification = Some(crate::verify::verify_aux_header(
            &block.header.raw,
            aux,
            chain_id,
            pl,
        ));
    }
    Ok(Json(response))
}

#[utoipa::path(
    get,
    path = "/api/v1/proof/{chain_id}/{height}",
    tag = "blocks",
    responses(
        (status = 200, description = "PSob proof witness (all fields to re-verify client-side)", body = ProofResponse),
        (status = 404, description = "Not indexed"),
        (status = 400, description = "Block has no AuxPoW witness")
    )
)]
async fn proof_handler(
    State(state): State<AppState>,
    Path((chain_id, height)): Path<(u32, u64)>,
) -> Result<Json<ProofResponse>, ApiError> {
    let block = state
        .db
        .block_at(chain_id, height)?
        .ok_or_else(|| ApiError::NotFound(format!("block {chain_id}@{height} is not indexed")))?;
    Ok(Json(proof_from_stored(&state, &block)?))
}

#[utoipa::path(
    get,
    path = "/api/v1/epoch/{ltc_start}/{ltc_end}",
    tag = "epoch",
    params(
        ("ltc_start" = u64, Path, description = "Inclusive LTC height window start"),
        ("ltc_end" = u64, Path, description = "Inclusive LTC height window end"),
        ("chain_id" = Option<u32>, Query, description = "Filter by aux chain id"),
        ("limit" = Option<usize>, Query, description = "Max items per page (default 20, max 200)"),
        ("offset" = Option<usize>, Query, description = "Skip this many items")
    ),
    responses((status = 200, description = "Paged epoch witness blocks", body = EpochResponse))
)]
async fn epoch_handler(
    State(state): State<AppState>,
    Path((ltc_start, ltc_end)): Path<(u64, u64)>,
    Query(q): Query<EpochQuery>,
) -> Result<Json<EpochResponse>, ApiError> {
    if ltc_start > ltc_end {
        return Err(ApiError::BadRequest("ltc_start must be <= ltc_end".into()));
    }
    let page = Page::new(q.limit, q.offset);
    let all = state
        .db
        .epoch_blocks(ltc_start, ltc_end, q.chain_id, Page::default())?;
    let blocks = state
        .db
        .epoch_blocks(ltc_start, ltc_end, q.chain_id, page)?;
    let items: Vec<EpochBlockItem> = blocks
        .into_iter()
        .map(|(chain_id, height, ltc_h, hash_le)| EpochBlockItem {
            chain_id,
            height,
            ltc_height: ltc_h,
            block_hash: display_hex(&hash_le),
        })
        .collect();
    Ok(Json(EpochResponse {
        ltc_start,
        ltc_end,
        total_blocks: all.len(),
        limit: page.limit,
        offset: page.offset,
        blocks: items,
    }))
}

#[utoipa::path(
    get,
    path = "/api/v1/epoch/latest",
    tag = "epoch",
    params(("min_legs" = Option<usize>, Query, description = "Minimum distinct chains (default 2)")),
    responses(
        (status = 200, description = "Latest sibling group", body = SiblingSummary),
        (status = 404, description = "No sibling groups indexed yet")
    )
)]
async fn epoch_latest_handler(
    State(state): State<AppState>,
    Query(q): Query<SiblingQuery>,
) -> Result<Json<SiblingSummary>, ApiError> {
    let group = state
        .db
        .latest_sibling_group(q.min_legs.unwrap_or(2))?
        .ok_or_else(|| ApiError::NotFound("no sibling groups indexed yet".into()))?;
    Ok(Json(SiblingSummary {
        parent_hash: display_hex(&group.parent_hash_le),
        ltc_height: group.ltc_height,
        legs_count: group.legs.len(),
        legs: group
            .legs
            .into_iter()
            .map(|(c, h)| ChainLeg {
                chain_id: c,
                name: chain_name(&state.config, c),
                height: h,
                block_hash: String::new(),
            })
            .collect(),
    }))
}

#[utoipa::path(
    post,
    path = "/api/v1/verify",
    tag = "verify",
    request_body = VerifyRequest,
    responses(
        (status = 200, description = "Full per-step verification result", body = VerifyResponse),
        (status = 400, description = "Malformed wire / missing pow_limit")
    )
)]
async fn verify_handler(
    State(state): State<AppState>,
    Json(req): Json<VerifyRequest>,
) -> Result<Json<VerifyResponse>, ApiError> {
    let wire = hex::decode(&req.wire_hex)
        .map_err(|e| ApiError::BadRequest(format!("wire_hex is not valid hex: {e}")))?;
    let pow_limit = match req.pow_limit_bits {
        Some(pl) => pl,
        None => pow_limit_for(&state.config, req.chain_id).ok_or_else(|| {
            ApiError::BadRequest("chain not configured: supply pow_limit_bits".into())
        })?,
    };

    let (aux_block, report) = crate::verify::verify_wire_block(&wire, req.chain_id, pow_limit)
        .map_err(|e| ApiError::BadRequest(format!("cannot parse CAuxPow wire: {e}")))?;

    Ok(Json(VerifyResponse {
        valid: report.valid,
        chain_id: req.chain_id,
        block_hash: aux_block.block_hash_display(),
        parent_hash: aux_block.parent_hash_display(),
        parent_chain_id: aux_block.aux.parent_chain_id(),
        coinbase_root_hex: report.coinbase_root_hex.clone(),
        n_size: report.n_size,
        nonce: report.nonce,
        chain_branch_depth: report.chain_branch_depth,
        chain_index: report.chain_index,
        verification: report,
    }))
}

#[utoipa::path(
    get,
    path = "/api/v1/stats",
    tag = "chains",
    responses((status = 200, description = "Indexer stats", body = StatsResponse))
)]
async fn stats_handler(State(state): State<AppState>) -> Result<Json<StatsResponse>, ApiError> {
    let stats = state.db.stats()?;
    let chains: Vec<StatsChain> = stats
        .chains
        .into_iter()
        .map(|c| StatsChain {
            chain_id: c.chain_id,
            name: chain_name(&state.config, c.chain_id)
                .unwrap_or_else(|| format!("chain{}", c.chain_id)),
            cursor_height: state.db.cursor_height(c.chain_id).ok().flatten(),
            blocks: c.blocks,
            min_height: c.min_height,
            max_height: c.max_height,
        })
        .collect();
    Ok(Json(StatsResponse {
        version: env!("CARGO_PKG_VERSION").into(),
        uptime_seconds: state.started_at.elapsed().as_secs(),
        total_blocks: stats.total_blocks,
        total_parents: stats.total_parents,
        sibling_groups: stats.sibling_groups,
        chains,
    }))
}

// ─── p2p handlers ─────────────────────────────────────────────────────────────

#[utoipa::path(
    get,
    path = "/api/v1/p2p/status",
    tag = "p2p",
    responses((status = 200, description = "P2P subsystem status"), (status = 503, description = "P2P disabled"))
)]
async fn p2p_status_handler(State(state): State<AppState>) -> Response {
    match &state.p2p {
        Some(handle) => {
            Json(serde_json::to_value(&*handle.status.read().await).unwrap()).into_response()
        }
        None => {
            ApiError::Internal("P2P subsystem is not enabled on this node".into()).into_response()
        }
    }
}

#[utoipa::path(
    get,
    path = "/api/v1/p2p/peers",
    tag = "p2p",
    responses((status = 200, description = "Connected peers"), (status = 503, description = "P2P disabled"))
)]
async fn p2p_peers_handler(State(state): State<AppState>) -> Response {
    match &state.p2p {
        Some(handle) => {
            let status = handle.status.read().await;
            Json(json!({
                "connected_peers_count": status.connected_peers_count,
                "connected_peers": status.connected_peers,
            }))
            .into_response()
        }
        None => ApiError::Internal("P2P subsystem is not enabled".into()).into_response(),
    }
}

#[utoipa::path(
    post,
    path = "/api/v1/p2p/broadcast",
    tag = "p2p",
    request_body = SwapIntentMessage,
    responses((status = 200, description = "Intent broadcast to gossip mesh"), (status = 503, description = "P2P disabled"))
)]
async fn p2p_broadcast_handler(
    State(state): State<AppState>,
    Json(intent): Json<SwapIntentMessage>,
) -> Response {
    match &state.p2p {
        Some(handle) => match handle.tx_intent.send(intent.clone()).await {
            Ok(_) => Json(json!({
                "status": "broadcasted",
                "intent_id": intent.intent_id,
                "peer_count": handle.status.read().await.connected_peers_count,
            }))
            .into_response(),
            Err(e) => ApiError::Internal(e.to_string()).into_response(),
        },
        None => ApiError::Internal("P2P subsystem is not enabled".into()).into_response(),
    }
}
