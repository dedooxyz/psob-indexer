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
    extract::{connect_info::ConnectInfo, DefaultBodyLimit, Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use std::net::SocketAddr;
use serde::{Deserialize, Serialize};
use serde_json::json;
use tower_http::{catch_panic::CatchPanicLayer, cors::CorsLayer, trace::TraceLayer};

use crate::metrics::Metrics;
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
    pub metrics: Arc<Metrics>,
    started_at: Instant,
}

impl AppState {
    pub fn new(
        db: Arc<Database>,
        config: Config,
        p2p: Option<P2pHandle>,
        metrics: Arc<Metrics>,
    ) -> Self {
        Self {
            db,
            config,
            p2p,
            metrics,
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
        cosettle_handler,
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
        Paged<SiblingSummary>,
        CoSettleResponse,
        CoSettleLeg
    )),
    tags(
        (name = "health", description = "Service liveness"),
        (name = "chains", description = "Configured aux chains"),
        (name = "siblings", description = "Cross-chain sibling groups (shared Litecoin parent)"),
        (name = "blocks", description = "Indexed aux blocks and their PSob proofs"),
        (name = "epoch", description = "Epoch witness windows"),
        (name = "verify", description = "Client-side verification helpers"),
        (name = "p2p", description = "Libp2p gossip mesh"),
        (name = "psob-swap", description = "PSOB psob-swap/1 order book + co-settlement")
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

/// Query for the PSOB co-settlement proof. Heights default to each chain's
/// latest indexed block when omitted (so a client can ask "are the two chains
/// currently co-settled at the tip?").
#[derive(Debug, Deserialize)]
pub struct CoSettleQuery {
    pub a_chain: u32,
    #[serde(default)]
    pub a_height: Option<u64>,
    pub b_chain: u32,
    #[serde(default)]
    pub b_height: Option<u64>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct CoSettleLeg {
    pub chain_id: u32,
    pub height: u64,
    /// Display (big-endian) hex of the aux block.
    pub block_hash: String,
    /// Display (big-endian) hex of the embedded Litecoin parent.
    pub parent_hash: String,
    pub ltc_height: Option<u64>,
    pub is_auxpow: bool,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct CoSettleResponse {
    /// True iff both legs embed the *same* Litecoin parent block — i.e. the two
    /// on-chain settlements are provably co-temporal under one LTC anchor.
    pub co_settled: bool,
    /// Display (big-endian) hex of the shared Litecoin parent (None if not).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shared_ltc_parent: Option<String>,
    pub ltc_height: Option<u64>,
    /// Co-settlement receipt token: sha256 of the canonical
    /// `(a_chain,a_height,b_chain,b_height,parent_a,parent_b)` tuple.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub epoch: Option<String>,
    pub a: CoSettleLeg,
    pub b: CoSettleLeg,
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
    /// H2 — explicit honesty flag: the indexer does NOT verify scrypt PoW (that is
    /// the ZK guest's job). `valid:true` only means the structural / AuxPoW
    /// commitment checks passed. Never treat `valid` as proof-of-work authority.
    pub pow_checked: bool,
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

/// M8 — upper bound on `wire_hex` size for `/verify`. A real AuxPoW wire blob
/// (80-byte header ‖ CAuxPow) is a few hundred bytes to a few KB; anything larger
/// is either malformed or a memory-exhaustion attempt.
const MAX_WIRE_HEX_LEN: usize = 1_000_000;

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
    /// H2 — retained only for client compatibility. The indexer NEVER trusts a
    /// caller-supplied pow limit: a caller could otherwise present a diff-1 limit
    /// and have `valid:true` bless a forgeable header. The configured chain's
    /// consensus `pow_limit_bits` is always used instead. Ignored if present.
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

#[derive(Debug, Deserialize)]
pub struct SwapIntentQuery {
    pub from: Option<u32>,
    pub to: Option<u32>,
    pub protocol: Option<String>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
}

#[utoipa::path(
    post,
    path = "/api/v1/swap/intents",
    tag = "swap",
    responses((status = 200, description = "Intent accepted & stored", body = serde_json::Value))
)]
async fn create_swap_intent(
    State(state): State<AppState>,
    Json(intent): Json<SwapIntentMessage>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let known: std::collections::HashSet<u32> = state
        .db
        .chain_registry()
        .into_iter()
        .map(|(id, _, _)| id)
        .collect();
    crate::swap::validate_swap_intent(&intent, &known)
        .map_err(|e| ApiError::BadRequest(format!("invalid swap intent: {e}")))?;
    state
        .db
        .insert_intent(&intent)
        .map_err(|e| ApiError::Internal(format!("could not store intent: {e}")))?;
    if let Some(handle) = &state.p2p {
        handle.broadcast_intent(intent.clone()).await;
    }
    Ok(Json(json!({"status": "accepted", "intent_id": intent.intent_id})))
}

#[utoipa::path(
    get,
    path = "/api/v1/swap/intents",
    tag = "swap",
    params(
        ("from" = Option<u32>, Query, description = "Filter by from_chain"),
        ("to" = Option<u32>, Query, description = "Filter by to_chain"),
        ("protocol" = Option<String>, Query, description = "Filter by protocol"),
        ("limit" = Option<usize>, Query, description = "Max items per page (default 20, max 200)"),
        ("offset" = Option<usize>, Query, description = "Skip this many items")
    ),
    responses((status = 200, description = "Paged swap intents", body = serde_json::Value))
)]
async fn list_swap_intents(
    State(state): State<AppState>,
    Query(q): Query<SwapIntentQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let page = Page::new(q.limit, q.offset);
    let (items, total) = state
        .db
        .list_intents(q.from, q.to, q.protocol.as_deref(), page)
        .map_err(|e| ApiError::Internal(format!("could not list intents: {e}")))?;
    Ok(Json(json!({"total": total, "intents": items})))
}

/// Build one leg of the co-settlement response from a stored block.
fn cosettle_leg(
    state: &AppState,
    chain_id: u32,
    height: u64,
    block: &StoredBlock,
    parent_le: Option<[u8; 32]>,
) -> CoSettleLeg {
    let block_hash = display_hex(&block.hash_le);
    let (parent_hash, ltc_height, is_auxpow) = match (&block.header.aux, parent_le) {
        (Some(_), Some(p)) => {
            let info = state.db.get_parent(&p).ok().flatten();
            (display_hex(&p), info.and_then(|i| i.ltc_height), true)
        }
        _ => (String::new(), None, false),
    };
    CoSettleLeg {
        chain_id,
        height,
        block_hash,
        parent_hash,
        ltc_height,
        is_auxpow,
    }
}

#[utoipa::path(
    get,
    path = "/api/v1/cosettle",
    tag = "psob-swap",
    params(
        ("a_chain" = u32, Query, description = "Aux chain id of leg A"),
        ("a_height" = Option<u64>, Query, description = "Block height of leg A (default: latest indexed)"),
        ("b_chain" = u32, Query, description = "Aux chain id of leg B"),
        ("b_height" = Option<u64>, Query, description = "Block height of leg B (default: latest indexed)")
    ),
    responses(
        (status = 200, description = "Co-settlement proof for the two legs", body = CoSettleResponse),
        (status = 404, description = "Chain/height not indexed"),
        (status = 400, description = "Malformed query")
    )
)]
async fn cosettle_handler(
    State(state): State<AppState>,
    Query(q): Query<CoSettleQuery>,
) -> Result<Json<CoSettleResponse>, ApiError> {
    let a_height = match q.a_height {
        Some(h) => h,
        None => state
            .db
            .latest_height(q.a_chain)?
            .ok_or_else(|| ApiError::NotFound(format!("no blocks indexed for chain {}", q.a_chain)))?,
    };
    let b_height = match q.b_height {
        Some(h) => h,
        None => state
            .db
            .latest_height(q.b_chain)?
            .ok_or_else(|| ApiError::NotFound(format!("no blocks indexed for chain {}", q.b_chain)))?,
    };
    let ba = state
        .db
        .block_at(q.a_chain, a_height)?
        .ok_or_else(|| ApiError::NotFound(format!("block {}@{} is not indexed", q.a_chain, a_height)))?;
    let bb = state
        .db
        .block_at(q.b_chain, b_height)?
        .ok_or_else(|| ApiError::NotFound(format!("block {}@{} is not indexed", q.b_chain, b_height)))?;

    let pa = ba.header.aux.as_ref().map(|a| crate::db::sha256d(&a.parent_header));
    let pb = bb.header.aux.as_ref().map(|a| crate::db::sha256d(&a.parent_header));
    let co_settled = matches!((&pa, &pb), (Some(x), Some(y)) if x == y);

    let (shared_ltc_parent, ltc_height, epoch) = if co_settled {
        let p = pa.unwrap();
        let info = state.db.get_parent(&p)?;
        let ltc_h = info.and_then(|i| i.ltc_height);
        let token = crate::db::sha256d(
            format!(
                "{}/{}/{}/{}/{}/{}",
                q.a_chain, a_height, q.b_chain, b_height, display_hex(&p), display_hex(&p)
            )
            .as_bytes(),
        );
        (Some(display_hex(&p)), ltc_h, Some(display_hex(&token)))
    } else {
        (None, None, None)
    };

    let a_leg = cosettle_leg(&state, q.a_chain, a_height, &ba, pa);
    let b_leg = cosettle_leg(&state, q.b_chain, b_height, &bb, pb);

    Ok(Json(CoSettleResponse {
        co_settled,
        shared_ltc_parent,
        ltc_height,
        epoch,
        a: a_leg,
        b: b_leg,
    }))
}

/// M8 — shared state for the auth/rate-limit middleware.
#[derive(Clone)]
struct SecurityState {
    config: Config,
    buckets: Arc<tokio::sync::Mutex<std::collections::HashMap<std::net::IpAddr, (u32, std::time::Instant)>>>,
}

/// M8 — best-effort security middleware: optional bearer-token auth and optional
/// per-client rate limiting. Both controls are off by default (unset config), so
/// the indexer behaves as before on trusted LAN/local deployments.
async fn security_middleware(
    State(sec): State<SecurityState>,
    req: axum::http::Request<axum::body::Body>,
    next: axum::middleware::Next,
) -> axum::response::Response {
    // 1) Optional bearer-token authentication (constant-time comparison).
    if let Some(expected) = &sec.config.auth_token {
        let ok = req
            .headers()
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .map(|v| constant_time_eq(v.as_bytes(), format!("Bearer {expected}").as_bytes()))
            .unwrap_or(false);
        if !ok {
            return (
                axum::http::StatusCode::UNAUTHORIZED,
                [(
                    axum::http::header::WWW_AUTHENTICATE,
                    "Bearer",
                )],
                "missing or invalid Authorization bearer token",
            )
                .into_response();
        }
    }

    // 2) Optional per-client rate limiting. Key on the real TCP peer when the
    //    server was started with connect-info (production); otherwise fall back to
    //    the first `x-forwarded-for` hop (trusted-proxy deployments); if neither is
    //    available we cannot attribute, so we skip rather than lock out traffic.
    if let Some(limit) = sec.config.rate_limit_per_min {
        let client_ip: Option<std::net::IpAddr> = req
            .extensions()
            .get::<ConnectInfo<SocketAddr>>()
            .map(|c| c.ip())
            .or_else(|| {
                req.headers()
                    .get("x-forwarded-for")
                    .and_then(|v| v.to_str().ok())
                    .and_then(|v| v.split(',').next())
                    .and_then(|s| s.trim().parse::<std::net::IpAddr>().ok())
            });
        if let Some(ip) = client_ip {
            let mut buckets = sec.buckets.lock().await;
            // Bound map growth: drop it if a spoofed-header flood inflated it.
            if buckets.len() > 65_536 {
                buckets.clear();
            }
            let now = std::time::Instant::now();
            let entry = buckets.entry(ip).or_insert((0, now));
            if now.duration_since(entry.1).as_secs() >= 60 {
                *entry = (0, now);
            }
            if entry.0 >= limit {
                return (
                    axum::http::StatusCode::TOO_MANY_REQUESTS,
                    "rate limit exceeded (per minute)",
                )
                    .into_response();
            }
            entry.0 += 1;
        }
    }

    next.run(req).await
}

/// Constant-time byte comparison (avoid leaking token length via timing).
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

pub fn create_router(state: AppState) -> Router {
    let cors = if state.config.cors_origins.iter().any(|o| o == "*") {
        tracing::warn!(
            cors_origins = "*",
            "CORS is permissive ('*'). Set PSOB_CORS_ORIGINS to explicit origins in production."
        );
        CorsLayer::permissive()
    } else {
        // A single malformed origin must NOT panic the whole server at boot.
        // Skip invalid entries (logged) and fail *closed* (deny all cross-origin)
        // if nothing valid remains, rather than silently allowing everything.
        let origins: Vec<axum::http::HeaderValue> = state
            .config
            .cors_origins
            .iter()
            .filter_map(|o| match o.parse::<axum::http::HeaderValue>() {
                Ok(v) => Some(v),
                Err(e) => {
                    tracing::warn!(origin = %o, err = %e, "skipping invalid CORS origin");
                    None
                }
            })
            .collect();
        if origins.is_empty() {
            CorsLayer::new()
        } else {
            CorsLayer::new().allow_origin(origins)
        }
    };

    let metrics = Arc::clone(&state.metrics);
    let metrics_middleware = axum::middleware::from_fn(
        move |req: axum::extract::Request, next: axum::middleware::Next| {
            let metrics = Arc::clone(&metrics);
            async move {
                let start = std::time::Instant::now();
                let method = req.method().as_str().to_string();
                let route = req
                    .extensions()
                    .get::<axum::extract::MatchedPath>()
                    .map(|p| p.as_str().to_string())
                    .unwrap_or_else(|| req.uri().path().to_string());
                let resp = next.run(req).await;
                metrics
                    .http_requests
                    .with_label_values(&[&method, &route])
                    .inc();
                metrics
                    .http_request_seconds
                    .with_label_values(&[&method, &route])
                    .observe(start.elapsed().as_secs_f64());
                resp
            }
        },
    );
    // M8 — optional auth + best-effort per-client rate limiting. Both are
    // opt-in (default off) so existing LAN/local deployments and the test suite
    // are unaffected; production operators set `PSOB_AUTH_TOKEN` and/or
    // `PSOB_RATE_LIMIT_PER_MIN`.
    let sec = SecurityState {
        config: state.config.clone(),
        buckets: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::<
            std::net::IpAddr,
            (u32, std::time::Instant),
        >::new())),
    };

    let api: Router<()> = Router::new()
        .route("/health", get(health_handler))
        .route("/api/v1/health", get(health_handler))
        .route("/metrics", get(crate::metrics::metrics_handler))
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
        .route("/api/v1/swap/intents", get(list_swap_intents))
        .route("/api/v1/swap/intents", post(create_swap_intent))
        .route("/api/v1/cosettle", get(cosettle_handler))
        .with_state(state)
        .layer(axum::middleware::from_fn_with_state(
            sec,
            security_middleware,
        ));
    let docs: Router<()> = utoipa_swagger_ui::SwaggerUi::new("/docs")
        .url("/api/v1/openapi.json", openapi_doc())
        .into();
    Router::new()
        .merge(docs)
        .merge(api)
        .layer(DefaultBodyLimit::max(8 * 1024 * 1024))
        .layer(cors)
        .layer(CatchPanicLayer::new())
        .layer(metrics_middleware)
        .layer(TraceLayer::new_for_http())
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
    let (parents, total) = state
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
        (Some(f), Some(t)) => {
            if f > t {
                return Err(ApiError::BadRequest("from must be <= to".into()));
            }
            if t.saturating_sub(f) > 10_000 {
                return Err(ApiError::BadRequest("requested block range exceeds maximum of 10000".into()));
            }
            (f, t)
        }
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
    if ltc_end.saturating_sub(ltc_start) > 10_000 {
        return Err(ApiError::BadRequest("requested epoch range exceeds maximum of 10000".into()));
    }
    let page = Page::new(q.limit, q.offset);
    let (blocks, total) = state
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
        total_blocks: total,
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
    // M8 — bound the input size before any parsing / allocation.
    if req.wire_hex.len() > MAX_WIRE_HEX_LEN {
        return Err(ApiError::BadRequest(format!(
            "wire_hex too large: {} bytes (max {})",
            req.wire_hex.len(),
            MAX_WIRE_HEX_LEN
        )));
    }
    let wire = hex::decode(&req.wire_hex)
        .map_err(|e| ApiError::BadRequest(format!("wire_hex is not valid hex: {e}")))?;

    // H2 — never trust a caller-supplied pow limit. Use the indexer's configured
    // consensus floor for the chain; reject if the chain is not configured here
    // (the indexer is per-operator and only vouches for chains it knows).
    let pow_limit = pow_limit_for(&state.config, req.chain_id).ok_or_else(|| {
        ApiError::BadRequest(
            "chain not configured on this indexer; cannot vouch for its pow limit".into(),
        )
    })?;

    let (aux_block, report) = crate::verify::verify_wire_block(&wire, req.chain_id, pow_limit)
        .map_err(|e| ApiError::BadRequest(format!("cannot parse CAuxPow wire: {e}")))?;

    Ok(Json(VerifyResponse {
        valid: report.valid,
        // H2 — the indexer performs NO scrypt PoW verification; the ZK guest does.
        pow_checked: false,
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
        Some(handle) => match handle.broadcast_intent(intent.clone()).await {
            true => Json(json!({
                "status": "broadcasted",
                "intent_id": intent.intent_id,
                "peer_count": handle.status.read().await.connected_peers_count,
            }))
            .into_response(),
            false => {
                ApiError::Internal("gossip channel closed (swarm down)".into()).into_response()
            }
        },
        None => ApiError::Internal("P2P subsystem is not enabled".into()).into_response(),
    }
}
