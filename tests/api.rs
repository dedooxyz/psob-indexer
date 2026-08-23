//! HTTP API integration tests — spin up the real router with a temp DB and hit
//! the flows an explorer or the TS SDK would use.

mod support;

use std::sync::Arc;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use axum::Router;
use http_body_util::BodyExt;
use psob_indexer::config::{AuxChain, Config, ResolverConfig};
use psob_indexer::p2p::P2pConfig;
use psob_indexer::server::{create_router, AppState};
use serde_json::Value;
use support::{fixture_jkc, sibling_pair, tmp_db_path, DINGO, JKC};
use tower::ServiceExt as _;

fn config() -> Config {
    Config {
        chains: vec![
            AuxChain {
                chain_id: JKC,
                name: "JKC".into(),
                electrs: "https://junk-api.s3na.xyz".into(),
                pow_limit_bits: 0x1e0f_ffff,
                start_height: Some(1_000_000),
            },
            AuxChain {
                chain_id: DINGO,
                name: "DINGO".into(),
                electrs: "https://dingo-api.s3na.xyz".into(),
                pow_limit_bits: 0x1e0f_ffff,
                start_height: Some(1_000_000),
            },
        ],
        db_path: tmp_db_path("app").display().to_string(),
        resolver: ResolverConfig {
            base: "https://litecoinspace.org/api".into(),
            api_key: String::new(),
            chain_slug: "litecoin".into(),
        },
        max_batch: 64,
        start_height: Some(1_000_000),
        poll_interval: std::time::Duration::from_secs(5),
        retry: psob_indexer::config::RetryConfig {
            max_retries: 1,
            base_backoff: std::time::Duration::from_millis(10),
            max_backoff: std::time::Duration::from_millis(50),
            min_request_interval: std::time::Duration::ZERO,
        },
        http: psob_indexer::config::HttpConfig {
            timeout: std::time::Duration::from_secs(5),
            concurrency: 2,
        },
        cors_origins: vec!["*".into()],
        bind_addr: "127.0.0.1:0".into(),
        p2p: P2pConfig::default(),
    }
}

async fn setup() -> (Router, Arc<psob_indexer::db::Database>, Config) {
    let config = config();
    let db = Arc::new(psob_indexer::db::Database::open(&config.db_path).expect("open db"));
    // Build a sibling group: JKC + DINGO under the fixture's LTC parent.
    let (jkc, dingo) = sibling_pair(100, 200);
    let parent_hash = {
        let a = jkc.header.aux.as_ref().unwrap();
        psob_indexer::db::sha256d(&a.parent_header)
    };
    db.insert_block(JKC, 100, &jkc).expect("insert jkc");
    db.insert_block(DINGO, 200, &dingo).expect("insert dingo");
    // Mainnet classification for the sibling group.
    db.classify_parent(&parent_hash, Some(347_000))
        .expect("classify");
    // A second JKC block in a different (unclassified) parent for range tests.
    let jkc2 = fixture_jkc();
    db.insert_block(JKC, 101, &jkc2).expect("insert jkc2");
    db.set_cursor_height(JKC, 101).expect("cursor");

    let state = AppState::new(db.clone(), config.clone(), None);
    (create_router(state), db, config)
}

async fn get(router: &Router, uri: &str) -> (StatusCode, Value) {
    let req = Request::builder().uri(uri).body(Body::empty()).unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let json = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    };
    (status, json)
}

async fn post(router: &Router, uri: &str, body: Value) -> (StatusCode, Value) {
    let req = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = router.clone().oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    let json = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
    (status, json)
}

#[tokio::test]
async fn health_and_chain_status() {
    let (router, _, config) = setup().await;
    let (status, body) = get(&router, "/api/v1/health").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "ok");
    assert_eq!(body["configured_chains"], 2);
    assert_eq!(body["schema_version"], 2);
    let _ = config;

    let (status, body) = get(&router, "/api/v1/chains").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["count"], 2);
    let jkc = body["chains"][0].clone();
    assert_eq!(jkc["chain_id"], JKC);
    assert_eq!(jkc["cursor_height"], 101);
}

#[tokio::test]
async fn siblings_list_and_detail_are_paged() {
    let (router, db, _) = setup().await;
    let (status, body) = get(&router, "/api/v1/siblings?min_legs=2&limit=1").await;
    assert_eq!(status, StatusCode::OK);
    let summary = body["items"][0].clone();
    assert_eq!(summary["legs_count"], 2);
    assert_eq!(summary["parent_hash"].as_str().unwrap().len(), 64);
    assert_eq!(summary["ltc_height"], 347_000);
    // Only one page requested; total counts all groups (this fixture has 1).
    assert_eq!(body["total"], 1);
    assert_eq!(body["limit"], 1);

    // Detail by parent hash — includes both leg blocks.
    let ph = summary["parent_hash"].as_str().unwrap();
    // Sanity: resolve a tiny bit of the DB path manually.
    {
        let mut le = hex::decode(ph).unwrap();
        le.reverse();
        let le_arr: [u8; 32] = le.try_into().unwrap();
        let found = db.get_parent(&le_arr).unwrap();
        eprintln!(
            "DB get_parent: {:?}",
            found.map(|p| (p.ltc_height, p.parent_state))
        );
        let sans = db.siblings_for_parent(&le_arr).unwrap();
        eprintln!("DB siblings: {}", sans.len());
    }
    let (status, detail) = get(&router, &format!("/api/v1/siblings/{ph}")).await;
    eprintln!("DETAIL status={status:?} body={detail}");
    assert_eq!(status, StatusCode::OK);
    assert_eq!(detail["sibling_count"], 2);
    assert_eq!(detail["siblings"].as_array().unwrap().len(), 2);

    // With auxpow payloads included, each sibling is self-verifiable.
    let (_, detail_full) = get(
        &router,
        &format!("/api/v1/siblings/{ph}?include_auxpow=true"),
    )
    .await;
    let sibling = detail_full["siblings"][0].clone();
    let auxhex = sibling["auxpow_hex"].as_str().unwrap();
    assert!(auxhex.len() >= 160, "wire payload present");

    // Unknown parent → clean 404 with the error envelope.
    let (status, err) = get(&router, &format!("/api/v1/siblings/{}", "11".repeat(32))).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(err["error"]["code"].as_str().is_some());
    let _ = db;
}

#[tokio::test]
async fn block_proof_verify_roundtrip() {
    let (router, _, _) = setup().await;
    let (status, block) = get(&router, "/api/v1/block/8224/100").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(block["chain_id"], JKC);
    assert_eq!(block["height"], 100);
    assert!(block["raw_auxpow_hex"].as_str().unwrap().len() >= 160);
    // The stored block re-verifies on read.
    eprintln!("VERIF: {}", block["verification"]);
    assert_eq!(block["verification"]["valid"], true);

    let (status, proof) = get(&router, "/api/v1/proof/8224/100").await;
    assert_eq!(status, StatusCode::OK);
    assert!(proof["chain_merkle_branch"].is_array());
    assert!(proof["coinbase_tx"].as_str().unwrap().len() > 20);
    assert!(proof["parent_header"].as_str().unwrap().len() == 160);

    // Client-side re-verification through /verify with the served wire bytes.
    let wire = proof["auxpow_hex"].as_str().unwrap();
    let (status, vr) = post(
        &router,
        "/api/v1/verify",
        serde_json::json!({ "chain_id": JKC, "wire_hex": wire }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(vr["valid"], true);
    assert_eq!(vr["block_hash"], block["block_hash"]);
    assert_eq!(
        vr["verification"]["proof1_coinbase_to_parent_root"]["ok"],
        true
    );
    assert_eq!(vr["verification"]["anti_grind_lcg_slot"]["ok"], true);

    // A tampered wire fails with detail: flip a byte of the committed root
    // (found right after the merged-mining magic in the raw coinbase).
    let mut bytes = hex::decode(wire).unwrap();
    let magic = [0xfa, 0xbe, 0x6d, 0x6d];
    let mp = bytes
        .windows(4)
        .position(|w| w == magic)
        .expect("magic present");
    bytes[mp + 8] ^= 1;
    let (status, bad) = post(
        &router,
        "/api/v1/verify",
        serde_json::json!({ "chain_id": JKC, "wire_hex": hex::encode(bytes) }),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(bad["valid"], false);
}

#[tokio::test]
async fn blocks_range_and_epoch() {
    let (router, _, _) = setup().await;
    let (status, body) = get(&router, "/api/v1/blocks?chain_id=8224&from=95&to=110").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["blocks"].as_array().unwrap().len(), 2);

    let (status, _err) = get(&router, "/api/v1/blocks").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let (status, epoch) = get(&router, "/api/v1/epoch/347000/348000").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(epoch["total_blocks"], 2);
    let (status, filtered) = get(&router, "/api/v1/epoch/347000/348000?chain_id=50").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(filtered["total_blocks"], 1);
    assert_eq!(filtered["blocks"][0]["chain_id"], DINGO);
}

#[tokio::test]
async fn openapi_document_is_served() {
    let (router, _, _) = setup().await;
    let (status, doc) = get(&router, "/api/v1/openapi.json").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(doc["openapi"], "3.0.3");
    assert!(doc["paths"] != Value::Null);
    assert!(
        doc["paths"]["/api/v1/siblings"].is_object(),
        "siblings path documented"
    );
}
