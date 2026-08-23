//! Prometheus metrics — `/metrics` endpoint, HTTP middleware, and ingest hooks.
//!
//! `Metrics` is a plain `Arc<Registry>` wrapper with pre-registered collectors.
//! DB-derived gauges (blocks per chain, sibling groups, cursors) are refreshed
//! at scrape time by the `/metrics` handler — cheap because the L1 cache
//! answers in microseconds.
//!
//! Metric naming: `psob_indexer_*`.

use std::sync::Arc;

use axum::{extract::State, response::IntoResponse};
use prometheus::{HistogramVec, IntCounterVec, IntGauge, IntGaugeVec, Registry};

use crate::db::Database;

/// HTTP request histogram buckets (seconds): generous DC-era spread.
fn request_buckets() -> Vec<f64> {
    vec![
        0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
    ]
}

pub struct Metrics {
    pub registry: Registry,
    pub http_requests: IntCounterVec,
    pub http_request_seconds: HistogramVec,
    pub ingest_blocks: IntCounterVec,
    pub ingest_ticks: IntCounterVec,
    pub ingest_errors: IntCounterVec,
    pub family_resolves: IntCounterVec,
    pub prune_blocks: IntCounterVec,
    // Scrape-time refreshed gauges:
    pub indexed_blocks: IntGaugeVec,
    pub chain_cursor: IntGaugeVec,
    pub sibling_groups: IntGauge,
    pub indexed_parents: IntGauge,
    pub uptime_seconds: IntGauge,
    started_at: std::time::Instant,
}

impl Metrics {
    pub fn new() -> Arc<Self> {
        let registry = Registry::new_custom(Some("psob_indexer".into()), None).unwrap();

        let http_requests = IntCounterVec::new(
            prometheus::opts!("http_requests_total", "HTTP requests by route"),
            &["method", "route"],
        )
        .unwrap();
        let http_request_seconds = HistogramVec::new(
            prometheus::histogram_opts!(
                "http_request_seconds",
                "HTTP request latency by route",
                request_buckets()
            ),
            &["method", "route"],
        )
        .unwrap();
        let ingest_blocks = IntCounterVec::new(
            prometheus::opts!("ingest_blocks_total", "Blocks ingested per chain"),
            &["chain_id"],
        )
        .unwrap();
        let ingest_ticks = IntCounterVec::new(
            prometheus::opts!("ingest_ticks_total", "Ingest ticks per chain"),
            &["chain_id"],
        )
        .unwrap();
        let ingest_errors = IntCounterVec::new(
            prometheus::opts!("ingest_errors_total", "Failed ingest ticks per chain"),
            &["chain_id"],
        )
        .unwrap();
        let family_resolves = IntCounterVec::new(
            prometheus::opts!("parent_resolves_total", "Parent classifications by state"),
            &["state"],
        )
        .unwrap();
        let prune_blocks = IntCounterVec::new(
            prometheus::opts!("prune_blocks_total", "Blocks pruned per chain"),
            &["chain_id"],
        )
        .unwrap();
        let indexed_blocks = IntGaugeVec::new(
            prometheus::opts!("indexed_blocks", "Indexed blocks per chain"),
            &["chain_id"],
        )
        .unwrap();
        let chain_cursor = IntGaugeVec::new(
            prometheus::opts!("chain_cursor", "Stored cursor per chain"),
            &["chain_id"],
        )
        .unwrap();
        let sibling_groups = IntGauge::new(
            "sibling_groups".to_string(),
            "Mainnet sibling groups (>= 2 legs)".to_string(),
        )
        .unwrap();
        let indexed_parents = IntGauge::new(
            "indexed_parents".to_string(),
            "Distinct embedded parent headers".to_string(),
        )
        .unwrap();
        let uptime_seconds = IntGauge::new(
            "uptime_seconds".to_string(),
            "Node uptime in seconds".to_string(),
        )
        .unwrap();

        for c in [
            &http_requests,
            &ingest_blocks,
            &ingest_ticks,
            &ingest_errors,
            &family_resolves,
            &prune_blocks,
        ] {
            registry.register(Box::new(c.clone())).unwrap();
        }
        for c in [&indexed_blocks, &chain_cursor] {
            registry.register(Box::new(c.clone())).unwrap();
        }
        registry
            .register(Box::new(http_request_seconds.clone()))
            .unwrap();
        registry.register(Box::new(sibling_groups.clone())).unwrap();
        registry
            .register(Box::new(indexed_parents.clone()))
            .unwrap();
        registry.register(Box::new(uptime_seconds.clone())).unwrap();

        Arc::new(Self {
            started_at: std::time::Instant::now(),
            registry,
            http_requests,
            http_request_seconds,
            ingest_blocks,
            ingest_ticks,
            ingest_errors,
            family_resolves,
            prune_blocks,
            indexed_blocks,
            chain_cursor,
            sibling_groups,
            indexed_parents,
            uptime_seconds,
        })
    }

    /// Refresh DB-derived gauges and render the registry.
    pub fn render(&self, db: &Database) -> String {
        self.uptime_seconds
            .set(self.started_at.elapsed().as_secs() as i64);
        if let Ok(stats) = db.stats() {
            for c in &stats.chains {
                let label = c.chain_id.to_string();
                self.indexed_blocks
                    .with_label_values(&[&label])
                    .set(c.blocks as i64);
                if let Some(h) = c.max_height {
                    self.chain_cursor.with_label_values(&[&label]).set(h as i64);
                }
            }
            self.sibling_groups.set(stats.sibling_groups as i64);
            self.indexed_parents.set(stats.total_parents as i64);
        }
        // Need an owned dump: prometheus's TextEncoder requires a header line
        // we construct manually from the registry.
        self.render_text()
    }

    fn render_text(&self) -> String {
        use prometheus::Encoder;
        let encoder = prometheus::TextEncoder::new();
        let mut buffer = Vec::new();
        // Ignore encode errors (out of memory edge) — the operator sees an
        // empty body rather than a failed scrape.
        let _ = encoder.encode(&self.registry.gather(), &mut buffer);
        String::from_utf8_lossy(&buffer).into_owned()
    }
}

/// `GET /metrics` — refresh DB-derived gauges, render text exposition.
pub async fn metrics_handler(State(state): State<crate::server::AppState>) -> impl IntoResponse {
    let text = state.metrics.render(&state.db);
    (
        [(
            axum::http::header::CONTENT_TYPE,
            "text/plain; version=0.0.4",
        )],
        text,
    )
        .into_response()
}
