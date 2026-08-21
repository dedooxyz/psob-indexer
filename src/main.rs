//! `psob-indexer` binary — PSob light client & HTTP REST API.
//!
//! Reads ALL configuration from the environment (see `.env.example`), opens
//! the SQLite cache, and runs:
//! 1. Background ingest loop across all configured AuxPoW chains.
//! 2. High-performance Axum REST API server for frontends, indexers, and BCN.

use std::sync::Arc;
use psob_indexer::config::Config;
use psob_indexer::db::Database;
use psob_indexer::p2p::{swarm::start_p2p_swarm, P2pConfig};
use psob_indexer::server::{create_router, AppState};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("psob_indexer=info")),
        )
        .init();

    let config = Config::from_env()?;
    tracing::info!(chains = config.chains.len(), "loaded psob-indexer config");

    let db = Arc::new(Database::open(&config.db_path)?);

    // Initialize P2P Swarm
    let p2p_config = P2pConfig::default();
    let (p2p_handle, p2p_task) = match start_p2p_swarm(p2p_config).await {
        Ok((h, task)) => (Some(h), Some(task)),
        Err(e) => {
            tracing::warn!("failed to start p2p swarm, running in standalone mode: {e}");
            (None, None)
        }
    };

    let bind_addr = std::env::var("PSOB_BIND_ADDR")
        .unwrap_or_else(|_| {
            let port = std::env::var("PSOB_PORT").unwrap_or_else(|_| "8080".to_string());
            format!("0.0.0.0:{port}")
        });

    let state = AppState {
        db: Arc::clone(&db),
        config: config.clone(),
        p2p: p2p_handle,
    };

    let router = create_router(state);
    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
    tracing::info!(addr = %bind_addr, "started psob-indexer HTTP REST API");

    // Run ingest loop, HTTP server, and P2P swarm
    tokio::select! {
        res = psob_indexer::ingest::run_with_db(config, Arc::clone(&db)) => {
            tracing::error!("ingest loop exited: {res:?}");
            res
        }
        res = axum::serve(listener, router) => {
            tracing::error!("HTTP server exited: {res:?}");
            Ok(())
        }
        _ = async {
            if let Some(task) = p2p_task {
                task.await;
            } else {
                std::future::pending::<()>().await;
            }
        } => {
            tracing::error!("P2P swarm task exited");
            Ok(())
        }
    }
}