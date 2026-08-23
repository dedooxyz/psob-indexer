//! `psob-indexer` binary — PSob light client, HTTP REST API, and gossip mesh.
//!
//! Reads configuration from `.env` / `psob-indexer.toml` / environment (in that
//! precedence order — see [`config::Config::load`]), opens the Redb cache, then
//! runs:
//! 1. The ingestor: one per-chain task, each with its own retry/backoff — a
//!    single failing chain never takes the whole node down.
//! 2. The Axum REST API (self-verifiable responses, OpenAPI at `/docs`).
//! 3. The optional libp2p gossip mesh (swap intents, header/sibling gossip).
//!
//! Shut down cleanly on SIGINT/SIGTERM: listeners close, ingest tasks abort.

use std::sync::Arc;

use psob_indexer::config::Config;
use psob_indexer::db::Database;
use psob_indexer::p2p::swarm::start_p2p_swarm;
use psob_indexer::server::{create_router, AppState};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                tracing_subscriber::EnvFilter::new("psob_indexer=info,chain_rpc=info")
            }),
        )
        .init();

    let config = Config::load()?;
    tracing::info!(
        chains = config.chains.len(),
        db = %config.db_path,
        http_concurrency = config.http.concurrency,
        "loaded psob-indexer config"
    );

    let db = Arc::new(Database::open(&config.db_path)?);

    // P2P is optional: if the swarm fails to start, the node still serves REST.
    let (p2p_handle, p2p_task) = match start_p2p_swarm(config.p2p.clone()).await {
        Ok((h, task)) => {
            tracing::info!("p2p gossip mesh enabled");
            (Some(h), Some(tokio::spawn(task)))
        }
        Err(e) => {
            tracing::warn!("failed to start p2p swarm, running in standalone mode: {e}");
            (None, None)
        }
    };

    let state = AppState::new(Arc::clone(&db), config.clone(), p2p_handle);
    let router = create_router(state);
    let listener = tokio::net::TcpListener::bind(&config.bind_addr).await?;
    tracing::info!(addr = %config.bind_addr, "started psob-indexer HTTP REST API (docs at /docs)");

    // Ingestor: one long-lived task per chain; they only exit on abort.
    let db_for_ingest = Arc::clone(&db);
    let config_for_ingest = config.clone();
    let ingest_task = tokio::spawn(async move {
        let ingestor = match psob_indexer::ingest::Ingestor::new(config_for_ingest, db_for_ingest) {
            Ok(i) => i,
            Err(e) => {
                tracing::error!("failed to construct ingestor: {e}");
                return;
            }
        };
        let handles = ingestor.spawn_all();
        for h in handles {
            let _ = h.await;
        }
    });

    // Serve until SIGINT/SIGTERM; then cleanly abort the background loops.
    tokio::select! {
        res = axum::serve(listener, router) => {
            tracing::error!("HTTP server exited: {res:?}");
            res?;
        }
        res = async {
            match p2p_task {
                Some(t) => { let _ = t.await; }
                None => std::future::pending::<()>().await,
            }
        } => {
            tracing::error!("P2P swarm task exited: {res:?}");
        }
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("SIGINT received, shutting down");
        }
    }
    ingest_task.abort();
    let _ = ingest_task.await;
    tracing::info!("psob-indexer stopped cleanly");
    Ok(())
}
