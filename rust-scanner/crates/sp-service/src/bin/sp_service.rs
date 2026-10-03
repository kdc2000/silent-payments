use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use clap::Parser;
use tokio::sync::broadcast;
use tracing_subscriber::EnvFilter;

use sp_service::block_reader::ChiaBlockReader;
use sp_service::config::{CliArgs, ServiceConfig};
use sp_service::generator::extract_coin_spends;
use sp_service::grouping::group_spends;
use sp_service::live_sync::{LiveSync, RpcConfig};
use sp_service::pruning::{prune_below_height, prune_spent_blocks};
use sp_service::tweak_index::{build_gcs_filter, TweakIndex};
use sp_service::ws::messages::ServerMessage;
use sp_service::ws::{create_router, AppState};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::from_default_env()
                .add_directive("sp_service=info".parse().unwrap()),
        )
        .init();

    // Parse CLI args and convert to config
    let args = CliArgs::parse();
    let config: ServiceConfig = args.into();

    tracing::info!(
        "Starting sp-service on port {} for {}",
        config.ws_port,
        config.network
    );

    // Open tweak index database
    let tweak_index = TweakIndex::open(&config.index_db_path)?;
    let mut last_height = tweak_index.get_last_indexed_height()?;
    if last_height == 0 {
        if let Some(start) = config.start_height {
            tweak_index.set_last_indexed_height(start)?;
            last_height = start;
            tracing::info!("Starting index from block {} (--start-height)", start);
        }
    }
    tracing::info!("Tweak index at height {}", last_height);

    // Open Chia DB for coin_record queries (UTXO-aware mode)
    let chia_db = match ChiaBlockReader::open(&config.chia_db_path) {
        Ok(reader) => {
            tracing::info!("Chia DB opened for coin status queries");
            Some(std::sync::Mutex::new(reader))
        }
        Err(e) => {
            tracing::warn!(
                "Could not open Chia DB for coin status: {}. UTXO-aware mode unavailable.",
                e
            );
            None
        }
    };

    // Create broadcast channel for live block push
    let (block_tx, _) = broadcast::channel::<ServerMessage>(64);

    // Build shared application state
    let state = Arc::new(AppState {
        tweak_index: std::sync::Mutex::new(tweak_index),
        block_tx: block_tx.clone(),
        tip_height: AtomicU32::new(last_height),
        config: config.clone(),
        chia_db,
    });

    // Build axum router
    let app = create_router(state.clone());

    // Bind TCP listener
    let addr = format!("0.0.0.0:{}", config.ws_port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    tracing::info!("WebSocket server listening on ws://{}", addr);

    // Spawn indexer task (tracks tip height via RPC polling)
    let state_indexer = state.clone();
    tokio::spawn(async move {
        if let Err(e) = run_indexer(state_indexer, block_tx).await {
            tracing::error!("Indexer task failed: {}", e);
        }
    });

    // Serve WebSocket connections
    axum::serve(listener, app).await?;

    Ok(())
}

/// Background task that polls the full node RPC for new blocks and processes them through
/// the full pipeline: read -> extract coin spends -> group -> store tweak data -> build GCS
/// filter -> broadcast to subscribers.
///
/// If RPC certs are not available, logs a warning and returns (service runs without live sync).
async fn run_indexer(
    state: Arc<AppState>,
    block_tx: broadcast::Sender<ServerMessage>,
) -> Result<(), Box<dyn std::error::Error>> {
    let last_height = state.tip_height.load(Ordering::Relaxed);

    let rpc_config = RpcConfig {
        url: state.config.rpc_url.clone(),
        cert_path: state.config.rpc_cert_path.clone(),
        key_path: state.config.rpc_key_path.clone(),
        poll_interval: std::time::Duration::from_secs(state.config.poll_interval_secs),
    };

    // Attempt to create LiveSync -- if certs not found, service runs without live sync
    let mut live_sync = match LiveSync::new(rpc_config, last_height) {
        Ok(ls) => ls,
        Err(e) => {
            tracing::warn!(
                "Could not initialize live sync (missing certs?): {}. Service will run without live block tracking.",
                e
            );
            return Ok(());
        }
    };

    // Open a separate read-only ChiaBlockReader for the indexer task
    // (the one in AppState.chia_db is used for coin_record queries)
    let chia_reader = match ChiaBlockReader::open(&state.config.chia_db_path) {
        Ok(reader) => Some(reader),
        Err(e) => {
            tracing::warn!(
                "Could not open Chia DB for indexing: {}. Service will track tip height only.",
                e
            );
            None
        }
    };

    // If Chia DB is not available, fall back to tip-height-only behavior
    let chia_reader = match chia_reader {
        Some(r) => r,
        None => {
            tracing::info!("Live sync started, polling for new blocks (tip-height only)");
            loop {
                tokio::time::sleep(live_sync.poll_interval()).await;
                if let Some(peak) = live_sync.check_for_new_blocks().await {
                    state.tip_height.store(peak, Ordering::Relaxed);
                    tracing::info!("New peak height: {}", peak);
                }
            }
        }
    };

    tracing::info!("Live sync started, polling for new blocks with full pipeline");

    // Pruning timer: runs periodically to remove stale tweak data
    let prune_interval = std::time::Duration::from_secs(state.config.prune_interval_secs);
    let mut last_prune = std::time::Instant::now();
    let pruning_enabled = state.config.prune_interval_secs > 0 && state.chia_db.is_some();
    if pruning_enabled {
        tracing::info!("Pruning enabled, interval: {}s", state.config.prune_interval_secs);
    }

    loop {
        tokio::time::sleep(live_sync.poll_interval()).await;

        if let Some(peak) = live_sync.check_for_new_blocks().await {
            let last_indexed = state
                .tweak_index
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get_last_indexed_height()
                .unwrap_or(0);

            'block_loop: for height in (last_indexed + 1)..=peak {
                // Read block from Chia DB
                let (header_hash, block) = match chia_reader.read_block(height) {
                    Ok(Some((hh, blk))) => (hh, blk),
                    Ok(None) => {
                        // Block not yet available in DB, stop here and retry on next poll
                        break 'block_loop;
                    }
                    Err(e) => {
                        tracing::error!("Failed to process block {}: {}", height, e);
                        break 'block_loop;
                    }
                };

                // Extract coin spends via CLVM generator
                let coin_spends = match extract_coin_spends(&chia_reader, &block) {
                    Ok(spends) => spends,
                    Err(e) => {
                        tracing::error!("Failed to process block {}: {}", height, e);
                        break 'block_loop;
                    }
                };

                // Group spends and compute tweak points
                let grouped_block = group_spends(height, header_hash, &coin_spends);

                // Store grouped block data in tweak index
                if let Err(e) = state
                    .tweak_index
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .store_block(&grouped_block)
                {
                    tracing::error!("Failed to process block {}: {}", height, e);
                    break 'block_loop;
                }

                // Build and store GCS filter from output puzzle hashes
                let puzzle_hashes: Vec<[u8; 32]> = grouped_block
                    .outputs
                    .iter()
                    .map(|output| <[u8; 32]>::try_from(output.puzzle_hash.as_ref()).unwrap())
                    .collect();

                if !puzzle_hashes.is_empty() {
                    let hh_bytes =
                        <[u8; 32]>::try_from(header_hash.as_ref()).unwrap();
                    let filter_data = build_gcs_filter(&hh_bytes, &puzzle_hashes);
                    if let Err(e) = state
                        .tweak_index
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .store_block_filter(height, &hh_bytes, &filter_data)
                    {
                        tracing::error!("Failed to process block {}: {}", height, e);
                        break 'block_loop;
                    }
                }

                // Broadcast block data to subscribed WebSocket clients
                let tweaks_data = state
                    .tweak_index
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .get_block_tweaks(height);

                if let Ok(Some((tweaks, outputs))) = tweaks_data {
                    let msg = ServerMessage::from_block_tweaks(height, &tweaks, &outputs);
                    let _ = block_tx.send(msg);
                }

                // Update tip height after each block
                state.tip_height.store(height, Ordering::Relaxed);

                tracing::info!(
                    "Indexed block {} ({} groups, {} outputs)",
                    height,
                    grouped_block.groups.len(),
                    grouped_block.outputs.len()
                );
            }

            // Ensure tip tracks peak even if we skipped some blocks
            live_sync.set_last_known_height(peak);
        }

        // Periodic pruning of fully-spent blocks
        if pruning_enabled && last_prune.elapsed() >= prune_interval {
            let start = std::time::Instant::now();
            let mut pruned = 0u32;

            if let Some(ref chia_db_mutex) = state.chia_db {
                let chia_reader = chia_db_mutex.lock().unwrap_or_else(|e| e.into_inner());
                let mut index = state.tweak_index.lock().unwrap_or_else(|e| e.into_inner());

                // Prune blocks below start_height if configured
                if let Some(start_height) = state.config.start_height {
                    match prune_below_height(&mut index, start_height) {
                        Ok(n) => pruned += n,
                        Err(e) => tracing::warn!("Prune below height failed: {}", e),
                    }
                }

                // Prune blocks whose outputs are all spent
                match prune_spent_blocks(&mut index, &chia_reader) {
                    Ok(n) => pruned += n,
                    Err(e) => tracing::warn!("Prune spent blocks failed: {}", e),
                }
            }

            let elapsed = start.elapsed();
            if pruned > 0 {
                tracing::info!("Pruned {} blocks in {:.1}s", pruned, elapsed.as_secs_f64());
            } else {
                tracing::debug!("Prune check complete, nothing to prune ({:.1}s)", elapsed.as_secs_f64());
            }

            last_prune = std::time::Instant::now();
        }
    }
}
