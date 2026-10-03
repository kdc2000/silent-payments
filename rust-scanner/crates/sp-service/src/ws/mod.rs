pub mod messages;

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::State;
use axum::response::IntoResponse;
use futures_util::stream::SplitSink;
use futures_util::{SinkExt, StreamExt};
use tokio::sync::broadcast;

use crate::block_reader::ChiaBlockReader;
use crate::config::ServiceConfig;
use crate::tweak_index::TweakIndex;
use messages::{ClientMessage, CoinStatusEntry, ServerMessage};

/// Shared application state accessible by all WebSocket handlers.
pub struct AppState {
    /// The tweak index database (std::sync::Mutex -- SQLite reads are microseconds).
    pub tweak_index: std::sync::Mutex<TweakIndex>,
    /// Broadcast channel sender for pushing new block data to subscribed clients.
    pub block_tx: broadcast::Sender<ServerMessage>,
    /// Current chain tip height (updated by indexer task, read by ChainInfo handler).
    pub tip_height: AtomicU32,
    /// Service configuration.
    pub config: ServiceConfig,
    /// Optional Chia full node DB reader for coin_record queries (UTXO-aware mode).
    /// None if the Chia DB is unavailable (tests, offline mode).
    pub chia_db: Option<std::sync::Mutex<ChiaBlockReader>>,
}

/// Create the axum router with the WebSocket endpoint.
pub fn create_router(state: Arc<AppState>) -> axum::Router {
    axum::Router::new()
        .route("/ws", axum::routing::any(ws_handler))
        .with_state(state)
}

/// Serve the WebSocket API on an already bound listener until it fails.
///
/// Lets other crates (and tests) run the real service endpoint without
/// depending on the HTTP framework themselves.
pub async fn serve(listener: tokio::net::TcpListener, state: Arc<AppState>) -> std::io::Result<()> {
    axum::serve(listener, create_router(state)).await
}

/// WebSocket upgrade handler -- accepts the connection and spawns the socket handler.
async fn ws_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AppState>>,
) -> impl IntoResponse {
    ws.on_upgrade(move |socket| handle_socket(socket, state))
}

/// Handle an individual WebSocket connection.
///
/// Splits the socket into sender/receiver halves, processes client messages,
/// and optionally forwards broadcast channel messages when subscribed.
async fn handle_socket(socket: WebSocket, state: Arc<AppState>) {
    let (sender, mut receiver) = socket.split();
    let mut sender = sender;
    let mut block_rx = state.block_tx.subscribe();
    let mut subscribed = false;

    tracing::info!("WebSocket client connected");

    loop {
        tokio::select! {
            msg = receiver.next() => {
                match msg {
                    Some(Ok(Message::Text(text))) => {
                        let (responses, is_subscribe) =
                            handle_client_message(&state, &text);
                        if is_subscribe {
                            subscribed = true;
                        }
                        if send_messages(&mut sender, &responses).await.is_err() {
                            break;
                        }
                    }
                    Some(Ok(Message::Close(_))) | None => break,
                    Some(Err(_)) => break,
                    _ => {} // axum handles ping/pong
                }
            }
            result = block_rx.recv(), if subscribed => {
                match result {
                    Ok(block_msg) => {
                        let json = match serde_json::to_string(&block_msg) {
                            Ok(j) => j,
                            Err(e) => {
                                tracing::warn!("failed to serialize block message: {}", e);
                                continue;
                            }
                        };
                        if sender.send(Message::Text(json.into())).await.is_err() {
                            break; // client disconnected
                        }
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        tracing::warn!("client lagged behind by {} blocks", n);
                        let err_msg = ServerMessage::Error {
                            message: format!("missed {} blocks, request range to catch up", n),
                        };
                        if let Ok(json) = serde_json::to_string(&err_msg) {
                            if sender.send(Message::Text(json.into())).await.is_err() {
                                break;
                            }
                        }
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                }
            }
        }
    }

    tracing::info!("WebSocket client disconnected");
}

/// Send multiple ServerMessage responses over the WebSocket.
///
/// Returns Err if the client has disconnected.
async fn send_messages(
    sender: &mut SplitSink<WebSocket, Message>,
    messages: &[ServerMessage],
) -> Result<(), ()> {
    for msg in messages {
        let json = serde_json::to_string(msg).map_err(|_| ())?;
        sender.send(Message::Text(json.into())).await.map_err(|_| ())?;
    }
    Ok(())
}

/// Process a client message and return the response(s) plus a subscribe flag.
///
/// Returns `(Vec<ServerMessage>, bool)` where the bool indicates if the client
/// just subscribed to live block updates.
fn handle_client_message(state: &AppState, text: &str) -> (Vec<ServerMessage>, bool) {
    let client_msg = match serde_json::from_str::<ClientMessage>(text) {
        Ok(msg) => msg,
        Err(e) => {
            return (
                vec![ServerMessage::Error {
                    message: format!("invalid message: {}", e),
                }],
                false,
            );
        }
    };

    match client_msg {
        ClientMessage::GetBlock { height } => {
            let index = state.tweak_index.lock().unwrap_or_else(|e| e.into_inner());
            match index.get_block_tweaks(height) {
                Ok(Some((tweaks, outputs))) => (
                    vec![ServerMessage::from_block_tweaks(height, &tweaks, &outputs)],
                    false,
                ),
                Ok(None) => (
                    vec![ServerMessage::Error {
                        message: format!("block {} not indexed", height),
                    }],
                    false,
                ),
                Err(e) => (
                    vec![ServerMessage::Error {
                        message: format!("db error: {}", e),
                    }],
                    false,
                ),
            }
        }

        ClientMessage::GetBlockRange { start, end } => {
            if start > end {
                return (
                    vec![ServerMessage::Error {
                        message: "start must be <= end".to_string(),
                    }],
                    false,
                );
            }
            if end - start > 1000 {
                return (
                    vec![ServerMessage::Error {
                        message: "range too large (max 1000 blocks)".to_string(),
                    }],
                    false,
                );
            }

            let index = state.tweak_index.lock().unwrap_or_else(|e| e.into_inner());
            let mut responses = Vec::new();
            for height in start..=end {
                match index.get_block_tweaks(height) {
                    Ok(Some((tweaks, outputs))) => {
                        responses
                            .push(ServerMessage::from_block_tweaks(height, &tweaks, &outputs));
                    }
                    Ok(None) => {
                        // Skip heights not yet indexed
                    }
                    Err(e) => {
                        responses.push(ServerMessage::Error {
                            message: format!("db error at height {}: {}", height, e),
                        });
                        break;
                    }
                }
            }
            (responses, false)
        }

        ClientMessage::GetChainInfo => {
            let (indexed_height, min_indexed_height) = {
                let index = state.tweak_index.lock().unwrap_or_else(|e| e.into_inner());
                (
                    index.get_last_indexed_height().unwrap_or(0),
                    index.get_min_indexed_height().unwrap_or(None),
                )
            };
            let tip_height = state.tip_height.load(Ordering::Relaxed);
            (
                vec![ServerMessage::ChainInfo {
                    network: state.config.network.to_string(),
                    tip_height,
                    indexed_height,
                    min_indexed_height,
                }],
                false,
            )
        }

        ClientMessage::GetBlockRangeUtxo { start, end } => {
            if start > end {
                return (
                    vec![ServerMessage::Error {
                        message: "start must be <= end".to_string(),
                    }],
                    false,
                );
            }
            if end - start > 1000 {
                return (
                    vec![ServerMessage::Error {
                        message: "range too large (max 1000 blocks)".to_string(),
                    }],
                    false,
                );
            }

            let index = state.tweak_index.lock().unwrap_or_else(|e| e.into_inner());
            let mut responses = Vec::new();

            match &state.chia_db {
                Some(chia_lock) => {
                    let chia_reader = chia_lock.lock().unwrap_or_else(|e| e.into_inner());
                    for height in start..=end {
                        match index.get_block_tweaks_utxo_aware(height, &chia_reader) {
                            Ok(Some((tweaks, outputs))) => {
                                responses.push(ServerMessage::from_block_tweaks(
                                    height, &tweaks, &outputs,
                                ));
                            }
                            Ok(None) => {}
                            Err(e) => {
                                responses.push(ServerMessage::Error {
                                    message: format!("db error at height {}: {}", height, e),
                                });
                                break;
                            }
                        }
                    }
                }
                None => {
                    // Fallback: regular (non-UTXO-aware) block range
                    for height in start..=end {
                        match index.get_block_tweaks(height) {
                            Ok(Some((tweaks, outputs))) => {
                                responses.push(ServerMessage::from_block_tweaks(
                                    height, &tweaks, &outputs,
                                ));
                            }
                            Ok(None) => {}
                            Err(e) => {
                                responses.push(ServerMessage::Error {
                                    message: format!("db error at height {}: {}", height, e),
                                });
                                break;
                            }
                        }
                    }
                }
            }
            (responses, false)
        }

        ClientMessage::GetBlockFilter { height } => {
            let index = state.tweak_index.lock().unwrap_or_else(|e| e.into_inner());
            match index.get_block_filter(height) {
                Ok(Some((hh, fd))) => (
                    vec![ServerMessage::BlockFilter {
                        height,
                        header_hash: hex::encode(&hh),
                        filter: hex::encode(&fd),
                    }],
                    false,
                ),
                Ok(None) => (
                    vec![ServerMessage::Error {
                        message: format!("filter not found for block {}", height),
                    }],
                    false,
                ),
                Err(e) => (
                    vec![ServerMessage::Error {
                        message: format!("db error: {}", e),
                    }],
                    false,
                ),
            }
        }

        ClientMessage::GetBlockFilterRange { start, end } => {
            if start > end {
                return (
                    vec![ServerMessage::Error {
                        message: "start must be <= end".to_string(),
                    }],
                    false,
                );
            }
            if end - start > 1000 {
                return (
                    vec![ServerMessage::Error {
                        message: "range too large (max 1000 blocks)".to_string(),
                    }],
                    false,
                );
            }

            let index = state.tweak_index.lock().unwrap_or_else(|e| e.into_inner());
            let mut responses = Vec::new();
            for height in start..=end {
                match index.get_block_filter(height) {
                    Ok(Some((hh, fd))) => {
                        responses.push(ServerMessage::BlockFilter {
                            height,
                            header_hash: hex::encode(&hh),
                            filter: hex::encode(&fd),
                        });
                    }
                    Ok(None) => {
                        // Skip heights without filters
                    }
                    Err(e) => {
                        responses.push(ServerMessage::Error {
                            message: format!("db error at height {}: {}", height, e),
                        });
                        break;
                    }
                }
            }
            (responses, false)
        }

        ClientMessage::CheckCoinStatus { coin_ids } => {
            match &state.chia_db {
                None => (
                    vec![ServerMessage::Error {
                        message: "coin status not available".to_string(),
                    }],
                    false,
                ),
                Some(chia_lock) => {
                    let chia_reader = chia_lock.lock().unwrap_or_else(|e| e.into_inner());

                    // Parse hex coin_ids to [u8; 32]
                    let mut parsed: Vec<([u8; 32], String)> = Vec::new();
                    for cid_hex in &coin_ids {
                        if let Ok(bytes) = hex::decode(cid_hex) {
                            if bytes.len() == 32 {
                                let mut arr = [0u8; 32];
                                arr.copy_from_slice(&bytes);
                                parsed.push((arr, cid_hex.clone()));
                            }
                        }
                    }

                    let coin_arrays: Vec<[u8; 32]> = parsed.iter().map(|(a, _)| *a).collect();
                    match chia_reader.check_coins_spent(&coin_arrays) {
                        Ok(spent_map) => {
                            let statuses: Vec<CoinStatusEntry> = parsed
                                .iter()
                                .map(|(arr, hex_id)| {
                                    match spent_map.get(arr) {
                                        Some(Some(h)) => CoinStatusEntry {
                                            coin_id: hex_id.clone(),
                                            spent: true,
                                            spent_height: Some(*h),
                                        },
                                        _ => CoinStatusEntry {
                                            coin_id: hex_id.clone(),
                                            spent: false,
                                            spent_height: None,
                                        },
                                    }
                                })
                                .collect();
                            (vec![ServerMessage::CoinStatus { statuses }], false)
                        }
                        Err(e) => (
                            vec![ServerMessage::Error {
                                message: format!("coin status error: {}", e),
                            }],
                            false,
                        ),
                    }
                }
            }
        }

        ClientMessage::Subscribe => {
            let indexed_height = {
                let index = state.tweak_index.lock().unwrap_or_else(|e| e.into_inner());
                index.get_last_indexed_height().unwrap_or(0)
            };
            let tip_height = state.tip_height.load(Ordering::Relaxed);
            (
                vec![ServerMessage::ChainInfo {
                    network: state.config.network.to_string(),
                    tip_height,
                    indexed_height,
                    min_indexed_height: None,
                }],
                true,
            )
        }
    }
}
