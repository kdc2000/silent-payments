use std::sync::atomic::AtomicU32;
use std::sync::{Arc, Mutex};

use futures_util::{SinkExt, StreamExt};
use tokio::sync::broadcast;
use tokio::time::{timeout, Duration};
use tokio_tungstenite::tungstenite::Message;

use sp_service::config::{Network, ServiceConfig};
use sp_service::grouping::GroupedBlock;
use sp_service::tweak_index::TweakIndex;
use sp_service::types::OutputCoin;
use sp_service::ws::messages::ServerMessage;
use sp_service::ws::{create_router, AppState};

/// Start a test server with an in-memory TweakIndex populated with test data.
/// Returns (socket address, shared state, broadcast sender).
async fn setup_test_server() -> (
    std::net::SocketAddr,
    Arc<AppState>,
    broadcast::Sender<ServerMessage>,
) {
    let mut index = TweakIndex::open_in_memory().unwrap();

    // Block 100: one output
    let block_100 = GroupedBlock {
        height: 100,
        header_hash: [1u8; 32].into(),
        groups: vec![],
        outputs: vec![OutputCoin {
            puzzle_hash: [0xAA; 32].into(),
            coin_id: [0xBB; 32].into(),
            amount: 1_000_000,
            parent_coin_id: [0xCC; 32].into(),
        }],
    };
    index.store_block(&block_100).unwrap();

    // Block 101: one different output
    let block_101 = GroupedBlock {
        height: 101,
        header_hash: [2u8; 32].into(),
        groups: vec![],
        outputs: vec![OutputCoin {
            puzzle_hash: [0xDD; 32].into(),
            coin_id: [0xEE; 32].into(),
            amount: 500_000,
            parent_coin_id: [0xFF; 32].into(),
        }],
    };
    index.store_block(&block_101).unwrap();

    let (block_tx, _) = broadcast::channel::<ServerMessage>(64);
    let config = ServiceConfig {
        network: Network::Testnet11,
        chia_db_path: std::path::PathBuf::from("/dev/null"),
        rpc_url: "https://localhost:8555".to_string(),
        rpc_cert_path: std::path::PathBuf::from("/dev/null"),
        rpc_key_path: std::path::PathBuf::from("/dev/null"),
        ws_port: 0,
        index_db_path: std::path::PathBuf::from("/dev/null"),
        poll_interval_secs: 5,
        prune_interval_secs: 3600,
        start_height: None,
    };

    let state = Arc::new(AppState {
        tweak_index: Mutex::new(index),
        block_tx: block_tx.clone(),
        tip_height: AtomicU32::new(200),
        config,
        chia_db: None,
    });

    let app = create_router(state.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    (addr, state, block_tx)
}

/// Connect a tokio-tungstenite WebSocket client to the test server.
async fn connect_client(
    addr: std::net::SocketAddr,
) -> tokio_tungstenite::WebSocketStream<
    tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
> {
    let url = format!("ws://{}/ws", addr);
    let (ws, _) = tokio_tungstenite::connect_async(&url).await.unwrap();
    ws
}

/// Read one text message from the WebSocket with a 2-second timeout.
async fn read_message(
    ws: &mut tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
) -> serde_json::Value {
    let msg = timeout(Duration::from_secs(2), ws.next())
        .await
        .expect("timed out waiting for message")
        .expect("stream ended")
        .expect("ws error");
    let text = msg.into_text().expect("expected text message");
    serde_json::from_str(&text).expect("invalid JSON")
}

// ---- Tests ----

/// Client can connect to the WebSocket endpoint.
#[tokio::test]
async fn test_ws_connect() {
    let (addr, _state, _tx) = setup_test_server().await;
    let mut ws = connect_client(addr).await;
    // Connection succeeded -- close gracefully
    ws.close(None).await.ok();
}

/// GetBlock returns BlockData with hex-encoded tweaks and outputs.
#[tokio::test]
async fn test_get_block() {
    let (addr, _state, _tx) = setup_test_server().await;
    let mut ws = connect_client(addr).await;

    // Request existing block
    ws.send(Message::Text(
        r#"{"type":"get_block","height":100}"#.into(),
    ))
    .await
    .unwrap();

    let resp = read_message(&mut ws).await;
    assert_eq!(resp["type"], "block_data");
    assert_eq!(resp["height"], 100);

    let outputs = resp["outputs"].as_array().unwrap();
    assert_eq!(outputs.len(), 1);
    assert_eq!(outputs[0]["amount"], 1_000_000);

    // puzzle_hash should be hex-encoded 32 bytes = 64 hex chars
    let ph = outputs[0]["puzzle_hash"].as_str().unwrap();
    assert_eq!(ph.len(), 64);
    assert_eq!(ph, "aa".repeat(32));

    // Request non-existent block
    ws.send(Message::Text(
        r#"{"type":"get_block","height":999}"#.into(),
    ))
    .await
    .unwrap();

    let resp = read_message(&mut ws).await;
    assert_eq!(resp["type"], "error");
    assert!(resp["message"].as_str().unwrap().contains("not indexed"));

    ws.close(None).await.ok();
}

/// GetBlockRange returns one BlockData per indexed height.
#[tokio::test]
async fn test_get_block_range() {
    let (addr, _state, _tx) = setup_test_server().await;
    let mut ws = connect_client(addr).await;

    ws.send(Message::Text(
        r#"{"type":"get_block_range","start":100,"end":101}"#.into(),
    ))
    .await
    .unwrap();

    // Should receive two BlockData messages
    let resp1 = read_message(&mut ws).await;
    let resp2 = read_message(&mut ws).await;

    assert_eq!(resp1["type"], "block_data");
    assert_eq!(resp2["type"], "block_data");

    // Collect heights (order may vary based on iteration)
    let h1 = resp1["height"].as_u64().unwrap() as u32;
    let h2 = resp2["height"].as_u64().unwrap() as u32;
    let mut heights = vec![h1, h2];
    heights.sort();
    assert_eq!(heights, vec![100, 101]);

    // Verify amounts match the expected heights
    if h1 == 100 {
        assert_eq!(resp1["outputs"][0]["amount"], 1_000_000);
        assert_eq!(resp2["outputs"][0]["amount"], 500_000);
    } else {
        assert_eq!(resp1["outputs"][0]["amount"], 500_000);
        assert_eq!(resp2["outputs"][0]["amount"], 1_000_000);
    }

    ws.close(None).await.ok();
}

/// GetChainInfo returns network, tip_height, and indexed_height.
#[tokio::test]
async fn test_get_chain_info() {
    let (addr, _state, _tx) = setup_test_server().await;
    let mut ws = connect_client(addr).await;

    ws.send(Message::Text(
        r#"{"type":"get_chain_info"}"#.into(),
    ))
    .await
    .unwrap();

    let resp = read_message(&mut ws).await;
    assert_eq!(resp["type"], "chain_info");
    assert_eq!(resp["network"], "testnet11");
    assert_eq!(resp["tip_height"], 200); // AtomicU32 set in setup
    assert_eq!(resp["indexed_height"], 101); // Last stored block

    ws.close(None).await.ok();
}

/// Subscribe receives initial chain_info then pushed BlockData.
#[tokio::test]
async fn test_subscribe_push() {
    let (addr, _state, block_tx) = setup_test_server().await;
    let mut ws = connect_client(addr).await;

    // Send subscribe
    ws.send(Message::Text(
        r#"{"type":"subscribe"}"#.into(),
    ))
    .await
    .unwrap();

    // Should receive chain_info acknowledgment
    let ack = read_message(&mut ws).await;
    assert_eq!(ack["type"], "chain_info");
    assert_eq!(ack["network"], "testnet11");

    // Simulate a new block via broadcast channel
    block_tx
        .send(ServerMessage::BlockData {
            height: 102,
            tweaks: vec!["aabb".to_string()],
            outputs: vec![],
        })
        .unwrap();

    // Should receive the pushed block data
    let pushed = read_message(&mut ws).await;
    assert_eq!(pushed["type"], "block_data");
    assert_eq!(pushed["height"], 102);
    assert_eq!(pushed["tweaks"][0], "aabb");
    assert!(pushed["outputs"].as_array().unwrap().is_empty());

    ws.close(None).await.ok();
}

/// Error handling: invalid message returns an error response.
#[tokio::test]
async fn test_invalid_message() {
    let (addr, _state, _tx) = setup_test_server().await;
    let mut ws = connect_client(addr).await;

    ws.send(Message::Text(
        r#"{"garbage":"data"}"#.into(),
    ))
    .await
    .unwrap();

    let resp = read_message(&mut ws).await;
    assert_eq!(resp["type"], "error");
    assert!(resp["message"]
        .as_str()
        .unwrap()
        .contains("invalid message"));

    ws.close(None).await.ok();
}

/// GetBlockFilter returns stored GCS filter data.
#[tokio::test]
async fn test_get_block_filter() {
    let (addr, state, _tx) = setup_test_server().await;

    // Pre-store a GCS filter in the tweak_index
    {
        let mut index = state.tweak_index.lock().unwrap();
        let header_hash = [1u8; 32]; // matches block 100's header_hash
        let filter_data = vec![0xDE, 0xAD, 0xBE, 0xEF];
        index.store_block_filter(100, &header_hash, &filter_data).unwrap();
    }

    let mut ws = connect_client(addr).await;

    ws.send(Message::Text(
        r#"{"type":"get_block_filter","height":100}"#.into(),
    ))
    .await
    .unwrap();

    let resp = read_message(&mut ws).await;
    assert_eq!(resp["type"], "block_filter");
    assert_eq!(resp["height"], 100);
    // header_hash should be hex of [1u8; 32]
    assert_eq!(resp["header_hash"].as_str().unwrap(), "01".repeat(32));
    // filter should be hex of [0xDE, 0xAD, 0xBE, 0xEF]
    assert_eq!(resp["filter"].as_str().unwrap(), "deadbeef");

    ws.close(None).await.ok();
}

/// GetBlockFilterRange returns filters for multiple heights.
#[tokio::test]
async fn test_get_block_filter_range() {
    let (addr, state, _tx) = setup_test_server().await;

    // Pre-store GCS filters for heights 100 and 101
    {
        let mut index = state.tweak_index.lock().unwrap();
        index.store_block_filter(100, &[1u8; 32], &[0xAA, 0xBB]).unwrap();
        index.store_block_filter(101, &[2u8; 32], &[0xCC, 0xDD]).unwrap();
    }

    let mut ws = connect_client(addr).await;

    ws.send(Message::Text(
        r#"{"type":"get_block_filter_range","start":100,"end":101}"#.into(),
    ))
    .await
    .unwrap();

    let resp1 = read_message(&mut ws).await;
    let resp2 = read_message(&mut ws).await;

    assert_eq!(resp1["type"], "block_filter");
    assert_eq!(resp2["type"], "block_filter");

    let h1 = resp1["height"].as_u64().unwrap() as u32;
    let h2 = resp2["height"].as_u64().unwrap() as u32;
    let mut heights = vec![h1, h2];
    heights.sort();
    assert_eq!(heights, vec![100, 101]);

    ws.close(None).await.ok();
}

/// GetBlockRangeUtxo falls back to regular behavior when chia_db is None.
#[tokio::test]
async fn test_get_block_range_utxo_fallback() {
    let (addr, _state, _tx) = setup_test_server().await;
    let mut ws = connect_client(addr).await;

    ws.send(Message::Text(
        r#"{"type":"get_block_range_utxo","start":100,"end":101}"#.into(),
    ))
    .await
    .unwrap();

    // Should receive two BlockData messages (same as regular GetBlockRange)
    let resp1 = read_message(&mut ws).await;
    let resp2 = read_message(&mut ws).await;

    assert_eq!(resp1["type"], "block_data");
    assert_eq!(resp2["type"], "block_data");

    let h1 = resp1["height"].as_u64().unwrap() as u32;
    let h2 = resp2["height"].as_u64().unwrap() as u32;
    let mut heights = vec![h1, h2];
    heights.sort();
    assert_eq!(heights, vec![100, 101]);

    ws.close(None).await.ok();
}

/// CheckCoinStatus returns error when chia_db is unavailable.
#[tokio::test]
async fn test_check_coin_status_unavailable() {
    let (addr, _state, _tx) = setup_test_server().await;
    let mut ws = connect_client(addr).await;

    ws.send(Message::Text(
        r#"{"type":"check_coin_status","coin_ids":["aabbccdd"]}"#.into(),
    ))
    .await
    .unwrap();

    let resp = read_message(&mut ws).await;
    assert_eq!(resp["type"], "error");
    assert!(resp["message"]
        .as_str()
        .unwrap()
        .contains("coin status not available"));

    ws.close(None).await.ok();
}

/// GetBlockFilter returns error for non-existent height.
#[tokio::test]
async fn test_get_block_filter_not_found() {
    let (addr, _state, _tx) = setup_test_server().await;
    let mut ws = connect_client(addr).await;

    ws.send(Message::Text(
        r#"{"type":"get_block_filter","height":999}"#.into(),
    ))
    .await
    .unwrap();

    let resp = read_message(&mut ws).await;
    assert_eq!(resp["type"], "error");
    assert!(resp["message"]
        .as_str()
        .unwrap()
        .contains("filter not found"));

    ws.close(None).await.ok();
}

/// Network enum supports testnet11 and mainnet with correct display and prefix.
#[tokio::test]
async fn test_network_config() {
    // Testnet11
    assert_eq!(Network::Testnet11.to_string(), "testnet11");
    assert_eq!(Network::Testnet11.address_prefix(), "txch");

    // Mainnet
    assert_eq!(Network::Mainnet.to_string(), "mainnet");
    assert_eq!(Network::Mainnet.address_prefix(), "xch");

    // ServiceConfig with mainnet
    let config = ServiceConfig {
        network: Network::Mainnet,
        chia_db_path: std::path::PathBuf::from("/dev/null"),
        rpc_url: "https://localhost:8555".to_string(),
        rpc_cert_path: std::path::PathBuf::from("/dev/null"),
        rpc_key_path: std::path::PathBuf::from("/dev/null"),
        ws_port: 0,
        index_db_path: std::path::PathBuf::from("/dev/null"),
        poll_interval_secs: 5,
        prune_interval_secs: 3600,
        start_height: None,
    };
    assert_eq!(config.network.to_string(), "mainnet");
}
