//! Client-against-server sync tests.
//!
//! The real service WebSocket endpoint (`sp_service::ws`) is started on a
//! local port over an in-memory tweak index, and the real client
//! (`sp_client::ws_client::run_client`) syncs against it into a temporary coin
//! store. The tests pin down that the sync path never skips a block:
//!
//! - a wallet that already holds a coin still detects a later payment after
//!   reconnecting (the server holds compact filters for every block, as the
//!   real service does; the client must not screen blocks with them);
//! - the block at the server's `min_indexed_height` is scanned;
//! - a block whose live push never arrives is fetched before the next pushed
//!   block is scanned.

use std::future::Future;
use std::sync::atomic::AtomicU32;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use chia_bls::{PublicKey, SecretKey};
use sha2::{Digest, Sha256};
use tokio::sync::broadcast;

use sp_client::coin_store::CoinStore;
use sp_client::scanner::derive_onetime_sk_from_tweak;
use sp_client::ws_client::run_client;
use sp_common::{compute_input_hash, create_silent_payment_outputs, ScalarField};
use sp_service::config::{Network, ServiceConfig};
use sp_service::grouping::{GroupedBlock, SpendGroup};
use sp_service::tweak_index::{build_gcs_filter, TweakIndex};
use sp_service::types::OutputCoin;
use sp_service::ws::messages::ServerMessage;
use sp_service::ws::{serve, AppState};

fn sk(seed: u8) -> SecretKey {
    SecretKey::from_seed(&[seed; 32])
}

/// The recipient wallet: scan secret key, spend secret key.
fn wallet() -> (SecretKey, SecretKey) {
    (sk(1), sk(2))
}

fn sha256(data: &str) -> [u8; 32] {
    Sha256::digest(data.as_bytes()).into()
}

/// A block containing one single-input silent payment to the wallet, plus an
/// unrelated output. Returns the block and the payment's coin ID.
fn payment_block(height: u32) -> (GroupedBlock, [u8; 32]) {
    let (scan_sk, spend_sk) = wallet();
    let sender = SecretKey::from_seed(&sha256(&format!("sender-{height}")));
    let input_coin_id = sha256(&format!("input-{height}"));

    let a_sum = ScalarField::from_bytes_raw(sender.to_bytes());
    let payment_ph = create_silent_payment_outputs(
        &a_sum,
        &[&input_coin_id],
        &[(scan_sk.public_key(), spend_sk.public_key())],
    )
    .unwrap()[0]
        .1;

    let sender_pk = sender.public_key();
    let input_hash = compute_input_hash(&[&input_coin_id], &sender_pk);
    let mut tweak_point = sender_pk;
    tweak_point.scalar_multiply(input_hash.as_bytes());

    let payment_coin_id = sha256(&format!("payment-{height}"));
    let block = GroupedBlock {
        height,
        header_hash: sha256(&format!("header-{height}")).into(),
        groups: vec![SpendGroup {
            spend_indices: vec![0],
            a_sum: sender_pk,
            tweak_point: Some(tweak_point),
            coin_ids: vec![input_coin_id.into()],
        }],
        outputs: vec![
            OutputCoin {
                puzzle_hash: payment_ph.into(),
                coin_id: payment_coin_id.into(),
                amount: 1000 + u64::from(height),
                parent_coin_id: input_coin_id.into(),
            },
            OutputCoin {
                puzzle_hash: sha256(&format!("change-ph-{height}")).into(),
                coin_id: sha256(&format!("change-{height}")).into(),
                amount: 5,
                parent_coin_id: input_coin_id.into(),
            },
        ],
    };
    (block, payment_coin_id)
}

/// A block with no spends and no outputs.
fn empty_block(height: u32) -> GroupedBlock {
    GroupedBlock {
        height,
        header_hash: sha256(&format!("header-{height}")).into(),
        groups: vec![],
        outputs: vec![],
    }
}

/// Index a block the way the service does: tweak data plus a compact filter
/// over the block's output puzzle hashes.
fn index_block(index: &mut TweakIndex, block: &GroupedBlock) {
    index.store_block(block).unwrap();
    let puzzle_hashes: Vec<[u8; 32]> = block
        .outputs
        .iter()
        .map(|o| o.puzzle_hash.as_ref().try_into().unwrap())
        .collect();
    if !puzzle_hashes.is_empty() {
        let header_hash: [u8; 32] = block.header_hash.as_ref().try_into().unwrap();
        index
            .store_block_filter(
                block.height,
                &header_hash,
                &build_gcs_filter(&header_hash, &puzzle_hashes),
            )
            .unwrap();
    }
}

/// The live push the service broadcasts for an indexed block.
fn live_push(block: &GroupedBlock) -> ServerMessage {
    let tweaks: Vec<Vec<u8>> = block
        .groups
        .iter()
        .filter_map(|g| g.tweak_point.map(|t| t.to_bytes().to_vec()))
        .collect();
    ServerMessage::from_block_tweaks(block.height, &tweaks, &block.outputs)
}

/// Start the real WebSocket service over `index`. Returns its URL and state.
async fn start_server(index: TweakIndex) -> (String, Arc<AppState>) {
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
        block_tx,
        tip_height: AtomicU32::new(0),
        config,
        chia_db: None,
    });

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server_state = state.clone();
    tokio::spawn(async move {
        serve(listener, server_state).await.unwrap();
    });
    (format!("ws://{addr}/ws"), state)
}

/// Run the client against `url` while `driver` runs, and stop the client when
/// the driver finishes. The client is given the scan secret key and the spend
/// PUBLIC key only. Panics if the driver takes longer than 20 seconds.
async fn with_client<F: Future>(url: &str, store: &CoinStore, driver: F) -> F::Output {
    let (scan_sk, spend_sk) = wallet();
    let spend_pk: PublicKey = spend_sk.public_key();
    tokio::select! {
        _ = run_client(url, store, &scan_sk, &spend_pk, 0) => unreachable!("run_client never returns"),
        out = tokio::time::timeout(Duration::from_secs(20), driver) => {
            out.expect("client did not reach the expected state in time")
        }
    }
}

/// Wait until `condition` holds, polling while the client runs.
async fn wait_until(condition: impl Fn() -> bool) {
    while !condition() {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// One client session: connect, sync, and stop once `last_scanned_height`
/// has reached `height`.
async fn sync_to_height(url: &str, store: &CoinStore, height: u32) {
    with_client(url, store, wait_until(|| store.get_last_scanned_height().unwrap() >= height)).await;
}

fn detected_coin_ids(store: &CoinStore) -> Vec<[u8; 32]> {
    store
        .list_detected_coins()
        .unwrap()
        .iter()
        .map(|c| c.coin_id)
        .collect()
}

fn open_store() -> (tempfile::NamedTempFile, CoinStore) {
    let tmp = tempfile::NamedTempFile::new().unwrap();
    let store = CoinStore::open(tmp.path()).unwrap();
    (tmp, store)
}

#[tokio::test]
async fn wallet_holding_a_coin_still_detects_a_later_payment_after_reconnect() {
    // Server: empty block 5, payment #1 in block 10. Filters exist for every
    // block with outputs.
    let mut index = TweakIndex::open_in_memory().unwrap();
    index_block(&mut index, &empty_block(5));
    let (block_10, coin_10) = payment_block(10);
    index_block(&mut index, &block_10);
    let (url, state) = start_server(index).await;

    // Session 1: the wallet syncs to height 10 and now holds one unspent coin.
    let (_tmp, store) = open_store();
    sync_to_height(&url, &store, 10).await;
    assert_eq!(detected_coin_ids(&store), vec![coin_10]);
    assert_eq!(store.get_unspent_coin_ids().unwrap(), vec![coin_10]);

    // While the client is offline, the server indexes more blocks; block 20
    // pays the wallet again. Its one-time puzzle hash is new, so no compact
    // filter matches anything the wallet already knows.
    let (block_20, coin_20) = payment_block(20);
    {
        let mut index = state.tweak_index.lock().unwrap();
        for height in 11..20 {
            index_block(&mut index, &empty_block(height));
        }
        index_block(&mut index, &block_20);
        index_block(&mut index, &empty_block(21));
    }

    // Session 2: reconnect. Catch-up covers 11..=21 and must scan block 20.
    sync_to_height(&url, &store, 21).await;
    assert_eq!(
        detected_coin_ids(&store),
        vec![coin_10, coin_20],
        "the later payment must be detected by a wallet that already holds a coin"
    );
    assert_eq!(store.get_last_scanned_height().unwrap(), 21);

    // What was stored is enough for a signer holding the spend secret key.
    let (_, spend_sk) = wallet();
    for coin in store.list_detected_coins().unwrap() {
        derive_onetime_sk_from_tweak(
            &spend_sk,
            &ScalarField::from_bytes_raw(coin.tweak),
            &coin.puzzle_hash,
        )
        .unwrap();
    }
}

#[tokio::test]
async fn block_at_min_indexed_height_is_scanned() {
    // The server's index starts at height 100, and that very block pays the
    // wallet. A fresh wallet (last scanned height 0) must scan it.
    let mut index = TweakIndex::open_in_memory().unwrap();
    let (block_100, coin_100) = payment_block(100);
    index_block(&mut index, &block_100);
    index_block(&mut index, &empty_block(101));
    assert_eq!(index.get_min_indexed_height().unwrap(), Some(100));
    let (url, _state) = start_server(index).await;

    let (_tmp, store) = open_store();
    sync_to_height(&url, &store, 101).await;
    assert_eq!(detected_coin_ids(&store), vec![coin_100]);
}

#[tokio::test]
async fn only_indexed_block_at_min_height_is_scanned() {
    // Index holds a single block: min_indexed_height == indexed_height.
    let mut index = TweakIndex::open_in_memory().unwrap();
    let (block_100, coin_100) = payment_block(100);
    index_block(&mut index, &block_100);
    let (url, _state) = start_server(index).await;

    let (_tmp, store) = open_store();
    sync_to_height(&url, &store, 100).await;
    assert_eq!(detected_coin_ids(&store), vec![coin_100]);
}

#[tokio::test]
async fn wallet_already_past_min_indexed_height_is_not_moved() {
    // The wallet has scanned up to 150; the index starts at 100. Catch-up
    // resumes at 151: block 120 is not rescanned, block 160 is scanned.
    let mut index = TweakIndex::open_in_memory().unwrap();
    index_block(&mut index, &empty_block(100));
    let (block_120, _coin_120) = payment_block(120);
    index_block(&mut index, &block_120);
    let (block_160, coin_160) = payment_block(160);
    index_block(&mut index, &block_160);
    let (url, _state) = start_server(index).await;

    let (_tmp, store) = open_store();
    store.update_last_scanned_height(150).unwrap();
    sync_to_height(&url, &store, 160).await;
    assert_eq!(detected_coin_ids(&store), vec![coin_160]);
}

#[tokio::test]
async fn block_whose_live_push_was_missed_is_fetched_before_later_blocks() {
    let mut index = TweakIndex::open_in_memory().unwrap();
    index_block(&mut index, &empty_block(5));
    let (block_10, coin_10) = payment_block(10);
    index_block(&mut index, &block_10);
    let (url, state) = start_server(index).await;

    let (_tmp, store) = open_store();
    with_client(&url, &store, async {
        // Catch-up to 10, then the client subscribes.
        wait_until(|| store.get_last_scanned_height().unwrap() >= 10).await;
        wait_until(|| state.block_tx.receiver_count() >= 1).await;
        // Give the Subscribe request time to be handled by the server.
        tokio::time::sleep(Duration::from_millis(200)).await;

        // The server indexes block 11 (a payment) and block 12, but only the
        // push for block 12 reaches the client.
        let (block_11, coin_11) = payment_block(11);
        let block_12 = empty_block(12);
        {
            let mut index = state.tweak_index.lock().unwrap();
            index_block(&mut index, &block_11);
            index_block(&mut index, &block_12);
        }
        state.block_tx.send(live_push(&block_12)).unwrap();

        wait_until(|| store.get_last_scanned_height().unwrap() >= 12).await;
        assert_eq!(
            detected_coin_ids(&store),
            vec![coin_10, coin_11],
            "block 11 must be scanned although its push never arrived"
        );

        // A normal push for the next block is processed as usual.
        let (block_13, coin_13) = payment_block(13);
        index_block(&mut state.tweak_index.lock().unwrap(), &block_13);
        state.block_tx.send(live_push(&block_13)).unwrap();
        wait_until(|| store.get_last_scanned_height().unwrap() >= 13).await;
        assert_eq!(detected_coin_ids(&store), vec![coin_10, coin_11, coin_13]);
    })
    .await;
}

/// A scripted stand-in for the service that never pushes a block and that
/// "indexes" `late_blocks` at the moment the client subscribes — after the
/// client has learned the indexed height and finished catch-up. It speaks the
/// same JSON messages as the real endpoint.
async fn start_scripted_server(blocks: Vec<GroupedBlock>, late_blocks: Vec<GroupedBlock>) -> String {
    use futures_util::{SinkExt, StreamExt};
    use sp_service::ws::messages::ClientMessage;
    use tokio_tungstenite::tungstenite::Message;

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (tcp, _) = listener.accept().await.unwrap();
        let mut ws = tokio_tungstenite::accept_async(tcp).await.unwrap();
        let mut visible = blocks;
        let mut late = late_blocks;
        while let Some(Ok(msg)) = ws.next().await {
            let Ok(text) = msg.into_text() else { continue };
            let Ok(request) = serde_json::from_str::<ClientMessage>(&text) else { continue };
            let chain_info = |visible: &[GroupedBlock]| ServerMessage::ChainInfo {
                network: "testnet11".to_string(),
                tip_height: visible.iter().map(|b| b.height).max().unwrap_or(0),
                indexed_height: visible.iter().map(|b| b.height).max().unwrap_or(0),
                min_indexed_height: visible.iter().map(|b| b.height).min(),
            };
            let replies: Vec<ServerMessage> = match request {
                ClientMessage::GetChainInfo => vec![chain_info(&visible)],
                ClientMessage::GetBlockRange { start, end } => visible
                    .iter()
                    .filter(|b| b.height >= start && b.height <= end)
                    .map(live_push)
                    .collect(),
                ClientMessage::Subscribe => {
                    visible.append(&mut late);
                    vec![chain_info(&visible)]
                }
                _ => vec![ServerMessage::Error {
                    message: "not available".to_string(),
                }],
            };
            for reply in replies {
                let json = serde_json::to_string(&reply).unwrap();
                if ws.send(Message::Text(json.into())).await.is_err() {
                    return;
                }
            }
        }
    });
    format!("ws://{addr}/ws")
}

#[tokio::test]
async fn blocks_indexed_between_catch_up_and_subscribe_are_scanned() {
    // The client learns the indexed height (10) first and subscribes later.
    // Blocks 11 and 12 are indexed in between: they are not in the catch-up
    // range and are never pushed. The Subscribe acknowledgment reports indexed
    // height 12, and the client must fetch 11..=12 on its own.
    let (block_10, coin_10) = payment_block(10);
    let (block_11, coin_11) = payment_block(11);
    let url = start_scripted_server(
        vec![empty_block(5), block_10],
        vec![block_11, empty_block(12)],
    )
    .await;

    let (_tmp, store) = open_store();
    sync_to_height(&url, &store, 12).await;
    assert_eq!(detected_coin_ids(&store), vec![coin_10, coin_11]);
}
