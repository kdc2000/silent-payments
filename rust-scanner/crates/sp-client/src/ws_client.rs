//! WebSocket client with reconnection loop, sync protocol, and block processing.
//!
//! Connects to the scanning service, syncs historical blocks via GetBlockRange,
//! subscribes to live block updates, and handles reconnection with exponential
//! backoff and gap recovery. Each block is processed through the scanner and
//! detected coins are stored in the local CoinStore. Label detection and coin
//! spend tracking are integrated into the sync loop.
//!
//! The sync path never skips a block. A silent payment's puzzle hash is not
//! known before the block's tweak points have been run through ECDH, so no
//! block can be ruled out in advance: the client fetches the tweak points and
//! outputs of every block in range and scans all of them. It does not use the
//! server's compact filters or its UTXO-aware range request.

use std::collections::{HashMap, VecDeque};

use chia_bls::{PublicKey, SecretKey};
use futures_util::sink::SinkExt;
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::StreamExt;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

use sp_common::generate_label;
use sp_service::ws::messages::{ClientMessage, CoinStatusEntry, OutputInfo, ServerMessage};

use crate::coin_store::CoinStore;
use crate::scanner::{self, OutputMeta};

/// Maximum backoff duration for reconnection attempts (seconds).
const MAX_BACKOFF_SECS: u64 = 30;

/// Maximum number of blocks to request per GetBlockRange message.
const BLOCK_RANGE_CHUNK: u32 = 1000;

/// Number of live blocks between coin spend-status checks.
const SPEND_CHECK_INTERVAL: u32 = 50;

type WsSink = SplitSink<WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>, Message>;
type WsStream = SplitStream<WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>>;

/// A block pushed by the server that has to wait until earlier heights are scanned.
type PendingBlock = (u32, Vec<String>, Vec<OutputInfo>);

/// Build a label map from the scan secret key for label indices 0..=max_label.
///
/// The map keys are the 48-byte serialized label public keys, and values are
/// the label indices m. This is used by the scanner for forward-computation
/// label detection. An index whose label scalar is zero cannot be used as a
/// label and is left out.
fn build_label_map(scan_sk: &SecretKey, max_label: u32) -> HashMap<[u8; 48], u32> {
    let mut labels = HashMap::new();
    for m in 0..=max_label {
        if let Ok((_scalar, label_pk)) = generate_label(scan_sk, m) {
            labels.insert(label_pk.to_bytes(), m);
        }
    }
    labels
}

/// The value `last_scanned_height` must have before catch-up starts, so that
/// the first block the server can serve is scanned.
///
/// `last_scanned` is the highest height already scanned; catch-up starts at
/// the height after it. If the server's index begins above that, catch-up
/// starts AT `min_indexed_height`: that block is the first one served and must
/// be scanned, so the height before it is returned.
fn resume_height(last_scanned: u32, min_indexed_height: Option<u32>) -> u32 {
    match min_indexed_height {
        Some(min_h) if last_scanned.saturating_add(1) < min_h => min_h - 1,
        _ => last_scanned,
    }
}

/// Parse hex-encoded tweak strings and output info into scanner-compatible types.
///
/// Tweak points come from another party, so each one is checked before it is
/// ever multiplied by the scan secret key (CHIP-0057 "Tweak Points"): it must
/// be a valid element of the prime-order G1 subgroup (`PublicKey::from_bytes`
/// validates this) and must not be the identity element.
///
/// Invalid entries are skipped with a warning log.
fn parse_block_for_scanning(
    tweaks_hex: &[String],
    outputs: &[OutputInfo],
) -> (Vec<PublicKey>, Vec<OutputMeta>) {
    let mut tweak_points = Vec::with_capacity(tweaks_hex.len());
    for tweak_hex in tweaks_hex {
        match hex::decode(tweak_hex) {
            Ok(bytes) if bytes.len() == 48 => {
                let arr: [u8; 48] = bytes.try_into().unwrap();
                match PublicKey::from_bytes(&arr) {
                    Ok(pk) if pk.is_inf() => {
                        tracing::warn!("Skipping identity tweak point");
                    }
                    Ok(pk) => tweak_points.push(pk),
                    Err(e) => tracing::warn!("Invalid tweak public key: {}", e),
                }
            }
            Ok(bytes) => {
                tracing::warn!(
                    "Tweak hex wrong length: expected 96 hex chars (48 bytes), got {} bytes",
                    bytes.len()
                );
            }
            Err(e) => {
                tracing::warn!("Invalid tweak hex: {}", e);
            }
        }
    }

    let mut output_metas = Vec::with_capacity(outputs.len());
    for output in outputs {
        let puzzle_hash = match hex::decode(&output.puzzle_hash) {
            Ok(b) if b.len() == 32 => {
                let arr: [u8; 32] = b.try_into().unwrap();
                arr
            }
            _ => {
                tracing::warn!("Invalid puzzle_hash hex in output");
                continue;
            }
        };
        let coin_id = match hex::decode(&output.coin_id) {
            Ok(b) if b.len() == 32 => {
                let arr: [u8; 32] = b.try_into().unwrap();
                arr
            }
            _ => {
                tracing::warn!("Invalid coin_id hex in output");
                continue;
            }
        };
        let parent_coin_id = match hex::decode(&output.parent_coin_id) {
            Ok(b) if b.len() == 32 => {
                let arr: [u8; 32] = b.try_into().unwrap();
                arr
            }
            _ => {
                tracing::warn!("Invalid parent_coin_id hex in output");
                continue;
            }
        };
        output_metas.push(OutputMeta {
            puzzle_hash,
            coin_id,
            amount: output.amount,
            parent_coin_id,
        });
    }

    (tweak_points, output_metas)
}

/// Scan a single block and store any detected coins.
///
/// Needs the scan secret key and the spend PUBLIC key only. What is stored per
/// coin is the combined tweak, never a secret key. Storing is idempotent, so a
/// block may be processed more than once.
///
/// Does not touch `last_scanned_height`; the caller records progress once it
/// knows that no lower height is still outstanding.
///
/// Returns the number of detected coins.
fn process_block(
    height: u32,
    tweaks_hex: &[String],
    outputs: &[OutputInfo],
    store: &CoinStore,
    scan_sk: &SecretKey,
    spend_pk: &PublicKey,
    labels: Option<&HashMap<[u8; 48], u32>>,
) -> Result<u32, Box<dyn std::error::Error>> {
    let (tweak_points, output_metas) = parse_block_for_scanning(tweaks_hex, outputs);

    let detected = scanner::scan_block(scan_sk, spend_pk, &tweak_points, &output_metas, labels);

    for coin in &detected {
        store.store_detected_coin(
            &coin.coin_id,
            &coin.puzzle_hash,
            coin.amount,
            coin.tweak.as_bytes(),
            coin.k,
            height,
            &coin.parent_coin_id,
            coin.label,
        )?;

        let label_str = match coin.label {
            Some(m) => format!(" (label m={})", m),
            None => String::new(),
        };
        tracing::info!(
            "Block {}: detected coin {} amount={} k={}{}",
            height,
            hex::encode(coin.coin_id),
            coin.amount,
            coin.k,
            label_str
        );
    }

    Ok(detected.len() as u32)
}

/// Read and deserialize the next server message from the WebSocket stream.
async fn read_server_message(
    stream: &mut WsStream,
) -> Result<ServerMessage, Box<dyn std::error::Error>> {
    let msg = stream
        .next()
        .await
        .ok_or("WebSocket stream closed")?
        .map_err(|e| -> Box<dyn std::error::Error> { Box::new(e) })?;

    let text = msg.into_text()?;
    let server_msg: ServerMessage = serde_json::from_str(&text)?;
    Ok(server_msg)
}

async fn send_client_message(
    sink: &mut WsSink,
    msg: &ClientMessage,
) -> Result<(), Box<dyn std::error::Error>> {
    sink.send(Message::Text(serde_json::to_string(msg)?.into()))
        .await?;
    Ok(())
}

/// The keys and label set a sync session scans with.
struct ScanContext<'a> {
    store: &'a CoinStore,
    scan_sk: &'a SecretKey,
    spend_pk: &'a PublicKey,
    labels: HashMap<[u8; 48], u32>,
}

impl ScanContext<'_> {
    fn process_block(
        &self,
        height: u32,
        tweaks: &[String],
        outputs: &[OutputInfo],
    ) -> Result<u32, Box<dyn std::error::Error>> {
        process_block(
            height,
            tweaks,
            outputs,
            self.store,
            self.scan_sk,
            self.spend_pk,
            Some(&self.labels),
        )
    }
}

/// Fetch and scan EVERY block the server holds in `start..=end`.
///
/// The range is requested in chunks with plain `GetBlockRange` (tweak points
/// and outputs for each indexed block); nothing is pre-filtered. Progress
/// (`last_scanned_height`) is recorded only after a whole chunk has arrived
/// without a server error, so an interrupted chunk is fetched again in full.
/// A server error fails the sync; the caller reconnects and resumes from the
/// recorded height.
///
/// Blocks pushed by the server for heights above `end` (live updates that
/// arrive while the range is being fetched) are queued in `pending`, in
/// arrival order, to be handled after the range.
async fn sync_range(
    sink: &mut WsSink,
    stream: &mut WsStream,
    ctx: &ScanContext<'_>,
    start: u32,
    end: u32,
    pending: &mut VecDeque<PendingBlock>,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut chunk_start = start;
    while chunk_start <= end {
        let chunk_end = chunk_start
            .saturating_add(BLOCK_RANGE_CHUNK - 1)
            .min(end);

        send_client_message(
            sink,
            &ClientMessage::GetBlockRange {
                start: chunk_start,
                end: chunk_end,
            },
        )
        .await?;
        // The ChainInfo reply marks the end of the range response.
        send_client_message(sink, &ClientMessage::GetChainInfo).await?;

        loop {
            match read_server_message(stream).await? {
                ServerMessage::BlockData {
                    height,
                    tweaks,
                    outputs,
                } => {
                    if height > end {
                        pending.push_back((height, tweaks, outputs));
                    } else if height >= chunk_start {
                        ctx.process_block(height, &tweaks, &outputs)?;
                    }
                    // Heights below chunk_start are already scanned.
                }
                ServerMessage::ChainInfo { .. } => break,
                ServerMessage::CoinStatus { statuses } => {
                    apply_coin_statuses(ctx.store, &statuses)?;
                }
                ServerMessage::Error { message } => {
                    return Err(format!(
                        "server error while syncing blocks {}-{}: {}",
                        chunk_start, chunk_end, message
                    )
                    .into());
                }
                ServerMessage::BlockFilter { .. } => {}
            }
        }

        ctx.store.update_last_scanned_height(chunk_end)?;
        if chunk_end == u32::MAX {
            break;
        }
        chunk_start = chunk_end + 1;
    }
    Ok(())
}

/// Mark the coins a CoinStatus response reports as spent, and log the balance.
fn apply_coin_statuses(
    store: &CoinStore,
    statuses: &[CoinStatusEntry],
) -> Result<(), Box<dyn std::error::Error>> {
    for status in statuses {
        if !status.spent {
            continue;
        }
        let id_bytes: Option<[u8; 32]> = hex::decode(&status.coin_id)
            .ok()
            .and_then(|b| b.try_into().ok());
        if let (Some(id_bytes), Some(height)) = (id_bytes, status.spent_height) {
            store.mark_coin_spent(&id_bytes, height)?;
            tracing::info!("Coin {} spent at height {}", status.coin_id, height);
        }
    }
    let (unspent, spent) = store.get_balance()?;
    tracing::info!(
        "Balance: {} mojos unspent, {} mojos spent",
        unspent,
        spent
    );
    Ok(())
}

/// Ask the server for the spend status of all unspent coins.
///
/// Only sends the request. Returns false if there was nothing to ask about.
async fn request_coin_statuses(
    sink: &mut WsSink,
    store: &CoinStore,
) -> Result<bool, Box<dyn std::error::Error>> {
    let unspent_ids = store.get_unspent_coin_ids()?;
    if unspent_ids.is_empty() {
        return Ok(false);
    }
    let coin_ids: Vec<String> = unspent_ids.iter().map(hex::encode).collect();
    send_client_message(sink, &ClientMessage::CheckCoinStatus { coin_ids }).await?;
    Ok(true)
}

/// Check spend status of unspent coins and wait for the answer.
///
/// Must only be called while NOT subscribed to live blocks: it takes the next
/// message as the answer, which is only safe when the server cannot push a
/// block in between. Returns false if the server cannot report coin status.
async fn check_coin_spends_before_subscribe(
    sink: &mut WsSink,
    stream: &mut WsStream,
    store: &CoinStore,
) -> Result<bool, Box<dyn std::error::Error>> {
    if !request_coin_statuses(sink, store).await? {
        return Ok(true);
    }
    match read_server_message(stream).await? {
        ServerMessage::CoinStatus { statuses } => {
            apply_coin_statuses(store, &statuses)?;
            Ok(true)
        }
        ServerMessage::Error { message } => {
            tracing::debug!("Coin status check unavailable: {}", message);
            Ok(false)
        }
        _ => Ok(true),
    }
}

/// Run a single sync session on an established WebSocket connection.
///
/// 1. Sends GetChainInfo to learn the indexed height
/// 2. Catches up: fetches and scans every block from the last scanned height
///    (or the server's first indexed block) to the indexed height
/// 3. Checks coin spend status after catch-up
/// 4. Subscribes to live block updates, then scans whatever the server
///    indexed between step 1 and the subscription
/// 5. Processes live blocks in height order. A pushed block that is not the
///    direct successor of the last scanned height first triggers a range
///    request for the heights in between, so a missed push never skips a block.
async fn sync_loop(
    ws: WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>,
    store: &CoinStore,
    scan_sk: &SecretKey,
    spend_pk: &PublicKey,
    max_labels: u32,
) -> Result<(), Box<dyn std::error::Error>> {
    let (mut sink, mut stream) = ws.split();

    // Label map for indices 0..=max_labels. The scanner checks the change
    // label m = 0 whatever is passed here.
    let ctx = ScanContext {
        store,
        scan_sk,
        spend_pk,
        labels: build_label_map(scan_sk, max_labels),
    };

    // Step 1: Get chain info
    send_client_message(&mut sink, &ClientMessage::GetChainInfo).await?;

    let chain_info = read_server_message(&mut stream).await?;
    let (indexed_height, min_indexed_height) = match chain_info {
        ServerMessage::ChainInfo {
            ref network,
            indexed_height,
            tip_height,
            min_indexed_height,
            ..
        } => {
            tracing::info!(
                "Connected to {} network, tip={}, indexed={}, min={}",
                network,
                tip_height,
                indexed_height,
                min_indexed_height.map_or("0".to_string(), |h| h.to_string())
            );
            (indexed_height, min_indexed_height)
        }
        _ => {
            return Err("Expected ChainInfo response, got something else".into());
        }
    };

    // Step 2: Historical catch-up over every block in range.
    let mut last_scanned = store.get_last_scanned_height()?;

    // If the server's index starts above our position, start at its first
    // indexed block (that block included).
    let resume = resume_height(last_scanned, min_indexed_height);
    if resume != last_scanned {
        tracing::info!(
            "Server index starts at height {}; resuming from there (was at {})",
            resume + 1,
            last_scanned
        );
        store.update_last_scanned_height(resume)?;
        last_scanned = resume;
    }

    // Nothing can be pushed before we subscribe, but sync_range needs a queue.
    let mut pending: VecDeque<PendingBlock> = VecDeque::new();

    if last_scanned < indexed_height {
        tracing::info!(
            "Historical catch-up: scanning blocks {} to {}",
            last_scanned + 1,
            indexed_height
        );
        sync_range(
            &mut sink,
            &mut stream,
            &ctx,
            last_scanned + 1,
            indexed_height,
            &mut pending,
        )
        .await?;
        tracing::info!(
            "Historical catch-up complete at height {}",
            indexed_height
        );
    } else {
        tracing::info!("Already synced to indexed height {}", indexed_height);
    }

    // Step 3: Check coin spend status after catch-up
    let coin_status_available =
        match check_coin_spends_before_subscribe(&mut sink, &mut stream, store).await {
            Ok(available) => available,
            Err(e) => {
                tracing::warn!("Post-catchup coin spend check failed: {}", e);
                return Err(e);
            }
        };

    // Step 4: Subscribe to live blocks
    send_client_message(&mut sink, &ClientMessage::Subscribe).await?;

    // The acknowledgment (ChainInfo) carries the indexed height at the moment
    // of subscribing. Blocks indexed while we were catching up lie between our
    // position and that height and will not be pushed: fetch them now.
    let subscribed_at = match read_server_message(&mut stream).await? {
        ServerMessage::ChainInfo { indexed_height, .. } => indexed_height,
        _ => return Err("Expected ChainInfo acknowledgment of Subscribe".into()),
    };
    tracing::info!("Subscribed to live blocks");

    let last_scanned = store.get_last_scanned_height()?;
    if last_scanned < subscribed_at {
        sync_range(
            &mut sink,
            &mut stream,
            &ctx,
            last_scanned + 1,
            subscribed_at,
            &mut pending,
        )
        .await?;
    }

    // Step 5: Process live blocks with periodic spend checking
    let mut live_block_count = 0u32;
    loop {
        let (height, tweaks, outputs) = match pending.pop_front() {
            Some(block) => block,
            None => match read_server_message(&mut stream).await? {
                ServerMessage::BlockData {
                    height,
                    tweaks,
                    outputs,
                } => (height, tweaks, outputs),
                ServerMessage::CoinStatus { statuses } => {
                    apply_coin_statuses(store, &statuses)?;
                    continue;
                }
                ServerMessage::Error { message } => {
                    // Not fatal here: if the server dropped pushes, the next
                    // pushed block's height shows the gap and it is refetched.
                    tracing::warn!("Server error: {}", message);
                    continue;
                }
                _ => continue,
            },
        };

        let last_scanned = store.get_last_scanned_height()?;
        if height <= last_scanned {
            continue; // already scanned
        }
        if height > last_scanned + 1 {
            // One or more pushes may have been missed. Fetch everything the
            // server holds below this block before scanning it.
            tracing::info!(
                "Live block {} is ahead of last scanned {}; fetching blocks in between",
                height,
                last_scanned
            );
            sync_range(
                &mut sink,
                &mut stream,
                &ctx,
                last_scanned + 1,
                height - 1,
                &mut pending,
            )
            .await?;
        }

        ctx.process_block(height, &tweaks, &outputs)?;
        store.update_last_scanned_height(height)?;

        live_block_count += 1;
        if coin_status_available && live_block_count.is_multiple_of(SPEND_CHECK_INTERVAL) {
            // The answer arrives in this loop as a CoinStatus message; it is
            // not awaited here, because a pushed block could arrive first.
            if let Err(e) = request_coin_statuses(&mut sink, store).await {
                tracing::warn!("Coin spend check failed: {}", e);
            }
        }
    }
}

/// Run the WebSocket client with automatic reconnection and gap recovery.
///
/// This function never returns under normal operation. It maintains a persistent
/// connection to the scanning service, reconnecting with exponential backoff
/// (1s, 2s, 4s, ... capped at 30s) after connection loss.
///
/// On each (re)connection, the sync loop:
/// 1. Queries GetChainInfo for the current indexed height
/// 2. Fetches and scans every block since the last scanned height via
///    GetBlockRange (gap recovery)
/// 3. Checks coin spend status
/// 4. Subscribes for live block updates
///
/// Syncing needs the scan secret key and the spend PUBLIC key only; the spend
/// secret key is never required here.
///
/// Labels with indices 0..=max_labels are scanned for. The change label m = 0
/// is always included.
pub async fn run_client(
    url: &str,
    store: &CoinStore,
    scan_sk: &SecretKey,
    spend_pk: &PublicKey,
    max_labels: u32,
) {
    let mut backoff_secs = 1u64;
    loop {
        tracing::info!("Connecting to {}...", url);
        match tokio_tungstenite::connect_async(url).await {
            Ok((ws, _response)) => {
                tracing::info!("Connected to {}", url);
                backoff_secs = 1; // Reset on successful connection
                match sync_loop(ws, store, scan_sk, spend_pk, max_labels).await {
                    Ok(()) => tracing::info!("Connection closed normally"),
                    Err(e) => tracing::warn!("Connection lost: {}", e),
                }
            }
            Err(e) => {
                tracing::warn!("Connection failed: {}", e);
            }
        }
        tracing::info!("Reconnecting in {} seconds...", backoff_secs);
        tokio::time::sleep(std::time::Duration::from_secs(backoff_secs)).await;
        backoff_secs = (backoff_secs * 2).min(MAX_BACKOFF_SECS);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::derive_onetime_sk_from_tweak;

    // Given recipient keys and values of CHIP Test Vector 1.
    const TV1_SCAN_SK: &str = "132567e4dec19a4f50d9e9a549f16283dfb5aa4ad1ffdb6a505fcfcc56a690f6";
    const TV1_SPEND_SK: &str = "53d140b312a0e16316314274eb6398e15706d100fe8a754990540febd931b087";
    const TV1_SENDER_PK: &str = "8d9a5ed9c9b1a58476b07262007c636d775f2a33f0533737f3b3b0eaf99a8c0c51b3f2d87dc03a657e07f1828ab760fa";
    const TV1_INPUT_HASH: &str = "38a1c8379cceb0fbebfdf3016707e54a1c7e9d21afb9489b9cc58f6055cc9411";
    const TV1_PH: &str = "23adba149dd9000d65e0f8e21b6975364cbe89a63caf56533df4b7664c21fbf5";
    const TV1_T0: &str = "5c560301c50fa309ad43d0f82cd1af143f6e3769659c80e8c14a072331582ab1";
    const TV1_ONETIME_SK: &str = "3c399c61ae130724903b3b650e936ff042b7646764289a33519e17100a89db37";

    fn sk(hex_str: &str) -> SecretKey {
        let bytes: [u8; 32] = hex::decode(hex_str).unwrap().try_into().unwrap();
        SecretKey::from_bytes(&bytes).unwrap()
    }

    fn tv1_tweak_hex() -> String {
        let pk_bytes: [u8; 48] = hex::decode(TV1_SENDER_PK).unwrap().try_into().unwrap();
        let mut tweak_point = PublicKey::from_bytes(&pk_bytes).unwrap();
        tweak_point.scalar_multiply(&hex::decode(TV1_INPUT_HASH).unwrap());
        hex::encode(tweak_point.to_bytes())
    }

    fn output_info(puzzle_hash: &str, coin_tag: u8, amount: u64) -> OutputInfo {
        OutputInfo {
            puzzle_hash: puzzle_hash.to_string(),
            coin_id: hex::encode([coin_tag; 32]),
            amount,
            parent_coin_id: hex::encode([0u8; 32]),
        }
    }

    /// A compressed G1 encoding that is on the curve but outside the
    /// prime-order subgroup.
    fn off_subgroup_point_hex() -> String {
        for x in 1u8..=255 {
            let mut bytes = [0u8; 48];
            bytes[0] = 0x80;
            bytes[47] = x;
            if let Ok(p) = PublicKey::from_bytes_unchecked(&bytes) {
                if !p.is_valid() {
                    return hex::encode(bytes);
                }
            }
        }
        panic!("no off-subgroup test point found");
    }

    #[test]
    fn test_parse_rejects_identity_and_off_subgroup_tweak_points() {
        let identity_hex = format!("c0{}", "00".repeat(47));
        let off_subgroup_hex = off_subgroup_point_hex();
        let good_hex = tv1_tweak_hex();

        let tweaks = vec![
            identity_hex,
            off_subgroup_hex,
            "zz".to_string(),
            "abcd".to_string(),
            good_hex.clone(),
        ];
        let (points, _) = parse_block_for_scanning(&tweaks, &[]);
        assert_eq!(points.len(), 1, "only the valid, non-identity point is kept");
        assert_eq!(hex::encode(points[0].to_bytes()), good_hex);
    }

    #[test]
    fn test_process_block_needs_no_spend_secret_key_and_stores_tweak() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let store = CoinStore::open(tmp.path()).unwrap();

        let scan_sk = sk(TV1_SCAN_SK);
        // The syncing side is given the spend PUBLIC key only.
        let spend_pk = sk(TV1_SPEND_SK).public_key();

        // Two coins carry the TV1 one-time puzzle hash; a third is unrelated.
        let outputs = vec![
            output_info(TV1_PH, 0x01, 1000),
            output_info(&hex::encode([0xaa; 32]), 0x02, 5),
            output_info(TV1_PH, 0x03, 2500),
        ];
        let count =
            process_block(42, &[tv1_tweak_hex()], &outputs, &store, &scan_sk, &spend_pk, None)
                .unwrap();
        assert_eq!(count, 2, "both coins with the matching puzzle hash are stored");
        // Progress is recorded by the caller, not by scanning a single block.
        assert_eq!(store.get_last_scanned_height().unwrap(), 0);

        let coins = store.list_detected_coins().unwrap();
        assert_eq!(coins.len(), 2);
        assert_eq!(store.get_balance().unwrap(), (3500, 0));
        for coin in &coins {
            assert_eq!(hex::encode(coin.puzzle_hash), TV1_PH);
            assert_eq!(coin.block_height, 42);
            assert_eq!(coin.k, 0);
            assert_eq!(coin.label, None);
            // What is stored is t_0, not the one-time secret key.
            assert_eq!(hex::encode(coin.tweak), TV1_T0);
            assert_ne!(hex::encode(coin.tweak), TV1_ONETIME_SK);

            // A signer holding b_spend turns the stored tweak into the key.
            let onetime_sk = derive_onetime_sk_from_tweak(
                &sk(TV1_SPEND_SK),
                &sp_common::ScalarField::from_bytes_raw(coin.tweak),
                &coin.puzzle_hash,
            )
            .unwrap();
            assert_eq!(hex::encode(onetime_sk.to_bytes()), TV1_ONETIME_SK);
        }
    }

    #[test]
    fn test_resume_height_includes_the_first_indexed_block() {
        // Fresh wallet, server index starts at 100: catch-up must start AT 100,
        // so the recorded "last scanned" height is 99.
        assert_eq!(resume_height(0, Some(100)), 99);
        // Wallet far behind the server's first block: same.
        assert_eq!(resume_height(40, Some(100)), 99);
        // Wallet directly below the first indexed block: next block is 100 already.
        assert_eq!(resume_height(99, Some(100)), 99);
        // Wallet at or past the first indexed block: unchanged, never moved back.
        assert_eq!(resume_height(100, Some(100)), 100);
        assert_eq!(resume_height(250, Some(100)), 250);
        // Empty index or index from genesis.
        assert_eq!(resume_height(7, None), 7);
        assert_eq!(resume_height(0, Some(0)), 0);
        assert_eq!(resume_height(0, Some(1)), 0);
    }

    #[test]
    fn test_label_map_always_contains_change_label() {
        let scan_sk = sk(TV1_SCAN_SK);
        let labels = build_label_map(&scan_sk, 0);
        assert_eq!(labels.len(), 1);
        assert_eq!(labels.values().copied().collect::<Vec<_>>(), vec![0]);
        assert_eq!(build_label_map(&scan_sk, 3).len(), 4);
    }
}
