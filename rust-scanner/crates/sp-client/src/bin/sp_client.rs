//! Silent payment light client CLI binary.
//!
//! Connects to the scanning service, syncs blocks, detects silent payment
//! coins using local ECDH, and stores results in a local SQLite database.
//! Supports labeled sub-address detection and coin spend tracking.
//!
//! Syncing needs the scan secret key and the spend PUBLIC key only. They are
//! either derived from a mnemonic (the spend secret key is dropped as soon as
//! its public key is known) or given directly for a watch-only client that
//! never sees the mnemonic or the spend secret key.
//!
//! Usage:
//!   sp-client --server-url ws://127.0.0.1:9999/ws --db-path coins.db
//!   sp-client --list-coins --db-path coins.db
//!   sp-client --max-labels 5 --db-path coins.db
//!   sp-client --scan-sk-file scan.key --spend-pk <96 hex chars> --db-path coins.db

use chia_bls::{PublicKey, SecretKey};
use clap::Parser;

/// Silent payment light client -- connects to scanning service, detects coins locally.
#[derive(Parser)]
#[command(name = "sp-client", about = "Silent payment light client")]
struct Args {
    /// WebSocket server URL. The default matches sp-service's default port (9999).
    #[arg(long, default_value = "ws://127.0.0.1:9999/ws")]
    server_url: String,

    /// Path to local coin database
    #[arg(long, default_value = "sp-client.db")]
    db_path: String,

    /// Path to file containing mnemonic (alternative to interactive input)
    #[arg(long)]
    mnemonic_file: Option<String>,

    /// Just list detected coins and exit (no sync)
    #[arg(long)]
    list_coins: bool,

    /// Watch-only mode: path to a file holding the scan secret key (64 hex chars).
    /// Requires --spend-pk; no mnemonic is read.
    #[arg(long, requires = "spend_pk", conflicts_with = "mnemonic_file")]
    scan_sk_file: Option<String>,

    /// Watch-only mode: the spend public key (96 hex chars). Requires --scan-sk-file.
    #[arg(long, requires = "scan_sk_file")]
    spend_pk: Option<String>,

    /// Maximum label index to scan (0=change only, default 10)
    #[arg(long, default_value_t = 10)]
    max_labels: u32,

    /// Start scanning from this block height (only applies on first run with empty DB)
    #[arg(long)]
    start_height: Option<u32>,
}

/// The keys a syncing client holds: the scan secret key and the spend PUBLIC
/// key. The spend secret key is not part of this and is never kept.
struct ScanKeys {
    scan_sk: SecretKey,
    spend_pk: PublicKey,
}

/// Derive the scanning keys from a mnemonic (hardened paths, CHIP-0057).
///
/// The spend secret key exists only inside this function, to compute its
/// public key.
fn scan_keys_from_mnemonic(mnemonic: &str) -> ScanKeys {
    let master_sk = sp_common::mnemonic_to_master_sk(mnemonic);
    ScanKeys {
        scan_sk: sp_common::master_to_scan_sk(&master_sk),
        spend_pk: sp_common::master_to_spend_sk(&master_sk).public_key(),
    }
}

/// Parse watch-only keys: scan secret key and spend public key, hex-encoded.
fn scan_keys_from_hex(scan_sk_hex: &str, spend_pk_hex: &str) -> Result<ScanKeys, String> {
    let strip = |s: &str| s.trim().trim_start_matches("0x").to_string();

    let sk_bytes: [u8; 32] = hex::decode(strip(scan_sk_hex))
        .map_err(|e| format!("scan secret key is not hex: {e}"))?
        .try_into()
        .map_err(|_| "scan secret key must be 32 bytes".to_string())?;
    if sk_bytes == [0u8; 32] {
        return Err("scan secret key must not be zero".to_string());
    }
    let scan_sk = SecretKey::from_bytes(&sk_bytes)
        .map_err(|e| format!("invalid scan secret key: {e}"))?;

    let pk_bytes: [u8; 48] = hex::decode(strip(spend_pk_hex))
        .map_err(|e| format!("spend public key is not hex: {e}"))?
        .try_into()
        .map_err(|_| "spend public key must be 48 bytes".to_string())?;
    let spend_pk = PublicKey::from_bytes(&pk_bytes)
        .map_err(|e| format!("invalid spend public key: {e}"))?;
    if spend_pk.is_inf() {
        return Err("spend public key must not be the identity element".to_string());
    }

    Ok(ScanKeys { scan_sk, spend_pk })
}

/// The `last_scanned_height` to record so that scanning starts AT
/// `start_height`: the store holds the last height already scanned, and the
/// client continues with the height after it.
fn last_scanned_for_start_height(start_height: u32) -> u32 {
    start_height.saturating_sub(1)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::from_default_env()
                .add_directive("sp_client=info".parse().unwrap()),
        )
        .init();

    let args = Args::parse();
    let store = sp_client::coin_store::CoinStore::open(std::path::Path::new(&args.db_path))?;

    // List coins mode
    if args.list_coins {
        let coins = store.list_detected_coins()?;
        if coins.is_empty() {
            println!("No detected coins.");
        } else {
            println!("Detected {} coin(s):", coins.len());
            for coin in &coins {
                println!("  coin_id: {}", hex::encode(coin.coin_id));
                println!("  puzzle_hash: {}", hex::encode(coin.puzzle_hash));
                println!("  amount: {} mojos", coin.amount);
                println!("  block_height: {}", coin.block_height);
                if let Some(m) = coin.label {
                    println!("  label: m={}", m);
                }
                if let Some(h) = coin.spent_height {
                    println!("  spent_height: {}", h);
                } else {
                    println!("  status: unspent");
                }
                println!("  ---");
            }
        }
        let (unspent, spent) = store.get_balance()?;
        println!(
            "Balance: {} mojos unspent ({} XCH)",
            unspent,
            unspent as f64 / 1e12
        );
        if spent > 0 {
            println!(
                "Spent:   {} mojos ({} XCH)",
                spent,
                spent as f64 / 1e12
            );
        }
        return Ok(());
    }

    // Load the scanning keys: scan secret key + spend public key.
    let keys = if let (Some(sk_file), Some(spend_pk_hex)) = (&args.scan_sk_file, &args.spend_pk) {
        tracing::info!("Watch-only mode: using scan key file and spend public key");
        scan_keys_from_hex(&std::fs::read_to_string(sk_file)?, spend_pk_hex)?
    } else {
        let mnemonic = if let Some(file_path) = &args.mnemonic_file {
            std::fs::read_to_string(file_path)?.trim().to_string()
        } else if let Ok(env_mnemonic) = std::env::var("SP_MNEMONIC") {
            env_mnemonic
        } else {
            tracing::info!("Enter mnemonic (input is hidden):");
            rpassword::read_password()?
        };
        scan_keys_from_mnemonic(&mnemonic)
    };

    let last_height = store.get_last_scanned_height()?;
    if last_height == 0 {
        if let Some(start) = args.start_height {
            store.update_last_scanned_height(last_scanned_for_start_height(start))?;
            tracing::info!("Starting scan from block {} (--start-height)", start);
        }
    }
    let last_height = store.get_last_scanned_height()?;
    tracing::info!("Starting client, last scanned height: {}", last_height);
    tracing::info!("Connecting to: {}", args.server_url);
    tracing::info!("Label detection: max_labels={}", args.max_labels);

    // Run the client (never returns unless Ctrl-C)
    sp_client::ws_client::run_client(
        &args.server_url,
        &store,
        &keys.scan_sk,
        &keys.spend_pk,
        args.max_labels,
    )
    .await;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_MNEMONIC: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    // CHIP-0057 Test Vector 8 (hardened derivation).
    const TV8_SCAN_SK: &str = "0c474f92e8945069c200bb09302d1e569a9b52f59cc04a27874b1bca2adeca9f";
    const TV8_SPEND_PK: &str = "ad0c7b65a3392b62782b8c0784b10c64b0f4dc8fc2d46d2d3c7c0e1b899bf183f76996226ddf9145789d6b0bf3499219";

    #[test]
    fn test_start_height_block_itself_is_scanned() {
        // The client scans from last_scanned + 1, so --start-height 500 must
        // record 499.
        assert_eq!(last_scanned_for_start_height(500) + 1, 500);
        assert_eq!(last_scanned_for_start_height(1), 0);
        assert_eq!(last_scanned_for_start_height(0), 0);
    }

    #[test]
    fn test_scan_keys_from_mnemonic_match_tv8() {
        let keys = scan_keys_from_mnemonic(TEST_MNEMONIC);
        assert_eq!(hex::encode(keys.scan_sk.to_bytes()), TV8_SCAN_SK);
        assert_eq!(hex::encode(keys.spend_pk.to_bytes()), TV8_SPEND_PK);
    }

    #[test]
    fn test_watch_only_keys_equal_mnemonic_keys() {
        let keys = match scan_keys_from_hex(&format!("{TV8_SCAN_SK}\n"), TV8_SPEND_PK) {
            Ok(k) => k,
            Err(e) => panic!("valid keys rejected: {e}"),
        };
        let from_mnemonic = scan_keys_from_mnemonic(TEST_MNEMONIC);
        assert_eq!(keys.scan_sk.to_bytes(), from_mnemonic.scan_sk.to_bytes());
        assert_eq!(keys.spend_pk.to_bytes(), from_mnemonic.spend_pk.to_bytes());
    }

    #[test]
    fn test_watch_only_keys_rejected_when_invalid() {
        let identity_pk = format!("c0{}", "00".repeat(47));
        let zero_sk = "00".repeat(32);
        let cases = [
            ("zz", TV8_SPEND_PK),
            (&TV8_SCAN_SK[2..], TV8_SPEND_PK),
            (zero_sk.as_str(), TV8_SPEND_PK),
            (TV8_SCAN_SK, "abcd"),
            (TV8_SCAN_SK, identity_pk.as_str()),
        ];
        for (sk, pk) in cases {
            assert!(scan_keys_from_hex(sk, pk).is_err(), "accepted sk={sk} pk={pk}");
        }
    }
}
