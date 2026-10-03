use std::fmt;
use std::path::PathBuf;
use std::str::FromStr;

use clap::Parser;
use serde::{Deserialize, Serialize};

/// Supported Chia networks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Network {
    Mainnet,
    Testnet11,
}

impl Network {
    /// Default path to the Chia blockchain SQLite database for this network.
    pub fn default_chia_db_path(&self) -> PathBuf {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
        match self {
            Network::Mainnet => PathBuf::from(format!(
                "{}/.chia/mainnet/db/blockchain_v2_mainnet.sqlite",
                home
            )),
            Network::Testnet11 => PathBuf::from(format!(
                "{}/.chia/mainnet/db/blockchain_v2_testnet11.sqlite",
                home
            )),
        }
    }

    /// Default directory containing RPC TLS certificate and key files.
    pub fn default_rpc_cert_dir(&self) -> PathBuf {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
        match self {
            Network::Mainnet | Network::Testnet11 => PathBuf::from(format!(
                "{}/.chia/mainnet/config/ssl/full_node",
                home
            )),
        }
    }

    /// Bech32m address prefix for this network.
    pub fn address_prefix(&self) -> &str {
        match self {
            Network::Mainnet => "xch",
            Network::Testnet11 => "txch",
        }
    }
}

impl fmt::Display for Network {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Network::Mainnet => write!(f, "mainnet"),
            Network::Testnet11 => write!(f, "testnet11"),
        }
    }
}

impl FromStr for Network {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "mainnet" => Ok(Network::Mainnet),
            "testnet11" => Ok(Network::Testnet11),
            other => Err(format!("unknown network: {}", other)),
        }
    }
}

/// Runtime configuration for the silent payment scanning service.
#[derive(Debug, Clone)]
pub struct ServiceConfig {
    pub network: Network,
    pub chia_db_path: PathBuf,
    pub rpc_url: String,
    pub rpc_cert_path: PathBuf,
    pub rpc_key_path: PathBuf,
    pub ws_port: u16,
    pub index_db_path: PathBuf,
    pub poll_interval_secs: u64,
    pub prune_interval_secs: u64,
    pub start_height: Option<u32>,
}

/// Command-line arguments parsed via clap.
#[derive(Debug, Parser)]
#[command(name = "sp-service", about = "Silent payment scanning service")]
pub struct CliArgs {
    /// Network to connect to (mainnet or testnet11).
    #[arg(long, default_value = "testnet11")]
    pub network: Network,

    /// Path to Chia blockchain database (overrides network default).
    #[arg(long)]
    pub chia_db: Option<PathBuf>,

    /// Full node RPC URL.
    #[arg(long, default_value = "https://localhost:8555")]
    pub rpc_url: String,

    /// Path to RPC TLS certificate (overrides network default).
    #[arg(long)]
    pub rpc_cert: Option<PathBuf>,

    /// Path to RPC TLS key (overrides network default).
    #[arg(long)]
    pub rpc_key: Option<PathBuf>,

    /// WebSocket server listen port.
    #[arg(long, default_value_t = 9999)]
    pub port: u16,

    /// Path to the service index database.
    #[arg(long, default_value = "sp_service_index.sqlite")]
    pub index_db: PathBuf,

    /// RPC polling interval in seconds.
    #[arg(long, default_value_t = 5)]
    pub poll_interval: u64,

    /// Pruning interval in seconds (0 to disable). Removes tweak data for blocks
    /// whose outputs are all spent on-chain.
    #[arg(long, default_value_t = 3600)]
    pub prune_interval: u64,

    /// Start indexing from this block height (only applies on first run with empty index).
    /// Also prunes existing data below this height.
    #[arg(long)]
    pub start_height: Option<u32>,
}

impl From<CliArgs> for ServiceConfig {
    fn from(args: CliArgs) -> Self {
        let cert_dir = args.network.default_rpc_cert_dir();
        Self {
            chia_db_path: args
                .chia_db
                .unwrap_or_else(|| args.network.default_chia_db_path()),
            rpc_url: args.rpc_url,
            rpc_cert_path: args
                .rpc_cert
                .unwrap_or_else(|| cert_dir.join("private_full_node.crt")),
            rpc_key_path: args
                .rpc_key
                .unwrap_or_else(|| cert_dir.join("private_full_node.key")),
            ws_port: args.port,
            index_db_path: args.index_db,
            poll_interval_secs: args.poll_interval,
            prune_interval_secs: args.prune_interval,
            network: args.network,
            start_height: args.start_height,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_network_display() {
        assert_eq!(Network::Testnet11.to_string(), "testnet11");
        assert_eq!(Network::Mainnet.to_string(), "mainnet");
    }

    #[test]
    fn test_network_from_str() {
        assert_eq!("testnet11".parse::<Network>().unwrap(), Network::Testnet11);
        assert_eq!("mainnet".parse::<Network>().unwrap(), Network::Mainnet);
        assert!("invalid".parse::<Network>().is_err());
    }

    #[test]
    fn test_network_default_paths() {
        let testnet_path = Network::Testnet11.default_chia_db_path();
        assert!(
            testnet_path.to_string_lossy().contains("testnet11"),
            "testnet11 path should contain 'testnet11': {:?}",
            testnet_path
        );

        let mainnet_path = Network::Mainnet.default_chia_db_path();
        assert!(
            mainnet_path.to_string_lossy().contains("mainnet"),
            "mainnet path should contain 'mainnet': {:?}",
            mainnet_path
        );
    }

    #[test]
    fn test_network_address_prefix() {
        assert_eq!(Network::Testnet11.address_prefix(), "txch");
        assert_eq!(Network::Mainnet.address_prefix(), "xch");
    }
}
