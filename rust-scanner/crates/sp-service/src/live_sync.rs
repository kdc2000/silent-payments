use std::path::PathBuf;
use std::time::Duration;

/// Configuration for connecting to the Chia full node RPC.
#[derive(Debug, Clone)]
pub struct RpcConfig {
    /// Full node RPC URL (e.g., "https://localhost:8555")
    pub url: String,
    /// Path to the TLS certificate file (full_node.crt)
    pub cert_path: PathBuf,
    /// Path to the TLS key file (full_node.key)
    pub key_path: PathBuf,
    /// Polling interval (default: 5 seconds, ~1/3 of Chia's 18s block time)
    pub poll_interval: Duration,
}

impl Default for RpcConfig {
    fn default() -> Self {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
        Self {
            url: "https://localhost:8555".to_string(),
            cert_path: PathBuf::from(format!(
                "{}/.chia/mainnet/config/ssl/full_node/private_full_node.crt",
                home
            )),
            key_path: PathBuf::from(format!(
                "{}/.chia/mainnet/config/ssl/full_node/private_full_node.key",
                home
            )),
            poll_interval: Duration::from_secs(5),
        }
    }
}

/// Response from get_blockchain_state RPC call.
#[derive(Debug, serde::Deserialize)]
struct BlockchainStateResponse {
    success: bool,
    blockchain_state: Option<BlockchainState>,
}

#[derive(Debug, serde::Deserialize)]
struct BlockchainState {
    peak: Option<Peak>,
}

#[derive(Debug, serde::Deserialize)]
struct Peak {
    height: u32,
}

/// Live sync client that polls the full node for new blocks.
pub struct LiveSync {
    config: RpcConfig,
    client: reqwest::Client,
    last_known_height: u32,
}

impl LiveSync {
    /// Create a new LiveSync with the given RPC config and starting height.
    pub fn new(
        config: RpcConfig,
        last_known_height: u32,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        // Build HTTP client with TLS cert authentication
        let cert_pem = std::fs::read(&config.cert_path)?;
        let key_pem = std::fs::read(&config.key_path)?;
        let identity = reqwest::Identity::from_pkcs8_pem(&cert_pem, &key_pem)?;

        let client = reqwest::Client::builder()
            .identity(identity)
            .danger_accept_invalid_certs(true) // Chia uses self-signed certs
            .timeout(Duration::from_secs(10))
            .build()?;

        Ok(Self {
            config,
            client,
            last_known_height,
        })
    }

    /// Poll the full node RPC for the current peak height.
    /// Returns None if the RPC call fails (node down, network error, etc).
    pub async fn get_peak_height(&self) -> Option<u32> {
        let url = format!("{}/get_blockchain_state", self.config.url);
        let resp = self
            .client
            .post(&url)
            .json(&serde_json::json!({}))
            .send()
            .await
            .ok()?;

        let body: BlockchainStateResponse = resp.json().await.ok()?;
        if body.success {
            body.blockchain_state?.peak.map(|p| p.height)
        } else {
            None
        }
    }

    /// Check if there are new blocks since last_known_height.
    /// Returns the new peak height if it's advanced, or None if no new blocks.
    pub async fn check_for_new_blocks(&mut self) -> Option<u32> {
        let peak = self.get_peak_height().await?;
        if peak > self.last_known_height {
            self.last_known_height = peak;
            Some(peak)
        } else {
            None
        }
    }

    /// Get the configured poll interval.
    pub fn poll_interval(&self) -> Duration {
        self.config.poll_interval
    }

    /// Update the last known height (called after processing blocks).
    pub fn set_last_known_height(&mut self, height: u32) {
        self.last_known_height = height;
    }

    /// Get the last known height.
    pub fn last_known_height(&self) -> u32 {
        self.last_known_height
    }
}
