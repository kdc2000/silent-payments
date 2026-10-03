use serde::{Deserialize, Serialize};

/// Messages sent from the client to the server over WebSocket.
#[derive(Debug, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ClientMessage {
    /// Request tweak data for a single block height.
    #[serde(rename = "get_block")]
    GetBlock { height: u32 },

    /// Request tweak data for a range of block heights (inclusive).
    #[serde(rename = "get_block_range")]
    GetBlockRange { start: u32, end: u32 },

    /// Request current chain information.
    #[serde(rename = "get_chain_info")]
    GetChainInfo,

    /// Subscribe to live block updates.
    #[serde(rename = "subscribe")]
    Subscribe,

    /// Request UTXO-aware tweak data for a range of block heights.
    #[serde(rename = "get_block_range_utxo")]
    GetBlockRangeUtxo { start: u32, end: u32 },

    /// Request GCS filter for a single block height.
    #[serde(rename = "get_block_filter")]
    GetBlockFilter { height: u32 },

    /// Request GCS filters for a range of block heights.
    #[serde(rename = "get_block_filter_range")]
    GetBlockFilterRange { start: u32, end: u32 },

    /// Check spend status of coin IDs.
    #[serde(rename = "check_coin_status")]
    CheckCoinStatus { coin_ids: Vec<String> },
}

/// Information about a coin output, serialized with hex-encoded byte fields.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OutputInfo {
    pub puzzle_hash: String,
    pub coin_id: String,
    pub amount: u64,
    pub parent_coin_id: String,
}

/// Messages sent from the server to the client over WebSocket.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ServerMessage {
    /// Tweak data and outputs for a single block.
    #[serde(rename = "block_data")]
    BlockData {
        height: u32,
        tweaks: Vec<String>,
        outputs: Vec<OutputInfo>,
    },

    /// Current chain state information.
    #[serde(rename = "chain_info")]
    ChainInfo {
        network: String,
        tip_height: u32,
        indexed_height: u32,
        #[serde(skip_serializing_if = "Option::is_none")]
        min_indexed_height: Option<u32>,
    },

    /// Error response.
    #[serde(rename = "error")]
    Error { message: String },

    /// GCS filter for a single block.
    #[serde(rename = "block_filter")]
    BlockFilter {
        height: u32,
        header_hash: String,
        filter: String,
    },

    /// Coin spend status response.
    #[serde(rename = "coin_status")]
    CoinStatus { statuses: Vec<CoinStatusEntry> },
}

/// Spend status of a single coin.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoinStatusEntry {
    pub coin_id: String,
    pub spent: bool,
    pub spent_height: Option<u32>,
}

impl ServerMessage {
    /// Create a BlockData message from raw tweak bytes and output coins.
    pub fn from_block_tweaks(
        height: u32,
        tweaks: &[Vec<u8>],
        outputs: &[crate::types::OutputCoin],
    ) -> Self {
        let tweaks_hex: Vec<String> = tweaks.iter().map(hex::encode).collect();
        let output_infos: Vec<OutputInfo> = outputs
            .iter()
            .map(|o| OutputInfo {
                puzzle_hash: hex::encode(o.puzzle_hash.as_ref()),
                coin_id: hex::encode(o.coin_id.as_ref()),
                amount: o.amount,
                parent_coin_id: hex::encode(o.parent_coin_id.as_ref()),
            })
            .collect();
        ServerMessage::BlockData {
            height,
            tweaks: tweaks_hex,
            outputs: output_infos,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_message_deserialize_get_block() {
        let msg: ClientMessage =
            serde_json::from_str(r#"{"type":"get_block","height":100}"#).unwrap();
        match msg {
            ClientMessage::GetBlock { height } => assert_eq!(height, 100),
            _ => panic!("expected GetBlock"),
        }
    }

    #[test]
    fn test_client_message_deserialize_subscribe() {
        let msg: ClientMessage = serde_json::from_str(r#"{"type":"subscribe"}"#).unwrap();
        assert!(matches!(msg, ClientMessage::Subscribe));
    }

    #[test]
    fn test_server_message_serialize_block_data() {
        let msg = ServerMessage::BlockData {
            height: 42,
            tweaks: vec!["aabb".to_string()],
            outputs: vec![OutputInfo {
                puzzle_hash: "0011".to_string(),
                coin_id: "2233".to_string(),
                amount: 500,
                parent_coin_id: "4455".to_string(),
            }],
        };
        let json = serde_json::to_string(&msg).unwrap();
        let roundtrip: ServerMessage = serde_json::from_str(&json).unwrap();
        match roundtrip {
            ServerMessage::BlockData {
                height,
                tweaks,
                outputs,
            } => {
                assert_eq!(height, 42);
                assert_eq!(tweaks, vec!["aabb"]);
                assert_eq!(outputs.len(), 1);
                assert_eq!(outputs[0].amount, 500);
            }
            _ => panic!("expected BlockData"),
        }
    }

    #[test]
    fn test_server_message_serialize_error() {
        let msg = ServerMessage::Error {
            message: "something went wrong".to_string(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        let roundtrip: ServerMessage = serde_json::from_str(&json).unwrap();
        match roundtrip {
            ServerMessage::Error { message } => assert_eq!(message, "something went wrong"),
            _ => panic!("expected Error"),
        }
    }

    // --- New message type tests ---

    #[test]
    fn test_client_message_deserialize_get_block_range_utxo() {
        let msg: ClientMessage =
            serde_json::from_str(r#"{"type":"get_block_range_utxo","start":100,"end":200}"#)
                .unwrap();
        match msg {
            ClientMessage::GetBlockRangeUtxo { start, end } => {
                assert_eq!(start, 100);
                assert_eq!(end, 200);
            }
            _ => panic!("expected GetBlockRangeUtxo"),
        }
    }

    #[test]
    fn test_client_message_deserialize_get_block_filter() {
        let msg: ClientMessage =
            serde_json::from_str(r#"{"type":"get_block_filter","height":500}"#).unwrap();
        match msg {
            ClientMessage::GetBlockFilter { height } => assert_eq!(height, 500),
            _ => panic!("expected GetBlockFilter"),
        }
    }

    #[test]
    fn test_client_message_deserialize_get_block_filter_range() {
        let msg: ClientMessage =
            serde_json::from_str(r#"{"type":"get_block_filter_range","start":10,"end":20}"#)
                .unwrap();
        match msg {
            ClientMessage::GetBlockFilterRange { start, end } => {
                assert_eq!(start, 10);
                assert_eq!(end, 20);
            }
            _ => panic!("expected GetBlockFilterRange"),
        }
    }

    #[test]
    fn test_client_message_deserialize_check_coin_status() {
        let msg: ClientMessage = serde_json::from_str(
            r#"{"type":"check_coin_status","coin_ids":["aabb","ccdd"]}"#,
        )
        .unwrap();
        match msg {
            ClientMessage::CheckCoinStatus { coin_ids } => {
                assert_eq!(coin_ids, vec!["aabb", "ccdd"]);
            }
            _ => panic!("expected CheckCoinStatus"),
        }
    }

    #[test]
    fn test_server_message_serialize_block_filter() {
        let msg = ServerMessage::BlockFilter {
            height: 42,
            header_hash: "aabb".to_string(),
            filter: "ccdd".to_string(),
        };
        let json = serde_json::to_string(&msg).unwrap();
        let roundtrip: ServerMessage = serde_json::from_str(&json).unwrap();
        match roundtrip {
            ServerMessage::BlockFilter {
                height,
                header_hash,
                filter,
            } => {
                assert_eq!(height, 42);
                assert_eq!(header_hash, "aabb");
                assert_eq!(filter, "ccdd");
            }
            _ => panic!("expected BlockFilter"),
        }
    }

    #[test]
    fn test_server_message_serialize_coin_status() {
        let msg = ServerMessage::CoinStatus {
            statuses: vec![
                CoinStatusEntry {
                    coin_id: "aabb".to_string(),
                    spent: true,
                    spent_height: Some(500),
                },
                CoinStatusEntry {
                    coin_id: "ccdd".to_string(),
                    spent: false,
                    spent_height: None,
                },
            ],
        };
        let json = serde_json::to_string(&msg).unwrap();
        let roundtrip: ServerMessage = serde_json::from_str(&json).unwrap();
        match roundtrip {
            ServerMessage::CoinStatus { statuses } => {
                assert_eq!(statuses.len(), 2);
                assert!(statuses[0].spent);
                assert_eq!(statuses[0].spent_height, Some(500));
                assert!(!statuses[1].spent);
                assert_eq!(statuses[1].spent_height, None);
            }
            _ => panic!("expected CoinStatus"),
        }
    }

    #[test]
    fn test_server_message_serialize_chain_info() {
        let msg = ServerMessage::ChainInfo {
            network: "testnet11".to_string(),
            tip_height: 1000,
            indexed_height: 990,
            min_indexed_height: Some(100),
        };
        let json = serde_json::to_string(&msg).unwrap();
        let roundtrip: ServerMessage = serde_json::from_str(&json).unwrap();
        match roundtrip {
            ServerMessage::ChainInfo {
                network,
                tip_height,
                indexed_height,
                ..
            } => {
                assert_eq!(network, "testnet11");
                assert_eq!(tip_height, 1000);
                assert_eq!(indexed_height, 990);
            }
            _ => panic!("expected ChainInfo"),
        }
    }
}
