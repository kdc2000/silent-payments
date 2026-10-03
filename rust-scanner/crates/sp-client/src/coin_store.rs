//! SQLite-backed coin store for detected silent payment coins.
//!
//! Persists detected coins and sync state to a local database,
//! providing crash-safe persistence and resumable scanning.
//!
//! The store holds no secret keys. For each coin it keeps the combined tweak
//! `(t_k + label_scalar) mod r` found by the scanner; a signer that holds the
//! spend secret key turns it into the one-time key with
//! [`crate::scanner::derive_onetime_sk_from_tweak`].

use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, params};

/// A detected coin record retrieved from the database.
#[derive(Debug, Clone)]
pub struct DetectedCoinRecord {
    pub coin_id: [u8; 32],
    pub puzzle_hash: [u8; 32],
    pub amount: u64,
    /// Combined tweak `(t_k + label_scalar) mod r`, 32 bytes big-endian.
    /// Not a secret key: spending also needs the spend secret key.
    pub tweak: [u8; 32],
    /// Output index k within the spend group.
    pub k: u32,
    pub block_height: u32,
    pub detected_at: i64,
    pub spent_height: Option<u32>,
    pub label: Option<u32>,
}

/// SQLite-backed store for detected silent payment coins and sync state.
pub struct CoinStore {
    conn: Connection,
}

impl CoinStore {
    /// Open or create a coin store database at the given path.
    ///
    /// Creates `detected_coins` and `sync_state` tables if they don't exist.
    /// Uses WAL mode for concurrent read performance.
    pub fn open(path: &std::path::Path) -> Result<Self, Box<dyn std::error::Error>> {
        let conn = Connection::open(path)?;
        conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;")?;
        let store = Self { conn };
        store.create_tables()?;
        store.check_schema()?;
        Ok(store)
    }

    fn create_tables(&self) -> Result<(), Box<dyn std::error::Error>> {
        self.conn.execute_batch("
            CREATE TABLE IF NOT EXISTS detected_coins (
                coin_id BLOB PRIMARY KEY,
                puzzle_hash BLOB NOT NULL,
                amount INTEGER NOT NULL,
                tweak BLOB NOT NULL,
                k INTEGER NOT NULL,
                block_height INTEGER NOT NULL,
                parent_coin_id BLOB NOT NULL,
                detected_at INTEGER NOT NULL,
                spent_height INTEGER DEFAULT NULL,
                label INTEGER DEFAULT NULL
            );
            CREATE TABLE IF NOT EXISTS sync_state (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            INSERT OR IGNORE INTO sync_state (key, value) VALUES ('last_scanned_height', '0');
        ")?;
        Ok(())
    }

    /// Refuse databases written with the earlier schema.
    ///
    /// Earlier versions stored a one-time SECRET key per coin (`onetime_sk`).
    /// There is no migration: such a database is rejected so that it is
    /// deleted and the chain rescanned, rather than silently mixed with the
    /// current tweak-only rows.
    fn check_schema(&self) -> Result<(), Box<dyn std::error::Error>> {
        let columns: Vec<String> = self.conn
            .prepare("PRAGMA table_info(detected_coins)")?
            .query_map([], |row| { let name: String = row.get(1)?; Ok(name) })?
            .filter_map(|r| r.ok())
            .collect();

        let has = |name: &str| columns.iter().any(|n| n == name);
        if has("onetime_sk") || !has("tweak") || !has("k") {
            return Err(
                "coin database uses an old schema (it stores one-time secret keys); \
                 delete it and rescan"
                    .into(),
            );
        }
        Ok(())
    }

    /// Store a detected coin. Duplicate coin_ids are silently ignored (INSERT OR IGNORE).
    ///
    /// `tweak` is the combined tweak `(t_k + label_scalar) mod r` reported by
    /// the scanner, and `k` the output index. No secret key is stored.
    #[allow(clippy::too_many_arguments)]
    pub fn store_detected_coin(
        &self,
        coin_id: &[u8; 32],
        puzzle_hash: &[u8; 32],
        amount: u64,
        tweak: &[u8; 32],
        k: u32,
        block_height: u32,
        parent_coin_id: &[u8; 32],
        label: Option<u32>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_secs() as i64;
        self.conn.execute(
            "INSERT OR IGNORE INTO detected_coins (coin_id, puzzle_hash, amount, tweak, k, block_height, parent_coin_id, detected_at, label) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                coin_id.as_slice(),
                puzzle_hash.as_slice(),
                amount as i64,
                tweak.as_slice(),
                k,
                block_height,
                parent_coin_id.as_slice(),
                now,
                label,
            ],
        )?;
        Ok(())
    }

    /// Mark a coin as spent at the given block height.
    pub fn mark_coin_spent(&self, coin_id: &[u8; 32], spent_height: u32) -> Result<(), Box<dyn std::error::Error>> {
        self.conn.execute(
            "UPDATE detected_coins SET spent_height=?1 WHERE coin_id=?2 AND spent_height IS NULL",
            params![spent_height, coin_id.as_slice()],
        )?;
        Ok(())
    }

    /// Get the balance as (unspent_total, spent_total).
    pub fn get_balance(&self) -> Result<(u64, u64), Box<dyn std::error::Error>> {
        let unspent: i64 = self.conn.query_row(
            "SELECT COALESCE(SUM(amount), 0) FROM detected_coins WHERE spent_height IS NULL",
            [], |row| row.get(0),
        )?;
        let spent: i64 = self.conn.query_row(
            "SELECT COALESCE(SUM(amount), 0) FROM detected_coins WHERE spent_height IS NOT NULL",
            [], |row| row.get(0),
        )?;
        Ok((unspent as u64, spent as u64))
    }

    /// Get coin IDs of all unspent detected coins.
    pub fn get_unspent_coin_ids(&self) -> Result<Vec<[u8; 32]>, Box<dyn std::error::Error>> {
        let mut stmt = self.conn.prepare(
            "SELECT coin_id FROM detected_coins WHERE spent_height IS NULL"
        )?;
        let rows = stmt.query_map([], |row| {
            let id: Vec<u8> = row.get(0)?;
            Ok(id)
        })?;
        let mut ids = Vec::new();
        for row in rows {
            let id_vec = row?;
            let id: [u8; 32] = id_vec.as_slice().try_into()?;
            ids.push(id);
        }
        Ok(ids)
    }

    /// Update the last scanned block height.
    pub fn update_last_scanned_height(&self, height: u32) -> Result<(), Box<dyn std::error::Error>> {
        self.conn.execute(
            "UPDATE sync_state SET value=?1 WHERE key='last_scanned_height'",
            params![height.to_string()],
        )?;
        Ok(())
    }

    /// Get the last scanned block height. Returns 0 for a fresh database.
    pub fn get_last_scanned_height(&self) -> Result<u32, Box<dyn std::error::Error>> {
        let height: String = self.conn.query_row(
            "SELECT value FROM sync_state WHERE key='last_scanned_height'",
            [],
            |row| row.get(0),
        )?;
        Ok(height.parse::<u32>()?)
    }

    /// List all detected coins ordered by block height.
    pub fn list_detected_coins(&self) -> Result<Vec<DetectedCoinRecord>, Box<dyn std::error::Error>> {
        let mut stmt = self.conn.prepare(
            "SELECT coin_id, puzzle_hash, amount, block_height, detected_at, spent_height, label, tweak, k FROM detected_coins ORDER BY block_height"
        )?;
        let rows = stmt.query_map([], |row| {
            let coin_id_vec: Vec<u8> = row.get(0)?;
            let puzzle_hash_vec: Vec<u8> = row.get(1)?;
            let amount: i64 = row.get(2)?;
            let block_height: u32 = row.get(3)?;
            let detected_at: i64 = row.get(4)?;
            let spent_height: Option<u32> = row.get(5)?;
            let label: Option<u32> = row.get(6)?;
            let tweak_vec: Vec<u8> = row.get(7)?;
            let k: u32 = row.get(8)?;
            Ok(DetectedCoinRecord {
                coin_id: coin_id_vec.as_slice().try_into().unwrap(),
                puzzle_hash: puzzle_hash_vec.as_slice().try_into().unwrap(),
                amount: amount as u64,
                tweak: tweak_vec.as_slice().try_into().unwrap(),
                k,
                block_height,
                detected_at,
                spent_height,
                label,
            })
        })?;
        let mut coins = Vec::new();
        for row in rows {
            coins.push(row?);
        }
        Ok(coins)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_open_creates_tables() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let store = CoinStore::open(tmp.path()).unwrap();
        assert_eq!(store.get_last_scanned_height().unwrap(), 0);
    }

    #[test]
    fn test_store_and_list() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let store = CoinStore::open(tmp.path()).unwrap();

        let coin_id = [1u8; 32];
        let puzzle_hash = [2u8; 32];
        let tweak = [3u8; 32];
        let parent_coin_id = [4u8; 32];
        let amount = 1000u64;
        let block_height = 100u32;

        store
            .store_detected_coin(&coin_id, &puzzle_hash, amount, &tweak, 0, block_height, &parent_coin_id, None)
            .unwrap();

        let coins = store.list_detected_coins().unwrap();
        assert_eq!(coins.len(), 1);
        assert_eq!(coins[0].coin_id, coin_id);
        assert_eq!(coins[0].puzzle_hash, puzzle_hash);
        assert_eq!(coins[0].amount, amount);
        assert_eq!(coins[0].block_height, block_height);
        assert!(coins[0].detected_at > 0);
        assert_eq!(coins[0].tweak, tweak);
        assert_eq!(coins[0].k, 0);
    }

    #[test]
    fn test_store_keeps_tweak_and_k() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let store = CoinStore::open(tmp.path()).unwrap();

        store
            .store_detected_coin(&[1u8; 32], &[2u8; 32], 10, &[0xabu8; 32], 7, 100, &[4u8; 32], Some(0))
            .unwrap();

        let coins = store.list_detected_coins().unwrap();
        assert_eq!(coins.len(), 1);
        assert_eq!(coins[0].tweak, [0xabu8; 32]);
        assert_eq!(coins[0].k, 7);
        assert_eq!(coins[0].label, Some(0));
    }

    #[test]
    fn test_schema_has_no_secret_key_column() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let store = CoinStore::open(tmp.path()).unwrap();
        let columns: Vec<String> = store.conn
            .prepare("PRAGMA table_info(detected_coins)").unwrap()
            .query_map([], |row| row.get::<_, String>(1)).unwrap()
            .map(|r| r.unwrap())
            .collect();
        assert_eq!(
            columns,
            [
                "coin_id", "puzzle_hash", "amount", "tweak", "k", "block_height",
                "parent_coin_id", "detected_at", "spent_height", "label",
            ]
        );
    }

    #[test]
    fn test_open_rejects_old_schema_with_secret_keys() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        {
            let conn = Connection::open(tmp.path()).unwrap();
            conn.execute_batch("
                CREATE TABLE detected_coins (
                    coin_id BLOB PRIMARY KEY,
                    puzzle_hash BLOB NOT NULL,
                    amount INTEGER NOT NULL,
                    onetime_sk BLOB NOT NULL,
                    block_height INTEGER NOT NULL,
                    parent_coin_id BLOB NOT NULL,
                    detected_at INTEGER NOT NULL,
                    spent_height INTEGER DEFAULT NULL,
                    label INTEGER DEFAULT NULL
                );
            ").unwrap();
        }
        let err = match CoinStore::open(tmp.path()) {
            Ok(_) => panic!("old-schema database must be rejected"),
            Err(e) => e.to_string(),
        };
        assert!(err.contains("old schema"), "unexpected error: {err}");
    }

    #[test]
    fn test_duplicate_ignored() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let store = CoinStore::open(tmp.path()).unwrap();

        let coin_id = [5u8; 32];
        let puzzle_hash = [6u8; 32];
        let tweak = [7u8; 32];
        let parent_coin_id = [8u8; 32];

        store
            .store_detected_coin(&coin_id, &puzzle_hash, 500, &tweak, 0, 50, &parent_coin_id, None)
            .unwrap();
        // Insert same coin_id again -- should be silently ignored
        store
            .store_detected_coin(&coin_id, &puzzle_hash, 999, &tweak, 0, 51, &parent_coin_id, None)
            .unwrap();

        let coins = store.list_detected_coins().unwrap();
        assert_eq!(coins.len(), 1, "duplicate coin_id should be ignored");
        assert_eq!(coins[0].amount, 500, "original amount should be preserved");
    }

    #[test]
    fn test_sync_state_update() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let store = CoinStore::open(tmp.path()).unwrap();

        assert_eq!(store.get_last_scanned_height().unwrap(), 0);
        store.update_last_scanned_height(500).unwrap();
        assert_eq!(store.get_last_scanned_height().unwrap(), 500);
    }

    #[test]
    fn test_sync_state_persistence() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();

        // Open, update height, then drop the store
        {
            let store = CoinStore::open(&path).unwrap();
            store.update_last_scanned_height(42).unwrap();
        }

        // Re-open and verify height persisted
        let store = CoinStore::open(&path).unwrap();
        assert_eq!(store.get_last_scanned_height().unwrap(), 42);
    }

    #[test]
    fn test_reopen_existing_database() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();

        // Open and close (creates schema)
        {
            let _store = CoinStore::open(&path).unwrap();
        }

        // Re-open (schema check should pass)
        let store = CoinStore::open(&path).unwrap();
        assert_eq!(store.get_last_scanned_height().unwrap(), 0);
    }

    #[test]
    fn test_store_with_label() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let store = CoinStore::open(tmp.path()).unwrap();

        let coin_id = [10u8; 32];
        let puzzle_hash = [11u8; 32];
        let tweak = [12u8; 32];
        let parent_coin_id = [13u8; 32];

        store.store_detected_coin(&coin_id, &puzzle_hash, 5000, &tweak, 0, 100, &parent_coin_id, Some(1)).unwrap();

        let coins = store.list_detected_coins().unwrap();
        assert_eq!(coins.len(), 1);
        assert_eq!(coins[0].label, Some(1));
    }

    #[test]
    fn test_mark_coin_spent() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let store = CoinStore::open(tmp.path()).unwrap();

        let coin_id = [20u8; 32];
        let puzzle_hash = [21u8; 32];
        let tweak = [22u8; 32];
        let parent_coin_id = [23u8; 32];

        store.store_detected_coin(&coin_id, &puzzle_hash, 3000, &tweak, 0, 100, &parent_coin_id, None).unwrap();

        // Initially unspent
        let coins = store.list_detected_coins().unwrap();
        assert_eq!(coins[0].spent_height, None);

        // Mark spent
        store.mark_coin_spent(&coin_id, 200).unwrap();

        let coins = store.list_detected_coins().unwrap();
        assert_eq!(coins[0].spent_height, Some(200));
    }

    #[test]
    fn test_get_balance() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let store = CoinStore::open(tmp.path()).unwrap();

        // Store 3 coins: 1000, 2000, 3000
        store.store_detected_coin(&[30u8; 32], &[31u8; 32], 1000, &[32u8; 32], 0, 100, &[33u8; 32], None).unwrap();
        store.store_detected_coin(&[34u8; 32], &[35u8; 32], 2000, &[36u8; 32], 0, 101, &[37u8; 32], None).unwrap();
        store.store_detected_coin(&[38u8; 32], &[39u8; 32], 3000, &[40u8; 32], 0, 102, &[41u8; 32], None).unwrap();

        // All unspent
        let (unspent, spent) = store.get_balance().unwrap();
        assert_eq!(unspent, 6000);
        assert_eq!(spent, 0);

        // Mark first coin spent
        store.mark_coin_spent(&[30u8; 32], 200).unwrap();
        let (unspent, spent) = store.get_balance().unwrap();
        assert_eq!(unspent, 5000);
        assert_eq!(spent, 1000);
    }

    #[test]
    fn test_get_unspent_coin_ids() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let store = CoinStore::open(tmp.path()).unwrap();

        let coin_id_1 = [50u8; 32];
        let coin_id_2 = [51u8; 32];

        store.store_detected_coin(&coin_id_1, &[52u8; 32], 1000, &[53u8; 32], 0, 100, &[54u8; 32], None).unwrap();
        store.store_detected_coin(&coin_id_2, &[55u8; 32], 2000, &[56u8; 32], 0, 101, &[57u8; 32], None).unwrap();

        // Both unspent
        let ids = store.get_unspent_coin_ids().unwrap();
        assert_eq!(ids.len(), 2);

        // Mark first spent
        store.mark_coin_spent(&coin_id_1, 200).unwrap();

        let ids = store.get_unspent_coin_ids().unwrap();
        assert_eq!(ids.len(), 1);
        assert_eq!(ids[0], coin_id_2);
    }
}
