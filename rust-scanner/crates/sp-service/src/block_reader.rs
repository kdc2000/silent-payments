use chia_protocol::{Bytes32, FullBlock};
use chia_traits::streamable::Streamable;
use rusqlite::{Connection, OpenFlags};
use std::collections::HashMap;
use std::io::Cursor;
use std::path::Path;

pub struct ChiaBlockReader {
    conn: Connection,
}

impl ChiaBlockReader {
    /// Open the Chia full node SQLite database in read-only mode.
    /// Uses SQLITE_OPEN_READ_ONLY | SQLITE_OPEN_NO_MUTEX for WAL safety.
    /// Sets busy_timeout to 5 seconds to avoid blocking the full node.
    pub fn open(db_path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let conn = Connection::open_with_flags(
            db_path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        Ok(Self { conn })
    }

    /// Get the maximum block height in the main chain.
    pub fn get_peak_height(&self) -> Result<Option<u32>, Box<dyn std::error::Error>> {
        let height: Option<u32> = self.conn.query_row(
            "SELECT MAX(height) FROM full_blocks WHERE in_main_chain=1",
            [],
            |row| row.get(0),
        )?;
        Ok(height)
    }

    /// Read a single block by height from the main chain.
    /// Returns None if no block exists at that height.
    /// Decompresses zstd blob and deserializes into FullBlock.
    pub fn read_block(
        &self,
        height: u32,
    ) -> Result<Option<(Bytes32, FullBlock)>, Box<dyn std::error::Error>> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT header_hash, block FROM full_blocks WHERE in_main_chain=1 AND height=?",
        )?;
        let result = stmt.query_row([height], |row| {
            let header_hash: Vec<u8> = row.get(0)?;
            let blob: Vec<u8> = row.get(1)?;
            Ok((header_hash, blob))
        });
        match result {
            Ok((header_hash, blob)) => {
                let decompressed = zstd::stream::decode_all(Cursor::new(&blob))?;
                let block = FullBlock::from_bytes_unchecked(&decompressed)?;
                let hash: Bytes32 = header_hash
                    .as_slice()
                    .try_into()
                    .map_err(|_| "invalid header_hash length")?;
                Ok(Some((hash, block)))
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Iterate main-chain blocks from start_height (inclusive) upward.
    /// Calls the callback with (height, header_hash, FullBlock) for each block.
    /// Decompresses zstd and deserializes each block.
    pub fn iterate_blocks(
        &self,
        start_height: u32,
        mut callback: impl FnMut(u32, Bytes32, FullBlock) -> Result<(), Box<dyn std::error::Error>>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut stmt = self.conn.prepare(
            "SELECT height, header_hash, block FROM full_blocks \
             WHERE in_main_chain=1 AND height >= ? ORDER BY height",
        )?;
        let rows = stmt.query_map([start_height], |row| {
            let height: u32 = row.get(0)?;
            let header_hash: Vec<u8> = row.get(1)?;
            let blob: Vec<u8> = row.get(2)?;
            Ok((height, header_hash, blob))
        })?;

        for row in rows {
            let (height, header_hash, blob) = row?;
            let decompressed = zstd::stream::decode_all(Cursor::new(&blob))?;
            let block = FullBlock::from_bytes_unchecked(&decompressed)?;
            let hash: Bytes32 = header_hash
                .as_slice()
                .try_into()
                .map_err(|_| "invalid header_hash length")?;
            callback(height, hash, block)?;
        }
        Ok(())
    }

    /// Check which coins in the given list have been spent on-chain.
    ///
    /// Queries the `coin_record` table from the Chia full node DB.
    /// Returns a HashMap where:
    /// - Key: coin_name (32 bytes)
    /// - Value: `Some(spent_height)` if spent, `None` if unspent
    ///
    /// Coins not found in the DB are excluded from the result.
    ///
    /// Batches queries in chunks of 500 to stay within SQLite parameter limits.
    pub fn check_coins_spent(
        &self,
        coin_names: &[[u8; 32]],
    ) -> Result<HashMap<[u8; 32], Option<u32>>, Box<dyn std::error::Error>> {
        let mut result = HashMap::new();
        if coin_names.is_empty() {
            return Ok(result);
        }

        for chunk in coin_names.chunks(500) {
            let placeholders: Vec<&str> = chunk.iter().map(|_| "?").collect();
            let sql = format!(
                "SELECT coin_name, spent_index FROM coin_record WHERE coin_name IN ({})",
                placeholders.join(",")
            );
            let mut stmt = self.conn.prepare(&sql)?;
            let params: Vec<&[u8]> = chunk.iter().map(|c| c.as_slice()).collect();
            let rows = stmt.query_map(rusqlite::params_from_iter(params), |row| {
                let name: Vec<u8> = row.get(0)?;
                let spent_index: u32 = row.get(1)?;
                Ok((name, spent_index))
            })?;

            for row in rows {
                let (name, spent_index) = row?;
                if name.len() == 32 {
                    let mut arr = [0u8; 32];
                    arr.copy_from_slice(&name);
                    if spent_index > 0 {
                        result.insert(arr, Some(spent_index));
                    } else {
                        result.insert(arr, None);
                    }
                }
            }
        }

        Ok(result)
    }

    /// Fetch the generator blob for a reference block (used by transactions_generator_ref_list).
    /// Returns the raw transactions_generator bytes for the block at the given height.
    pub fn get_ref_generator(
        &self,
        height: u32,
    ) -> Result<Option<Vec<u8>>, Box<dyn std::error::Error>> {
        let mut stmt = self.conn.prepare_cached(
            "SELECT block FROM full_blocks WHERE in_main_chain=1 AND height=?",
        )?;
        let result = stmt.query_row([height], |row| {
            let blob: Vec<u8> = row.get(0)?;
            Ok(blob)
        });
        match result {
            Ok(blob) => {
                let decompressed = zstd::stream::decode_all(Cursor::new(&blob))?;
                let block = FullBlock::from_bytes_unchecked(&decompressed)?;
                Ok(block.transactions_generator.map(|g| g.to_vec()))
            }
            Err(rusqlite::Error::QueryReturnedNoRows) => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Open the given in-memory connection as a ChiaBlockReader.
    /// This is only used in tests to inject a mock coin_record table.
    #[cfg(test)]
    pub(crate) fn from_connection(conn: Connection) -> Self {
        Self { conn }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn setup_coin_record_db() -> ChiaBlockReader {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE coin_record (
                coin_name BLOB NOT NULL,
                confirmed_index INTEGER,
                spent_index INTEGER,
                coinbase INTEGER,
                puzzle_hash BLOB,
                coin_parent BLOB,
                amount BLOB,
                timestamp INTEGER
            );"
        ).unwrap();

        // Coin A: spent at height 500
        let coin_a = [0xAAu8; 32];
        conn.execute(
            "INSERT INTO coin_record (coin_name, confirmed_index, spent_index, coinbase, puzzle_hash, coin_parent, amount, timestamp)
             VALUES (?1, 100, 500, 0, ?2, ?2, X'00', 0)",
            rusqlite::params![coin_a.as_slice(), [0u8; 32].as_slice()],
        ).unwrap();

        // Coin B: unspent (spent_index=0)
        let coin_b = [0xBBu8; 32];
        conn.execute(
            "INSERT INTO coin_record (coin_name, confirmed_index, spent_index, coinbase, puzzle_hash, coin_parent, amount, timestamp)
             VALUES (?1, 200, 0, 0, ?2, ?2, X'00', 0)",
            rusqlite::params![coin_b.as_slice(), [0u8; 32].as_slice()],
        ).unwrap();

        // Coin C: spent at height 1000
        let coin_c = [0xCCu8; 32];
        conn.execute(
            "INSERT INTO coin_record (coin_name, confirmed_index, spent_index, coinbase, puzzle_hash, coin_parent, amount, timestamp)
             VALUES (?1, 300, 1000, 0, ?2, ?2, X'00', 0)",
            rusqlite::params![coin_c.as_slice(), [0u8; 32].as_slice()],
        ).unwrap();

        ChiaBlockReader::from_connection(conn)
    }

    #[test]
    fn test_check_coins_spent_returns_correct_status() {
        let reader = setup_coin_record_db();
        let coin_a = [0xAAu8; 32];
        let coin_b = [0xBBu8; 32];
        let coin_c = [0xCCu8; 32];

        let result = reader.check_coins_spent(&[coin_a, coin_b, coin_c]).unwrap();
        assert_eq!(result.len(), 3);
        assert_eq!(result[&coin_a], Some(500));
        assert_eq!(result[&coin_b], None); // unspent
        assert_eq!(result[&coin_c], Some(1000));
    }

    #[test]
    fn test_check_coins_spent_empty_list() {
        let reader = setup_coin_record_db();
        let result = reader.check_coins_spent(&[]).unwrap();
        assert!(result.is_empty());
    }

    #[test]
    fn test_check_coins_spent_unknown_coin_not_in_result() {
        let reader = setup_coin_record_db();
        let unknown = [0xFFu8; 32];
        let result = reader.check_coins_spent(&[unknown]).unwrap();
        assert!(!result.contains_key(&unknown));
    }

    #[test]
    fn test_check_coins_spent_batches_correctly() {
        let conn = Connection::open_in_memory().unwrap();
        conn.execute_batch(
            "CREATE TABLE coin_record (
                coin_name BLOB NOT NULL,
                confirmed_index INTEGER,
                spent_index INTEGER,
                coinbase INTEGER,
                puzzle_hash BLOB,
                coin_parent BLOB,
                amount BLOB,
                timestamp INTEGER
            );"
        ).unwrap();

        // Insert 600 coins (more than 500 batch size)
        let mut coins = Vec::new();
        for i in 0u16..600 {
            let mut name = [0u8; 32];
            name[0] = (i >> 8) as u8;
            name[1] = (i & 0xFF) as u8;
            let spent_index = if i % 2 == 0 { i as u32 + 1 } else { 0 };
            conn.execute(
                "INSERT INTO coin_record (coin_name, confirmed_index, spent_index, coinbase, puzzle_hash, coin_parent, amount, timestamp)
                 VALUES (?1, ?2, ?3, 0, ?4, ?4, X'00', 0)",
                rusqlite::params![name.as_slice(), i as u32, spent_index, [0u8; 32].as_slice()],
            ).unwrap();
            coins.push(name);
        }

        let reader = ChiaBlockReader::from_connection(conn);
        let result = reader.check_coins_spent(&coins).unwrap();
        assert_eq!(result.len(), 600);

        // Verify even indices are spent, odd are unspent
        for (i, coin) in coins.iter().enumerate() {
            if i % 2 == 0 {
                assert!(result[coin].is_some(), "coin {} should be spent", i);
            } else {
                assert_eq!(result[coin], None, "coin {} should be unspent", i);
            }
        }
    }
}
