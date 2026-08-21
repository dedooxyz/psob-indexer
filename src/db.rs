//! Hybrid In-Memory (DashMap) & Embedded KV (Redb) Store for PSob Indexer.
//!
//! Provides ultra-low latency (< 5 microseconds) lookups directly from RAM
//! while persisting all block records, sibling indices, and Litecoin parent
//! classifications to an ACID, log-structured Redb database.

use anyhow::Context;
use dashmap::DashMap;
use redb::{Database as RedbDb, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Arc;

use common::BlockHeader;

// Redb Table Definitions
const TABLE_AUX_BLOCKS: TableDefinition<(u32, u64), &[u8]> = TableDefinition::new("aux_blocks");
const TABLE_PARENT_BLOCKS: TableDefinition<&[u8; 32], &[u8]> = TableDefinition::new("parent_blocks");
const TABLE_SIBLING_INDEX: TableDefinition<(&[u8; 32], u32, u64), ()> = TableDefinition::new("sibling_index");
const TABLE_META: TableDefinition<&str, &str> = TableDefinition::new("meta");

/// A raw stored aux-chain record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredBlock {
    pub hash_le: [u8; 32],
    pub chain_id: u32,
    pub height: u64,
    pub header: BlockHeader,
}

/// A parent (Litecoin-real or trial) header we've seen embedded in auxpow.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredParent {
    pub parent_hash_le: [u8; 32],
    pub parent_header: Vec<u8>,
    /// `Some(ltc_height)` iff this parent was confirmed to be a mainnet block.
    /// `None` = trial block.
    pub ltc_height: Option<u64>,
    /// 0 = unprobed, 1 = mainnet, 2 = trial.
    pub parent_state: i64,
    /// Accumulated parent-header work (big-endian U256) for gate heuristics.
    pub work: [u8; 32],
}

/// A Litecoin mainnet parent shared by at least `min_legs` distinct aux
/// chains — a provable cross-chain sibling anchor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SharedParent {
    pub parent_hash_le: [u8; 32],
    pub ltc_height: u64,
    pub legs: Vec<(u32, u64)>, // (chain_id, height) of each sibling block
}

pub struct Database {
    redb: Arc<RedbDb>,
    // L1 In-Memory RAM Caches for sub-microsecond responses
    cache_blocks: DashMap<(u32, u64), StoredBlock>,
    cache_parents: DashMap<[u8; 32], StoredParent>,
    cache_siblings: DashMap<[u8; 32], Vec<StoredBlock>>,
    cache_meta: DashMap<String, String>,
}

impl Database {
    pub fn open(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let redb = RedbDb::create(path).context("open/create redb storage")?;
        
        // Initialize tables in a write transaction
        let write_txn = redb.begin_write().context("begin init write txn")?;
        {
            let _ = write_txn.open_table(TABLE_AUX_BLOCKS).context("open aux_blocks")?;
            let _ = write_txn.open_table(TABLE_PARENT_BLOCKS).context("open parent_blocks")?;
            let _ = write_txn.open_table(TABLE_SIBLING_INDEX).context("open sibling_index")?;
            let _ = write_txn.open_table(TABLE_META).context("open meta")?;
        }
        write_txn.commit().context("commit table init")?;

        let db = Self {
            redb: Arc::new(redb),
            cache_blocks: DashMap::new(),
            cache_parents: DashMap::new(),
            cache_siblings: DashMap::new(),
            cache_meta: DashMap::new(),
        };

        // Preload recent caches from disk
        db.warm_up_cache().context("warm up ram cache")?;
        Ok(db)
    }

    fn warm_up_cache(&self) -> anyhow::Result<()> {
        let read_txn = self.redb.begin_read().context("warmup read txn")?;
        
        // Load metadata
        if let Ok(table) = read_txn.open_table(TABLE_META) {
            for row in table.iter()? {
                let (k, v) = row?;
                self.cache_meta.insert(k.value().to_string(), v.value().to_string());
            }
        }

        // Load parents
        if let Ok(table) = read_txn.open_table(TABLE_PARENT_BLOCKS) {
            for row in table.iter()? {
                let (k, v) = row?;
                if let Ok(parent) = bincode::deserialize::<StoredParent>(v.value()) {
                    self.cache_parents.insert(*k.value(), parent);
                }
            }
        }

        // Load aux blocks
        if let Ok(table) = read_txn.open_table(TABLE_AUX_BLOCKS) {
            for row in table.iter()? {
                let (k, v) = row?;
                if let Ok(block) = bincode::deserialize::<StoredBlock>(v.value()) {
                    let key = k.value();
                    self.cache_blocks.insert(key, block.clone());
                    
                    if let Some(aux) = &block.header.aux {
                        let parent_hash = sha256d(&aux.parent_header);
                        let mut list = self.cache_siblings.entry(parent_hash).or_insert_with(Vec::new);
                        if !list.iter().any(|b| b.chain_id == block.chain_id && b.height == block.height) {
                            list.push(block);
                        }
                    }
                }
            }
        }

        Ok(())
    }

    pub fn upsert_chain(&self, chain_id: u32, name: &str, electrs: &str) -> anyhow::Result<()> {
        let key = format!("chain.{chain_id}");
        let val = format!("{name}|{electrs}");
        self.set_meta(&key, &val)
    }

    pub fn get_meta(&self, key: &str) -> anyhow::Result<Option<String>> {
        if let Some(v) = self.cache_meta.get(key) {
            return Ok(Some(v.clone()));
        }

        let read_txn = self.redb.begin_read()?;
        let table = read_txn.open_table(TABLE_META)?;
        if let Some(val) = table.get(key)? {
            let s = val.value().to_string();
            self.cache_meta.insert(key.to_string(), s.clone());
            return Ok(Some(s));
        }
        Ok(None)
    }

    pub fn set_meta(&self, key: &str, value: &str) -> anyhow::Result<()> {
        self.cache_meta.insert(key.to_string(), value.to_string());
        let write_txn = self.redb.begin_write()?;
        {
            let mut table = write_txn.open_table(TABLE_META)?;
            table.insert(key, value)?;
        }
        write_txn.commit()?;
        Ok(())
    }

    pub fn block_at(&self, chain_id: u32, height: u64) -> anyhow::Result<Option<StoredBlock>> {
        if let Some(b) = self.cache_blocks.get(&(chain_id, height)) {
            return Ok(Some(b.clone()));
        }

        let read_txn = self.redb.begin_read()?;
        let table = read_txn.open_table(TABLE_AUX_BLOCKS)?;
        if let Some(val) = table.get((chain_id, height))? {
            let block: StoredBlock = bincode::deserialize(val.value()).context("decode stored block")?;
            self.cache_blocks.insert((chain_id, height), block.clone());
            return Ok(Some(block));
        }
        Ok(None)
    }

    pub fn rollback_from(&self, chain_id: u32, from_height: u64) -> anyhow::Result<u64> {
        let mut count = 0u64;
        let write_txn = self.redb.begin_write()?;
        {
            let mut table = write_txn.open_table(TABLE_AUX_BLOCKS)?;
            // Remove blocks >= from_height
            let keys_to_remove: Vec<(u32, u64)> = self.cache_blocks
                .iter()
                .filter(|entry| entry.key().0 == chain_id && entry.key().1 >= from_height)
                .map(|entry| *entry.key())
                .collect();

            for k in keys_to_remove {
                self.cache_blocks.remove(&k);
                let _ = table.remove(k);
                count += 1;
            }
        }
        write_txn.commit()?;

        let cursor_key = format!("{chain_id}.cursor_height");
        if let Some(h) = self.get_meta(&cursor_key)? {
            if let Ok(hh) = h.parse::<u64>() {
                if hh >= from_height {
                    self.set_meta(&cursor_key, &(from_height.saturating_sub(1)).to_string())?;
                }
            }
        }

        Ok(count)
    }

    pub fn insert_block(&self, chain_id: u32, height: u64, block: &StoredBlock) -> anyhow::Result<()> {
        let parent_hash = block
            .header
            .aux
            .as_ref()
            .and_then(|a| Some(sha256d(&a.parent_header)))
            .ok_or_else(|| anyhow::anyhow!("missing auxpow for parent hash"))?;

        // 1. Update L1 In-Memory Caches
        self.cache_blocks.insert((chain_id, height), block.clone());
        {
            let mut list = self.cache_siblings.entry(parent_hash).or_insert_with(Vec::new);
            if !list.iter().any(|b| b.chain_id == chain_id && b.height == height) {
                list.push(block.clone());
            }
        }

        let parent_header = block.header.aux.as_ref().unwrap().parent_header.clone();
        let work = {
            let bits = u32::from_le_bytes([
                parent_header[72], parent_header[73], parent_header[74], parent_header[75],
            ]);
            common::block_work(&common::expand_target(bits).unwrap_or([0xff; 32]))
        };

        if !self.cache_parents.contains_key(&parent_hash) {
            let stored_parent = StoredParent {
                parent_hash_le: parent_hash,
                parent_header: parent_header.clone(),
                ltc_height: None,
                parent_state: 0,
                work,
            };
            self.cache_parents.insert(parent_hash, stored_parent);
        }

        // 2. Persist to L2 Redb Storage
        let encoded_block = bincode::serialize(block).context("serialize block")?;
        let parent_obj = self.cache_parents.get(&parent_hash).unwrap().clone();
        let encoded_parent = bincode::serialize(&parent_obj).context("serialize parent")?;

        let write_txn = self.redb.begin_write()?;
        {
            let mut table_blocks = write_txn.open_table(TABLE_AUX_BLOCKS)?;
            table_blocks.insert((chain_id, height), encoded_block.as_slice())?;

            let mut table_parents = write_txn.open_table(TABLE_PARENT_BLOCKS)?;
            table_parents.insert(&parent_hash, encoded_parent.as_slice())?;

            let mut table_siblings = write_txn.open_table(TABLE_SIBLING_INDEX)?;
            table_siblings.insert((&parent_hash, chain_id, height), ())?;
        }
        write_txn.commit()?;

        Ok(())
    }

    pub fn cursor_height(&self, chain_id: u32) -> anyhow::Result<Option<u64>> {
        let key = format!("{chain_id}.cursor_height");
        Ok(self
            .get_meta(&key)?
            .and_then(|v| v.parse::<u64>().ok()))
    }

    pub fn set_cursor_height(&self, chain_id: u32, height: u64) -> anyhow::Result<()> {
        self.set_meta(&format!("{chain_id}.cursor_height"), &height.to_string())
    }

    pub fn classify_parent(
        &self,
        parent_hash_le: &[u8; 32],
        ltc_height: Option<u64>,
    ) -> anyhow::Result<()> {
        let parent_state = if ltc_height.is_some() { 1 } else { 2 };
        
        // Update in-memory cache
        if let Some(mut p) = self.cache_parents.get_mut(parent_hash_le) {
            p.ltc_height = ltc_height;
            p.parent_state = parent_state;
        }

        // Update Redb
        let write_txn = self.redb.begin_write()?;
        {
            let mut table = write_txn.open_table(TABLE_PARENT_BLOCKS)?;
            if let Some(p) = self.cache_parents.get(parent_hash_le) {
                let encoded = bincode::serialize(&*p)?;
                table.insert(parent_hash_le, encoded.as_slice())?;
            }
        }
        write_txn.commit()?;

        Ok(())
    }

    pub fn get_parent(&self, parent_hash_le: &[u8; 32]) -> anyhow::Result<Option<StoredParent>> {
        if let Some(p) = self.cache_parents.get(parent_hash_le) {
            return Ok(Some(p.clone()));
        }

        let read_txn = self.redb.begin_read()?;
        let table = read_txn.open_table(TABLE_PARENT_BLOCKS)?;
        if let Some(val) = table.get(parent_hash_le)? {
            let parent: StoredParent = bincode::deserialize(val.value())?;
            self.cache_parents.insert(*parent_hash_le, parent.clone());
            return Ok(Some(parent));
        }
        Ok(None)
    }

    pub fn unclassified_parents(&self) -> anyhow::Result<Vec<[u8; 32]>> {
        let mut out = Vec::new();
        for entry in self.cache_parents.iter() {
            if entry.value().parent_state == 0 {
                out.push(*entry.key());
            }
        }
        Ok(out)
    }

    pub fn siblings_for_parent(&self, parent_hash_le: &[u8; 32]) -> anyhow::Result<Vec<StoredBlock>> {
        if let Some(list) = self.cache_siblings.get(parent_hash_le) {
            return Ok(list.clone());
        }
        Ok(Vec::new())
    }

    pub fn shared_mainnet_parents(&self, min_legs: usize, max: usize) -> anyhow::Result<Vec<SharedParent>> {
        let mut out = Vec::new();
        for entry in self.cache_parents.iter() {
            let p = entry.value();
            if let Some(ltc_h) = p.ltc_height {
                if let Some(siblings) = self.cache_siblings.get(entry.key()) {
                    let legs: Vec<(u32, u64)> = siblings.iter().map(|s| (s.chain_id, s.height)).collect();
                    if legs.len() >= min_legs {
                        out.push(SharedParent {
                            parent_hash_le: *entry.key(),
                            ltc_height: ltc_h,
                            legs,
                        });
                    }
                }
            }
        }

        // Sort by legs descending, then ltc_height descending
        out.sort_by(|a, b| b.legs.len().cmp(&a.legs.len()).then_with(|| b.ltc_height.cmp(&a.ltc_height)));
        out.truncate(max);
        Ok(out)
    }

    pub fn epoch_blocks(
        &self,
        ltc_start: u64,
        ltc_end: u64,
    ) -> anyhow::Result<Vec<(u32, u64, u64, [u8; 32])>> {
        let mut out = Vec::new();
        for entry in self.cache_parents.iter() {
            let p = entry.value();
            if let Some(ltc_h) = p.ltc_height {
                if ltc_h >= ltc_start && ltc_h <= ltc_end {
                    if let Some(siblings) = self.cache_siblings.get(entry.key()) {
                        for s in siblings.iter() {
                            out.push((s.chain_id, s.height, ltc_h, s.hash_le));
                        }
                    }
                }
            }
        }

        out.sort_by_key(|item| (item.2, item.0, item.1));
        Ok(out)
    }
}

fn sha256d(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut out = [0u8; 32];
    out.copy_from_slice(&Sha256::digest(Sha256::digest(data)));
    out
}