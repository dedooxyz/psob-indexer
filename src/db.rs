//! Storage layer — an embedded Redb KV store with an in-memory L1 cache.
//!
//! # What is stored
//!
//! Every aux block is stored **with its full wire payload** (80-byte header +
//! CAuxPow, `wire_hex`) so it remains self-verifiable *after* the indexer
//! hands it to a client — the indexer is an untrusted caching and discovery
//! layer, never the trust root. The parsed [`common::BlockHeader`] is kept
//! alongside for fast in-process queries.
//!
//! # Layout
//!
//! | Table             | Key                                  | Value         |
//! |-------------------|--------------------------------------|---------------|
//! | `aux_blocks`      | `(chain_id, height)`                 | StoredBlock   |
//! | `parent_blocks`   | `[u8; 32]` (parent hash, LE)         | StoredParent  |
//! | `sibling_index`   | `(parent_hash, chain_id, height)`    | `()`          |
//! | `meta`            | `str`                                | `str`         |
//!
//! The `sibling_index` key order makes the "all blocks under one parent hash"
//! query a range scan — the same ordering the index keeps in memory.
//!
//! # Cache
//!
//! A [`DashMap`] L1 mirrors the tables so hot queries stay µs-fast. The cache
//! is keyed identically to Redb and warmed from disk at open (the indexer's
//! working set is bounded by the ingestion window, not by full-chain history —
//! deep history can be pruned via [`Database::rollback_from`]).
//!
//! `bincode` is used for value serialization (compact, deterministic for the
//! fixed fields we store). The [`SCHEMA_VERSION`] gate protects against
//! loading a database written by an incompatible code version.

use anyhow::Context;
use dashmap::DashMap;
use redb::{Database as RedbDb, ReadableTable, ReadableTableMetadata, TableDefinition};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Arc;

use common::BlockHeader;

/// Bump whenever the on-disk record layout changes. On a mismatch the DB is
/// refuse-to-open (it is a disposable cache — delete and re-ingest).
pub const SCHEMA_VERSION: u32 = 2;

const META_SCHEMA_VERSION: &str = "schema_version";

const TABLE_AUX_BLOCKS: TableDefinition<(u32, u64), &[u8]> = TableDefinition::new("aux_blocks");
const TABLE_PARENT_BLOCKS: TableDefinition<&[u8; 32], &[u8]> =
    TableDefinition::new("parent_blocks");
const TABLE_SIBLING_INDEX: TableDefinition<(&[u8; 32], u32, u64), ()> =
    TableDefinition::new("sibling_index");
const TABLE_META: TableDefinition<&str, &str> = TableDefinition::new("meta");

/// A raw stored aux-chain record. `wire_hex` is the full 80-byte header +
/// CAuxPow payload (self-verifiable); the parsed `header` is derived from the
/// same bytes at ingest time.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredBlock {
    pub hash_le: [u8; 32],
    pub chain_id: u32,
    pub height: u64,
    pub header: BlockHeader,
    /// Full wire payload: `header.raw` ‖ CAuxPow, hex-encoded.
    pub wire_hex: String,
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

/// Pagination window — the default max page size is 100; offsets are view
/// positions, not database cursors (the working set fits in the L1 cache).
#[derive(Debug, Clone, Copy)]
pub struct Page {
    pub limit: usize,
    pub offset: usize,
}

impl Default for Page {
    fn default() -> Self {
        Self {
            limit: 20,
            offset: 0,
        }
    }
}

impl Page {
    pub fn new(limit: Option<usize>, offset: Option<usize>) -> Self {
        Self {
            limit: limit.unwrap_or(20).clamp(1, 200),
            offset: offset.unwrap_or(0),
        }
    }
}

/// Canonical key of a stored aux block.
type BlockKey = (u32, u64);

/// A block row to prune: its key plus the parent hash of its auxpow (if any)
/// so the sibling index can be cleaned up in the same transaction.
type PruneRow = (BlockKey, Option<[u8; 32]>);

/// One row of an epoch query: `(chain_id, aux_height, ltc_height, hash_le)`.
pub type EpochRow = (u32, u64, u64, [u8; 32]);

/// Summary counters for the `/stats` endpoint.
#[derive(Debug, Clone, Serialize)]
pub struct Stats {
    pub total_blocks: u64,
    pub total_parents: usize,
    pub sibling_groups: usize,
    pub chains: Vec<ChainStats>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ChainStats {
    pub chain_id: u32,
    pub blocks: u64,
    pub min_height: Option<u64>,
    pub max_height: Option<u64>,
}

#[derive(Debug)]
pub struct Database {
    redb: Arc<RedbDb>,
    // L1 in-memory caches for µs-scale hot queries.
    cache_blocks: DashMap<(u32, u64), StoredBlock>,
    cache_parents: DashMap<[u8; 32], StoredParent>,
    cache_siblings: DashMap<[u8; 32], Vec<StoredBlock>>,
    cache_meta: DashMap<String, String>,
}

impl Database {
    pub fn open(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let redb = RedbDb::create(path).context("open/create redb storage")?;

        let write_txn = redb.begin_write().context("begin init write txn")?;
        {
            let _ = write_txn
                .open_table(TABLE_AUX_BLOCKS)
                .context("open aux_blocks")?;
            let _ = write_txn
                .open_table(TABLE_PARENT_BLOCKS)
                .context("open parent_blocks")?;
            let _ = write_txn
                .open_table(TABLE_SIBLING_INDEX)
                .context("open sibling_index")?;
            let _ = write_txn.open_table(TABLE_META).context("open meta")?;
        }
        // Schema gate BEFORE any read: refuse to half-load an incompatible DB.
        {
            let mut table_meta = write_txn
                .open_table(TABLE_META)
                .context("open meta (gate)")?;
            let current: Option<u32> = table_meta
                .get(META_SCHEMA_VERSION)?
                .and_then(|v| v.value().parse::<u32>().ok());
            match current {
                Some(v) if v == SCHEMA_VERSION => {}
                Some(v) => anyhow::bail!(
                    "database schema v{v} is incompatible with this indexer (needs v{SCHEMA_VERSION}): \
                     delete the db file and re-ingest",
                ),
                None => {
                    // Fresh database.
                    table_meta.insert(META_SCHEMA_VERSION, SCHEMA_VERSION.to_string().as_str())?;
                }
            }
        }
        write_txn.commit().context("commit init")?;

        let db = Self {
            redb: Arc::new(redb),
            cache_blocks: DashMap::new(),
            cache_parents: DashMap::new(),
            cache_siblings: DashMap::new(),
            cache_meta: DashMap::new(),
        };
        db.warm_up_cache().context("warm up ram cache")?;
        Ok(db)
    }

    /// Load the full working set into the L1 cache.
    fn warm_up_cache(&self) -> anyhow::Result<()> {
        let read_txn = self.redb.begin_read().context("warmup read txn")?;

        if let Ok(table) = read_txn.open_table(TABLE_META) {
            for row in table.iter()? {
                let (k, v) = row?;
                self.cache_meta
                    .insert(k.value().to_string(), v.value().to_string());
            }
        }

        if let Ok(table) = read_txn.open_table(TABLE_PARENT_BLOCKS) {
            for row in table.iter()? {
                let (k, v) = row?;
                if let Ok(parent) = bincode::deserialize::<StoredParent>(v.value()) {
                    self.cache_parents.insert(*k.value(), parent);
                }
            }
        }

        if let Ok(table) = read_txn.open_table(TABLE_AUX_BLOCKS) {
            for row in table.iter()? {
                let (k, v) = row?;
                if let Ok(block) = bincode::deserialize::<StoredBlock>(v.value()) {
                    let key = k.value();
                    self.cache_blocks.insert(key, block.clone());
                    if let Some(aux) = &block.header.aux {
                        let parent_hash = sha256d(&aux.parent_header);
                        let mut list = self.cache_siblings.entry(parent_hash).or_default();
                        if !list
                            .iter()
                            .any(|b| b.chain_id == block.chain_id && b.height == block.height)
                        {
                            list.push(block);
                        }
                    }
                }
            }
        }

        Ok(())
    }

    // ─── metadata ────────────────────────────────────────────────────────────

    pub fn upsert_chain(&self, chain_id: u32, name: &str, electrs: &str) -> anyhow::Result<()> {
        let key = format!("chain.{chain_id}");
        let val = format!("{name}|{electrs}");
        self.set_meta(&key, &val)
    }

    pub fn chain_registry(&self) -> Vec<(u32, String, String)> {
        self.cache_meta
            .iter()
            .filter_map(|e| {
                let key = e.key();
                if let Some(id) = key.strip_prefix("chain.") {
                    let id = id.parse::<u32>().ok()?;
                    let v = e.value().as_str();
                    let (name, url) = v.split_once('|').unwrap_or((v, ""));
                    Some((id, name.to_string(), url.to_string()))
                } else {
                    None
                }
            })
            .collect()
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

    // ─── aux blocks ──────────────────────────────────────────────────────────

    pub fn block_at(&self, chain_id: u32, height: u64) -> anyhow::Result<Option<StoredBlock>> {
        if let Some(b) = self.cache_blocks.get(&(chain_id, height)) {
            return Ok(Some(b.clone()));
        }
        let read_txn = self.redb.begin_read()?;
        let table = read_txn.open_table(TABLE_AUX_BLOCKS)?;
        if let Some(val) = table.get((chain_id, height))? {
            let block: StoredBlock =
                bincode::deserialize(val.value()).context("decode stored block")?;
            self.cache_blocks.insert((chain_id, height), block.clone());
            return Ok(Some(block));
        }
        Ok(None)
    }

    /// Range query over one chain: `[from, to]` heights, paged.
    pub fn blocks_range(
        &self,
        chain_id: u32,
        from: u64,
        to: u64,
        page: Page,
    ) -> anyhow::Result<Vec<StoredBlock>> {
        if from > to {
            return Ok(Vec::new());
        }
        let read_txn = self.redb.begin_read()?;
        let table = read_txn.open_table(TABLE_AUX_BLOCKS)?;
        let mut out = Vec::new();
        // Redb range over the (chain_id, height) composite key — the index order
        // makes this a seek, not a full scan.
        let it = table.range((chain_id, from)..=(chain_id, to))?;
        let mut skipped = 0usize;
        for item in it {
            if out.len() >= page.limit {
                break;
            }
            if skipped < page.offset {
                skipped += 1;
                continue;
            }
            let (_, v) = item?;
            if let Ok(block) = bincode::deserialize::<StoredBlock>(v.value()) {
                out.push(block);
            }
        }
        Ok(out)
    }

    /// Count of stored blocks for one chain (range-derived, cache-consistent).
    pub fn chain_block_count(&self, chain_id: u32) -> anyhow::Result<u64> {
        let mut count = 0u64;
        let read_txn = self.redb.begin_read()?;
        if let Ok(table) = read_txn.open_table(TABLE_AUX_BLOCKS) {
            for item in table.range((chain_id, 0)..=(chain_id, u64::MAX))? {
                let _ = item?;
                count += 1;
            }
        }
        Ok(count)
    }

    pub fn total_blocks(&self) -> anyhow::Result<u64> {
        let read_txn = self.redb.begin_read()?;
        if let Ok(table) = read_txn.open_table(TABLE_AUX_BLOCKS) {
            return Ok(table.len()?);
        }
        Ok(0)
    }

    /// Insert a batch of verified blocks in one write transaction.
    pub fn insert_blocks(&self, blocks: &[(u32, u64, StoredBlock)]) -> anyhow::Result<()> {
        if blocks.is_empty() {
            return Ok(());
        }
        for (chain_id, height, block) in blocks {
            self.cache_blocks
                .insert((*chain_id, *height), block.clone());
        }

        let write_txn = self.redb.begin_write()?;
        {
            let mut table_blocks = write_txn.open_table(TABLE_AUX_BLOCKS)?;
            let mut table_siblings = write_txn.open_table(TABLE_SIBLING_INDEX)?;
            for (chain_id, height, block) in blocks {
                let (chain_id, height) = (*chain_id, *height);
                let encoded = bincode::serialize(block).context("serialize block")?;
                table_blocks.insert((chain_id, height), encoded.as_slice())?;

                let parent_hash = block
                    .header
                    .aux
                    .as_ref()
                    .map(|a| sha256d(&a.parent_header))
                    .ok_or_else(|| {
                        anyhow::anyhow!("block {chain_id}@{height} has no auxpow witness")
                    })?;
                table_siblings.insert((&parent_hash, chain_id, height), ())?;
            }
        }
        write_txn.commit()?;

        // Memory sibling index + parent cache (after durable-commit success).
        for (chain_id, height, block) in blocks {
            let Some(aux) = &block.header.aux else {
                continue;
            };
            let parent_hash = sha256d(&aux.parent_header);
            {
                let mut list = self.cache_siblings.entry(parent_hash).or_default();
                if !list
                    .iter()
                    .any(|b| b.chain_id == *chain_id && b.height == *height)
                {
                    list.push(block.clone());
                }
            }
            if !self.cache_parents.contains_key(&parent_hash) {
                let work = {
                    let bits = u32::from_le_bytes([
                        aux.parent_header[72],
                        aux.parent_header[73],
                        aux.parent_header[74],
                        aux.parent_header[75],
                    ]);
                    common::block_work(&common::expand_target(bits).unwrap_or([0xff; 32]))
                };
                self.cache_parents.insert(
                    parent_hash,
                    StoredParent {
                        parent_hash_le: parent_hash,
                        parent_header: aux.parent_header.clone(),
                        ltc_height: None,
                        parent_state: 0,
                        work,
                    },
                );
            }
        }
        Ok(())
    }

    /// Single-block insert convenience (tests, small batches).
    pub fn insert_block(
        &self,
        chain_id: u32,
        height: u64,
        block: &StoredBlock,
    ) -> anyhow::Result<()> {
        self.insert_blocks(&[(chain_id, height, block.clone())])
    }

    /// Roll back every block of `chain_id` at height >= `from_height`, for both
    /// the durable store and the caches. Returns the number of blocks removed.
    pub fn rollback_from(&self, chain_id: u32, from_height: u64) -> anyhow::Result<u64> {
        let mut count = 0u64;

        // Disk: range-delete (redb tables do not expose ranged deletes).
        {
            let write_txn = self.redb.begin_write()?;
            {
                let mut table_blocks = write_txn.open_table(TABLE_AUX_BLOCKS)?;
                let keys: Vec<(u32, u64)> = table_blocks
                    .range((chain_id, from_height)..=(chain_id, u64::MAX))?
                    .map(|item| item.map(|(k, _)| (k.value().0, k.value().1)))
                    .collect::<redb::Result<Vec<_>>>()?;
                for k in keys {
                    table_blocks.remove(k)?;
                    count += 1;
                }

                let mut table_siblings = write_txn.open_table(TABLE_SIBLING_INDEX)?;
                // Range is per-parent; walk only parents that may contain this chain.
                let parents: Vec<[u8; 32]> = self.cache_parents.iter().map(|e| *e.key()).collect();
                for p in parents {
                    let keys: Vec<(u32, u64)> = table_siblings
                        .range((&p, chain_id, from_height)..=(&p, chain_id, u64::MAX))?
                        .map(|item| item.map(|(k, _)| (k.value().1, k.value().2)))
                        .collect::<redb::Result<Vec<_>>>()?;
                    for (c, h) in keys {
                        table_siblings.remove((&p, c, h))?;
                    }
                }
            }
            write_txn.commit()?;
        }

        // Memory. Collect keys first — DashMap iterators and removes cannot
        // interleave (iterating holds the shard lock; removing re-enters it).
        let mut to_remove: Vec<(BlockKey, Option<[u8; 32]>)> = self
            .cache_blocks
            .iter()
            .filter(|entry| entry.key().0 == chain_id && entry.key().1 >= from_height)
            .map(|entry| {
                let key = *entry.key();
                let parent_hash = entry
                    .value()
                    .header
                    .aux
                    .as_ref()
                    .map(|a| sha256d(&a.parent_header));
                (key, parent_hash)
            })
            .collect();
        to_remove.sort_by_key(|(k, _)| *k);
        let mut removed_parents: Vec<[u8; 32]> = to_remove.iter().filter_map(|(_, p)| *p).collect();
        removed_parents.sort();
        removed_parents.dedup();
        for ((c, h), _) in to_remove {
            self.cache_blocks.remove(&(c, h));
        }
        for ph in removed_parents {
            if let Some(mut list) = self.cache_siblings.get_mut(&ph) {
                list.retain(|b| !(b.chain_id == chain_id && b.height >= from_height));
            }
        }

        let cursor_key = format!("{chain_id}.cursor_height");
        if let Some(h) = self.get_meta(&cursor_key)? {
            if let Ok(hh) = h.parse::<u64>() {
                if hh >= from_height {
                    self.set_meta(&cursor_key, &from_height.saturating_sub(1).to_string())?;
                }
            }
        }

        Ok(count)
    }

    // ─── pruning ─────────────────────────────────────────────────────────────

    /// Remove every block of `chain_id` with height < `below` (and its sibling
    /// index entries). Returns the number of blocks removed. The cursor is
    /// untouched; only old data drops away (bounded-window deployments).
    pub fn prune_before(&self, chain_id: u32, below: u64) -> anyhow::Result<u64> {
        let count = {
            let write_txn = self.redb.begin_write()?;
            let n = {
                let mut table_blocks = write_txn.open_table(TABLE_AUX_BLOCKS)?;
                let mut table_siblings = write_txn.open_table(TABLE_SIBLING_INDEX)?;

                let removals: Vec<PruneRow> = table_blocks
                    .range((chain_id, 0)..=(chain_id, below.saturating_sub(1)))?
                    .map(|item| {
                        let (k, v) = item?;
                        let key = (k.value().0, k.value().1);
                        let parent = bincode::deserialize::<StoredBlock>(v.value())
                            .ok()
                            .and_then(|b| b.header.aux.map(|a| sha256d(&a.parent_header)));
                        Ok((key, parent))
                    })
                    .collect::<redb::Result<Vec<_>>>()?;

                for ((c, h), parent) in &removals {
                    table_blocks.remove((*c, *h))?;
                    if let Some(p) = parent {
                        table_siblings.remove((p, *c, *h))?;
                    }
                }
                removals.len() as u64
            };
            write_txn.commit()?;
            n
        };

        // Memory: collect first, then mutate (DashMap iter/remove don't mix).
        let mut parents_to_refresh: Vec<[u8; 32]> = Vec::new();
        let keys: Vec<(u32, u64)> = self
            .cache_blocks
            .iter()
            .filter(|entry| entry.key().0 == chain_id && entry.key().1 < below)
            .map(|entry| {
                if let Some(aux) = &entry.value().header.aux {
                    let p = sha256d(&aux.parent_header);
                    if !parents_to_refresh.contains(&p) {
                        parents_to_refresh.push(p);
                    }
                }
                *entry.key()
            })
            .collect();
        for k in keys {
            self.cache_blocks.remove(&k);
        }
        for p in parents_to_refresh {
            if let Some(mut list) = self.cache_siblings.get_mut(&p) {
                list.retain(|b| !(b.chain_id == chain_id && b.height < below));
            }
        }
        Ok(count)
    }

    // ─── parents & siblings ──────────────────────────────────────────────────

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

    /// Record our resolve of the parent: 1 = mainnet (with height), 2 = trial.
    pub fn classify_parent(
        &self,
        parent_hash_le: &[u8; 32],
        ltc_height: Option<u64>,
    ) -> anyhow::Result<()> {
        let parent_state = if ltc_height.is_some() { 1 } else { 2 };
        if let Some(mut p) = self.cache_parents.get_mut(parent_hash_le) {
            p.ltc_height = ltc_height;
            p.parent_state = parent_state;
        }

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

    /// Parents whose mainnet/trial state is still 0 (unknown).
    pub fn unclassified_parents(&self) -> Vec<[u8; 32]> {
        self.cache_parents
            .iter()
            .filter(|e| e.value().parent_state == 0)
            .map(|e| *e.key())
            .collect()
    }

    /// All aux blocks stored under one parent hash — a range seek on the
    /// `sibling_index` (cached L1 first for hot paths).
    pub fn siblings_for_parent(
        &self,
        parent_hash_le: &[u8; 32],
    ) -> anyhow::Result<Vec<StoredBlock>> {
        if let Some(list) = self.cache_siblings.get(parent_hash_le) {
            return Ok(list.clone());
        }
        self.sibling_blocks_range(parent_hash_le, Page::default())
            .map(|(blocks, _)| blocks)
    }

    /// Paged range-scan of the sibling index. Returns `(blocks, total_in_range)`.
    pub fn sibling_blocks_range(
        &self,
        parent_hash_le: &[u8; 32],
        page: Page,
    ) -> anyhow::Result<(Vec<StoredBlock>, usize)> {
        let read_txn = self.redb.begin_read()?;
        let table_index = read_txn.open_table(TABLE_SIBLING_INDEX)?;
        let table_blocks = read_txn.open_table(TABLE_AUX_BLOCKS)?;

        let mut total = 0usize;
        let mut out = Vec::new();
        let range = table_index
            .range((parent_hash_le, 0u32, 0u64)..=(parent_hash_le, u32::MAX, u64::MAX))?;
        for item in range {
            let (k, _) = item?;
            let ((_, chain_id, height), _) = (k.value(), ());
            if let Some(val) = table_blocks.get((chain_id, height))? {
                total += 1;
                if total > page.offset && out.len() < page.limit {
                    if let Ok(block) = bincode::deserialize::<StoredBlock>(val.value()) {
                        out.push(block);
                    }
                }
            }
        }
        Ok((out, total))
    }

    /// Every *mainnet* parent shared by at least `min_legs` chains, sorted
    /// (most legs first, then highest LTC height), paged.
    pub fn shared_mainnet_parents(
        &self,
        min_legs: usize,
        page: Page,
        chain_filter: Option<u32>,
    ) -> anyhow::Result<Vec<SharedParent>> {
        let mut out = Vec::new();
        for entry in self.cache_parents.iter() {
            let p = entry.value();
            if let Some(ltc_h) = p.ltc_height {
                if let Some(siblings) = self.cache_siblings.get(entry.key()) {
                    // One leg per distinct chain (lowest height seen); a chain
                    // with two siblings under the same parent is still one leg
                    // of the sibling GROUP.
                    let mut by_chain: std::collections::BTreeMap<u32, u64> =
                        std::collections::BTreeMap::new();
                    for s in siblings.iter() {
                        if let Some(c) = chain_filter {
                            if s.chain_id != c {
                                continue;
                            }
                        }
                        by_chain
                            .entry(s.chain_id)
                            .and_modify(|h| *h = (*h).min(s.height))
                            .or_insert(s.height);
                    }
                    let legs: Vec<(u32, u64)> = by_chain.into_iter().collect();
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
        out.sort_by(|a, b| {
            b.legs
                .len()
                .cmp(&a.legs.len())
                .then_with(|| b.ltc_height.cmp(&a.ltc_height))
        });
        Ok(out.into_iter().skip(page.offset).take(page.limit).collect())
    }

    /// Latest sibling group (highest LTC height with >= min_legs legs).
    pub fn latest_sibling_group(&self, min_legs: usize) -> anyhow::Result<Option<SharedParent>> {
        let mut out = self.shared_mainnet_parents(min_legs, Page::new(Some(1), Some(0)), None)?;
        Ok(out.pop())
    }

    /// All sibling-parent blocks anchored in the LTC height window
    /// `[ltc_start, ltc_end]`, optionally filtered by chain, paged & sorted by
    /// `(ltc_height, chain_id, height)`.
    pub fn epoch_blocks(
        &self,
        ltc_start: u64,
        ltc_end: u64,
        chain_filter: Option<u32>,
        page: Page,
    ) -> anyhow::Result<Vec<EpochRow>> {
        let mut out = Vec::new();
        for entry in self.cache_parents.iter() {
            let p = entry.value();
            if let Some(ltc_h) = p.ltc_height {
                if ltc_h >= ltc_start && ltc_h <= ltc_end {
                    if let Some(siblings) = self.cache_siblings.get(entry.key()) {
                        for s in siblings.iter() {
                            if chain_filter.is_none_or(|c| s.chain_id == c) {
                                out.push((s.chain_id, s.height, ltc_h, s.hash_le));
                            }
                        }
                    }
                }
            }
        }
        out.sort_by_key(|item| (item.2, item.0, item.1));
        Ok(out.into_iter().skip(page.offset).take(page.limit).collect())
    }

    // ─── stats ───────────────────────────────────────────────────────────────

    /// Per-chain block counts + work bounds + top-level totals.
    pub fn stats(&self) -> anyhow::Result<Stats> {
        let mut chains: std::collections::BTreeMap<u32, (u64, Option<u64>, Option<u64>)> =
            std::collections::BTreeMap::new();
        for entry in self.cache_blocks.iter() {
            let (chain_id, height) = *entry.key();
            let e = chains.entry(chain_id).or_insert((0, None, None));
            e.0 += 1;
            e.1 = Some(e.1.map_or(height, |min| min.min(height)));
            e.2 = Some(e.2.map_or(height, |max| max.max(height)));
        }
        let mut siblings = 0usize;
        for entry in self.cache_parents.iter() {
            if entry.value().parent_state == 1 {
                if let Some(s) = self.cache_siblings.get(entry.key()) {
                    let distinct: std::collections::HashSet<u32> =
                        s.iter().map(|b| b.chain_id).collect();
                    if distinct.len() >= 2 {
                        siblings += 1;
                    }
                }
            }
        }
        Ok(Stats {
            total_blocks: self.total_blocks()?,
            total_parents: self.cache_parents.len(),
            sibling_groups: siblings,
            chains: chains
                .into_iter()
                .map(|(chain_id, (blocks, min_height, max_height))| ChainStats {
                    chain_id,
                    blocks,
                    min_height,
                    max_height,
                })
                .collect(),
        })
    }

    // ─── cursor ──────────────────────────────────────────────────────────────

    pub fn cursor_height(&self, chain_id: u32) -> anyhow::Result<Option<u64>> {
        let key = format!("{chain_id}.cursor_height");
        Ok(self.get_meta(&key)?.and_then(|v| v.parse::<u64>().ok()))
    }

    pub fn set_cursor_height(&self, chain_id: u32, height: u64) -> anyhow::Result<()> {
        self.set_meta(&format!("{chain_id}.cursor_height"), &height.to_string())
    }
}

/// sha256d — the block/tx hash of the scrypt/AuxPoW family. Exposed so other
/// crates and tests share one implementation instead of re-inventing it.
pub fn sha256d(data: &[u8]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut out = [0u8; 32];
    out.copy_from_slice(&Sha256::digest(Sha256::digest(data)));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    use common::cauxpow::parse_auxpow;

    const FIXTURE: &str = include_str!("../crates/common/tests/fixtures/jkc_1095600_header.hex");
    const DINGO: u32 = 50;

    fn fixture_block(chain_id: u32, height: u64, mask: u8) -> StoredBlock {
        let wire = hex::decode(FIXTURE.trim()).expect("fixture hex");
        let (base, mut aux) = parse_auxpow(&wire).expect("parses");
        // Make each fixture unique per chain/height: bump the header nonce and
        // chain id so hashes differ (height + mask in the version field).
        let version = u32::from_le_bytes(base[0..4].try_into().unwrap());
        let mut hdr = base;
        hdr[0..4].copy_from_slice(
            &((chain_id << 16) | (version & 0xffff) | (mask as u32)).to_le_bytes(),
        );
        hdr[76..80].copy_from_slice(&(height as u32 ^ mask as u32).to_le_bytes());
        let hash = sha256d(&hdr);
        // Rebuild the chain commitment for the new hash: modify the committed
        // bytes in the coinbase in place (find magic, overwrite root).
        if let Some(pos) = aux
            .coinbase_tx
            .windows(4)
            .position(|w| w == common::AUXPOW_MAGIC)
        {
            let mut rev = hash;
            rev.reverse();
            let start = pos + common::AUXPOW_MAGIC.len();
            aux.coinbase_tx[start..start + 32].copy_from_slice(&rev);
        }
        StoredBlock {
            hash_le: hash,
            chain_id,
            height,
            header: BlockHeader {
                raw: hdr.to_vec(),
                aux: Some(aux.clone()),
            },
            wire_hex: hex::encode(&hdr[..]),
        }
    }

    #[test]
    fn open_writes_schema_version_and_rejects_old() {
        let dir = tempfile_dir();
        let db = Database::open(&dir).expect("fresh db");
        assert_eq!(
            db.get_meta(META_SCHEMA_VERSION).unwrap().as_deref(),
            Some("2")
        );

        // Simulate an older DB by overwriting the version — must refuse to open.
        db.set_meta(META_SCHEMA_VERSION, "1").expect("write");
        drop(db);
        let err = Database::open(&dir).unwrap_err();
        assert!(err.to_string().contains("incompatible"));
    }

    #[test]
    fn sibling_grouping_and_pagination() {
        // One JKC block + one DINGO block under the SAME LTC parent (fixture parent).
        let dir = tempfile_dir();
        let db = Database::open(&dir).expect("open");
        let jkc = fixture_block(8224, 100, 1);
        let dingo = fixture_block(DINGO, 200, 2);
        let jkc2 = fixture_block(8224, 101, 3);

        db.insert_blocks(&[
            (8224, 100, jkc.clone()),
            (DINGO, 200, dingo.clone()),
            (8224, 101, jkc2.clone()),
        ])
        .expect("insert");

        let parent_hash = sha256d(&jkc.header.aux.as_ref().unwrap().parent_header);
        // All three blocks share the fixture's parent.
        assert_eq!(db.siblings_for_parent(&parent_hash).unwrap().len(), 3);

        // Pagination over the sibling list.
        let (page1, total) = db
            .sibling_blocks_range(&parent_hash, Page::new(Some(2), Some(0)))
            .unwrap();
        assert_eq!(page1.len(), 2);
        assert_eq!(total, 3);

        // Range scan by chain + height.
        let range = db.blocks_range(8224, 90, 200, Page::default()).unwrap();
        assert_eq!(range.len(), 2);

        // Mark one chain mainnet → sibling group appears with min_legs=2.
        let ltc_h = 347_000;
        db.classify_parent(&parent_hash, Some(ltc_h))
            .expect("classify");
        let groups = db.shared_mainnet_parents(2, Page::default(), None).unwrap();
        assert_eq!(groups.len(), 1);
        assert_eq!(groups[0].ltc_height, ltc_h);
        assert_eq!(groups[0].legs.len(), 2);

        // Epoch window (LTC heights) is inclusive and filterable by chain.
        let epoch = db
            .epoch_blocks(ltc_h, ltc_h, Some(DINGO), Page::default())
            .unwrap();
        assert_eq!(epoch.len(), 1);
        assert_eq!(epoch[0].0, DINGO);
    }

    #[test]
    fn rollback_removes_blocks_caches_and_cursor() {
        let dir = tempfile_dir();
        let db = Database::open(&dir).expect("open");
        for h in 100..=105 {
            let b = fixture_block(8224, h, 1);
            db.insert_block(8224, h, &b).expect("insert");
        }
        db.set_cursor_height(8224, 105).expect("cursor");
        assert_eq!(db.cursor_height(8224).unwrap(), Some(105));

        let removed = db.rollback_from(8224, 103).expect("rollback");
        assert_eq!(removed, 3);
        assert!(db.block_at(8224, 103).unwrap().is_none());
        assert!(db.block_at(8224, 101).unwrap().is_some());
        // Cursor rewound just below the rollback point.
        assert_eq!(db.cursor_height(8224).unwrap(), Some(102));
    }

    #[test]
    fn stats_are_consistent() {
        let dir = tempfile_dir();
        let db = Database::open(&dir).expect("open");
        db.insert_blocks(&[
            (8224, 1, fixture_block(8224, 1, 1)),
            (8224, 2, fixture_block(8224, 2, 2)),
            (DINGO, 1, fixture_block(DINGO, 1, 3)),
        ])
        .expect("insert");
        let s = db.stats().expect("stats");
        assert_eq!(s.total_blocks, 3);
        assert_eq!(s.chains.len(), 2);
        let jkc = s.chains.iter().find(|c| c.chain_id == 8224).unwrap();
        assert_eq!(jkc.blocks, 2);
        assert_eq!(jkc.min_height, Some(1));
        assert_eq!(jkc.max_height, Some(2));
    }

    #[test]
    fn prune_before_keeps_bounded_window() {
        let dir = tempfile_dir();
        let db = Database::open(&dir).expect("open");
        for h in 100..=105 {
            db.insert_block(8224, h, &fixture_block(8224, h, 1))
                .expect("insert");
        }
        // Window of 3: keep heights >= 103.
        let removed = db.prune_before(8224, 103).expect("prune");
        assert_eq!(removed, 3);
        assert!(db.block_at(8224, 102).unwrap().is_none());
        assert!(db.block_at(8224, 103).unwrap().is_some());
        assert_eq!(db.chain_block_count(8224).unwrap(), 3);
        let stats = db.stats().unwrap();
        let chain = stats.chains.iter().find(|c| c.chain_id == 8224).unwrap();
        assert_eq!(chain.min_height, Some(103));
        assert_eq!(chain.max_height, Some(105));
        // Pruning again is a no-op.
        assert_eq!(db.prune_before(8224, 103).unwrap(), 0);
    }

    fn tempfile_dir() -> std::path::PathBuf {
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let base = std::env::temp_dir();
        let p = base.join(format!("psob-db-test-{}-{}", std::process::id(), n));
        let _ = std::fs::remove_file(&p);
        let _ = std::fs::remove_file(p.with_extension(".redb"));
        p
    }
}
