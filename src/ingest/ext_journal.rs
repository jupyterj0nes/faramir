//! What ext4 keeps of a deleted or rewritten file, and how to get it back.
//!
//! When ext4 deletes a file it zeroes the inode's extent tree, so the live
//! inode table leads nowhere. The jbd2 journal, however, holds copies of
//! every metadata block as it was *before* each transaction: inode table
//! blocks (the inode with its size, times and extents intact) and directory
//! blocks (name and inode number). Those copies, crossed with the data
//! blocks that are still free, give back the name, the path, the dates and
//! the content of a deleted file, and the previous content of a rewritten
//! one. It is the ext4 counterpart of a Volume Shadow Copy, and like one it
//! is small and circular, so it covers the last hours or days.
//!
//! Everything here is a bounded, read-only parser over an [`Ext4Read`]:
//! superblock, group descriptors, inodes, extent trees, the journal, and a
//! directory-block heuristic for copies whose owner is not known.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;

use ext4_view::Ext4Read;

use crate::errors::FaramirError;
use crate::windows::diag;

const SUPERBLOCK_OFFSET: u64 = 1024;
const EXT_MAGIC: u16 = 0xEF53;
const EXTENT_MAGIC: u16 = 0xF30A;
const INCOMPAT_64BIT: u32 = 0x80;
const INODE_EXTENTS_FL: u32 = 0x0008_0000;
const INODE_INLINE_DATA_FL: u32 = 0x1000_0000;
const ROOT_INO: u32 = 2;
const JOURNAL_INO_DEFAULT: u32 = 8;

const JBD2_MAGIC: u32 = 0xC03B_3998;
const JBD2_DESCRIPTOR: u32 = 1;
const JBD2_COMMIT: u32 = 2;
const JBD2_SUPERBLOCK_V1: u32 = 3;
const JBD2_SUPERBLOCK_V2: u32 = 4;
const JBD2_REVOKE: u32 = 5;
const JBD2_INCOMPAT_64BIT: u32 = 2;
const JBD2_INCOMPAT_CSUM_V2: u32 = 8;
const JBD2_INCOMPAT_CSUM_V3: u32 = 0x10;
const TAG_ESCAPE: u32 = 1;
const TAG_SAME_UUID: u32 = 2;
const TAG_LAST: u32 = 8;

/// Largest file content recovered (same ceiling as the live extraction).
pub const MAX_RECOVER_BYTES: u64 = 16 << 20;
/// Directories walked when mapping the live tree.
pub const MAX_DIRS: usize = 200_000;
/// Journal size accepted (beyond this the walk is cut, with a diagnostic).
pub const MAX_JOURNAL_BLOCKS: u64 = 1 << 20;

fn u16le(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}
fn u32le(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}
fn u32be(b: &[u8], o: usize) -> u32 {
    u32::from_be_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}
fn u16be(b: &[u8], o: usize) -> u16 {
    u16::from_be_bytes([b[o], b[o + 1]])
}

// ─── geometry ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Geometry {
    pub block_size: u64,
    pub blocks_count: u64,
    pub inodes_count: u32,
    pub blocks_per_group: u32,
    pub inodes_per_group: u32,
    pub inode_size: u16,
    pub first_data_block: u32,
    pub desc_size: u16,
    pub journal_ino: u32,
    pub feature_incompat: u32,
    pub volume_name: String,
}

impl Geometry {
    pub fn parse(sb: &[u8]) -> Result<Self, FaramirError> {
        if sb.len() < 1024 {
            return Err(FaramirError::ExtJournalParseError("superblock shorter than 1024 bytes".into()));
        }
        if u16le(sb, 0x38) != EXT_MAGIC {
            return Err(FaramirError::ExtJournalParseError(format!("bad ext magic {:#06x}", u16le(sb, 0x38))));
        }
        let log = u32le(sb, 0x18);
        if log > 6 {
            return Err(FaramirError::ExtJournalParseError(format!("implausible log block size {log}")));
        }
        let feature_incompat = u32le(sb, 0x60);
        let blocks_lo = u32le(sb, 0x04) as u64;
        let blocks_hi = if feature_incompat & INCOMPAT_64BIT != 0 { u32le(sb, 0x150) as u64 } else { 0 };
        let rev = u32le(sb, 0x4c);
        let inode_size = if rev >= 1 { u16le(sb, 0x58) } else { 128 };
        let desc_size = if feature_incompat & INCOMPAT_64BIT != 0 { u16le(sb, 0xfe).max(32) } else { 32 };
        let g = Geometry {
            block_size: 1024u64 << log,
            blocks_count: blocks_lo | (blocks_hi << 32),
            inodes_count: u32le(sb, 0x00),
            blocks_per_group: u32le(sb, 0x20),
            inodes_per_group: u32le(sb, 0x28),
            inode_size,
            first_data_block: u32le(sb, 0x14),
            desc_size,
            journal_ino: if rev >= 1 { u32le(sb, 0xe0) } else { JOURNAL_INO_DEFAULT },
            feature_incompat,
            volume_name: String::from_utf8_lossy(&sb[0x78..0x88]).trim_end_matches('\0').to_string(),
        };
        if g.blocks_per_group == 0 || g.inodes_per_group == 0 || !(128..=4096).contains(&g.inode_size) || g.blocks_count == 0 {
            return Err(FaramirError::ExtJournalParseError(format!(
                "implausible geometry: {} blocks/group, {} inodes/group, inode size {}, {} blocks",
                g.blocks_per_group, g.inodes_per_group, g.inode_size, g.blocks_count
            )));
        }
        Ok(g)
    }

    pub fn group_count(&self) -> u64 {
        (self.blocks_count - self.first_data_block as u64).div_ceil(self.blocks_per_group as u64)
    }

    /// Blocks an inode table spans.
    pub fn inode_table_blocks(&self) -> u64 {
        (self.inodes_per_group as u64 * self.inode_size as u64).div_ceil(self.block_size)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Group {
    pub block_bitmap: u64,
    pub inode_bitmap: u64,
    pub inode_table: u64,
}

/// The volume as seen through its metadata.
pub struct Volume<'a> {
    reader: &'a mut dyn Ext4Read,
    pub geo: Geometry,
    pub groups: Vec<Group>,
    block_cache: HashMap<u64, Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawInode {
    pub ino: u32,
    pub mode: u16,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    pub atime: u32,
    pub ctime: u32,
    pub mtime: u32,
    pub dtime: u32,
    pub crtime: Option<u32>,
    pub links: u16,
    pub flags: u32,
    pub generation: u32,
    pub block: [u8; 60],
}

impl RawInode {
    pub fn parse(ino: u32, b: &[u8]) -> Option<RawInode> {
        if b.len() < 128 {
            return None;
        }
        let mut block = [0u8; 60];
        block.copy_from_slice(&b[40..100]);
        let extra = if b.len() >= 132 { u16le(b, 128) as usize } else { 0 };
        let crtime = (b.len() >= 148 && extra >= 20).then(|| u32le(b, 144));
        Some(RawInode {
            ino,
            mode: u16le(b, 0),
            uid: u16le(b, 2) as u32 | ((if b.len() >= 122 { u16le(b, 120) } else { 0 } as u32) << 16),
            gid: u16le(b, 24) as u32 | ((if b.len() >= 124 { u16le(b, 122) } else { 0 } as u32) << 16),
            size: u32le(b, 4) as u64 | ((u32le(b, 108) as u64) << 32),
            atime: u32le(b, 8),
            ctime: u32le(b, 12),
            mtime: u32le(b, 16),
            dtime: u32le(b, 20),
            crtime,
            links: u16le(b, 26),
            flags: u32le(b, 32),
            generation: u32le(b, 100),
            block,
        })
    }

    pub fn is_regular(&self) -> bool {
        self.mode & 0xF000 == 0x8000
    }
    pub fn is_dir(&self) -> bool {
        self.mode & 0xF000 == 0x4000
    }
    pub fn is_symlink(&self) -> bool {
        self.mode & 0xF000 == 0xA000
    }
    pub fn uses_extents(&self) -> bool {
        self.flags & INODE_EXTENTS_FL != 0
    }
    pub fn inline_data(&self) -> bool {
        self.flags & INODE_INLINE_DATA_FL != 0
    }
    /// Looks like an inode that is or was in use (a zeroed slot is not).
    pub fn plausible(&self) -> bool {
        self.mode != 0 && (self.is_regular() || self.is_dir() || self.is_symlink()) && self.mtime != 0
    }
}

/// `(logical block, length, physical block)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Extent {
    pub logical: u32,
    pub len: u32,
    pub physical: u64,
}

/// Parse an extent node (inode `i_block` or an index-pointed block).
/// `(logical block, length, physical block)`; length is 0 for an index entry.
pub type ExtentEntry = (u32, u32, u64);

/// Parse an extent node: its depth and entries (leaves or index pointers).
pub fn parse_extent_node(b: &[u8]) -> Option<(u16, Vec<ExtentEntry>)> {
    if b.len() < 12 || u16le(b, 0) != EXTENT_MAGIC {
        return None;
    }
    let entries = u16le(b, 2) as usize;
    let depth = u16le(b, 6);
    if entries > (b.len() - 12) / 12 || entries > 340 {
        return None;
    }
    let mut out = Vec::with_capacity(entries);
    for i in 0..entries {
        let e = &b[12 + i * 12..24 + i * 12];
        if depth == 0 {
            let raw_len = u16le(e, 4) as u32;
            let len = if raw_len > 32768 { raw_len - 32768 } else { raw_len }; // uninitialised extents
            let phys = u32le(e, 8) as u64 | ((u16le(e, 6) as u64) << 32);
            out.push((u32le(e, 0), len, phys));
        } else {
            let leaf = u32le(e, 4) as u64 | ((u16le(e, 8) as u64) << 32);
            out.push((u32le(e, 0), 0, leaf));
        }
    }
    Some((depth, out))
}

impl<'a> Volume<'a> {
    pub fn open(reader: &'a mut dyn Ext4Read) -> Result<Self, FaramirError> {
        let mut sb = vec![0u8; 1024];
        reader.read(SUPERBLOCK_OFFSET, &mut sb).map_err(|e| FaramirError::ExtJournalParseError(format!("superblock: {e}")))?;
        let geo = Geometry::parse(&sb)?;
        let mut v = Volume { reader, geo, groups: Vec::new(), block_cache: HashMap::new() };
        let count = v.geo.group_count();
        if count > 1 << 20 {
            return Err(FaramirError::ExtJournalParseError(format!("{count} block groups")));
        }
        let table_block = v.geo.first_data_block as u64 + 1;
        let per_block = v.geo.block_size / v.geo.desc_size as u64;
        let mut groups = Vec::with_capacity(count as usize);
        for g in 0..count {
            let blk = v.read_block(table_block + g / per_block)?;
            let o = ((g % per_block) * v.geo.desc_size as u64) as usize;
            let d = &blk[o..o + v.geo.desc_size as usize];
            let hi = |off: usize| if v.geo.desc_size >= 64 { u32le(d, off) as u64 } else { 0 };
            groups.push(Group {
                block_bitmap: u32le(d, 0) as u64 | (hi(32) << 32),
                inode_bitmap: u32le(d, 4) as u64 | (hi(36) << 32),
                inode_table: u32le(d, 8) as u64 | (hi(40) << 32),
            });
        }
        v.groups = groups;
        Ok(v)
    }

    pub fn read_block(&mut self, block: u64) -> Result<Vec<u8>, FaramirError> {
        if block >= self.geo.blocks_count {
            return Err(FaramirError::ExtJournalParseError(format!("block {block} beyond the volume")));
        }
        if let Some(b) = self.block_cache.get(&block) {
            return Ok(b.clone());
        }
        let mut buf = vec![0u8; self.geo.block_size as usize];
        self.reader.read(block * self.geo.block_size, &mut buf).map_err(|e| FaramirError::ExtJournalParseError(format!("block {block}: {e}")))?;
        if self.block_cache.len() < 4096 {
            self.block_cache.insert(block, buf.clone());
        }
        Ok(buf)
    }

    /// Group and byte offset of an inode inside its group's table.
    fn inode_location(&self, ino: u32) -> Option<(usize, u64)> {
        if ino == 0 || ino > self.geo.inodes_count {
            return None;
        }
        let idx = (ino - 1) as u64;
        let group = (idx / self.geo.inodes_per_group as u64) as usize;
        let within = idx % self.geo.inodes_per_group as u64;
        Some((group, within * self.geo.inode_size as u64))
    }

    pub fn read_inode(&mut self, ino: u32) -> Option<RawInode> {
        let (group, off) = self.inode_location(ino)?;
        let table = self.groups.get(group)?.inode_table;
        let bs = self.geo.block_size;
        let blk = self.read_block(table + off / bs).ok()?;
        let o = (off % bs) as usize;
        RawInode::parse(ino, &blk[o..o + self.geo.inode_size as usize])
    }

    /// Every extent of an inode, index nodes followed.
    pub fn extents(&mut self, inode: &RawInode) -> Vec<Extent> {
        let mut out = Vec::new();
        if inode.inline_data() {
            return out;
        }
        if inode.uses_extents() {
            let mut stack: Vec<(Vec<u8>, usize)> = vec![(inode.block.to_vec(), 0)];
            let mut visited = 0usize;
            while let Some((node, depth_guard)) = stack.pop() {
                visited += 1;
                if visited > 4096 || depth_guard > 6 {
                    break;
                }
                let Some((depth, entries)) = parse_extent_node(&node) else { continue };
                for (logical, len, phys) in entries {
                    if depth == 0 {
                        if len > 0 && phys < self.geo.blocks_count {
                            out.push(Extent { logical, len, physical: phys });
                        }
                    } else if let Ok(b) = self.read_block(phys) {
                        stack.push((b, depth_guard + 1));
                    }
                }
            }
        } else {
            // ext2/ext3 block map: direct blocks and one level of indirection
            for i in 0..12 {
                let p = u32le(&inode.block, i * 4) as u64;
                if p != 0 && p < self.geo.blocks_count {
                    out.push(Extent { logical: i as u32, len: 1, physical: p });
                }
            }
            let ind = u32le(&inode.block, 48) as u64;
            if ind != 0 && ind < self.geo.blocks_count {
                if let Ok(b) = self.read_block(ind) {
                    for (i, c) in b.chunks_exact(4).enumerate() {
                        let p = u32le(c, 0) as u64;
                        if p != 0 && p < self.geo.blocks_count {
                            out.push(Extent { logical: 12 + i as u32, len: 1, physical: p });
                        }
                    }
                }
            }
        }
        out.sort_by_key(|e| e.logical);
        out
    }

    /// Physical blocks of an inode in logical order (holes skipped).
    pub fn block_list(&mut self, inode: &RawInode) -> Vec<u64> {
        let mut blocks = Vec::new();
        for e in self.extents(inode) {
            for i in 0..e.len as u64 {
                if blocks.len() as u64 * self.geo.block_size > MAX_RECOVER_BYTES {
                    return blocks;
                }
                blocks.push(e.physical + i);
            }
        }
        blocks
    }

    /// File content from an inode's own map (inline, extents or block map), cut to `size`.
    pub fn read_content(&mut self, inode: &RawInode) -> Option<Vec<u8>> {
        if inode.size > MAX_RECOVER_BYTES {
            return None;
        }
        if inode.inline_data() {
            let n = (inode.size as usize).min(60);
            return Some(inode.block[..n].to_vec());
        }
        let mut data = Vec::with_capacity(inode.size as usize);
        for b in self.block_list(inode) {
            data.extend_from_slice(&self.read_block(b).ok()?);
            if data.len() as u64 >= inode.size {
                break;
            }
        }
        data.truncate(inode.size as usize);
        Some(data)
    }

    /// Is this block allocated right now, per the live block bitmap?
    pub fn block_allocated(&mut self, block: u64) -> Option<bool> {
        let rel = block.checked_sub(self.geo.first_data_block as u64)?;
        let group = (rel / self.geo.blocks_per_group as u64) as usize;
        let bit = (rel % self.geo.blocks_per_group as u64) as usize;
        let bitmap_block = self.groups.get(group)?.block_bitmap;
        let bm = self.read_block(bitmap_block).ok()?;
        bm.get(bit / 8).map(|b| b & (1 << (bit % 8)) != 0)
    }

    /// Which inode table (group, first inode number) a block belongs to, if any.
    pub fn inode_table_owner(&self, block: u64) -> Option<(usize, u32)> {
        let span = self.geo.inode_table_blocks();
        for (g, grp) in self.groups.iter().enumerate() {
            if block >= grp.inode_table && block < grp.inode_table + span {
                let per_block = (self.geo.block_size / self.geo.inode_size as u64) as u32;
                let first = g as u32 * self.geo.inodes_per_group + ((block - grp.inode_table) as u32) * per_block + 1;
                return Some((g, first));
            }
        }
        None
    }

    /// Inodes stored in a copy of an inode table block.
    pub fn inodes_in_block(&self, block: u64, data: &[u8]) -> Vec<RawInode> {
        let Some((_, first)) = self.inode_table_owner(block) else { return Vec::new() };
        let isz = self.geo.inode_size as usize;
        data.chunks_exact(isz)
            .enumerate()
            .filter_map(|(i, chunk)| RawInode::parse(first + i as u32, chunk))
            .filter(|ino| ino.plausible() && ino.ino <= self.geo.inodes_count)
            .collect()
    }
}

// ─── directory blocks ────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirEntry {
    pub ino: u32,
    pub name: String,
    pub file_type: u8,
    /// Byte offset of the entry in its block.
    pub offset: usize,
}

/// Entries of a directory block following the `rec_len` chain. `None` when
/// the block does not look like a directory block at all.
pub fn parse_dir_block(b: &[u8]) -> Option<Vec<DirEntry>> {
    let mut out = Vec::new();
    let mut off = 0usize;
    let mut live = 0usize;
    while off + 8 <= b.len() {
        let ino = u32le(b, off);
        let rec_len = u16le(b, off + 4) as usize;
        let name_len = b[off + 6] as usize;
        let ftype = b[off + 7];
        if rec_len < 8 || !rec_len.is_multiple_of(4) || off + rec_len > b.len() || 8 + name_len > rec_len {
            return None;
        }
        if ino != 0 {
            if name_len == 0 || ftype > 7 && ftype != 0xDE {
                return None;
            }
            let raw = &b[off + 8..off + 8 + name_len];
            if raw.iter().any(|&c| c == 0 || c == b'/') {
                return None;
            }
            out.push(DirEntry { ino, name: String::from_utf8_lossy(raw).to_string(), file_type: ftype, offset: off });
            live += 1;
        }
        off += rec_len;
    }
    (off == b.len() && live > 0).then_some(out)
}

/// Entries that are not on the `rec_len` chain any more: what an old kernel
/// leaves behind after `rm`. Modern ext4 often zeroes them; when it does
/// not, they come back here.
pub fn slack_dir_entries(b: &[u8], chain: &[DirEntry]) -> Vec<DirEntry> {
    let on_chain: HashSet<usize> = chain.iter().map(|e| e.offset).collect();
    let mut out = Vec::new();
    let mut off = 0usize;
    while off + 12 <= b.len() {
        if !on_chain.contains(&off) {
            let ino = u32le(b, off);
            let rec_len = u16le(b, off + 4) as usize;
            let name_len = b[off + 6] as usize;
            let ftype = b[off + 7];
            if ino != 0 && rec_len >= 8 + name_len && rec_len.is_multiple_of(4) && off + 8 + name_len <= b.len() && (1..=255).contains(&name_len) && ftype <= 7 {
                let raw = &b[off + 8..off + 8 + name_len];
                if raw.iter().all(|&c| c >= 0x20 && c != b'/' && c != 0x7f) {
                    out.push(DirEntry { ino, name: String::from_utf8_lossy(raw).to_string(), file_type: ftype, offset: off });
                }
            }
        }
        off += 4;
    }
    out
}

// ─── the live tree ───────────────────────────────────────────────────────────

/// Directory inodes, their paths, their blocks and their live entries.
#[derive(Debug, Default)]
pub struct LiveTree {
    pub dir_path: HashMap<u32, String>,
    pub block_owner: HashMap<u64, u32>,
    pub entries: HashMap<u32, HashMap<String, u32>>,
    /// `(path, inode)` of regular files.
    pub files: HashMap<String, u32>,
    pub dirs_walked: usize,
    pub truncated: bool,
}

impl LiveTree {
    pub fn walk(vol: &mut Volume<'_>) -> LiveTree {
        let mut t = LiveTree::default();
        let mut queue: Vec<(u32, String)> = vec![(ROOT_INO, String::new())];
        let mut seen: HashSet<u32> = HashSet::new();
        while let Some((ino, path)) = queue.pop() {
            if !seen.insert(ino) {
                continue;
            }
            if t.dirs_walked >= MAX_DIRS {
                t.truncated = true;
                break;
            }
            let Some(inode) = vol.read_inode(ino) else { continue };
            if !inode.is_dir() || inode.inline_data() {
                continue;
            }
            t.dirs_walked += 1;
            t.dir_path.insert(ino, if path.is_empty() { "/".to_string() } else { path.clone() });
            let mut names: HashMap<String, u32> = HashMap::new();
            for blk in vol.block_list(&inode) {
                t.block_owner.insert(blk, ino);
                let Ok(data) = vol.read_block(blk) else { continue };
                let Some(entries) = parse_dir_block(&data) else { continue };
                for e in entries {
                    if e.name == "." || e.name == ".." {
                        continue;
                    }
                    let child = format!("{path}/{}", e.name);
                    names.insert(e.name.clone(), e.ino);
                    match e.file_type {
                        2 => queue.push((e.ino, child)),
                        1 => {
                            t.files.insert(child, e.ino);
                        }
                        0 => {
                            if let Some(ci) = vol.read_inode(e.ino) {
                                if ci.is_dir() {
                                    queue.push((e.ino, child));
                                } else if ci.is_regular() {
                                    t.files.insert(child, e.ino);
                                }
                            }
                        }
                        _ => {}
                    }
                }
            }
            t.entries.insert(ino, names);
        }
        t
    }
}

// ─── the journal ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JournalInfo {
    pub block_size: u32,
    pub max_len: u32,
    pub first: u32,
    pub sequence: u32,
    pub start: u32,
    pub incompat: u32,
    pub blocks_scanned: u32,
    pub descriptors: usize,
    pub commits: usize,
    pub revokes: usize,
    pub copies: usize,
}

/// One block copy found in the journal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockCopy {
    pub sequence: u32,
    pub fs_block: u64,
    pub journal_block: u32,
    pub escaped: bool,
}

/// Size of a descriptor tag for the journal's feature set.
pub fn tag_size(incompat: u32) -> usize {
    if incompat & JBD2_INCOMPAT_CSUM_V3 != 0 {
        16
    } else if incompat & JBD2_INCOMPAT_64BIT != 0 {
        12
    } else {
        8
    }
}

/// Tags of a descriptor block: `(fs block, flags)` in order.
pub fn parse_descriptor_tags(b: &[u8], incompat: u32) -> Vec<(u64, u32)> {
    let ts = tag_size(incompat);
    let csum_v3 = incompat & JBD2_INCOMPAT_CSUM_V3 != 0;
    let tail = if incompat & (JBD2_INCOMPAT_CSUM_V2 | JBD2_INCOMPAT_CSUM_V3) != 0 { 4 } else { 0 };
    let mut out = Vec::new();
    let mut off = 12usize;
    while off + ts <= b.len().saturating_sub(tail) {
        let t = &b[off..off + ts];
        let (blocknr, flags, high) = if csum_v3 {
            (u32be(t, 0) as u64, u32be(t, 4), u32be(t, 8) as u64)
        } else {
            let high = if ts == 12 { u32be(t, 8) as u64 } else { 0 };
            (u32be(t, 0) as u64, u16be(t, 6) as u32, high)
        };
        let fs_block = blocknr | (high << 32);
        out.push((fs_block, flags));
        off += ts;
        if flags & TAG_SAME_UUID == 0 {
            off += 16;
        }
        if flags & TAG_LAST != 0 {
            break;
        }
        if out.len() > 4096 {
            break;
        }
    }
    out
}

/// Walk the whole journal area (not only the live transactions: old,
/// already-checkpointed copies are the point) and list every block copy.
pub fn scan_journal(vol: &mut Volume<'_>, label: &str) -> Result<(JournalInfo, Vec<BlockCopy>), FaramirError> {
    let jino = vol.geo.journal_ino;
    let inode = vol.read_inode(jino).ok_or_else(|| FaramirError::ExtJournalParseError(format!("{label}: journal inode {jino} unreadable")))?;
    if !inode.is_regular() || inode.size == 0 {
        return Err(FaramirError::ExtJournalParseError(format!("{label}: journal inode {jino} is not a file (mode {:#o}, {} bytes)", inode.mode, inode.size)));
    }
    // the journal is one file; its blocks in logical order
    let mut jblocks: Vec<u64> = Vec::new();
    for e in vol.extents(&inode) {
        for i in 0..e.len as u64 {
            jblocks.push(e.physical + i);
            if jblocks.len() as u64 > MAX_JOURNAL_BLOCKS {
                break;
            }
        }
    }
    if jblocks.is_empty() {
        return Err(FaramirError::ExtJournalParseError(format!("{label}: journal has no extents")));
    }
    let sb = vol.read_block(jblocks[0])?;
    if u32be(&sb, 0) != JBD2_MAGIC || !matches!(u32be(&sb, 4), JBD2_SUPERBLOCK_V1 | JBD2_SUPERBLOCK_V2) {
        return Err(FaramirError::ExtJournalParseError(format!("{label}: no jbd2 superblock in the journal file")));
    }
    let v2 = u32be(&sb, 4) == JBD2_SUPERBLOCK_V2;
    let mut info = JournalInfo {
        block_size: u32be(&sb, 12),
        max_len: u32be(&sb, 16),
        first: u32be(&sb, 20),
        sequence: u32be(&sb, 24),
        start: u32be(&sb, 28),
        incompat: if v2 { u32be(&sb, 40) } else { 0 },
        blocks_scanned: 0,
        descriptors: 0,
        commits: 0,
        revokes: 0,
        copies: 0,
    };
    if info.block_size as u64 != vol.geo.block_size {
        return Err(FaramirError::ExtJournalParseError(format!("{label}: journal block size {} differs from the file system's {}", info.block_size, vol.geo.block_size)));
    }
    let max_len = (info.max_len as usize).min(jblocks.len());
    let first = info.first as usize;
    if first >= max_len {
        return Err(FaramirError::ExtJournalParseError(format!("{label}: journal first block {first} beyond its length {max_len}")));
    }
    let mut copies = Vec::new();
    let mut j = first;
    while j < max_len {
        let Ok(b) = vol.read_block(jblocks[j]) else { break };
        info.blocks_scanned += 1;
        if u32be(&b, 0) != JBD2_MAGIC {
            j += 1;
            continue;
        }
        let kind = u32be(&b, 4);
        let seq = u32be(&b, 8);
        match kind {
            JBD2_DESCRIPTOR => {
                info.descriptors += 1;
                let tags = parse_descriptor_tags(&b, info.incompat);
                let mut data_idx = j + 1;
                for (fs_block, flags) in tags {
                    if data_idx >= max_len {
                        data_idx = first; // the journal wraps
                    }
                    copies.push(BlockCopy { sequence: seq, fs_block, journal_block: data_idx as u32, escaped: flags & TAG_ESCAPE != 0 });
                    data_idx += 1;
                }
                j = if data_idx <= j { max_len } else { data_idx };
            }
            JBD2_COMMIT => {
                info.commits += 1;
                j += 1;
            }
            JBD2_REVOKE => {
                info.revokes += 1;
                j += 1;
            }
            _ => {
                j += 1;
            }
        }
    }
    info.copies = copies.len();
    // keep the raw journal block numbers around for the reads
    let mapped: Vec<BlockCopy> = copies.into_iter().filter(|c| (c.journal_block as usize) < jblocks.len() && c.fs_block < vol.geo.blocks_count).collect();
    JOURNAL_BLOCKS.with(|m| *m.borrow_mut() = jblocks);
    Ok((info, mapped))
}

thread_local! {
    static JOURNAL_BLOCKS: std::cell::RefCell<Vec<u64>> = const { std::cell::RefCell::new(Vec::new()) };
}

/// Bytes of a block copy as they were in the file system (escape undone).
pub fn read_copy(vol: &mut Volume<'_>, c: &BlockCopy) -> Option<Vec<u8>> {
    let phys = JOURNAL_BLOCKS.with(|m| m.borrow().get(c.journal_block as usize).copied())?;
    let mut b = vol.read_block(phys).ok()?;
    if c.escaped && b.len() >= 4 {
        b[..4].copy_from_slice(&JBD2_MAGIC.to_be_bytes());
    }
    Some(b)
}

// ─── recovery ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveredKind {
    /// Named in a journal directory copy or in directory slack, gone from the live tree.
    Deleted,
    /// A live file whose journal inode copy points at different, still-free blocks.
    PreviousVersion,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveredFile {
    pub path: String,
    pub ino: u32,
    pub kind: RecoveredKind,
    /// `journal seq N` or `directory slack`.
    pub source: String,
    pub size: u64,
    pub mtime: u32,
    pub crtime: Option<u32>,
    /// Deletion time from the live inode, when it still carries it.
    pub dtime: Option<u32>,
    pub content: Option<Vec<u8>>,
    /// The old blocks are allocated again; the content was not taken.
    pub blocks_reused: bool,
}

#[derive(Debug, Default, Clone)]
pub struct RecoveryReport {
    pub journal: Option<JournalInfo>,
    pub inode_copies: usize,
    pub dir_copies: usize,
    pub files: Vec<RecoveredFile>,
    pub live_dirs: usize,
}

/// Does this path belong to the persistence surface the Linux techniques read?
pub fn is_persistence_path(path: &str) -> bool {
    use super::linux_image::{HOME_DIRS, HOME_FILES, LINUX_DIRS, LINUX_FILES};
    if LINUX_FILES.contains(&path) {
        return true;
    }
    if LINUX_DIRS.iter().any(|d| path.starts_with(&format!("{d}/"))) {
        return true;
    }
    let home_rel = if let Some(r) = path.strip_prefix("/root/") {
        Some(r)
    } else if let Some(r) = path.strip_prefix("/home/") {
        r.split_once('/').map(|(_, rest)| rest)
    } else {
        None
    };
    match home_rel {
        Some(rel) => HOME_FILES.contains(&rel) || HOME_DIRS.iter().any(|d| rel.starts_with(&format!("{d}/"))),
        None => false,
    }
}

fn all_free(vol: &mut Volume<'_>, blocks: &[u64]) -> bool {
    !blocks.is_empty() && blocks.iter().all(|&b| vol.block_allocated(b) == Some(false))
}

/// Find deleted files and previous versions under the persistence surface.
pub fn recover(reader: &mut dyn Ext4Read, label: &str) -> Result<RecoveryReport, FaramirError> {
    let mut vol = Volume::open(reader)?;
    let mut report = RecoveryReport::default();
    let live = LiveTree::walk(&mut vol);
    report.live_dirs = live.dirs_walked;
    let live_inos: HashSet<u32> = live.files.values().copied().collect();

    // 1. journal copies: inodes by number (latest first), directory blocks by owner
    let (info, copies) = match scan_journal(&mut vol, label) {
        Ok(x) => x,
        Err(e) => {
            diag::record(e);
            (JournalInfo { block_size: 0, max_len: 0, first: 0, sequence: 0, start: 0, incompat: 0, blocks_scanned: 0, descriptors: 0, commits: 0, revokes: 0, copies: 0 }, Vec::new())
        }
    };
    let mut inode_copies: BTreeMap<u32, Vec<(u32, RawInode)>> = BTreeMap::new();
    // (dir inode, name) -> (child inode, seq)
    let mut dir_names: HashMap<(u32, String), Vec<(u32, u32)>> = HashMap::new();
    for c in &copies {
        let Some(data) = read_copy(&mut vol, c) else { continue };
        if vol.inode_table_owner(c.fs_block).is_some() {
            let inodes = vol.inodes_in_block(c.fs_block, &data);
            if !inodes.is_empty() {
                report.inode_copies += 1;
            }
            for ino in inodes {
                inode_copies.entry(ino.ino).or_default().push((c.sequence, ino));
            }
            continue;
        }
        if let Some(entries) = parse_dir_block(&data) {
            report.dir_copies += 1;
            let owner = live
                .block_owner
                .get(&c.fs_block)
                .copied()
                .or_else(|| entries.iter().find(|e| e.name == ".").map(|e| e.ino));
            let Some(owner) = owner else { continue };
            // every inode a name ever pointed at, with the latest transaction that
            // showed the pairing (a name replaced by rename has two histories)
            for e in entries.into_iter().filter(|e| e.name != "." && e.name != "..") {
                let seen = dir_names.entry((owner, e.name)).or_default();
                match seen.iter_mut().find(|(ino, _)| *ino == e.ino) {
                    Some(slot) => slot.1 = slot.1.max(c.sequence),
                    None => seen.push((e.ino, c.sequence)),
                }
            }
        }
    }
    for v in inode_copies.values_mut() {
        v.sort_by_key(|(seq, _)| std::cmp::Reverse(*seq));
    }
    report.journal = Some(info);

    // 2. directory slack of the live tree
    let mut slack: Vec<(u32, DirEntry)> = Vec::new();
    for (&blk, &owner) in &live.block_owner {
        let Ok(data) = vol.read_block(blk) else { continue };
        let Some(chain) = parse_dir_block(&data) else { continue };
        for e in slack_dir_entries(&data, &chain) {
            slack.push((owner, e));
        }
    }

    // 3. names gone from the live tree, or pointing at another inode now
    //    (replaced by rename: the old inode is the previous version)
    let mut candidates: Vec<(u32, String, u32, String, bool, Option<u32>)> = Vec::new(); // (dir, name, ino, source, replaced, seq the name was seen at)
    for ((dir, name), history) in &dir_names {
        let live_ino = live.entries.get(dir).and_then(|m| m.get(name)).copied();
        for (ino, seq) in history {
            if live_ino != Some(*ino) {
                candidates.push((*dir, name.clone(), *ino, format!("journal seq {seq}"), live_ino.is_some(), Some(*seq)));
            }
        }
    }
    for (dir, e) in slack {
        let live_ino = live.entries.get(&dir).and_then(|m| m.get(&e.name)).copied();
        if live_ino != Some(e.ino) && !candidates.iter().any(|c| c.0 == dir && c.1 == e.name && c.2 == e.ino) {
            candidates.push((dir, e.name, e.ino, "directory slack".to_string(), live_ino.is_some(), None));
        }
    }
    let mut seen: HashSet<(String, u32)> = HashSet::new();
    for (dir, name, ino, source, replaced, name_seq) in candidates {
        let Some(dir_path) = live.dir_path.get(&dir) else { continue };
        let path = if dir_path == "/" { format!("/{name}") } else { format!("{dir_path}/{name}") };
        if !is_persistence_path(&path) || !seen.insert((path.clone(), ino)) {
            continue;
        }
        let live_inode = vol.read_inode(ino);
        // the inode as it was before deletion: latest journal copy without dtime
        // the inode as it was while the name pointed at it: the latest copy at or
        // before the transaction that recorded the name, without dtime. An inode
        // number gets recycled, so a later copy may belong to another file.
        let before = inode_copies.get(&ino).and_then(|v| {
            v.iter()
                .filter(|(seq, i)| i.dtime == 0 && i.is_regular() && name_seq.is_none_or(|ns| *seq <= ns))
                .max_by_key(|(seq, _)| *seq)
                .cloned()
        });
        let generation = before.as_ref().map(|(_, i)| i.generation);
        // deletion time: the live slot if it still belongs to this file, else a
        // later journal copy of the same generation that carries dtime
        let dtime = live_inode
            .as_ref()
            .filter(|i| i.dtime != 0 && generation.is_none_or(|g| g == i.generation))
            .map(|i| i.dtime)
            .or_else(|| {
                inode_copies.get(&ino).and_then(|v| {
                    v.iter().filter(|(_, i)| i.dtime != 0 && generation.is_none_or(|g| g == i.generation)).map(|(_, i)| i.dtime).max()
                })
            });
        let (size, mtime, crtime, content, reused) = match &before {
            Some((_, old)) => {
                let blocks = vol.block_list(old);
                let free = old.inline_data() || all_free(&mut vol, &blocks);
                let content = if free { vol.read_content(old) } else { None };
                (old.size, old.mtime, old.crtime, content, !free)
            }
            None => match &live_inode {
                // inode reused or no copy: only what the live slot says
                Some(li) if li.dtime != 0 => (0, li.mtime, li.crtime, None, false),
                _ => (0, 0, None, None, false),
            },
        };
        report.files.push(RecoveredFile {
            path,
            ino,
            kind: if replaced { RecoveredKind::PreviousVersion } else { RecoveredKind::Deleted },
            source: match &before {
                Some((seq, _)) => format!("journal seq {seq}{}", if replaced { " (replaced by rename)" } else { "" }),
                None => source,
            },
            size,
            mtime,
            crtime,
            dtime,
            content,
            blocks_reused: reused,
        });
    }

    // 4. previous versions of live files (in-place rewrites whose old blocks were freed)
    for (path, &ino) in &live.files {
        if !is_persistence_path(path) {
            continue;
        }
        let Some(live_inode) = vol.read_inode(ino) else { continue };
        let live_blocks: HashSet<u64> = vol.block_list(&live_inode).into_iter().collect();
        let Some(versions) = inode_copies.get(&ino) else { continue };
        let mut emitted = 0usize;
        for (seq, old) in versions {
            if !old.is_regular() || old.dtime != 0 || old.generation != live_inode.generation || (old.mtime == live_inode.mtime && old.size == live_inode.size) {
                continue;
            }
            let blocks = vol.block_list(old);
            if blocks.is_empty() || blocks.iter().any(|b| live_blocks.contains(b)) {
                continue; // rewritten in place: the old content is gone
            }
            let free = all_free(&mut vol, &blocks);
            let content = if free { vol.read_content(old) } else { None };
            report.files.push(RecoveredFile {
                path: path.clone(),
                ino,
                kind: RecoveredKind::PreviousVersion,
                source: format!("journal seq {seq}"),
                size: old.size,
                mtime: old.mtime,
                crtime: old.crtime,
                dtime: None,
                content,
                blocks_reused: !free,
            });
            emitted += 1;
            if emitted >= 8 {
                break;
            }
        }
    }
    let _ = live_inos;

    // identical versions of one inode (same content, same mtime) collapse to the latest
    let mut keep: Vec<RecoveredFile> = Vec::new();
    for f in report.files.drain(..) {
        if let Some(existing) = keep.iter_mut().find(|k| k.path == f.path && k.ino == f.ino && k.kind == f.kind && k.mtime == f.mtime && k.size == f.size && k.content == f.content) {
            if f.source > existing.source {
                *existing = f;
            }
            continue;
        }
        keep.push(f);
    }
    report.files = keep;
    Ok(report)
}

/// Unix seconds to the timeline format.
pub fn unix_to_string(secs: u32) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp(secs as i64, 0)
        .map(|d| d.format(crate::windows::techniques::FORMAT_DATE).to_string())
        .unwrap_or_default()
}

/// Manifest entry written next to the recovered files.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, PartialEq, Eq)]
pub struct ManifestEntry {
    pub path: String,
    pub staged: Option<String>,
    pub ino: u32,
    pub kind: String,
    pub source: String,
    pub size: u64,
    pub mtime: String,
    pub crtime: Option<String>,
    pub dtime: Option<String>,
    pub content_recovered: bool,
    pub blocks_reused: bool,
}

pub const MANIFEST_FILE: &str = "faramir_recovered.json";

/// Write recovered files under `out_dir` keeping the original tree (a
/// previous version gets a `.v<seq>` suffix) and a manifest describing them.
pub fn stage(report: &RecoveryReport, out_dir: &Path, label: &str) -> Result<Vec<ManifestEntry>, FaramirError> {
    std::fs::create_dir_all(out_dir).map_err(|e| FaramirError::StagingDirFailed(format!("{}: {e}", out_dir.display())))?;
    let mut entries = Vec::new();
    for f in &report.files {
        let rel = f.path.trim_start_matches('/').replace('/', std::path::MAIN_SEPARATOR_STR);
        // a previous version keeps its file name (the parsers key on it) inside
        // a folder of its own: `_v<seq>_ino<N>/etc/crontab`
        let staged_rel = match f.kind {
            RecoveredKind::Deleted => rel,
            RecoveredKind::PreviousVersion => format!(
                "{}{}{rel}",
                version_dir_name(f.source.split(' ').nth(2).unwrap_or("0"), f.ino),
                std::path::MAIN_SEPARATOR_STR
            ),
        };
        let mut staged = None;
        if let Some(c) = &f.content {
            let dest = out_dir.join(&staged_rel);
            if let Some(p) = dest.parent() {
                let _ = std::fs::create_dir_all(p);
            }
            match std::fs::write(&dest, c) {
                Ok(()) => {
                    if let Some(t) = std::time::UNIX_EPOCH.checked_add(std::time::Duration::from_secs(f.mtime as u64)) {
                        let _ = std::fs::File::options().write(true).open(&dest).and_then(|fh| fh.set_modified(t));
                    }
                    staged = Some(staged_rel.clone());
                }
                Err(e) => {
                    diag::record(FaramirError::LinuxExtractError(format!("{label}: recovered {} -> {}: {e}", f.path, dest.display())));
                }
            }
        }
        entries.push(ManifestEntry {
            path: f.path.clone(),
            staged,
            ino: f.ino,
            kind: match f.kind {
                RecoveredKind::Deleted => "deleted".into(),
                RecoveredKind::PreviousVersion => "previous_version".into(),
            },
            source: f.source.clone(),
            size: f.size,
            mtime: unix_to_string(f.mtime),
            crtime: f.crtime.map(unix_to_string),
            dtime: f.dtime.map(unix_to_string),
            content_recovered: f.content.is_some(),
            blocks_reused: f.blocks_reused,
        });
    }
    let json = serde_json::to_string_pretty(&entries).map_err(|e| FaramirError::LinuxExtractError(format!("{label}: manifest: {e}")))?;
    std::fs::write(out_dir.join(MANIFEST_FILE), json).map_err(|e| FaramirError::LinuxExtractError(format!("{label}: manifest: {e}")))?;
    Ok(entries)
}

/// Folder a previous version is staged under.
pub fn version_dir_name(seq: &str, ino: u32) -> String {
    format!("_v{seq}_ino{ino}")
}

/// Root to resolve host paths against for a staged entry (the version folder
/// for a previous version, the recovery folder itself for a deleted file).
pub fn staged_root(recovered_dir: &Path, staged: &str) -> std::path::PathBuf {
    match staged.split(['/', '\\']).next() {
        Some(first) if first.starts_with("_v") && first.contains("_ino") => recovered_dir.join(first),
        _ => recovered_dir.to_path_buf(),
    }
}

/// Read a manifest written by [`stage`].
pub fn read_manifest(dir: &Path) -> Option<Vec<ManifestEntry>> {
    let text = std::fs::read_to_string(dir.join(MANIFEST_FILE)).ok()?;
    serde_json::from_str(&text).ok()
}
