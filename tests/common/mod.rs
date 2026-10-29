//! Test support: a minimal but spec-faithful writer for regf hives and HvLE
//! transaction logs, so every technique and the dirty-hive recovery path can
//! be exercised with hand-built, deterministic evidence.
#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use blockcarve::hive_logs::{marvin32, MARVIN32_SEED as MARVIN_SEED};

pub const FILETIME_2024: u64 = 133_500_000_000_000_000;
pub const BASE_BLOCK: usize = 4096;
pub const HBIN_HEADER: usize = 32;

static COUNTER: AtomicU64 = AtomicU64::new(0);

// ─── Temp dirs ──────────────────────────────────────────────────────────────

pub struct TempDir {
    pub path: PathBuf,
}

impl TempDir {
    pub fn new(prefix: &str) -> Self {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let path = std::env::temp_dir().join(format!("faramir_{prefix}_{}_{n}_{nanos}", std::process::id()));
        std::fs::create_dir_all(&path).unwrap();
        TempDir { path }
    }

    pub fn join(&self, rel: &str) -> PathBuf {
        self.path.join(rel.replace('/', std::path::MAIN_SEPARATOR_STR))
    }

    pub fn mkdir(&self, rel: &str) -> PathBuf {
        let p = self.join(rel);
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    pub fn write(&self, rel: &str, bytes: &[u8]) -> PathBuf {
        let p = self.join(rel);
        if let Some(parent) = p.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(&p, bytes).unwrap();
        p
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

// ─── Hive model ─────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub enum ValueDef {
    Sz(String),
    ExpandSz(String),
    /// 1-character string stored inline in the vk (what Windows does for <=4 bytes).
    SzResident(String),
    Dword(u32),
    MultiSz(Vec<String>),
    Binary(Vec<u8>),
}

#[derive(Clone, Debug)]
pub struct KeyDef {
    pub name: String,
    pub values: Vec<(String, ValueDef)>,
    pub subkeys: Vec<KeyDef>,
    pub timestamp: u64,
    /// Written as a free cell and left out of the parent's subkey list,
    /// exactly what Windows leaves behind after `RegDeleteKey`.
    pub deleted: bool,
    /// Written as free vk cells (with their data) and left out of the value list.
    pub deleted_values: Vec<(String, ValueDef)>,
}

impl KeyDef {
    pub fn new(name: &str) -> Self {
        KeyDef {
            name: name.to_string(),
            values: Vec::new(),
            subkeys: Vec::new(),
            timestamp: FILETIME_2024,
            deleted: false,
            deleted_values: Vec::new(),
        }
    }

    pub fn child_mut(&mut self, name: &str) -> &mut KeyDef {
        let idx = match self.subkeys.iter().position(|k| k.name.eq_ignore_ascii_case(name)) {
            Some(i) => i,
            None => {
                self.subkeys.push(KeyDef::new(name));
                self.subkeys.len() - 1
            }
        };
        &mut self.subkeys[idx]
    }
}

#[derive(Clone, Debug)]
pub struct HiveBuilder {
    pub root: KeyDef,
    pub embedded_name: String,
    pub sequence: u32,
    pub minor_version: u32,
    pub min_bin_size: usize,
}

impl HiveBuilder {
    pub fn new(embedded_name: &str) -> Self {
        HiveBuilder {
            root: KeyDef::new("ROOT"),
            embedded_name: embedded_name.to_string(),
            sequence: 5,
            minor_version: 5,
            min_bin_size: 0,
        }
    }

    pub fn software() -> Self {
        Self::new(r"emRoot\System32\Config\SOFTWARE")
    }
    pub fn system() -> Self {
        Self::new(r"emRoot\System32\Config\SYSTEM")
    }
    pub fn ntuser(user: &str) -> Self {
        Self::new(&format!(r"\??\C:\Users\{user}\ntuser.dat"))
    }
    pub fn usrclass(user: &str) -> Self {
        Self::new(&format!(r"{user}\AppData\Local\Microsoft\Windows\UsrClass.dat"))
    }
    pub fn default_hive() -> Self {
        Self::new(r"emRoot\System32\Config\DEFAULT")
    }
    pub fn anonymous() -> Self {
        Self::new("")
    }

    pub fn key(&mut self, path: &str) -> &mut KeyDef {
        let mut cur = &mut self.root;
        for part in path.split('\\').filter(|p| !p.is_empty()) {
            cur = cur.child_mut(part);
        }
        cur
    }

    pub fn set(&mut self, path: &str, name: &str, v: ValueDef) -> &mut Self {
        let k = self.key(path);
        k.values.retain(|(n, _)| !n.eq_ignore_ascii_case(name));
        k.values.push((name.to_string(), v));
        self
    }

    pub fn sz(&mut self, path: &str, name: &str, s: &str) -> &mut Self {
        self.set(path, name, ValueDef::Sz(s.to_string()))
    }
    pub fn expand_sz(&mut self, path: &str, name: &str, s: &str) -> &mut Self {
        self.set(path, name, ValueDef::ExpandSz(s.to_string()))
    }
    pub fn sz_resident(&mut self, path: &str, name: &str, s: &str) -> &mut Self {
        self.set(path, name, ValueDef::SzResident(s.to_string()))
    }
    pub fn dword(&mut self, path: &str, name: &str, n: u32) -> &mut Self {
        self.set(path, name, ValueDef::Dword(n))
    }
    pub fn multi_sz(&mut self, path: &str, name: &str, list: &[&str]) -> &mut Self {
        self.set(path, name, ValueDef::MultiSz(list.iter().map(|s| s.to_string()).collect()))
    }
    pub fn binary(&mut self, path: &str, name: &str, b: &[u8]) -> &mut Self {
        self.set(path, name, ValueDef::Binary(b.to_vec()))
    }

    /// Mark a key (and everything under it) as deleted: its cells stay on disk as free cells.
    pub fn delete_key(&mut self, path: &str) -> &mut Self {
        fn mark(k: &mut KeyDef) {
            k.deleted = true;
            for c in &mut k.subkeys {
                mark(c);
            }
        }
        mark(self.key(path));
        self
    }

    /// Delete a value: its vk cell (and data) stay on disk as free cells.
    pub fn delete_value(&mut self, path: &str, name: &str) -> &mut Self {
        let k = self.key(path);
        if let Some(pos) = k.values.iter().position(|(n, _)| n.eq_ignore_ascii_case(name)) {
            let v = k.values.remove(pos);
            k.deleted_values.push(v);
        }
        self
    }

    /// A value that only exists as a free cell (never listed).
    pub fn deleted_sz(&mut self, path: &str, name: &str, s: &str) -> &mut Self {
        self.key(path).deleted_values.push((name.to_string(), ValueDef::Sz(s.to_string())));
        self
    }

    /// Serialised hive bins (what follows the base block).
    pub fn hbin_region(&self) -> Vec<u8> {
        let (bins, _root_off) = self.serialise_bins();
        bins
    }

    pub fn root_cell_offset(&self) -> u32 {
        let (_bins, root_off) = self.serialise_bins();
        root_off
    }

    fn serialise_bins(&self) -> (Vec<u8>, u32) {
        let mut bins = Bins::new();
        let root_off = write_key(&mut bins, &self.root, true);
        (bins.finish(self.min_bin_size), root_off)
    }

    pub fn build(&self) -> Vec<u8> {
        self.build_with(self.sequence, self.sequence)
    }

    pub fn build_with(&self, primary: u32, secondary: u32) -> Vec<u8> {
        let (bins, root_off) = self.serialise_bins();
        let mut out = base_block(
            primary,
            secondary,
            root_off,
            bins.len() as u32,
            &self.embedded_name,
            0,
            self.minor_version,
        )
        .to_vec();
        out.extend_from_slice(&bins);
        out
    }

    pub fn write(&self, path: &Path) -> PathBuf {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, self.build()).unwrap();
        path.to_path_buf()
    }

    pub fn write_with(&self, path: &Path, primary: u32, secondary: u32) -> PathBuf {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        std::fs::write(path, self.build_with(primary, secondary)).unwrap();
        path.to_path_buf()
    }
}

// ─── Cell allocator ─────────────────────────────────────────────────────────

struct Bins {
    data: Vec<u8>,
}

impl Bins {
    fn new() -> Self {
        Bins { data: vec![0u8; HBIN_HEADER] }
    }

    fn alloc(&mut self, payload: &[u8]) -> u32 {
        self.alloc_with(payload, false)
    }

    /// `free == true` writes the cell with a positive size: a deleted cell.
    fn alloc_with(&mut self, payload: &[u8], free: bool) -> u32 {
        let off = self.data.len() as u32;
        let total = (4 + payload.len()).div_ceil(8) * 8;
        let size = if free { total as i32 } else { -(total as i32) };
        self.data.extend_from_slice(&size.to_le_bytes());
        self.data.extend_from_slice(payload);
        self.data.resize(off as usize + total, 0);
        off
    }

    fn patch_u32(&mut self, off: usize, v: u32) {
        self.data[off..off + 4].copy_from_slice(&v.to_le_bytes());
    }

    fn finish(mut self, min_size: usize) -> Vec<u8> {
        let used = self.data.len();
        let mut size = used.div_ceil(4096) * 4096;
        if size < min_size {
            size = min_size.div_ceil(4096) * 4096;
        }
        if size > used {
            let free = (size - used) as i32;
            self.data.extend_from_slice(&free.to_le_bytes());
            self.data.resize(size, 0);
        }
        self.data[0..4].copy_from_slice(b"hbin");
        self.data[4..8].copy_from_slice(&0u32.to_le_bytes());
        self.data[8..12].copy_from_slice(&(size as u32).to_le_bytes());
        self.data[20..28].copy_from_slice(&FILETIME_2024.to_le_bytes());
        self.data
    }
}

pub fn utf16le(s: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for u in s.encode_utf16() {
        out.extend_from_slice(&u.to_le_bytes());
    }
    out.extend_from_slice(&[0, 0]);
    out
}

fn multi_sz_bytes(list: &[String]) -> Vec<u8> {
    let mut out = Vec::new();
    for s in list {
        out.extend_from_slice(&utf16le(s));
    }
    out.extend_from_slice(&[0, 0]);
    out
}

fn write_value(bins: &mut Bins, name: &str, v: &ValueDef) -> u32 {
    write_value_with(bins, name, v, false)
}

fn write_value_with(bins: &mut Bins, name: &str, v: &ValueDef, free: bool) -> u32 {
    let (data_size, data_field, data_type): (u32, u32, u32) = match v {
        ValueDef::Sz(s) | ValueDef::ExpandSz(s) => {
            let bytes = utf16le(s);
            let off = bins.alloc_with(&bytes, free);
            (bytes.len() as u32, off, if matches!(v, ValueDef::Sz(_)) { 1 } else { 2 })
        }
        ValueDef::SzResident(s) => {
            let bytes = utf16le(s);
            assert!(bytes.len() <= 4, "resident strings must fit in 4 bytes");
            let mut field = [0u8; 4];
            field[..bytes.len()].copy_from_slice(&bytes);
            (0x8000_0000 | bytes.len() as u32, u32::from_le_bytes(field), 1)
        }
        ValueDef::Dword(n) => (0x8000_0004, *n, 4),
        ValueDef::MultiSz(list) => {
            let bytes = multi_sz_bytes(list);
            let off = bins.alloc(&bytes);
            (bytes.len() as u32, off, 7)
        }
        ValueDef::Binary(b) => {
            let off = bins.alloc(b);
            (b.len() as u32, off, 3)
        }
    };
    let name_bytes = name.as_bytes();
    let mut vk = Vec::new();
    vk.extend_from_slice(b"vk");
    vk.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
    vk.extend_from_slice(&data_size.to_le_bytes());
    vk.extend_from_slice(&data_field.to_le_bytes());
    vk.extend_from_slice(&data_type.to_le_bytes());
    vk.extend_from_slice(&1u16.to_le_bytes()); // VALUE_COMP_NAME (ASCII name)
    vk.extend_from_slice(&0u16.to_le_bytes());
    vk.extend_from_slice(name_bytes);
    bins.alloc_with(&vk, free)
}

fn nk_cell_len(key: &KeyDef) -> usize {
    (4 + 0x4c + key.name.len()).div_ceil(8) * 8
}

/// The root key is written FIRST at a fixed offset (0x20) so that every
/// variant of a hive (base + each log step) keeps the same root cell offset,
/// exactly like Windows never moves the root of a real hive.
fn write_key(bins: &mut Bins, key: &KeyDef, is_root: bool) -> u32 {
    let reserved = if is_root {
        let placeholder = vec![0u8; nk_cell_len(key) - 4];
        Some(bins.alloc(&placeholder))
    } else {
        None
    };
    // every child is written (deleted ones as free cells); only live ones are listed
    let child_offs: Vec<u32> = key.subkeys.iter().map(|k| write_key(bins, k, false)).collect();
    let live_children: Vec<(&KeyDef, u32)> = key.subkeys.iter().zip(child_offs.iter().copied()).filter(|(k, _)| !k.deleted).collect();

    let sk_list_off = if live_children.is_empty() {
        0xffff_ffff
    } else {
        let mut p = Vec::new();
        p.extend_from_slice(b"lf");
        p.extend_from_slice(&(live_children.len() as u16).to_le_bytes());
        for (child, off) in &live_children {
            p.extend_from_slice(&off.to_le_bytes());
            let mut hint = [0u8; 4];
            for (i, b) in child.name.bytes().take(4).enumerate() {
                hint[i] = b;
            }
            p.extend_from_slice(&hint);
        }
        bins.alloc(&p)
    };

    let free = key.deleted;
    for (n, v) in &key.deleted_values {
        write_value_with(bins, n, v, true);
    }
    let val_offs: Vec<u32> = key.values.iter().map(|(n, v)| write_value_with(bins, n, v, free)).collect();
    let vl_off = if val_offs.is_empty() {
        0xffff_ffff
    } else {
        let mut p = Vec::new();
        for o in &val_offs {
            p.extend_from_slice(&o.to_le_bytes());
        }
        bins.alloc_with(&p, free)
    };

    let name_bytes = key.name.as_bytes();
    let mut nk = Vec::new();
    nk.extend_from_slice(b"nk");
    nk.extend_from_slice(&(if is_root { 0x2Cu16 } else { 0x20u16 }).to_le_bytes());
    nk.extend_from_slice(&key.timestamp.to_le_bytes());
    nk.extend_from_slice(&0u32.to_le_bytes()); // access bits
    nk.extend_from_slice(&0u32.to_le_bytes()); // parent (patched below for children)
    nk.extend_from_slice(&(live_children.len() as u32).to_le_bytes());
    nk.extend_from_slice(&0u32.to_le_bytes()); // volatile subkey count
    nk.extend_from_slice(&sk_list_off.to_le_bytes());
    nk.extend_from_slice(&0xffff_ffffu32.to_le_bytes()); // volatile subkeys list
    nk.extend_from_slice(&(val_offs.len() as u32).to_le_bytes());
    nk.extend_from_slice(&vl_off.to_le_bytes());
    nk.extend_from_slice(&0xffff_ffffu32.to_le_bytes()); // security
    nk.extend_from_slice(&0xffff_ffffu32.to_le_bytes()); // class name
    let max_sub_name = key.subkeys.iter().map(|k| k.name.len() * 2).max().unwrap_or(0) as u32;
    nk.extend_from_slice(&max_sub_name.to_le_bytes());
    nk.extend_from_slice(&0u32.to_le_bytes()); // max class
    let max_val_name = key.values.iter().map(|(n, _)| n.len() * 2).max().unwrap_or(0) as u32;
    nk.extend_from_slice(&max_val_name.to_le_bytes());
    nk.extend_from_slice(&4096u32.to_le_bytes()); // max value data
    nk.extend_from_slice(&0u32.to_le_bytes()); // workvar
    nk.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
    nk.extend_from_slice(&0u16.to_le_bytes());
    nk.extend_from_slice(name_bytes);
    let off = match reserved {
        Some(off) => {
            let start = off as usize + 4;
            bins.data[start..start + nk.len()].copy_from_slice(&nk);
            off
        }
        None => bins.alloc_with(&nk, key.deleted),
    };

    for child in child_offs {
        // cell header (4) + "nk"(2) + flags(2) + timestamp(8) + access(4) = 0x14 → parent field
        bins.patch_u32(child as usize + 4 + 0x10, off);
    }
    off
}

// ─── Base block & checksum ──────────────────────────────────────────────────

pub fn checksum(bytes: &[u8]) -> u32 {
    let mut acc: u32 = 0;
    for i in 0..127 {
        let o = i * 4;
        acc ^= u32::from_le_bytes([bytes[o], bytes[o + 1], bytes[o + 2], bytes[o + 3]]);
    }
    match acc {
        0xffff_ffff => 0xffff_fffe,
        0 => 1,
        v => v,
    }
}

pub fn base_block(
    primary: u32,
    secondary: u32,
    root_off: u32,
    data_size: u32,
    embedded_name: &str,
    file_type: u32,
    minor_version: u32,
) -> [u8; BASE_BLOCK] {
    let mut b = [0u8; BASE_BLOCK];
    b[0..4].copy_from_slice(b"regf");
    b[4..8].copy_from_slice(&primary.to_le_bytes());
    b[8..12].copy_from_slice(&secondary.to_le_bytes());
    b[12..20].copy_from_slice(&FILETIME_2024.to_le_bytes());
    b[0x14..0x18].copy_from_slice(&1u32.to_le_bytes());
    b[0x18..0x1c].copy_from_slice(&minor_version.to_le_bytes());
    b[0x1c..0x20].copy_from_slice(&file_type.to_le_bytes());
    b[0x20..0x24].copy_from_slice(&1u32.to_le_bytes());
    b[0x24..0x28].copy_from_slice(&root_off.to_le_bytes());
    b[0x28..0x2c].copy_from_slice(&data_size.to_le_bytes());
    b[0x2c..0x30].copy_from_slice(&1u32.to_le_bytes());
    let units: Vec<u16> = embedded_name.encode_utf16().collect();
    let tail: Vec<u16> = if units.len() > 32 { units[units.len() - 32..].to_vec() } else { units };
    for (i, u) in tail.iter().enumerate() {
        b[0x30 + i * 2..0x30 + i * 2 + 2].copy_from_slice(&u.to_le_bytes());
    }
    let sum = checksum(&b);
    b[0x1fc..0x200].copy_from_slice(&sum.to_le_bytes());
    b
}

/// Patch sequences/file type of an existing base block and fix the checksum.
pub fn patch_base_block(block: &mut [u8], primary: u32, secondary: u32, file_type: u32) {
    block[4..8].copy_from_slice(&primary.to_le_bytes());
    block[8..12].copy_from_slice(&secondary.to_le_bytes());
    block[0x1c..0x20].copy_from_slice(&file_type.to_le_bytes());
    let sum = checksum(block);
    block[0x1fc..0x200].copy_from_slice(&sum.to_le_bytes());
}

// ─── HvLE transaction logs ──────────────────────────────────────────────────

#[derive(Clone, Debug)]
pub struct LogEntryDef {
    pub sequence: u32,
    pub hbin_data_size: u32,
    /// (offset relative to hbin data start, page bytes)
    pub pages: Vec<(u32, Vec<u8>)>,
}

pub fn full_page_entry(sequence: u32, hbin: &[u8]) -> LogEntryDef {
    LogEntryDef {
        sequence,
        hbin_data_size: hbin.len() as u32,
        pages: vec![(0, hbin.to_vec())],
    }
}

/// Serialise one HvLE entry as Windows writes it: both Marvin32 hashes stored in full
/// (64 bits), Hash-1 over everything after the 40-byte header, Hash-2 over the first 32 bytes.
pub fn encode_log_entry(e: &LogEntryDef) -> Vec<u8> {
    let payload: usize = e.pages.iter().map(|(_, p)| p.len()).sum();
    let raw = 40 + 8 * e.pages.len() + payload;
    let size = raw.div_ceil(512) * 512;

    let mut out = Vec::with_capacity(size);
    out.extend_from_slice(b"HvLE");
    out.extend_from_slice(&(size as u32).to_le_bytes());
    out.extend_from_slice(&0u32.to_le_bytes());
    out.extend_from_slice(&e.sequence.to_le_bytes());
    out.extend_from_slice(&e.hbin_data_size.to_le_bytes());
    out.extend_from_slice(&(e.pages.len() as u32).to_le_bytes());
    out.resize(40, 0);
    for (off, page) in &e.pages {
        out.extend_from_slice(&off.to_le_bytes());
        out.extend_from_slice(&(page.len() as u32).to_le_bytes());
    }
    for (_, page) in &e.pages {
        out.extend_from_slice(page);
    }
    out.resize(size, 0);
    let h1 = marvin32(MARVIN_SEED, &out[40..]);
    out[24..32].copy_from_slice(&h1.to_le_bytes());
    let h2 = marvin32(MARVIN_SEED, &out[..32]);
    out[32..40].copy_from_slice(&h2.to_le_bytes());
    out
}

/// Build a complete `.LOG1`/`.LOG2` file for the hive whose bytes are `primary_hive`.
pub fn build_log(primary_hive: &[u8], entries: &[LogEntryDef]) -> Vec<u8> {
    let mut block = primary_hive[..512].to_vec();
    let seq = entries.first().map(|e| e.sequence).unwrap_or(1);
    patch_base_block(&mut block, seq, seq, 6);
    let mut out = block;
    for e in entries {
        out.extend_from_slice(&encode_log_entry(e));
    }
    out
}

pub struct DirtyFixture {
    pub primary: Vec<u8>,
    pub log1: Vec<u8>,
    pub log2: Option<Vec<u8>>,
}

/// A dirty primary (primary = secondary + 1) plus logs that turn it into `steps`
/// applied in order. With `split_logs` the first step lands in LOG1 and the
/// rest in LOG2 (how Windows alternates), otherwise everything is in LOG1.
pub fn build_dirty(base: &HiveBuilder, steps: &[&HiveBuilder], secondary: u32, split_logs: bool) -> DirtyFixture {
    let mut sizes = vec![base.hbin_region().len()];
    sizes.extend(steps.iter().map(|s| s.hbin_region().len()));
    let bin = *sizes.iter().max().unwrap();

    let mut base = base.clone();
    base.min_bin_size = bin;
    let primary = base.build_with(secondary + 1, secondary);

    let entries: Vec<LogEntryDef> = steps
        .iter()
        .enumerate()
        .map(|(k, s)| {
            let mut s = (*s).clone();
            s.min_bin_size = bin;
            full_page_entry(secondary + 1 + k as u32, &s.hbin_region())
        })
        .collect();

    if split_logs && entries.len() > 1 {
        DirtyFixture {
            log1: build_log(&primary, &entries[..1]),
            log2: Some(build_log(&primary, &entries[1..])),
            primary,
        }
    } else {
        DirtyFixture {
            log1: build_log(&primary, &entries),
            log2: None,
            primary,
        }
    }
}

/// Write `fixture` as `<rel>`, `<rel>.LOG1` and optionally `<rel>.LOG2`.
pub fn write_dirty(dir: &TempDir, rel: &str, fixture: &DirtyFixture) -> PathBuf {
    let hive = dir.write(rel, &fixture.primary);
    dir.write(&format!("{rel}.LOG1"), &fixture.log1);
    if let Some(l2) = &fixture.log2 {
        dir.write(&format!("{rel}.LOG2"), l2);
    }
    hive
}

/// Repo-relative fixture path.
pub fn fixture(rel: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests").join("fixtures").join(rel)
}

/// Collision-free suffix for temp file names: nanoseconds plus a process-wide
/// counter (Windows clocks tick every 100 ns and tests run in parallel).
#[allow(dead_code)]
pub fn unique_suffix() -> String {
    static SEQ: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let n = SEQ.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    format!("{}_{n}", chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0))
}
