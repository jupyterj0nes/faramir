//! Recovery of deleted registry keys and values from the free cells of a hive.
//!
//! When a key or value is deleted, Windows only flips the sign of its cell
//! size: the bytes stay in place until the space is reused. This module walks
//! every hive bin with its own bounds-checked parser (free cells may hold
//! garbage, so nothing here trusts a count or an offset without checking it),
//! rebuilds the path of each deleted key through the parent chain, and reports
//! the ones that live under a persistence location, plus orphan deleted values
//! whose data looks like a command line.

use std::collections::{HashMap, HashSet};
use std::io::{Cursor, Seek, SeekFrom};
use std::path::Path;

use super::diag;
use super::hives::{open_hive, HiveInfo, HiveKind, BASE_BLOCK_SIZE};
use super::techniques::{HiveSet, KeyRoot, Persistence, Root, TechniqueId};
use crate::errors::FaramirError;

const HBIN_HEADER: usize = 32;
const NK_FIXED: usize = 0x4c;
const VK_FIXED: usize = 0x14;
const MAX_VALUES_PER_KEY: u32 = 4096;
const MAX_DATA_BYTES: usize = 64 * 1024;
const MAX_NAME_BYTES: usize = 512;
const MAX_CHAIN: usize = 128;

/// Marker placed in [`Persistence::source`] for recovered findings.
pub const SOURCE_DELETED: &str = "deleted";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawKey {
    pub offset: u32,
    pub allocated: bool,
    pub name: String,
    pub parent: u32,
    pub timestamp_filetime: u64,
    pub values_count: u32,
    pub values_list: u32,
    pub is_root: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawValue {
    pub offset: u32,
    pub allocated: bool,
    pub name: String,
    pub data_type: u32,
    pub data: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeletedKey {
    pub key: RawKey,
    /// Root-relative path (`Microsoft\Windows\CurrentVersion\Run`) or, when the
    /// parent chain is broken, `?\<reachable tail>`.
    pub path: String,
    pub values: Vec<RawValue>,
}

#[derive(Debug, Default, Clone)]
pub struct DeletedScan {
    pub bins: usize,
    pub cells: usize,
    pub live_keys: usize,
    pub deleted_keys: Vec<DeletedKey>,
    pub orphan_values: Vec<RawValue>,
}

/// Bounds-checked view over a hive's bytes.
pub struct HiveImage {
    bytes: Vec<u8>,
    root_cell: u32,
}

fn u32_at(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}
fn u16_at(b: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([b[off], b[off + 1]])
}
fn u64_at(b: &[u8], off: usize) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[off..off + 8]);
    u64::from_le_bytes(a)
}

fn decode_name(raw: &[u8], ascii: bool) -> Option<String> {
    let s = if ascii {
        raw.iter().map(|&b| b as char).collect::<String>()
    } else {
        let units: Vec<u16> = raw.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
        String::from_utf16(&units).ok()?
    };
    if s.is_empty() || s.chars().any(|c| c.is_control()) {
        return None;
    }
    Some(s)
}

fn decode_utf16_string(raw: &[u8]) -> String {
    let units: Vec<u16> = raw.chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).take_while(|&u| u != 0).collect();
    String::from_utf16_lossy(&units)
}

impl HiveImage {
    pub fn new(bytes: Vec<u8>) -> Result<Self, FaramirError> {
        if bytes.len() < BASE_BLOCK_SIZE + HBIN_HEADER {
            return Err(FaramirError::HiveHeaderTruncated(format!("{} bytes", bytes.len())));
        }
        if &bytes[..4] != b"regf" {
            return Err(FaramirError::HiveSignatureInvalid("deleted-cell scan".into()));
        }
        let root_cell = u32_at(&bytes, 0x24);
        Ok(HiveImage { bytes, root_cell })
    }

    /// Bytes of a hive opened through the normal pipeline (transaction logs applied).
    pub fn from_info(info: &HiveInfo) -> Result<Self, FaramirError> {
        let mut opened = open_hive(info)?;
        let mut buf = Cursor::new(Vec::with_capacity(info.header.data_size as usize + BASE_BLOCK_SIZE));
        let bytes = if opened.recovery.opened_without_base_block || opened.hive.write_baseblock(&mut buf).is_err() {
            std::fs::read(&info.path).map_err(|e| FaramirError::HiveOpenFailed(format!("{}: {e}", info.path.display())))?
        } else {
            opened.hive.seek(SeekFrom::Start(0)).map_err(|e| FaramirError::HiveOpenFailed(e.to_string()))?;
            std::io::copy(&mut opened.hive, &mut buf).map_err(|e| FaramirError::HiveOpenFailed(e.to_string()))?;
            buf.into_inner()
        };
        Self::new(bytes)
    }

    fn region(&self) -> &[u8] {
        &self.bytes[BASE_BLOCK_SIZE..]
    }

    /// Cell at `off` (relative to the hive bins data): (allocated, payload after the size field).
    pub fn cell(&self, off: u32) -> Option<(bool, &[u8])> {
        let r = self.region();
        let o = off as usize;
        if o + 4 > r.len() || !o.is_multiple_of(8) {
            return None;
        }
        let raw = i32::from_le_bytes([r[o], r[o + 1], r[o + 2], r[o + 3]]);
        let size = raw.unsigned_abs() as usize;
        if size < 8 || !size.is_multiple_of(8) || o + size > r.len() {
            return None;
        }
        Some((raw < 0, &r[o + 4..o + size]))
    }

    fn parse_nk(&self, off: u32) -> Option<RawKey> {
        let (allocated, p) = self.cell(off)?;
        if p.len() < NK_FIXED || &p[..2] != b"nk" {
            return None;
        }
        let flags = u16_at(p, 2);
        let name_len = u16_at(p, 0x48) as usize;
        if name_len == 0 || name_len > MAX_NAME_BYTES || NK_FIXED + name_len > p.len() {
            return None;
        }
        let name = decode_name(&p[NK_FIXED..NK_FIXED + name_len], flags & 0x20 != 0)?;
        Some(RawKey {
            offset: off,
            allocated,
            name,
            parent: u32_at(p, 0x10),
            timestamp_filetime: u64_at(p, 0x04),
            values_count: u32_at(p, 0x24),
            values_list: u32_at(p, 0x28),
            is_root: flags & 0x04 != 0 || off == self.root_cell,
        })
    }

    fn parse_vk(&self, off: u32) -> Option<RawValue> {
        let (allocated, p) = self.cell(off)?;
        if p.len() < VK_FIXED || &p[..2] != b"vk" {
            return None;
        }
        let name_len = u16_at(p, 2) as usize;
        let data_size = u32_at(p, 4);
        let data_field = u32_at(p, 8);
        let data_type = u32_at(p, 12);
        let flags = u16_at(p, 16);
        if name_len > MAX_NAME_BYTES || VK_FIXED + name_len > p.len() {
            return None;
        }
        let name = if name_len == 0 {
            "(Default)".to_string()
        } else {
            decode_name(&p[VK_FIXED..VK_FIXED + name_len], flags & 1 != 0)?
        };
        let data = self.string_data(data_size, data_field, data_type);
        Some(RawValue { offset: off, allocated, name, data_type, data })
    }

    fn string_data(&self, data_size: u32, data_field: u32, data_type: u32) -> Option<String> {
        if data_type != 1 && data_type != 2 {
            return None;
        }
        let len = (data_size & 0x7fff_ffff) as usize;
        if data_size & 0x8000_0000 != 0 {
            let bytes = data_field.to_le_bytes();
            return Some(decode_utf16_string(&bytes[..len.min(4)]));
        }
        if len == 0 || len > MAX_DATA_BYTES {
            return None;
        }
        let (_, p) = self.cell(data_field)?;
        if p.len() < len {
            return None;
        }
        Some(decode_utf16_string(&p[..len]))
    }

    fn values_of(&self, key: &RawKey, referenced: &mut HashSet<u32>) -> Vec<RawValue> {
        let count = key.values_count;
        if count == 0 || count > MAX_VALUES_PER_KEY || key.values_list == 0xffff_ffff {
            return Vec::new();
        }
        let Some((_, list)) = self.cell(key.values_list) else { return Vec::new() };
        let mut out = Vec::new();
        for i in 0..count as usize {
            if (i + 1) * 4 > list.len() {
                break;
            }
            let vk_off = u32_at(list, i * 4);
            if let Some(v) = self.parse_vk(vk_off) {
                referenced.insert(vk_off);
                out.push(v);
            }
        }
        out
    }

    /// Walk every hive bin and classify its cells.
    pub fn scan(&self) -> DeletedScan {
        let r = self.region();
        let mut scan = DeletedScan::default();
        let mut keys: HashMap<u32, RawKey> = HashMap::new();
        let mut free_vk: Vec<u32> = Vec::new();

        let mut pos = 0usize;
        while pos + HBIN_HEADER <= r.len() {
            if &r[pos..pos + 4] != b"hbin" {
                pos += 4096;
                continue;
            }
            let size = u32_at(r, pos + 8) as usize;
            if size == 0 || !size.is_multiple_of(4096) || pos + size > r.len() {
                pos += 4096;
                continue;
            }
            scan.bins += 1;
            let end = pos + size;
            let mut c = pos + HBIN_HEADER;
            while c + 8 <= end {
                let raw = i32::from_le_bytes([r[c], r[c + 1], r[c + 2], r[c + 3]]);
                let csize = raw.unsigned_abs() as usize;
                if csize < 8 || !csize.is_multiple_of(8) || c + csize > end {
                    break;
                }
                scan.cells += 1;
                let magic = &r[c + 4..c + 6];
                let off = c as u32;
                if magic == b"nk" {
                    if let Some(k) = self.parse_nk(off) {
                        if k.allocated {
                            scan.live_keys += 1;
                        }
                        keys.insert(off, k);
                    }
                } else if magic == b"vk" && raw > 0 {
                    free_vk.push(off);
                }
                c += csize;
            }
            pos = end;
        }

        let mut referenced: HashSet<u32> = HashSet::new();
        let mut deleted: Vec<DeletedKey> = Vec::new();
        for key in keys.values().filter(|k| !k.allocated) {
            let path = self.resolve_path(key, &keys);
            let values = self.values_of(key, &mut referenced);
            deleted.push(DeletedKey { key: key.clone(), path, values });
        }
        deleted.sort_by(|a, b| a.path.cmp(&b.path).then(a.key.offset.cmp(&b.key.offset)));
        scan.deleted_keys = deleted;

        for off in free_vk {
            if referenced.contains(&off) {
                continue;
            }
            if let Some(v) = self.parse_vk(off) {
                scan.orphan_values.push(v);
            }
        }
        scan
    }

    fn resolve_path(&self, key: &RawKey, keys: &HashMap<u32, RawKey>) -> String {
        let mut parts = vec![key.name.clone()];
        let mut cur = key.parent;
        let mut hops = 0;
        loop {
            if cur == self.root_cell {
                parts.reverse();
                return parts.join("\\");
            }
            hops += 1;
            if hops > MAX_CHAIN {
                break;
            }
            match keys.get(&cur) {
                Some(p) if p.is_root => {
                    parts.reverse();
                    return parts.join("\\");
                }
                Some(p) => {
                    parts.push(p.name.clone());
                    cur = p.parent;
                }
                None => break,
            }
        }
        parts.push("?".to_string());
        parts.reverse();
        parts.join("\\")
    }
}

// ─── matching against persistence locations ─────────────────────────────────

/// SYSTEM-hive locations, relative to `ControlSetNNN\`.
const SYSTEM_LOCATIONS: &[(&str, TechniqueId)] = &[
    (r"Services\W32Time\TimeProviders", TechniqueId::TimeProviders),
    (r"Control\Print\Monitors", TechniqueId::PrintMonitors),
    (r"Control\Session Manager\AppCertDlls", TechniqueId::AppCertDlls),
    (r"Control\Session Manager", TechniqueId::BootExecute),
    (r"Control\Lsa", TechniqueId::LsaPackages),
    (r"Control\ContentIndex\Language", TechniqueId::NldpDllOverridePath),
    (r"Services", TechniqueId::WindowsServices),
];

fn strip_control_set(path: &str) -> Option<&str> {
    let upper = path.to_uppercase();
    if !upper.starts_with("CONTROLSET") {
        return None;
    }
    let rest = &path[10..];
    let digits = rest.chars().take_while(|c| c.is_ascii_digit()).count();
    if digits == 0 {
        return None;
    }
    rest[digits..].strip_prefix('\\')
}

fn path_under(path: &str, root: &str) -> bool {
    let p = path.to_uppercase();
    let r = root.to_uppercase();
    p == r || p.starts_with(&format!("{r}\\"))
}

/// Which technique a deleted key path belongs to, for a hive of `kind`.
pub fn classify_deleted_path(path: &str, kind: HiveKind) -> Option<(TechniqueId, &'static str)> {
    let path = path.strip_prefix("?\\").unwrap_or(path);
    if kind == HiveKind::System || kind == HiveKind::Unknown {
        if let Some(rel) = strip_control_set(path) {
            for (loc, id) in SYSTEM_LOCATIONS {
                if path_under(rel, loc) {
                    return Some((*id, "System"));
                }
            }
        }
    }
    let mut best: Option<(usize, TechniqueId, &'static str)> = None;
    for id in TechniqueId::ALL {
        for kr in id.roots() {
            if kr.root == Root::System || !kr.root.accepts(kind) {
                continue;
            }
            if path_under(path, kr.path) {
                let depth = kr.path.len();
                if best.is_none_or(|(d, _, _)| depth > d) {
                    best = Some((depth, id, kr.access));
                }
            }
        }
    }
    best.map(|(_, id, access)| (id, access))
}

fn looks_executable(data: &str) -> bool {
    let d = data.trim().to_lowercase();
    if d.is_empty() {
        return false;
    }
    let ext = [".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".scr", ".com", ".msi", ".hta", ".lnk"];
    ext.iter().any(|e| d.contains(e)) || (d.contains(":\\") && d.len() > 4)
}

fn filetime_to_string(ft: u64) -> String {
    crate::utils::filetime_to_iso(ft)
        .and_then(|iso| chrono::DateTime::parse_from_rfc3339(&iso).ok())
        .map(|dt| dt.with_timezone(&chrono::Utc).format(super::techniques::FORMAT_DATE).to_string())
        .unwrap_or_default()
}

/// Deleted persistence found in one hive, as findings.
pub fn findings_for_hive(info: &HiveInfo, scan: &DeletedScan) -> Vec<Persistence> {
    let origin = info.path.to_string_lossy().to_string();
    let mut out = Vec::new();
    for dk in &scan.deleted_keys {
        let Some((id, access)) = classify_deleted_path(&dk.path, info.kind) else { continue };
        let ts = filetime_to_string(dk.key.timestamp_filetime);
        let strings: Vec<&RawValue> = dk.values.iter().filter(|v| v.data.as_deref().is_some_and(|d| !d.trim().is_empty())).collect();
        if strings.is_empty() {
            out!("\t[deleted key] {}", dk.path);
            out.push(Persistence {
                timestamp: ts,
                technique: id.label().to_string(),
                path: format!("deleted key {}", dk.path),
                value: dk.key.name.clone(),
                access_gained: access.to_string(),
                source: SOURCE_DELETED.to_string(),
                origin: origin.clone(),
            });
            continue;
        }
        for v in strings {
            let data = v.data.clone().unwrap_or_default();
            out!("\t[deleted key] {} \\ {} = {}", dk.path, v.name, data);
            out.push(Persistence {
                timestamp: ts.clone(),
                technique: id.label().to_string(),
                path: format!("deleted key {}\\{}", dk.path, v.name),
                value: data,
                access_gained: access.to_string(),
                source: SOURCE_DELETED.to_string(),
                origin: origin.clone(),
            });
        }
    }
    for v in &scan.orphan_values {
        let Some(data) = &v.data else { continue };
        if !looks_executable(data) {
            continue;
        }
        out!("\t[deleted value] {} = {}", v.name, data);
        out.push(Persistence {
            timestamp: String::new(),
            technique: TechniqueId::DeletedRegistry.label().to_string(),
            path: format!("deleted value {} (key unknown)", v.name),
            value: data.clone(),
            access_gained: "Unknown".to_string(),
            source: SOURCE_DELETED.to_string(),
            origin: origin.clone(),
        });
    }
    out
}

/// Scan one hive file.
pub fn scan_hive(info: &HiveInfo) -> Result<DeletedScan, FaramirError> {
    let image = HiveImage::from_info(info)?;
    Ok(image.scan())
}

/// Scan every hive of the set, reusing the instances the techniques opened.
pub fn scan_set(set: &mut HiveSet) -> Vec<Persistence> {
    out!("+ Recovering deleted registry keys and values.");
    let mut out = Vec::new();
    for idx in 0..set.len() {
        let Some(info) = set.info(idx).cloned() else { continue };
        let Some(bytes) = set.hive_bytes(idx) else { continue };
        match std::panic::catch_unwind(move || HiveImage::new(bytes).map(|img| img.scan())) {
            Ok(Ok(scan)) => {
                if !scan.deleted_keys.is_empty() || !scan.orphan_values.is_empty() {
                    out!(
                        "\t{}: {} deleted key(s), {} orphan value(s) in {} cell(s)",
                        info.path.display(),
                        scan.deleted_keys.len(),
                        scan.orphan_values.len(),
                        scan.cells
                    );
                }
                out.extend(findings_for_hive(&info, &scan));
            }
            Ok(Err(e)) => {
                diag::record(e);
            }
            Err(p) => {
                diag::record(FaramirError::TechniquePanicked(format!(
                    "deleted-cell scan on {}: {}",
                    info.path.display(),
                    diag::panic_message(&*p)
                )));
            }
        }
    }
    out
}

/// Convenience for tests and tooling: scan a hive file on disk.
pub fn scan_path(path: &Path) -> Result<DeletedScan, FaramirError> {
    let info = super::hives::classify_hive(path, path.parent().unwrap_or(path))?;
    scan_hive(&info)
}

#[allow(dead_code)]
fn _roots_are_static(_: &KeyRoot) {}
