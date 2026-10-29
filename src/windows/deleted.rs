//! Recovery of deleted registry keys and values from the free cells of a hive.
//!
//! When a key or value is deleted, Windows only flips the sign of its cell
//! size: the bytes stay in place until the space is reused. This module walks
//! every hive bin with its own bounds-checked parser (free cells may hold
//! garbage, so nothing here trusts a count or an offset without checking it),
//! rebuilds the path of each deleted key through the parent chain, and reports
//! the ones that live under a persistence location, plus orphan deleted values
//! whose data looks like a command line.

use std::io::{Cursor, Seek, SeekFrom};
use std::path::Path;

use super::diag;
use super::hives::{open_hive, HiveInfo, HiveKind, BASE_BLOCK_SIZE};
use super::techniques::{HiveSet, KeyRoot, Persistence, Root, TechniqueId};
use crate::errors::FaramirError;

const HBIN_HEADER: usize = 32;

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
    /// Text of a `REG_SZ` / `REG_EXPAND_SZ` value.
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

fn key_from(k: blockcarve::hive_cells::RawKey) -> RawKey {
    RawKey {
        offset: k.offset,
        allocated: k.allocated,
        name: k.name,
        parent: k.parent,
        timestamp_filetime: k.timestamp_filetime,
        values_count: k.values_count,
        values_list: k.values_list,
        is_root: k.is_root,
    }
}

fn value_from(v: blockcarve::hive_cells::RawValue) -> RawValue {
    use blockcarve::hive_cells::{REG_EXPAND_SZ, REG_SZ};
    let data = if matches!(v.data_type, REG_SZ | REG_EXPAND_SZ) { v.text() } else { None };
    RawValue { offset: v.offset, allocated: v.allocated, name: v.name, data_type: v.data_type, data }
}

/// Bounds-checked view over a hive's bytes. The cell walker is
/// `blockcarve::hive_cells`, shared with caarea and masstin; this type keeps
/// faramir's error codes and its pipeline entry point.
pub struct HiveImage {
    bytes: Vec<u8>,
}

impl HiveImage {
    pub fn new(bytes: Vec<u8>) -> Result<Self, FaramirError> {
        if bytes.len() < BASE_BLOCK_SIZE + HBIN_HEADER {
            return Err(FaramirError::HiveHeaderTruncated(format!("{} bytes", bytes.len())));
        }
        if &bytes[..4] != b"regf" {
            return Err(FaramirError::HiveSignatureInvalid("deleted-cell scan".into()));
        }
        Ok(HiveImage { bytes })
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

    fn image(&self) -> blockcarve::hive_cells::HiveImage<'_> {
        blockcarve::hive_cells::HiveImage::new(&self.bytes).expect("checked in HiveImage::new")
    }

    /// Cell at `off` (relative to the hive bins data): (allocated, payload after the size field).
    pub fn cell(&self, off: u32) -> Option<(bool, &[u8])> {
        let r = &self.bytes[BASE_BLOCK_SIZE..];
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

    /// Walk every hive bin and classify its cells.
    pub fn scan(&self) -> DeletedScan {
        let s = self.image().scan();
        DeletedScan {
            bins: s.bins,
            cells: s.cells,
            live_keys: s.live_keys,
            deleted_keys: s
                .deleted_keys
                .into_iter()
                .map(|dk| DeletedKey { key: key_from(dk.key), path: dk.path, values: dk.values.into_iter().map(value_from).collect() })
                .collect(),
            orphan_values: s.orphan_values.into_iter().map(value_from).collect(),
        }
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
    (r"Control\SecurityProviders", TechniqueId::SecurityProviders),
    (r"Control\NetworkProvider", TechniqueId::NetworkProviders),
    (r"Control\Terminal Server", TechniqueId::TerminalServerPrograms),
    (r"Control\Session Manager\Environment", TechniqueId::CorProfiler),
    (r"Control\SafeBoot", TechniqueId::SafeBootAlternateShell),
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
            if kr.root == Root::System || !kr.root.accepts(kind) || kr.path.is_empty() {
                continue;
            }
            if path_under(path, kr.path) && deleted_path_marker_ok(id, path) {
                let depth = kr.path.len();
                if best.is_none_or(|(d, _, _)| depth > d) {
                    best = Some((depth, id, kr.access));
                }
            }
        }
    }
    best.map(|(_, id, access)| (id, access))
}

/// Techniques rooted at a wide subtree (`Microsoft\Office`, `Classes`) only
/// claim a deleted key when the path shows the persistence location itself.
fn deleted_path_marker_ok(id: TechniqueId, path: &str) -> bool {
    let p = path.to_uppercase();
    let any = |markers: &[&str]| markers.iter().any(|m| p.contains(&m.to_uppercase()));
    match id {
        TechniqueId::OfficeAddins => any(&["\\ADDINS", "\\EXCEL\\OPTIONS"]),
        TechniqueId::FileAssociations => any(&["\\SHELL\\OPEN\\COMMAND"]),
        TechniqueId::ShellExtensions => any(&["\\SHELLEX\\", "BROWSER HELPER OBJECTS", "SHELLEXECUTEHOOKS", "SHELLICONOVERLAYIDENTIFIERS"]),
        TechniqueId::ComTreatAs => any(&["\\TREATAS"]),
        TechniqueId::ComHijacking => any(&["SERVER32"]) || !any(&["\\TREATAS"]),
        _ => true,
    }
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
