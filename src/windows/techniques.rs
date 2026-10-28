//! Every Windows persistence technique, with its registry roots declared explicitly.
//!
//! A registry path only makes sense relative to the hive it lives in:
//! `SOFTWARE\Microsoft\Windows\CurrentVersion\Run` exists under the root of
//! `NTUSER.DAT` (HKCU), while the same autostart in the `SOFTWARE` hive is
//! `Microsoft\Windows\CurrentVersion\Run` (the hive *is* HKLM\SOFTWARE).
//! Each [`KeyRoot`] therefore names the [`Root`] it applies to and the engine
//! only tries it against hives of that kind (or of unknown kind, so renamed
//! hives never lose detections).

use std::cell::RefCell;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::rc::Rc;

use chrono::Utc;
use nt_hive2::{KeyNode, KeyValue, RegistryValue, SubPath};
use walkdir::WalkDir;

use super::diag;
use super::hives::{classify_hive, discover_hives, open_hive, HiveFile, HiveInfo, HiveKind, OpenedHive, RecoveryReport};
use crate::errors::FaramirError;

pub const FORMAT_DATE: &str = "%Y-%m-%d %H:%M:%S%.3f";

// ─── Data model ─────────────────────────────────────────────────────────────

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Persistence {
    pub timestamp: String,
    pub technique: String,
    pub path: String,
    pub value: String,
    pub access_gained: String,
    /// Empty for the live volume; `vss:<store>:<created>` when the finding
    /// comes from a Volume Shadow Copy and is no longer present live.
    pub source: String,
    /// File the finding was read from (hive, task XML, profile…), stamped by the engine.
    pub origin: String,
}

/// Logical registry root a key path is relative to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Root {
    /// HKLM\SOFTWARE  (hive file `SOFTWARE`)
    Software,
    /// HKLM\SYSTEM    (hive file `SYSTEM`)
    System,
    /// HKCU / HKU\.DEFAULT (hive files `NTUSER.DAT`, `DEFAULT`)
    UserProfile,
    /// HKCU\Software\Classes (hive file `UsrClass.dat`)
    UsrClass,
}

impl Root {
    pub fn label(&self) -> &'static str {
        match self {
            Root::Software => "HKLM\\SOFTWARE",
            Root::System => "HKLM\\SYSTEM",
            Root::UserProfile => "HKCU",
            Root::UsrClass => "HKCU\\Software\\Classes",
        }
    }

    /// Can a hive of `kind` be scanned with paths relative to this root?
    pub fn accepts(&self, kind: HiveKind) -> bool {
        if kind == HiveKind::Unknown {
            return true;
        }
        match self {
            Root::Software => kind == HiveKind::Software,
            Root::System => kind == HiveKind::System,
            Root::UserProfile => kind.is_user_profile(),
            Root::UsrClass => kind == HiveKind::UsrClass,
        }
    }
}

/// A registry key path relative to a [`Root`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyRoot {
    pub root: Root,
    pub path: &'static str,
    pub access: &'static str,
}

const fn kr(root: Root, path: &'static str, access: &'static str) -> KeyRoot {
    KeyRoot { root, path, access }
}

// ─── Key tables ─────────────────────────────────────────────────────────────

pub const RUN_ROOTS: &[KeyRoot] = &[
    kr(Root::UserProfile, r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "User"),
    kr(Root::Software, r"Microsoft\Windows\CurrentVersion\Run", "System"),
    kr(Root::Software, r"Wow6432Node\Microsoft\Windows\CurrentVersion\Run", "System"),
];
pub const RUNONCE_ROOTS: &[KeyRoot] = &[
    kr(Root::UserProfile, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "User"),
    kr(Root::Software, r"Microsoft\Windows\CurrentVersion\RunOnce", "System"),
    kr(Root::Software, r"Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce", "System"),
];
pub const RUNEX_ROOTS: &[KeyRoot] = &[
    kr(Root::UserProfile, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunEx", "User"),
    kr(Root::Software, r"Microsoft\Windows\CurrentVersion\RunEx", "System"),
    kr(Root::Software, r"Wow6432Node\Microsoft\Windows\CurrentVersion\RunEx", "System"),
];
pub const RUNONCEEX_ROOTS: &[KeyRoot] = &[
    kr(Root::UserProfile, r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx", "User"),
    kr(Root::Software, r"Microsoft\Windows\CurrentVersion\RunOnceEx", "System"),
    kr(Root::Software, r"Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnceEx", "System"),
];
pub const IFEO_ROOTS: &[KeyRoot] = &[
    kr(Root::Software, r"Microsoft\Windows NT\CurrentVersion\Image File Execution Options", "System"),
    kr(Root::Software, r"Wow6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options", "System"),
];
pub const AEDEBUG_ROOTS: &[KeyRoot] = &[
    kr(Root::Software, r"Microsoft\Windows NT\CurrentVersion\AeDebug", "System"),
    kr(Root::Software, r"Wow6432Node\Microsoft\Windows NT\CurrentVersion\AeDebug", "System"),
];
pub const WER_HANGS_ROOTS: &[KeyRoot] = &[
    kr(Root::Software, r"Microsoft\Windows\Windows Error Reporting\Hangs", "System"),
    kr(Root::UserProfile, r"SOFTWARE\Microsoft\Windows\Windows Error Reporting\Hangs", "User"),
];
pub const CMD_AUTORUN_ROOTS: &[KeyRoot] = &[
    kr(Root::UserProfile, r"Software\Microsoft\Command Processor", "User"),
    kr(Root::Software, r"Microsoft\Command Processor", "System"),
];
pub const EXPLORER_WINDOWS_ROOTS: &[KeyRoot] = &[
    kr(Root::UserProfile, r"Software\Microsoft\Windows NT\CurrentVersion\Windows", "User"),
    kr(Root::Software, r"Microsoft\Windows NT\CurrentVersion\Windows", "System"),
];
pub const WINLOGON_ROOTS: &[KeyRoot] = &[
    kr(Root::UserProfile, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "User"),
    kr(Root::Software, r"Microsoft\Windows NT\CurrentVersion\Winlogon", "System"),
];
pub const APP_PATHS_ROOTS: &[KeyRoot] = &[
    kr(Root::UserProfile, r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths", "User"),
    kr(Root::Software, r"Microsoft\Windows\CurrentVersion\App Paths", "System"),
    kr(Root::Software, r"Wow6432Node\Microsoft\Windows\CurrentVersion\App Paths", "System"),
];
pub const GP_EXTENSIONS_ROOTS: &[KeyRoot] = &[
    kr(Root::Software, r"Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions", "System"),
    kr(Root::UserProfile, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions", "User"),
];
pub const CHM_HELPER_ROOTS: &[KeyRoot] = &[
    kr(Root::UserProfile, r"Software\Microsoft\HtmlHelp Author", "User"),
    kr(Root::Software, r"Microsoft\HtmlHelp Author", "System"),
];
pub const TASKCACHE_ROOTS: &[KeyRoot] = &[
    kr(Root::Software, r"Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks", "System"),
];
pub const ENVIRONMENT_ROOTS: &[KeyRoot] = &[
    kr(Root::UserProfile, r"Environment", "User"),
];
pub const HHCTRL_ROOTS: &[KeyRoot] = &[
    kr(Root::Software, r"Classes\CLSID\{52A2AAAE-085D-4187-97EA-8C30DB990436}\InprocServer32", "System"),
    kr(Root::Software, r"Classes\Wow6432Node\CLSID\{52A2AAAE-085D-4187-97EA-8C30DB990436}\InprocServer32", "System"),
    kr(Root::UserProfile, r"Software\Classes\CLSID\{52A2AAAE-085D-4187-97EA-8C30DB990436}\InprocServer32", "User"),
    kr(Root::UsrClass, r"CLSID\{52A2AAAE-085D-4187-97EA-8C30DB990436}\InprocServer32", "User"),
];
pub const APPINIT_ROOTS: &[KeyRoot] = &[
    kr(Root::Software, r"Microsoft\Windows NT\CurrentVersion\Windows", "System"),
    kr(Root::Software, r"Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows", "System"),
];
pub const ACTIVE_SETUP_ROOTS: &[KeyRoot] = &[
    kr(Root::Software, r"Microsoft\Active Setup\Installed Components", "System"),
    kr(Root::Software, r"Wow6432Node\Microsoft\Active Setup\Installed Components", "System"),
    kr(Root::UserProfile, r"SOFTWARE\Microsoft\Active Setup\Installed Components", "User"),
];
pub const SCREENSAVER_ROOTS: &[KeyRoot] = &[
    kr(Root::UserProfile, r"Control Panel\Desktop", "User"),
];
pub const SILENT_PROCESS_EXIT_ROOTS: &[KeyRoot] = &[
    kr(Root::Software, r"Microsoft\Windows NT\CurrentVersion\SilentProcessExit", "System"),
    kr(Root::Software, r"Wow6432Node\Microsoft\Windows NT\CurrentVersion\SilentProcessExit", "System"),
];
pub const COM_CLSID_ROOTS: &[KeyRoot] = &[
    kr(Root::UserProfile, r"Software\Classes\CLSID", "User"),
    kr(Root::UsrClass, r"CLSID", "User"),
];
pub const NETSH_ROOTS: &[KeyRoot] = &[
    kr(Root::Software, r"Microsoft\NetSh", "System"),
    kr(Root::Software, r"Wow6432Node\Microsoft\NetSh", "System"),
];
/// SYSTEM-hive techniques resolve `ControlSetNNN` first; these are the sub paths.
pub const SYSTEM_ONLY: &[KeyRoot] = &[kr(Root::System, "", "System")];

// ─── Technique catalogue ────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TechniqueId {
    Run,
    RunOnce,
    RunEx,
    RunOnceEx,
    ImageFileExecutionOptions,
    NldpDllOverridePath,
    AeDebug,
    WerFaultHangs,
    CmdAutorun,
    ExplorerLoad,
    WinlogonUserinit,
    WinlogonShell,
    TerminalProfileStartOnUserLogin,
    AppCertDlls,
    AppPaths,
    ServiceDlls,
    GpExtensionDlls,
    WinlogonMpNotify,
    ChmHelperDll,
    StartupPrograms,
    ScheduledTasks,
    WindowsServices,
    UserInitMprScript,
    HhCtrlHijacking,
    AppInitDlls,
    LsaPackages,
    BootExecute,
    ActiveSetup,
    Screensaver,
    SilentProcessExit,
    ComHijacking,
    PrintMonitors,
    TimeProviders,
    NetshHelperDlls,
    PowerShellProfiles,
    /// Deleted keys/values recovered from free hive cells (see `windows::deleted`).
    DeletedRegistry,
}

impl TechniqueId {
    pub const ALL: [TechniqueId; 36] = [
        TechniqueId::Run,
        TechniqueId::RunOnce,
        TechniqueId::RunEx,
        TechniqueId::RunOnceEx,
        TechniqueId::ImageFileExecutionOptions,
        TechniqueId::NldpDllOverridePath,
        TechniqueId::AeDebug,
        TechniqueId::WerFaultHangs,
        TechniqueId::CmdAutorun,
        TechniqueId::ExplorerLoad,
        TechniqueId::WinlogonUserinit,
        TechniqueId::WinlogonShell,
        TechniqueId::TerminalProfileStartOnUserLogin,
        TechniqueId::AppCertDlls,
        TechniqueId::AppPaths,
        TechniqueId::ServiceDlls,
        TechniqueId::GpExtensionDlls,
        TechniqueId::WinlogonMpNotify,
        TechniqueId::ChmHelperDll,
        TechniqueId::StartupPrograms,
        TechniqueId::ScheduledTasks,
        TechniqueId::WindowsServices,
        TechniqueId::UserInitMprScript,
        TechniqueId::HhCtrlHijacking,
        TechniqueId::AppInitDlls,
        TechniqueId::LsaPackages,
        TechniqueId::BootExecute,
        TechniqueId::ActiveSetup,
        TechniqueId::Screensaver,
        TechniqueId::SilentProcessExit,
        TechniqueId::ComHijacking,
        TechniqueId::PrintMonitors,
        TechniqueId::TimeProviders,
        TechniqueId::NetshHelperDlls,
        TechniqueId::PowerShellProfiles,
        TechniqueId::DeletedRegistry,
    ];

    pub fn label(&self) -> &'static str {
        match self {
            TechniqueId::Run => "Registry Run Key",
            TechniqueId::RunOnce => "Registry RunOnce Key",
            TechniqueId::RunEx => "Registry RunEx Key",
            TechniqueId::RunOnceEx => "Registry RunOnceEx Key",
            TechniqueId::ImageFileExecutionOptions => "Image file execution options",
            TechniqueId::NldpDllOverridePath => "Natural Language Development Platform 6 DLL Override Path",
            TechniqueId::AeDebug => "AEDebug Custom Debugger",
            TechniqueId::WerFaultHangs => "Windows Error Reporting Debugger",
            TechniqueId::CmdAutorun => "Command Processor AutoRun key",
            TechniqueId::ExplorerLoad => "Explorer Load Property",
            TechniqueId::WinlogonUserinit => "Winlogon Userinit Property",
            TechniqueId::WinlogonShell => "Winlogon shell Property",
            TechniqueId::TerminalProfileStartOnUserLogin => "Windows Terminal startOnUserLogin",
            TechniqueId::AppCertDlls => "AppCertDlls properties.",
            TechniqueId::AppPaths => "App Paths",
            TechniqueId::ServiceDlls => "ServiceDll Hijacking",
            TechniqueId::GpExtensionDlls => "Group Policy Extension DLL",
            TechniqueId::WinlogonMpNotify => "MPNotify",
            TechniqueId::ChmHelperDll => "CHMHelperDll",
            TechniqueId::StartupPrograms => "Startup Folder",
            TechniqueId::ScheduledTasks => "Scheduled Task",
            TechniqueId::WindowsServices => "Windows Service",
            TechniqueId::UserInitMprScript => "User Init Mpr Logon Script",
            TechniqueId::HhCtrlHijacking => "Hijacking of hhctrl.ocx",
            TechniqueId::AppInitDlls => "AppInit DLLs",
            TechniqueId::LsaPackages => "LSA Packages",
            TechniqueId::BootExecute => "Boot Execute",
            TechniqueId::ActiveSetup => "Active Setup StubPath",
            TechniqueId::Screensaver => "Screensaver",
            TechniqueId::SilentProcessExit => "Silent Process Exit Monitor",
            TechniqueId::ComHijacking => "COM Object Hijacking",
            TechniqueId::PrintMonitors => "Print Monitor DLL",
            TechniqueId::TimeProviders => "Time Provider DLL",
            TechniqueId::NetshHelperDlls => "Netsh Helper DLL",
            TechniqueId::PowerShellProfiles => "PowerShell Profile Script",
            TechniqueId::DeletedRegistry => "Deleted Registry Persistence",
        }
    }

    /// Registry roots the technique reads (empty for filesystem-only techniques).
    pub fn roots(&self) -> &'static [KeyRoot] {
        match self {
            TechniqueId::Run => RUN_ROOTS,
            TechniqueId::RunOnce => RUNONCE_ROOTS,
            TechniqueId::RunEx => RUNEX_ROOTS,
            TechniqueId::RunOnceEx => RUNONCEEX_ROOTS,
            TechniqueId::ImageFileExecutionOptions => IFEO_ROOTS,
            TechniqueId::NldpDllOverridePath => SYSTEM_ONLY,
            TechniqueId::AeDebug => AEDEBUG_ROOTS,
            TechniqueId::WerFaultHangs => WER_HANGS_ROOTS,
            TechniqueId::CmdAutorun => CMD_AUTORUN_ROOTS,
            TechniqueId::ExplorerLoad => EXPLORER_WINDOWS_ROOTS,
            TechniqueId::WinlogonUserinit => WINLOGON_ROOTS,
            TechniqueId::WinlogonShell => WINLOGON_ROOTS,
            TechniqueId::TerminalProfileStartOnUserLogin => &[],
            TechniqueId::AppCertDlls => SYSTEM_ONLY,
            TechniqueId::AppPaths => APP_PATHS_ROOTS,
            TechniqueId::ServiceDlls => SYSTEM_ONLY,
            TechniqueId::GpExtensionDlls => GP_EXTENSIONS_ROOTS,
            TechniqueId::WinlogonMpNotify => WINLOGON_ROOTS,
            TechniqueId::ChmHelperDll => CHM_HELPER_ROOTS,
            TechniqueId::StartupPrograms => &[],
            TechniqueId::ScheduledTasks => TASKCACHE_ROOTS,
            TechniqueId::WindowsServices => SYSTEM_ONLY,
            TechniqueId::UserInitMprScript => ENVIRONMENT_ROOTS,
            TechniqueId::HhCtrlHijacking => HHCTRL_ROOTS,
            TechniqueId::AppInitDlls => APPINIT_ROOTS,
            TechniqueId::LsaPackages => SYSTEM_ONLY,
            TechniqueId::BootExecute => SYSTEM_ONLY,
            TechniqueId::ActiveSetup => ACTIVE_SETUP_ROOTS,
            TechniqueId::Screensaver => SCREENSAVER_ROOTS,
            TechniqueId::SilentProcessExit => SILENT_PROCESS_EXIT_ROOTS,
            TechniqueId::ComHijacking => COM_CLSID_ROOTS,
            TechniqueId::PrintMonitors => SYSTEM_ONLY,
            TechniqueId::TimeProviders => SYSTEM_ONLY,
            TechniqueId::NetshHelperDlls => NETSH_ROOTS,
            TechniqueId::PowerShellProfiles => &[],
            TechniqueId::DeletedRegistry => &[],
        }
    }

    pub fn is_registry_based(&self) -> bool {
        !self.roots().is_empty() || *self == TechniqueId::DeletedRegistry
    }

    /// Hive kinds this technique can read something from.
    pub fn hive_kinds(&self) -> Vec<HiveKind> {
        let mut kinds = Vec::new();
        for r in self.roots() {
            for k in HiveKind::ALL {
                if k != HiveKind::Unknown && r.root.accepts(k) && !kinds.contains(&k) {
                    kinds.push(k);
                }
            }
        }
        kinds
    }
}

// ─── Hive set (opened lazily, each hive once) ───────────────────────────────

enum HiveState {
    Unopened,
    Open(Box<OpenedHive>),
    Failed,
}

struct HiveEntry {
    info: HiveInfo,
    state: HiveState,
}

/// The hives of one evidence target. Hives are opened (and their logs
/// replayed) once, on first use, and shared by every technique.
pub struct HiveSet {
    entries: Vec<HiveEntry>,
}

impl HiveSet {
    pub fn new(infos: Vec<HiveInfo>) -> Self {
        HiveSet {
            entries: infos
                .into_iter()
                .map(|info| HiveEntry {
                    info,
                    state: HiveState::Unopened,
                })
                .collect(),
        }
    }

    pub fn empty() -> Self {
        HiveSet { entries: Vec::new() }
    }

    /// Walk a directory (or take a single file) and queue every hive found.
    pub fn discover(root: &Path) -> Self {
        Self::new(discover_hives(root))
    }

    /// Queue explicit files; classification failures are recorded and skipped.
    pub fn from_paths(paths: &[PathBuf], evidence_root: &Path) -> Self {
        let mut infos = Vec::new();
        for p in paths {
            if let Ok(info) = classify_hive(p, evidence_root) {
                infos.push(info);
            }
        }
        Self::new(infos)
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn infos(&self) -> Vec<&HiveInfo> {
        self.entries.iter().map(|e| &e.info).collect()
    }

    pub fn kinds(&self) -> Vec<HiveKind> {
        self.entries.iter().map(|e| e.info.kind).collect()
    }

    pub fn indices_for(&self, root: Root) -> Vec<usize> {
        self.entries
            .iter()
            .enumerate()
            .filter(|(_, e)| root.accepts(e.info.kind))
            .map(|(i, _)| i)
            .collect()
    }

    /// Open (once) and return the hive at `idx`.
    pub fn open(&mut self, idx: usize) -> Option<(&HiveInfo, &mut HiveFile)> {
        let entry = self.entries.get_mut(idx)?;
        if matches!(entry.state, HiveState::Unopened) {
            entry.state = match open_hive(&entry.info) {
                Ok(o) => HiveState::Open(Box::new(o)),
                Err(_) => HiveState::Failed,
            };
        }
        match &mut entry.state {
            HiveState::Open(o) => Some((&entry.info, &mut o.hive)),
            _ => None,
        }
    }

    pub fn recovery(&self, idx: usize) -> Option<&RecoveryReport> {
        match &self.entries.get(idx)?.state {
            HiveState::Open(o) => Some(&o.recovery),
            _ => None,
        }
    }

    pub fn info(&self, idx: usize) -> Option<&HiveInfo> {
        self.entries.get(idx).map(|e| &e.info)
    }

    /// Full bytes of the hive as analysed (transaction logs applied), from the
    /// already-open instance. Falls back to the on-disk file when the hive was
    /// opened without its base block.
    pub fn hive_bytes(&mut self, idx: usize) -> Option<Vec<u8>> {
        let path = self.info(idx)?.path.clone();
        self.open(idx)?;
        let without_base_block = self.recovery(idx)?.opened_without_base_block;
        if without_base_block {
            return std::fs::read(&path).ok();
        }
        let (_, hive) = self.open(idx)?;
        let mut buf = std::io::Cursor::new(Vec::new());
        if hive.write_baseblock(&mut buf).is_err() {
            return std::fs::read(&path).ok();
        }
        use std::io::{Seek, SeekFrom};
        hive.seek(SeekFrom::Start(0)).ok()?;
        std::io::copy(hive, &mut buf).ok()?;
        Some(buf.into_inner())
    }
}

// ─── Value helpers ──────────────────────────────────────────────────────────

fn fmt_ts(dt: &chrono::DateTime<Utc>) -> String {
    dt.format(FORMAT_DATE).to_string()
}

fn file_mtime_string(path: &Path, created: bool) -> String {
    path.metadata()
        .ok()
        .and_then(|m| if created { m.created().ok() } else { m.modified().ok() })
        .and_then(|t| {
            let secs = t.duration_since(std::time::UNIX_EPOCH).ok()?.as_secs() as i64;
            chrono::DateTime::from_timestamp(secs, 0)
        })
        .map(|dt: chrono::DateTime<Utc>| dt.format(FORMAT_DATE).to_string())
        .unwrap_or_default()
}

fn data_type_name(v: &KeyValue) -> String {
    v.data_type().map(|t| t.to_string()).unwrap_or_default()
}

/// String content of a value, including the short resident strings nt_hive2
/// reports as `RegDWord` (1..=2 UTF-16 chars stored inline in the offset field).
pub fn string_value(v: &KeyValue) -> Option<String> {
    match v.value() {
        RegistryValue::RegSZ(s) | RegistryValue::RegExpandSZ(s) | RegistryValue::RegLink(s) => {
            Some(s.trim_end_matches(char::from(0)).to_string())
        }
        RegistryValue::RegDWord(n) if v.is_resident() => {
            let ty = data_type_name(v);
            if ty == "RegSZ" || ty == "RegExpandSZ" {
                let bytes = n.to_le_bytes();
                let len = (v.data_size() as usize).min(4);
                let units: Vec<u16> = bytes[..len]
                    .chunks_exact(2)
                    .map(|c| u16::from_le_bytes([c[0], c[1]]))
                    .take_while(|&u| u != 0)
                    .collect();
                Some(String::from_utf16_lossy(&units))
            } else {
                None
            }
        }
        _ => None,
    }
}

pub fn dword_value(v: &KeyValue) -> Option<u32> {
    match v.value() {
        RegistryValue::RegDWord(n) | RegistryValue::RegDWordBigEndian(n) => Some(*n),
        _ => None,
    }
}

pub fn multi_string_value(v: &KeyValue) -> Vec<String> {
    match v.value() {
        RegistryValue::RegMultiSZ(list) => list.clone(),
        _ => string_value(v).into_iter().collect(),
    }
}

pub fn is_default_value_name(name: &str) -> bool {
    name.is_empty() || name.eq_ignore_ascii_case("(default)")
}

fn find_value<'a>(key: &'a KeyNode, name: &str) -> Option<&'a KeyValue> {
    key.values().iter().find(|v| v.name().eq_ignore_ascii_case(name))
}

fn find_default_value(key: &KeyNode) -> Option<&KeyValue> {
    key.values().iter().find(|v| is_default_value_name(v.name()))
}

fn display_value(v: &KeyValue) -> String {
    string_value(v).unwrap_or_else(|| v.value().to_string())
}

// ─── Visiting helpers ───────────────────────────────────────────────────────

type KeyRef = Rc<RefCell<KeyNode>>;

fn root_key(info: &HiveInfo, hive: &mut HiveFile) -> Result<KeyNode, FaramirError> {
    hive.root_key_node()
        .map_err(|e| FaramirError::HiveRootKeyFailed(format!("{}: {e}", info.path.display())))
}

fn subpath(root: &KeyNode, path: &str, hive: &mut HiveFile, info: &HiveInfo) -> Result<Option<KeyRef>, FaramirError> {
    root.subpath(path, hive)
        .map_err(|e| FaramirError::KeyNotFound(format!("{}\\{path} in {}: {e}", "", info.path.display())))
}

/// Run `f` for every hive accepted by each root where the key path exists.
/// Panics inside nt_hive2 are caught per hive and reported as `TechniquePanicked`.
fn visit_roots<F>(set: &mut HiveSet, roots: &[KeyRoot], technique: &str, mut f: F) -> Vec<Persistence>
where
    F: FnMut(&KeyRoot, &HiveInfo, &KeyNode, &mut HiveFile) -> Vec<Persistence>,
{
    let mut out = Vec::new();
    let mut any_hive = false;
    for root in roots {
        for idx in set.indices_for(root.root) {
            any_hive = true;
            let Some((info, hive)) = set.open(idx) else { continue };
            let label = info.path.display().to_string();
            let result = catch_unwind(AssertUnwindSafe(|| -> Result<Vec<Persistence>, FaramirError> {
                let rk = root_key(info, hive)?;
                match subpath(&rk, root.path, hive, info)? {
                    Some(key_rc) => {
                        let key = key_rc.borrow();
                        Ok(stamp_origin(f(root, info, &key, hive), &info.path))
                    }
                    None => Ok(Vec::new()),
                }
            }));
            match result {
                Ok(Ok(v)) => out.extend(v),
                Ok(Err(e)) => {
                    diag::record(e);
                }
                Err(p) => {
                    diag::record(FaramirError::TechniquePanicked(format!(
                        "{technique} on {label}: {}",
                        diag::panic_message(&*p)
                    )));
                }
            }
        }
    }
    if !any_hive {
        diag::record(FaramirError::TechniqueNoApplicableHive(technique.to_string()));
    }
    out
}

/// Resolve the active `ControlSetNNN` number of a SYSTEM hive.
pub fn resolve_control_set(root: &KeyNode, hive: &mut HiveFile, label: &str) -> Result<u32, FaramirError> {
    let selected: Option<u32> = root
        .subpath("Select", hive)
        .ok()
        .flatten()
        .and_then(|sel| find_value(&sel.borrow(), "Current").and_then(dword_value));
    if let Some(n) = selected {
        let name = format!("ControlSet{n:03}");
        if let Ok(Some(_)) = root.subpath(name.as_str(), hive) {
            return Ok(n);
        }
    }
    let mut found: Vec<u32> = Vec::new();
    if let Ok(subkeys) = root.subkeys(hive) {
        for sk in subkeys.iter() {
            let name = sk.borrow().name().to_uppercase();
            if let Some(num) = name.strip_prefix("CONTROLSET") {
                if let Ok(n) = num.parse::<u32>() {
                    found.push(n);
                }
            }
        }
    }
    found.sort_unstable();
    match found.first() {
        Some(n) => {
            if selected.is_some() {
                diag::record(FaramirError::CurrentControlSetFailed(format!(
                    "{label}: Select\\Current points to a missing ControlSet, using ControlSet{n:03}"
                )));
            }
            Ok(*n)
        }
        None => Err(FaramirError::ControlSetNotFound(label.to_string())),
    }
}

/// Run `f` on `ControlSetNNN\<sub>` of every SYSTEM hive.
fn visit_control_set<F>(set: &mut HiveSet, sub: &str, technique: &str, mut f: F) -> Vec<Persistence>
where
    F: FnMut(&HiveInfo, &KeyNode, &mut HiveFile, u32) -> Vec<Persistence>,
{
    let mut out = Vec::new();
    let mut any_hive = false;
    for idx in set.indices_for(Root::System) {
        any_hive = true;
        let Some((info, hive)) = set.open(idx) else { continue };
        let label = info.path.display().to_string();
        let result = catch_unwind(AssertUnwindSafe(|| -> Result<Vec<Persistence>, FaramirError> {
            let rk = root_key(info, hive)?;
            let cs = match resolve_control_set(&rk, hive, &label) {
                Ok(n) => n,
                Err(e) => {
                    // An Unknown-kind hive that is not SYSTEM simply has no control set.
                    if info.kind == HiveKind::Unknown {
                        return Ok(Vec::new());
                    }
                    return Err(e);
                }
            };
            let path = if sub.is_empty() {
                format!("ControlSet{cs:03}")
            } else {
                format!("ControlSet{cs:03}\\{sub}")
            };
            match subpath(&rk, &path, hive, info)? {
                Some(key_rc) => {
                    let key = key_rc.borrow();
                    Ok(stamp_origin(f(info, &key, hive, cs), &info.path))
                }
                None => Ok(Vec::new()),
            }
        }));
        match result {
            Ok(Ok(v)) => out.extend(v),
            Ok(Err(e)) => {
                diag::record(e);
            }
            Err(p) => {
                diag::record(FaramirError::TechniquePanicked(format!(
                    "{technique} on {label}: {}",
                    diag::panic_message(&*p)
                )));
            }
        }
    }
    if !any_hive {
        diag::record(FaramirError::TechniqueNoApplicableHive(technique.to_string()));
    }
    out
}

fn persist(ts: String, technique: &str, path: String, value: String, access: &str) -> Persistence {
    Persistence {
        timestamp: ts,
        technique: technique.to_string(),
        path,
        value,
        access_gained: access.to_string(),
        source: String::new(),
        origin: String::new(),
    }
}

/// Stamp the file every finding was read from (only when not already set).
fn stamp_origin(mut findings: Vec<Persistence>, origin: &Path) -> Vec<Persistence> {
    let o = origin.to_string_lossy().to_string();
    for p in &mut findings {
        if p.origin.is_empty() {
            p.origin = o.clone();
        }
    }
    findings
}

/// Every string value of the key → one finding each (Run keys & co.).
fn string_values_of_key(set: &mut HiveSet, roots: &[KeyRoot], technique: &str) -> Vec<Persistence> {
    visit_roots(set, roots, technique, |root, info, key, _hive| {
        let ts = fmt_ts(key.timestamp());
        key.values()
            .iter()
            .filter_map(|v| {
                let s = string_value(v)?;
                if s.trim().is_empty() {
                    diag::record(FaramirError::ValueEmpty(format!(
                        "{}\\{} '{}' in {}",
                        root.root.label(),
                        root.path,
                        v.name(),
                        info.path.display()
                    )));
                    return None;
                }
                println!("\t{s}");
                Some(persist(
                    ts.clone(),
                    technique,
                    info.path.to_string_lossy().to_string(),
                    s,
                    root.access,
                ))
            })
            .collect()
    })
}

/// A single named value of the key.
fn single_value_key(
    set: &mut HiveSet,
    roots: &[KeyRoot],
    value_names: &[&str],
    technique: &str,
    persistence_value: &str,
) -> Vec<Persistence> {
    visit_roots(set, roots, technique, |root, _info, key, _hive| {
        key.values()
            .iter()
            .filter(|v| value_names.iter().any(|n| v.name().eq_ignore_ascii_case(n)))
            .map(|v| {
                let path_str = format!("Name: {} Value: {}", v.name(), display_value(v));
                println!("\t{path_str}");
                persist(
                    fmt_ts(key.timestamp()),
                    technique,
                    path_str,
                    persistence_value.to_string(),
                    root.access,
                )
            })
            .collect()
    })
}

/// Every value of the key.
fn all_values_key(set: &mut HiveSet, roots: &[KeyRoot], technique: &str, persistence_value: &str) -> Vec<Persistence> {
    visit_roots(set, roots, technique, |root, _info, key, _hive| {
        key.values()
            .iter()
            .map(|v| {
                let path_str = format!("{} {}", v.name(), display_value(v));
                println!("\t{path_str}");
                persist(
                    fmt_ts(key.timestamp()),
                    technique,
                    path_str,
                    persistence_value.to_string(),
                    root.access,
                )
            })
            .collect()
    })
}

// ─── Techniques ─────────────────────────────────────────────────────────────

pub fn get_run(set: &mut HiveSet) -> Vec<Persistence> {
    println!("+ Getting Run Persistence");
    string_values_of_key(set, RUN_ROOTS, TechniqueId::Run.label())
}

pub fn get_runonce(set: &mut HiveSet) -> Vec<Persistence> {
    println!("+ Getting RunOnce Persistence");
    string_values_of_key(set, RUNONCE_ROOTS, TechniqueId::RunOnce.label())
}

pub fn get_runex(set: &mut HiveSet) -> Vec<Persistence> {
    println!("+ Getting RunEx Persistence");
    string_values_of_key(set, RUNEX_ROOTS, TechniqueId::RunEx.label())
}

pub fn get_runonceex(set: &mut HiveSet) -> Vec<Persistence> {
    println!("+ Getting RunOnceEx Persistence");
    string_values_of_key(set, RUNONCEEX_ROOTS, TechniqueId::RunOnceEx.label())
}

pub fn get_image_file_execution_options(set: &mut HiveSet) -> Vec<Persistence> {
    println!("+ Getting Image File Execution Options");
    let technique = TechniqueId::ImageFileExecutionOptions.label();
    visit_roots(set, IFEO_ROOTS, technique, |_root, _info, key, hive| {
        let mut entries = Vec::new();
        if let Ok(subkeys) = key.subkeys(hive) {
            for image_rc in subkeys.iter() {
                let image = image_rc.borrow();
                let ts = fmt_ts(image.timestamp());
                if let Some(s) = find_value(&image, "Debugger").and_then(string_value) {
                    if s.trim().is_empty() {
                        continue;
                    }
                    println!("\t{s}");
                    entries.push(persist(ts.clone(), technique, s.clone(), s, "System/User"));
                }
            }
        }
        entries
    })
}

pub fn get_nldp_dll_override_path(set: &mut HiveSet) -> Vec<Persistence> {
    println!("+ Getting Natural Language Development Platform DLL path override properties.");
    let technique = TechniqueId::NldpDllOverridePath.label();
    visit_control_set(set, r"Control\ContentIndex\Language", technique, |_info, langs, hive, _cs| {
        let mut out = Vec::new();
        if let Ok(subkeys) = langs.subkeys(hive) {
            for lang_rc in subkeys.iter() {
                let lang = lang_rc.borrow();
                let ts = fmt_ts(lang.timestamp());
                let stemmer = find_value(&lang, "StemmerDLLPathOverride").and_then(string_value);
                let wb = find_value(&lang, "WBDLLPathOverride").and_then(string_value);
                if stemmer.is_some() || wb.is_some() {
                    let val = wb.clone().or_else(|| stemmer.clone()).unwrap_or_default();
                    println!("\t{val}");
                    out.push(persist(ts, technique, stemmer.unwrap_or_default(), val, "System"));
                }
            }
        }
        out
    })
}

fn debugger_entries(set: &mut HiveSet, roots: &[KeyRoot], technique: &str, persistence_value: &str) -> Vec<Persistence> {
    visit_roots(set, roots, technique, |root, _info, key, hive| {
        let mut entries = Vec::new();
        let ts = fmt_ts(key.timestamp());
        for v in key.values() {
            if v.name().eq_ignore_ascii_case("Debugger") || v.name().eq_ignore_ascii_case("ReflectDebugger") {
                let path_str = format!("Name: {} Value: {}", v.name(), display_value(v));
                println!("\t{path_str}");
                entries.push(persist(ts.clone(), technique, path_str, persistence_value.to_string(), root.access));
            }
        }
        if let Ok(subkeys) = key.subkeys(hive) {
            for sub_rc in subkeys.iter() {
                let sub = sub_rc.borrow();
                let ts = fmt_ts(sub.timestamp());
                for v in sub.values() {
                    let path_str = format!("Name: {} Value: {}", v.name(), display_value(v));
                    println!("\t{path_str}");
                    entries.push(persist(ts.clone(), technique, path_str, persistence_value.to_string(), root.access));
                }
            }
        }
        entries
    })
}

pub fn get_aedebug(set: &mut HiveSet) -> Vec<Persistence> {
    println!("+ Getting AeDebug properties.");
    debugger_entries(set, AEDEBUG_ROOTS, TechniqueId::AeDebug.label(), "AeDebug")
}

pub fn get_wer_fault_hangs(set: &mut HiveSet) -> Vec<Persistence> {
    println!("+ Getting WerFault Hangs registry key Debug property.");
    debugger_entries(set, WER_HANGS_ROOTS, TechniqueId::WerFaultHangs.label(), "werfaultDebuggger")
}

pub fn get_cmd_autorun(set: &mut HiveSet) -> Vec<Persistence> {
    println!("+ Getting Command Processor's AutoRun property.");
    let technique = TechniqueId::CmdAutorun.label();
    visit_roots(set, CMD_AUTORUN_ROOTS, technique, |root, _info, key, _hive| {
        key.values()
            .iter()
            .filter(|v| v.name().eq_ignore_ascii_case("AutoRun"))
            .filter_map(|v| {
                let s = string_value(v)?;
                let path_str = format!("Name: {s}");
                println!("\t{path_str}");
                Some(persist(fmt_ts(key.timestamp()), technique, path_str, "CmdAutoRun".to_string(), root.access))
            })
            .collect()
    })
}

pub fn get_explorer_load(set: &mut HiveSet) -> Vec<Persistence> {
    println!("+ Getting Explorer's Load property.");
    single_value_key(set, EXPLORER_WINDOWS_ROOTS, &["Load", "Run"], TechniqueId::ExplorerLoad.label(), "ExplorerLoad")
}

pub fn get_winlogon_userinit(set: &mut HiveSet) -> Vec<Persistence> {
    println!("+ Getting Winlogon's Userinit property.");
    single_value_key(set, WINLOGON_ROOTS, &["Userinit"], TechniqueId::WinlogonUserinit.label(), "WinLogonUserInit")
}

pub fn get_winlogon_shell(set: &mut HiveSet) -> Vec<Persistence> {
    println!("+ Getting Winlogon's Shell property.");
    single_value_key(set, WINLOGON_ROOTS, &["Shell"], TechniqueId::WinlogonShell.label(), "WinLogonShell")
}

pub fn get_winlogon_mpnotify(set: &mut HiveSet) -> Vec<Persistence> {
    println!("+ Getting Winlogon MPNotify property.");
    single_value_key(set, WINLOGON_ROOTS, &["mpnotify"], TechniqueId::WinlogonMpNotify.label(), "MPNotify")
}

pub fn get_app_cert_dlls(set: &mut HiveSet) -> Vec<Persistence> {
    println!("+ Getting AppCertDlls properties.");
    let technique = TechniqueId::AppCertDlls.label();
    visit_control_set(set, r"Control\Session Manager\AppCertDlls", technique, |_info, key, _hive, _cs| {
        key.values()
            .iter()
            .map(|v| {
                let path_str = format!("{} {}", v.name(), display_value(v));
                println!("\t{path_str}");
                persist(fmt_ts(key.timestamp()), technique, path_str, "AppCertDlls".to_string(), "System")
            })
            .collect()
    })
}

pub fn get_app_paths(set: &mut HiveSet) -> Vec<Persistence> {
    println!("+ Getting App Paths inside the registry.");
    let technique = TechniqueId::AppPaths.label();
    visit_roots(set, APP_PATHS_ROOTS, technique, |root, _info, key, hive| {
        let mut entries = Vec::new();
        if let Ok(apps) = key.subkeys(hive) {
            for app_rc in apps.iter() {
                let app = app_rc.borrow();
                if let Some(exe) = find_default_value(&app).and_then(string_value) {
                    println!("\t{exe}");
                    entries.push(persist(fmt_ts(app.timestamp()), technique, exe, app.name().to_string(), root.access));
                }
            }
        }
        entries
    })
}

fn service_dll_of(svc: &KeyNode, hive: &mut HiveFile) -> Option<String> {
    let direct = find_value(svc, "ServiceDll").and_then(string_value);
    let params = svc.subkeys(hive).ok().and_then(|subs| {
        subs.iter()
            .find(|k| k.borrow().name().eq_ignore_ascii_case("Parameters"))
            .and_then(|p| find_value(&p.borrow(), "ServiceDll").and_then(string_value))
    });
    params.or(direct)
}

pub fn get_service_dlls(set: &mut HiveSet) -> Vec<Persistence> {
    println!("+ Getting Service DLLs inside the registry.");
    let technique = TechniqueId::ServiceDlls.label();
    visit_control_set(set, "Services", technique, |_info, services, hive, _cs| {
        let mut out = Vec::new();
        if let Ok(keys) = services.subkeys(hive) {
            for svc_rc in keys.iter() {
                let svc = svc_rc.borrow();
                let ts = fmt_ts(svc.timestamp());
                if let Some(dll) = service_dll_of(&svc, hive) {
                    println!("\t{dll}");
                    out.push(persist(ts, technique, dll, "ServiceDlls".to_string(), "System"));
                }
            }
        }
        out
    })
}

pub fn get_gp_extension_dlls(set: &mut HiveSet) -> Vec<Persistence> {
    println!("+ Getting Group Policy Extension DLLs inside the registry.");
    let technique = TechniqueId::GpExtensionDlls.label();
    visit_roots(set, GP_EXTENSIONS_ROOTS, technique, |root, _info, key, hive| {
        let mut entries = Vec::new();
        if let Ok(subkeys) = key.subkeys(hive) {
            for ext_rc in subkeys.iter() {
                let ext = ext_rc.borrow();
                if let Some(dll) = find_value(&ext, "DllName").and_then(string_value) {
                    println!("\t{dll}");
                    entries.push(persist(fmt_ts(ext.timestamp()), technique, dll, technique.to_string(), root.access));
                }
            }
        }
        entries
    })
}

pub fn get_chm_helper_dll(set: &mut HiveSet) -> Vec<Persistence> {
    println!("+ Getting CHM Helper DLL inside the registry.");
    all_values_key(set, CHM_HELPER_ROOTS, TechniqueId::ChmHelperDll.label(), "CHMHelperDll")
}

pub fn get_startup_programs(startup_files: &[PathBuf]) -> Vec<Persistence> {
    println!("+ Checking if users' Startup folder contains interesting artifacts.");
    let technique = TechniqueId::StartupPrograms.label();
    startup_files
        .iter()
        .map(|program| {
            println!("\t{}", program.display());
            let mut p = persist(
                file_mtime_string(program, true),
                technique,
                program.to_string_lossy().to_string(),
                "Startup Folder".to_string(),
                "User",
            );
            p.origin = program.to_string_lossy().to_string();
            p
        })
        .collect()
}

pub fn get_scheduled_tasks(set: &mut HiveSet, source_evidence: Option<&Path>) -> Vec<Persistence> {
    println!("+ Getting scheduled tasks.");
    let technique = TechniqueId::ScheduledTasks.label();
    let mut result = visit_roots(set, TASKCACHE_ROOTS, technique, |root, _info, key, hive| {
        let mut entries = Vec::new();
        if let Ok(tasks) = key.subkeys(hive) {
            for task_rc in tasks.iter() {
                let task = task_rc.borrow();
                if let Some(path_val) = find_value(&task, "Path").and_then(string_value) {
                    println!("\t{path_val}");
                    entries.push(persist(fmt_ts(task.timestamp()), technique, path_val, "Scheduled Task".to_string(), root.access));
                }
            }
        }
        entries
    });

    if let Some(source) = source_evidence {
        for entry in WalkDir::new(source).into_iter().flatten() {
            let path = entry.path();
            let in_tasks = path
                .parent()
                .and_then(|p| p.file_name())
                .map(|n| n.to_string_lossy().eq_ignore_ascii_case("Tasks"))
                .unwrap_or(false);
            if !path.is_file() || !in_tasks {
                continue;
            }
            let Ok(content) = std::fs::read_to_string(path) else { continue };
            let doc = match roxmltree::Document::parse(&content) {
                Ok(d) => d,
                Err(e) => {
                    if content.trim_start().starts_with('<') {
                        diag::record(FaramirError::TaskXmlParseError(format!("{}: {e}", path.display())));
                    }
                    continue;
                }
            };
            let ns = "http://schemas.microsoft.com/windows/2004/02/mit/task";
            let command = doc
                .descendants()
                .find(|n| n.has_tag_name((ns, "Command")))
                .and_then(|n| n.text())
                .map(|s| s.trim().to_string())
                .unwrap_or_default();
            if command.is_empty() {
                continue;
            }
            let args = doc
                .descendants()
                .find(|n| n.has_tag_name((ns, "Arguments")))
                .and_then(|n| n.text())
                .map(|s| s.trim().to_string())
                .unwrap_or_default();
            let full_cmd = if args.is_empty() { command.clone() } else { format!("{command} {args}") };
            println!("\t{full_cmd}");
            let mut p = persist(
                file_mtime_string(path, false),
                "Scheduled Task (XML)",
                path.to_string_lossy().to_string(),
                full_cmd,
                "System",
            );
            p.origin = path.to_string_lossy().to_string();
            result.push(p);
        }
    }
    result
}

pub fn get_windows_services(set: &mut HiveSet) -> Vec<Persistence> {
    println!("+ Checking Windows Services.");
    let technique = TechniqueId::WindowsServices.label();
    visit_control_set(set, "Services", technique, |_info, services, hive, _cs| {
        let mut out = Vec::new();
        if let Ok(keys) = services.subkeys(hive) {
            for svc_rc in keys.iter() {
                let svc = svc_rc.borrow();
                let ts = fmt_ts(svc.timestamp());
                let has_service_dll = find_value(&svc, "ServiceDll").is_some();
                let display_name = find_value(&svc, "DisplayName").and_then(string_value).unwrap_or_default();
                if !has_service_dll {
                    if let Some(img) = find_value(&svc, "ImagePath").and_then(string_value) {
                        println!("\t{img}");
                        out.push(persist(ts, technique, img, display_name, "System"));
                    }
                }
            }
        }
        out
    })
}

pub fn get_user_init_mpr_script(set: &mut HiveSet) -> Vec<Persistence> {
    println!("+ Getting users' UserInitMprLogonScript property.");
    let technique = TechniqueId::UserInitMprScript.label();
    visit_roots(set, ENVIRONMENT_ROOTS, technique, |root, _info, key, _hive| {
        key.values()
            .iter()
            .filter(|v| v.name().eq_ignore_ascii_case("UserInitMprLogonScript"))
            .filter_map(|v| {
                let s = string_value(v)?;
                let path_str = format!("{} {s}", v.name());
                println!("\t{path_str}");
                Some(persist(fmt_ts(key.timestamp()), technique, path_str, s, root.access))
            })
            .collect()
    })
}

pub fn get_hhctrl_hijacking(set: &mut HiveSet) -> Vec<Persistence> {
    println!("+ Getting the hhctrl.ocx library inside the registry.");
    let technique = TechniqueId::HhCtrlHijacking.label();
    visit_roots(set, HHCTRL_ROOTS, technique, |root, _info, key, _hive| {
        find_default_value(key)
            .and_then(|v| string_value(v).map(|s| (v.name().to_string(), s)))
            .map(|(name, s)| {
                let path_str = format!("{name} {s}");
                println!("\t{path_str}");
                persist(fmt_ts(key.timestamp()), technique, path_str, s, root.access)
            })
            .into_iter()
            .collect()
    })
}

pub fn get_app_init_dlls(set: &mut HiveSet) -> Vec<Persistence> {
    println!("+ Getting AppInit_DLLs property.");
    let technique = TechniqueId::AppInitDlls.label();
    visit_roots(set, APPINIT_ROOTS, technique, |root, _info, key, _hive| {
        let load_flag = find_value(key, "LoadAppInit_DLLs").and_then(dword_value).unwrap_or(1);
        if load_flag == 0 {
            return Vec::new();
        }
        let tech_name = if root.path.to_uppercase().contains("WOW6432NODE") {
            "AppInit DLLs (Wow6432Node)"
        } else {
            technique
        };
        key.values()
            .iter()
            .filter(|v| v.name().eq_ignore_ascii_case("AppInit_DLLs"))
            .filter_map(|v| {
                let s = string_value(v)?;
                if s.trim().is_empty() {
                    return None;
                }
                println!("\t{s}");
                Some(persist(fmt_ts(key.timestamp()), tech_name, root.path.to_string(), s, root.access))
            })
            .collect()
    })
}

/// Packages Windows ships with; anything else is reported.
pub const LSA_DEFAULT_PACKAGES: &[&str] = &[
    "", "msv1_0", "scecli", "rassfm", "kerberos", "negoexts", "pku2u", "tspkg", "wdigest", "schannel", "cloudap",
];

pub fn get_lsa_packages(set: &mut HiveSet) -> Vec<Persistence> {
    println!("+ Getting LSA Authentication, Security and Notification Packages.");
    let technique = TechniqueId::LsaPackages.label();
    let value_names = ["Authentication Packages", "Security Packages", "Notification Packages"];
    let _ = technique;
    let mut out = visit_control_set(set, r"Control\Lsa", "LSA Packages", |_info, key, _hive, cs| {
        let ts = fmt_ts(key.timestamp());
        let mut entries = Vec::new();
        for value_name in value_names {
            if let Some(v) = find_value(key, value_name) {
                for pkg in multi_string_value(v) {
                    let pkg = pkg.trim();
                    if LSA_DEFAULT_PACKAGES.iter().any(|d| d.eq_ignore_ascii_case(pkg)) {
                        continue;
                    }
                    println!("\t{pkg}");
                    entries.push(persist(
                        ts.clone(),
                        &format!("LSA {value_name}"),
                        format!(r"SYSTEM\ControlSet{cs:03}\Control\Lsa"),
                        pkg.to_string(),
                        "System",
                    ));
                }
            }
        }
        entries
    });
    out.extend(visit_control_set(set, r"Control\Lsa\OSConfig", "LSA Packages", |_info, key, _hive, cs| {
        let ts = fmt_ts(key.timestamp());
        let mut entries = Vec::new();
        if let Some(v) = find_value(key, "Security Packages") {
            for pkg in multi_string_value(v) {
                let pkg = pkg.trim();
                if LSA_DEFAULT_PACKAGES.iter().any(|d| d.eq_ignore_ascii_case(pkg)) {
                    continue;
                }
                println!("\t{pkg}");
                entries.push(persist(
                    ts.clone(),
                    "LSA Security Packages (OSConfig)",
                    format!(r"SYSTEM\ControlSet{cs:03}\Control\Lsa\OSConfig"),
                    pkg.to_string(),
                    "System",
                ));
            }
        }
        entries
    }));
    out
}

pub const BOOT_EXECUTE_DEFAULTS: &[&str] = &["autocheck autochk *", "autocheck autochk*", ""];

pub fn get_boot_execute(set: &mut HiveSet) -> Vec<Persistence> {
    println!("+ Getting BootExecute property.");
    let technique = TechniqueId::BootExecute.label();
    visit_control_set(set, r"Control\Session Manager", technique, |_info, key, _hive, cs| {
        let ts = fmt_ts(key.timestamp());
        let mut entries = Vec::new();
        for value_name in ["BootExecute", "SetupExecute", "BootExecuteNoPnpSync"] {
            if let Some(v) = find_value(key, value_name) {
                for item in multi_string_value(v) {
                    let item = item.trim();
                    if BOOT_EXECUTE_DEFAULTS.iter().any(|d| d.eq_ignore_ascii_case(item)) {
                        continue;
                    }
                    println!("\t{item}");
                    entries.push(persist(
                        ts.clone(),
                        technique,
                        format!(r"SYSTEM\ControlSet{cs:03}\Control\Session Manager\{value_name}"),
                        item.to_string(),
                        "System",
                    ));
                }
            }
        }
        entries
    })
}

pub fn get_active_setup(set: &mut HiveSet) -> Vec<Persistence> {
    println!("+ Getting Active Setup Installed Components.");
    let technique = TechniqueId::ActiveSetup.label();
    visit_roots(set, ACTIVE_SETUP_ROOTS, technique, |root, _info, key, hive| {
        let mut entries = Vec::new();
        if let Ok(subkeys) = key.subkeys(hive) {
            for comp_rc in subkeys.iter() {
                let comp = comp_rc.borrow();
                if let Some(stub) = find_value(&comp, "StubPath").and_then(string_value) {
                    let stub = stub.trim().to_string();
                    if stub.is_empty() {
                        continue;
                    }
                    println!("\t{stub}");
                    entries.push(persist(
                        fmt_ts(comp.timestamp()),
                        technique,
                        format!(r"{}\{}", root.path, comp.name()),
                        stub,
                        root.access,
                    ));
                }
            }
        }
        entries
    })
}

pub fn get_screensaver(set: &mut HiveSet) -> Vec<Persistence> {
    println!("+ Getting Screensaver persistence.");
    let technique = TechniqueId::Screensaver.label();
    visit_roots(set, SCREENSAVER_ROOTS, technique, |root, info, key, _hive| {
        find_value(key, "SCRNSAVE.EXE")
            .and_then(string_value)
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .map(|s| {
                println!("\t{s}");
                persist(fmt_ts(key.timestamp()), technique, info.path.to_string_lossy().to_string(), s, root.access)
            })
            .into_iter()
            .collect()
    })
}

pub fn get_silent_process_exit(set: &mut HiveSet) -> Vec<Persistence> {
    println!("+ Getting SilentProcessExit persistence.");
    let technique = TechniqueId::SilentProcessExit.label();
    visit_roots(set, SILENT_PROCESS_EXIT_ROOTS, technique, |root, _info, key, hive| {
        let mut entries = Vec::new();
        if let Ok(monitored) = key.subkeys(hive) {
            for mon_rc in monitored.iter() {
                let mon = mon_rc.borrow();
                if let Some(proc_) = find_value(&mon, "MonitorProcess").and_then(string_value) {
                    let proc_ = proc_.trim().to_string();
                    if proc_.is_empty() {
                        continue;
                    }
                    println!("\t{} -> {proc_}", mon.name());
                    entries.push(persist(
                        fmt_ts(mon.timestamp()),
                        technique,
                        format!(r"{}\{}", root.path, mon.name()),
                        proc_,
                        root.access,
                    ));
                }
            }
        }
        entries
    })
}

pub fn get_com_hijacking(set: &mut HiveSet) -> Vec<Persistence> {
    println!("+ Getting COM Object hijacking (HKCU Classes).");
    let technique = TechniqueId::ComHijacking.label();
    visit_roots(set, COM_CLSID_ROOTS, technique, |root, _info, key, hive| {
        let mut entries = Vec::new();
        if let Ok(clsids) = key.subkeys(hive) {
            for clsid_rc in clsids.iter() {
                let clsid = clsid_rc.borrow();
                let Ok(subs) = clsid.subkeys(hive) else { continue };
                for server_name in ["InprocServer32", "LocalServer32"] {
                    let server = subs.iter().find(|k| k.borrow().name().eq_ignore_ascii_case(server_name)).cloned();
                    if let Some(server_rc) = server {
                        let server = server_rc.borrow();
                        if let Some(dll) = find_default_value(&server).and_then(string_value) {
                            let dll = dll.trim().to_string();
                            if dll.is_empty() {
                                continue;
                            }
                            println!("\t{} -> {dll}", clsid.name());
                            entries.push(persist(
                                fmt_ts(server.timestamp()),
                                technique,
                                format!(r"{}\{}\{server_name}", root.path, clsid.name()),
                                dll,
                                root.access,
                            ));
                        }
                    }
                }
            }
        }
        entries
    })
}

pub const STANDARD_PRINT_MONITORS: &[&str] = &[
    "Local Port",
    "Standard TCP/IP Port",
    "USB Monitor",
    "WSD Port",
    "Microsoft Shared Fax Monitor",
];

pub fn get_print_monitors(set: &mut HiveSet) -> Vec<Persistence> {
    println!("+ Getting Print Monitors.");
    let technique = TechniqueId::PrintMonitors.label();
    visit_control_set(set, r"Control\Print\Monitors", technique, |_info, mon_key, hive, cs| {
        let mut out = Vec::new();
        if let Ok(subkeys) = mon_key.subkeys(hive) {
            for sub_rc in subkeys.iter() {
                let sub = sub_rc.borrow();
                let name = sub.name();
                if STANDARD_PRINT_MONITORS.iter().any(|s| s.eq_ignore_ascii_case(name)) {
                    continue;
                }
                let driver = find_value(&sub, "Driver").and_then(string_value).unwrap_or_else(|| name.to_string());
                println!("\t{name} -> {driver}");
                out.push(persist(
                    fmt_ts(sub.timestamp()),
                    technique,
                    format!(r"SYSTEM\ControlSet{cs:03}\Control\Print\Monitors\{name}"),
                    driver,
                    "System",
                ));
            }
        }
        out
    })
}

pub const STANDARD_TIME_PROVIDER_DLLS: &[&str] = &["w32time.dll", "vmictimeprovider.dll"];

pub fn get_time_providers(set: &mut HiveSet) -> Vec<Persistence> {
    println!("+ Getting W32Time Time Providers.");
    let technique = TechniqueId::TimeProviders.label();
    visit_control_set(set, r"Services\W32Time\TimeProviders", technique, |_info, tp_key, hive, cs| {
        let mut out = Vec::new();
        if let Ok(subkeys) = tp_key.subkeys(hive) {
            for sub_rc in subkeys.iter() {
                let sub = sub_rc.borrow();
                let name = sub.name();
                if let Some(dll) = find_value(&sub, "DllName").and_then(string_value) {
                    let lower = dll.to_lowercase();
                    if STANDARD_TIME_PROVIDER_DLLS.iter().any(|s| lower.ends_with(s)) {
                        continue;
                    }
                    println!("\t{name} -> {dll}");
                    out.push(persist(
                        fmt_ts(sub.timestamp()),
                        technique,
                        format!(r"SYSTEM\ControlSet{cs:03}\Services\W32Time\TimeProviders\{name}"),
                        dll,
                        "System",
                    ));
                }
            }
        }
        out
    })
}

pub fn get_netsh_helper_dlls(set: &mut HiveSet) -> Vec<Persistence> {
    println!("+ Getting Netsh Helper DLLs.");
    let technique = TechniqueId::NetshHelperDlls.label();
    visit_roots(set, NETSH_ROOTS, technique, |root, _info, key, _hive| {
        key.values()
            .iter()
            .filter_map(|v| {
                let s = string_value(v)?;
                println!("\t{} -> {s}", v.name());
                Some(persist(
                    fmt_ts(key.timestamp()),
                    technique,
                    format!(r"{}\{}", root.path, v.name()),
                    s,
                    root.access,
                ))
            })
            .collect()
    })
}

pub fn get_powershell_profiles(source: &Path) -> Vec<Persistence> {
    println!("+ Checking for PowerShell Profile scripts...");
    let technique = TechniqueId::PowerShellProfiles.label();
    let mut result = Vec::new();
    for entry in WalkDir::new(source).into_iter().flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let fname = path.file_name().unwrap_or_default().to_string_lossy().to_lowercase();
        if fname.ends_with("profile.ps1") {
            println!("\tFound PowerShell profile: {}", path.display());
            let mut p = persist(
                file_mtime_string(path, false),
                technique,
                path.to_string_lossy().to_string(),
                path.to_string_lossy().to_string(),
                "User",
            );
            p.origin = path.to_string_lossy().to_string();
            result.push(p);
        }
    }
    result
}

pub fn get_terminal_profile_start_on_user_login(settings_files: &[PathBuf]) -> Vec<Persistence> {
    println!("+ Checking if users' Windows Terminal Profile's settings.json contains a startOnUserLogin value.");
    let technique = TechniqueId::TerminalProfileStartOnUserLogin.label();
    let mut result = Vec::new();
    for file in settings_files {
        let Ok(content) = std::fs::read_to_string(file) else { continue };
        let data: serde_json::Value = match serde_json::from_str(&content) {
            Ok(d) => d,
            Err(e) => {
                diag::record(FaramirError::TerminalJsonParseError(format!("{}: {e}", file.display())));
                continue;
            }
        };
        let profiles = &data["profiles"];
        let list = if profiles.is_object() {
            profiles["list"].as_array().cloned().unwrap_or_default()
        } else if profiles.is_array() {
            profiles.as_array().cloned().unwrap_or_default()
        } else {
            continue;
        };
        for profile in &list {
            if profile.get("startOnUserLogin") != Some(&serde_json::Value::Bool(true)) {
                continue;
            }
            let commandline = profile
                .get("commandline")
                .and_then(|v| v.as_str())
                .unwrap_or("N/A")
                .to_string();
            println!("\t{commandline}");
            let mut p = persist(
                file_mtime_string(file, false),
                technique,
                file.to_string_lossy().to_string(),
                commandline,
                "User",
            );
            p.origin = file.to_string_lossy().to_string();
            result.push(p);
        }
    }
    result
}

// ─── File discovery ─────────────────────────────────────────────────────────

pub fn get_settings_json_files(source: &Path) -> Vec<PathBuf> {
    println!("+ Searching for settings.json files...");
    let mut files = Vec::new();
    for entry in WalkDir::new(source).into_iter().flatten() {
        let path = entry.path();
        if entry.file_name() != "settings.json" || !path.is_file() {
            continue;
        }
        let is_terminal = path.ancestors().any(|p| {
            p.file_name()
                .map(|n| n.to_string_lossy().contains("Microsoft.WindowsTerminal"))
                .unwrap_or(false)
        });
        if is_terminal {
            println!("\tFound settings.json: {}", path.display());
            files.push(path.to_path_buf());
        }
    }
    if files.is_empty() {
        println!("No settings.json files found.");
    }
    files
}

pub fn get_startup_files(source: &Path) -> Vec<PathBuf> {
    println!("+ Searching for startup files...");
    let mut files = Vec::new();
    for entry in WalkDir::new(source).into_iter().flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let in_startup = path
            .parent()
            .and_then(|p| p.file_name())
            .map(|n| n.to_string_lossy().eq_ignore_ascii_case("Startup"))
            .unwrap_or(false);
        if in_startup {
            println!("\tFound startup file: {}", path.display());
            files.push(path.to_path_buf());
        }
    }
    if files.is_empty() {
        println!("No startup files found.");
    }
    files
}

// ─── Dispatch ───────────────────────────────────────────────────────────────

/// Run one technique. `source` is the evidence directory for filesystem techniques.
pub fn run_technique(id: TechniqueId, set: &mut HiveSet, source: Option<&Path>) -> Vec<Persistence> {
    match id {
        TechniqueId::Run => get_run(set),
        TechniqueId::RunOnce => get_runonce(set),
        TechniqueId::RunEx => get_runex(set),
        TechniqueId::RunOnceEx => get_runonceex(set),
        TechniqueId::ImageFileExecutionOptions => get_image_file_execution_options(set),
        TechniqueId::NldpDllOverridePath => get_nldp_dll_override_path(set),
        TechniqueId::AeDebug => get_aedebug(set),
        TechniqueId::WerFaultHangs => get_wer_fault_hangs(set),
        TechniqueId::CmdAutorun => get_cmd_autorun(set),
        TechniqueId::ExplorerLoad => get_explorer_load(set),
        TechniqueId::WinlogonUserinit => get_winlogon_userinit(set),
        TechniqueId::WinlogonShell => get_winlogon_shell(set),
        TechniqueId::TerminalProfileStartOnUserLogin => {
            let files = source.map(get_settings_json_files).unwrap_or_default();
            get_terminal_profile_start_on_user_login(&files)
        }
        TechniqueId::AppCertDlls => get_app_cert_dlls(set),
        TechniqueId::AppPaths => get_app_paths(set),
        TechniqueId::ServiceDlls => get_service_dlls(set),
        TechniqueId::GpExtensionDlls => get_gp_extension_dlls(set),
        TechniqueId::WinlogonMpNotify => get_winlogon_mpnotify(set),
        TechniqueId::ChmHelperDll => get_chm_helper_dll(set),
        TechniqueId::StartupPrograms => {
            let files = source.map(get_startup_files).unwrap_or_default();
            get_startup_programs(&files)
        }
        TechniqueId::ScheduledTasks => get_scheduled_tasks(set, source),
        TechniqueId::WindowsServices => get_windows_services(set),
        TechniqueId::UserInitMprScript => get_user_init_mpr_script(set),
        TechniqueId::HhCtrlHijacking => get_hhctrl_hijacking(set),
        TechniqueId::AppInitDlls => get_app_init_dlls(set),
        TechniqueId::LsaPackages => get_lsa_packages(set),
        TechniqueId::BootExecute => get_boot_execute(set),
        TechniqueId::ActiveSetup => get_active_setup(set),
        TechniqueId::Screensaver => get_screensaver(set),
        TechniqueId::SilentProcessExit => get_silent_process_exit(set),
        TechniqueId::ComHijacking => get_com_hijacking(set),
        TechniqueId::PrintMonitors => get_print_monitors(set),
        TechniqueId::TimeProviders => get_time_providers(set),
        TechniqueId::NetshHelperDlls => get_netsh_helper_dlls(set),
        TechniqueId::PowerShellProfiles => source.map(get_powershell_profiles).unwrap_or_default(),
        TechniqueId::DeletedRegistry => super::deleted::scan_set(set),
    }
}

/// Run every technique against the set and the evidence directory.
pub fn run_all(set: &mut HiveSet, source: &Path) -> Vec<Persistence> {
    let mut all = Vec::new();
    for id in TechniqueId::ALL {
        if id.is_registry_based() && set.is_empty() {
            continue;
        }
        all.extend(run_technique(id, set, Some(source)));
    }
    all
}
