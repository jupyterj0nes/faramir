//! Techniques added after comparing the catalogue with IRFlow's persistence
//! analyser and Autoruns: policy Run keys, Startup-folder redirects,
//! ShellServiceObjectDelayLoad, security support providers, Winlogon Notify,
//! network and credential providers, Terminal Server startup programs, the
//! .NET profiler hook, COM `TreatAs`, Group Policy scripts, file-association
//! hijacks, Office add-ins, shell extensions and BHOs, service failure
//! commands, SafeBoot's alternate shell, and browser extensions (policy
//! keys here, profile files in [`crate::browser_ext`]).

use std::path::Path;

use nt_hive2::{KeyNode, SubPath};
use walkdir::WalkDir;

use super::diag;
use super::hives::{HiveFile, HiveInfo};
use super::techniques::{
    display_value, dword_value, file_mtime_string, find_default_value, find_value, fmt_ts, multi_string_value, persist, root_key, string_value,
    string_values_of_key, visit_control_set, visit_roots, HiveSet, Persistence, Root, TechniqueId, BROWSER_EXTERNAL_ROOTS, BROWSER_POLICY_ROOTS,
    BROWSER_POLICY_SETTINGS_ROOTS, CLASSES_ROOTS, COM_TREATAS_ROOTS, CREDENTIAL_PROVIDER_ROOTS, ENVIRONMENT_ROOTS, EXPLORER_HOOK_ROOTS,
    GPO_SCRIPT_ROOTS, OFFICE_ROOTS, POLICIES_RUN_ROOTS, SHELL_FOLDERS_ROOTS, SSODL_ROOTS, WINLOGON_NOTIFY_ROOTS,
};
use crate::errors::FaramirError;

/// `InprocServer32` / `LocalServer32` of a CLSID, looked up in the Classes
/// tree of the hive the finding came from.
fn resolve_clsid(info: &HiveInfo, hive: &mut HiveFile, root: Root, clsid: &str) -> Option<String> {
    let rk = root_key(info, hive).ok()?;
    let bases: &[&str] = match root {
        Root::Software => &["Classes\\CLSID", "Classes\\Wow6432Node\\CLSID"],
        Root::UserProfile => &["Software\\Classes\\CLSID"],
        Root::UsrClass => &["CLSID"],
        Root::System => &[],
    };
    for b in bases {
        for server in ["InprocServer32", "LocalServer32"] {
            let p = format!("{b}\\{clsid}\\{server}");
            if let Ok(Some(k)) = rk.subpath(&p, hive) {
                if let Some(s) = find_default_value(&k.borrow()).and_then(string_value) {
                    let s = s.trim().to_string();
                    if !s.is_empty() {
                        return Some(s);
                    }
                }
            }
        }
    }
    None
}

fn with_dll(label: &str, dll: Option<String>) -> String {
    match dll {
        Some(d) => format!("{label} -> {d}"),
        None => label.to_string(),
    }
}

// ─── 1. Policies\Explorer\Run ───────────────────────────────────────────────

pub fn get_policies_run(set: &mut HiveSet) -> Vec<Persistence> {
    out!("+ Getting Policies\\Explorer\\Run keys.");
    string_values_of_key(set, POLICIES_RUN_ROOTS, TechniqueId::PoliciesRun.label())
}

// ─── 2. Startup folder redirect ─────────────────────────────────────────────

/// The Startup folder is where Windows put it: under a `Start Menu\Programs` tree.
pub fn is_default_startup_path(v: &str) -> bool {
    let l = v.to_lowercase().replace('/', "\\");
    l.ends_with("\\start menu\\programs\\startup") || l.ends_with("\\start menu\\programs\\startup\\")
}

pub fn get_startup_folder_redirect(set: &mut HiveSet) -> Vec<Persistence> {
    out!("+ Checking Startup folder locations in Shell Folders.");
    let technique = TechniqueId::StartupFolderRedirect.label();
    visit_roots(set, SHELL_FOLDERS_ROOTS, technique, |root, _info, key, _hive| {
        key.values()
            .iter()
            .filter(|v| v.name().eq_ignore_ascii_case("Startup") || v.name().eq_ignore_ascii_case("Common Startup"))
            .filter_map(|v| {
                let s = string_value(v)?;
                if s.trim().is_empty() || is_default_startup_path(&s) {
                    return None;
                }
                out!("\t{} = {s} (redirected)", v.name());
                Some(persist(fmt_ts(key.timestamp()), technique, format!(r"{}\{}", root.path, v.name()), s, root.access))
            })
            .collect()
    })
}

// ─── 3. ShellServiceObjectDelayLoad ─────────────────────────────────────────

pub fn get_ssodl(set: &mut HiveSet) -> Vec<Persistence> {
    out!("+ Getting ShellServiceObjectDelayLoad objects.");
    let technique = TechniqueId::ShellServiceObjectDelayLoad.label();
    visit_roots(set, SSODL_ROOTS, technique, |root, info, key, hive| {
        let mut out = Vec::new();
        for v in key.values() {
            let Some(clsid) = string_value(v) else { continue };
            let dll = resolve_clsid(info, hive, root.root, clsid.trim());
            out!("\t{} = {}", v.name(), with_dll(&clsid, dll.clone()));
            out.push(persist(fmt_ts(key.timestamp()), technique, format!(r"{}\{}", root.path, v.name()), with_dll(clsid.trim(), dll), root.access));
        }
        out
    })
}

// ─── 4. SecurityProviders ───────────────────────────────────────────────────

pub const DEFAULT_SECURITY_PROVIDERS: &[&str] = &["credssp.dll", "pwdssp.dll", "schannel.dll", "msapsspc.dll", "msnsspc.dll", "digest.dll", "tspkg.dll", "wdigest.dll", "kerberos.dll", "msv1_0.dll"];

pub fn get_security_providers(set: &mut HiveSet) -> Vec<Persistence> {
    out!("+ Getting Security Support Providers.");
    let technique = TechniqueId::SecurityProviders.label();
    visit_control_set(set, r"Control\SecurityProviders", technique, |_info, key, _hive, cs| {
        let Some(v) = find_value(key, "SecurityProviders") else { return Vec::new() };
        let Some(list) = string_value(v) else { return Vec::new() };
        list.split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty() && !DEFAULT_SECURITY_PROVIDERS.iter().any(|d| d.eq_ignore_ascii_case(s)))
            .map(|s| {
                out!("\t{s}");
                persist(fmt_ts(key.timestamp()), technique, format!(r"ControlSet{cs:03}\Control\SecurityProviders\SecurityProviders"), s.to_string(), "System")
            })
            .collect()
    })
}

// ─── 5. Winlogon\Notify ─────────────────────────────────────────────────────

pub fn get_winlogon_notify(set: &mut HiveSet) -> Vec<Persistence> {
    out!("+ Getting Winlogon Notify packages.");
    let technique = TechniqueId::WinlogonNotify.label();
    visit_roots(set, WINLOGON_NOTIFY_ROOTS, technique, |root, _info, key, hive| {
        let mut out = Vec::new();
        if let Ok(subs) = key.subkeys(hive) {
            for s_rc in subs.iter() {
                let s = s_rc.borrow();
                if let Some(dll) = find_value(&s, "DLLName").and_then(string_value) {
                    out!("\t{} = {dll}", s.name());
                    out.push(persist(fmt_ts(s.timestamp()), technique, format!(r"{}\{}", root.path, s.name()), dll, root.access));
                }
            }
        }
        out
    })
}

// ─── 6. Network providers ───────────────────────────────────────────────────

pub const DEFAULT_NETWORK_PROVIDERS: &[&str] = &["RDPNP", "LanmanWorkstation", "webclient", "P9NP", "vmhgfs", "PRNP"];

pub fn get_network_providers(set: &mut HiveSet) -> Vec<Persistence> {
    out!("+ Getting network providers.");
    let technique = TechniqueId::NetworkProviders.label();
    visit_control_set(set, r"Control\NetworkProvider\Order", technique, |info, key, hive, cs| {
        let Some(order) = find_value(key, "ProviderOrder").and_then(string_value) else { return Vec::new() };
        let mut out = Vec::new();
        let rk = match root_key(info, hive) {
            Ok(r) => r,
            Err(e) => {
                diag::record(e);
                return out;
            }
        };
        for name in order.split(',').map(|s| s.trim()).filter(|s| !s.is_empty()) {
            let path = format!(r"ControlSet{cs:03}\Services\{name}\NetworkProvider");
            let dll = rk.subpath(&path, hive).ok().flatten().and_then(|k| find_value(&k.borrow(), "ProviderPath").and_then(string_value));
            let standard = DEFAULT_NETWORK_PROVIDERS.iter().any(|d| d.eq_ignore_ascii_case(name));
            let in_system = dll.as_deref().map(|d| d.to_lowercase().contains("\\system32\\")).unwrap_or(false);
            if standard && in_system {
                continue;
            }
            out!("\t{name} = {}", dll.clone().unwrap_or_default());
            out.push(persist(fmt_ts(key.timestamp()), technique, path, with_dll(name, dll), "System"));
        }
        out
    })
}

// ─── 7. Credential providers ────────────────────────────────────────────────

pub const DEFAULT_CREDENTIAL_PROVIDER_DLLS: &[&str] = &[
    "authui.dll", "smartcardcredentialprovider.dll", "ngccredprov.dll", "biocredprov.dll", "certcredprovider.dll", "cngcredui.dll",
    "vaultcredprovider.dll", "facecredentialprovider.dll", "windowshello.dll", "credprovhost.dll", "winbio.dll", "pinenrollmentcredprov.dll",
    "iriscredentialprovider.dll", "fidocredprov.dll", "cloudap.dll", "msvcredprov.dll", "iwisecredprov.dll", "wlidcredprov.dll", "pwdssp.dll",
    "SmartcardCredentialProvider.dll", "RASPLAP.dll", "wlanplap.dll", "vpnplap.dll", "credentialenrollmentmanager.dll",
];

pub fn get_credential_providers(set: &mut HiveSet) -> Vec<Persistence> {
    out!("+ Getting credential providers.");
    let technique = TechniqueId::CredentialProviders.label();
    visit_roots(set, CREDENTIAL_PROVIDER_ROOTS, technique, |root, info, key, hive| {
        let mut out = Vec::new();
        let Ok(subs) = key.subkeys(hive) else { return out };
        for s_rc in subs.iter() {
            let s = s_rc.borrow();
            let clsid = s.name().to_string();
            let name = find_default_value(&s).and_then(string_value).unwrap_or_default();
            let dll = resolve_clsid(info, hive, root.root, &clsid);
            let base = dll.as_deref().and_then(|d| d.rsplit('\\').next()).unwrap_or("").to_lowercase();
            if !base.is_empty() && DEFAULT_CREDENTIAL_PROVIDER_DLLS.iter().any(|d| d.eq_ignore_ascii_case(&base)) {
                continue;
            }
            out!("\t{clsid} {name} {}", dll.clone().unwrap_or_default());
            out.push(persist(fmt_ts(s.timestamp()), technique, format!(r"{}\{clsid}", root.path), with_dll(format!("{clsid} {name}").trim(), dll), root.access));
        }
        out
    })
}

// ─── 8. Terminal Server startup programs ────────────────────────────────────

pub fn get_terminal_server_programs(set: &mut HiveSet) -> Vec<Persistence> {
    out!("+ Getting Terminal Server InitialProgram / StartupPrograms.");
    let technique = TechniqueId::TerminalServerPrograms.label();
    visit_control_set(set, r"Control\Terminal Server", technique, |_info, key, hive, cs| {
        let mut out = Vec::new();
        let checks: &[(&str, &str, &[&str])] = &[
            (r"WinStations\RDP-Tcp", "InitialProgram", &[]),
            (r"WinStations\Console", "InitialProgram", &[]),
            (r"Wds\rdpwd", "StartupPrograms", &["rdpclip"]),
            ("", "InitialProgram", &[]),
        ];
        for (sub, value_name, defaults) in checks {
            let k = if sub.is_empty() { None } else { key.subpath(*sub, hive).ok().flatten() };
            let node_ref = k.as_ref().map(|r| r.borrow());
            let node: &KeyNode = match &node_ref {
                Some(r) => r,
                None if sub.is_empty() => key,
                None => continue,
            };
            let Some(v) = find_value(node, value_name).and_then(string_value) else { continue };
            let v = v.trim().to_string();
            if v.is_empty() || defaults.iter().any(|d| d.eq_ignore_ascii_case(&v)) {
                continue;
            }
            out!("\t{sub}\\{value_name} = {v}");
            out.push(persist(fmt_ts(node.timestamp()), technique, format!(r"ControlSet{cs:03}\Control\Terminal Server\{sub}\{value_name}"), v, "System"));
        }
        out
    })
}

// ─── 9. COR_PROFILER ────────────────────────────────────────────────────────

const PROFILER_VALUES: &[&str] = &["COR_PROFILER", "COR_PROFILER_PATH", "COR_PROFILER_PATH_64", "COR_PROFILER_PATH_32", "CORECLR_PROFILER", "CORECLR_PROFILER_PATH", "CORECLR_PROFILER_PATH_64", "CORECLR_PROFILER_PATH_32"];

fn profiler_findings(key: &KeyNode, path: &str, access: &str, technique: &str) -> Vec<Persistence> {
    let enabled = ["COR_ENABLE_PROFILING", "CORECLR_ENABLE_PROFILING"].iter().any(|n| find_value(key, n).and_then(string_value).map(|v| v.trim() == "1").unwrap_or(false));
    let mut out = Vec::new();
    for v in key.values().iter().filter(|v| PROFILER_VALUES.iter().any(|n| v.name().eq_ignore_ascii_case(n))) {
        let s = display_value(v).trim().to_string();
        if s.is_empty() {
            continue;
        }
        out!("\t{} = {s} (profiling {})", v.name(), if enabled { "enabled" } else { "not enabled" });
        out.push(persist(fmt_ts(key.timestamp()), technique, format!(r"{path}\{}{}", v.name(), if enabled { " [COR_ENABLE_PROFILING=1]" } else { "" }), s, access));
    }
    out
}

pub fn get_cor_profiler(set: &mut HiveSet) -> Vec<Persistence> {
    out!("+ Checking .NET profiler environment variables.");
    let technique = TechniqueId::CorProfiler.label();
    let mut out = visit_roots(set, ENVIRONMENT_ROOTS, technique, |root, _info, key, _hive| profiler_findings(key, root.path, root.access, technique));
    out.extend(visit_control_set(set, r"Control\Session Manager\Environment", technique, |_info, key, _hive, cs| {
        profiler_findings(key, &format!(r"ControlSet{cs:03}\Control\Session Manager\Environment"), "System", technique)
    }));
    out
}

// ─── 10. COM TreatAs ────────────────────────────────────────────────────────

pub fn get_com_treatas(set: &mut HiveSet) -> Vec<Persistence> {
    out!("+ Getting COM TreatAs redirects.");
    let technique = TechniqueId::ComTreatAs.label();
    visit_roots(set, COM_TREATAS_ROOTS, technique, |root, info, key, hive| {
        let mut out = Vec::new();
        let Ok(clsids) = key.subkeys(hive) else { return out };
        for c_rc in clsids.iter() {
            let c = c_rc.borrow();
            let Ok(subs) = c.subkeys(hive) else { continue };
            let Some(t_rc) = subs.iter().find(|k| k.borrow().name().eq_ignore_ascii_case("TreatAs")).cloned() else { continue };
            let t = t_rc.borrow();
            let Some(target) = find_default_value(&t).and_then(string_value) else { continue };
            let target = target.trim().to_string();
            if target.is_empty() {
                continue;
            }
            let dll = resolve_clsid(info, hive, root.root, &target);
            out!("\t{} TreatAs {}", c.name(), with_dll(&target, dll.clone()));
            out.push(persist(fmt_ts(t.timestamp()), technique, format!(r"{}\{}\TreatAs", root.path, c.name()), with_dll(&target, dll), root.access));
        }
        out
    })
}

// ─── 11. Group Policy scripts ───────────────────────────────────────────────

pub fn get_gpo_scripts(set: &mut HiveSet, source: Option<&Path>) -> Vec<Persistence> {
    out!("+ Getting Group Policy startup/logon scripts.");
    let technique = TechniqueId::GpoScripts.label();
    let mut out = visit_roots(set, GPO_SCRIPT_ROOTS, technique, |root, _info, key, hive| {
        let mut found = Vec::new();
        let Ok(gpos) = key.subkeys(hive) else { return found };
        for g_rc in gpos.iter() {
            let g = g_rc.borrow();
            let gpo_name = find_value(&g, "DisplayName").or_else(|| find_value(&g, "GPOName")).and_then(string_value).unwrap_or_default();
            let Ok(scripts) = g.subkeys(hive) else { continue };
            for s_rc in scripts.iter() {
                let s = s_rc.borrow();
                let Some(script) = find_value(&s, "Script").and_then(string_value) else { continue };
                let params = find_value(&s, "Parameters").and_then(string_value).unwrap_or_default();
                let cmd = format!("{} {}", script.trim(), params.trim()).trim().to_string();
                out!("\t[{gpo_name}] {cmd}");
                found.push(persist(fmt_ts(s.timestamp()), technique, format!(r"{}\{}\{} ({gpo_name})", root.path, g.name(), s.name()), cmd, root.access));
            }
        }
        found
    });
    if let Some(src) = source {
        out.extend(gpo_script_ini_files(src, technique));
    }
    out
}

/// `scripts.ini` / `psscripts.ini` under `GroupPolicy\{Machine,User}\Scripts`:
/// `[Startup]` / `[Logon]` sections with `NCmdLine=` and `NParameters=`.
pub fn parse_scripts_ini(text: &str) -> Vec<(String, String)> {
    let mut section = String::new();
    let mut cmds: std::collections::BTreeMap<(String, String), (String, String)> = std::collections::BTreeMap::new();
    for line in text.lines() {
        let l = line.trim().trim_start_matches('\u{feff}');
        if l.starts_with('[') && l.ends_with(']') {
            section = l[1..l.len() - 1].to_string();
            continue;
        }
        let Some((k, v)) = l.split_once('=') else { continue };
        let k = k.trim();
        let digits: String = k.chars().take_while(|c| c.is_ascii_digit()).collect();
        let rest = &k[digits.len()..];
        let entry = cmds.entry((section.clone(), digits)).or_default();
        if rest.eq_ignore_ascii_case("CmdLine") {
            entry.0 = v.trim().to_string();
        } else if rest.eq_ignore_ascii_case("Parameters") {
            entry.1 = v.trim().to_string();
        }
    }
    cmds.into_iter().filter(|(_, (c, _))| !c.is_empty()).map(|((s, _), (c, p))| (s, format!("{c} {p}").trim().to_string())).collect()
}

fn gpo_script_ini_files(source: &Path, technique: &str) -> Vec<Persistence> {
    let mut out = Vec::new();
    for entry in WalkDir::new(source).into_iter().flatten() {
        let p = entry.path();
        if !p.is_file() {
            continue;
        }
        let name = p.file_name().unwrap_or_default().to_string_lossy().to_lowercase();
        if name != "scripts.ini" && name != "psscripts.ini" {
            continue;
        }
        let lower = p.to_string_lossy().to_lowercase();
        if !lower.contains("grouppolicy") && !lower.contains("group policy") && !lower.contains("\\scripts\\") && !lower.contains("/scripts/") {
            continue;
        }
        let Ok(bytes) = std::fs::read(p) else { continue };
        let text = if bytes.starts_with(&[0xff, 0xfe]) {
            let units: Vec<u16> = bytes[2..].chunks_exact(2).map(|c| u16::from_le_bytes([c[0], c[1]])).collect();
            String::from_utf16_lossy(&units)
        } else {
            String::from_utf8_lossy(&bytes).to_string()
        };
        let access = if lower.contains("\\user\\") || lower.contains("/user/") { "User" } else { "System" };
        for (section, cmd) in parse_scripts_ini(&text) {
            out!("\t{} [{section}] {cmd}", p.display());
            let mut f = persist(file_mtime_string(p, false), technique, format!("{} [{section}]", p.display()), cmd, access);
            f.origin = p.to_string_lossy().to_string();
            out.push(f);
        }
    }
    out
}

// ─── 13. File associations ──────────────────────────────────────────────────

/// `(ProgID, substring every legitimate default command contains)`; an
/// empty substring means the key does not exist on a clean system.
pub const FILE_ASSOCIATIONS: &[(&str, &str)] = &[
    ("exefile", "\"%1\" %*"),
    ("batfile", "\"%1\" %*"),
    ("cmdfile", "\"%1\" %*"),
    ("comfile", "\"%1\" %*"),
    ("piffile", "\"%1\" %*"),
    ("scrfile", "\"%1\""),
    ("txtfile", "notepad"),
    ("regfile", "regedit"),
    ("inffile", "notepad"),
    ("mscfile", "mmc.exe"),
    ("ms-settings", ""),
    ("Folder", ""),
    ("Directory", ""),
    ("htafile", "mshta"),
    ("VBSFile", "wscript"),
    ("JSFile", "wscript"),
    ("WSFFile", "wscript"),
    ("Microsoft.PowerShellScript.1", "notepad"),
    ("lnkfile", ""),
];

pub fn get_file_associations(set: &mut HiveSet) -> Vec<Persistence> {
    out!("+ Checking file association commands.");
    let technique = TechniqueId::FileAssociations.label();
    visit_roots(set, CLASSES_ROOTS, technique, |root, _info, key, hive| {
        let mut out = Vec::new();
        for (progid, default) in FILE_ASSOCIATIONS {
            let path = format!(r"{progid}\shell\open\command");
            let Ok(Some(k_rc)) = key.subpath(&path, hive) else { continue };
            let k = k_rc.borrow();
            let Some(cmd) = find_default_value(&k).and_then(string_value) else { continue };
            let cmd = cmd.trim().to_string();
            if cmd.is_empty() {
                continue;
            }
            let legit = !default.is_empty() && cmd.to_lowercase().contains(&default.to_lowercase()) && !cmd.to_lowercase().contains("\\temp\\") && !cmd.to_lowercase().contains("\\users\\public\\");
            // `"%1" %*` with anything before it is still a hijack (`evil.exe "%1" %*`)
            let wrapped = !default.is_empty() && default.starts_with("\"%1\"") && !cmd.starts_with(default);
            if legit && !wrapped {
                continue;
            }
            out!("\t{}\\{path} = {cmd}", root.root.label());
            out.push(persist(fmt_ts(k.timestamp()), technique, format!(r"{}{}{path}", root.path, if root.path.is_empty() { "" } else { "\\" }), cmd, root.access));
        }
        out
    })
}

// ─── 14. Office add-ins ─────────────────────────────────────────────────────

const OFFICE_APPS: &[&str] = &["Word", "Excel", "PowerPoint", "Outlook", "Access", "OneNote", "Project", "Visio", "Publisher", "MS Project"];

fn office_addins_of(app: &str, addins: &KeyNode, hive: &mut HiveFile, info: &HiveInfo, root: Root, base: &str, technique: &str, access: &str) -> Vec<Persistence> {
    let mut out = Vec::new();
    let Ok(subs) = addins.subkeys(hive) else { return out };
    for a_rc in subs.iter() {
        let a = a_rc.borrow();
        let load = find_value(&a, "LoadBehavior").and_then(dword_value).unwrap_or(0);
        if load == 0 {
            continue; // registered but disabled
        }
        let friendly = find_value(&a, "FriendlyName").and_then(string_value).unwrap_or_default();
        let progid = a.name().to_string();
        // ProgID -> CLSID -> server, when the Classes tree is in this hive
        let dll = root_key(info, hive).ok().and_then(|rk| {
            let bases: &[&str] = match root {
                Root::Software => &["Classes", "Classes\\Wow6432Node"],
                Root::UserProfile => &["Software\\Classes"],
                Root::UsrClass => &[""],
                Root::System => &[],
            };
            for b in bases {
                let p = if b.is_empty() { format!("{progid}\\CLSID") } else { format!("{b}\\{progid}\\CLSID") };
                if let Ok(Some(c)) = rk.subpath(&p, hive) {
                    if let Some(clsid) = find_default_value(&c.borrow()).and_then(string_value) {
                        if let Some(d) = resolve_clsid(info, hive, root, clsid.trim()) {
                            return Some(d);
                        }
                    }
                }
            }
            None
        });
        let manifest = find_value(&a, "Manifest").and_then(string_value);
        let what = match (&dll, &manifest) {
            (Some(d), _) => format!("{progid} ({friendly}) -> {d}"),
            (None, Some(m)) => format!("{progid} ({friendly}) manifest {m}"),
            (None, None) => format!("{progid} ({friendly})"),
        };
        out!("\t{app}: {what} LoadBehavior={load}");
        out.push(persist(fmt_ts(a.timestamp()), technique, format!(r"{base}\{app}\Addins\{progid} LoadBehavior={load}"), what, access));
    }
    out
}

pub fn get_office_addins(set: &mut HiveSet) -> Vec<Persistence> {
    out!("+ Getting Office add-ins and XLL/XLA OPEN entries.");
    let technique = TechniqueId::OfficeAddins.label();
    visit_roots(set, OFFICE_ROOTS, technique, |root, info, key, hive| {
        let mut out = Vec::new();
        let Ok(children) = key.subkeys(hive) else { return out };
        for c_rc in children.iter() {
            let c = c_rc.borrow();
            let name = c.name().to_string();
            let is_version = name.chars().all(|ch| ch.is_ascii_digit() || ch == '.') && !name.is_empty();
            if OFFICE_APPS.iter().any(|a| a.eq_ignore_ascii_case(&name)) {
                if let Ok(Some(addins)) = c.subpath("Addins", hive) {
                    out.extend(office_addins_of(&name, &addins.borrow(), hive, info, root.root, root.path, technique, root.access));
                }
            } else if is_version {
                let Ok(apps) = c.subkeys(hive) else { continue };
                for app_rc in apps.iter() {
                    let app = app_rc.borrow();
                    let app_name = app.name().to_string();
                    if let Ok(Some(addins)) = app.subpath("Addins", hive) {
                        out.extend(office_addins_of(&format!("{name}\\{app_name}"), &addins.borrow(), hive, info, root.root, root.path, technique, root.access));
                    }
                    if app_name.eq_ignore_ascii_case("Excel") {
                        if let Ok(Some(opts)) = app.subpath("Options", hive) {
                            let opts = opts.borrow();
                            for v in opts.values().iter().filter(|v| {
                                let n = v.name().to_uppercase();
                                n == "OPEN" || (n.starts_with("OPEN") && n[4..].chars().all(|ch| ch.is_ascii_digit()))
                            }) {
                                let Some(s) = string_value(v) else { continue };
                                out!("\t{name}\\Excel\\Options\\{} = {s}", v.name());
                                out.push(persist(fmt_ts(opts.timestamp()), technique, format!(r"{}\{name}\Excel\Options\{}", root.path, v.name()), s, root.access));
                            }
                        }
                    }
                }
            }
        }
        out
    })
}

// ─── 15. Shell extensions and BHOs ──────────────────────────────────────────

/// Explorer hooks keyed by CLSID subkey, plus `shellex` handlers under the ProgIDs attackers use.
pub const SHELLEX_HANDLERS: &[&str] = &[
    r"*\shellex\ContextMenuHandlers",
    r"*\shellex\PropertySheetHandlers",
    r"*\shellex\CopyHookHandlers",
    r"*\shellex\DragDropHandlers",
    r"AllFilesystemObjects\shellex\ContextMenuHandlers",
    r"AllFilesystemObjects\shellex\DragDropHandlers",
    r"Directory\shellex\ContextMenuHandlers",
    r"Directory\shellex\DragDropHandlers",
    r"Directory\shellex\CopyHookHandlers",
    r"Directory\Background\shellex\ContextMenuHandlers",
    r"Folder\shellex\ContextMenuHandlers",
    r"Folder\shellex\ColumnHandlers",
    r"Folder\shellex\DragDropHandlers",
    r"Drive\shellex\ContextMenuHandlers",
    r"Desktop\Background\shellex\ContextMenuHandlers",
    r"Network\shellex\ContextMenuHandlers",
    r"Printers\shellex\ContextMenuHandlers",
    r"Unknown\shellex\ContextMenuHandlers",
    r"lnkfile\shellex\ContextMenuHandlers",
    r"exefile\shellex\ContextMenuHandlers",
];

fn clsid_subkeys(root: Root, info: &HiveInfo, key: &KeyNode, hive: &mut HiveFile, path: &str, access: &str, technique: &str) -> Vec<Persistence> {
    let mut out = Vec::new();
    let Ok(subs) = key.subkeys(hive) else { return out };
    for s_rc in subs.iter() {
        let s = s_rc.borrow();
        let name = s.name().to_string();
        // the subkey is the CLSID, or its default value is
        let clsid = if name.starts_with('{') { name.clone() } else { find_default_value(&s).and_then(string_value).unwrap_or_default().trim().to_string() };
        if clsid.is_empty() {
            continue;
        }
        let dll = resolve_clsid(info, hive, root, &clsid);
        let label = if name == clsid { clsid.clone() } else { format!("{name} = {clsid}") };
        out!("\t{path}\\{name} {}", with_dll("", dll.clone()));
        out.push(persist(fmt_ts(s.timestamp()), technique, format!(r"{path}\{name}"), with_dll(&label, dll), access));
    }
    out
}

pub fn get_shell_extensions(set: &mut HiveSet) -> Vec<Persistence> {
    out!("+ Getting shell extensions, BHOs and Explorer hooks.");
    let technique = TechniqueId::ShellExtensions.label();
    let mut out = visit_roots(set, EXPLORER_HOOK_ROOTS, technique, |root, info, key, hive| clsid_subkeys(root.root, info, key, hive, root.path, root.access, technique));
    out.extend(visit_roots(set, CLASSES_ROOTS, technique, |root, info, key, hive| {
        let mut found = Vec::new();
        for handler in SHELLEX_HANDLERS {
            let Ok(Some(k_rc)) = key.subpath(*handler, hive) else { continue };
            let k = k_rc.borrow();
            let path = if root.path.is_empty() { handler.to_string() } else { format!(r"{}\{handler}", root.path) };
            found.extend(clsid_subkeys(root.root, info, &k, hive, &path, root.access, technique));
        }
        found
    }));
    out
}

// ─── 16. Service FailureCommand ─────────────────────────────────────────────

pub fn get_service_failure_commands(set: &mut HiveSet) -> Vec<Persistence> {
    out!("+ Getting service failure commands.");
    let technique = TechniqueId::ServiceFailureCommand.label();
    visit_control_set(set, "Services", technique, |_info, key, hive, cs| {
        let mut out = Vec::new();
        let Ok(svcs) = key.subkeys(hive) else { return out };
        for s_rc in svcs.iter() {
            let s = s_rc.borrow();
            if let Some(cmd) = find_value(&s, "FailureCommand").and_then(string_value) {
                let cmd = cmd.trim().to_string();
                if cmd.is_empty() {
                    continue;
                }
                out!("\t{} -> {cmd}", s.name());
                out.push(persist(fmt_ts(s.timestamp()), technique, format!(r"ControlSet{cs:03}\Services\{}\FailureCommand", s.name()), cmd, "System"));
            }
        }
        out
    })
}

// ─── 17. SafeBoot AlternateShell ────────────────────────────────────────────

pub fn get_safeboot_alternate_shell(set: &mut HiveSet) -> Vec<Persistence> {
    out!("+ Checking SafeBoot AlternateShell.");
    let technique = TechniqueId::SafeBootAlternateShell.label();
    visit_control_set(set, r"Control\SafeBoot", technique, |_info, key, _hive, cs| {
        let Some(v) = find_value(key, "AlternateShell").and_then(string_value) else { return Vec::new() };
        let v = v.trim().to_string();
        if v.is_empty() || v.eq_ignore_ascii_case("cmd.exe") {
            return Vec::new();
        }
        out!("\tAlternateShell = {v}");
        vec![persist(fmt_ts(key.timestamp()), technique, format!(r"ControlSet{cs:03}\Control\SafeBoot\AlternateShell"), v, "System")]
    })
}

// ─── 18. Browser extensions ─────────────────────────────────────────────────

pub fn get_browser_extensions(set: &mut HiveSet, source: Option<&Path>) -> Vec<Persistence> {
    out!("+ Getting browser extensions (policy keys, external installs, profiles).");
    let technique = TechniqueId::BrowserExtensions.label();
    // force-installed by policy: values `N = <id>;<update_url>`
    let mut out = visit_roots(set, BROWSER_POLICY_ROOTS, technique, |root, _info, key, _hive| {
        key.values()
            .iter()
            .filter_map(|v| {
                let s = string_value(v)?;
                let s = s.trim().to_string();
                if s.is_empty() {
                    return None;
                }
                let browser = crate::browser_ext::browser_of_policy_path(root.path);
                let (id, url) = s.split_once(';').map(|(a, b)| (a.trim().to_string(), b.trim().to_string())).unwrap_or((s.clone(), String::new()));
                out!("\t{browser} force-installed {id} {url}");
                Some(persist(
                    fmt_ts(key.timestamp()),
                    technique,
                    format!(r"{}\{}", root.path, v.name()),
                    format!("{browser} {id} [force-installed by policy]{}", if url.is_empty() { String::new() } else { format!(" update_url={url}") }),
                    root.access,
                ))
            })
            .collect()
    });
    // ExtensionSettings: subkey per id (or a JSON blob in the default value)
    out.extend(visit_roots(set, BROWSER_POLICY_SETTINGS_ROOTS, technique, |root, _info, key, hive| {
        let mut found = Vec::new();
        let browser = crate::browser_ext::browser_of_policy_path(root.path);
        if let Some(json) = find_default_value(key).and_then(string_value) {
            for e in crate::browser_ext::parse_extension_settings_json(&json, browser) {
                found.push(persist(fmt_ts(key.timestamp()), technique, format!(r"{}\(Default)", root.path), e.summary(), root.access));
            }
        }
        if let Ok(subs) = key.subkeys(hive) {
            for s_rc in subs.iter() {
                let s = s_rc.borrow();
                let mode = find_value(&s, "installation_mode").and_then(string_value).unwrap_or_default();
                let url = find_value(&s, "update_url").or_else(|| find_value(&s, "install_url")).and_then(string_value).unwrap_or_default();
                if mode.is_empty() && url.is_empty() {
                    continue;
                }
                if mode.eq_ignore_ascii_case("blocked") || mode.eq_ignore_ascii_case("removed") {
                    continue;
                }
                out!("\t{browser} {} {mode} {url}", s.name());
                found.push(persist(fmt_ts(s.timestamp()), technique, format!(r"{}\{}", root.path, s.name()), format!("{browser} {} [{mode} by policy]{}", s.name(), if url.is_empty() { String::new() } else { format!(" update_url={url}") }), root.access));
            }
        }
        found
    }));
    // external installs: subkey per id with update_url or path
    out.extend(visit_roots(set, BROWSER_EXTERNAL_ROOTS, technique, |root, _info, key, hive| {
        let mut found = Vec::new();
        let browser = crate::browser_ext::browser_of_policy_path(root.path);
        if let Ok(subs) = key.subkeys(hive) {
            for s_rc in subs.iter() {
                let s = s_rc.borrow();
                let url = find_value(&s, "update_url").and_then(string_value).unwrap_or_default();
                let path = find_value(&s, "path").and_then(string_value).unwrap_or_default();
                let ver = find_value(&s, "version").and_then(string_value).unwrap_or_default();
                if url.is_empty() && path.is_empty() {
                    continue;
                }
                let how = if !path.is_empty() { format!("crx {path} {ver}") } else { format!("update_url={url}") };
                out!("\t{browser} external {} {how}", s.name());
                found.push(persist(fmt_ts(s.timestamp()), technique, format!(r"{}\{}", root.path, s.name()), format!("{browser} {} [external install via registry] {how}", s.name()), root.access));
            }
        }
        found
    }));
    if let Some(src) = source {
        for e in crate::browser_ext::scan_tree(src) {
            let mut f = persist(e.install_time.clone().unwrap_or_else(|| file_mtime_string(Path::new(&e.file), false)), technique, format!("{} [{}] {}", e.browser, e.profile, e.id), e.summary(), "User");
            f.origin = e.file.clone();
            out.push(f);
        }
    }
    let _ = multi_string_value; // keep the import list honest for future list-valued keys
    out
}

#[allow(dead_code)]
fn _unused(_: FaramirError) {}
