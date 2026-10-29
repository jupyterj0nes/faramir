//! The techniques added after the IRFlow / Autoruns comparison, each
//! against synthetic hives: the planted value is reported from the right
//! hive, defaults are not, and nothing panics.
mod common;

use common::*;
use faramir::windows::diag;
use faramir::windows::extra::*;
use faramir::windows::techniques::*;
use std::path::PathBuf;

fn set_with(dir: &TempDir, hives: &[(&str, &HiveBuilder)]) -> HiveSet {
    let paths: Vec<PathBuf> = hives.iter().map(|(name, b)| b.write(&dir.join(name))).collect();
    HiveSet::from_paths(&paths, &dir.path)
}

fn run(id: TechniqueId, set: &mut HiveSet) -> Vec<Persistence> {
    diag::clear();
    let p = run_technique(id, set, None);
    assert!(!diag::has("ERR_WIN_TECH_PANIC"), "{:?}", diag::snapshot());
    p
}

fn values(p: &[Persistence]) -> Vec<String> {
    p.iter().map(|x| x.value.clone()).collect()
}

fn system_with_cs(cs: u32) -> HiveBuilder {
    let mut b = HiveBuilder::system();
    b.dword("Select", "Current", cs);
    b.key(&format!("ControlSet{cs:03}"));
    b
}

// ─── Policies\Explorer\Run ───────────────────────────────────────────────────

#[test]
fn policies_run_in_both_hives() {
    let d = TempDir::new("x_polrun");
    let mut sw = HiveBuilder::software();
    sw.sz(r"Microsoft\Windows\CurrentVersion\Policies\Explorer\Run", "1", r"C:\ProgramData\p.exe");
    let mut nt = HiveBuilder::ntuser("bob");
    nt.sz(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run", "x", r"C:\Users\bob\u.exe");
    let mut set = set_with(&d, &[("SOFTWARE", &sw), ("bob_NTUSER.DAT", &nt)]);
    let p = run(TechniqueId::PoliciesRun, &mut set);
    let mut v = values(&p);
    v.sort();
    assert_eq!(v, vec![r"C:\ProgramData\p.exe", r"C:\Users\bob\u.exe"]);
    assert_eq!(p.iter().filter(|x| x.access_gained == "System").count(), 1);
    assert_eq!(p[0].technique, "Policies Explorer Run Key");
}

// ─── Startup folder redirect ─────────────────────────────────────────────────

#[test]
fn startup_folder_redirect_reports_only_non_default_paths() {
    let d = TempDir::new("x_shellfold");
    let mut nt = HiveBuilder::ntuser("bob");
    nt.expand_sz(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders", "Startup", r"%USERPROFILE%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup")
        .sz(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders", "Startup", r"C:\Users\bob\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup")
        .sz(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders", "Desktop", r"C:\Users\bob\Desktop");
    let mut set = set_with(&d, &[("NTUSER.DAT", &nt)]);
    assert!(run(TechniqueId::StartupFolderRedirect, &mut set).is_empty());

    let mut nt2 = HiveBuilder::ntuser("eve");
    nt2.expand_sz(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders", "Startup", r"C:\Users\eve\AppData\Local\Temp\boot");
    let mut sw = HiveBuilder::software();
    sw.sz(r"Microsoft\Windows\CurrentVersion\Explorer\Shell Folders", "Common Startup", r"C:\ProgramData\x");
    let mut set = set_with(&d, &[("eve_NTUSER.DAT", &nt2), ("SOFTWARE", &sw)]);
    let p = run(TechniqueId::StartupFolderRedirect, &mut set);
    let mut v = values(&p);
    v.sort();
    assert_eq!(v, vec![r"C:\ProgramData\x", r"C:\Users\eve\AppData\Local\Temp\boot"]);
    assert!(is_default_startup_path(r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp"));
    assert!(!is_default_startup_path(r"C:\Temp\Startup"));
}

// ─── ShellServiceObjectDelayLoad ─────────────────────────────────────────────

#[test]
fn ssodl_resolves_the_clsid_to_its_dll() {
    let d = TempDir::new("x_ssodl");
    let mut sw = HiveBuilder::software();
    sw.sz(r"Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad", "WebCheck", "{E6FB5E20-DE35-11CF-9C87-00AA005127ED}")
        .sz(r"Classes\CLSID\{E6FB5E20-DE35-11CF-9C87-00AA005127ED}\InprocServer32", "", r"C:\Users\Public\wc.dll");
    let mut set = set_with(&d, &[("SOFTWARE", &sw)]);
    let p = run(TechniqueId::ShellServiceObjectDelayLoad, &mut set);
    assert_eq!(values(&p), vec![r"{E6FB5E20-DE35-11CF-9C87-00AA005127ED} -> C:\Users\Public\wc.dll"]);
    assert!(p[0].path.ends_with("ShellServiceObjectDelayLoad\\WebCheck"));
}

// ─── SecurityProviders ───────────────────────────────────────────────────────

#[test]
fn security_providers_skip_defaults() {
    let d = TempDir::new("x_ssp");
    let mut sys = system_with_cs(1);
    sys.sz(r"ControlSet001\Control\SecurityProviders", "SecurityProviders", "credssp.dll, pwdssp.dll, evilssp.dll");
    let mut set = set_with(&d, &[("SYSTEM", &sys)]);
    let p = run(TechniqueId::SecurityProviders, &mut set);
    assert_eq!(values(&p), vec!["evilssp.dll"]);
    assert!(p[0].path.contains("ControlSet001"));
    let mut sys2 = system_with_cs(1);
    sys2.sz(r"ControlSet001\Control\SecurityProviders", "SecurityProviders", "credssp.dll, pwdssp.dll");
    let mut set = set_with(&d, &[("SYSTEM2", &sys2)]);
    assert!(run(TechniqueId::SecurityProviders, &mut set).is_empty());
}

// ─── Winlogon Notify ─────────────────────────────────────────────────────────

#[test]
fn winlogon_notify_dllname() {
    let d = TempDir::new("x_notify");
    let mut sw = HiveBuilder::software();
    sw.sz(r"Microsoft\Windows NT\CurrentVersion\Winlogon\Notify\evil", "DLLName", r"C:\Windows\Temp\n.dll").sz(r"Microsoft\Windows NT\CurrentVersion\Winlogon\Notify\evil", "Logon", "OnLogon");
    let mut set = set_with(&d, &[("SOFTWARE", &sw)]);
    let p = run(TechniqueId::WinlogonNotify, &mut set);
    assert_eq!(values(&p), vec![r"C:\Windows\Temp\n.dll"]);
    assert!(p[0].path.ends_with(r"Winlogon\Notify\evil"));
}

// ─── Network providers ───────────────────────────────────────────────────────

#[test]
fn network_providers_report_the_unknown_one_with_its_dll() {
    let d = TempDir::new("x_netprov");
    let mut sys = system_with_cs(1);
    sys.sz(r"ControlSet001\Control\NetworkProvider\Order", "ProviderOrder", "RDPNP,LanmanWorkstation,webclient,StealNP")
        .sz(r"ControlSet001\Services\RDPNP\NetworkProvider", "ProviderPath", r"%SystemRoot%\System32\drprov.dll")
        .sz(r"ControlSet001\Services\LanmanWorkstation\NetworkProvider", "ProviderPath", r"%SystemRoot%\System32\ntlanman.dll")
        .sz(r"ControlSet001\Services\webclient\NetworkProvider", "ProviderPath", r"%SystemRoot%\System32\davclnt.dll")
        .sz(r"ControlSet001\Services\StealNP\NetworkProvider", "ProviderPath", r"C:\ProgramData\np.dll");
    let mut set = set_with(&d, &[("SYSTEM", &sys)]);
    let p = run(TechniqueId::NetworkProviders, &mut set);
    assert_eq!(values(&p), vec![r"StealNP -> C:\ProgramData\np.dll"]);
    assert!(p[0].path.contains(r"Services\StealNP\NetworkProvider"));
}

#[test]
fn standard_network_provider_outside_system32_is_reported() {
    let d = TempDir::new("x_netprov2");
    let mut sys = system_with_cs(1);
    sys.sz(r"ControlSet001\Control\NetworkProvider\Order", "ProviderOrder", "RDPNP").sz(r"ControlSet001\Services\RDPNP\NetworkProvider", "ProviderPath", r"C:\Users\Public\drprov.dll");
    let mut set = set_with(&d, &[("SYSTEM", &sys)]);
    assert_eq!(values(&run(TechniqueId::NetworkProviders, &mut set)), vec![r"RDPNP -> C:\Users\Public\drprov.dll"]);
}

// ─── Credential providers ────────────────────────────────────────────────────

#[test]
fn credential_providers_skip_microsoft_dlls() {
    let d = TempDir::new("x_credprov");
    let mut sw = HiveBuilder::software();
    sw.sz(r"Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{1b283861-754f-4022-ad47-a5eaaa618894}", "", "Smartcard Reader Selection Provider")
        .sz(r"Classes\CLSID\{1b283861-754f-4022-ad47-a5eaaa618894}\InprocServer32", "", r"%SystemRoot%\System32\SmartcardCredentialProvider.dll")
        .sz(r"Microsoft\Windows\CurrentVersion\Authentication\Credential Providers\{DEADBEEF-0000-0000-0000-000000000001}", "", "Helpful Provider")
        .sz(r"Classes\CLSID\{DEADBEEF-0000-0000-0000-000000000001}\InprocServer32", "", r"C:\ProgramData\cp.dll")
        .sz(r"Microsoft\Windows\CurrentVersion\Authentication\Credential Provider Filters\{DEADBEEF-0000-0000-0000-000000000002}", "", "Filter");
    let mut set = set_with(&d, &[("SOFTWARE", &sw)]);
    let p = run(TechniqueId::CredentialProviders, &mut set);
    let v = values(&p);
    assert_eq!(v.len(), 2, "{v:?}");
    assert!(v.iter().any(|x| x.contains("Helpful Provider -> C:\\ProgramData\\cp.dll")), "{v:?}");
    assert!(v.iter().any(|x| x.contains("{DEADBEEF-0000-0000-0000-000000000002} Filter")), "unresolved CLSID still reported: {v:?}");
}

// ─── Terminal Server ─────────────────────────────────────────────────────────

#[test]
fn terminal_server_programs() {
    let d = TempDir::new("x_ts");
    let mut sys = system_with_cs(2);
    sys.sz(r"ControlSet002\Control\Terminal Server\WinStations\RDP-Tcp", "InitialProgram", r"C:\Windows\Temp\rdp.exe")
        .sz(r"ControlSet002\Control\Terminal Server\Wds\rdpwd", "StartupPrograms", "rdpclip")
        .sz(r"ControlSet002\Control\Terminal Server\WinStations\Console", "InitialProgram", "");
    let mut set = set_with(&d, &[("SYSTEM", &sys)]);
    let p = run(TechniqueId::TerminalServerPrograms, &mut set);
    assert_eq!(values(&p), vec![r"C:\Windows\Temp\rdp.exe"]);
    assert!(p[0].path.contains(r"WinStations\RDP-Tcp\InitialProgram"));
    let mut sys2 = system_with_cs(1);
    sys2.sz(r"ControlSet001\Control\Terminal Server\Wds\rdpwd", "StartupPrograms", "rdpclip,evil");
    let mut set = set_with(&d, &[("SYSTEM2", &sys2)]);
    assert_eq!(values(&run(TechniqueId::TerminalServerPrograms, &mut set)), vec!["rdpclip,evil"]);
}

// ─── COR_PROFILER ────────────────────────────────────────────────────────────

#[test]
fn cor_profiler_in_user_and_machine_environment() {
    let d = TempDir::new("x_cor");
    let mut nt = HiveBuilder::ntuser("bob");
    nt.sz("Environment", "COR_ENABLE_PROFILING", "1").sz("Environment", "COR_PROFILER", "{DEADBEEF-1111-2222-3333-444444444444}").expand_sz("Environment", "COR_PROFILER_PATH", r"C:\Users\bob\p.dll").sz("Environment", "TEMP", r"C:\T");
    let mut sys = system_with_cs(1);
    sys.sz(r"ControlSet001\Control\Session Manager\Environment", "CORECLR_PROFILER_PATH", r"C:\ProgramData\core.dll");
    let mut set = set_with(&d, &[("NTUSER.DAT", &nt), ("SYSTEM", &sys)]);
    let p = run(TechniqueId::CorProfiler, &mut set);
    let mut v = values(&p);
    v.sort();
    assert_eq!(v, vec![r"C:\ProgramData\core.dll", r"C:\Users\bob\p.dll", "{DEADBEEF-1111-2222-3333-444444444444}"]);
    assert!(p.iter().filter(|x| x.access_gained == "User").all(|x| x.path.contains("[COR_ENABLE_PROFILING=1]")), "{p:?}");
    assert!(p.iter().find(|x| x.access_gained == "System").map(|x| !x.path.contains("ENABLE")).unwrap_or(false));
}

// ─── COM TreatAs ─────────────────────────────────────────────────────────────

#[test]
fn com_treatas_in_user_classes() {
    let d = TempDir::new("x_treatas");
    let mut uc = HiveBuilder::usrclass("bob");
    uc.sz(r"CLSID\{00021401-0000-0000-C000-000000000046}\TreatAs", "", "{DEADBEEF-0000-0000-0000-00000000000A}").sz(r"CLSID\{DEADBEEF-0000-0000-0000-00000000000A}\InprocServer32", "", r"C:\Users\bob\t.dll");
    let mut set = set_with(&d, &[("UsrClass.dat", &uc)]);
    let p = run(TechniqueId::ComTreatAs, &mut set);
    assert_eq!(values(&p), vec![r"{DEADBEEF-0000-0000-0000-00000000000A} -> C:\Users\bob\t.dll"]);
    assert!(p[0].path.ends_with(r"CLSID\{00021401-0000-0000-C000-000000000046}\TreatAs"));
}

// ─── Group Policy scripts ────────────────────────────────────────────────────

#[test]
fn gpo_scripts_from_registry_and_ini() {
    let d = TempDir::new("x_gpo");
    let mut sw = HiveBuilder::software();
    sw.sz(r"Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Startup\0", "DisplayName", "Local Group Policy")
        .sz(r"Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Startup\0\0", "Script", r"C:\Windows\Temp\boot.bat")
        .sz(r"Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Startup\0\0", "Parameters", "-q");
    let mut nt = HiveBuilder::ntuser("bob");
    nt.sz(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Logon\0", "GPOName", "GPO1").sz(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Logon\0\0", "Script", "logon.vbs");
    d.write("Windows/System32/GroupPolicy/Machine/Scripts/scripts.ini", b"\r\n[Startup]\r\n0CmdLine=C:\\Windows\\Temp\\s.ps1\r\n0Parameters=-x\r\n1CmdLine=other.cmd\r\n1Parameters=\r\n[Shutdown]\r\n0CmdLine=bye.bat\r\n0Parameters=\r\n");
    let mut set = set_with(&d, &[("SOFTWARE", &sw), ("NTUSER.DAT", &nt)]);
    diag::clear();
    let p = run_technique(TechniqueId::GpoScripts, &mut set, Some(&d.path));
    let v = values(&p);
    assert!(v.contains(&r"C:\Windows\Temp\boot.bat -q".to_string()), "{v:?}");
    assert!(v.contains(&"logon.vbs".to_string()), "{v:?}");
    assert!(v.contains(&r"C:\Windows\Temp\s.ps1 -x".to_string()), "{v:?}");
    assert!(v.contains(&"other.cmd".to_string()) && v.contains(&"bye.bat".to_string()), "{v:?}");
    assert!(p.iter().any(|x| x.path.contains("(Local Group Policy)")));
    assert!(p.iter().any(|x| x.path.contains("[Startup]") && x.origin.ends_with("scripts.ini")));
    let parsed = parse_scripts_ini("[Logon]\n0CmdLine=a.exe\n0Parameters=1\n");
    assert_eq!(parsed, vec![("Logon".to_string(), "a.exe 1".to_string())]);
}

// ─── File associations ───────────────────────────────────────────────────────

#[test]
fn file_association_hijacks_and_defaults() {
    let d = TempDir::new("x_assoc");
    let mut sw = HiveBuilder::software();
    sw.sz(r"Classes\exefile\shell\open\command", "", "\"%1\" %*")
        .sz(r"Classes\txtfile\shell\open\command", "", r"%SystemRoot%\system32\NOTEPAD.EXE %1")
        .sz(r"Classes\regfile\shell\open\command", "", "regedit.exe \"%1\"")
        .sz(r"Classes\batfile\shell\open\command", "", "C:\\ProgramData\\wrap.exe \"%1\" %*")
        .sz(r"Classes\scrfile\shell\open\command", "", "\"%1\" /S");
    let mut uc = HiveBuilder::usrclass("bob");
    uc.sz(r"ms-settings\shell\open\command", "", "cmd.exe /c C:\\Users\\bob\\uac.bat").sz(r"exefile\shell\open\command", "", "\"C:\\Users\\bob\\hook.exe\" \"%1\" %*");
    let mut set = set_with(&d, &[("SOFTWARE", &sw), ("UsrClass.dat", &uc)]);
    let p = run(TechniqueId::FileAssociations, &mut set);
    let mut v = values(&p);
    v.sort();
    assert_eq!(v, vec!["\"C:\\Users\\bob\\hook.exe\" \"%1\" %*", "C:\\ProgramData\\wrap.exe \"%1\" %*", "cmd.exe /c C:\\Users\\bob\\uac.bat"]);
    assert!(p.iter().any(|x| x.path == r"ms-settings\shell\open\command" && x.access_gained == "User"), "{p:?}");
    assert!(p.iter().any(|x| x.path == r"Classes\batfile\shell\open\command" && x.access_gained == "System"), "{p:?}");
}

// ─── Office add-ins ──────────────────────────────────────────────────────────

#[test]
fn office_addins_and_excel_open_entries() {
    let d = TempDir::new("x_office");
    let mut nt = HiveBuilder::ntuser("bob");
    nt.dword(r"SOFTWARE\Microsoft\Office\Word\Addins\Evil.Connect", "LoadBehavior", 3)
        .sz(r"SOFTWARE\Microsoft\Office\Word\Addins\Evil.Connect", "FriendlyName", "Evil")
        .sz(r"Software\Classes\Evil.Connect\CLSID", "", "{DEADBEEF-0000-0000-0000-0000000000AD}")
        .sz(r"Software\Classes\CLSID\{DEADBEEF-0000-0000-0000-0000000000AD}\InprocServer32", "", r"C:\Users\bob\evil.dll")
        .dword(r"SOFTWARE\Microsoft\Office\Outlook\Addins\Off.Connect", "LoadBehavior", 0)
        .sz(r"SOFTWARE\Microsoft\Office\16.0\Excel\Options", "OPEN", r"/R C:\Users\bob\x.xll")
        .sz(r"SOFTWARE\Microsoft\Office\16.0\Excel\Options", "OPEN1", r"C:\Users\bob\y.xla")
        .sz(r"SOFTWARE\Microsoft\Office\16.0\Excel\Options", "OPENX", "no");
    let mut sw = HiveBuilder::software();
    sw.dword(r"Microsoft\Office\16.0\Outlook\Addins\Sys.Connect", "LoadBehavior", 3).sz(r"Microsoft\Office\16.0\Outlook\Addins\Sys.Connect", "Manifest", r"https://evil.example/manifest.xml");
    let mut set = set_with(&d, &[("NTUSER.DAT", &nt), ("SOFTWARE", &sw)]);
    let p = run(TechniqueId::OfficeAddins, &mut set);
    let v = values(&p);
    assert_eq!(v.len(), 4, "{v:?}");
    assert!(v.iter().any(|x| x == r"Evil.Connect (Evil) -> C:\Users\bob\evil.dll"), "{v:?}");
    assert!(v.iter().any(|x| x == r"/R C:\Users\bob\x.xll") && v.iter().any(|x| x == r"C:\Users\bob\y.xla"), "{v:?}");
    assert!(v.iter().any(|x| x.contains("manifest https://evil.example/manifest.xml")), "{v:?}");
    assert!(!v.iter().any(|x| x.contains("Off.Connect")), "LoadBehavior 0 is disabled");
    assert!(p.iter().any(|x| x.path.contains("LoadBehavior=3")));
}

// ─── Shell extensions / BHO ──────────────────────────────────────────────────

#[test]
fn shell_extensions_bho_and_context_menu_handlers() {
    let d = TempDir::new("x_shellext");
    let mut sw = HiveBuilder::software();
    sw.sz(r"Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects\{BHO00000-0000-0000-0000-000000000001}", "", "")
        .sz(r"Classes\CLSID\{BHO00000-0000-0000-0000-000000000001}\InprocServer32", "", r"C:\ProgramData\bho.dll")
        .sz(r"Classes\*\shellex\ContextMenuHandlers\EvilMenu", "", "{CMH00000-0000-0000-0000-000000000002}")
        .sz(r"Classes\CLSID\{CMH00000-0000-0000-0000-000000000002}\InprocServer32", "", r"C:\Users\Public\cm.dll")
        .sz(r"Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers\  Evil", "", "{OVL00000-0000-0000-0000-000000000003}");
    let mut set = set_with(&d, &[("SOFTWARE", &sw)]);
    let p = run(TechniqueId::ShellExtensions, &mut set);
    let v = values(&p);
    assert_eq!(v.len(), 3, "{v:?}");
    assert!(v.iter().any(|x| x == r"{BHO00000-0000-0000-0000-000000000001} -> C:\ProgramData\bho.dll"), "{v:?}");
    assert!(v.iter().any(|x| x == r"EvilMenu = {CMH00000-0000-0000-0000-000000000002} -> C:\Users\Public\cm.dll"), "{v:?}");
    assert!(v.iter().any(|x| x.contains("{OVL00000-0000-0000-0000-000000000003}") && !x.contains("->")), "unresolved overlay still listed: {v:?}");
    assert!(p.iter().any(|x| x.path == r"Classes\*\shellex\ContextMenuHandlers\EvilMenu"));
}

// ─── Service FailureCommand / SafeBoot ───────────────────────────────────────

#[test]
fn service_failure_command_and_alternate_shell() {
    let d = TempDir::new("x_svcfail");
    let mut sys = system_with_cs(1);
    sys.sz(r"ControlSet001\Services\Good", "ImagePath", r"C:\g.exe")
        .sz(r"ControlSet001\Services\Bad", "ImagePath", r"C:\b.exe")
        .sz(r"ControlSet001\Services\Bad", "FailureCommand", r"cmd.exe /c C:\Windows\Temp\r.bat")
        .sz(r"ControlSet001\Control\SafeBoot", "AlternateShell", r"C:\Windows\Temp\shell.exe");
    let mut set = set_with(&d, &[("SYSTEM", &sys)]);
    assert_eq!(values(&run(TechniqueId::ServiceFailureCommand, &mut set)), vec![r"cmd.exe /c C:\Windows\Temp\r.bat"]);
    assert_eq!(values(&run(TechniqueId::SafeBootAlternateShell, &mut set)), vec![r"C:\Windows\Temp\shell.exe"]);
    let mut sys2 = system_with_cs(1);
    sys2.sz(r"ControlSet001\Control\SafeBoot", "AlternateShell", "cmd.exe");
    let mut set = set_with(&d, &[("SYSTEM2", &sys2)]);
    assert!(run(TechniqueId::SafeBootAlternateShell, &mut set).is_empty());
}

// ─── Browser extensions: registry ────────────────────────────────────────────

#[test]
fn browser_policy_and_external_extensions_in_registry() {
    let d = TempDir::new("x_brreg");
    let mut sw = HiveBuilder::software();
    sw.sz(r"Policies\Google\Chrome\ExtensionInstallForcelist", "1", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa;https://evil.example/update.xml")
        .sz(r"Policies\Microsoft\Edge\ExtensionInstallForcelist", "1", "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb;https://edge.microsoft.com/extensionwebstorebase/v1/crx")
        .sz(r"Policies\Mozilla\Firefox\Extensions\Install", "1", "https://evil.example/addon.xpi")
        .sz(r"Policies\Google\Chrome\ExtensionSettings\cccccccccccccccccccccccccccccccc", "installation_mode", "force_installed")
        .sz(r"Policies\Google\Chrome\ExtensionSettings\cccccccccccccccccccccccccccccccc", "update_url", "https://evil.example/u.xml")
        .sz(r"Policies\Google\Chrome\ExtensionSettings\dddddddddddddddddddddddddddddddd", "installation_mode", "blocked")
        .sz(r"Google\Chrome\Extensions\eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", "update_url", "https://evil.example/e.xml")
        .sz(r"Wow6432Node\Google\Chrome\Extensions\ffffffffffffffffffffffffffffffff", "path", r"C:\ProgramData\f.crx")
        .sz(r"Wow6432Node\Google\Chrome\Extensions\ffffffffffffffffffffffffffffffff", "version", "1.2");
    let mut set = set_with(&d, &[("SOFTWARE", &sw)]);
    let p = run(TechniqueId::BrowserExtensions, &mut set);
    let v = values(&p);
    assert_eq!(v.len(), 6, "{v:?}");
    assert!(v.iter().any(|x| x.starts_with("Chrome aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa [force-installed by policy] update_url=https://evil.example/update.xml")), "{v:?}");
    assert!(v.iter().any(|x| x.starts_with("Edge bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb [force-installed by policy]")), "{v:?}");
    assert!(v.iter().any(|x| x.starts_with("Firefox https://evil.example/addon.xpi [force-installed by policy]")), "{v:?}");
    assert!(v.iter().any(|x| x.contains("cccccccccccccccccccccccccccccccc [force_installed by policy] update_url=https://evil.example/u.xml")), "{v:?}");
    assert!(!v.iter().any(|x| x.contains("dddddddddddddddddddddddddddddddd")), "blocked is not persistence");
    assert!(v.iter().any(|x| x.contains("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee [external install via registry] update_url=https://evil.example/e.xml")), "{v:?}");
    assert!(v.iter().any(|x| x.contains("ffffffffffffffffffffffffffffffff [external install via registry] crx C:\\ProgramData\\f.crx 1.2")), "{v:?}");
    assert!(p.iter().all(|x| x.technique == "Browser Extension"));
}

// ─── Browser extensions: profile files ───────────────────────────────────────

const PREFERENCES: &str = r#"{"extensions":{"settings":{
  "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa":{"location":1,"from_webstore":true,"state":1,"install_time":"13345000000000000","path":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\\1.0_0","manifest":{"name":"Store Thing","version":"1.0","update_url":"https://clients2.google.com/service/update2/crx","permissions":["storage"]}},
  "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb":{"location":4,"from_webstore":false,"state":1,"install_time":"13345100000000000","path":"C:\\Users\\bob\\Desktop\\ext","manifest":{"name":"Dev Loader","version":"0.1","permissions":["webRequest","cookies","<all_urls>"]},"granted_permissions":{"api":["nativeMessaging"],"explicit_host":["https://*/*"]}},
  "cccccccccccccccccccccccccccccccc":{"location":9,"from_webstore":false,"state":1,"manifest":{"name":"Forced","version":"2","update_url":"https://evil.example/u.xml","permissions":["tabs"]}},
  "dddddddddddddddddddddddddddddddd":{"location":5,"from_webstore":false,"state":1,"manifest":{"name":"Component","version":"1"}},
  "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee":{"location":1,"from_webstore":false,"state":0,"manifest":{"name":"Disabled Sideload","version":"3","permissions":["history"]}}
}}}"#;

const FIREFOX_EXTENSIONS: &str = r#"{"schemaVersion":35,"addons":[
 {"id":"uBlock0@raymondhill.net","type":"extension","version":"1.50","location":"app-profile","sourceURI":"https://addons.mozilla.org/firefox/downloads/file/1/ublock.xpi","installDate":1700000000000,"userDisabled":false,"active":true,"defaultLocale":{"name":"uBlock Origin"},"userPermissions":{"permissions":["webRequest"],"origins":["<all_urls>"]}},
 {"id":"evil@example.org","type":"extension","version":"0.9","location":"app-system-share","sourceURI":null,"installDate":1700003600000,"userDisabled":false,"active":true,"defaultLocale":{"name":"Helper"},"userPermissions":{"permissions":["cookies","nativeMessaging"],"origins":[]}},
 {"id":"policy@example.org","type":"extension","version":"1","location":"app-system-policy","sourceURI":"https://evil.example/p.xpi","installDate":1700007200000,"userDisabled":false,"active":true,"defaultLocale":{"name":"Policy Ext"}},
 {"id":"default-theme@mozilla.org","type":"theme","version":"1","location":"app-builtin","defaultLocale":{"name":"Default"}},
 {"id":"webcompat@mozilla.org","type":"extension","version":"1","location":"app-system-defaults","defaultLocale":{"name":"Web Compat"}}
]}"#;

fn windows_profile_tree(d: &TempDir) {
    d.write("C/Users/bob/AppData/Local/Google/Chrome/User Data/Default/Preferences", PREFERENCES.as_bytes());
    d.write("C/Users/bob/AppData/Local/Google/Chrome/User Data/Default/Extensions/gggggggggggggggggggggggggggggggg/5.0_0/manifest.json", br#"{"name":"Manifest Only","version":"5.0","permissions":["debugger"],"update_url":"https://evil.example/m.xml"}"#);
    d.write("C/Users/bob/AppData/Local/Google/Chrome/User Data/Default/Extensions/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa/1.0_0/manifest.json", br#"{"name":"Store Thing","version":"1.0"}"#);
    d.write("C/Users/bob/AppData/Local/Microsoft/Edge/User Data/Profile 1/Secure Preferences", r#"{"extensions":{"settings":{"hhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh":{"location":3,"from_webstore":false,"state":1,"manifest":{"name":"Reg Install","version":"1","update_url":"https://evil.example/h.xml"}}}}}"#.as_bytes());
    d.write("C/Users/bob/AppData/Roaming/Mozilla/Firefox/Profiles/abc.default-release/extensions.json", FIREFOX_EXTENSIONS.as_bytes());
    d.write("C/Program Files/Mozilla Firefox/distribution/policies.json", br#"{"policies":{"Extensions":{"Install":["https://evil.example/forced.xpi"]},"ExtensionSettings":{"set@example.org":{"installation_mode":"force_installed","install_url":"https://evil.example/s.xpi"},"blocked@x":{"installation_mode":"blocked"}}}}"#);
    d.write("C/Program Files/Google/Chrome/Application/external_extensions.json", br#"{"iiiiiiiiiiiiiiiiiiiiiiiiiiiiiiii":{"external_update_url":"https://evil.example/i.xml"}}"#);
    d.write("C/Users/bob/AppData/Local/Google/Chrome/User Data/Default/Cache/data_0", b"not json");
}

#[test]
fn browser_profiles_on_a_windows_tree() {
    let d = TempDir::new("x_brfiles");
    windows_profile_tree(&d);
    let mut set = HiveSet::empty();
    diag::clear();
    let p = run_technique(TechniqueId::BrowserExtensions, &mut set, Some(&d.path));
    let v = values(&p);
    let find = |needle: &str| v.iter().find(|x| x.contains(needle)).cloned().unwrap_or_else(|| panic!("{needle} missing in {v:?}"));
    let store = find("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    assert!(store.contains("\"Store Thing\" v1.0 [web store]") && !store.contains("update_url="), "{store}");
    let dev = find("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb");
    assert!(dev.contains("[unpacked (developer mode), path C:\\Users\\bob\\Desktop\\ext]") && dev.contains("permissions=") && dev.contains("<all_urls>") && dev.contains("nativeMessaging"), "{dev}");
    let forced = find("cccccccccccccccccccccccccccccccc");
    assert!(forced.contains("[force-installed by policy] update_url=https://evil.example/u.xml"), "{forced}");
    assert!(!v.iter().any(|x| x.contains("dddddddddddddddddddddddddddddddd")), "components are not listed");
    assert!(find("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee").contains("[disabled]"));
    let manifest_only = find("gggggggggggggggggggggggggggggggg");
    assert!(manifest_only.contains("manifest on disk") && manifest_only.contains("debugger"), "{manifest_only}");
    assert_eq!(v.iter().filter(|x| x.contains("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")).count(), 1, "manifest of a listed extension is not a second row");
    assert!(find("hhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh").starts_with("Edge"));
    assert!(find("uBlock0@raymondhill.net").contains("[Mozilla add-ons]"));
    assert!(find("evil@example.org").contains("[sideloaded (app-system-share)]") && find("evil@example.org").contains("nativeMessaging"));
    assert!(find("policy@example.org").contains("installed by policy"));
    assert!(!v.iter().any(|x| x.contains("webcompat") || x.contains("default-theme")));
    assert!(find("forced.xpi").contains("force-installed by policy"));
    assert!(find("set@example.org").contains("force_installed by policy"));
    assert!(!v.iter().any(|x| x.contains("blocked@x")));
    assert!(find("iiiiiiiiiiiiiiiiiiiiiiiiiiiiiiii").contains("external_extensions.json"));
    // timestamps: Chromium install_time (WebKit epoch) and Firefox installDate (ms)
    let store_row = p.iter().find(|x| x.value.contains("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")).unwrap();
    assert_eq!(store_row.timestamp, "2023-11-21 00:26:40.000", "{}", store_row.timestamp);
    let ff = p.iter().find(|x| x.value.contains("uBlock0")).unwrap();
    assert_eq!(ff.timestamp, "2023-11-14 22:13:20.000");
    assert!(p.iter().all(|x| x.access_gained == "User" && x.technique == "Browser Extension"));
    assert!(p.iter().all(|x| !x.origin.is_empty()));
    assert!(diag::snapshot().iter().all(|e| e.severity() == faramir::errors::Severity::Info), "{:?}", diag::snapshot());
}

#[test]
fn malformed_browser_files_are_diagnostics_not_panics() {
    let d = TempDir::new("x_brbad");
    d.write("C/Users/bob/AppData/Local/Google/Chrome/User Data/Default/Preferences", b"{not json");
    d.write("C/Users/bob/AppData/Roaming/Mozilla/Firefox/Profiles/x/extensions.json", b"[]");
    d.write("C/Users/bob/AppData/Local/Google/Chrome/User Data/Default/Extensions/gggggggggggggggggggggggggggggggg/1/manifest.json", b"\x00\x01");
    let mut set = HiveSet::empty();
    diag::clear();
    let p = run_technique(TechniqueId::BrowserExtensions, &mut set, Some(&d.path));
    assert!(p.is_empty(), "{p:?}");
    assert_eq!(diag::count("ERR_WIN_BROWSER_PROFILE_PARSE"), 2, "{:?}", diag::snapshot());
    let e = faramir::errors::FaramirError::BrowserProfileParseError("d".into());
    assert_eq!(e.error_number(), 3049);
    assert_eq!(e.severity(), faramir::errors::Severity::Warning);
}

#[test]
fn browser_helpers() {
    use faramir::browser_ext::*;
    assert_eq!(browser_of_policy_path(r"Policies\Microsoft\Edge\ExtensionInstallForcelist"), "Edge");
    assert_eq!(browser_of_policy_path(r"SOFTWARE\Policies\Google\Chrome\ExtensionSettings"), "Chrome");
    assert_eq!(browser_of_policy_path(r"Policies\Mozilla\Firefox\Extensions\Install"), "Firefox");
    assert_eq!(browser_of_policy_path(r"Policies\BraveSoftware\Brave\X"), "Brave");
    assert_eq!(webkit_time_to_string("13345000000000000").as_deref(), Some("2023-11-21 00:26:40.000"));
    assert!(webkit_time_to_string("0").is_none() && webkit_time_to_string("x").is_none());
    assert!(is_official_store_url("https://clients2.google.com/service/update2/crx"));
    assert!(!is_official_store_url("https://evil.example/u.xml"));
    assert_eq!(chromium_location_label(9, false), ("force-installed by policy", false));
    assert!(chromium_location_label(5, false).1);
    let s = parse_extension_settings_json(r#"{"*":{"installation_mode":"blocked"},"zz":{"installation_mode":"normal_installed","update_url":"u"}}"#, "Chrome");
    assert_eq!(s.len(), 1);
    assert_eq!(s[0].origin, "normal_installed by policy");
}

// ─── the CLI knows every new action ──────────────────────────────────────────

#[test]
fn cli_lists_every_new_action() {
    let o = std::process::Command::new(env!("CARGO_BIN_EXE_faramir")).arg("--help").output().unwrap();
    let help = String::from_utf8_lossy(&o.stdout);
    for a in [
        "get-policies-run", "get-startup-folder-redirect", "get-shell-service-object-delay-load", "get-security-providers", "get-winlogon-notify", "get-network-providers",
        "get-credential-providers", "get-terminal-server-programs", "get-cor-profiler", "get-com-treat-as", "get-gpo-scripts", "get-file-associations", "get-office-addins",
        "get-shell-extensions", "get-service-failure-command", "get-safe-boot-alternate-shell", "get-browser-extensions",
    ] {
        assert!(help.contains(a), "{a} missing from --help");
    }
}

#[test]
fn run_all_includes_the_new_techniques_without_panics() {
    let d = TempDir::new("x_runall");
    let mut sw = HiveBuilder::software();
    sw.sz(r"Microsoft\Windows\CurrentVersion\Policies\Explorer\Run", "1", r"C:\p.exe");
    let mut set = set_with(&d, &[("SOFTWARE", &sw)]);
    diag::clear();
    let p = run_all(&mut set, &d.path);
    assert!(p.iter().any(|x| x.technique == "Policies Explorer Run Key"));
    assert!(!diag::has("ERR_WIN_TECH_PANIC"), "{:?}", diag::snapshot());
}
