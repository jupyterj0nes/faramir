//! Every registry technique against synthetic hives: the right root in the
//! right hive is detected, bogus roots in the wrong hive are not, and nothing
//! ever panics out of the engine.
mod common;

use common::*;
use faramir::windows::diag;
use faramir::windows::hives::HiveKind;
use faramir::windows::techniques::*;
use std::path::PathBuf;

fn set_with(dir: &TempDir, hives: &[(&str, &HiveBuilder)]) -> HiveSet {
    let paths: Vec<PathBuf> = hives.iter().map(|(name, b)| b.write(&dir.join(name))).collect();
    HiveSet::from_paths(&paths, &dir.path)
}

fn run(id: TechniqueId, set: &mut HiveSet) -> Vec<Persistence> {
    diag::clear();
    run_technique(id, set, None)
}

fn values(p: &[Persistence]) -> Vec<String> {
    p.iter().map(|x| x.value.clone()).collect()
}

fn accesses(p: &[Persistence]) -> Vec<String> {
    p.iter().map(|x| x.access_gained.clone()).collect()
}

fn system_with_cs(cs: u32) -> HiveBuilder {
    let mut b = HiveBuilder::system();
    b.dword("Select", "Current", cs);
    b.key(&format!("ControlSet{cs:03}"));
    b
}

// ─── Run family ──────────────────────────────────────────────────────────────

#[test]
fn run_in_software_hive_is_system_access() {
    let d = TempDir::new("t_run_sw");
    let mut sw = HiveBuilder::software();
    sw.sz(r"Microsoft\Windows\CurrentVersion\Run", "Updater", r"C:\evil\u.exe");
    let mut set = set_with(&d, &[("SOFTWARE", &sw)]);
    let p = run(TechniqueId::Run, &mut set);
    assert_eq!(values(&p), vec![r"C:\evil\u.exe"]);
    assert_eq!(accesses(&p), vec!["System"]);
    assert_eq!(p[0].technique, "Registry Run Key");
    assert!(p[0].path.ends_with("SOFTWARE"));
    assert_eq!(p[0].timestamp, "2024-01-17 21:20:00.000");
}

#[test]
fn run_in_software_wow6432node() {
    let d = TempDir::new("t_run_wow");
    let mut sw = HiveBuilder::software();
    sw.sz(r"Wow6432Node\Microsoft\Windows\CurrentVersion\Run", "Legacy32", r"C:\x86\l.exe");
    let mut set = set_with(&d, &[("SOFTWARE", &sw)]);
    assert_eq!(values(&run(TechniqueId::Run, &mut set)), vec![r"C:\x86\l.exe"]);
}

#[test]
fn run_in_ntuser_is_user_access() {
    let d = TempDir::new("t_run_nt");
    let mut nt = HiveBuilder::ntuser("bob");
    nt.sz(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "OneDrive", r"C:\Users\bob\od.exe");
    let mut set = set_with(&d, &[("NTUSER.DAT", &nt)]);
    let p = run(TechniqueId::Run, &mut set);
    assert_eq!(values(&p), vec![r"C:\Users\bob\od.exe"]);
    assert_eq!(accesses(&p), vec!["User"]);
}

#[test]
fn run_in_default_hive_is_scanned_with_user_layout() {
    let d = TempDir::new("t_run_def");
    let mut def = HiveBuilder::default_hive();
    def.sz(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "SysCtx", r"C:\sys.exe");
    let mut set = set_with(&d, &[("DEFAULT", &def)]);
    assert_eq!(values(&run(TechniqueId::Run, &mut set)), vec![r"C:\sys.exe"]);
}

#[test]
fn run_hkcu_layout_inside_software_hive_is_not_scanned() {
    // A SOFTWARE hive never has a SOFTWARE\ subkey; such data must not be read with the HKCU root.
    let d = TempDir::new("t_run_wrong");
    let mut sw = HiveBuilder::software();
    sw.sz(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "Bogus", r"C:\bogus.exe");
    let mut set = set_with(&d, &[("SOFTWARE", &sw)]);
    assert!(run(TechniqueId::Run, &mut set).is_empty());
}

#[test]
fn run_unknown_kind_hive_is_tried_against_every_root() {
    diag::clear();
    let d = TempDir::new("t_run_unknown");
    let mut blob = HiveBuilder::anonymous();
    blob.sz(r"Microsoft\Windows\CurrentVersion\Run", "Hidden", r"C:\h.exe");
    let mut set = set_with(&d, &[("blob.bin", &blob)]);
    assert_eq!(set.kinds(), vec![HiveKind::Unknown]);
    assert_eq!(values(&run(TechniqueId::Run, &mut set)), vec![r"C:\h.exe"]);
}

#[test]
fn run_handles_expand_sz_resident_and_ignores_dword() {
    let d = TempDir::new("t_run_types");
    let mut sw = HiveBuilder::software();
    sw.expand_sz(r"Microsoft\Windows\CurrentVersion\Run", "A", r"%TEMP%\a.exe")
        .sz_resident(r"Microsoft\Windows\CurrentVersion\Run", "B", "b")
        .dword(r"Microsoft\Windows\CurrentVersion\Run", "C", 7);
    let mut set = set_with(&d, &[("SOFTWARE", &sw)]);
    let mut v = values(&run(TechniqueId::Run, &mut set));
    v.sort();
    assert_eq!(v, vec![r"%TEMP%\a.exe", "b"]);
}

#[test]
fn run_empty_string_is_reported_as_value_empty_warning() {
    let d = TempDir::new("t_run_empty");
    let mut sw = HiveBuilder::software();
    sw.sz(r"Microsoft\Windows\CurrentVersion\Run", "Blank", "   ");
    let mut set = set_with(&d, &[("SOFTWARE", &sw)]);
    assert!(run(TechniqueId::Run, &mut set).is_empty());
    assert!(diag::has("ERR_WIN_VALUE_EMPTY"));
}

#[test]
fn run_multiple_hives_all_contribute() {
    let d = TempDir::new("t_run_multi");
    let mut sw = HiveBuilder::software();
    sw.sz(r"Microsoft\Windows\CurrentVersion\Run", "S", r"C:\s.exe");
    let mut bob = HiveBuilder::ntuser("bob");
    bob.sz(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "B", r"C:\b.exe");
    let mut alice = HiveBuilder::ntuser("alice");
    alice.sz(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run", "A", r"C:\a.exe");
    let mut set = set_with(&d, &[("SOFTWARE", &sw), ("bob_NTUSER.DAT", &bob), ("alice_NTUSER.DAT", &alice)]);
    let mut v = values(&run(TechniqueId::Run, &mut set));
    v.sort();
    assert_eq!(v, vec![r"C:\a.exe", r"C:\b.exe", r"C:\s.exe"]);
}

#[test]
fn runonce_runex_runonceex() {
    let d = TempDir::new("t_runonce");
    let mut sw = HiveBuilder::software();
    sw.sz(r"Microsoft\Windows\CurrentVersion\RunOnce", "a", "1.exe")
        .sz(r"Microsoft\Windows\CurrentVersion\RunEx", "b", "2.exe")
        .sz(r"Microsoft\Windows\CurrentVersion\RunOnceEx", "c", "3.exe");
    let mut nt = HiveBuilder::ntuser("bob");
    nt.sz(r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce", "d", "4.exe")
        .sz(r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunEx", "e", "5.exe")
        .sz(r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx", "f", "6.exe");
    let mut set = set_with(&d, &[("SOFTWARE", &sw), ("NTUSER.DAT", &nt)]);
    let mut once = values(&run(TechniqueId::RunOnce, &mut set));
    once.sort();
    assert_eq!(once, vec!["1.exe", "4.exe"]);
    let mut ex = values(&run(TechniqueId::RunEx, &mut set));
    ex.sort();
    assert_eq!(ex, vec!["2.exe", "5.exe"]);
    let mut onceex = values(&run(TechniqueId::RunOnceEx, &mut set));
    onceex.sort();
    assert_eq!(onceex, vec!["3.exe", "6.exe"]);
}

// ─── Debugger-style techniques ───────────────────────────────────────────────

#[test]
fn ifeo_debugger_in_software_and_wow6432node() {
    let d = TempDir::new("t_ifeo");
    let mut sw = HiveBuilder::software();
    sw.sz(r"Microsoft\Windows NT\CurrentVersion\Image File Execution Options\sethc.exe", "Debugger", r"C:\Windows\System32\cmd.exe")
        .sz(r"Wow6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\notepad.exe", "Debugger", r"C:\evil32.exe")
        .dword(r"Microsoft\Windows NT\CurrentVersion\Image File Execution Options\benign.exe", "GlobalFlag", 0x200);
    let mut set = set_with(&d, &[("SOFTWARE", &sw)]);
    let mut v = values(&run(TechniqueId::ImageFileExecutionOptions, &mut set));
    v.sort();
    assert_eq!(v, vec![r"C:\Windows\System32\cmd.exe", r"C:\evil32.exe"]);
}

#[test]
fn ifeo_is_not_read_from_user_hives() {
    let d = TempDir::new("t_ifeo_nt");
    let mut nt = HiveBuilder::ntuser("bob");
    nt.sz(r"Microsoft\Windows NT\CurrentVersion\Image File Execution Options\x.exe", "Debugger", "y");
    let mut set = set_with(&d, &[("NTUSER.DAT", &nt)]);
    assert!(run(TechniqueId::ImageFileExecutionOptions, &mut set).is_empty());
    assert!(diag::has("ERR_WIN_TECH_NO_HIVE"));
}

#[test]
fn aedebug_direct_value_and_subkeys() {
    let d = TempDir::new("t_aedebug");
    let mut sw = HiveBuilder::software();
    sw.sz(r"Microsoft\Windows NT\CurrentVersion\AeDebug", "Debugger", r"C:\evil\dbg.exe -p %ld")
        .sz(r"Wow6432Node\Microsoft\Windows NT\CurrentVersion\AeDebug\Sub", "X", "y");
    let mut set = set_with(&d, &[("SOFTWARE", &sw)]);
    let p = run(TechniqueId::AeDebug, &mut set);
    assert_eq!(p.len(), 2);
    assert!(p.iter().any(|x| x.path.contains(r"C:\evil\dbg.exe")));
    assert!(p.iter().all(|x| x.value == "AeDebug"));
}

#[test]
fn wer_hangs_in_software_and_ntuser() {
    let d = TempDir::new("t_wer");
    let mut sw = HiveBuilder::software();
    sw.sz(r"Microsoft\Windows\Windows Error Reporting\Hangs", "Debugger", r"C:\sys_dbg.exe");
    let mut nt = HiveBuilder::ntuser("bob");
    nt.sz(r"SOFTWARE\Microsoft\Windows\Windows Error Reporting\Hangs", "ReflectDebugger", r"C:\usr_dbg.exe");
    let mut set = set_with(&d, &[("SOFTWARE", &sw), ("NTUSER.DAT", &nt)]);
    let p = run(TechniqueId::WerFaultHangs, &mut set);
    assert_eq!(p.len(), 2);
    let mut a = accesses(&p);
    a.sort();
    assert_eq!(a, vec!["System", "User"]);
}

#[test]
fn silent_process_exit_monitor() {
    let d = TempDir::new("t_spe");
    let mut sw = HiveBuilder::software();
    sw.sz(r"Microsoft\Windows NT\CurrentVersion\SilentProcessExit\notepad.exe", "MonitorProcess", r"C:\evil\mon.exe")
        .sz(r"Microsoft\Windows NT\CurrentVersion\SilentProcessExit\empty.exe", "MonitorProcess", "")
        .sz(r"Wow6432Node\Microsoft\Windows NT\CurrentVersion\SilentProcessExit\calc.exe", "MonitorProcess", r"C:\m32.exe");
    let mut set = set_with(&d, &[("SOFTWARE", &sw)]);
    let p = run(TechniqueId::SilentProcessExit, &mut set);
    let mut v = values(&p);
    v.sort();
    assert_eq!(v, vec![r"C:\evil\mon.exe", r"C:\m32.exe"]);
    assert!(p.iter().any(|x| x.path.ends_with(r"SilentProcessExit\notepad.exe")));
}

// ─── Shell / logon ───────────────────────────────────────────────────────────

#[test]
fn cmd_autorun_user_and_system() {
    let d = TempDir::new("t_cmd");
    let mut nt = HiveBuilder::ntuser("bob");
    nt.sz(r"Software\Microsoft\Command Processor", "AutoRun", r"C:\u.bat");
    let mut sw = HiveBuilder::software();
    sw.sz(r"Microsoft\Command Processor", "AutoRun", r"C:\s.bat");
    let mut set = set_with(&d, &[("NTUSER.DAT", &nt), ("SOFTWARE", &sw)]);
    let p = run(TechniqueId::CmdAutorun, &mut set);
    assert_eq!(p.len(), 2);
    let mut a = accesses(&p);
    a.sort();
    assert_eq!(a, vec!["System", "User"]);
    assert!(p.iter().all(|x| x.value == "CmdAutoRun"));
}

#[test]
fn explorer_load_and_run_values() {
    let d = TempDir::new("t_load");
    let mut nt = HiveBuilder::ntuser("bob");
    nt.sz(r"Software\Microsoft\Windows NT\CurrentVersion\Windows", "Load", r"C:\l.exe")
        .sz(r"Software\Microsoft\Windows NT\CurrentVersion\Windows", "Run", r"C:\r.exe")
        .sz(r"Software\Microsoft\Windows NT\CurrentVersion\Windows", "Unrelated", "x");
    let mut set = set_with(&d, &[("NTUSER.DAT", &nt)]);
    let p = run(TechniqueId::ExplorerLoad, &mut set);
    assert_eq!(p.len(), 2);
    assert!(p.iter().any(|x| x.path.contains("Name: Load")));
    assert!(p.iter().any(|x| x.path.contains("Name: Run")));
    assert_eq!(accesses(&p), vec!["User", "User"]);
}

#[test]
fn winlogon_userinit_shell_mpnotify() {
    let d = TempDir::new("t_winlogon");
    let mut sw = HiveBuilder::software();
    sw.sz(r"Microsoft\Windows NT\CurrentVersion\Winlogon", "Userinit", r"C:\Windows\system32\userinit.exe,C:\evil.exe")
        .sz(r"Microsoft\Windows NT\CurrentVersion\Winlogon", "Shell", "explorer.exe")
        .sz(r"Microsoft\Windows NT\CurrentVersion\Winlogon", "mpnotify", r"C:\mp.exe");
    let mut nt = HiveBuilder::ntuser("bob");
    nt.sz(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "Shell", r"explorer.exe,C:\u.exe");
    let mut set = set_with(&d, &[("SOFTWARE", &sw), ("NTUSER.DAT", &nt)]);

    let u = run(TechniqueId::WinlogonUserinit, &mut set);
    assert_eq!(u.len(), 1);
    assert!(u[0].path.contains(r"C:\evil.exe"));
    assert_eq!(u[0].value, "WinLogonUserInit");

    let s = run(TechniqueId::WinlogonShell, &mut set);
    assert_eq!(s.len(), 2, "HKLM and HKCU Shell");
    let mut a = accesses(&s);
    a.sort();
    assert_eq!(a, vec!["System", "User"]);

    let m = run(TechniqueId::WinlogonMpNotify, &mut set);
    assert_eq!(m.len(), 1);
    assert!(m[0].path.contains(r"C:\mp.exe"));
}

#[test]
fn userinit_mpr_logon_script() {
    let d = TempDir::new("t_mpr");
    let mut nt = HiveBuilder::ntuser("bob");
    nt.sz("Environment", "UserInitMprLogonScript", r"C:\logon.bat").sz("Environment", "TEMP", r"C:\Temp");
    let mut def = HiveBuilder::default_hive();
    def.sz("Environment", "UserInitMprLogonScript", r"C:\def.bat");
    let mut set = set_with(&d, &[("NTUSER.DAT", &nt), ("DEFAULT", &def)]);
    let mut v = values(&run(TechniqueId::UserInitMprScript, &mut set));
    v.sort();
    assert_eq!(v, vec![r"C:\def.bat", r"C:\logon.bat"]);
}

#[test]
fn screensaver_only_from_user_hives() {
    let d = TempDir::new("t_scr");
    let mut nt = HiveBuilder::ntuser("bob");
    nt.sz(r"Control Panel\Desktop", "SCRNSAVE.EXE", r"C:\evil.scr");
    let mut nt2 = HiveBuilder::ntuser("alice");
    nt2.sz(r"Control Panel\Desktop", "SCRNSAVE.EXE", "  ");
    let mut sw = HiveBuilder::software();
    sw.sz(r"Control Panel\Desktop", "SCRNSAVE.EXE", r"C:\bogus.scr");
    let mut set = set_with(&d, &[("bob_NTUSER.DAT", &nt), ("alice_NTUSER.DAT", &nt2), ("SOFTWARE", &sw)]);
    let p = run(TechniqueId::Screensaver, &mut set);
    assert_eq!(values(&p), vec![r"C:\evil.scr"]);
    assert_eq!(accesses(&p), vec!["User"]);
}

// ─── DLL hijack families ─────────────────────────────────────────────────────

#[test]
fn app_cert_dlls_from_control_set() {
    let d = TempDir::new("t_appcert");
    let mut sys = system_with_cs(1);
    sys.sz(r"ControlSet001\Control\Session Manager\AppCertDlls", "evil", r"C:\ac.dll");
    let mut set = set_with(&d, &[("SYSTEM", &sys)]);
    let p = run(TechniqueId::AppCertDlls, &mut set);
    assert_eq!(p.len(), 1);
    assert!(p[0].path.contains(r"C:\ac.dll"));
    assert_eq!(p[0].value, "AppCertDlls");
}

#[test]
fn app_paths_user_system_and_wow() {
    let d = TempDir::new("t_apppaths");
    let mut sw = HiveBuilder::software();
    sw.sz(r"Microsoft\Windows\CurrentVersion\App Paths\evil.exe", "", r"C:\e.exe")
        .sz(r"Wow6432Node\Microsoft\Windows\CurrentVersion\App Paths\w.exe", "", r"C:\w.exe");
    let mut nt = HiveBuilder::ntuser("bob");
    nt.sz(r"SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\u.exe", "", r"C:\u.exe");
    let mut set = set_with(&d, &[("SOFTWARE", &sw), ("NTUSER.DAT", &nt)]);
    let p = run(TechniqueId::AppPaths, &mut set);
    assert_eq!(p.len(), 3);
    let mut names = values(&p);
    names.sort();
    assert_eq!(names, vec!["evil.exe", "u.exe", "w.exe"]);
    assert!(p.iter().any(|x| x.path == r"C:\u.exe" && x.access_gained == "User"));
}

#[test]
fn service_dlls_direct_and_parameters() {
    let d = TempDir::new("t_svcdll");
    let mut sys = system_with_cs(1);
    sys.sz(r"ControlSet001\Services\SvcA", "ServiceDll", r"C:\a.dll")
        .sz(r"ControlSet001\Services\SvcB\Parameters", "ServiceDll", r"C:\b.dll")
        .sz(r"ControlSet001\Services\SvcC", "ImagePath", r"C:\c.exe");
    let mut set = set_with(&d, &[("SYSTEM", &sys)]);
    let mut v: Vec<String> = run(TechniqueId::ServiceDlls, &mut set).iter().map(|p| p.path.clone()).collect();
    v.sort();
    assert_eq!(v, vec![r"C:\a.dll", r"C:\b.dll"]);
}

#[test]
fn windows_services_image_paths_exclude_dll_hosted() {
    let d = TempDir::new("t_svc");
    let mut sys = system_with_cs(1);
    sys.sz(r"ControlSet001\Services\SvcA", "ServiceDll", r"C:\a.dll")
        .sz(r"ControlSet001\Services\SvcA", "ImagePath", r"svchost.exe -k x")
        .sz(r"ControlSet001\Services\SvcC", "ImagePath", r"C:\c.exe")
        .sz(r"ControlSet001\Services\SvcC", "DisplayName", "Evil C");
    let mut set = set_with(&d, &[("SYSTEM", &sys)]);
    let p = run(TechniqueId::WindowsServices, &mut set);
    assert_eq!(p.len(), 1);
    assert_eq!(p[0].path, r"C:\c.exe");
    assert_eq!(p[0].value, "Evil C");
}

#[test]
fn gp_extension_dlls() {
    let d = TempDir::new("t_gpe");
    let mut sw = HiveBuilder::software();
    sw.sz(r"Microsoft\Windows NT\CurrentVersion\Winlogon\GPExtensions\{guid}", "DllName", r"C:\gp.dll");
    let mut set = set_with(&d, &[("SOFTWARE", &sw)]);
    let p = run(TechniqueId::GpExtensionDlls, &mut set);
    assert_eq!(p.len(), 1);
    assert_eq!(p[0].path, r"C:\gp.dll");
}

#[test]
fn chm_helper_dll_user_and_system() {
    let d = TempDir::new("t_chm");
    let mut nt = HiveBuilder::ntuser("bob");
    nt.sz(r"Software\Microsoft\HtmlHelp Author", "Location", r"C:\u.dll");
    let mut sw = HiveBuilder::software();
    sw.sz(r"Microsoft\HtmlHelp Author", "Location", r"C:\s.dll");
    let mut set = set_with(&d, &[("NTUSER.DAT", &nt), ("SOFTWARE", &sw)]);
    let p = run(TechniqueId::ChmHelperDll, &mut set);
    assert_eq!(p.len(), 2);
    assert!(p.iter().any(|x| x.path.contains(r"C:\u.dll") && x.access_gained == "User"));
    assert!(p.iter().any(|x| x.path.contains(r"C:\s.dll") && x.access_gained == "System"));
}

#[test]
fn hhctrl_hijacking_in_every_classes_root() {
    let d = TempDir::new("t_hhctrl");
    let clsid = r"CLSID\{52A2AAAE-085D-4187-97EA-8C30DB990436}\InprocServer32";
    let mut sw = HiveBuilder::software();
    sw.sz(&format!(r"Classes\{clsid}"), "", r"C:\hklm.dll");
    let mut nt = HiveBuilder::ntuser("bob");
    nt.sz(&format!(r"Software\Classes\{clsid}"), "", r"C:\hkcu.dll");
    let mut uc = HiveBuilder::usrclass("bob");
    uc.sz(clsid, "", r"C:\usrclass.dll");
    let mut set = set_with(&d, &[("SOFTWARE", &sw), ("NTUSER.DAT", &nt), ("UsrClass.dat", &uc)]);
    assert_eq!(set.kinds(), vec![HiveKind::Software, HiveKind::NtUser, HiveKind::UsrClass]);
    let mut v = values(&run(TechniqueId::HhCtrlHijacking, &mut set));
    v.sort();
    assert_eq!(v, vec![r"C:\hkcu.dll", r"C:\hklm.dll", r"C:\usrclass.dll"]);
}

#[test]
fn appinit_dlls_respects_load_flag() {
    let d = TempDir::new("t_appinit");
    let mut on = HiveBuilder::software();
    on.sz(r"Microsoft\Windows NT\CurrentVersion\Windows", "AppInit_DLLs", r"C:\ai.dll")
        .dword(r"Microsoft\Windows NT\CurrentVersion\Windows", "LoadAppInit_DLLs", 1)
        .sz(r"Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows", "AppInit_DLLs", r"C:\ai32.dll");
    let mut set = set_with(&d, &[("SOFTWARE", &on)]);
    let p = run(TechniqueId::AppInitDlls, &mut set);
    assert_eq!(p.len(), 2);
    assert!(p.iter().any(|x| x.technique == "AppInit DLLs" && x.value == r"C:\ai.dll"));
    assert!(p.iter().any(|x| x.technique == "AppInit DLLs (Wow6432Node)" && x.value == r"C:\ai32.dll"));

    let d2 = TempDir::new("t_appinit_off");
    let mut off = HiveBuilder::software();
    off.sz(r"Microsoft\Windows NT\CurrentVersion\Windows", "AppInit_DLLs", r"C:\ai.dll")
        .dword(r"Microsoft\Windows NT\CurrentVersion\Windows", "LoadAppInit_DLLs", 0);
    let mut set2 = set_with(&d2, &[("SOFTWARE", &off)]);
    assert!(run(TechniqueId::AppInitDlls, &mut set2).is_empty());
}

#[test]
fn com_hijacking_inproc_and_local_server_in_ntuser_and_usrclass() {
    let d = TempDir::new("t_com");
    let mut nt = HiveBuilder::ntuser("bob");
    nt.sz(r"Software\Classes\CLSID\{A}\InprocServer32", "", r"C:\a.dll")
        .sz(r"Software\Classes\CLSID\{B}\LocalServer32", "", r"C:\b.exe")
        .sz(r"Software\Classes\CLSID\{C}\InprocServer32", "", "");
    let mut uc = HiveBuilder::usrclass("bob");
    uc.sz(r"CLSID\{D}\InprocServer32", "", r"C:\d.dll");
    let mut set = set_with(&d, &[("NTUSER.DAT", &nt), ("UsrClass.dat", &uc)]);
    let p = run(TechniqueId::ComHijacking, &mut set);
    let mut v = values(&p);
    v.sort();
    assert_eq!(v, vec![r"C:\a.dll", r"C:\b.exe", r"C:\d.dll"]);
    assert!(p.iter().any(|x| x.path == r"Software\Classes\CLSID\{B}\LocalServer32"));
    assert!(p.iter().any(|x| x.path == r"CLSID\{D}\InprocServer32"));
}

#[test]
fn netsh_helper_dlls_including_wow() {
    let d = TempDir::new("t_netsh");
    let mut sw = HiveBuilder::software();
    sw.sz(r"Microsoft\NetSh", "evilhelper", r"C:\nh.dll").sz(r"Wow6432Node\Microsoft\NetSh", "h32", r"C:\nh32.dll");
    let mut set = set_with(&d, &[("SOFTWARE", &sw)]);
    let p = run(TechniqueId::NetshHelperDlls, &mut set);
    assert_eq!(p.len(), 2);
    assert!(p.iter().any(|x| x.path == r"Microsoft\NetSh\evilhelper"));
}

// ─── SYSTEM-hive lists ───────────────────────────────────────────────────────

#[test]
fn lsa_packages_filter_defaults() {
    let d = TempDir::new("t_lsa");
    let mut sys = system_with_cs(1);
    sys.multi_sz(r"ControlSet001\Control\Lsa", "Authentication Packages", &["msv1_0", "evilpkg"])
        .multi_sz(r"ControlSet001\Control\Lsa", "Security Packages", &["kerberos", "msv1_0", "mimilib"])
        .multi_sz(r"ControlSet001\Control\Lsa", "Notification Packages", &["scecli", "rassfm"])
        .multi_sz(r"ControlSet001\Control\Lsa\OSConfig", "Security Packages", &["kerberos", "oscfg_evil"]);
    let mut set = set_with(&d, &[("SYSTEM", &sys)]);
    let p = run(TechniqueId::LsaPackages, &mut set);
    let mut v = values(&p);
    v.sort();
    assert_eq!(v, vec!["evilpkg", "mimilib", "oscfg_evil"]);
    assert!(p.iter().any(|x| x.technique == "LSA Authentication Packages"));
    assert!(p.iter().any(|x| x.technique == "LSA Security Packages (OSConfig)"));
    assert!(p.iter().all(|x| x.path.contains("ControlSet001")));
}

#[test]
fn lsa_single_sz_value_is_accepted() {
    let d = TempDir::new("t_lsa_sz");
    let mut sys = system_with_cs(1);
    sys.sz(r"ControlSet001\Control\Lsa", "Authentication Packages", "evilsz");
    let mut set = set_with(&d, &[("SYSTEM", &sys)]);
    assert_eq!(values(&run(TechniqueId::LsaPackages, &mut set)), vec!["evilsz"]);
}

#[test]
fn boot_execute_and_setup_execute() {
    let d = TempDir::new("t_boot");
    let mut sys = system_with_cs(1);
    sys.multi_sz(r"ControlSet001\Control\Session Manager", "BootExecute", &["autocheck autochk *", "evilboot.exe"])
        .multi_sz(r"ControlSet001\Control\Session Manager", "SetupExecute", &["setupevil.exe"]);
    let mut set = set_with(&d, &[("SYSTEM", &sys)]);
    let p = run(TechniqueId::BootExecute, &mut set);
    let mut v = values(&p);
    v.sort();
    assert_eq!(v, vec!["evilboot.exe", "setupevil.exe"]);
    assert!(p.iter().any(|x| x.path.ends_with(r"Session Manager\BootExecute")));
    assert!(p.iter().any(|x| x.path.ends_with(r"Session Manager\SetupExecute")));
}

#[test]
fn print_monitors_skip_standard() {
    let d = TempDir::new("t_print");
    let mut sys = system_with_cs(1);
    sys.sz(r"ControlSet001\Control\Print\Monitors\Local Port", "Driver", "localspl.dll")
        .sz(r"ControlSet001\Control\Print\Monitors\Evil Monitor", "Driver", "evilmon.dll")
        .key(r"ControlSet001\Control\Print\Monitors\NoDriver");
    let mut set = set_with(&d, &[("SYSTEM", &sys)]);
    let p = run(TechniqueId::PrintMonitors, &mut set);
    let mut v = values(&p);
    v.sort();
    assert_eq!(v, vec!["NoDriver", "evilmon.dll"]);
    assert!(p.iter().all(|x| x.path.starts_with(r"SYSTEM\ControlSet001\Control\Print\Monitors\")));
}

#[test]
fn time_providers_skip_standard_dlls() {
    let d = TempDir::new("t_time");
    let mut sys = system_with_cs(1);
    sys.sz(r"ControlSet001\Services\W32Time\TimeProviders\NtpClient", "DllName", r"%systemroot%\system32\w32time.DLL")
        .sz(r"ControlSet001\Services\W32Time\TimeProviders\VMICTimeProvider", "DllName", r"C:\Windows\System32\vmictimeprovider.dll")
        .sz(r"ControlSet001\Services\W32Time\TimeProviders\Evil", "DllName", r"C:\evil\tp.dll");
    let mut set = set_with(&d, &[("SYSTEM", &sys)]);
    let p = run(TechniqueId::TimeProviders, &mut set);
    assert_eq!(values(&p), vec![r"C:\evil\tp.dll"]);
}

#[test]
fn nldp_dll_override_paths() {
    let d = TempDir::new("t_nldp");
    let mut sys = system_with_cs(1);
    sys.sz(r"ControlSet001\Control\ContentIndex\Language\English_US", "WBDLLPathOverride", r"C:\wb.dll")
        .sz(r"ControlSet001\Control\ContentIndex\Language\Neutral", "StemmerDLLPathOverride", r"C:\stem.dll")
        .key(r"ControlSet001\Control\ContentIndex\Language\Clean");
    let mut set = set_with(&d, &[("SYSTEM", &sys)]);
    let p = run(TechniqueId::NldpDllOverridePath, &mut set);
    let mut v = values(&p);
    v.sort();
    assert_eq!(v, vec![r"C:\stem.dll", r"C:\wb.dll"]);
}

#[test]
fn active_setup_in_software_wow_and_ntuser() {
    let d = TempDir::new("t_asetup");
    let mut sw = HiveBuilder::software();
    sw.sz(r"Microsoft\Active Setup\Installed Components\{A}", "StubPath", r"C:\a.exe")
        .sz(r"Wow6432Node\Microsoft\Active Setup\Installed Components\{B}", "StubPath", r"C:\b.exe")
        .sz(r"Microsoft\Active Setup\Installed Components\{E}", "StubPath", "  ");
    let mut nt = HiveBuilder::ntuser("bob");
    nt.sz(r"SOFTWARE\Microsoft\Active Setup\Installed Components\{C}", "StubPath", r"C:\c.exe");
    let mut set = set_with(&d, &[("SOFTWARE", &sw), ("NTUSER.DAT", &nt)]);
    let p = run(TechniqueId::ActiveSetup, &mut set);
    let mut v = values(&p);
    v.sort();
    assert_eq!(v, vec![r"C:\a.exe", r"C:\b.exe", r"C:\c.exe"]);
    assert!(p.iter().any(|x| x.access_gained == "User" && x.value == r"C:\c.exe"));
    assert!(p.iter().any(|x| x.path == r"Microsoft\Active Setup\Installed Components\{A}"));
}

#[test]
fn scheduled_tasks_registry_and_xml() {
    let d = TempDir::new("t_tasks");
    let mut sw = HiveBuilder::software();
    sw.sz(r"Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks\{T1}", "Path", r"\Microsoft\Windows\Evil\Task");
    let mut set = set_with(&d, &[("SOFTWARE", &sw)]);
    d.write(
        "C/Windows/System32/Tasks/EvilTask",
        br#"<?xml version="1.0" encoding="UTF-16"?><Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task"><Actions><Exec><Command>C:\evil.exe</Command><Arguments>-x</Arguments></Exec></Actions></Task>"#,
    );
    d.write("C/Windows/System32/Tasks/Broken", b"<Task><unclosed>");
    d.write("C/Windows/System32/Tasks/NoCommand", br#"<Task xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task"><Actions/></Task>"#);
    diag::clear();
    let p = run_technique(TechniqueId::ScheduledTasks, &mut set, Some(&d.path));
    assert_eq!(p.len(), 2);
    assert!(p.iter().any(|x| x.technique == "Scheduled Task" && x.path == r"\Microsoft\Windows\Evil\Task"));
    assert!(p.iter().any(|x| x.technique == "Scheduled Task (XML)" && x.value == r"C:\evil.exe -x"));
    assert!(diag::has("ERR_WIN_TASK_XML_PARSE"));
}

// ─── Filesystem techniques ───────────────────────────────────────────────────

#[test]
fn startup_folder_programs() {
    let d = TempDir::new("t_startup");
    d.write("C/Users/bob/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/evil.lnk", b"lnk");
    d.write("C/Users/bob/Documents/not_startup.txt", b"x");
    let mut set = HiveSet::empty();
    let p = run_technique(TechniqueId::StartupPrograms, &mut set, Some(&d.path));
    assert_eq!(p.len(), 1);
    assert!(p[0].path.ends_with("evil.lnk"));
    assert_eq!(p[0].access_gained, "User");
}

#[test]
fn powershell_profiles() {
    let d = TempDir::new("t_ps");
    d.write("C/Users/bob/Documents/WindowsPowerShell/Microsoft.PowerShell_profile.ps1", b"iex (x)");
    d.write("C/Windows/System32/WindowsPowerShell/v1.0/profile.ps1", b"x");
    d.write("C/other/script.ps1", b"x");
    let mut set = HiveSet::empty();
    let p = run_technique(TechniqueId::PowerShellProfiles, &mut set, Some(&d.path));
    assert_eq!(p.len(), 2);
}

#[test]
fn terminal_profile_start_on_user_login() {
    let d = TempDir::new("t_term");
    d.write(
        "C/Users/bob/AppData/Local/Packages/Microsoft.WindowsTerminal_8wekyb3d8bbwe/LocalState/settings.json",
        br#"{"profiles":{"list":[{"name":"evil","startOnUserLogin":true,"commandline":"C:\\evil.exe"},{"name":"ok","commandline":"pwsh"}]}}"#,
    );
    d.write("C/Users/bob/AppData/Local/Packages/Microsoft.WindowsTerminal_x/LocalState/settings.json", b"{not json");
    d.write("C/Users/bob/.vscode/settings.json", br#"{"profiles":{"list":[{"startOnUserLogin":true}]}}"#);
    diag::clear();
    let mut set = HiveSet::empty();
    let p = run_technique(TechniqueId::TerminalProfileStartOnUserLogin, &mut set, Some(&d.path));
    assert_eq!(p.len(), 1);
    assert_eq!(p[0].value, r"C:\evil.exe");
    assert!(diag::has("ERR_WIN_TERMINAL_JSON_PARSE"));
}

#[test]
fn filesystem_techniques_without_source_return_nothing() {
    let mut set = HiveSet::empty();
    assert!(run_technique(TechniqueId::StartupPrograms, &mut set, None).is_empty());
    assert!(run_technique(TechniqueId::PowerShellProfiles, &mut set, None).is_empty());
    assert!(run_technique(TechniqueId::TerminalProfileStartOnUserLogin, &mut set, None).is_empty());
}

// ─── Control set resolution ──────────────────────────────────────────────────

#[test]
fn control_set_from_select_current() {
    let d = TempDir::new("t_cs_sel");
    let mut sys = system_with_cs(2);
    sys.key("ControlSet001");
    sys.sz(r"ControlSet002\Control\Print\Monitors\Evil", "Driver", "e.dll");
    sys.sz(r"ControlSet001\Control\Print\Monitors\Old", "Driver", "o.dll");
    let mut set = set_with(&d, &[("SYSTEM", &sys)]);
    let p = run(TechniqueId::PrintMonitors, &mut set);
    assert_eq!(values(&p), vec!["e.dll"]);
    assert!(p[0].path.contains("ControlSet002"));
}

#[test]
fn control_set_without_select_uses_lowest() {
    let d = TempDir::new("t_cs_nosel");
    let mut sys = HiveBuilder::system();
    sys.sz(r"ControlSet003\Control\Print\Monitors\Evil", "Driver", "e.dll");
    sys.key("ControlSet005");
    let mut set = set_with(&d, &[("SYSTEM", &sys)]);
    let p = run(TechniqueId::PrintMonitors, &mut set);
    assert_eq!(values(&p), vec!["e.dll"]);
    assert!(p[0].path.contains("ControlSet003"));
}

#[test]
fn control_set_select_pointing_to_missing_falls_back_with_warning() {
    let d = TempDir::new("t_cs_bad");
    let mut sys = HiveBuilder::system();
    sys.dword("Select", "Current", 9);
    sys.sz(r"ControlSet001\Control\Print\Monitors\Evil", "Driver", "e.dll");
    let mut set = set_with(&d, &[("SYSTEM", &sys)]);
    let p = run(TechniqueId::PrintMonitors, &mut set);
    assert_eq!(values(&p), vec!["e.dll"]);
    assert!(diag::has("ERR_WIN_CONTROL_SET_FAIL"));
}

#[test]
fn control_set_missing_entirely_is_a_warning() {
    let d = TempDir::new("t_cs_none");
    let mut sys = HiveBuilder::system();
    sys.sz("Setup", "x", "y");
    let mut set = set_with(&d, &[("SYSTEM", &sys)]);
    assert!(run(TechniqueId::PrintMonitors, &mut set).is_empty());
    assert!(diag::has("ERR_WIN_CONTROL_SET_MISSING"));
}

#[test]
fn control_set_unknown_hive_without_control_set_is_silent() {
    let d = TempDir::new("t_cs_unknown");
    let mut blob = HiveBuilder::anonymous();
    blob.sz(r"Microsoft\Windows\CurrentVersion\Run", "x", "y.exe");
    let mut set = set_with(&d, &[("blob.bin", &blob)]);
    assert!(run(TechniqueId::PrintMonitors, &mut set).is_empty());
    assert!(!diag::has("ERR_WIN_CONTROL_SET_MISSING"));
}

// ─── Engine robustness ───────────────────────────────────────────────────────

#[test]
fn technique_without_applicable_hive_records_warning() {
    let d = TempDir::new("t_nohive");
    let nt = HiveBuilder::ntuser("bob");
    let mut set = set_with(&d, &[("NTUSER.DAT", &nt)]);
    assert!(run(TechniqueId::ServiceDlls, &mut set).is_empty());
    assert!(diag::has("ERR_WIN_TECH_NO_HIVE"));
}

#[test]
fn garbage_hive_bins_do_not_crash_the_engine() {
    diag::clear();
    let d = TempDir::new("t_garbage");
    let mut bytes = base_block(1, 1, 0x20, 8192, r"emRoot\System32\Config\SOFTWARE", 0, 5).to_vec();
    let mut junk = vec![0xEEu8; 8192];
    junk[..4].copy_from_slice(b"hbin");
    bytes.extend_from_slice(&junk);
    let p = d.write("SOFTWARE", &bytes);
    let mut set = HiveSet::from_paths(&[p], &d.path);
    assert_eq!(set.len(), 1);
    let out = run_technique(TechniqueId::Run, &mut set, None);
    assert!(out.is_empty());
    let s = diag::snapshot();
    assert!(
        s.iter().any(|e| matches!(e.code(), "ERR_WIN_TECH_PANIC" | "ERR_WIN_ROOT_KEY_FAIL" | "ERR_WIN_KEY_NOT_FOUND" | "ERR_WIN_HIVE_OPEN" | "ERR_WIN_HIVE_PARSE_PANIC")),
        "{s:?}"
    );
}

#[test]
fn hive_set_from_paths_skips_unreadable_files() {
    diag::clear();
    let d = TempDir::new("t_set_bad");
    let good = HiveBuilder::software().write(&d.join("SOFTWARE"));
    let bad = d.write("SYSTEM", b"nope");
    let set = HiveSet::from_paths(&[good, bad, d.join("missing")], &d.path);
    assert_eq!(set.len(), 1);
    assert_eq!(set.kinds(), vec![HiveKind::Software]);
    assert!(diag::has("ERR_WIN_HIVE_SIGNATURE"));
    assert!(diag::has("ERR_WIN_HIVE_OPEN"));
}

#[test]
fn hive_set_indices_for_roots() {
    let d = TempDir::new("t_set_idx");
    let set = set_with(
        &d,
        &[
            ("SOFTWARE", &HiveBuilder::software()),
            ("SYSTEM", &HiveBuilder::system()),
            ("NTUSER.DAT", &HiveBuilder::ntuser("bob")),
            ("DEFAULT", &HiveBuilder::default_hive()),
            ("UsrClass.dat", &HiveBuilder::usrclass("bob")),
            ("blob.bin", &HiveBuilder::anonymous()),
        ],
    );
    assert_eq!(set.len(), 6);
    assert_eq!(set.indices_for(Root::Software), vec![0, 5]);
    assert_eq!(set.indices_for(Root::System), vec![1, 5]);
    assert_eq!(set.indices_for(Root::UserProfile), vec![2, 3, 5]);
    assert_eq!(set.indices_for(Root::UsrClass), vec![4, 5]);
    assert_eq!(set.infos().len(), 6);
    assert_eq!(set.info(1).unwrap().kind, HiveKind::System);
    assert!(set.info(9).is_none());
}

#[test]
fn hive_set_opens_each_hive_once_and_reports_recovery() {
    diag::clear();
    let d = TempDir::new("t_set_once");
    let base = HiveBuilder::software();
    let mut step = HiveBuilder::software();
    step.sz(r"Microsoft\Windows\CurrentVersion\Run", "R", r"C:\r.exe");
    let fx = build_dirty(&base, &[&step], 3, false);
    let hive = write_dirty(&d, "SOFTWARE", &fx);
    let mut set = HiveSet::from_paths(&[hive], &d.path);
    assert!(set.recovery(0).is_none(), "not opened yet");
    assert_eq!(values(&run_technique(TechniqueId::Run, &mut set, None)), vec![r"C:\r.exe"]);
    assert!(set.recovery(0).unwrap().logs_applied);
    let before = diag::count("ERR_WIN_HIVE_RECOVERED");
    run_technique(TechniqueId::RunOnce, &mut set, None);
    assert_eq!(diag::count("ERR_WIN_HIVE_RECOVERED"), before, "second technique must reuse the opened hive");
}

#[test]
fn run_all_covers_every_hive_kind_and_technique() {
    let d = TempDir::new("t_run_all");
    let mut sw = HiveBuilder::software();
    sw.sz(r"Microsoft\Windows\CurrentVersion\Run", "S", r"C:\s.exe")
        .sz(r"Microsoft\Active Setup\Installed Components\{A}", "StubPath", r"C:\as.exe")
        .sz(r"Microsoft\NetSh", "h", r"C:\h.dll");
    let mut sys = system_with_cs(1);
    sys.sz(r"ControlSet001\Services\Evil", "ImagePath", r"C:\svc.exe")
        .multi_sz(r"ControlSet001\Control\Lsa", "Security Packages", &["badpkg"]);
    let mut nt = HiveBuilder::ntuser("bob");
    nt.sz(r"Control Panel\Desktop", "SCRNSAVE.EXE", r"C:\scr.scr")
        .sz(r"Software\Classes\CLSID\{X}\InprocServer32", "", r"C:\com.dll");
    let mut uc = HiveBuilder::usrclass("bob");
    uc.sz(r"CLSID\{52A2AAAE-085D-4187-97EA-8C30DB990436}\InprocServer32", "", r"C:\hh.dll");
    let mut set = set_with(&d, &[("SOFTWARE", &sw), ("SYSTEM", &sys), ("NTUSER.DAT", &nt), ("UsrClass.dat", &uc)]);
    d.write("Users/bob/Startup/x.lnk", b"x");
    diag::clear();
    let all = run_all(&mut set, &d.path);
    let v = values(&all);
    for expected in [r"C:\s.exe", r"C:\as.exe", r"C:\h.dll", "badpkg", r"C:\scr.scr", r"C:\com.dll", r"C:\hh.dll", "Startup Folder"] {
        assert!(v.contains(&expected.to_string()), "missing {expected} in {v:?}");
    }
    assert!(all.iter().any(|p| p.path == r"C:\svc.exe"));
    assert!(!diag::has("ERR_WIN_TECH_PANIC"));
    assert!(!diag::has("ERR_WIN_TECH_NO_HIVE"), "{:?}", diag::snapshot());
}

#[test]
fn run_all_with_empty_set_runs_only_filesystem_techniques() {
    let d = TempDir::new("t_run_all_empty");
    d.write("Users/bob/Startup/x.lnk", b"x");
    let mut set = HiveSet::empty();
    diag::clear();
    let all = run_all(&mut set, &d.path);
    assert_eq!(all.len(), 1);
    assert!(!diag::has("ERR_WIN_TECH_NO_HIVE"));
}

// ─── Catalogue invariants ────────────────────────────────────────────────────

#[test]
fn technique_catalogue_is_complete_and_unique() {
    assert_eq!(TechniqueId::ALL.len(), 35);
    let labels: std::collections::HashSet<&str> = TechniqueId::ALL.iter().map(|t| t.label()).collect();
    assert_eq!(labels.len(), 35);
}

#[test]
fn technique_roots_reference_the_right_hives() {
    let sorted = |t: TechniqueId| {
        let mut k = t.hive_kinds();
        k.sort_by_key(|k| k.label());
        k
    };
    assert_eq!(sorted(TechniqueId::Run), vec![HiveKind::Default, HiveKind::NtUser, HiveKind::Software]);
    assert_eq!(sorted(TechniqueId::PrintMonitors), vec![HiveKind::System]);
    assert_eq!(sorted(TechniqueId::ComHijacking), vec![HiveKind::Default, HiveKind::NtUser, HiveKind::UsrClass]);
    assert_eq!(sorted(TechniqueId::HhCtrlHijacking), vec![HiveKind::Default, HiveKind::NtUser, HiveKind::Software, HiveKind::UsrClass]);
    assert!(TechniqueId::StartupPrograms.hive_kinds().is_empty());
    assert!(!TechniqueId::StartupPrograms.is_registry_based());
    assert!(TechniqueId::ActiveSetup.is_registry_based());
}

#[test]
fn user_profile_roots_never_start_with_a_hive_relative_hklm_path() {
    // HKCU paths that target HKLM data must be rooted at SOFTWARE\ / Software\ ; HKLM\SOFTWARE paths must not.
    for t in TechniqueId::ALL {
        for r in t.roots() {
            match r.root {
                Root::Software => assert!(
                    !r.path.to_uppercase().starts_with("SOFTWARE\\"),
                    "{:?}: {} is rooted wrong for the SOFTWARE hive",
                    t,
                    r.path
                ),
                Root::System => assert!(!r.path.to_uppercase().starts_with("SYSTEM\\") && !r.path.to_uppercase().contains("CURRENTCONTROLSET"), "{:?}: {}", t, r.path),
                Root::UsrClass => assert!(!r.path.to_uppercase().starts_with("SOFTWARE\\CLASSES"), "{:?}: {}", t, r.path),
                Root::UserProfile => {}
            }
            assert!(!r.access.is_empty());
        }
    }
}

#[test]
fn root_accepts_matrix() {
    assert!(Root::Software.accepts(HiveKind::Software));
    assert!(!Root::Software.accepts(HiveKind::System));
    assert!(Root::System.accepts(HiveKind::System));
    assert!(!Root::System.accepts(HiveKind::NtUser));
    assert!(Root::UserProfile.accepts(HiveKind::NtUser));
    assert!(Root::UserProfile.accepts(HiveKind::Default));
    assert!(!Root::UserProfile.accepts(HiveKind::UsrClass));
    assert!(Root::UsrClass.accepts(HiveKind::UsrClass));
    for r in [Root::Software, Root::System, Root::UserProfile, Root::UsrClass] {
        assert!(r.accepts(HiveKind::Unknown), "{r:?}");
        assert!(!r.accepts(HiveKind::Sam));
        assert!(!r.label().is_empty());
    }
}

#[test]
fn persistence_to_event_mapping() {
    let p = Persistence {
        timestamp: "2024-01-17 21:20:00.000".into(),
        technique: "Registry Run Key".into(),
        path: r"C:\ev\SOFTWARE".into(),
        value: r"C:\evil\u.exe --silent".into(),
        access_gained: "System".into(),
    };
    let e = faramir::windows::persistence_to_event(&p, "HOST01");
    assert_eq!(e.computer, "HOST01");
    assert_eq!(e.artifact, "windows:persistence:registry_run_key");
    assert_eq!(e.processname, "u.exe");
    assert_eq!(e.commandline.as_deref(), Some(r"C:\evil\u.exe --silent"));
    assert_eq!(e.parentprocessname, r"C:\ev\SOFTWARE");
    assert_eq!(e.subject_username, "System");
    assert_eq!(e.timestamp, p.timestamp);
    let bare = Persistence { value: "rundll32 x".into(), technique: "COM Object Hijacking".into(), ..Default::default() };
    let e2 = faramir::windows::persistence_to_event(&bare, "H");
    assert_eq!(e2.processname, "rundll32");
    assert_eq!(e2.artifact, "windows:persistence:com_object_hijacking");
}

#[test]
fn process_name_extraction_from_real_autostart_values() {
    use faramir::windows::process_name_of;
    assert_eq!(process_name_of(r"C:\Windows\System32\OneDriveSetup.exe /thfirstsetup"), "OneDriveSetup.exe");
    assert_eq!(process_name_of(r"%ProgramFiles%\Windows Mail\wab.exe /Upgrade"), "wab.exe");
    assert_eq!(process_name_of(r#""C:\Program Files\Evil Corp\agent.exe" --silent"#), "agent.exe");
    assert_eq!(process_name_of(r"explorer.exe,C:\evil\x.exe"), "explorer.exe");
    assert_eq!(process_name_of(r"C:\Windows\system32\userinit.exe,"), "userinit.exe");
    assert_eq!(process_name_of(r"rundll32.exe C:\evil\p.dll,Run"), "rundll32.exe");
    assert_eq!(process_name_of(r"C:\evil\p.dll"), "p.dll");
    assert_eq!(process_name_of("powershell -enc AAAA"), "powershell");
    assert_eq!(process_name_of(r"/usr/bin/evil --flag"), "/usr/bin/evil");
    assert_eq!(process_name_of(r"C:\exe_tools\run.exe"), "run.exe", "folder containing 'exe' must not fool the cut");
    assert_eq!(process_name_of(""), "");
    assert_eq!(process_name_of("   "), "");
}

#[test]
fn value_helpers_on_defaults() {
    assert!(is_default_value_name(""));
    assert!(is_default_value_name("(Default)"));
    assert!(is_default_value_name("(default)"));
    assert!(!is_default_value_name("Default"));
    assert_eq!(LSA_DEFAULT_PACKAGES.len(), 11);
    assert!(BOOT_EXECUTE_DEFAULTS.contains(&"autocheck autochk *"));
    assert_eq!(STANDARD_PRINT_MONITORS.len(), 5);
}
