//! Behaviour learned from a real Ubuntu 22.04 collection: usr-merged
//! duplicates, staging paths leaking into the output, timestamp format and
//! Debian's stock `pam_permit` closers.
mod common;

use common::*;
use faramir::errors::{FaramirError, Severity};
use faramir::parsers::linux::pam::{pam_permit_is_bypass, parse_pam_file};
use faramir::parsers::linux::{dedupe_events, evidence_path, process_linux_target};
use faramir::windows::diag;
use std::path::Path;

const UNIT: &str = "[Unit]\nDescription=Demo\n[Service]\nExecStart=/opt/demo/agent --serve\n[Install]\nWantedBy=multi-user.target\n";

fn uac_root(d: &TempDir) -> std::path::PathBuf {
    d.mkdir("uac-host-linux-20261028000000/[root]")
}

// ─── usr-merge duplicates ────────────────────────────────────────────────────

#[test]
fn usr_merged_units_are_reported_once() {
    let d = TempDir::new("lnx_usrmerge");
    let r = uac_root(&d);
    d.write(&format!("{}/lib/systemd/system/demo.service", r.strip_prefix(&d.path).unwrap().display()), UNIT.as_bytes());
    d.write(&format!("{}/usr/lib/systemd/system/demo.service", r.strip_prefix(&d.path).unwrap().display()), UNIT.as_bytes());
    diag::clear();
    let events = process_linux_target(&r, "host");
    let demo: Vec<_> = events.iter().filter(|e| e.commandline.as_deref().unwrap_or("").contains("demo.service")).collect();
    assert_eq!(demo.len(), 1, "{events:?}");
    assert_eq!(diag::count("ERR_LNX_DUPLICATE_SKIPPED"), 1);
    assert!(diag::snapshot().iter().all(|e| e.severity() == Severity::Info));
}

#[test]
fn usr_merged_generators_are_reported_once_with_the_host_path() {
    let d = TempDir::new("lnx_gen");
    let r = uac_root(&d);
    let rel = r.strip_prefix(&d.path).unwrap().display().to_string();
    d.write(&format!("{rel}/lib/systemd/system-generators/demo-gen"), b"#!/bin/sh\necho hi\n");
    d.write(&format!("{rel}/usr/lib/systemd/system-generators/demo-gen"), b"#!/bin/sh\necho hi\n");
    diag::clear();
    let events = process_linux_target(&r, "host");
    let gens: Vec<_> = events.iter().filter(|e| e.artifact == "linux:systemd:generator").collect();
    assert_eq!(gens.len(), 1, "{gens:?}");
    let cmd = gens[0].commandline.clone().unwrap();
    assert!(cmd.ends_with("systemd/system-generators/demo-gen"), "{cmd}");
    assert!(!cmd.contains("uac-host") && !cmd.contains("[root]") && !cmd.contains('\\'), "staging path leaked: {cmd}");
}

#[test]
fn different_units_with_the_same_name_in_etc_and_lib_are_both_kept() {
    let d = TempDir::new("lnx_override");
    let r = uac_root(&d);
    let rel = r.strip_prefix(&d.path).unwrap().display().to_string();
    d.write(&format!("{rel}/lib/systemd/system/demo.service"), UNIT.as_bytes());
    d.write(&format!("{rel}/etc/systemd/system/demo.service"), UNIT.replace("/opt/demo/agent", "/tmp/.x/agent").as_bytes());
    let events = process_linux_target(&r, "host");
    let demo: Vec<_> = events.iter().filter(|e| e.commandline.as_deref().unwrap_or("").contains("demo.service")).collect();
    assert_eq!(demo.len(), 2, "an override with a different ExecStart is a second finding: {demo:?}");
}

#[test]
fn dedupe_keeps_the_first_copy_and_counts_the_rest() {
    let mk = |cmd: &str| faramir::event::Event {
        timestamp: "2026-01-01 00:00:00.000".into(),
        computer: "h".into(),
        artifact: "linux:systemd:generator".into(),
        event_id: 0,
        pid: 0,
        subject_username: "root".into(),
        target_username: "root".into(),
        processname: "g".into(),
        commandline: Some(cmd.into()),
        parentprocessname: "systemd".into(),
    };
    diag::clear();
    let out = dedupe_events(vec![mk("/usr/lib/systemd/system-generators/g"), mk("/lib/systemd/system-generators/g"), mk("/usr/sbin/g"), mk("/sbin/g"), mk("/opt/g")]);
    assert_eq!(out.len(), 3);
    assert_eq!(out[0].commandline.as_deref(), Some("/usr/lib/systemd/system-generators/g"));
    assert_eq!(diag::count("ERR_LNX_DUPLICATE_SKIPPED"), 2);
}

// ─── paths as they were on the host ──────────────────────────────────────────

#[test]
fn periodic_cron_scripts_show_their_host_path() {
    let d = TempDir::new("lnx_cronpath");
    let r = uac_root(&d);
    let rel = r.strip_prefix(&d.path).unwrap().display().to_string();
    d.write(&format!("{rel}/etc/cron.daily/apport"), b"#!/bin/sh\nrm -f /var/crash/*\n");
    let events = process_linux_target(&r, "host");
    let cron: Vec<_> = events.iter().filter(|e| e.artifact == "linux:cron:periodic:cron.daily").collect();
    assert_eq!(cron.len(), 1);
    assert_eq!(cron[0].commandline.as_deref(), Some("Periodic Cron Script: /etc/cron.daily/apport"));
}

#[test]
fn evidence_path_heuristics_without_a_root() {
    assert_eq!(evidence_path(Path::new(r"C:\Temp\faramir_arc_1\uac-h-linux-1\[root]\etc\cron.daily\apport")), "/etc/cron.daily/apport");
    assert_eq!(evidence_path(Path::new("/mnt/suspect/etc/systemd/system/x.service")), "/etc/systemd/system/x.service");
    assert_eq!(evidence_path(Path::new("/mnt/suspect/usr/lib/systemd/system-generators/g")), "/usr/lib/systemd/system-generators/g");
    assert_eq!(evidence_path(Path::new("/home/analyst/cases/h/home/bob/.bashrc")), "/home/bob/.bashrc");
    assert_eq!(evidence_path(Path::new("/mnt/suspect/lib/udev/rules.d/99.rules")), "/lib/udev/rules.d/99.rules");
    assert_eq!(evidence_path(Path::new("/etc/crontab")), "/etc/crontab");
    assert_eq!(evidence_path(Path::new("nothing/known/here.txt")), "/nothing/known/here.txt");
}

// ─── timestamps ──────────────────────────────────────────────────────────────

#[test]
fn linux_timestamps_use_the_timeline_format() {
    let d = TempDir::new("lnx_ts");
    let r = uac_root(&d);
    let rel = r.strip_prefix(&d.path).unwrap().display().to_string();
    d.write(&format!("{rel}/etc/crontab"), b"* * * * * root /opt/x/run.sh\n");
    d.write(&format!("{rel}/etc/sudoers"), b"bob ALL=(ALL) NOPASSWD:ALL\n");
    d.write(&format!("{rel}/etc/pam.d/sshd"), b"auth sufficient pam_permit.so\n");
    d.write(&format!("{rel}/etc/ld.so.preload"), b"/tmp/evil.so\n");
    d.write(&format!("{rel}/etc/systemd/system/demo.service"), UNIT.as_bytes());
    let events = process_linux_target(&r, "host");
    assert!(events.len() >= 5, "{events:?}");
    let re = |s: &str| {
        let b = s.as_bytes();
        b.len() == 23 && b[4] == b'-' && b[7] == b'-' && b[10] == b' ' && b[13] == b':' && b[16] == b':' && b[19] == b'.'
    };
    for e in &events {
        assert!(re(&e.timestamp), "{} has timestamp {:?}", e.artifact, e.timestamp);
        assert!(!e.timestamp.contains('T') && !e.timestamp.contains('+'), "{:?}", e.timestamp);
    }
}

// ─── pam_permit ──────────────────────────────────────────────────────────────

fn pam(d: &TempDir, name: &str, body: &str) -> Vec<faramir::event::Event> {
    let p = d.write(&format!("pam.d/{name}"), body.as_bytes());
    parse_pam_file(&p, "h").unwrap()
}

#[test]
fn debian_stock_common_auth_is_not_a_bypass() {
    let d = TempDir::new("pam_stock");
    let body = "auth\t[success=2 default=ignore]\tpam_unix.so nullok\nauth\t[success=1 default=ignore]\tpam_sss.so use_first_pass\nauth\trequisite\t\t\tpam_deny.so\nauth\trequired\t\t\tpam_permit.so\nauth\toptional\t\t\tpam_cap.so\n";
    let evs = pam(&d, "common-auth", body);
    assert!(evs.iter().all(|e| e.artifact != "linux:pam:permit_bypass"), "{evs:?}");
    let body = "account\t[success=1 new_authtok_reqd=done default=ignore]\tpam_unix.so\naccount\trequisite\t\t\tpam_deny.so\naccount\trequired\t\t\tpam_permit.so\naccount\tsufficient\t\t\tpam_localuser.so\naccount\t[default=bad success=ok user_unknown=ignore]\tpam_sss.so\n";
    let evs = pam(&d, "common-account", body);
    assert!(evs.iter().all(|e| e.artifact != "linux:pam:permit_bypass"), "{evs:?}");
}

#[test]
fn pam_permit_first_in_its_stack_is_a_bypass() {
    let d = TempDir::new("pam_first");
    let evs = pam(&d, "sshd", "auth required pam_permit.so\nauth required pam_unix.so\n");
    assert_eq!(evs.iter().filter(|e| e.artifact == "linux:pam:permit_bypass").count(), 1);
    // the account stack is independent of the auth stack
    let evs = pam(&d, "su", "auth required pam_unix.so\naccount required pam_permit.so\n");
    assert_eq!(evs.iter().filter(|e| e.artifact == "linux:pam:permit_bypass").count(), 1, "{evs:?}");
}

#[test]
fn pam_permit_with_a_stack_ending_control_is_a_bypass_anywhere() {
    let d = TempDir::new("pam_suff");
    for ctl in ["sufficient", "binding", "[success=done default=ignore]", "[success=ok new_authtok_reqd=ok default=bad]"] {
        let evs = pam(&d, "login", &format!("auth required pam_unix.so\nauth {ctl} pam_permit.so\n"));
        assert_eq!(evs.iter().filter(|e| e.artifact == "linux:pam:permit_bypass").count(), 1, "{ctl}");
    }
}

#[test]
fn pam_permit_rule_table() {
    assert!(pam_permit_is_bypass("required", true));
    assert!(!pam_permit_is_bypass("required", false));
    assert!(!pam_permit_is_bypass("requisite", false));
    assert!(!pam_permit_is_bypass("optional", false));
    assert!(!pam_permit_is_bypass("[default=1]", false));
    assert!(pam_permit_is_bypass("sufficient", false));
    assert!(pam_permit_is_bypass("SUFFICIENT", false));
    assert!(pam_permit_is_bypass("[success=done default=ignore]", false));
    assert!(!pam_permit_is_bypass("[success=2 default=ignore]", false));
}

#[test]
fn pam_type_with_leading_dash_is_still_a_stack_member() {
    let d = TempDir::new("pam_dash");
    let evs = pam(&d, "x", "-auth optional pam_unix.so\nauth required pam_permit.so\n");
    assert!(evs.iter().all(|e| e.artifact != "linux:pam:permit_bypass"), "{evs:?}");
}

#[test]
fn linux_duplicate_error_code() {
    let e = FaramirError::LinuxDuplicateSkipped("d".into());
    assert_eq!(e.code(), "ERR_LNX_DUPLICATE_SKIPPED");
    assert_eq!(e.error_number(), 4022);
    assert_eq!(e.severity(), Severity::Info);
    assert_eq!(e.category(), "LNX");
    assert!(FaramirError::catalog().iter().any(|c| c.error_number() == 4022));
}

#[test]
fn bracketed_pam_control_does_not_hide_the_module() {
    let d = TempDir::new("pam_bracket");
    let evs = pam(&d, "sshd", "auth [success=1 default=ignore] pam_unix.so nullok\nauth [success=done default=die] pam_exec.so /tmp/x.sh\n");
    let exec: Vec<_> = evs.iter().filter(|e| e.artifact == "linux:pam:exec_backdoor").collect();
    assert_eq!(exec.len(), 1, "{evs:?}");
    assert!(exec[0].commandline.as_deref().unwrap().contains("[success=done default=die] pam_exec.so /tmp/x.sh"), "{:?}", exec[0].commandline);
    let evs = pam(&d, "broken", "auth [success=1 default=ignore pam_unix.so\n");
    assert!(evs.is_empty(), "unterminated control is skipped, not misparsed: {evs:?}");
}

// ─── browser extensions on a Linux tree ──────────────────────────────────────

#[test]
fn browser_profiles_and_policies_on_a_linux_tree() {
    let d = TempDir::new("lnx_browser");
    let r = uac_root(&d);
    let rel = r.strip_prefix(&d.path).unwrap().display().to_string();
    d.write(&format!("{rel}/home/bob/.config/google-chrome/Default/Preferences"), br#"{"extensions":{"settings":{"abcdefghijklmnopabcdefghijklmnop":{"location":4,"from_webstore":false,"state":1,"install_time":"13345000000000000","path":"/opt/ext","manifest":{"name":"Dev Loader","version":"1.0","permissions":["webRequest","<all_urls>"]}}}}}"#);
    d.write(&format!("{rel}/home/bob/.config/google-chrome/Default/Extensions/zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz/2.0_0/manifest.json"), br#"{"name":"Orphan","version":"2.0","permissions":["cookies"]}"#);
    d.write(&format!("{rel}/home/bob/.mozilla/firefox/abc.default/extensions.json"), br#"{"addons":[{"id":"side@x","type":"extension","version":"1","location":"app-system-share","sourceURI":null,"installDate":1700000000000,"userDisabled":false,"active":true,"defaultLocale":{"name":"Side"},"userPermissions":{"permissions":["nativeMessaging"],"origins":[]}}]}"#);
    d.write(&format!("{rel}/etc/opt/chrome/policies/managed/lab.json"), br#"{"ExtensionInstallForcelist":["forcedforcedforcedforcedforcedfo;https://evil.example/f.xml"]}"#);
    d.write(&format!("{rel}/etc/firefox/policies/policies.json"), br#"{"policies":{"Extensions":{"Install":["https://evil.example/p.xpi"]}}}"#);
    d.write(&format!("{rel}/home/bob/.config/google-chrome/Default/Cache/data_0"), b"junk");
    diag::clear();
    let events = process_linux_target(&r, "host");
    let br: Vec<_> = events.iter().filter(|e| e.artifact.starts_with("linux:browser:")).collect();
    let cmds: Vec<&str> = br.iter().map(|e| e.commandline.as_deref().unwrap_or("")).collect();
    assert_eq!(br.len(), 5, "{cmds:?}");
    let find = |n: &str| cmds.iter().find(|c| c.contains(n)).copied().unwrap_or_else(|| panic!("{n} missing: {cmds:?}"));
    assert!(find("abcdefghijklmnopabcdefghijklmnop").contains("[unpacked (developer mode), path /opt/ext]"));
    assert!(find("abcdefghijklmnopabcdefghijklmnop").contains("/home/bob/.config/google-chrome/Default/Preferences"), "host path, not staging");
    assert!(find("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz").contains("manifest on disk"));
    assert!(find("side@x").contains("sideloaded") && find("side@x").contains("nativeMessaging"));
    assert!(find("forcedforcedforcedforcedforcedfo").contains("force-installed by policy"));
    assert!(find("p.xpi").contains("force-installed by policy"));
    let forced = br.iter().filter(|e| e.artifact == "linux:browser:extension_forced").count();
    assert_eq!(forced, 2, "{br:?}");
    let dev = br.iter().find(|e| e.commandline.as_deref().unwrap().contains("abcdefghijklmnop")).unwrap();
    assert_eq!(dev.subject_username, "bob");
    assert_eq!(dev.timestamp, "2023-11-21 00:26:40.000");
    assert_eq!(dev.processname, "chrome");
    assert!(!diag::has("ERR_WIN_BROWSER_PROFILE_PARSE"));
}
