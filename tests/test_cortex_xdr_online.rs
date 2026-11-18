//! A synthetic Cortex XDR online triage, laid out the way the console's
//! download is: one folder per collector at the top of the zip, holding
//! either a table (`netstat/netstat.csv`, every table with a `host_name`
//! column) or the collector's raw files in a zip named after it
//! (`cron_files/cron_files_<32 hex>_<32 hex>.zip`). Inside that zip the files
//! sit under made-up names (`entry_1_0/crontab`) and `manifest.json` says
//! where each one was on the host.
use faramir::ingest::archive::{cortex_online_hostname, inspect_triage_archive, unpack_archive_recursive, unpack_cortex_online};
use faramir::ingest::triage::TriageType;
use std::io::Write;
use std::path::{Path, PathBuf};
use zip::write::FileOptions;
use zip::ZipWriter;

const HOST: &str = "websrv01.corp.example";
const ID1: &str = "0123456789abcdef0123456789abcdef";
const ID2: &str = "fedcba9876543210fedcba9876543210";
/// 2024-03-01T12:00:00Z, in the milliseconds the triage's file listing uses.
const MTIME_MS: u64 = 1_709_294_400_000;

fn zip_bytes(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut cursor = std::io::Cursor::new(Vec::new());
    {
        let mut w = ZipWriter::new(&mut cursor);
        for (name, data) in entries {
            w.start_file(*name, FileOptions::default()).unwrap();
            w.write_all(data).unwrap();
        }
        w.finish().unwrap();
    }
    cursor.into_inner()
}

fn table(columns: &str, rows: &[&str]) -> Vec<u8> {
    let mut s = format!("{columns},generated_time,agent_id,host_name\n");
    for r in rows {
        s.push_str(&format!("{r},2026-11-01T10:00:00Z,agent-1,{HOST}\n"));
    }
    s.into_bytes()
}

fn manifest(files: &[(&str, &str)]) -> Vec<u8> {
    let files: Vec<serde_json::Value> = files
        .iter()
        .map(|(path, archived)| serde_json::json!({"path": path, "driveName": "/", "size": 1, "archivedPath": archived, "sha256": "00"}))
        .collect();
    serde_json::to_vec(&serde_json::json!({"entries": [{"requestedPath": "/etc/*", "files": files}], "collectedFilesCount": files.len()})).unwrap()
}

const CRONTAB: &[u8] = b"SHELL=/bin/sh\n*/5 * * * * root /usr/local/bin/beacon.sh\n";
const SERVICE: &[u8] = b"[Unit]\nDescription=Updater\n[Service]\nExecStart=/opt/updater/run.sh\n[Install]\nWantedBy=multi-user.target\n";

/// The package, written to a fresh folder. Returns (folder, zip).
fn build_package(tag: &str, file_name: &str) -> (PathBuf, PathBuf) {
    let dir = std::env::temp_dir().join(format!("faramir_cortex_online_{}_{}", tag, std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let cron = zip_bytes(&[
        ("manifest.json", &manifest(&[("/etc/crontab", "entry_1_0/crontab"), ("/etc/cron.d/backup", "entry_2_0/backup"), ("/../../outside/evil.service", "entry_3_0/evil.service")])),
        ("stdout.txt", b"done"),
        ("script_output.txt", b"{}"),
        ("entry_1_0/crontab", CRONTAB),
        ("entry_2_0/backup", b"0 3 * * * root /usr/local/bin/backup.sh\n"),
        ("entry_3_0/evil.service", SERVICE),
    ]);
    let units = zip_bytes(&[
        ("manifest.json", &manifest(&[("/etc/systemd/system/updater.service", "entry_1_0/updater.service"), ("/lib/systemd/system/merged.service", "entry_2_0/merged.service")])),
        ("entry_1_0/updater.service", SERVICE),
        ("entry_2_0/merged.service", SERVICE),
        // the manifest does not name this one
        ("entry_9_0/orphan.service", SERVICE),
    ]);
    let bodyfile = table(
        "name,inode,mode_as_string,uid,gid,size,atime,mtime,ctime,crtime,md5",
        &[
            &format!("/etc/crontab,1,-rw-r--r--,0,0,57,{m},{m},{m},{m},x", m = MTIME_MS),
            // a usr-merged system: the listing says /usr/lib, the collector /lib
            &format!("/usr/lib/systemd/system/merged.service,2,-rw-r--r--,0,0,90,{m},{m},{m},{m},x", m = MTIME_MS),
        ],
    );
    let package = zip_bytes(&[
        // an empty table first: the host must come from one that has a row
        ("uname/uname.csv", b"manufacturer,model,generated_time,agent_id,host_name\n"),
        ("netstat/netstat.csv", &table("protocol,local_port", &["tcp,22"])),
        ("process_listing/process_listing_linux.csv", &table("name,pid", &["sshd,812"])),
        ("bodyfile/bodyfile.csv", &bodyfile),
        (&format!("cron_files/cron_files_{ID1}_{ID2}.zip"), &cron),
        (&format!("systemd_units/systemd_units_{ID1}_{ID2}.zip"), &units),
    ]);
    let zip = dir.join(file_name);
    std::fs::write(&zip, package).unwrap();
    (dir, zip)
}

fn files_under(root: &Path) -> Vec<String> {
    let mut out: Vec<String> = walkdir::WalkDir::new(root)
        .into_iter()
        .flatten()
        .filter(|e| e.path().is_file() && e.file_name() != faramir::parsers::linux::UNDATED_MARKER)
        .map(|e| e.path().strip_prefix(root).unwrap().to_string_lossy().replace('\\', "/"))
        .collect();
    out.sort();
    out
}

#[test]
fn the_package_is_recognised_and_the_host_comes_from_its_tables() {
    // the download is named anything; here, after another machine
    let (dir, zip) = build_package("detect", "some-download-2.zip");
    let info = inspect_triage_archive(&zip).expect("inspected");
    assert_eq!(info.kind, TriageType::CortexXdrOnline);
    assert_eq!(info.kind.label(), "Cortex XDR online triage");
    assert_eq!(info.hostname.as_deref(), Some(HOST));
    assert_eq!(cortex_online_hostname(&zip).as_deref(), Some(HOST));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_package_with_no_table_row_falls_back_to_the_name_of_the_download() {
    let dir = std::env::temp_dir().join(format!("faramir_cortex_online_norow_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let inner = zip_bytes(&[("manifest.json", &manifest(&[("/etc/crontab", "entry_1_0/crontab")])), ("entry_1_0/crontab", CRONTAB)]);
    let package = zip_bytes(&[
        ("uname/uname.csv", b"manufacturer,generated_time,host_name\n"),
        (&format!("cron_files/cron_files_{ID1}_{ID2}.zip"), &inner),
        (&format!("systemd_units/systemd_units_{ID1}_{ID2}.zip"), &inner),
    ]);
    let zip = dir.join("dbsrv07.zip");
    std::fs::write(&zip, package).unwrap();
    let info = inspect_triage_archive(&zip).expect("inspected");
    assert_eq!(info.kind, TriageType::CortexXdrOnline);
    assert_eq!(info.hostname.as_deref(), Some("dbsrv07"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_files_go_back_to_their_path_on_the_host() {
    let (dir, zip) = build_package("unpack", "websrv01.zip");
    let out = dir.join("staged");
    std::fs::create_dir_all(&out).unwrap();
    let (placed, loose) = unpack_cortex_online(&zip, &out, true).unwrap();
    let files = files_under(&out);
    assert_eq!(
        files,
        vec![
            "etc/cron.d/backup",
            "etc/crontab",
            "etc/systemd/system/updater.service",
            "lib/systemd/system/merged.service",
            // `..` in a manifest path never leaves the staging folder
            "outside/evil.service",
            // not in the manifest: kept, under its collector
            "systemd_units/entry_9_0/orphan.service",
        ]
    );
    // the files the listing gives no time for
    let mut undated: Vec<String> = std::fs::read_to_string(out.join(faramir::parsers::linux::UNDATED_MARKER)).unwrap().lines().map(str::to_string).collect();
    undated.sort();
    assert_eq!(undated, vec!["/etc/cron.d/backup", "/etc/systemd/system/updater.service", "/outside/evil.service", "/systemd_units/entry_9_0/orphan.service"]);
    assert_eq!((placed, loose), (5, 1));
    // nothing of the collector's own report, and nothing outside the folder
    assert!(!files.iter().any(|f| f.ends_with("manifest.json") || f.ends_with("stdout.txt") || f.ends_with("script_output.txt")));
    assert!(!dir.join("outside").exists() && !dir.parent().unwrap().join("outside").join("evil.service").exists());
    assert_eq!(std::fs::read(out.join("etc/crontab")).unwrap(), CRONTAB);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_file_takes_the_modification_time_the_triage_listed_for_it() {
    let (dir, zip) = build_package("mtime", "websrv01.zip");
    let out = dir.join("staged");
    std::fs::create_dir_all(&out).unwrap();
    unpack_cortex_online(&zip, &out, true).unwrap();
    let ms = |p: &str| std::fs::metadata(out.join(p)).unwrap().modified().unwrap().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64;
    assert_eq!(ms("etc/crontab"), MTIME_MS);
    // listed as /usr/lib/..., collected as /lib/...: the same file
    assert_eq!(ms("lib/systemd/system/merged.service"), MTIME_MS);
    // not in the listing: no time to give it, it keeps the moment it was unpacked
    assert!(ms("etc/cron.d/backup") > MTIME_MS + 1000);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_whole_package_is_one_evidence_root_and_one_host() {
    let (dir, zip) = build_package("root", "websrv01.zip");
    let staging = dir.join("staging");
    std::fs::create_dir_all(&staging).unwrap();
    let roots = unpack_archive_recursive(&zip, &staging, true).unwrap();
    // one root: the collectors' zips are not each a host of their own
    assert_eq!(roots, vec![staging.join("websrv01")]);
    assert!(faramir::parsers::linux::is_linux_target(&roots[0]));

    let events = faramir::parsers::linux::process_linux_target(&roots[0], HOST);
    assert!(events.iter().all(|e| e.computer == HOST));
    // the cron job is found because the file is back at /etc/crontab, and it is cited by that path
    let cron: Vec<_> = events.iter().filter(|e| e.artifact.starts_with("linux:cron")).collect();
    assert!(cron.iter().any(|e| e.source_file == "/etc/crontab" && e.commandline.as_deref().unwrap_or("").contains("beacon.sh")), "{:?}", cron.iter().map(|e| (&e.artifact, &e.source_file)).collect::<Vec<_>>());
    assert!(cron.iter().any(|e| e.source_file == "/etc/cron.d/backup"));
    assert!(events.iter().any(|e| e.artifact == "linux:systemd:service" && e.source_file == "/etc/systemd/system/updater.service"));
    // and it is dated by the host's file, not by the unpacking
    let job = cron.iter().find(|e| e.source_file == "/etc/crontab").unwrap();
    assert!(job.timestamp.starts_with("2024-03-01"), "{}", job.timestamp);
    // a file the listing does not name: its findings carry no time, not the moment of the unpacking
    let undated = cron.iter().find(|e| e.source_file == "/etc/cron.d/backup").unwrap();
    assert_eq!(undated.timestamp, "");
    let unit = events.iter().find(|e| e.source_file == "/etc/systemd/system/updater.service").unwrap();
    assert_eq!(unit.timestamp, "");
    assert!(events.iter().all(|e| !e.timestamp.starts_with(&chrono::Utc::now().format("%Y-%m-%d").to_string())), "no finding dated today");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_collector_zip_without_manifest_keeps_its_files_under_the_collector() {
    let dir = std::env::temp_dir().join(format!("faramir_cortex_online_noman_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let broken = zip_bytes(&[("manifest.json", b"{ not json"), ("entry_1_0/updater.service", SERVICE)]);
    let fine = zip_bytes(&[("manifest.json", &manifest(&[("/etc/crontab", "entry_1_0/crontab")])), ("entry_1_0/crontab", CRONTAB)]);
    let package = zip_bytes(&[
        (&format!("systemd_units/systemd_units_{ID1}_{ID2}.zip"), &broken),
        (&format!("cron_files/cron_files_{ID1}_{ID2}.zip"), &fine),
        // not a collector's zip: left alone
        ("notes/readme.zip", &fine),
    ]);
    let zip = dir.join("h.zip");
    std::fs::write(&zip, package).unwrap();
    let out = dir.join("staged");
    std::fs::create_dir_all(&out).unwrap();
    let (placed, loose) = unpack_cortex_online(&zip, &out, true).unwrap();
    assert_eq!((placed, loose), (1, 1));
    assert_eq!(files_under(&out), vec!["etc/crontab", "systemd_units/entry_1_0/updater.service"]);
    let _ = std::fs::remove_dir_all(&dir);
}
