//! XFS volumes inside disk images: a GPT partition and an LVM logical
//! volume, both v5 with checksums, built by `scripts/linux_disk_lab.sh`
//! with one canary per technique and a 300-entry directory.
mod common;

use common::*;
use faramir::errors::{FaramirError, Severity};
use faramir::ingest::image::unpack_disk_image;
use faramir::ingest::linux_image::{is_linux_volume_dir, sniff, SharedReader, VolumeKind};
use faramir::ingest::xfs_image::extract_from_xfs;
use faramir::parsers::linux::process_linux_target;
use faramir::windows::diag;
use std::io::{Cursor, Read};
use std::path::PathBuf;
use std::sync::Arc;

fn gunzip_fixture(d: &TempDir, name: &str) -> PathBuf {
    let gz = std::fs::File::open(fixture(&format!("linux_disk/{name}.gz"))).expect("fixture");
    let mut dec = flate2::read::GzDecoder::new(gz);
    let mut bytes = Vec::new();
    dec.read_to_end(&mut bytes).unwrap();
    d.write(name, &bytes)
}

fn truth(tag: &str) -> Vec<(String, String)> {
    std::fs::read_to_string(fixture("linux_disk/truth.txt"))
        .unwrap()
        .lines()
        .filter_map(|l| {
            let mut it = l.splitn(3, ' ');
            let t = it.next()?;
            let k = it.next()?;
            let v = it.next()?;
            (t == tag).then(|| (k.to_string(), v.to_string()))
        })
        .collect()
}

fn run_image(d: &TempDir, name: &str) -> (PathBuf, Vec<faramir::event::Event>, String) {
    let img = gunzip_fixture(d, name);
    diag::clear();
    let out = unpack_disk_image(&img, &d.mkdir(&format!("stg_{name}")), true).expect("unpack");
    let vols: Vec<PathBuf> = std::fs::read_dir(&out).unwrap().flatten().map(|e| e.path()).filter(|p| p.is_dir() && is_linux_volume_dir(&p.file_name().unwrap().to_string_lossy())).collect();
    assert_eq!(vols.len(), 1, "{vols:?}");
    let host = std::fs::read_to_string(vols[0].join("etc/hostname")).unwrap().trim().to_string();
    let events = process_linux_target(&vols[0], &host);
    (vols[0].clone(), events, host)
}

fn check_canaries(tag: &str, events: &[faramir::event::Event], host: &str) {
    assert_eq!(host, format!("lab-{tag}"));
    for (k, v) in truth(tag) {
        let hit = events.iter().any(|e| e.commandline.as_deref().unwrap_or("").contains(&v) || e.processname.contains(&v));
        if k.starts_with("deleted_") || k == "previous_crontab" || k == "inplace_sudo" {
            assert!(!hit, "{tag}: {k} is gone from the live tree and XFS has no journal recovery yet");
        } else if k == "hostname" {
            continue;
        } else {
            assert!(hit, "{tag}: canary {k} ({v}) missing from {} events", events.len());
        }
    }
    assert!(events.iter().all(|e| e.computer == host));
    assert!(events.iter().all(|e| !e.commandline.as_deref().unwrap_or("").contains("stg_")), "staging path leaked");
}

#[test]
fn gpt_xfs_partition_yields_every_live_canary() {
    let d = TempDir::new("xfs_gpt");
    let (vol, events, host) = run_image(&d, "gpt_xfs.img");
    assert_eq!(vol.file_name().unwrap().to_string_lossy(), "partition_0_linux");
    check_canaries("xfs", &events, &host);
    assert!(vol.join("etc/crontab").is_file());
    assert!(vol.join("usr/lib/systemd/system/lab.service").is_file());
    assert!(vol.join("etc/systemd/system/multi-user.target.wants/lab.service").is_file(), "symlinked unit resolved to its target");
    assert!(!vol.join("lib").exists(), "usr-merge link not copied twice");
    assert!(vol.join("var/spool/cron/crontabs/bob").is_file());
    assert!(vol.join("home/bob/.ssh/authorized_keys").is_file());
    assert!(!vol.join("etc/cron.d/gone").exists());
    assert!(diag::snapshot().iter().all(|e| e.severity() != Severity::Error), "{:?}", diag::snapshot());
}

#[test]
fn leaf_form_directory_with_300_entries_is_walked() {
    let d = TempDir::new("xfs_leaf");
    let (vol, _, _) = run_image(&d, "gpt_xfs.img");
    let noise = vol.join("usr/lib/systemd/system/noise.d");
    let n = std::fs::read_dir(&noise).unwrap().flatten().count();
    assert_eq!(n, 300, "{}", noise.display());
    assert_eq!(std::fs::read_to_string(noise.join("noise_300.txt")).unwrap().trim(), "noise 300");
}

#[test]
fn lvm_xfs_logical_volume_is_read_in_place() {
    let d = TempDir::new("xfs_lvm");
    let (vol, events, host) = run_image(&d, "mbr_lvm_xfs.img");
    assert_eq!(vol.file_name().unwrap().to_string_lossy(), "partition_0_lvm_vg_xfs_root_linux");
    check_canaries("lvmxfs", &events, &host);
    assert!(diag::snapshot().iter().all(|e| e.severity() != Severity::Error), "{:?}", diag::snapshot());
    assert!(diag::has("ERR_ING_LINUX_VOLUME_EXTRACTED"));
}

#[test]
fn file_mtimes_come_from_the_inode() {
    let d = TempDir::new("xfs_mtime");
    let (vol, events, _) = run_image(&d, "gpt_xfs.img");
    let m = std::fs::metadata(vol.join("etc/crontab")).unwrap().modified().unwrap();
    let secs = m.duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    assert!(secs > 1_700_000_000, "mtime set from the XFS inode, not the extraction time: {secs}");
    assert!(events.iter().all(|e| e.timestamp.starts_with("20")), "{events:?}");
}

#[test]
fn xfs_through_the_cli() {
    let d = TempDir::new("xfs_cli");
    let img = gunzip_fixture(&d, "mbr_lvm_xfs.img");
    let out = d.join("xfs.csv");
    let o = std::process::Command::new(env!("CARGO_BIN_EXE_faramir")).arg("-f").arg(&img).arg("-o").arg(&out).arg("--verbose").output().unwrap();
    let stdout = String::from_utf8_lossy(&o.stdout);
    let stderr = String::from_utf8_lossy(&o.stderr);
    assert!(o.status.success(), "{stderr}");
    assert!(stdout.contains("LV vg_xfs/root: XFS, host 'lab-lvmxfs'"), "{stdout}");
    assert!(!stderr.contains("[ERROR]") && !stderr.contains("[WARN]") && !stderr.contains("[PANIC]"), "{stderr}");
    assert!(!stderr.contains("ERR_ING_LINUX_FS_UNSUPPORTED"), "{stderr}");
    let csv = std::fs::read_to_string(&out).unwrap();
    assert!(csv.contains("linux:sudoers:nopasswd") && csv.contains("/opt/lab/lvmxfs/sudo_v2.sh"), "{csv}");
    assert!(csv.lines().skip(1).all(|r| r.contains("\"lab-lvmxfs\"")));
}

#[test]
fn extract_from_xfs_on_a_whole_volume_device() {
    // the GPT image's first partition starts at LBA 2048
    let d = TempDir::new("xfs_device");
    let img = gunzip_fixture(&d, "gpt_xfs.img");
    let reader = SharedReader::new(std::fs::File::open(&img).unwrap()).at(2048 * 512);
    let device: Arc<dyn fs_core::BlockRead> = Arc::new(reader);
    diag::clear();
    let x = extract_from_xfs(device, &d.mkdir("out"), "t").unwrap();
    assert_eq!(x.hostname.as_deref(), Some("lab-xfs"));
    assert!(x.files >= 320, "{x:?}");
    assert_eq!(x.errors, 0);
    assert_eq!(x.skipped_large, 0);
}

#[test]
fn not_xfs_is_a_parse_error_not_a_panic() {
    let device: Arc<dyn fs_core::BlockRead> = Arc::new(SharedReader::new(Cursor::new(vec![0u8; 1 << 20])));
    let d = TempDir::new("xfs_notxfs");
    let e = extract_from_xfs(device, &d.mkdir("out"), "blob").unwrap_err();
    assert_eq!(e.code(), "ERR_ING_XFS_PARSE");
    assert_eq!(e.error_number(), 2042);
    assert_eq!(e.severity(), Severity::Error);
    assert!(FaramirError::catalog().iter().any(|c| c.code() == "ERR_ING_XFS_PARSE"));
}

#[test]
fn xfs_is_a_readable_kind_now() {
    assert!(VolumeKind::Xfs.is_readable_linux());
    assert!(!VolumeKind::Xfs.is_unsupported_linux());
    assert!(VolumeKind::Btrfs.is_unsupported_linux());
    let mut v = vec![0u8; 8192];
    v[..4].copy_from_slice(b"XFSB");
    assert_eq!(sniff(&SharedReader::new(Cursor::new(v)), 0), VolumeKind::Xfs);
}
