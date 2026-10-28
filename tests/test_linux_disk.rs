//! Linux volumes inside disk images: ext4 behind GPT, ext4 inside LVM behind
//! MBR, the volume sniffer, the shared reader, and the real-host image.
//!
//! The two small images were built by `scripts/linux_disk_lab.sh` on an
//! Ubuntu 22.04 host; `truth.txt` lists the canary planted per technique.
mod common;

use common::*;
use faramir::errors::{FaramirError, Severity};
use faramir::ingest::image::unpack_disk_image;
use faramir::ingest::linux_image::{is_linux_volume_dir, linux_dir_name, list_volumes, sniff, LogicalVolume, SharedReader, VolumeKind};
use faramir::parsers::linux::process_linux_target;
use faramir::windows::diag;
use std::io::{Cursor, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

fn gunzip_fixture(d: &TempDir, name: &str) -> PathBuf {
    let gz = std::fs::File::open(fixture(&format!("linux_disk/{name}.gz"))).expect("fixture");
    let mut dec = flate2::read::GzDecoder::new(gz);
    let mut bytes = Vec::new();
    dec.read_to_end(&mut bytes).unwrap();
    d.write(name, &bytes)
}

/// `(tag, technique, value)` rows of truth.txt for one image.
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

/// Techniques the planted canary is expected to surface as a row.
fn expected_in_rows(k: &str) -> bool {
    // deleted_cron only exists in unallocated space: Linux carving is not there yet
    k != "deleted_cron" && k != "hostname" && k != "key"
}

fn run_image(d: &TempDir, name: &str) -> (PathBuf, Vec<faramir::event::Event>, String) {
    let img = gunzip_fixture(d, name);
    let staging = d.mkdir(&format!("staging_{name}"));
    diag::clear();
    let out = unpack_disk_image(&img, &staging, true).expect("unpack");
    let vols: Vec<PathBuf> = std::fs::read_dir(&out)
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_dir() && is_linux_volume_dir(&p.file_name().unwrap().to_string_lossy()))
        .collect();
    assert_eq!(vols.len(), 1, "one Linux volume staged: {vols:?}");
    let host = std::fs::read_to_string(vols[0].join("etc/hostname")).unwrap().trim().to_string();
    let events = process_linux_target(&vols[0], &host);
    (vols[0].clone(), events, host)
}

fn check_canaries(tag: &str, events: &[faramir::event::Event], host: &str) {
    assert_eq!(host, format!("lab-{tag}"));
    for (k, v) in truth(tag) {
        let v = if k == "preload" { v.replace(".sh", ".so") } else { v };
        let hit = events.iter().any(|e| e.commandline.as_deref().unwrap_or("").contains(&v) || e.processname.contains(&v));
        if expected_in_rows(&k) {
            assert!(hit, "{tag}: canary {k} ({v}) missing from {} events", events.len());
        } else if k == "deleted_cron" {
            assert!(!hit, "{tag}: a deleted cron entry can only come back through carving");
        } else if k == "key" {
            assert!(events.iter().any(|e| e.artifact == "linux:ssh:authorized_key" && e.commandline.as_deref().unwrap_or("").contains(&v)), "{tag}: key {v}");
        }
    }
    assert!(events.iter().all(|e| e.computer == host));
    assert!(events.iter().all(|e| !e.commandline.as_deref().unwrap_or("").contains("staging_")), "staging path leaked");
}

// ─── the two lab images ──────────────────────────────────────────────────────

#[test]
fn gpt_ext4_image_yields_every_canary() {
    let d = TempDir::new("lnxdisk_gpt");
    let (vol, events, host) = run_image(&d, "gpt_ext4.img");
    assert_eq!(vol.file_name().unwrap().to_string_lossy(), "partition_0_linux");
    assert!(vol.join("etc/crontab").is_file());
    assert!(vol.join("usr/lib/systemd/system/lab.service").is_file());
    assert!(vol.join("etc/systemd/system/multi-user.target.wants/lab.service").is_file(), "symlinked unit is copied as its target");
    assert!(!vol.join("lib").exists(), "usr-merged /lib is not copied twice");
    assert!(vol.join("home/bob/.ssh/authorized_keys").is_file());
    assert!(vol.join("root/.profile").is_file());
    assert!(vol.join("var/spool/cron/crontabs/bob").is_file());
    check_canaries("gpt", &events, &host);
    assert!(diag::has("ERR_ING_LINUX_VOLUME_EXTRACTED"));
    assert!(diag::snapshot().iter().all(|e| e.severity() != Severity::Error), "{:?}", diag::snapshot());
}

#[test]
fn mbr_lvm_ext4_image_yields_every_canary() {
    let d = TempDir::new("lnxdisk_lvm");
    let (vol, events, host) = run_image(&d, "mbr_lvm_ext4.img");
    assert_eq!(vol.file_name().unwrap().to_string_lossy(), "partition_0_lvm_vg_lab_root_linux");
    check_canaries("lvm", &events, &host);
    assert!(diag::snapshot().iter().all(|e| e.severity() != Severity::Error), "{:?}", diag::snapshot());
}

#[test]
fn reboot_cron_in_cron_d_is_a_row_with_its_user() {
    let d = TempDir::new("lnxdisk_reboot");
    let (_, events, _) = run_image(&d, "gpt_ext4.img");
    let r: Vec<_> = events.iter().filter(|e| e.commandline.as_deref().unwrap_or("").contains("cron_d.sh")).collect();
    assert_eq!(r.len(), 1, "{events:?}");
    assert_eq!(r[0].artifact, "linux:cron:system_job");
    assert_eq!(r[0].subject_username, "root");
    assert!(r[0].commandline.as_deref().unwrap().contains("@reboot /opt/lab/gpt/cron_d.sh"), "{:?}", r[0].commandline);
}

#[test]
fn profile_scripts_running_from_opt_are_rows() {
    let d = TempDir::new("lnxdisk_profiles");
    let (_, events, _) = run_image(&d, "gpt_ext4.img");
    let shell: Vec<_> = events.iter().filter(|e| e.artifact.starts_with("linux:shell:")).collect();
    let cmds: Vec<&str> = shell.iter().map(|e| e.commandline.as_deref().unwrap_or("")).collect();
    assert!(cmds.iter().any(|c| c.contains("bashrc.sh")), "{cmds:?}");
    assert!(cmds.iter().any(|c| c.contains("root_profile.sh")), "{cmds:?}");
    assert!(cmds.iter().any(|c| c.contains("profile_d.sh")), "{cmds:?}");
    assert!(shell.iter().any(|e| e.artifact == "linux:shell:unusual_location_execution"));
}

#[test]
fn image_through_the_cli() {
    let d = TempDir::new("lnxdisk_cli");
    let img = gunzip_fixture(&d, "mbr_lvm_ext4.img");
    let out = d.join("lvm.csv");
    let o = std::process::Command::new(env!("CARGO_BIN_EXE_faramir")).arg("-f").arg(&img).arg("-o").arg(&out).arg("--verbose").output().unwrap();
    let stdout = String::from_utf8_lossy(&o.stdout);
    let stderr = String::from_utf8_lossy(&o.stderr);
    assert!(o.status.success(), "{stderr}");
    assert!(stdout.contains("LVM, 1 logical volume(s)"), "{stdout}");
    assert!(stdout.contains("host 'lab-lvm'"), "{stdout}");
    assert!(stdout.contains("Detected Linux volume [lab-lvm]"), "{stdout}");
    assert!(!stdout.contains("No NTFS"), "{stdout}");
    assert!(!stderr.contains("[PANIC]") && !stderr.contains("[ERROR]"), "{stderr}");
    let rows: Vec<String> = std::fs::read_to_string(&out).unwrap().lines().skip(1).map(String::from).collect();
    assert!(rows.len() >= 12, "{rows:?}");
    assert!(rows.iter().all(|r| r.contains("\"lab-lvm\"")), "{rows:?}");
    assert!(rows.iter().any(|r| r.contains("linux:sudoers:nopasswd") && r.contains("/opt/lab/lvm/sudo.sh")), "{rows:?}");
}

#[test]
fn get_linux_persistence_action_also_reads_images() {
    let d = TempDir::new("lnxdisk_action");
    let img = gunzip_fixture(&d, "gpt_ext4.img");
    let out = d.join("gpt.csv");
    let o = std::process::Command::new(env!("CARGO_BIN_EXE_faramir")).arg("-f").arg(&img).arg("-o").arg(&out).arg("--silent").arg("get-linux-persistence").output().unwrap();
    assert!(o.status.success());
    let rows = std::fs::read_to_string(&out).unwrap().lines().count() - 1;
    assert!(rows >= 12, "{rows}");
    let o = std::process::Command::new(env!("CARGO_BIN_EXE_faramir")).arg("-f").arg(&img).arg("-o").arg(&d.join("none.csv")).arg("--silent").arg("get-run").output().unwrap();
    assert!(o.status.success());
    assert_eq!(std::fs::read_to_string(d.join("none.csv")).unwrap().lines().count(), 1, "a Windows-only action yields nothing from a Linux image");
}

// ─── volume sniffing on synthetic bytes ──────────────────────────────────────

fn mem(bytes: Vec<u8>) -> SharedReader<Cursor<Vec<u8>>> {
    SharedReader::new(Cursor::new(bytes))
}

fn with_magic(size: usize, at: usize, magic: &[u8]) -> Vec<u8> {
    let mut v = vec![0u8; size];
    v[at..at + magic.len()].copy_from_slice(magic);
    v
}

#[test]
fn sniff_recognises_every_kind() {
    assert_eq!(sniff(&mem(with_magic(8192, 3, b"NTFS    ")), 0), VolumeKind::Ntfs);
    assert_eq!(sniff(&mem(with_magic(8192, 3, b"-FVE-FS-")), 0), VolumeKind::BitLocker);
    assert_eq!(sniff(&mem(with_magic(8192, 0x438, &[0x53, 0xEF])), 0), VolumeKind::Ext);
    assert_eq!(sniff(&mem(with_magic(8192, 0, b"XFSB")), 0), VolumeKind::Xfs);
    assert_eq!(sniff(&mem(with_magic(8192, 0, b"LUKS\xba\xbe")), 0), VolumeKind::Luks);
    assert_eq!(sniff(&mem(with_magic(8192, 512, b"LABELONE")), 0), VolumeKind::Lvm);
    assert_eq!(sniff(&mem(with_magic(0x20000, 0x10040, b"_BHRfS_M")), 0), VolumeKind::Btrfs);
    assert_eq!(sniff(&mem(with_magic(8192, 0x400, &[0x10, 0x20, 0xF5, 0xF2])), 0), VolumeKind::F2fs);
    assert_eq!(sniff(&mem(with_magic(8192, 4086, b"SWAPSPACE2")), 0), VolumeKind::Swap);
    assert_eq!(sniff(&mem(with_magic(8192, 0x36, b"FAT16   ")), 0), VolumeKind::Fat);
    assert_eq!(sniff(&mem(with_magic(8192, 0x52, b"FAT32   ")), 0), VolumeKind::Fat);
    assert_eq!(sniff(&mem(vec![0u8; 8192]), 0), VolumeKind::Unknown);
    assert_eq!(sniff(&mem(vec![0u8; 100]), 0), VolumeKind::Unknown, "short volume");
    // offsets are honoured
    assert_eq!(sniff(&mem(with_magic(16384, 4096 + 0x438, &[0x53, 0xEF])), 4096), VolumeKind::Ext);
}

#[test]
fn volume_kind_labels_and_classes() {
    assert!(VolumeKind::Ext.is_readable_linux());
    assert!(!VolumeKind::Xfs.is_readable_linux());
    assert!(VolumeKind::Xfs.is_unsupported_linux() && VolumeKind::Btrfs.is_unsupported_linux() && VolumeKind::F2fs.is_unsupported_linux());
    assert!(!VolumeKind::Ntfs.is_unsupported_linux() && !VolumeKind::Lvm.is_unsupported_linux());
    for k in [VolumeKind::Ntfs, VolumeKind::Ext, VolumeKind::Lvm, VolumeKind::Luks, VolumeKind::Unknown] {
        assert!(!k.label().is_empty());
    }
}

fn mbr_image(entries: &[(u8, u32, u32)], size: usize) -> Vec<u8> {
    let mut v = vec![0u8; size];
    for (i, (ptype, lba, sectors)) in entries.iter().enumerate() {
        let e = 446 + i * 16;
        v[e + 4] = *ptype;
        v[e + 8..e + 12].copy_from_slice(&lba.to_le_bytes());
        v[e + 12..e + 16].copy_from_slice(&sectors.to_le_bytes());
    }
    v[510] = 0x55;
    v[511] = 0xAA;
    v
}

#[test]
fn list_volumes_walks_mbr_entries_and_sniffs_each() {
    let mut img = mbr_image(&[(0x83, 2048, 2048), (0x8e, 4096, 2048), (0x07, 6144, 2048)], 8192 * 512);
    let p1 = 2048 * 512;
    img[p1 + 0x438..p1 + 0x43a].copy_from_slice(&[0x53, 0xEF]);
    let p2 = 4096 * 512;
    img[p2 + 512..p2 + 520].copy_from_slice(b"LABELONE");
    let p3 = 6144 * 512;
    img[p3 + 3..p3 + 11].copy_from_slice(b"NTFS    ");
    let vols = list_volumes(&mem(img), 8192 * 512);
    let kinds: Vec<(u64, VolumeKind, &str)> = vols.iter().map(|v| (v.offset, v.kind, v.table)).collect();
    assert_eq!(kinds, vec![(p1 as u64, VolumeKind::Ext, "mbr"), (p2 as u64, VolumeKind::Lvm, "mbr"), (p3 as u64, VolumeKind::Ntfs, "mbr")]);
    assert_eq!(vols[0].size, 2048 * 512);
}

#[test]
fn list_volumes_walks_gpt_entries_of_any_type() {
    let size = 8192 * 512;
    let mut img = vec![0u8; size];
    img[446 + 4] = 0xEE;
    img[510] = 0x55;
    img[511] = 0xAA;
    img[512..520].copy_from_slice(b"EFI PART");
    img[512 + 72..512 + 80].copy_from_slice(&2u64.to_le_bytes()); // entries at LBA 2
    img[512 + 80..512 + 84].copy_from_slice(&2u32.to_le_bytes());
    img[512 + 84..512 + 88].copy_from_slice(&128u32.to_le_bytes());
    let e0 = 1024;
    img[e0..e0 + 16].copy_from_slice(&[1u8; 16]); // some random type GUID
    img[e0 + 32..e0 + 40].copy_from_slice(&2048u64.to_le_bytes());
    img[e0 + 40..e0 + 48].copy_from_slice(&4095u64.to_le_bytes());
    let e1 = 1024 + 128;
    img[e1..e1 + 16].copy_from_slice(&faramir::ingest::linux_image::GPT_LINUX_FS_GUID);
    img[e1 + 32..e1 + 40].copy_from_slice(&4096u64.to_le_bytes());
    img[e1 + 40..e1 + 48].copy_from_slice(&8191u64.to_le_bytes());
    let p0 = 2048 * 512;
    img[p0..p0 + 4].copy_from_slice(b"XFSB");
    let p1 = 4096 * 512;
    img[p1 + 0x438..p1 + 0x43a].copy_from_slice(&[0x53, 0xEF]);
    let vols = list_volumes(&mem(img), size as u64);
    assert_eq!(vols.len(), 2);
    assert_eq!((vols[0].offset, vols[0].kind, vols[0].table), (p0 as u64, VolumeKind::Xfs, "gpt"));
    assert_eq!((vols[1].offset, vols[1].kind, vols[1].size), (p1 as u64, VolumeKind::Ext, 4096 * 512));
}

#[test]
fn list_volumes_without_a_table_sniffs_offset_zero() {
    let vols = list_volumes(&mem(with_magic(8192, 0x438, &[0x53, 0xEF])), 8192);
    assert_eq!(vols.len(), 1);
    assert_eq!((vols[0].offset, vols[0].kind, vols[0].table, vols[0].size), (0, VolumeKind::Ext, "whole", 8192));
    assert!(list_volumes(&mem(vec![0u8; 8192]), 8192).is_empty());
    assert!(list_volumes(&mem(vec![0u8; 100]), 100).is_empty());
}

#[test]
fn unsupported_and_encrypted_volumes_are_reported_not_ignored() {
    let d = TempDir::new("lnxdisk_unsupported");
    let mut img = mbr_image(&[(0x83, 2048, 2048), (0x83, 4096, 2048)], 8192 * 512);
    let p1 = 2048 * 512;
    img[p1..p1 + 4].copy_from_slice(b"XFSB");
    let p2 = 4096 * 512;
    img[p2..p2 + 6].copy_from_slice(b"LUKS\xba\xbe");
    let path = d.write("mixed.raw", &img);
    diag::clear();
    let err = unpack_disk_image(&path, &d.mkdir("stg"), true).expect_err("nothing readable");
    let text = err.to_string();
    assert!(text.contains("found: XFS") && text.contains("LUKS"), "{text}");
    assert_eq!(diag::count("ERR_ING_LINUX_FS_UNSUPPORTED"), 1);
    assert_eq!(diag::count("ERR_ING_LUKS_ENCRYPTED"), 1);
}

// ─── the shared reader ───────────────────────────────────────────────────────

#[test]
fn shared_reader_views_do_not_disturb_each_other() {
    let data: Vec<u8> = (0..=255u8).cycle().take(4096).collect();
    let base = mem(data.clone());
    let mut a = base.clone();
    let mut b = base.at(1000);
    let mut buf = [0u8; 4];
    a.read_exact(&mut buf).unwrap();
    assert_eq!(buf, [0, 1, 2, 3]);
    b.read_exact(&mut buf).unwrap();
    assert_eq!(buf, [232, 233, 234, 235]);
    a.read_exact(&mut buf).unwrap();
    assert_eq!(buf, [4, 5, 6, 7], "a's cursor survived b's read");
    assert_eq!(b.seek(SeekFrom::Current(-2)).unwrap(), 2);
    assert_eq!(b.seek(SeekFrom::End(0)).unwrap(), 4096 - 1000);
    assert!(b.seek(SeekFrom::Current(-100000)).is_err());
    let mut c = [0u8; 2];
    base.read_at(4094, &mut c).unwrap();
    assert_eq!(c, [254, 255]);
    assert!(base.read_at(4095, &mut c).is_err(), "short read is an error");
    let nested = base.at(1000).at(24);
    nested.read_at(0, &mut c).unwrap();
    assert_eq!(c, [0, 1], "offsets compose");
}

// ─── names and codes ─────────────────────────────────────────────────────────

#[test]
fn linux_dir_names_are_recognisable_and_safe() {
    assert_eq!(linux_dir_name(2, None), "partition_2_linux");
    let lv = LogicalVolume { vg: "ubuntu-vg".into(), name: "ubuntu lv/root".into(), size: 1, kind: VolumeKind::Ext };
    assert_eq!(linux_dir_name(0, Some(&lv)), "partition_0_lvm_ubuntu-vg_ubuntu_lv_root_linux");
    assert!(is_linux_volume_dir("partition_0_linux"));
    assert!(is_linux_volume_dir("partition_3_lvm_vg_root_linux"));
    assert!(!is_linux_volume_dir("partition_0"));
    assert!(!is_linux_volume_dir("partition_0_vss_1"));
    assert!(!is_linux_volume_dir("uac-host-linux"));
}

#[test]
fn linux_image_error_codes() {
    let cases = [
        (FaramirError::ExtParseError("d".into()), "ERR_ING_EXT_PARSE", 2031, Severity::Error),
        (FaramirError::LvmParseError("d".into()), "ERR_ING_LVM_PARSE", 2032, Severity::Error),
        (FaramirError::LvmUnsupportedLayout("d".into()), "ERR_ING_LVM_UNSUPPORTED_LAYOUT", 2033, Severity::Warning),
        (FaramirError::LinuxFsUnsupported("d".into()), "ERR_ING_LINUX_FS_UNSUPPORTED", 2034, Severity::Warning),
        (FaramirError::LuksEncrypted("d".into()), "ERR_ING_LUKS_ENCRYPTED", 2035, Severity::Warning),
        (FaramirError::LinuxExtractError("d".into()), "ERR_ING_LINUX_EXTRACT", 2036, Severity::Warning),
        (FaramirError::LinuxVolumeExtracted("d".into()), "ERR_ING_LINUX_VOLUME_EXTRACTED", 2037, Severity::Info),
    ];
    for (e, code, n, sev) in cases {
        assert_eq!(e.code(), code);
        assert_eq!(e.error_number(), n);
        assert_eq!(e.severity(), sev, "{code}");
        assert_eq!(e.detail(), "d");
        assert!(e.to_string().starts_with(&format!("[{code} - {n}] ")));
        assert!(FaramirError::catalog().iter().any(|c| c.code() == code));
    }
}

// ─── the real host ───────────────────────────────────────────────────────────

/// `FARAMIR_LINUXDISK=<dir>` with `real_ext4.img` from `scripts/linux_disk_lab.sh`.
#[test]
#[ignore]
fn real_host_ext4_image_matches_the_uac_collection() {
    let Some(dir) = std::env::var_os("FARAMIR_LINUXDISK").map(PathBuf::from).filter(|p| p.join("real_ext4.img").is_file()) else {
        eprintln!("FARAMIR_LINUXDISK not set; skipping");
        return;
    };
    let d = TempDir::new("lnxdisk_real");
    diag::clear();
    let out = unpack_disk_image(&dir.join("real_ext4.img"), &d.mkdir("stg"), true).unwrap();
    let vol = out.join("partition_0_linux");
    assert!(vol.join("etc/sudoers").is_file());
    let host = std::fs::read_to_string(vol.join("etc/hostname")).unwrap().trim().to_lowercase();
    let events = process_linux_target(&vol, &host);
    assert!(events.len() > 500, "{}", events.len());
    assert!(events.iter().filter(|e| e.artifact == "linux:sudoers:nopasswd").count() >= 3);
    assert!(events.iter().any(|e| e.commandline.as_deref().unwrap_or("").contains("%Leadership")));
    assert!(events.iter().all(|e| !e.timestamp.contains('T')));
    assert!(diag::snapshot().iter().all(|e| e.severity() != Severity::Error), "{:?}", diag::snapshot());
    let _ = Path::new(&dir);
}
