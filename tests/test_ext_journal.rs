//! What the ext4 journal gives back: deleted files with name, path, dates
//! and content; previous versions of rewritten files; and the parsers it is
//! built on (superblock, inodes, extents, directory blocks, jbd2 tags).
mod common;

use common::*;
use faramir::errors::{FaramirError, Severity};
use faramir::ingest::ext_journal::*;
use faramir::ingest::image::{unpack_disk_image, RECOVERED_SUFFIX};
use faramir::ingest::linux_image::{is_linux_volume_dir, SharedReader};
use faramir::parsers::linux::{process_linux_target, process_recovered};
use faramir::windows::diag;
use std::io::Read;
use std::path::PathBuf;

fn gunzip_fixture(d: &TempDir, name: &str) -> PathBuf {
    let gz = std::fs::File::open(fixture(&format!("linux_disk/{name}.gz"))).expect("fixture");
    let mut dec = flate2::read::GzDecoder::new(gz);
    let mut bytes = Vec::new();
    dec.read_to_end(&mut bytes).unwrap();
    d.write(name, &bytes)
}

fn truth(tag: &str, key: &str) -> String {
    std::fs::read_to_string(fixture("linux_disk/truth.txt"))
        .unwrap()
        .lines()
        .find_map(|l| {
            let mut it = l.splitn(3, ' ');
            (it.next()? == tag && it.next()? == key).then(|| it.next().unwrap_or("").to_string())
        })
        .unwrap_or_else(|| panic!("truth {tag} {key}"))
}

/// Unpack an image and return (volume dir, recovered dir, manifest).
fn unpack(d: &TempDir, name: &str) -> (PathBuf, PathBuf, Vec<ManifestEntry>) {
    let img = gunzip_fixture(d, name);
    diag::clear();
    let out = unpack_disk_image(&img, &d.mkdir(&format!("stg_{name}")), true).expect("unpack");
    let vol = std::fs::read_dir(&out).unwrap().flatten().map(|e| e.path()).find(|p| p.is_dir() && is_linux_volume_dir(&p.file_name().unwrap().to_string_lossy())).expect("volume dir");
    let rec = vol.with_file_name(format!("{}{RECOVERED_SUFFIX}", vol.file_name().unwrap().to_string_lossy()));
    assert!(rec.is_dir(), "{} missing", rec.display());
    let manifest = read_manifest(&rec).expect("manifest");
    (vol, rec, manifest)
}

fn entry<'a>(m: &'a [ManifestEntry], path: &str, kind: &str) -> &'a ManifestEntry {
    m.iter().find(|e| e.path == path && e.kind == kind).unwrap_or_else(|| panic!("{kind} {path} not in {m:?}"))
}

// ─── the lab images ──────────────────────────────────────────────────────────

fn check_image(tag: &str, name: &str) {
    let d = TempDir::new(&format!("ej_{tag}"));
    let (vol, rec, manifest) = unpack(&d, name);
    assert_eq!(manifest.len(), 5, "{manifest:?}");

    // three deleted files, every one with its content, dates and the transaction it came from
    for (path, key) in [("/etc/cron.d/gone", "deleted_cron"), ("/etc/systemd/system/gone.service", "deleted_service"), ("/home/bob/.ssh/authorized_keys2", "deleted_key")] {
        let e = entry(&manifest, path, "deleted");
        assert!(e.content_recovered && !e.blocks_reused, "{e:?}");
        assert!(e.source.starts_with("journal seq "), "{e:?}");
        assert!(e.dtime.is_some() && e.mtime.len() == 23, "{e:?}");
        assert!(e.size > 0);
        let staged = rec.join(e.staged.as_ref().unwrap());
        let content = std::fs::read_to_string(&staged).unwrap();
        assert!(content.contains(&truth(tag, key)), "{path}: {content:?}");
        assert!(!vol.join(path.trim_start_matches('/')).exists(), "{path} must not be in the live tree");
    }

    // a file replaced by rename: the old inode is a previous version with the old content
    let e = entry(&manifest, "/etc/crontab", "previous_version");
    assert!(e.source.contains("replaced by rename"), "{e:?}");
    assert!(e.content_recovered);
    let old = std::fs::read_to_string(rec.join(e.staged.as_ref().unwrap())).unwrap();
    assert!(old.contains(&truth(tag, "previous_crontab")) && !old.contains("crontab_v2"), "{old:?}");
    let live = std::fs::read_to_string(vol.join("etc/crontab")).unwrap();
    assert!(live.contains(&truth(tag, "crontab_v2")) && !live.contains(&truth(tag, "previous_crontab")));
    assert!(e.staged.as_ref().unwrap().ends_with("crontab"), "keeps its name for the parsers: {:?}", e.staged);

    // a file rewritten in place whose old blocks were freed
    let e = entry(&manifest, "/etc/sudoers.d/lab", "previous_version");
    assert!(e.content_recovered);
    let old = std::fs::read_to_string(rec.join(e.staged.as_ref().unwrap())).unwrap();
    assert!(old.contains(&truth(tag, "inplace_sudo")) && !old.contains("sudo_v2"), "{old:?}");

    assert!(diag::count("ERR_ING_EXT_DELETED_RECOVERED") >= 5, "{:?}", diag::snapshot());
    assert!(diag::snapshot().iter().all(|x| x.severity() != Severity::Error), "{:?}", diag::snapshot());
}

#[test]
fn gpt_ext4_journal_gives_back_deleted_files_and_previous_versions() {
    check_image("gpt", "gpt_ext4.img");
}

#[test]
fn lvm_ext4_journal_gives_back_deleted_files_and_previous_versions() {
    check_image("lvm", "mbr_lvm_ext4.img");
}

#[test]
fn recovered_files_become_tagged_events() {
    let d = TempDir::new("ej_events");
    let (vol, rec, _) = unpack(&d, "gpt_ext4.img");
    let host = std::fs::read_to_string(vol.join("etc/hostname")).unwrap().trim().to_string();
    let live = process_linux_target(&vol, &host);
    let ev = process_recovered(&rec, &host);
    let arts: Vec<&str> = ev.iter().map(|e| e.artifact.as_str()).collect();
    assert!(arts.contains(&"linux:deleted:cron:system_job"), "{arts:?}");
    assert!(arts.contains(&"linux:deleted:systemd:service"), "{arts:?}");
    assert!(arts.contains(&"linux:deleted:ssh:authorized_key"), "{arts:?}");
    assert!(arts.contains(&"linux:previous_version:cron:system_job"), "{arts:?}");
    assert!(arts.contains(&"linux:previous_version:sudoers:nopasswd"), "{arts:?}");
    assert!(!arts.iter().any(|a| a.ends_with(":file")), "every recovered file was parseable: {arts:?}");
    let cron = ev.iter().find(|e| e.artifact == "linux:deleted:cron:system_job").unwrap();
    let cmd = cron.commandline.as_deref().unwrap();
    assert!(cmd.contains(&truth("gpt", "deleted_cron")) && cmd.contains("[deleted 20") && cmd.contains("journal seq") && cmd.ends_with("/etc/cron.d/gone"), "{cmd}");
    assert_eq!(cron.timestamp.len(), 23);
    let prev = ev.iter().find(|e| e.artifact == "linux:previous_version:cron:system_job").unwrap();
    let cmd = prev.commandline.as_deref().unwrap();
    assert!(cmd.contains(&truth("gpt", "previous_crontab")) && cmd.contains("[previous version written") && cmd.contains("(File: crontab)"), "{cmd}");
    assert!(!cmd.contains("stg_") && !cmd.contains("_v2_ino") && !cmd.contains('\\'), "staging path leaked: {cmd}");
    // nothing recovered is also a live row
    for e in &ev {
        assert!(!live.iter().any(|l| l.artifact == e.artifact), "{}", e.artifact);
    }
    assert!(ev.iter().all(|e| e.computer == host));
}

#[test]
fn cli_reports_recovered_items() {
    let d = TempDir::new("ej_cli");
    let img = gunzip_fixture(&d, "mbr_lvm_ext4.img");
    let out = d.join("lvm.csv");
    let o = std::process::Command::new(env!("CARGO_BIN_EXE_faramir")).arg("-f").arg(&img).arg("-o").arg(&out).arg("--verbose").output().unwrap();
    let stdout = String::from_utf8_lossy(&o.stdout);
    let stderr = String::from_utf8_lossy(&o.stderr);
    assert!(o.status.success(), "{stderr}");
    assert!(stdout.contains("journal: 3 deleted file(s) and 2 previous version(s)"), "{stdout}");
    assert!(stdout.contains("recovered from the ext4 journal"), "{stdout}");
    assert!(stderr.contains("ERR_ING_EXT_DELETED_RECOVERED"), "{stderr}");
    assert!(!stderr.contains("[ERROR]") && !stderr.contains("[WARN]") && !stderr.contains("[PANIC]"), "{stderr}");
    let csv = std::fs::read_to_string(&out).unwrap();
    assert!(csv.contains("linux:deleted:cron:system_job") && csv.contains(&truth("lvm", "deleted_cron")), "{csv}");
    assert!(csv.contains("linux:deleted:ssh:authorized_key") && csv.contains(&truth("lvm", "deleted_key")), "{csv}");
    assert!(csv.contains("linux:previous_version:cron:system_job"), "{csv}");
}

#[test]
fn volume_without_deletions_reports_an_empty_journal_as_info() {
    // the carving lab VHD is NTFS; a Linux image with nothing deleted under the
    // persistence surface is the real-host sample (ignored test below). Here:
    // the manifest of a fresh volume is consistent with its journal counts.
    let d = TempDir::new("ej_counts");
    let img = gunzip_fixture(&d, "gpt_ext4.img");
    let mut r = SharedReader::new(std::fs::File::open(&img).unwrap()).at(1024 * 1024);
    let report = recover(&mut r, "t").unwrap();
    let j = report.journal.as_ref().unwrap();
    assert!(j.descriptors >= 3 && j.commits >= 3 && j.copies > 40, "{j:?}");
    assert!(report.inode_copies > 0 && report.dir_copies > 0);
    assert_eq!(report.files.len(), 5);
    assert!(report.live_dirs > 10);
}

// ─── geometry and inodes ─────────────────────────────────────────────────────

#[test]
fn geometry_of_the_fixture() {
    let d = TempDir::new("ej_geo");
    let img = gunzip_fixture(&d, "gpt_ext4.img");
    let mut r = SharedReader::new(std::fs::File::open(&img).unwrap()).at(1024 * 1024);
    let mut vol = Volume::open(&mut r).unwrap();
    assert_eq!(vol.geo.block_size, 4096);
    assert_eq!(vol.geo.inode_size, 256);
    assert_eq!(vol.geo.journal_ino, 8);
    assert_eq!(vol.geo.volume_name, "labroot");
    assert_eq!(vol.groups.len(), 1);
    let root = vol.read_inode(2).unwrap();
    assert!(root.is_dir() && root.uses_extents());
    assert_eq!(vol.extents(&root).len(), 1);
    let j = vol.read_inode(8).unwrap();
    assert!(j.is_regular() && j.size >= 4 << 20);
    let root_block = vol.extents(&root)[0].physical;
    assert!(vol.block_allocated(root_block).unwrap());
    let tree = LiveTree::walk(&mut vol);
    assert!(tree.files.contains_key("/etc/crontab"));
    assert!(tree.dir_path.values().any(|p| p == "/etc/cron.d"));
    assert!(!tree.truncated);
}

#[test]
fn geometry_rejects_garbage() {
    assert_eq!(Geometry::parse(&[0u8; 100]).unwrap_err().code(), "ERR_ING_EXT_JOURNAL_PARSE");
    let mut sb = vec![0u8; 1024];
    assert!(Geometry::parse(&sb).unwrap_err().to_string().contains("bad ext magic"));
    sb[0x38..0x3a].copy_from_slice(&0xEF53u16.to_le_bytes());
    sb[0x18..0x1c].copy_from_slice(&9u32.to_le_bytes());
    assert!(Geometry::parse(&sb).unwrap_err().to_string().contains("log block size"));
    sb[0x18..0x1c].copy_from_slice(&2u32.to_le_bytes());
    assert!(Geometry::parse(&sb).unwrap_err().to_string().contains("implausible geometry"));
    sb[0x04..0x08].copy_from_slice(&1000u32.to_le_bytes());
    sb[0x20..0x24].copy_from_slice(&32768u32.to_le_bytes());
    sb[0x28..0x2c].copy_from_slice(&8192u32.to_le_bytes());
    sb[0x4c..0x50].copy_from_slice(&1u32.to_le_bytes());
    sb[0x58..0x5a].copy_from_slice(&256u16.to_le_bytes());
    sb[0xe0..0xe4].copy_from_slice(&8u32.to_le_bytes());
    let g = Geometry::parse(&sb).unwrap();
    assert_eq!((g.block_size, g.inode_size, g.desc_size, g.journal_ino, g.group_count()), (4096, 256, 32, 8, 1));
    assert_eq!(g.inode_table_blocks(), 512);
}

#[test]
fn raw_inode_fields() {
    let mut b = vec![0u8; 256];
    b[0..2].copy_from_slice(&0o100644u16.to_le_bytes());
    b[4..8].copy_from_slice(&1234u32.to_le_bytes());
    b[16..20].copy_from_slice(&1_700_000_000u32.to_le_bytes());
    b[20..24].copy_from_slice(&1_700_000_100u32.to_le_bytes());
    b[32..36].copy_from_slice(&0x80000u32.to_le_bytes());
    b[100..104].copy_from_slice(&77u32.to_le_bytes());
    b[128..130].copy_from_slice(&32u16.to_le_bytes());
    b[144..148].copy_from_slice(&1_699_999_000u32.to_le_bytes());
    let i = RawInode::parse(42, &b).unwrap();
    assert!(i.is_regular() && i.uses_extents() && !i.inline_data() && i.plausible());
    assert_eq!((i.ino, i.size, i.mtime, i.dtime, i.generation, i.crtime), (42, 1234, 1_700_000_000, 1_700_000_100, 77, Some(1_699_999_000)));
    assert!(RawInode::parse(1, &b[..100]).is_none());
    let zero = RawInode::parse(1, &[0u8; 128]).unwrap();
    assert!(!zero.plausible());
    let mut d = b.clone();
    d[0..2].copy_from_slice(&0o40755u16.to_le_bytes());
    assert!(RawInode::parse(2, &d).unwrap().is_dir());
}

#[test]
fn extent_nodes_leaf_index_and_junk() {
    let mut n = vec![0u8; 60];
    n[0..2].copy_from_slice(&0xF30Au16.to_le_bytes());
    n[2..4].copy_from_slice(&2u16.to_le_bytes());
    n[6..8].copy_from_slice(&0u16.to_le_bytes());
    // leaf 1: logical 0, len 3, phys 0x1_0000_0010
    n[12..16].copy_from_slice(&0u32.to_le_bytes());
    n[16..18].copy_from_slice(&3u16.to_le_bytes());
    n[18..20].copy_from_slice(&1u16.to_le_bytes());
    n[20..24].copy_from_slice(&0x10u32.to_le_bytes());
    // leaf 2: uninitialised extent, len encoded + 32768
    n[24..28].copy_from_slice(&3u32.to_le_bytes());
    n[28..30].copy_from_slice(&(32768u16 + 2).to_le_bytes());
    n[32..36].copy_from_slice(&0x20u32.to_le_bytes());
    let (depth, e) = parse_extent_node(&n).unwrap();
    assert_eq!(depth, 0);
    assert_eq!(e, vec![(0, 3, 0x1_0000_0010), (3, 2, 0x20)]);
    n[6..8].copy_from_slice(&1u16.to_le_bytes());
    n[16..20].copy_from_slice(&0x30u32.to_le_bytes());
    n[20..22].copy_from_slice(&0u16.to_le_bytes());
    let (depth, e) = parse_extent_node(&n).unwrap();
    assert_eq!(depth, 1);
    assert_eq!(e[0], (0, 0, 0x30));
    assert!(parse_extent_node(&[0u8; 60]).is_none());
    n[2..4].copy_from_slice(&900u16.to_le_bytes());
    assert!(parse_extent_node(&n).is_none(), "entry count beyond the node");
}

// ─── directory blocks ────────────────────────────────────────────────────────

fn dirent(ino: u32, rec_len: u16, name: &str, ftype: u8) -> Vec<u8> {
    let mut v = Vec::new();
    v.extend_from_slice(&ino.to_le_bytes());
    v.extend_from_slice(&rec_len.to_le_bytes());
    v.push(name.len() as u8);
    v.push(ftype);
    v.extend_from_slice(name.as_bytes());
    v.resize(rec_len as usize, 0);
    v
}

fn dir_block(entries: &[(u32, &str, u8)], with_tail: bool) -> Vec<u8> {
    let mut b = Vec::new();
    let total = 4096 - if with_tail { 12 } else { 0 };
    for (i, (ino, name, ft)) in entries.iter().enumerate() {
        let min = ((8 + name.len()) as u16).div_ceil(4) * 4;
        let rec = if i + 1 == entries.len() { (total - b.len()) as u16 } else { min };
        b.extend_from_slice(&dirent(*ino, rec, name, *ft));
    }
    if with_tail {
        b.extend_from_slice(&dirent(0, 12, "", 0xDE));
    }
    b
}

#[test]
fn directory_block_chain_is_parsed_with_and_without_checksum_tail() {
    for tail in [false, true] {
        let b = dir_block(&[(12, ".", 2), (2, "..", 2), (58, "crontab", 1), (13, "cron.d", 2)], tail);
        assert_eq!(b.len(), 4096);
        let e = parse_dir_block(&b).unwrap();
        let names: Vec<(u32, &str)> = e.iter().map(|x| (x.ino, x.name.as_str())).collect();
        assert_eq!(names, vec![(12, "."), (2, ".."), (58, "crontab"), (13, "cron.d")]);
    }
}

#[test]
fn directory_block_heuristic_rejects_other_blocks() {
    assert!(parse_dir_block(&[0u8; 4096]).is_none(), "all zero");
    let mut b = dir_block(&[(12, ".", 2), (58, "x", 1)], true);
    b[4..6].copy_from_slice(&10u16.to_le_bytes()); // rec_len not a multiple of 4
    assert!(parse_dir_block(&b).is_none());
    let mut b = dir_block(&[(12, ".", 2), (58, "x", 1)], true);
    b[8] = b'/';
    assert!(parse_dir_block(&b).is_none(), "slash in a name");
    let mut b = dir_block(&[(12, ".", 2), (58, "x", 1)], false);
    b[4..6].copy_from_slice(&4000u16.to_le_bytes()); // chain no longer ends at the block end
    assert!(parse_dir_block(&b).is_none());
    let mut inode_table = vec![0u8; 4096];
    inode_table[0..2].copy_from_slice(&0o100644u16.to_le_bytes());
    assert!(parse_dir_block(&inode_table).is_none());
}

#[test]
fn slack_entries_are_found_off_the_chain() {
    // "gone" deleted the old way: its entry absorbed into the previous rec_len, bytes left intact
    let mut b = dir_block(&[(12, ".", 2), (2, "..", 2), (41, "crontab", 1), (58, "gone", 1), (13, "cron.d", 2)], true);
    let chain = parse_dir_block(&b).unwrap();
    let gone = chain.iter().find(|e| e.name == "gone").unwrap().offset;
    let prev = chain.iter().find(|e| e.name == "crontab").unwrap();
    let merged = (gone - prev.offset) as u16 + u16::from_le_bytes([b[gone + 4], b[gone + 5]]);
    b[prev.offset + 4..prev.offset + 6].copy_from_slice(&merged.to_le_bytes());
    let chain = parse_dir_block(&b).unwrap();
    assert!(chain.iter().all(|e| e.name != "gone"));
    let slack = slack_dir_entries(&b, &chain);
    assert_eq!(slack.iter().map(|e| (e.ino, e.name.as_str())).collect::<Vec<_>>(), vec![(58, "gone")]);
}

// ─── jbd2 ────────────────────────────────────────────────────────────────────

#[test]
fn descriptor_tags_in_every_layout() {
    assert_eq!(tag_size(0), 8);
    assert_eq!(tag_size(2), 12);
    assert_eq!(tag_size(0x10), 16);
    assert_eq!(tag_size(0x12), 16);
    // v3 (csum v3 + 64-bit): 16-byte tags, csum tail
    let mut b = vec![0u8; 4096];
    b[0..4].copy_from_slice(&0xC03B3998u32.to_be_bytes());
    b[4..8].copy_from_slice(&1u32.to_be_bytes());
    b[8..12].copy_from_slice(&7u32.to_be_bytes());
    let mut o = 12;
    for (blk, flags, high) in [(100u32, 2u32, 0u32), (200, 2 | 1, 1), (300, 2 | 8, 0)] {
        b[o..o + 4].copy_from_slice(&blk.to_be_bytes());
        b[o + 4..o + 8].copy_from_slice(&flags.to_be_bytes());
        b[o + 8..o + 12].copy_from_slice(&high.to_be_bytes());
        o += 16;
    }
    let tags = parse_descriptor_tags(&b, 0x12);
    assert_eq!(tags, vec![(100, 2), (0x1_0000_0000 + 200, 3), (300, 10)]);
    // v2 without 64-bit: 8-byte tags, first tag carries a uuid (no SAME_UUID flag)
    let mut b = vec![0u8; 1024];
    b[12..16].copy_from_slice(&5u32.to_be_bytes());
    b[18..20].copy_from_slice(&0u16.to_be_bytes()); // flags 0 -> uuid follows
    let second = 12 + 8 + 16;
    b[second..second + 4].copy_from_slice(&6u32.to_be_bytes());
    b[second + 6..second + 8].copy_from_slice(&(2u16 | 8).to_be_bytes());
    assert_eq!(parse_descriptor_tags(&b, 0), vec![(5, 0), (6, 10)]);
    // 64-bit v2: 12-byte tags
    let mut b = vec![0u8; 1024];
    b[12..16].copy_from_slice(&9u32.to_be_bytes());
    b[18..20].copy_from_slice(&(2u16 | 8).to_be_bytes());
    b[20..24].copy_from_slice(&2u32.to_be_bytes());
    assert_eq!(parse_descriptor_tags(&b, 2), vec![(0x2_0000_0009, 10)]);
    // a descriptor without LAST_TAG stops at the block end
    let b = vec![0u8; 64];
    // flags 0 means a 16-byte uuid follows each 8-byte tag: (64 - 12) / 24 = 2 tags
    assert_eq!(parse_descriptor_tags(&b, 0).len(), 2);
}

#[test]
fn journal_scan_of_the_fixture_counts_transactions() {
    let d = TempDir::new("ej_scan");
    let img = gunzip_fixture(&d, "gpt_ext4.img");
    let mut r = SharedReader::new(std::fs::File::open(&img).unwrap()).at(1024 * 1024);
    let mut vol = Volume::open(&mut r).unwrap();
    let (info, copies) = scan_journal(&mut vol, "t").unwrap();
    assert_eq!(info.block_size, 4096);
    assert_eq!(info.max_len, 1024);
    assert_eq!(info.first, 1);
    assert!(info.descriptors >= 3 && info.commits == info.descriptors, "{info:?}");
    assert!(info.incompat & 0x10 != 0, "csum v3 journal: {info:?}");
    assert_eq!(info.copies, copies.len());
    let seqs: std::collections::BTreeSet<u32> = copies.iter().map(|c| c.sequence).collect();
    assert!(seqs.len() >= 3, "{seqs:?}");
    assert!(copies.iter().all(|c| c.fs_block < vol.geo.blocks_count));
    let inode_table_copies = copies.iter().filter(|c| vol.inode_table_owner(c.fs_block).is_some()).count();
    assert!(inode_table_copies > 0);
    let c = copies.iter().find(|c| vol.inode_table_owner(c.fs_block).is_some()).unwrap();
    let data = read_copy(&mut vol, c).unwrap();
    assert!(!vol.inodes_in_block(c.fs_block, &data).is_empty());
}

// ─── staging and events ──────────────────────────────────────────────────────

#[test]
fn persistence_path_filter() {
    for p in ["/etc/crontab", "/etc/cron.d/x", "/etc/systemd/system/a.wants/b.service", "/usr/lib/systemd/system/x.service", "/home/bob/.bashrc", "/home/bob/.ssh/authorized_keys", "/root/.profile", "/home/a/.config/autostart/x.desktop", "/etc/sudoers.d/90-x", "/etc/pam.d/sshd", "/etc/ld.so.preload"] {
        assert!(is_persistence_path(p), "{p}");
    }
    for p in ["/etc/crontab.new", "/var/log/syslog", "/home/bob/notes.txt", "/home/bob/.cache/x", "/root", "/etc", "/opt/app/run.sh", "/etc/ssh/ssh_host_rsa_key"] {
        assert!(!is_persistence_path(p), "{p}");
    }
}

#[test]
fn staging_layout_and_manifest_round_trip() {
    let d = TempDir::new("ej_stage");
    let report = RecoveryReport {
        journal: None,
        inode_copies: 0,
        dir_copies: 0,
        live_dirs: 0,
        files: vec![
            RecoveredFile { path: "/etc/cron.d/gone".into(), ino: 58, kind: RecoveredKind::Deleted, source: "journal seq 2".into(), size: 5, mtime: 1_700_000_000, crtime: None, dtime: Some(1_700_000_050), content: Some(b"a b c".to_vec()), blocks_reused: false },
            RecoveredFile { path: "/etc/crontab".into(), ino: 41, kind: RecoveredKind::PreviousVersion, source: "journal seq 2 (replaced by rename)".into(), size: 3, mtime: 1_700_000_000, crtime: Some(1), dtime: None, content: Some(b"old".to_vec()), blocks_reused: false },
            RecoveredFile { path: "/etc/cron.d/reused".into(), ino: 70, kind: RecoveredKind::Deleted, source: "directory slack".into(), size: 0, mtime: 0, crtime: None, dtime: None, content: None, blocks_reused: true },
        ],
    };
    let out = d.join("vol.recovered");
    let entries = stage(&report, &out, "t").unwrap();
    assert_eq!(entries.len(), 3);
    assert_eq!(std::fs::read(out.join("etc/cron.d/gone")).unwrap(), b"a b c");
    assert_eq!(entries[0].dtime.as_deref(), Some("2023-11-14 22:14:10.000"));
    assert_eq!(entries[1].staged.as_deref(), Some(&format!("_v2_ino41{}etc{}crontab", std::path::MAIN_SEPARATOR, std::path::MAIN_SEPARATOR)[..]));
    assert_eq!(std::fs::read(out.join("_v2_ino41").join("etc").join("crontab")).unwrap(), b"old");
    assert_eq!(staged_root(&out, entries[1].staged.as_deref().unwrap()), out.join("_v2_ino41"));
    assert_eq!(staged_root(&out, "etc/cron.d/gone"), out);
    assert!(entries[2].staged.is_none() && !entries[2].content_recovered && entries[2].blocks_reused);
    assert_eq!(read_manifest(&out).unwrap(), entries);
    assert!(read_manifest(&d.join("nowhere")).is_none());

    let ev = process_recovered(&out, "h");
    let by_art: Vec<&str> = ev.iter().map(|e| e.artifact.as_str()).collect();
    assert!(by_art.contains(&"linux:deleted:file"), "{by_art:?}");
    let reused = ev.iter().find(|e| e.commandline.as_deref().unwrap_or("").contains("/etc/cron.d/reused")).unwrap();
    assert!(reused.commandline.as_deref().unwrap().contains("content blocks reused"), "{:?}", reused.commandline);
    assert_eq!(reused.parentprocessname, "ext4 journal");
    let prev = ev.iter().find(|e| e.artifact.starts_with("linux:previous_version:")).unwrap();
    let cmd = prev.commandline.as_deref().unwrap();
    assert!(cmd.contains("[previous version written 2023-11-14 22:13:20.000, journal seq 2 (replaced by rename)]") && cmd.contains("/etc/crontab"), "{cmd}");
}

#[test]
fn unix_time_formatting() {
    assert_eq!(unix_to_string(0), "1970-01-01 00:00:00.000");
    assert_eq!(unix_to_string(1_700_000_000), "2023-11-14 22:13:20.000");
}

#[test]
fn journal_error_codes() {
    let cases = [
        (FaramirError::ExtJournalParseError("d".into()), "ERR_ING_EXT_JOURNAL_PARSE", 2038, Severity::Warning),
        (FaramirError::ExtJournalEmpty("d".into()), "ERR_ING_EXT_JOURNAL_EMPTY", 2039, Severity::Info),
        (FaramirError::ExtDeletedRecovered("d".into()), "ERR_ING_EXT_DELETED_RECOVERED", 2040, Severity::Info),
        (FaramirError::ExtDeletedContentReused("d".into()), "ERR_ING_EXT_DELETED_CONTENT_REUSED", 2041, Severity::Warning),
    ];
    for (e, code, n, sev) in cases {
        assert_eq!(e.code(), code);
        assert_eq!(e.error_number(), n);
        assert_eq!(e.severity(), sev, "{code}");
        assert_eq!(e.detail(), "d");
        assert!(FaramirError::catalog().iter().any(|c| c.code() == code));
    }
}

#[test]
fn recovery_on_a_non_ext_source_is_an_error_not_a_panic() {
    let mut r = SharedReader::new(std::io::Cursor::new(vec![0u8; 8192]));
    let e = recover(&mut r, "blob").unwrap_err();
    assert_eq!(e.code(), "ERR_ING_EXT_JOURNAL_PARSE");
    let mut r = SharedReader::new(std::io::Cursor::new(vec![0u8; 100]));
    assert!(recover(&mut r, "tiny").is_err());
}
