//! Disk images recognised by their content: a cloud snapshot with no
//! extension (an Azure OS disk export starts with GRUB's boot code, `EB 63 90`),
//! a fixed VHD with no extension, a raw disk named `.vhd`, and the files that
//! must not be taken for an image (hives, later EWF segments, small files).
mod common;

use common::*;
use faramir::ingest::image::{image_kind, image_kind_from_bytes, is_supported_image, unpack_disk_image, ImageKind, SNIFF_MIN_SIZE};
use faramir::ingest::linux_image::is_linux_volume_dir;
use std::io::Read;
use std::path::{Path, PathBuf};

fn fixture_bytes(name: &str) -> Vec<u8> {
    let gz = std::fs::File::open(fixture(&format!("linux_disk/{name}.gz"))).expect("fixture");
    let mut dec = flate2::read::GzDecoder::new(gz);
    let mut bytes = Vec::new();
    dec.read_to_end(&mut bytes).unwrap();
    bytes
}

/// A fixed VHD footer, as Azure and Hyper-V write it after the disk's bytes.
fn fixed_vhd_footer(size: u64) -> [u8; 512] {
    let mut f = [0u8; 512];
    f[..8].copy_from_slice(b"conectix");
    f[16..24].copy_from_slice(&u64::MAX.to_be_bytes());
    f[40..48].copy_from_slice(&size.to_be_bytes());
    f[48..56].copy_from_slice(&size.to_be_bytes());
    f[60..64].copy_from_slice(&2u32.to_be_bytes());
    f
}

/// The hostname of the one Linux volume an image stages.
fn staged_host(d: &TempDir, img: &Path) -> String {
    let staging = d.mkdir(&format!("staging_{}", img.file_name().unwrap().to_string_lossy()));
    let out = unpack_disk_image(img, &staging, true).expect("unpack");
    let vols: Vec<PathBuf> = std::fs::read_dir(&out)
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.is_dir() && is_linux_volume_dir(&p.file_name().unwrap().to_string_lossy()))
        .collect();
    assert_eq!(vols.len(), 1, "one Linux volume staged: {vols:?}");
    std::fs::read_to_string(vols[0].join("etc/hostname")).unwrap().trim().to_string()
}

fn head_with(at: usize, bytes: &[u8]) -> Vec<u8> {
    let mut h = vec![0u8; 4096];
    h[at..at + bytes.len()].copy_from_slice(bytes);
    h
}

// ─── the signatures ─────────────────────────────────────────────────────────

#[test]
fn container_formats_by_their_magic() {
    let tail = [0u8; 512];
    assert_eq!(image_kind_from_bytes(&head_with(0, b"EVF\x09\x0d\x0a\xff\x00"), &tail), Some(ImageKind::Ewf));
    assert_eq!(image_kind_from_bytes(&head_with(0, b"EVF2\x0d\x0a\x81\x00"), &tail), Some(ImageKind::Ewf));
    assert_eq!(image_kind_from_bytes(&head_with(0, b"vhdxfile"), &tail), Some(ImageKind::Vhd));
    assert_eq!(image_kind_from_bytes(&head_with(0, b"QFI\xfb"), &tail), Some(ImageKind::Vhd));
    assert_eq!(image_kind_from_bytes(&head_with(0, b"conectix"), &tail), Some(ImageKind::Vhd), "dynamic VHD: footer copy at the start");
    assert_eq!(image_kind_from_bytes(&head_with(0, b"KDMV"), &tail), Some(ImageKind::Vmdk));
    let mut fixed_tail = [0u8; 512];
    fixed_tail[..8].copy_from_slice(b"conectix");
    assert_eq!(image_kind_from_bytes(&vec![0u8; 4096], &fixed_tail), Some(ImageKind::Vhd), "fixed VHD: footer at the end");
}

#[test]
fn raw_disks_and_volumes_by_what_they_start_with() {
    let tail = [0u8; 512];
    // GRUB's MBR, as on an Azure Linux OS disk, with one partition at sector 2048
    let mut grub = head_with(0, &[0xEB, 0x63, 0x90, 0x00]);
    grub[446] = 0x80;
    grub[450] = 0x83;
    grub[454..458].copy_from_slice(&2048u32.to_le_bytes());
    grub[458..462].copy_from_slice(&1_000_000u32.to_le_bytes());
    grub[510] = 0x55;
    grub[511] = 0xAA;
    assert_eq!(image_kind_from_bytes(&grub, &tail), Some(ImageKind::Raw));
    let mut gpt = head_with(512, b"EFI PART");
    gpt[510] = 0x55;
    gpt[511] = 0xAA;
    assert_eq!(image_kind_from_bytes(&gpt, &tail), Some(ImageKind::Raw));
    assert_eq!(image_kind_from_bytes(&head_with(3, b"NTFS    "), &tail), Some(ImageKind::Raw), "a volume image");
    assert_eq!(image_kind_from_bytes(&head_with(1080, &[0x53, 0xEF]), &tail), Some(ImageKind::Raw), "an ext volume image");
    assert_eq!(image_kind_from_bytes(&head_with(0, b"XFSB"), &tail), Some(ImageKind::Raw));
    assert_eq!(image_kind_from_bytes(&head_with(512, b"LABELONE"), &tail), Some(ImageKind::Raw), "an LVM physical volume");
}

#[test]
fn other_content_is_not_an_image() {
    let tail = [0u8; 512];
    assert_eq!(image_kind_from_bytes(&head_with(0, b"regf"), &tail), None, "a hive");
    assert_eq!(image_kind_from_bytes(&head_with(0, b"ElfFile\0"), &tail), None, "an event log");
    assert_eq!(image_kind_from_bytes(&head_with(0, b"PK\x03\x04"), &tail), None, "a zip");
    assert_eq!(image_kind_from_bytes(&vec![0u8; 4096], &tail), None, "zeros");
    // a boot signature with an empty partition table is not enough
    let mut empty_mbr = vec![0u8; 4096];
    empty_mbr[510] = 0x55;
    empty_mbr[511] = 0xAA;
    assert_eq!(image_kind_from_bytes(&empty_mbr, &tail), None);
    assert_eq!(image_kind_from_bytes(&[0u8; 100], &tail), None, "too short to judge");
}

// ─── files on disk ──────────────────────────────────────────────────────────

#[test]
fn extensionless_snapshot_is_an_image_and_is_staged() {
    let d = TempDir::new("sniff_snapshot");
    let img = d.write("snap-lab_os_disk-20261116", &fixture_bytes("gpt_ext4.img"));
    assert!(is_supported_image(&img), "a GPT disk with no extension is an image");
    assert_eq!(image_kind(&img), ImageKind::Raw);
    assert!(staged_host(&d, &img).starts_with("lab-"));
}

#[test]
fn snapshot_with_an_unknown_extension_is_an_image() {
    let d = TempDir::new("sniff_unknown_ext");
    let img = d.write("disk.20261116", &fixture_bytes("mbr_lvm_ext4.img"));
    assert!(is_supported_image(&img));
    assert!(staged_host(&d, &img).starts_with("lab-"));
}

#[test]
fn extensionless_fixed_vhd_opens_as_vhd() {
    let d = TempDir::new("sniff_fixed_vhd");
    let mut bytes = fixture_bytes("gpt_xfs.img");
    let size = bytes.len() as u64;
    bytes.extend_from_slice(&fixed_vhd_footer(size));
    let img = d.write("snap-lab_os_disk", &bytes);
    assert!(is_supported_image(&img));
    assert_eq!(image_kind(&img), ImageKind::Vhd);
    assert!(staged_host(&d, &img).starts_with("lab-"));
    // named .dd, the footer still makes it a VHD
    let dd = d.write("snap-lab_os_disk.dd", &bytes);
    assert_eq!(image_kind(&dd), ImageKind::Vhd);
}

#[test]
fn raw_disk_named_vhd_opens_as_raw() {
    let d = TempDir::new("sniff_raw_named_vhd");
    let img = d.write("exported.vhd", &fixture_bytes("gpt_ext4.img"));
    assert_eq!(image_kind(&img), ImageKind::Raw, "no conectix footer: a plain copy");
    assert!(staged_host(&d, &img).starts_with("lab-"));
}

#[test]
fn hives_segments_and_small_files_are_not_sniffed_as_images() {
    let d = TempDir::new("sniff_negatives");
    let mut hive = vec![0u8; 256 * 1024];
    hive[..4].copy_from_slice(b"regf");
    assert!(!is_supported_image(&d.write("SYSTEM", &hive)), "a hive with no extension");
    let mut seg = vec![0u8; 256 * 1024];
    seg[..8].copy_from_slice(b"EVF\x09\x0d\x0a\xff\x00");
    assert!(!is_supported_image(&d.write("case.E02", &seg)), "a later EWF segment carries the same magic");
    let small = fixture_bytes("gpt_ext4.img")[..(SNIFF_MIN_SIZE as usize - 1)].to_vec();
    assert!(!is_supported_image(&d.write("tiny", &small)), "under the minimum size");
    assert!(!is_supported_image(&d.join("missing")), "a file that is not there");
}

#[test]
fn directory_with_an_extensionless_snapshot_finds_it() {
    let d = TempDir::new("sniff_dir");
    let dir = d.mkdir("Azure/HOST01");
    std::fs::write(dir.join("snap-HOST01_os_disk-20261116"), fixture_bytes("gpt_ext4.img")).unwrap();
    std::fs::write(dir.join("notes.txt"), b"snapshot taken 16 Nov\n").unwrap();
    let mut ws = faramir::ingest::prepare_evidence(Some(&[dir.to_string_lossy().to_string()]), None, true).expect("prepare");
    let staged = ws.directories.iter().any(|p| walkdir::WalkDir::new(p).into_iter().flatten().any(|e| e.path().ends_with("etc/hostname")));
    let dirs = ws.directories.clone();
    ws.cleanup();
    assert!(staged, "the snapshot was unpacked: {dirs:?}");
}

// ─── the command line ───────────────────────────────────────────────────────

#[test]
fn cli_on_an_extensionless_snapshot_gives_rows_and_the_real_version() {
    let d = TempDir::new("sniff_cli");
    let img = d.write("snap-lab_os_disk-20261116", &fixture_bytes("gpt_ext4.img"));
    let out = d.join("out.csv");
    let o = std::process::Command::new(env!("CARGO_BIN_EXE_faramir"))
        .args(["-f", &img.to_string_lossy(), "-o", &out.to_string_lossy()])
        .output()
        .expect("run faramir");
    let stdout = String::from_utf8_lossy(&o.stdout).to_string();
    let stderr = String::from_utf8_lossy(&o.stderr).to_string();
    assert!(o.status.success(), "{stdout}\n{stderr}");
    assert!(stdout.contains(&format!("Faramir v{} ", env!("CARGO_PKG_VERSION"))), "banner carries the crate's version: {stdout}");
    assert!(!stdout.contains("ERR_WIN_HIVE_SIGNATURE") && !stderr.contains("ERR_WIN_HIVE_SIGNATURE"), "not read as a hive");
    let csv = std::fs::read_to_string(&out).unwrap();
    assert!(csv.lines().count() > 10, "persistence rows from the image: {} lines", csv.lines().count());
    assert!(csv.contains("/opt/lab/gpt/"), "the lab's canaries are in the timeline");
}
