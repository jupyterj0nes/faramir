//! VMDK / VHD / VHDX readers and image-set handling.
mod common;

use common::*;
use faramir::errors::{FaramirError, Severity};
use faramir::ingest::image::*;
use faramir::ingest::vhd::{open_virtual_disk, vhdx_guids, VhdReader, VhdxReader};
use faramir::ingest::vmdk::VmdkReader;
use faramir::windows::diag;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

fn pattern(n: usize, seed: u8) -> Vec<u8> {
    (0..n).map(|i| ((i as u32 * 31 + seed as u32) % 251) as u8).collect()
}

fn vhd_footer(size: u64, disk_type: u32, data_offset: u64) -> [u8; 512] {
    let mut f = [0u8; 512];
    f[..8].copy_from_slice(b"conectix");
    f[16..24].copy_from_slice(&data_offset.to_be_bytes());
    f[40..48].copy_from_slice(&size.to_be_bytes());
    f[48..56].copy_from_slice(&size.to_be_bytes());
    f[60..64].copy_from_slice(&disk_type.to_be_bytes());
    f
}

// ─── segment classification ──────────────────────────────────────────────────

#[test]
fn primary_segments() {
    for p in ["disk.E01", "disk.Ex01", "disk.e01", "vm.vmdk", "vm.vhd", "vm.vhdx", "d.dd", "d.raw", "d.img", "d.001"] {
        assert!(is_primary_image_segment(Path::new(p)), "{p}");
        assert!(is_supported_image(Path::new(p)), "{p}");
        assert!(!is_secondary_image_segment(Path::new(p)), "{p}");
    }
}

#[test]
fn secondary_segments_are_recognised_but_not_fed() {
    for p in ["disk.E02", "disk.e17", "disk.Ex02", "vm-flat.vmdk", "vm-ctk.vmdk", "vm-s001.vmdk", "vm-s012.vmdk", "vm-000001.vmdk", "d.002", "d.137"] {
        assert!(!is_primary_image_segment(Path::new(p)), "{p}");
        assert!(is_image_file(Path::new(p)), "{p}");
        assert!(is_secondary_image_segment(Path::new(p)), "{p}");
    }
}

#[test]
fn non_images() {
    for p in ["notes.txt", "triage.zip", "SYSTEM", "a.e0", "a.exe", "vm-s.vmdk.bak"] {
        assert!(!is_image_file(Path::new(p)), "{p}");
        assert!(!is_supported_image(Path::new(p)), "{p}");
    }
}

#[test]
fn vmdk_descriptor_named_like_a_snapshot_base_is_primary() {
    assert!(is_primary_image_segment(Path::new("server-0001.vmdk")), "4 digits is not a snapshot suffix");
    assert!(is_primary_image_segment(Path::new("server-sales.vmdk")));
    assert!(is_primary_image_segment(Path::new("server-s.vmdk")));
}

#[test]
fn discovery_skips_secondary_segments_with_info() {
    diag::clear();
    let d = TempDir::new("vdisk_disc");
    d.write("case/disk.E01", b"x");
    d.write("case/disk.E02", b"x");
    d.write("case/disk.E03", b"x");
    d.write("case/vm.vmdk", b"x");
    d.write("case/vm-flat.vmdk", b"x");
    d.write("case/vm-s001.vmdk", b"x");
    let dirs = vec![d.path.to_string_lossy().to_string()];
    let (_, _, _, images) = faramir::ingest::discover_evidence_targets(Some(&dirs), None);
    let names: Vec<String> = images.iter().map(|p| p.file_name().unwrap().to_string_lossy().to_lowercase()).collect();
    assert_eq!(names.len(), 2, "{names:?}");
    assert!(names.contains(&"disk.e01".to_string()));
    assert!(names.contains(&"vm.vmdk".to_string()));
    assert_eq!(diag::count("ERR_ING_IMAGE_SEGMENT_SKIPPED"), 4);
}

#[test]
fn explicit_secondary_segment_file_is_reported_not_processed() {
    diag::clear();
    let d = TempDir::new("vdisk_file");
    let p = d.write("disk.E02", b"x");
    let files = vec![p.to_string_lossy().to_string()];
    let (_, direct, _, images) = faramir::ingest::discover_evidence_targets(None, Some(&files));
    assert!(images.is_empty());
    assert!(direct.is_empty());
    assert!(diag::has("ERR_ING_IMAGE_SEGMENT_SKIPPED"));
}

// ─── VHD ─────────────────────────────────────────────────────────────────────

#[test]
fn fixed_vhd_through_open_virtual_disk() {
    let d = TempDir::new("vhd_fixed");
    let data = pattern(8192, 3);
    let mut img = data.clone();
    img.extend_from_slice(&vhd_footer(8192, 2, u64::MAX));
    let p = d.write("disk.vhd", &img);
    let (mut r, size) = open_virtual_disk(p.to_str().unwrap()).unwrap();
    assert_eq!(size, 8192);
    let mut out = Vec::new();
    r.read_to_end(&mut out).unwrap();
    assert_eq!(out, data);
    r.seek(SeekFrom::Start(4000)).unwrap();
    let mut b = [0u8; 16];
    r.read_exact(&mut b).unwrap();
    assert_eq!(&b[..], &data[4000..4016]);
    assert_eq!(VhdReader::probe_size(p.to_str().unwrap()), Some(8192));
}

#[test]
fn vhd_with_only_leading_footer_copy() {
    let d = TempDir::new("vhd_lead");
    let mut img = vhd_footer(1024, 2, u64::MAX).to_vec();
    img.extend_from_slice(&pattern(1024, 1));
    img.extend_from_slice(&[0u8; 511]); // truncated trailing footer
    let p = d.write("disk.vhd", &img);
    assert!(VhdReader::open(p.to_str().unwrap()).is_ok());
}

#[test]
fn tiny_file_is_not_a_vhd() {
    let d = TempDir::new("vhd_tiny");
    let p = d.write("disk.vhd", b"short");
    assert!(VhdReader::open(p.to_str().unwrap()).err().unwrap().contains("too small"));
}

// ─── VHDX ────────────────────────────────────────────────────────────────────

/// Minimal dynamic VHDX: 1 MB blocks, 3 blocks, block 1 unallocated.
fn build_vhdx(block_data: &[Option<Vec<u8>>]) -> Vec<u8> {
    let block_size: u64 = 1 << 20;
    let virtual_size = block_size * block_data.len() as u64;
    let bat_off: u64 = 1 << 20; // 1 MB
    let meta_off: u64 = 2 << 20; // 2 MB
    let data_off: u64 = 3 << 20; // payload blocks start at 3 MB
    let mut img = vec![0u8; data_off as usize];
    img[..8].copy_from_slice(b"vhdxfile");
    // region table at 192 KB (and a copy at 256 KB)
    for off in [192 * 1024usize, 256 * 1024] {
        img[off..off + 4].copy_from_slice(b"regi");
        img[off + 8..off + 12].copy_from_slice(&2u32.to_le_bytes());
        let e0 = off + 16;
        img[e0..e0 + 16].copy_from_slice(&vhdx_guids::BAT);
        img[e0 + 16..e0 + 24].copy_from_slice(&bat_off.to_le_bytes());
        img[e0 + 24..e0 + 28].copy_from_slice(&(1u32 << 20).to_le_bytes());
        let e1 = off + 48;
        img[e1..e1 + 16].copy_from_slice(&vhdx_guids::METADATA);
        img[e1 + 16..e1 + 24].copy_from_slice(&meta_off.to_le_bytes());
        img[e1 + 24..e1 + 28].copy_from_slice(&(1u32 << 20).to_le_bytes());
    }
    // metadata table
    let m = meta_off as usize;
    img[m..m + 8].copy_from_slice(b"metadata");
    img[m + 10..m + 12].copy_from_slice(&3u16.to_le_bytes());
    let items: [([u8; 16], u32, Vec<u8>); 3] = [
        (vhdx_guids::FILE_PARAMETERS, 0x10000, {
            let mut v = (block_size as u32).to_le_bytes().to_vec();
            v.extend_from_slice(&0u32.to_le_bytes());
            v
        }),
        (vhdx_guids::VIRTUAL_DISK_SIZE, 0x10010, virtual_size.to_le_bytes().to_vec()),
        (vhdx_guids::LOGICAL_SECTOR_SIZE, 0x10020, 512u32.to_le_bytes().to_vec()),
    ];
    for (i, (gid, off, payload)) in items.iter().enumerate() {
        let e = m + 32 + i * 32;
        img[e..e + 16].copy_from_slice(gid);
        img[e + 16..e + 20].copy_from_slice(&off.to_le_bytes());
        img[e + 20..e + 24].copy_from_slice(&(payload.len() as u32).to_le_bytes());
        let p = m + *off as usize;
        img[p..p + payload.len()].copy_from_slice(payload);
    }
    // BAT and payload (chunk ratio is 4 for 1 MB blocks / 512-byte sectors; no bitmap entry within 3 blocks)
    let mut next = data_off;
    for (i, block) in block_data.iter().enumerate() {
        let e = bat_off as usize + i * 8;
        match block {
            Some(bytes) => {
                let entry: u64 = next | 6; // fully present
                img[e..e + 8].copy_from_slice(&entry.to_le_bytes());
                img.resize((next + block_size) as usize, 0);
                img[next as usize..next as usize + bytes.len()].copy_from_slice(bytes);
                next += block_size;
            }
            None => img[e..e + 8].copy_from_slice(&0u64.to_le_bytes()),
        }
    }
    img
}

#[test]
fn dynamic_vhdx_reads_blocks_and_holes() {
    let d = TempDir::new("vhdx_dyn");
    let b0 = pattern(1 << 20, 5);
    let b2 = pattern(1 << 20, 9);
    let img = build_vhdx(&[Some(b0.clone()), None, Some(b2.clone())]);
    let p = d.write("disk.vhdx", &img);
    let mut r = VhdxReader::open(p.to_str().unwrap()).unwrap();
    assert_eq!(r.total_size(), 3 << 20);
    let mut out = Vec::new();
    r.read_to_end(&mut out).unwrap();
    assert_eq!(out.len(), 3 << 20);
    assert_eq!(&out[..1 << 20], &b0[..]);
    assert!(out[1 << 20..2 << 20].iter().all(|b| *b == 0), "unallocated block reads as zeros");
    assert_eq!(&out[2 << 20..], &b2[..]);
    // seek across a block boundary
    r.seek(SeekFrom::Start((2 << 20) - 8)).unwrap();
    let mut b = [0u8; 16];
    r.read_exact(&mut b).unwrap();
    assert!(b[..8].iter().all(|x| *x == 0));
    assert_eq!(&b[8..], &b2[..8]);
    assert_eq!(VhdxReader::probe_size(p.to_str().unwrap()), Some(3 << 20));
    let (mut boxed, size) = open_virtual_disk(p.to_str().unwrap()).unwrap();
    assert_eq!(size, 3 << 20);
    let mut first = [0u8; 4];
    boxed.read_exact(&mut first).unwrap();
    assert_eq!(&first, &b0[..4]);
}

#[test]
fn vhdx_without_signature_is_refused() {
    let d = TempDir::new("vhdx_bad");
    let p = d.write("disk.vhdx", &vec![0u8; 4 << 20]);
    assert!(VhdxReader::open(p.to_str().unwrap()).err().unwrap().contains("vhdxfile"));
}

#[test]
fn vhdx_without_region_table_is_refused() {
    let d = TempDir::new("vhdx_noreg");
    let mut img = vec![0u8; 4 << 20];
    img[..8].copy_from_slice(b"vhdxfile");
    let p = d.write("disk.vhdx", &img);
    assert!(VhdxReader::open(p.to_str().unwrap()).err().unwrap().contains("region table"));
}

// ─── VMDK ────────────────────────────────────────────────────────────────────

#[test]
fn vmdk_descriptor_with_split_flat_extents_and_zero_extent() {
    let d = TempDir::new("vmdk_split");
    let a = pattern(2048, 2);
    let b = pattern(1024, 7);
    d.write("vm-f001.vmdk", &a);
    d.write("vm-f002.vmdk", &b);
    let desc = "# Disk DescriptorFile\nversion=1\ncreateType=\"twoGbMaxExtentFlat\"\nRW 4 FLAT \"vm-f001.vmdk\" 0\nRW 2 FLAT \"vm-f002.vmdk\" 0\nRW 2 ZERO\n";
    let p = d.write("vm.vmdk", desc.as_bytes());
    let mut r = VmdkReader::open(p.to_str().unwrap()).unwrap();
    assert_eq!(r.total_size(), 4096);
    let mut out = Vec::new();
    r.read_to_end(&mut out).unwrap();
    assert_eq!(&out[..2048], &a[..]);
    assert_eq!(&out[2048..3072], &b[..]);
    assert!(out[3072..].iter().all(|x| *x == 0));
    assert_eq!(VmdkReader::probe_size(p.to_str().unwrap()), Some(4096));
}

#[test]
fn vmdk_descriptor_without_data_file_is_incomplete() {
    let d = TempDir::new("vmdk_incomplete");
    let desc = "# Disk DescriptorFile\ncreateType=\"monolithicFlat\"\nRW 2048 FLAT \"vm-flat.vmdk\" 0\n";
    let p = d.write("vm.vmdk", desc.as_bytes());
    let err = VmdkReader::open(p.to_str().unwrap()).err().unwrap();
    assert!(err.contains("Incomplete VMDK"), "{err}");
    let staging = d.mkdir("staging");
    let e = unpack_disk_image(&p, &staging, true).unwrap_err().to_string();
    assert!(e.contains("ERR_ING_IMAGE_INCOMPLETE"), "{e}");
}

#[test]
fn vmdk_filepart_fallback_for_incomplete_uploads() {
    let d = TempDir::new("vmdk_filepart");
    let a = pattern(1024, 4);
    d.write("vm-flat.vmdk.filepart", &a);
    let desc = "# Disk DescriptorFile\ncreateType=\"monolithicFlat\"\nRW 2 FLAT \"vm-flat.vmdk\" 0\n";
    let p = d.write("vm.vmdk", desc.as_bytes());
    let mut r = VmdkReader::open(p.to_str().unwrap()).unwrap();
    let mut out = Vec::new();
    r.read_to_end(&mut out).unwrap();
    assert_eq!(out, a);
}

#[test]
fn raw_bytes_named_vmdk_are_read_flat() {
    let d = TempDir::new("vmdk_raw");
    let a = pattern(4096, 8);
    let p = d.write("vm.vmdk", &a);
    let mut r = VmdkReader::open(p.to_str().unwrap()).unwrap();
    let mut out = Vec::new();
    r.read_to_end(&mut out).unwrap();
    assert_eq!(out, a);
}

#[test]
fn garbage_vmdk_reports_open_error_code() {
    let d = TempDir::new("vmdk_garbage");
    let desc = "# Disk DescriptorFile\ncreateType=\"x\"\nRW 2 BOGUS \"vm-flat.vmdk\" 0\n";
    let p = d.write("vm.vmdk", desc.as_bytes());
    let staging = d.mkdir("staging");
    let e = unpack_disk_image(&p, &staging, true).unwrap_err().to_string();
    assert!(e.contains("ERR_ING_VMDK_OPEN"), "{e}");
}

// ─── pipeline on virtual disks ───────────────────────────────────────────────

#[test]
fn fixed_vhd_without_ntfs_is_reported_cleanly() {
    let d = TempDir::new("vhd_pipeline");
    let mut img = vec![0u8; 1 << 20];
    img.extend_from_slice(&vhd_footer(1 << 20, 2, u64::MAX));
    let p = d.write("empty.vhd", &img);
    let staging = d.mkdir("staging");
    let e = unpack_disk_image(&p, &staging, true).unwrap_err().to_string();
    assert!(e.contains("NTFS"), "{e}");
}

#[test]
fn differencing_vhd_is_incomplete_image() {
    let d = TempDir::new("vhd_diff");
    let p = d.write("child.vhd", &vhd_footer(4096, 4, 512));
    let staging = d.mkdir("staging");
    let e = unpack_disk_image(&p, &staging, true).unwrap_err().to_string();
    assert!(e.contains("ERR_ING_IMAGE_INCOMPLETE"), "{e}");
}

#[test]
fn fixed_vhd_with_ntfs_signature_reaches_the_ntfs_parser() {
    // The pipeline must find the volume (offset 0) and hand it to the NTFS
    // parser; a bare boot-sector signature then fails inside NTFS, not before.
    let d = TempDir::new("vhd_ntfs_sig");
    let mut img = vec![0u8; 1 << 20];
    img[3..11].copy_from_slice(b"NTFS    ");
    img[510] = 0x55;
    img[511] = 0xAA;
    img.extend_from_slice(&vhd_footer(1 << 20, 2, u64::MAX));
    let p = d.write("sig.vhd", &img);
    let staging = d.mkdir("staging");
    let out = unpack_disk_image(&p, &staging, true).expect("partition found, extraction warns but completes");
    assert!(out.exists());
}

// ─── error codes ─────────────────────────────────────────────────────────────

#[test]
fn ingest_image_error_codes() {
    let cases = [
        (FaramirError::VmdkOpenFailed("x".into()), "ERR_ING_VMDK_OPEN", 2015, Severity::Error),
        (FaramirError::VhdOpenFailed("x".into()), "ERR_ING_VHD_OPEN", 2016, Severity::Error),
        (FaramirError::ImageSegmentSkipped("x".into()), "ERR_ING_IMAGE_SEGMENT_SKIPPED", 2017, Severity::Info),
        (FaramirError::ImageIncomplete("x".into()), "ERR_ING_IMAGE_INCOMPLETE", 2018, Severity::Error),
    ];
    for (e, code, n, sev) in cases {
        assert_eq!(e.code(), code);
        assert_eq!(e.error_number(), n);
        assert_eq!(e.severity(), sev);
        assert_eq!(e.category(), "ING");
        assert!(e.to_string().contains(code));
    }
    let mut nums: Vec<u32> = FaramirError::catalog().iter().map(|e| e.error_number()).filter(|n| (2000..3000).contains(n)).collect();
    nums.sort_unstable();
    assert_eq!(nums.first(), Some(&2001));
    assert_eq!(nums.last(), Some(&2037));
    for w in nums.windows(2) {
        assert_eq!(w[1], w[0] + 1);
    }
}
