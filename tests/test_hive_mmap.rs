//! A clean hive is read through a memory map; the map and the buffered file
//! give the same bytes and the same findings, and the map never changes what
//! a technique sees.
mod common;
use common::*;
use faramir::windows::diag;
use faramir::windows::hives::HiveSource;
use faramir::windows::{run_all, HiveSet};
use std::io::{Read, Seek, SeekFrom};

const RUN: &str = r"Microsoft\Windows\CurrentVersion\Run";

#[test]
fn clean_hive_opens_through_the_memory_map() {
    let d = TempDir::new("mmap_open");
    let mut b = HiveBuilder::software();
    b.sz(RUN, "Updater", r"C:\evil\updater.exe");
    let path = b.write(&d.join("SOFTWARE"));
    diag::clear();
    let src = HiveSource::open(&path).unwrap();
    assert!(src.is_mapped(), "a readable hive is mapped, not buffered");
    assert!(diag::snapshot().iter().all(|e| e.error_number() != 3050), "no map failure recorded: {:?}", diag::snapshot());
}

#[test]
fn mapped_and_buffered_sources_read_the_same_bytes() {
    let d = TempDir::new("mmap_bytes");
    let mut b = HiveBuilder::software();
    for i in 0..40 {
        b.sz(RUN, &format!("Entry{i}"), &format!(r"C:\Program Files\App{i}\app{i}.exe --flag{i}"));
    }
    let path = b.write(&d.join("SOFTWARE"));
    let want = std::fs::read(&path).unwrap();
    assert!(want.len() > 8192, "fixture spans several pages: {} bytes", want.len());

    let mut mapped = HiveSource::open(&path).unwrap();
    assert!(mapped.is_mapped());
    let mut got = Vec::new();
    mapped.read_to_end(&mut got).unwrap();
    assert_eq!(got, want, "the whole file through the map");

    let mut buffered = HiveSource::File(std::io::BufReader::new(std::fs::File::open(&path).unwrap()));
    // the techniques seek thousands of times: every landing must agree
    for off in [0u64, 1, 4095, 4096, 4097, 8192, want.len() as u64 - 17, want.len() as u64 - 1] {
        let mut a = [0u8; 16];
        let mut c = [0u8; 16];
        mapped.seek(SeekFrom::Start(off)).unwrap();
        buffered.seek(SeekFrom::Start(off)).unwrap();
        let na = mapped.read(&mut a).unwrap();
        let nc = buffered.read(&mut c).unwrap();
        assert_eq!((na, &a[..na]), (nc, &c[..nc]), "offset {off}");
    }
    assert_eq!(mapped.seek(SeekFrom::End(0)).unwrap(), want.len() as u64);
    let mut none = [0u8; 4];
    assert_eq!(mapped.read(&mut none).unwrap(), 0, "reading past the end gives nothing, as a file does");
}

#[test]
fn techniques_find_the_same_through_the_map() {
    let d = TempDir::new("mmap_findings");
    let mut b = HiveBuilder::software();
    b.sz(RUN, "Updater", r"C:\evil\updater.exe").sz(RUN, "Tray", r"C:\Program Files\Vendor\tray.exe");
    let path = b.write(&d.join("SOFTWARE"));
    diag::clear();
    let mut set = HiveSet::from_paths(&[path], &d.path);
    let found = run_all(&mut set, &d.path);
    let values: Vec<&str> = found.iter().map(|p| p.value.as_str()).collect();
    assert!(values.contains(&r"C:\evil\updater.exe") && values.contains(&r"C:\Program Files\Vendor\tray.exe"), "{values:?}");
    assert!(diag::snapshot().iter().all(|e| e.error_number() != 3050), "{:?}", diag::snapshot());
}

#[test]
fn an_empty_file_maps_to_nothing_and_a_missing_one_is_an_open_error() {
    // memmap2 maps a zero-length file as an empty slice on every platform, so
    // the map does not fail here; the buffered fallback itself is exercised by
    // `mapped_and_buffered_sources_read_the_same_bytes` and its diagnostic by
    // `test_err_hive_map_failed_code`
    let d = TempDir::new("mmap_empty");
    let path = d.write("EMPTY", &[]);
    diag::clear();
    let mut src = HiveSource::open(&path).unwrap();
    let mut got = Vec::new();
    src.read_to_end(&mut got).unwrap();
    assert!(got.is_empty());
    assert!(HiveSource::open(&d.join("missing")).is_err(), "a missing file is an open error, not a map error");
    assert!(diag::snapshot().iter().all(|e| e.error_number() != 3050), "{:?}", diag::snapshot());
}
