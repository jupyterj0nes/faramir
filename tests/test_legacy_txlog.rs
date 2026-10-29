//! Old-format (Windows 7 / 8, `DIRT`) transaction logs are replayed, checked against the
//! hive Windows 7 recovered itself.

mod common;

use common::*;
use faramir::windows::diag;
use faramir::windows::hives::open_hive_path;
use std::io::{Read, Seek, SeekFrom};

#[test]
fn old_format_log_is_replayed_like_windows_7() {
    diag::clear();
    let mut opened = open_hive_path(&fixture("old_dirty_hive/OldDirtyHive")).unwrap();
    assert!(opened.recovery.was_dirty);
    assert!(opened.recovery.logs_applied, "{:?}", diag::snapshot());
    assert!(diag::has("ERR_WIN_HIVE_RECOVERED"));

    let mut ours = Vec::new();
    opened.hive.seek(SeekFrom::Start(0)).unwrap();
    opened.hive.read_to_end(&mut ours).unwrap();
    let windows = std::fs::read(fixture("old_dirty_hive/RecoveredHive_Windows7")).unwrap();
    let theirs = &windows[4096..];
    let n = ours.len().min(theirs.len());
    assert!(n > 0);

    // Windows refreshes the timestamp in the first hbin header when it writes the hive, and
    // loading it refreshes one cached nk field (largest value name length): one byte out of
    // the 1,109 the log corrects.
    let diffs: Vec<usize> = (0..n).filter(|i| !(20..28).contains(i)).filter(|&i| ours[i] != theirs[i]).collect();
    assert!(diffs.len() <= 4, "{} byte(s) differ from the Windows 7 recovery, first at {:#x}", diffs.len(), diffs[0]);

    let dirty = std::fs::read(fixture("old_dirty_hive/OldDirtyHive")).unwrap();
    let changed = (0..n).filter(|&i| dirty[4096 + i] != theirs[i]).count();
    assert!(changed > 100, "the log must actually change the hive ({changed} bytes)");
}
