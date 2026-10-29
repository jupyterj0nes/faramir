//! Independent oracle: Faramir's transaction-log replay of the real Windows 10
//! dirty hive must produce the same registry tree as Eric Zimmerman's rla.exe.
mod common;

use common::*;
use faramir::windows::diag;
use faramir::windows::hives::{open_hive_path, HiveFile, HiveSource};
use nt_hive2::{Hive, HiveParseMode, KeyNode};
use std::collections::BTreeMap;
use std::fs::File;
use std::io::{BufReader, Cursor, Seek, SeekFrom};

/// path -> (last write, [(value name, rendered data)])
type Dump = BTreeMap<String, (String, Vec<(String, String)>)>;

fn dump_key(key: &KeyNode, path: &str, hive: &mut HiveFile, out: &mut Dump) {
    let mut values: Vec<(String, String)> = key
        .values()
        .iter()
        .map(|v| (v.name().to_string(), v.value().to_string()))
        .collect();
    values.sort();
    out.insert(path.to_string(), (key.timestamp().to_rfc3339(), values));
    let subkeys = match key.subkeys(hive) {
        Ok(s) => s.iter().cloned().collect::<Vec<_>>(),
        Err(_) => Vec::new(),
    };
    for sk in subkeys {
        let sk = sk.borrow();
        let child = if path.is_empty() { sk.name().to_string() } else { format!("{path}\\{}", sk.name()) };
        dump_key(&sk, &child, hive, out);
    }
}

fn dump(hive: &mut HiveFile) -> Dump {
    let root = hive.root_key_node().unwrap();
    let mut out = Dump::new();
    dump_key(&root, "", hive, &mut out);
    out
}

fn open_clean(path: &std::path::Path) -> HiveFile {
    Hive::new(HiveSource::File(BufReader::new(File::open(path).unwrap())), HiveParseMode::NormalWithBaseBlock)
        .unwrap()
        .treat_hive_as_clean()
}

#[test]
fn faramir_replay_matches_rla_tree() {
    diag::clear();
    let d = TempDir::new("oracle_rla");
    for name in ["NewDirtyHive", "NewDirtyHive.LOG1", "NewDirtyHive.LOG2"] {
        std::fs::copy(fixture(&format!("dirty_hive/{name}")), d.join(name)).unwrap();
    }
    let mut ours = open_hive_path(&d.join("NewDirtyHive")).unwrap();
    assert!(ours.recovery.logs_applied, "{:?}", diag::snapshot());
    let mut theirs = open_clean(&fixture("dirty_hive/NewDirtyHive.rla-replayed"));

    let a = dump(&mut ours.hive);
    let b = dump(&mut theirs);
    assert!(a.len() >= 2, "fixture must have a tree, got {} keys", a.len());
    let only_ours: Vec<&String> = a.keys().filter(|k| !b.contains_key(*k)).collect();
    let only_theirs: Vec<&String> = b.keys().filter(|k| !a.contains_key(*k)).collect();
    assert!(only_ours.is_empty() && only_theirs.is_empty(), "key sets differ: ours-only {only_ours:?}, rla-only {only_theirs:?}");
    for (k, va) in &a {
        let vb = &b[k];
        assert_eq!(va, vb, "key {k} differs");
    }
}

#[test]
fn faramir_replay_matches_rla_bytes() {
    diag::clear();
    let d = TempDir::new("oracle_rla_bytes");
    for name in ["NewDirtyHive", "NewDirtyHive.LOG1", "NewDirtyHive.LOG2"] {
        std::fs::copy(fixture(&format!("dirty_hive/{name}")), d.join(name)).unwrap();
    }
    let mut ours = open_hive_path(&d.join("NewDirtyHive")).unwrap();
    assert!(ours.recovery.logs_applied);

    let mut buf = Cursor::new(Vec::new());
    ours.hive.write_baseblock(&mut buf).unwrap();
    ours.hive.seek(SeekFrom::Start(0)).unwrap();
    std::io::copy(&mut ours.hive, &mut buf).unwrap();
    let replayed = buf.into_inner();
    let rla = std::fs::read(fixture("dirty_hive/NewDirtyHive.rla-replayed")).unwrap();
    assert_eq!(replayed.len(), rla.len(), "sizes differ");

    // Hive bins must be identical; the base block may differ in checksum/timestamp bookkeeping.
    let bins_ours = &replayed[4096..];
    let bins_rla = &rla[4096..];
    let diffs = bins_ours.iter().zip(bins_rla).filter(|(x, y)| x != y).count();
    assert_eq!(diffs, 0, "{diffs} differing bytes in hive bins after replay");

    let seq_ours = u32::from_le_bytes(replayed[4..8].try_into().unwrap());
    let seq_rla = u32::from_le_bytes(rla[4..8].try_into().unwrap());
    assert_eq!(seq_ours, seq_rla, "final sequence number must agree (rla reports 0x5)");
}

#[test]
fn dirty_tree_differs_from_replayed_tree() {
    // Sanity: the logs actually change something, otherwise the oracle proves nothing.
    let mut dirty = {
        let h: Hive<HiveSource, nt_hive2::DirtyHive> =
            Hive::new(HiveSource::File(BufReader::new(File::open(fixture("dirty_hive/NewDirtyHive")).unwrap())), HiveParseMode::NormalWithBaseBlock).unwrap();
        h.treat_hive_as_clean()
    };
    let mut rla = open_clean(&fixture("dirty_hive/NewDirtyHive.rla-replayed"));
    assert_ne!(dump(&mut dirty), dump(&mut rla));
}
