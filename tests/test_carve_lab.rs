//! Cross-examination of `--carve` against a volume built by
//! `scripts/carve_lab.ps1` on a real Windows host.
//!
//! Point `FARAMIR_CARVELAB` at the folder holding `carvelab.vhd` and
//! `truth.json` and run `cargo test --test test_carve_lab -- --ignored`.
//! Every deleted hive must be carved (or recognised as identical to a live
//! one) at exactly `partition_offset + LCN * cluster_size`, and the canary
//! Run value must come out tagged `carved`.
mod common;

use faramir::carve::{carve_path, fingerprints_under};
use faramir::windows::{diag, run_technique, HiveSet, TechniqueId};
use serde::Deserialize;
use std::collections::HashSet;
use std::path::PathBuf;

fn lab_dir() -> Option<PathBuf> {
    std::env::var_os("FARAMIR_CARVELAB").map(PathBuf::from).filter(|p| p.join("carvelab.vhd").is_file() && p.join("truth.json").is_file())
}

#[derive(serde::Deserialize)]
struct Extent {
    clusters: i64,
    lcn: i64,
}

/// PowerShell's ConvertTo-Json writes a one-element array as a bare object.
#[derive(serde::Deserialize)]
#[serde(untagged)]
enum OneOrMany {
    One(Extent),
    Many(Vec<Extent>),
}

fn extents<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<Extent>, D::Error> {
    Ok(match OneOrMany::deserialize(d)? {
        OneOrMany::One(e) => vec![e],
        OneOrMany::Many(v) => v,
    })
}

#[derive(serde::Deserialize)]
struct FileFacts {
    size: u64,
    #[serde(deserialize_with = "extents")]
    extents: Vec<Extent>,
    embedded: String,
}

#[derive(serde::Deserialize)]
struct Truth {
    canary: String,
    partition_offset: u64,
    cluster_size: u64,
    deleted: Vec<String>,
    live: Vec<String>,
    files: std::collections::BTreeMap<String, FileFacts>,
}

#[test]
#[ignore]
fn lab_volume_hives_are_carved_at_their_clusters() {
    let Some(dir) = lab_dir() else {
        eprintln!("FARAMIR_CARVELAB not set or incomplete; skipping");
        return;
    };
    let text = std::fs::read_to_string(dir.join("truth.json")).unwrap();
    let truth: Truth = serde_json::from_str(text.trim_start_matches('\u{feff}')).expect("truth.json");
    let tmp = common::TempDir::new("carve_lab");

    // the live volume through the normal pipeline, to know what is extracted
    let extracted = tmp.join("extracted");
    faramir::ingest::image::unpack_disk_image(&dir.join("carvelab.vhd"), &extracted, true).unwrap();
    let known = fingerprints_under(&extracted);
    assert_eq!(known.len(), truth.live.len(), "one fingerprint per live hive");

    diag::clear();
    let report = carve_path(&dir.join("carvelab.vhd"), &tmp.join("carved"), &known);
    let diags: Vec<String> = diag::snapshot().iter().map(|e| e.to_string()).collect();
    assert!(!report.stats.aborted);
    assert_eq!(report.stats.read_errors, 0);

    let offset_of = |f: &FileFacts| {
        assert_eq!(f.extents.len(), 1, "lab files are contiguous");
        truth.partition_offset + f.extents[0].lcn as u64 * truth.cluster_size
    };
    let carved_offsets: HashSet<u64> = report.hives.iter().map(|h| h.offset).collect();
    for name in &truth.deleted {
        let f = &truth.files[name];
        let off = offset_of(f);
        if name == "ntuser_bak" {
            assert!(
                diags.iter().any(|d| d.contains("ERR_ING_CARVE_MATCHES_EXTRACTED") && d.contains(&format!("{off:#x}"))),
                "{name} at {off:#x} must be reported identical to a live hive: {diags:?}"
            );
            assert!(!carved_offsets.contains(&off));
        } else {
            let h = report.hives.iter().find(|h| h.offset == off).unwrap_or_else(|| panic!("{name} not carved at {off:#x}: {:?}", carved_offsets));
            assert!(h.complete, "{name} is contiguous and untouched, must be complete");
            assert_eq!(h.recovered_len as u64, f.size);
            assert_eq!(h.header.embedded_name, f.embedded);
            assert_eq!(f.extents[0].clusters as u64 * truth.cluster_size, f.size.div_ceil(truth.cluster_size) * truth.cluster_size);
        }
    }
    for name in &truth.live {
        let off = offset_of(&truth.files[name]);
        assert!(!carved_offsets.contains(&off), "live hive {name} must not be carved");
    }
    assert_eq!(report.hives.len(), truth.deleted.len() - 1);

    // the canary only exists in mallory's deleted hive
    let mut set = HiveSet::from_paths(&report.hive_paths(), &report.out_dir);
    let found = run_technique(TechniqueId::Run, &mut set, None);
    let canary: Vec<_> = found.iter().filter(|p| p.value == truth.canary).collect();
    assert_eq!(canary.len(), 1, "{found:?}");
    let mallory_off = offset_of(&truth.files["mallory"]);
    assert!(canary[0].origin.contains(&format!("{mallory_off:012x}")), "{}", canary[0].origin);
}
