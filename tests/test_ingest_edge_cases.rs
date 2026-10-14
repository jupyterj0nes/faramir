use faramir::ingest::archive::*;
use faramir::ingest::image::*;
use faramir::ingest::triage::*;
use std::path::Path;

// ─── Supported Archive Formats ────────────────────────────────────────────────

#[test]
fn test_archive_zip_supported() {
    assert!(is_supported_archive(Path::new("triage.zip")));
}

#[test]
fn test_archive_tar_gz_supported() {
    assert!(is_supported_archive(Path::new("uac.tar.gz")));
}

#[test]
fn test_archive_tgz_supported() {
    assert!(is_supported_archive(Path::new("uac.tgz")));
}

#[test]
fn test_archive_tar_supported() {
    assert!(is_supported_archive(Path::new("system.tar")));
}

#[test]
fn test_archive_7z_supported() {
    assert!(is_supported_archive(Path::new("collection.7z")));
}

#[test]
fn test_archive_rar_supported() {
    assert!(is_supported_archive(Path::new("collection.rar")));
}

#[test]
fn test_archive_case_insensitive() {
    assert!(is_supported_archive(Path::new("TRIAGE.ZIP")));
    assert!(is_supported_archive(Path::new("UAC.TAR.GZ")));
}

#[test]
fn test_archive_unsupported_extensions() {
    assert!(!is_supported_archive(Path::new("binary.exe")));
    assert!(!is_supported_archive(Path::new("data.bin")));
    assert!(!is_supported_archive(Path::new("disk.iso")));
    assert!(!is_supported_archive(Path::new("timeline.csv")));
    assert!(!is_supported_archive(Path::new("document.pdf")));
    assert!(!is_supported_archive(Path::new("noextension")));
}

// ─── Supported Disk Image Formats ─────────────────────────────────────────────

#[test]
fn test_image_e01_supported() {
    assert!(is_supported_image(Path::new("evidence.E01")));
    assert!(is_supported_image(Path::new("evidence.e01")));
}

#[test]
fn test_image_ex01_supported() {
    assert!(is_supported_image(Path::new("evidence.ex01")));
}

#[test]
fn test_image_raw_supported() {
    assert!(is_supported_image(Path::new("disk.raw")));
}

#[test]
fn test_image_dd_supported() {
    assert!(is_supported_image(Path::new("disk.dd")));
}

#[test]
fn test_image_img_supported() {
    assert!(is_supported_image(Path::new("disk.img")));
}

#[test]
fn test_image_001_supported() {
    assert!(is_supported_image(Path::new("disk.001")));
}

#[test]
fn test_image_vmdk_supported() {
    assert!(is_supported_image(Path::new("vm.vmdk")));
}

#[test]
fn test_image_vhd_supported() {
    assert!(is_supported_image(Path::new("disk.vhd")));
}

#[test]
fn test_image_vhdx_supported() {
    assert!(is_supported_image(Path::new("disk.vhdx")));
}

#[test]
fn test_image_unsupported_extensions() {
    assert!(!is_supported_image(Path::new("archive.zip")));
    assert!(!is_supported_image(Path::new("log.txt")));
    assert!(!is_supported_image(Path::new("hive.hve")));
}

// ─── Triage Detection Edge Cases ──────────────────────────────────────────────

#[test]
fn test_triage_detect_cylr_case_variant() {
    let entries = vec!["report.cylr.log".to_string()];
    let kind = detect_triage_type("export.zip", &entries);
    assert_eq!(kind, Some(TriageType::CyLROrLive));
}

#[test]
fn test_triage_detect_uac_stem_prefix() {
    let entries = vec!["dummy.txt".to_string()];
    let kind = detect_triage_type("uac-host-linux-2026.tar.gz", &entries);
    assert_eq!(kind, Some(TriageType::Uac));
}

#[test]
fn test_triage_detect_velociraptor_path() {
    let entries = vec!["random.json".to_string()];
    let kind = detect_triage_type("C:\\Cases\\Velociraptor\\output.zip", &entries);
    assert_eq!(kind, Some(TriageType::Velociraptor));
}

#[test]
fn test_triage_detect_velociraptor_auto_uploads() {
    let entries = vec!["uploads/auto/C/file.txt".to_string()];
    let kind = detect_triage_type("export.zip", &entries);
    assert_eq!(kind, Some(TriageType::Velociraptor));
}

#[test]
fn test_triage_detect_generic_fallback() {
    let entries = vec!["some_random_file.txt".to_string()];
    let kind = detect_triage_type("random_archive.zip", &entries);
    assert_eq!(kind, None);
}

#[test]
fn test_triage_type_labels() {
    assert_eq!(TriageType::Kape.label(), "KAPE");
    assert_eq!(TriageType::Velociraptor.label(), "Velociraptor");
    assert_eq!(TriageType::CortexXdr.label(), "Cortex XDR");
    assert_eq!(TriageType::CyLROrLive.label(), "CyLR");
    assert_eq!(TriageType::Uac.label(), "UAC");
    assert_eq!(TriageType::Generic.label(), "Generic Triage");
}

// ─── Hostname Extraction Edge Cases ───────────────────────────────────────────

#[test]
fn test_extract_hostname_uac_standard() {
    let h = extract_triage_hostname("uac-webserver01-linux-20260406120000.tar.gz", TriageType::Uac);
    assert_eq!(h, Some("webserver01".to_string()));
}

#[test]
fn test_extract_hostname_uac_multi_dash() {
    let h = extract_triage_hostname("uac-prod-db-cluster-01-linux-20260406120000.tar.gz", TriageType::Uac);
    assert_eq!(h, Some("prod-db-cluster-01".to_string()));
}

#[test]
fn test_extract_hostname_uac_unknown_rejected() {
    let h = extract_triage_hostname("uac-unknown-linux-20260406120000.tar.gz", TriageType::Uac);
    assert_eq!(h, None);
}

#[test]
fn test_extract_hostname_uac_too_short() {
    let h = extract_triage_hostname("uac-short.tar.gz", TriageType::Uac);
    assert_eq!(h, None);
}

#[test]
fn test_extract_hostname_cortex_valid() {
    let h = extract_triage_hostname("offline_collector_output_DESKTOP-ABC_2026-01-01_12-00-00.zip", TriageType::CortexXdr);
    assert_eq!(h, Some("DESKTOP-ABC".to_string()));
}

#[test]
fn test_extract_hostname_cortex_invalid_prefix() {
    let h = extract_triage_hostname("wrong_collector_output_DESKTOP_2026-01-01.zip", TriageType::CortexXdr);
    assert_eq!(h, None);
}

#[test]
fn test_extract_hostname_velociraptor_valid() {
    let h = extract_triage_hostname("Collection-SERVER123-20260406T100000Z.zip", TriageType::Velociraptor);
    assert_eq!(h, Some("SERVER123".to_string()));
}

#[test]
fn test_extract_hostname_velociraptor_invalid_prefix() {
    let h = extract_triage_hostname("Triage-SERVER123-2026.zip", TriageType::Velociraptor);
    assert_eq!(h, None);
}

#[test]
fn test_extract_hostname_kape_valid() {
    let h = extract_triage_hostname("HOST01_20260406_120000.zip", TriageType::Kape);
    assert_eq!(h, Some("HOST01".to_string()));
}

#[test]
fn test_extract_hostname_kape_missing_digits() {
    let h = extract_triage_hostname("HOST01_nodigits.zip", TriageType::Kape);
    assert_eq!(h, None);
}

#[test]
fn test_inspect_triage_archive_nonexistent() {
    let info = inspect_triage_archive(Path::new("/non/existent/archive.zip"));
    assert!(info.is_none());
}
