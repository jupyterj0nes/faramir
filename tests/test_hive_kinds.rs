//! Hive classification by file name and by embedded header name.
mod common;

use common::*;
use faramir::windows::diag;
use faramir::windows::hives::*;

// ─── from_file_name ──────────────────────────────────────────────────────────

#[test]
fn name_canonical_system() {
    assert_eq!(HiveKind::from_file_name("SYSTEM"), HiveKind::System);
}
#[test]
fn name_canonical_lowercase() {
    assert_eq!(HiveKind::from_file_name("software"), HiveKind::Software);
}
#[test]
fn name_canonical_mixed_case() {
    assert_eq!(HiveKind::from_file_name("NtUser.dat"), HiveKind::NtUser);
}
#[test]
fn name_sam_security_default() {
    assert_eq!(HiveKind::from_file_name("SAM"), HiveKind::Sam);
    assert_eq!(HiveKind::from_file_name("SECURITY"), HiveKind::Security);
    assert_eq!(HiveKind::from_file_name("DEFAULT"), HiveKind::Default);
}
#[test]
fn name_usrclass_amcache_bcd() {
    assert_eq!(HiveKind::from_file_name("UsrClass.dat"), HiveKind::UsrClass);
    assert_eq!(HiveKind::from_file_name("Amcache.hve"), HiveKind::Amcache);
    assert_eq!(HiveKind::from_file_name("BCD"), HiveKind::Bcd);
    assert_eq!(HiveKind::from_file_name("COMPONENTS"), HiveKind::Components);
    assert_eq!(HiveKind::from_file_name("DRIVERS"), HiveKind::Drivers);
}
#[test]
fn name_image_dump_user_prefix() {
    // src/ingest/image.rs writes Users\<user>_NTUSER.DAT
    assert_eq!(HiveKind::from_file_name("bob_NTUSER.DAT"), HiveKind::NtUser);
    assert_eq!(HiveKind::from_file_name("Administrator_ntuser.dat"), HiveKind::NtUser);
}
#[test]
fn name_dash_prefix() {
    assert_eq!(HiveKind::from_file_name("HOST01-SYSTEM"), HiveKind::System);
    assert_eq!(HiveKind::from_file_name("alice-NTUSER.DAT"), HiveKind::NtUser);
}
#[test]
fn name_flattened_collector_path() {
    assert_eq!(HiveKind::from_file_name("C_Windows_System32_config_SOFTWARE"), HiveKind::Software);
    assert_eq!(HiveKind::from_file_name("C_Windows_System32_config_SYSTEM"), HiveKind::System);
    assert_eq!(HiveKind::from_file_name("C_Users_bob_NTUSER.DAT"), HiveKind::NtUser);
}
#[test]
fn name_copy_suffixes() {
    assert_eq!(HiveKind::from_file_name("SOFTWARE.hve"), HiveKind::Software);
    assert_eq!(HiveKind::from_file_name("SYSTEM.bak"), HiveKind::System);
    assert_eq!(HiveKind::from_file_name("system.hiv"), HiveKind::System);
    assert_eq!(HiveKind::from_file_name("SOFTWARE.hve.bak"), HiveKind::Software);
}
#[test]
fn name_dot_prefix() {
    assert_eq!(HiveKind::from_file_name("host.SYSTEM"), HiveKind::System);
}
#[test]
fn name_ntuser_man_mandatory_profile() {
    assert_eq!(HiveKind::from_file_name("NTUSER.MAN"), HiveKind::NtUser);
    assert_eq!(HiveKind::from_file_name("bob_NTUSER.MAN"), HiveKind::NtUser);
}
#[test]
fn name_unknown_for_random_files() {
    assert_eq!(HiveKind::from_file_name("evidence.bin"), HiveKind::Unknown);
    assert_eq!(HiveKind::from_file_name("hive"), HiveKind::Unknown);
    assert_eq!(HiveKind::from_file_name(""), HiveKind::Unknown);
    assert_eq!(HiveKind::from_file_name("   "), HiveKind::Unknown);
}
#[test]
fn name_companions_are_not_hives() {
    assert_eq!(HiveKind::from_file_name("SYSTEM.LOG1"), HiveKind::Unknown);
    assert_eq!(HiveKind::from_file_name("SOFTWARE.LOG2"), HiveKind::Unknown);
    assert_eq!(HiveKind::from_file_name("NTUSER.DAT{016888bd-6c6f-11de-8d1d-001e0bcde3ec}.TM.blf"), HiveKind::Unknown);
}
#[test]
fn name_does_not_confuse_substrings() {
    assert_eq!(HiveKind::from_file_name("MYSYSTEMNOTES.TXT"), HiveKind::Unknown);
    assert_eq!(HiveKind::from_file_name("samba.conf"), HiveKind::Unknown);
    assert_eq!(HiveKind::from_file_name("softwarelist.csv"), HiveKind::Unknown);
}
#[test]
fn name_trims_whitespace() {
    assert_eq!(HiveKind::from_file_name("  SYSTEM  "), HiveKind::System);
}

// ─── from_embedded_name ──────────────────────────────────────────────────────

#[test]
fn embedded_software_tail() {
    assert_eq!(HiveKind::from_embedded_name(r"emRoot\System32\Config\SOFTWARE"), HiveKind::Software);
}
#[test]
fn embedded_system_tail() {
    assert_eq!(HiveKind::from_embedded_name(r"emRoot\System32\Config\SYSTEM"), HiveKind::System);
}
#[test]
fn embedded_ntuser_full_path() {
    assert_eq!(HiveKind::from_embedded_name(r"\??\C:\Users\bob\ntuser.dat"), HiveKind::NtUser);
}
#[test]
fn embedded_ntuser_truncated_tail() {
    assert_eq!(HiveKind::from_embedded_name(r"ers\averylongusername\ntuser.dat"), HiveKind::NtUser);
}
#[test]
fn embedded_usrclass() {
    assert_eq!(HiveKind::from_embedded_name(r"Local\Microsoft\Windows\UsrClass.dat"), HiveKind::UsrClass);
}
#[test]
fn embedded_default_sam_security() {
    assert_eq!(HiveKind::from_embedded_name(r"emRoot\System32\Config\DEFAULT"), HiveKind::Default);
    assert_eq!(HiveKind::from_embedded_name(r"temRoot\System32\Config\SAM"), HiveKind::Sam);
    assert_eq!(HiveKind::from_embedded_name(r"emRoot\System32\Config\SECURITY"), HiveKind::Security);
}
#[test]
fn embedded_amcache_bcd() {
    assert_eq!(HiveKind::from_embedded_name(r"AppCompat\Programs\Amcache.hve"), HiveKind::Amcache);
    assert_eq!(HiveKind::from_embedded_name(r"\Device\HarddiskVolume1\Boot\BCD"), HiveKind::Bcd);
}
#[test]
fn embedded_forward_slashes_and_nuls() {
    assert_eq!(HiveKind::from_embedded_name("Config/SOFTWARE\0\0"), HiveKind::Software);
}
#[test]
fn embedded_unknown() {
    assert_eq!(HiveKind::from_embedded_name(r"ers\user\Desktop\1\NewDirtyHive"), HiveKind::Unknown);
    assert_eq!(HiveKind::from_embedded_name(""), HiveKind::Unknown);
    assert_eq!(HiveKind::from_embedded_name("\0\0\0"), HiveKind::Unknown);
}
#[test]
fn embedded_case_insensitive() {
    assert_eq!(HiveKind::from_embedded_name(r"config\software"), HiveKind::Software);
}

// ─── kind properties ─────────────────────────────────────────────────────────

#[test]
fn user_profile_kinds() {
    assert!(HiveKind::NtUser.is_user_profile());
    assert!(HiveKind::Default.is_user_profile());
    assert!(!HiveKind::UsrClass.is_user_profile());
    assert!(!HiveKind::Software.is_user_profile());
    assert!(!HiveKind::Unknown.is_user_profile());
}
#[test]
fn persistence_relevant_kinds() {
    for k in [HiveKind::System, HiveKind::Software, HiveKind::Default, HiveKind::NtUser, HiveKind::UsrClass, HiveKind::Unknown] {
        assert!(k.is_persistence_relevant(), "{k}");
    }
    for k in [HiveKind::Sam, HiveKind::Security, HiveKind::Amcache, HiveKind::Bcd, HiveKind::Components, HiveKind::Drivers] {
        assert!(!k.is_persistence_relevant(), "{k}");
    }
}
#[test]
fn canonical_names_and_labels() {
    assert_eq!(HiveKind::NtUser.canonical_file_name(), Some("NTUSER.DAT"));
    assert_eq!(HiveKind::Unknown.canonical_file_name(), None);
    assert_eq!(HiveKind::Unknown.label(), "UNKNOWN");
    assert_eq!(HiveKind::System.to_string(), "SYSTEM");
    assert_eq!(HiveKind::ALL.len(), 12);
}
#[test]
fn every_canonical_name_round_trips_through_from_file_name() {
    for k in HiveKind::ALL {
        if let Some(name) = k.canonical_file_name() {
            assert_eq!(HiveKind::from_file_name(name), k);
            assert_eq!(HiveKind::from_file_name(&format!("HOST_{name}")), k);
            assert_eq!(HiveKind::from_file_name(&name.to_lowercase()), k);
        }
    }
}

// ─── companion files ─────────────────────────────────────────────────────────

#[test]
fn companion_log_files() {
    assert!(is_hive_companion_file("SYSTEM.LOG1"));
    assert!(is_hive_companion_file("software.log2"));
    assert!(is_hive_companion_file("SYSTEM.LOG"));
}
#[test]
fn companion_txr_files() {
    assert!(is_hive_companion_file("NTUSER.DAT{016888bd-6c6f-11de-8d1d-001e0bcde3ec}.TM.blf"));
    assert!(is_hive_companion_file("NTUSER.DAT{016888bd-6c6f-11de-8d1d-001e0bcde3ec}.TMContainer00000000000000000001.regtrans-ms"));
    assert!(is_hive_companion_file("UsrClass.dat{guid}.TM"));
}
#[test]
fn companion_tmp_sav() {
    assert!(is_hive_companion_file("SOFTWARE.TMP"));
    assert!(is_hive_companion_file("SYSTEM.sav"));
}
#[test]
fn companion_negative() {
    assert!(!is_hive_companion_file("SYSTEM"));
    assert!(!is_hive_companion_file("NTUSER.DAT"));
    assert!(!is_hive_companion_file("SOFTWARE.hve"));
    assert!(!is_hive_companion_file("bob_NTUSER.DAT"));
}
#[test]
fn companion_base_kind_resolution() {
    assert_eq!(companion_base_kind("SYSTEM.LOG1"), HiveKind::System);
    assert_eq!(companion_base_kind("bob_NTUSER.DAT.LOG2"), HiveKind::NtUser);
    assert_eq!(companion_base_kind("NTUSER.DAT{guid}.TM.blf"), HiveKind::NtUser);
    assert_eq!(companion_base_kind("auth.log"), HiveKind::Unknown);
    assert_eq!(companion_base_kind("random.tmp"), HiveKind::Unknown);
}

// ─── header parsing ──────────────────────────────────────────────────────────

#[test]
fn header_parse_rejects_short_buffer() {
    let e = HiveHeader::parse(b"reg", "x").unwrap_err();
    assert_eq!(e.code(), "ERR_WIN_HIVE_TRUNCATED");
}
#[test]
fn header_parse_rejects_bad_magic() {
    let e = HiveHeader::parse(&[0u8; 4096], "x").unwrap_err();
    assert_eq!(e.code(), "ERR_WIN_HIVE_SIGNATURE");
}
#[test]
fn header_parse_rejects_regf_but_under_512() {
    let mut b = vec![0u8; 100];
    b[..4].copy_from_slice(b"regf");
    let e = HiveHeader::parse(&b, "x").unwrap_err();
    assert_eq!(e.code(), "ERR_WIN_HIVE_TRUNCATED");
}
#[test]
fn header_parse_reads_every_field() {
    let b = base_block(7, 6, 0x20, 8192, r"emRoot\System32\Config\SYSTEM", 0, 5);
    let h = HiveHeader::parse(&b, "x").unwrap();
    assert_eq!(h.primary_sequence, 7);
    assert_eq!(h.secondary_sequence, 6);
    assert!(h.is_dirty());
    assert_eq!(h.major_version, 1);
    assert_eq!(h.minor_version, 5);
    assert_eq!(h.version(), "1.5");
    assert!(h.is_supported_version());
    assert_eq!(h.file_type, 0);
    assert!(h.is_primary());
    assert!(!h.is_transaction_log());
    assert_eq!(h.root_cell_offset, 0x20);
    assert_eq!(h.data_size, 8192);
    assert_eq!(h.embedded_name, r"emRoot\System32\Config\SYSTEM");
    assert_eq!(h.kind(), HiveKind::System);
    assert!(h.checksum_valid());
    assert_eq!(h.timestamp_filetime, FILETIME_2024);
}
#[test]
fn header_checksum_detects_corruption() {
    let mut b = base_block(1, 1, 0x20, 4096, "x", 0, 5);
    b[0x40] ^= 0xff;
    let h = HiveHeader::parse(&b, "x").unwrap();
    assert!(!h.checksum_valid());
}
#[test]
fn header_checksum_corner_cases() {
    let zeros = [0u8; 512];
    assert_eq!(compute_base_block_checksum(&zeros), 1);
    let mut ones = [0u8; 512];
    ones[0..4].copy_from_slice(&0xffff_ffffu32.to_le_bytes());
    assert_eq!(compute_base_block_checksum(&ones), 0xffff_fffe);
}
#[test]
fn header_file_types() {
    for (ft, legacy, new, primary) in [(0u32, false, false, true), (1, true, false, false), (2, true, false, false), (6, false, true, false), (9, false, false, false)] {
        let b = base_block(1, 1, 0x20, 4096, "x", ft, 5);
        let h = HiveHeader::parse(&b, "x").unwrap();
        assert_eq!(h.is_legacy_log(), legacy, "ft={ft}");
        assert_eq!(h.is_new_log(), new, "ft={ft}");
        assert_eq!(h.is_primary(), primary, "ft={ft}");
    }
}
#[test]
fn header_unsupported_version() {
    let b = base_block(1, 1, 0x20, 4096, "x", 0, 9);
    let h = HiveHeader::parse(&b, "x").unwrap();
    assert!(!h.is_supported_version());
}
#[test]
fn embedded_name_is_truncated_to_last_32_chars() {
    let long = r"\??\C:\Users\averyveryverylongusername\ntuser.dat";
    let b = base_block(1, 1, 0x20, 4096, long, 0, 5);
    let decoded = decode_embedded_name(&b);
    assert_eq!(decoded.encode_utf16().count(), 32);
    assert!(decoded.ends_with("ntuser.dat"));
    assert_eq!(HiveKind::from_embedded_name(&decoded), HiveKind::NtUser);
}
#[test]
fn decode_embedded_name_short_buffer() {
    assert_eq!(decode_embedded_name(&[0u8; 10]), "");
}

// ─── read_hive_header on disk ────────────────────────────────────────────────

#[test]
fn read_header_missing_file() {
    let e = read_hive_header(std::path::Path::new("Z:/definitely/missing/SYSTEM")).unwrap_err();
    assert_eq!(e.code(), "ERR_WIN_HIVE_OPEN");
}
#[test]
fn read_header_empty_file() {
    let d = TempDir::new("hdr_empty");
    let p = d.write("SYSTEM", b"");
    assert_eq!(read_hive_header(&p).unwrap_err().code(), "ERR_WIN_HIVE_EMPTY");
}
#[test]
fn read_header_not_regf() {
    let d = TempDir::new("hdr_text");
    let p = d.write("SYSTEM", b"this is not a hive at all, just text that is long enough");
    assert_eq!(read_hive_header(&p).unwrap_err().code(), "ERR_WIN_HIVE_SIGNATURE");
}
#[test]
fn read_header_primary_shorter_than_base_block() {
    let d = TempDir::new("hdr_short");
    let b = base_block(1, 1, 0x20, 4096, "x", 0, 5);
    let p = d.write("SYSTEM", &b[..2048]);
    assert_eq!(read_hive_header(&p).unwrap_err().code(), "ERR_WIN_HIVE_TRUNCATED");
}
#[test]
fn read_header_log_only_needs_512_bytes() {
    let d = TempDir::new("hdr_log");
    let b = base_block(1, 1, 0x20, 4096, "x", 6, 5);
    let p = d.write("SYSTEM.LOG1", &b[..512]);
    let h = read_hive_header(&p).unwrap();
    assert!(h.is_new_log());
}

// ─── classify_hive ───────────────────────────────────────────────────────────

#[test]
fn classify_header_and_name_agree() {
    diag::clear();
    let d = TempDir::new("cls_agree");
    let p = HiveBuilder::software().write(&d.join("SOFTWARE"));
    let info = classify_hive(&p, &d.path).unwrap();
    assert_eq!(info.kind, HiveKind::Software);
    assert_eq!(info.name_kind, HiveKind::Software);
    assert!(!diag::has("ERR_WIN_HIVE_NAME_HEADER_MISMATCH"));
    assert_eq!(info.file_name(), "SOFTWARE");
    assert!(!info.is_dirty());
    assert!(info.label().contains("SOFTWARE"));
}
#[test]
fn classify_header_wins_over_misleading_name() {
    diag::clear();
    let d = TempDir::new("cls_mismatch");
    let p = HiveBuilder::software().write(&d.join("SYSTEM"));
    let info = classify_hive(&p, &d.path).unwrap();
    assert_eq!(info.kind, HiveKind::Software);
    assert_eq!(info.name_kind, HiveKind::System);
    assert!(diag::has("ERR_WIN_HIVE_NAME_HEADER_MISMATCH"));
}
#[test]
fn classify_header_resolves_random_file_name() {
    diag::clear();
    let d = TempDir::new("cls_random");
    let p = HiveBuilder::ntuser("bob").write(&d.join("evidence_0001.bin"));
    let info = classify_hive(&p, &d.path).unwrap();
    assert_eq!(info.kind, HiveKind::NtUser);
    assert_eq!(info.name_kind, HiveKind::Unknown);
    assert!(!diag::has("ERR_WIN_HIVE_KIND_UNRESOLVED"));
}
#[test]
fn classify_name_used_when_header_is_blank() {
    diag::clear();
    let d = TempDir::new("cls_blank");
    let p = HiveBuilder::anonymous().write(&d.join("SYSTEM"));
    let info = classify_hive(&p, &d.path).unwrap();
    assert_eq!(info.kind, HiveKind::System);
}
#[test]
fn classify_unknown_when_nothing_helps() {
    diag::clear();
    let d = TempDir::new("cls_unknown");
    let p = HiveBuilder::anonymous().write(&d.join("blob.bin"));
    let info = classify_hive(&p, &d.path).unwrap();
    assert_eq!(info.kind, HiveKind::Unknown);
    assert!(diag::has("ERR_WIN_HIVE_KIND_UNRESOLVED"));
}
#[test]
fn classify_rejects_transaction_log_named_like_hive() {
    diag::clear();
    let d = TempDir::new("cls_log");
    let mut b = HiveBuilder::software().build();
    patch_base_block(&mut b, 1, 1, 6);
    let p = d.write("SOFTWARE", &b);
    let e = classify_hive(&p, &d.path).unwrap_err();
    assert_eq!(e.code(), "ERR_WIN_HIVE_NOT_PRIMARY");
    assert!(diag::has("ERR_WIN_HIVE_NOT_PRIMARY"));
}
#[test]
fn classify_rejects_unsupported_version() {
    diag::clear();
    let d = TempDir::new("cls_ver");
    let mut b = HiveBuilder::software();
    b.minor_version = 9;
    let p = b.write(&d.join("SOFTWARE"));
    assert_eq!(classify_hive(&p, &d.path).unwrap_err().code(), "ERR_WIN_HIVE_CORRUPT");
}
#[test]
fn classify_records_signature_error() {
    diag::clear();
    let d = TempDir::new("cls_sig");
    let p = d.write("SOFTWARE", &[0u8; 8192]);
    assert_eq!(classify_hive(&p, &d.path).unwrap_err().code(), "ERR_WIN_HIVE_SIGNATURE");
    assert!(diag::has("ERR_WIN_HIVE_SIGNATURE"));
}
#[test]
fn classify_keeps_dirty_flag() {
    let d = TempDir::new("cls_dirty");
    let p = HiveBuilder::software().write_with(&d.join("SOFTWARE"), 8, 7);
    let info = classify_hive(&p, &d.path).unwrap();
    assert!(info.is_dirty());
    assert_eq!(info.evidence_root, d.path);
}
