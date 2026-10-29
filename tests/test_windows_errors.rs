//! Error-code contract for the Windows hive / transaction-log subsystem.
use faramir::errors::{FaramirError, Severity};
use std::collections::HashSet;

fn check(err: FaramirError, code: &str, number: u32, severity: Severity) {
    assert_eq!(err.code(), code);
    assert_eq!(err.error_number(), number);
    assert_eq!(err.severity(), severity);
    let text = err.to_string();
    assert!(text.contains(code), "{text}");
    assert!(text.contains(&number.to_string()), "{text}");
    assert!(text.contains("detail-marker"), "display must include the detail: {text}");
    assert_eq!(err.detail(), "detail-marker");
    assert_eq!(err.category(), "WIN");
}

#[test]
fn err_hive_signature_invalid() {
    check(FaramirError::HiveSignatureInvalid("detail-marker".into()), "ERR_WIN_HIVE_SIGNATURE", 3019, Severity::Error);
}
#[test]
fn err_hive_header_truncated() {
    check(FaramirError::HiveHeaderTruncated("detail-marker".into()), "ERR_WIN_HIVE_TRUNCATED", 3020, Severity::Error);
}
#[test]
fn err_hive_checksum_invalid() {
    check(FaramirError::HiveChecksumInvalid("detail-marker".into()), "ERR_WIN_HIVE_CHECKSUM", 3021, Severity::Warning);
}
#[test]
fn err_hive_kind_unresolved() {
    check(FaramirError::HiveKindUnresolved("detail-marker".into()), "ERR_WIN_HIVE_KIND_UNRESOLVED", 3022, Severity::Warning);
}
#[test]
fn err_hive_name_header_mismatch() {
    check(FaramirError::HiveNameHeaderMismatch("detail-marker".into()), "ERR_WIN_HIVE_NAME_HEADER_MISMATCH", 3023, Severity::Warning);
}
#[test]
fn err_hive_parse_panic() {
    check(FaramirError::HiveParsePanic("detail-marker".into()), "ERR_WIN_HIVE_PARSE_PANIC", 3024, Severity::Error);
}
#[test]
fn err_hive_companion_skipped() {
    check(FaramirError::HiveCompanionSkipped("detail-marker".into()), "ERR_WIN_HIVE_COMPANION_SKIPPED", 3025, Severity::Info);
}
#[test]
fn err_hive_duplicate_skipped() {
    check(FaramirError::HiveDuplicateSkipped("detail-marker".into()), "ERR_WIN_HIVE_DUPLICATE", 3026, Severity::Info);
}
#[test]
fn err_hive_not_primary() {
    check(FaramirError::HiveNotPrimaryFile("detail-marker".into()), "ERR_WIN_HIVE_NOT_PRIMARY", 3027, Severity::Error);
}
#[test]
fn err_txlog_not_found() {
    check(FaramirError::TxLogNotFound("detail-marker".into()), "ERR_WIN_TX_LOG_NOT_FOUND", 3028, Severity::Warning);
}
#[test]
fn err_txlog_open_failed() {
    check(FaramirError::TxLogOpenFailed("detail-marker".into()), "ERR_WIN_TX_LOG_OPEN", 3029, Severity::Error);
}
#[test]
fn err_txlog_signature_invalid() {
    check(FaramirError::TxLogSignatureInvalid("detail-marker".into()), "ERR_WIN_TX_LOG_SIGNATURE", 3030, Severity::Error);
}
#[test]
fn err_txlog_legacy_format() {
    check(FaramirError::TxLogLegacyFormat("detail-marker".into()), "ERR_WIN_TX_LOG_LEGACY", 3031, Severity::Warning);
}
#[test]
fn err_txlog_truncated() {
    check(FaramirError::TxLogTruncated("detail-marker".into()), "ERR_WIN_TX_LOG_TRUNCATED", 3032, Severity::Warning);
}
#[test]
fn err_txlog_entry_invalid() {
    check(FaramirError::TxLogEntryInvalid("detail-marker".into()), "ERR_WIN_TX_LOG_ENTRY_INVALID", 3033, Severity::Warning);
}
#[test]
fn err_txlog_no_entries() {
    check(FaramirError::TxLogNoEntries("detail-marker".into()), "ERR_WIN_TX_LOG_EMPTY", 3034, Severity::Warning);
}
#[test]
fn err_txlog_sequence_mismatch() {
    check(FaramirError::TxLogSequenceMismatch("detail-marker".into()), "ERR_WIN_TX_LOG_SEQUENCE", 3035, Severity::Warning);
}
#[test]
fn err_txlog_hive_mismatch() {
    // Rejecting another hive's log is routine in multi-user packages: informational only.
    check(FaramirError::TxLogHiveMismatch("detail-marker".into()), "ERR_WIN_TX_LOG_HIVE_MISMATCH", 3036, Severity::Info);
}
#[test]
fn err_txlog_apply_failed() {
    check(FaramirError::TxLogApplyFailed("detail-marker".into()), "ERR_WIN_TX_LOG_APPLY", 3037, Severity::Warning);
}
#[test]
fn err_txlog_apply_panic() {
    check(FaramirError::TxLogApplyPanic("detail-marker".into()), "ERR_WIN_TX_LOG_APPLY_PANIC", 3038, Severity::Warning);
}
#[test]
fn err_txlog_ambiguous() {
    check(FaramirError::TxLogAmbiguous("detail-marker".into()), "ERR_WIN_TX_LOG_AMBIGUOUS", 3039, Severity::Warning);
}
#[test]
fn err_txlog_partially_applied() {
    check(FaramirError::TxLogPartiallyApplied("detail-marker".into()), "ERR_WIN_TX_LOG_PARTIAL", 3040, Severity::Warning);
}
#[test]
fn err_control_set_not_found() {
    check(FaramirError::ControlSetNotFound("detail-marker".into()), "ERR_WIN_CONTROL_SET_MISSING", 3041, Severity::Warning);
}
#[test]
fn err_technique_no_applicable_hive() {
    // Coverage information for partial collections (e.g. only NTUSER.DAT): not a fault.
    check(FaramirError::TechniqueNoApplicableHive("detail-marker".into()), "ERR_WIN_TECH_NO_HIVE", 3042, Severity::Info);
}
#[test]
fn err_technique_panicked() {
    check(FaramirError::TechniquePanicked("detail-marker".into()), "ERR_WIN_TECH_PANIC", 3043, Severity::Warning);
}
#[test]
fn err_hive_discovery_io() {
    check(FaramirError::HiveDiscoveryIoError("detail-marker".into()), "ERR_WIN_HIVE_DISCOVERY_IO", 3044, Severity::Warning);
}
#[test]
fn err_value_empty() {
    check(FaramirError::ValueEmpty("detail-marker".into()), "ERR_WIN_VALUE_EMPTY", 3045, Severity::Warning);
}
#[test]
fn err_hive_empty_file() {
    check(FaramirError::HiveEmptyFile("detail-marker".into()), "ERR_WIN_HIVE_EMPTY", 3046, Severity::Error);
}
#[test]
fn err_txlog_remote_match() {
    check(FaramirError::TxLogRemoteMatch("detail-marker".into()), "ERR_WIN_TX_LOG_REMOTE_MATCH", 3047, Severity::Info);
}
#[test]
fn err_hive_recovered() {
    check(FaramirError::HiveRecovered("detail-marker".into()), "ERR_WIN_HIVE_RECOVERED", 3048, Severity::Info);
}

// ─── Catalogue-wide invariants ───────────────────────────────────────────────

#[test]
fn catalog_numbers_are_unique() {
    let cat = FaramirError::catalog();
    let nums: HashSet<u32> = cat.iter().map(|e| e.error_number()).collect();
    assert_eq!(nums.len(), cat.len(), "duplicate error numbers");
}

#[test]
fn catalog_codes_are_unique() {
    let cat = FaramirError::catalog();
    let codes: HashSet<&str> = cat.iter().map(|e| e.code()).collect();
    assert_eq!(codes.len(), cat.len(), "duplicate error codes");
}

#[test]
fn catalog_has_at_least_ninety_codes() {
    assert!(FaramirError::catalog().len() >= 90, "{}", FaramirError::catalog().len());
}

#[test]
fn catalog_codes_follow_prefix_convention() {
    for e in FaramirError::catalog() {
        let expected_prefix = format!("ERR_{}_", e.category());
        assert!(e.code().starts_with(&expected_prefix), "{} should start with {expected_prefix}", e.code());
        assert!(e.code().chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_'), "{}", e.code());
    }
}

#[test]
fn catalog_numbers_match_category_ranges() {
    for e in FaramirError::catalog() {
        let n = e.error_number();
        let range_ok = match e.category() {
            "SYS" => (1000..2000).contains(&n),
            "ING" => (2000..3000).contains(&n),
            "WIN" => (3000..4000).contains(&n),
            "LNX" => (4000..5000).contains(&n),
            "OUT" => (5000..6000).contains(&n),
            "CLI" => (6000..7000).contains(&n),
            other => panic!("unknown category {other}"),
        };
        assert!(range_ok, "{} has number {n} outside its range", e.code());
    }
}

#[test]
fn catalog_display_always_contains_code_and_number() {
    for e in FaramirError::catalog() {
        let s = e.to_string();
        assert!(s.starts_with(&format!("[{} - {}] ", e.code(), e.error_number())), "{s}");
    }
}

#[test]
fn catalog_windows_range_is_dense() {
    let mut nums: Vec<u32> = FaramirError::catalog()
        .iter()
        .map(|e| e.error_number())
        .filter(|n| (3000..4000).contains(n))
        .collect();
    nums.sort_unstable();
    assert_eq!(nums.first(), Some(&3001));
    for w in nums.windows(2) {
        assert_eq!(w[1], w[0] + 1, "gap between {} and {}", w[0], w[1]);
    }
    assert_eq!(*nums.last().unwrap(), 3049);
}

#[test]
fn severity_labels() {
    assert_eq!(Severity::Error.label(), "ERROR");
    assert_eq!(Severity::Warning.label(), "WARN");
    assert_eq!(Severity::Info.label(), "INFO");
}

#[test]
fn legacy_codes_default_to_error_severity() {
    assert_eq!(FaramirError::HiveOpenFailed(String::new()).severity(), Severity::Error);
    assert_eq!(FaramirError::ImageOpenFailed(String::new()).severity(), Severity::Error);
    assert_eq!(FaramirError::CronSyntax(String::new()).severity(), Severity::Error);
}

#[test]
fn dirty_without_logs_is_a_warning_not_an_error() {
    assert_eq!(FaramirError::HiveDirtyNoLogs(String::new()).severity(), Severity::Warning);
    assert_eq!(FaramirError::TxLogReplayFailed(String::new()).severity(), Severity::Warning);
}

#[test]
fn categories_by_number() {
    assert_eq!(FaramirError::IoError(String::new()).category(), "SYS");
    assert_eq!(FaramirError::ArchiveCorrupt(String::new()).category(), "ING");
    assert_eq!(FaramirError::TxLogNotFound(String::new()).category(), "WIN");
    assert_eq!(FaramirError::PamSyntax(String::new()).category(), "LNX");
    assert_eq!(FaramirError::OutCsvFlushFailed(String::new()).category(), "OUT");
    assert_eq!(FaramirError::CliNoTarget(String::new()).category(), "CLI");
}

#[test]
fn detail_round_trips_for_every_variant() {
    for e in FaramirError::catalog() {
        assert_eq!(e.detail(), "");
    }
    let e = FaramirError::TxLogTruncated("C:\\x.LOG1 entry #2".into());
    assert_eq!(e.detail(), "C:\\x.LOG1 entry #2");
}

#[test]
fn errors_are_cloneable_and_comparable() {
    let a = FaramirError::TxLogHiveMismatch("x".into());
    let b = a.clone();
    assert_eq!(a, b);
    assert_ne!(a, FaramirError::TxLogHiveMismatch("y".into()));
}
