//! Which archive entries get extracted: transaction logs must always come out,
//! Linux execution logs must not be shadowed by registry rules.
use faramir::ingest::archive::is_relevant_artifact;

#[test]
fn registry_log1_log2_are_extracted() {
    assert!(is_relevant_artifact("C/Windows/System32/config/SYSTEM.LOG1"));
    assert!(is_relevant_artifact("C/Windows/System32/config/SOFTWARE.LOG2"));
    assert!(is_relevant_artifact("C\\Windows\\System32\\config\\DEFAULT.LOG1"));
}

#[test]
fn user_hive_logs_are_extracted() {
    assert!(is_relevant_artifact("C/Users/bob/NTUSER.DAT.LOG1"));
    assert!(is_relevant_artifact("C/Users/bob/AppData/Local/Microsoft/Windows/UsrClass.dat.LOG2"));
}

#[test]
fn prefixed_and_flattened_logs_are_extracted() {
    assert!(is_relevant_artifact("Users/bob_NTUSER.DAT.LOG1"));
    assert!(is_relevant_artifact("output/C_Windows_System32_config_SOFTWARE.LOG2"));
}

#[test]
fn legacy_hive_log_is_extracted() {
    assert!(is_relevant_artifact("config/SYSTEM.LOG"));
    assert!(is_relevant_artifact("Users/bob/NTUSER.DAT.LOG"));
}

#[test]
fn unrelated_dot_log_is_not_extracted() {
    assert!(!is_relevant_artifact("ProgramData/app/random.log"));
    assert!(!is_relevant_artifact("Windows/Logs/CBS/CBS.log"));
}

#[test]
fn txr_companions_are_not_extracted() {
    assert!(!is_relevant_artifact("Users/bob/NTUSER.DAT{guid}.TM.blf"));
    assert!(!is_relevant_artifact("Users/bob/NTUSER.DAT{guid}.TMContainer00000000000000000001.regtrans-ms"));
    assert!(!is_relevant_artifact("config/SOFTWARE.sav"));
}

#[test]
fn every_primary_hive_is_extracted() {
    for name in ["SYSTEM", "SOFTWARE", "SAM", "SECURITY", "DEFAULT", "NTUSER.DAT", "UsrClass.dat", "Amcache.hve"] {
        assert!(is_relevant_artifact(&format!("C/x/{name}")), "{name}");
        assert!(is_relevant_artifact(&format!("C/x/HOST_{name}")), "HOST_{name}");
        assert!(is_relevant_artifact(&format!("C/x/host-{name}")), "host-{name}");
    }
}

#[test]
fn linux_audit_and_auth_logs_still_extracted() {
    assert!(is_relevant_artifact("[root]/var/log/audit/audit.log"));
    assert!(is_relevant_artifact("[root]/var/log/audit/audit.log.1"));
    assert!(is_relevant_artifact("var/log/auth.log"));
    assert!(is_relevant_artifact("var/log/auth.log.2"));
}

#[test]
fn linux_package_logs_still_extracted() {
    assert!(is_relevant_artifact("var/log/dpkg.log"));
    assert!(is_relevant_artifact("var/log/yum.log"));
    assert!(is_relevant_artifact("var/log/dpkg.log.1"));
}

#[test]
fn linux_web_access_logs_still_extracted() {
    assert!(is_relevant_artifact("var/log/apache2/access.log"));
    assert!(is_relevant_artifact("var/log/httpd/access_log"));
}

#[test]
fn linux_cron_and_secure_logs_still_extracted() {
    assert!(is_relevant_artifact("var/log/cron"));
    assert!(is_relevant_artifact("var/log/cron-20260101"));
    assert!(is_relevant_artifact("var/log/secure"));
}

#[test]
fn linux_persistence_files_still_extracted() {
    assert!(is_relevant_artifact("etc/systemd/system/evil.service"));
    assert!(is_relevant_artifact("etc/cron.d/evil"));
    assert!(is_relevant_artifact("etc/ld.so.preload"));
    assert!(is_relevant_artifact("root/.ssh/authorized_keys"));
}

#[test]
fn evtx_and_tasks_still_extracted() {
    assert!(is_relevant_artifact("C/Windows/System32/winevt/Logs/Security.evtx"));
    assert!(is_relevant_artifact("C/Windows/System32/Tasks/Microsoft/Windows/Evil"));
}

#[test]
fn vmware_noise_is_ignored() {
    assert!(!is_relevant_artifact("vmware-tools/modules/source/vmhgfs.tar"));
}

#[test]
fn nested_archives_and_markers_extracted() {
    assert!(is_relevant_artifact("output/collection.zip"));
    assert!(is_relevant_artifact("output/manifest.json"));
    assert!(is_relevant_artifact("_kape.cli"));
}

#[test]
fn case_insensitive_matching() {
    assert!(is_relevant_artifact("C/WINDOWS/SYSTEM32/CONFIG/SYSTEM.log1"));
    assert!(is_relevant_artifact("c/windows/system32/config/software"));
}
