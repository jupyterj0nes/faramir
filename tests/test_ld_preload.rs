mod common;
use faramir::parsers::linux::ld_preload::*;
use std::fs::File;
use std::io::Write;

fn create_temp_preload(content: &str) -> (std::path::PathBuf, tempfile_guard::FileGuard) {
    let path = std::env::temp_dir().join(format!("ld_so_preload_{}_{}", std::process::id(), common::unique_suffix()));
    {
        let mut f = File::create(&path).unwrap();
        f.write_all(content.as_bytes()).unwrap();
    }
    let guard = tempfile_guard::FileGuard(path.clone());
    (path, guard)
}

mod tempfile_guard {
    pub struct FileGuard(pub std::path::PathBuf);
    impl Drop for FileGuard {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }
}

#[test]
fn test_ld_preload_valid_single() {
    let (p, _g) = create_temp_preload("/usr/local/lib/libhook.so\n");
    let evs = parse_ld_so_preload(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 1);
    assert_eq!(evs[0].processname, "libhook.so");
    assert_eq!(evs[0].artifact, "linux:rootkit:ld_so_preload");
    assert_eq!(evs[0].subject_username, "root");
}

#[test]
fn test_ld_preload_valid_multiple_lines() {
    let (p, _g) = create_temp_preload("/lib/x86_64-linux-gnu/libevil1.so\n/opt/lib/libevil2.so\n");
    let evs = parse_ld_so_preload(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 2);
    assert_eq!(evs[0].processname, "libevil1.so");
    assert_eq!(evs[1].processname, "libevil2.so");
}

#[test]
fn test_ld_preload_valid_space_separated() {
    let (p, _g) = create_temp_preload("/lib/liba.so /lib/libb.so /lib/libc.so\n");
    let evs = parse_ld_so_preload(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 3);
}

#[test]
fn test_ld_preload_with_comments() {
    let (p, _g) = create_temp_preload("# Custom preloads\n/lib/libhook.so\n# End\n");
    let evs = parse_ld_so_preload(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 1);
}

#[test]
fn test_ld_preload_relative_path_err() {
    let (p, _g) = create_temp_preload("libevil.so\n");
    let err = parse_ld_so_preload(&p, "HOST").unwrap_err();
    assert_eq!(err.code(), "ERR_LNX_LDPRELOAD_INVALID");
    assert_eq!(err.error_number(), 5001);
}

#[test]
fn test_ld_preload_relative_dot_slash_err() {
    let (p, _g) = create_temp_preload("./libevil.so\n");
    let err = parse_ld_so_preload(&p, "HOST").unwrap_err();
    assert_eq!(err.code(), "ERR_LNX_LDPRELOAD_INVALID");
}

#[test]
fn test_ld_preload_empty_file_err() {
    let (p, _g) = create_temp_preload("");
    let err = parse_ld_so_preload(&p, "HOST").unwrap_err();
    assert_eq!(err.code(), "ERR_LNX_LDPRELOAD_EMPTY");
    assert_eq!(err.error_number(), 5002);
}

#[test]
fn test_ld_preload_comments_only_err() {
    let (p, _g) = create_temp_preload("# only comments\n# nothing else\n");
    let err = parse_ld_so_preload(&p, "HOST").unwrap_err();
    assert_eq!(err.code(), "ERR_LNX_LDPRELOAD_EMPTY");
}

#[test]
fn test_ld_preload_whitespace_only_err() {
    let (p, _g) = create_temp_preload("   \n\t   \n");
    let err = parse_ld_so_preload(&p, "HOST").unwrap_err();
    assert_eq!(err.code(), "ERR_LNX_LDPRELOAD_EMPTY");
}

#[test]
fn test_ld_preload_not_found_err() {
    let p = std::path::PathBuf::from("/non/existent/ld.so.preload");
    let err = parse_ld_so_preload(&p, "HOST").unwrap_err();
    assert_eq!(err.code(), "ERR_LNX_IO_NOT_FOUND");
}

#[test]
fn test_ld_preload_commandline_format() {
    let (p, _g) = create_temp_preload("/tmp/hook.so\n");
    let evs = parse_ld_so_preload(&p, "HOST").unwrap();
    assert!(evs[0].commandline.as_ref().unwrap().contains("Preloaded Dynamic Library: /tmp/hook.so"));
}

#[test]
fn test_ld_preload_parentprocess_is_ld_so() {
    let (p, _g) = create_temp_preload("/tmp/hook.so\n");
    let evs = parse_ld_so_preload(&p, "HOST").unwrap();
    assert_eq!(evs[0].parentprocessname, "ld.so");
}

#[test]
fn test_ld_preload_root_subject() {
    let (p, _g) = create_temp_preload("/usr/lib/rootkit.so\n");
    let evs = parse_ld_so_preload(&p, "HOST").unwrap();
    assert_eq!(evs[0].subject_username, "root");
}

#[test]
fn test_ld_preload_multiple_with_trailing_empty_lines() {
    let (p, _g) = create_temp_preload("/lib/a.so\n\n\n");
    let evs = parse_ld_so_preload(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 1);
}

#[test]
fn test_ld_preload_mixed_valid_and_invalid_fails() {
    let (p, _g) = create_temp_preload("/lib/valid.so\ninvalid.so\n");
    let err = parse_ld_so_preload(&p, "HOST").unwrap_err();
    assert_eq!(err.code(), "ERR_LNX_LDPRELOAD_INVALID");
}

#[test]
fn test_ld_preload_deep_path() {
    let (p, _g) = create_temp_preload("/opt/app/plugins/security/sub/mod.so\n");
    let evs = parse_ld_so_preload(&p, "HOST").unwrap();
    assert_eq!(evs[0].processname, "mod.so");
}

#[test]
fn test_ld_preload_dev_shm_path() {
    let (p, _g) = create_temp_preload("/dev/shm/.rk.so\n");
    let evs = parse_ld_so_preload(&p, "HOST").unwrap();
    assert_eq!(evs[0].processname, ".rk.so");
}

#[test]
fn test_ld_preload_tabs_separated() {
    let (p, _g) = create_temp_preload("/lib/one.so\t/lib/two.so\n");
    let evs = parse_ld_so_preload(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 2);
}

#[test]
fn test_ld_preload_trailing_spaces_on_path() {
    let (p, _g) = create_temp_preload("  /lib/trimmed.so   \n");
    let evs = parse_ld_so_preload(&p, "HOST").unwrap();
    assert_eq!(evs[0].processname, "trimmed.so");
}

#[test]
fn test_ld_preload_computer_name_propagated() {
    let (p, _g) = create_temp_preload("/lib/hook.so\n");
    let evs = parse_ld_so_preload(&p, "TARGET_HOST_01").unwrap();
    assert_eq!(evs[0].computer, "TARGET_HOST_01");
}

#[test]
fn test_ld_preload_event_id_zero() {
    let (p, _g) = create_temp_preload("/lib/hook.so\n");
    let evs = parse_ld_so_preload(&p, "HOST").unwrap();
    assert_eq!(evs[0].event_id, 0);
}

#[test]
fn test_ld_preload_pid_zero() {
    let (p, _g) = create_temp_preload("/lib/hook.so\n");
    let evs = parse_ld_so_preload(&p, "HOST").unwrap();
    assert_eq!(evs[0].pid, 0);
}

#[test]
fn test_ld_preload_multiple_commas_in_path() {
    let (p, _g) = create_temp_preload("/lib/lib,name,with,commas.so\n");
    let evs = parse_ld_so_preload(&p, "HOST").unwrap();
    assert_eq!(evs[0].processname, "lib,name,with,commas.so");
}

#[test]
fn test_ld_preload_four_libraries() {
    let (p, _g) = create_temp_preload("/lib/1.so /lib/2.so /lib/3.so /lib/4.so\n");
    let evs = parse_ld_so_preload(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 4);
}

#[test]
fn test_ld_preload_five_libraries() {
    let (p, _g) = create_temp_preload("/lib/1.so\n/lib/2.so\n/lib/3.so\n/lib/4.so\n/lib/5.so\n");
    let evs = parse_ld_so_preload(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 5);
}
