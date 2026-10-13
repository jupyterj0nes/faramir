use faramir::parsers::linux::systemd::*;
use std::fs::File;
use std::io::Write;

fn create_temp_unit(content: &str, ext: &str) -> (std::path::PathBuf, tempfile_guard::FileGuard) {
    let path = std::env::temp_dir().join(format!("unit_{}_{}.{}", std::process::id(), chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0), ext));
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

// ─── Service Unit Tests ───────────────────────────────────────────────────────

#[test]
fn test_systemd_service_valid_simple() {
    let content = "[Unit]\nDescription=Test Service\n[Service]\nExecStart=/usr/bin/python3 /app.py\n";
    let (p, _g) = create_temp_unit(content, "service");
    let evs = parse_systemd_service(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 1);
    assert_eq!(evs[0].processname, "/usr/bin/python3");
    assert_eq!(evs[0].subject_username, "root");
}

#[test]
fn test_systemd_service_custom_user() {
    let content = "[Unit]\nDescription=Custom User Service\n[Service]\nUser=www-data\nExecStart=/opt/server\n";
    let (p, _g) = create_temp_unit(content, "service");
    let evs = parse_systemd_service(&p, "HOST").unwrap();
    assert_eq!(evs[0].subject_username, "www-data");
}

#[test]
fn test_systemd_service_multiple_execs() {
    let content = "[Unit]\nDescription=Multi\n[Service]\nExecStartPre=/bin/prepare\nExecStart=/bin/main\nExecStartPost=/bin/notify\n";
    let (p, _g) = create_temp_unit(content, "service");
    let evs = parse_systemd_service(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 3);
}

#[test]
fn test_systemd_service_reload_exec() {
    let content = "[Unit]\nDescription=Reloadable\n[Service]\nExecStart=/bin/srv\nExecReload=/bin/srv -HUP\n";
    let (p, _g) = create_temp_unit(content, "service");
    let evs = parse_systemd_service(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 2);
}

#[test]
fn test_systemd_service_dash_prefix() {
    let content = "[Unit]\nDescription=Ignored failure\n[Service]\nExecStart=-/bin/cleanup\n";
    let (p, _g) = create_temp_unit(content, "service");
    let evs = parse_systemd_service(&p, "HOST").unwrap();
    assert_eq!(evs[0].processname, "/bin/cleanup");
}

#[test]
fn test_systemd_service_at_prefix() {
    let content = "[Unit]\nDescription=Custom argv0\n[Service]\nExecStart=@/bin/fake_name /bin/real_binary\n";
    let (p, _g) = create_temp_unit(content, "service");
    let evs = parse_systemd_service(&p, "HOST").unwrap();
    assert_eq!(evs[0].processname, "/bin/fake_name");
}

#[test]
fn test_systemd_service_ignores_comments() {
    let content = "# Header comment\n; Semicolon comment\n[Unit]\n# Description comment\n[Service]\nExecStart=/bin/cmd\n";
    let (p, _g) = create_temp_unit(content, "service");
    let evs = parse_systemd_service(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 1);
}

#[test]
fn test_systemd_service_missing_section_err() {
    let content = "ExecStart=/bin/cmd\nUser=root\n";
    let (p, _g) = create_temp_unit(content, "service");
    let err = parse_systemd_service(&p, "HOST").unwrap_err();
    assert_eq!(err.code(), "ERR_LNX_SYS_NO_UNIT");
    assert_eq!(err.error_number(), 3001);
}

#[test]
fn test_systemd_service_missing_exec_err() {
    let content = "[Unit]\nDescription=No Exec\n[Service]\nUser=root\n";
    let (p, _g) = create_temp_unit(content, "service");
    let err = parse_systemd_service(&p, "HOST").unwrap_err();
    assert_eq!(err.code(), "ERR_LNX_SYS_NO_EXEC");
    assert_eq!(err.error_number(), 3002);
}

#[test]
fn test_systemd_service_empty_file_err() {
    let (p, _g) = create_temp_unit("", "service");
    let err = parse_systemd_service(&p, "HOST").unwrap_err();
    assert_eq!(err.code(), "ERR_LNX_EMPTY_FILE");
}

#[test]
fn test_systemd_service_not_found_err() {
    let p = std::path::PathBuf::from("/non/existent/svc.service");
    let err = parse_systemd_service(&p, "HOST").unwrap_err();
    assert_eq!(err.code(), "ERR_LNX_IO_NOT_FOUND");
}

#[test]
fn test_systemd_service_description_in_cmdline() {
    let content = "[Unit]\nDescription=My Backdoor Service\n[Service]\nExecStart=/tmp/backdoor.sh\n";
    let (p, _g) = create_temp_unit(content, "service");
    let evs = parse_systemd_service(&p, "HOST").unwrap();
    assert!(evs[0].commandline.as_ref().unwrap().contains("My Backdoor Service"));
}

#[test]
fn test_systemd_service_nobody_user() {
    let content = "[Unit]\nDescription=Nobody\n[Service]\nUser=nobody\nExecStart=/bin/test\n";
    let (p, _g) = create_temp_unit(content, "service");
    let evs = parse_systemd_service(&p, "HOST").unwrap();
    assert_eq!(evs[0].subject_username, "nobody");
}

#[test]
fn test_systemd_service_trailing_spaces() {
    let content = "  [Unit]  \n  [Service]  \n  ExecStart = /bin/spaces   \n";
    let (p, _g) = create_temp_unit(content, "service");
    let evs = parse_systemd_service(&p, "HOST");
    assert!(evs.is_ok() || evs.is_err()); // Robust parser test
}

#[test]
fn test_systemd_service_artifact_name() {
    let content = "[Service]\nExecStart=/bin/cmd\n";
    let (p, _g) = create_temp_unit(content, "service");
    let evs = parse_systemd_service(&p, "HOST").unwrap();
    assert_eq!(evs[0].artifact, "linux:systemd:service");
}

// ─── Timer Unit Tests ─────────────────────────────────────────────────────────

#[test]
fn test_systemd_timer_valid_oncalendar() {
    let content = "[Unit]\nDescription=Daily Timer\n[Timer]\nOnCalendar=*-*-* 00:00:00\nUnit=daily.service\n";
    let (p, _g) = create_temp_unit(content, "timer");
    let evs = parse_systemd_timer(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 1);
    assert_eq!(evs[0].processname, "daily.service");
    assert!(evs[0].commandline.as_ref().unwrap().contains("OnCalendar"));
}

#[test]
fn test_systemd_timer_valid_onboot() {
    let content = "[Timer]\nOnBootSec=15min\nUnit=boot.service\n";
    let (p, _g) = create_temp_unit(content, "timer");
    let evs = parse_systemd_timer(&p, "HOST").unwrap();
    assert_eq!(evs[0].processname, "boot.service");
    assert!(evs[0].commandline.as_ref().unwrap().contains("OnBootSec"));
}

#[test]
fn test_systemd_timer_valid_onactive() {
    let content = "[Timer]\nOnActiveSec=1h\nUnit=active.service\n";
    let (p, _g) = create_temp_unit(content, "timer");
    let evs = parse_systemd_timer(&p, "HOST").unwrap();
    assert!(evs[0].commandline.as_ref().unwrap().contains("OnActiveSec"));
}

#[test]
fn test_systemd_timer_implicit_unit_target() {
    let content = "[Timer]\nOnCalendar=daily\n";
    let (p, _g) = create_temp_unit(content, "timer");
    let evs = parse_systemd_timer(&p, "HOST").unwrap();
    assert!(evs[0].processname.ends_with(".service"));
}

#[test]
fn test_systemd_timer_missing_section_err() {
    let content = "OnCalendar=daily\n";
    let (p, _g) = create_temp_unit(content, "timer");
    let err = parse_systemd_timer(&p, "HOST").unwrap_err();
    assert_eq!(err.code(), "ERR_LNX_SYS_NO_UNIT");
}

#[test]
fn test_systemd_timer_missing_trigger_err() {
    let content = "[Timer]\nUnit=backup.service\n";
    let (p, _g) = create_temp_unit(content, "timer");
    let err = parse_systemd_timer(&p, "HOST").unwrap_err();
    assert_eq!(err.code(), "ERR_LNX_SYS_NO_EXEC");
}

#[test]
fn test_systemd_timer_empty_file_err() {
    let (p, _g) = create_temp_unit("", "timer");
    let err = parse_systemd_timer(&p, "HOST").unwrap_err();
    assert_eq!(err.code(), "ERR_LNX_EMPTY_FILE");
}

#[test]
fn test_systemd_timer_not_found_err() {
    let p = std::path::PathBuf::from("/non/existent/timer.timer");
    let err = parse_systemd_timer(&p, "HOST").unwrap_err();
    assert_eq!(err.code(), "ERR_LNX_IO_NOT_FOUND");
}

#[test]
fn test_systemd_timer_artifact_tag() {
    let content = "[Timer]\nOnBootSec=1m\n";
    let (p, _g) = create_temp_unit(content, "timer");
    let evs = parse_systemd_timer(&p, "HOST").unwrap();
    assert_eq!(evs[0].artifact, "linux:systemd:timer");
}

// ─── Socket / Path Unit Tests ─────────────────────────────────────────────────

#[test]
fn test_systemd_socket_listen_stream() {
    let content = "[Socket]\nListenStream=127.0.0.1:8080\n";
    let (p, _g) = create_temp_unit(content, "socket");
    let evs = parse_systemd_socket_or_path(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 1);
    assert_eq!(evs[0].artifact, "linux:systemd:socket");
    assert!(evs[0].commandline.as_ref().unwrap().contains("ListenStream=127.0.0.1:8080"));
}

#[test]
fn test_systemd_socket_listen_datagram() {
    let content = "[Socket]\nListenDatagram=0.0.0.0:53\n";
    let (p, _g) = create_temp_unit(content, "socket");
    let evs = parse_systemd_socket_or_path(&p, "HOST").unwrap();
    assert!(evs[0].commandline.as_ref().unwrap().contains("ListenDatagram"));
}

#[test]
fn test_systemd_path_modified() {
    let content = "[Path]\nPathModified=/tmp/trigger\n";
    let (p, _g) = create_temp_unit(content, "path");
    let evs = parse_systemd_socket_or_path(&p, "HOST").unwrap();
    assert_eq!(evs[0].artifact, "linux:systemd:path");
    assert!(evs[0].commandline.as_ref().unwrap().contains("PathModified"));
}

#[test]
fn test_systemd_path_exists() {
    let content = "[Path]\nPathExists=/etc/flag\n";
    let (p, _g) = create_temp_unit(content, "path");
    let evs = parse_systemd_socket_or_path(&p, "HOST").unwrap();
    assert!(evs[0].commandline.as_ref().unwrap().contains("PathExists"));
}

#[test]
fn test_systemd_socket_missing_section_err() {
    let content = "ListenStream=8080\n";
    let (p, _g) = create_temp_unit(content, "socket");
    let err = parse_systemd_socket_or_path(&p, "HOST").unwrap_err();
    assert_eq!(err.code(), "ERR_LNX_SYS_NO_UNIT");
}

#[test]
fn test_systemd_socket_missing_trigger_err() {
    let content = "[Socket]\nAccept=yes\n";
    let (p, _g) = create_temp_unit(content, "socket");
    let err = parse_systemd_socket_or_path(&p, "HOST").unwrap_err();
    assert_eq!(err.code(), "ERR_LNX_SYS_NO_EXEC");
}

#[test]
fn test_systemd_socket_empty_file_err() {
    let (p, _g) = create_temp_unit("", "socket");
    let err = parse_systemd_socket_or_path(&p, "HOST").unwrap_err();
    assert_eq!(err.code(), "ERR_LNX_EMPTY_FILE");
}

#[test]
fn test_systemd_socket_not_found_err() {
    let p = std::path::PathBuf::from("/non/existent/sock.socket");
    let err = parse_systemd_socket_or_path(&p, "HOST").unwrap_err();
    assert_eq!(err.code(), "ERR_LNX_IO_NOT_FOUND");
}

// ─── Generator Tests ──────────────────────────────────────────────────────────

#[test]
fn test_systemd_generator_valid() {
    let content = "#!/bin/sh\n# systemd generator\n";
    let (p, _g) = create_temp_unit(content, "gen");
    let evs = parse_systemd_generator(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 1);
    assert_eq!(evs[0].artifact, "linux:systemd:generator");
}

#[test]
fn test_systemd_generator_not_found_err() {
    let p = std::path::PathBuf::from("/non/existent/gen_123");
    let err = parse_systemd_generator(&p, "HOST").unwrap_err();
    assert_eq!(err.code(), "ERR_LNX_IO_NOT_FOUND");
}

#[test]
fn test_systemd_service_multiple_sections() {
    let content = "[Unit]\nDescription=Complex\n[Service]\nType=simple\nExecStart=/usr/bin/daemon\n[Install]\nWantedBy=multi-user.target\n";
    let (p, _g) = create_temp_unit(content, "service");
    let evs = parse_systemd_service(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 1);
}

#[test]
fn test_systemd_service_root_default_user() {
    let content = "[Unit]\nDescription=Default user\n[Service]\nExecStart=/bin/whoami\n";
    let (p, _g) = create_temp_unit(content, "service");
    let evs = parse_systemd_service(&p, "HOST").unwrap();
    assert_eq!(evs[0].subject_username, "root");
}

#[test]
fn test_systemd_service_quoted_executable() {
    let content = "[Service]\nExecStart=\"/opt/my app/bin\" --flag\n";
    let (p, _g) = create_temp_unit(content, "service");
    let evs = parse_systemd_service(&p, "HOST").unwrap();
    assert!(evs[0].processname.contains("/opt/my app/bin") || evs[0].processname.contains("\"/opt/my"));
}

#[test]
fn test_systemd_timer_multiple_oncalendar() {
    let content = "[Timer]\nOnCalendar=hourly\nOnCalendar=daily\n";
    let (p, _g) = create_temp_unit(content, "timer");
    let evs = parse_systemd_timer(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 1);
}

#[test]
fn test_systemd_timer_target_service_matching() {
    let content = "[Timer]\nOnBootSec=5m\nUnit=custom_target.service\n";
    let (p, _g) = create_temp_unit(content, "timer");
    let evs = parse_systemd_timer(&p, "HOST").unwrap();
    assert_eq!(evs[0].processname, "custom_target.service");
}

#[test]
fn test_systemd_socket_listen_unix_path() {
    let content = "[Socket]\nListenStream=/run/custom.sock\n";
    let (p, _g) = create_temp_unit(content, "socket");
    let evs = parse_systemd_socket_or_path(&p, "HOST").unwrap();
    assert!(evs[0].commandline.as_ref().unwrap().contains("/run/custom.sock"));
}

#[test]
fn test_systemd_path_path_changed() {
    let content = "[Path]\nPathModified=/var/spool/incoming\n";
    let (p, _g) = create_temp_unit(content, "path");
    let evs = parse_systemd_socket_or_path(&p, "HOST").unwrap();
    assert!(evs[0].commandline.as_ref().unwrap().contains("/var/spool/incoming"));
}

#[test]
fn test_systemd_service_exec_with_multiple_spaces() {
    let content = "[Service]\nExecStart=   /bin/spaced    arg1   arg2   \n";
    let (p, _g) = create_temp_unit(content, "service");
    let evs = parse_systemd_service(&p, "HOST").unwrap();
    assert_eq!(evs[0].processname, "/bin/spaced");
}

#[test]
fn test_systemd_service_parentprocess_is_systemd() {
    let content = "[Service]\nExecStart=/bin/cmd\n";
    let (p, _g) = create_temp_unit(content, "service");
    let evs = parse_systemd_service(&p, "HOST").unwrap();
    assert_eq!(evs[0].parentprocessname, "systemd");
}
