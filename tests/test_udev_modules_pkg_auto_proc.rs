use faramir::parsers::linux::udev::*;
use faramir::parsers::linux::modules::*;
use faramir::parsers::linux::package_manager::*;
use faramir::parsers::linux::autostart::*;
use faramir::parsers::linux::proc::*;
use std::fs::File;
use std::io::Write;

fn create_temp_file(content: &str, ext: &str) -> (std::path::PathBuf, tempfile_guard::FileGuard) {
    let path = std::env::temp_dir().join(format!("test_misc_{}_{}.{}", std::process::id(), chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0), ext));
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

// ─── UDEV Tests (20) ──────────────────────────────────────────────────────────

#[test]
fn test_udev_run_action_simple() {
    let content = "ACTION==\"add\", SUBSYSTEM==\"block\", RUN+=\"/usr/local/bin/usb_detect.sh\"\n";
    let (p, _g) = create_temp_file(content, "rules");
    let evs = parse_udev_rule_file(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 1);
    assert_eq!(evs[0].artifact, "linux:udev:run_action");
    assert_eq!(evs[0].processname, "/usr/local/bin/usb_detect.sh");
}

#[test]
fn test_udev_run_action_single_quotes() {
    let content = "KERNEL==\"sd*\", RUN+='/bin/sh /tmp/hook.sh'\n";
    let (p, _g) = create_temp_file(content, "rules");
    let evs = parse_udev_rule_file(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 1);
    assert_eq!(evs[0].processname, "/bin/sh");
}

#[test]
fn test_udev_run_action_multiple_rules() {
    let content = "SUBSYSTEM==\"net\", RUN+=\"/bin/net1\"\nSUBSYSTEM==\"usb\", RUN+=\"/bin/usb1\"\n";
    let (p, _g) = create_temp_file(content, "rules");
    let evs = parse_udev_rule_file(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 2);
}

#[test]
fn test_udev_rule_without_run_ignored() {
    let content = "SUBSYSTEM==\"block\", ATTR{size}==\"0\", GOTO=\"end\"\n";
    let (p, _g) = create_temp_file(content, "rules");
    let evs = parse_udev_rule_file(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 0);
}

#[test]
fn test_udev_comments_ignored() {
    let content = "# SUBSYSTEM==\"block\", RUN+=\"/bin/hook\"\n# comment\n";
    let (p, _g) = create_temp_file(content, "rules");
    let evs = parse_udev_rule_file(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 0);
}

#[test]
fn test_udev_empty_file_err() {
    let (p, _g) = create_temp_file("", "rules");
    let err = parse_udev_rule_file(&p, "HOST").unwrap_err();
    assert_eq!(err.code(), "ERR_LNX_EMPTY_FILE");
}

#[test]
fn test_udev_not_found_err() {
    let p = std::path::PathBuf::from("/non/existent/99-usb.rules");
    let err = parse_udev_rule_file(&p, "HOST").unwrap_err();
    assert_eq!(err.code(), "ERR_LNX_IO_NOT_FOUND");
}

#[test]
fn test_udev_subject_root() {
    let (p, _g) = create_temp_file("RUN+=\"/bin/cmd\"\n", "rules");
    let evs = parse_udev_rule_file(&p, "HOST").unwrap();
    assert_eq!(evs[0].subject_username, "root");
}

#[test]
fn test_udev_parent_is_udevd() {
    let (p, _g) = create_temp_file("RUN+=\"/bin/cmd\"\n", "rules");
    let evs = parse_udev_rule_file(&p, "HOST").unwrap();
    assert_eq!(evs[0].parentprocessname, "udevd");
}

#[test]
fn test_udev_target_user_root() {
    let (p, _g) = create_temp_file("RUN+=\"/bin/cmd\"\n", "rules");
    let evs = parse_udev_rule_file(&p, "HOST").unwrap();
    assert_eq!(evs[0].target_username, "root");
}

#[test]
fn test_udev_line_number() {
    let (p, _g) = create_temp_file("# 1\n# 2\nRUN+=\"/bin/cmd\"\n", "rules");
    let evs = parse_udev_rule_file(&p, "HOST").unwrap();
    assert!(evs[0].commandline.as_ref().unwrap().contains("line 3"));
}

#[test]
fn test_udev_spaces_in_run() {
    let (p, _g) = create_temp_file("ACTION==\"add\",   RUN+=  \"/bin/test\"  \n", "rules");
    let evs = parse_udev_rule_file(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 1);
}

#[test]
fn test_udev_event_id_zero() {
    let (p, _g) = create_temp_file("RUN+=\"/bin/cmd\"\n", "rules");
    let evs = parse_udev_rule_file(&p, "HOST").unwrap();
    assert_eq!(evs[0].event_id, 0);
}

#[test]
fn test_udev_pid_zero() {
    let (p, _g) = create_temp_file("RUN+=\"/bin/cmd\"\n", "rules");
    let evs = parse_udev_rule_file(&p, "HOST").unwrap();
    assert_eq!(evs[0].pid, 0);
}

#[test]
fn test_udev_computer_name() {
    let (p, _g) = create_temp_file("RUN+=\"/bin/cmd\"\n", "rules");
    let evs = parse_udev_rule_file(&p, "UBUNTU-TEST").unwrap();
    assert_eq!(evs[0].computer, "UBUNTU-TEST");
}

#[test]
fn test_udev_unquoted_run() {
    let (p, _g) = create_temp_file("RUN+=/bin/echo\n", "rules");
    let evs = parse_udev_rule_file(&p, "HOST").unwrap();
    assert_eq!(evs[0].processname, "/bin/echo");
}

#[test]
fn test_udev_three_rules() {
    let (p, _g) = create_temp_file("RUN+=\"/1\"\nRUN+=\"/2\"\nRUN+=\"/3\"\n", "rules");
    let evs = parse_udev_rule_file(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 3);
}

#[test]
fn test_udev_env_assignment_ignored() {
    let (p, _g) = create_temp_file("ENV{DEVTYPE}==\"usb_device\", NAME=\"custom\"\n", "rules");
    let evs = parse_udev_rule_file(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 0);
}

#[test]
fn test_udev_options_ignored() {
    let (p, _g) = create_temp_file("OPTIONS+=\"static_node=vhost-net\"\n", "rules");
    let evs = parse_udev_rule_file(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 0);
}

#[test]
fn test_udev_long_command() {
    let (p, _g) = create_temp_file("RUN+=\"/usr/bin/logger -t udev 'USB plugged in'\"\n", "rules");
    let evs = parse_udev_rule_file(&p, "HOST").unwrap();
    assert_eq!(evs[0].processname, "/usr/bin/logger");
}

// ─── MODULES Tests (20) ───────────────────────────────────────────────────────

#[test]
fn test_modules_etc_modules_entry() {
    let (p, _g) = create_temp_file("overlay\nbtrfs\n", "modules");
    let evs = parse_kernel_modules_config(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 2);
    assert_eq!(evs[0].artifact, "linux:kernel:module_load");
    assert_eq!(evs[0].processname, "overlay");
}

#[test]
fn test_modules_modprobe_install_hook() {
    let path = std::env::temp_dir().join(format!("modprobe.d_{}.conf", std::process::id()));
    {
        let mut f = File::create(&path).unwrap();
        f.write_all(b"install rkhook /bin/sh -c '/tmp/install.sh'\n").unwrap();
    }
    let evs = parse_kernel_modules_config(&path, "HOST").unwrap();
    let _ = std::fs::remove_file(&path);
    assert_eq!(evs.len(), 1);
    assert_eq!(evs[0].artifact, "linux:modprobe:install_command");
    assert_eq!(evs[0].processname, "rkhook");
}

#[test]
fn test_modules_empty_err() {
    let (p, _g) = create_temp_file("", "modules");
    let err = parse_kernel_modules_config(&p, "HOST").unwrap_err();
    assert_eq!(err.code(), "ERR_LNX_EMPTY_FILE");
}

#[test]
fn test_modules_not_found_err() {
    let p = std::path::PathBuf::from("/non/existent/modules");
    let err = parse_kernel_modules_config(&p, "HOST").unwrap_err();
    assert_eq!(err.code(), "ERR_LNX_IO_NOT_FOUND");
}

#[test]
fn test_modules_comments_ignored() {
    let (p, _g) = create_temp_file("# overlay\n# loop\n", "modules");
    let evs = parse_kernel_modules_config(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 0);
}

#[test]
fn test_modules_with_options() {
    let (p, _g) = create_temp_file("e1000e InterruptThrottleRate=3000\n", "modules");
    let evs = parse_kernel_modules_config(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 1);
    assert_eq!(evs[0].processname, "e1000e");
}

#[test]
fn test_modules_parent_is_kernel() {
    let (p, _g) = create_temp_file("lp\n", "modules");
    let evs = parse_kernel_modules_config(&p, "HOST").unwrap();
    assert_eq!(evs[0].parentprocessname, "kernel");
}

#[test]
fn test_modules_subject_root() {
    let (p, _g) = create_temp_file("lp\n", "modules");
    let evs = parse_kernel_modules_config(&p, "HOST").unwrap();
    assert_eq!(evs[0].subject_username, "root");
}

#[test]
fn test_modules_multiple_entries() {
    let (p, _g) = create_temp_file("mod1\nmod2\nmod3\n", "modules");
    let evs = parse_kernel_modules_config(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 3);
}

#[test]
fn test_modules_trailing_newlines() {
    let (p, _g) = create_temp_file("mod1\n\n\n", "modules");
    let evs = parse_kernel_modules_config(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 1);
}

#[test]
fn test_modules_modprobe_standard_alias_ignored() {
    let path = std::env::temp_dir().join(format!("modprobe.d_alias_{}.conf", std::process::id()));
    {
        let mut f = File::create(&path).unwrap();
        f.write_all(b"alias net-pf-10 ipv6\noptions ipv6 disable=1\n").unwrap();
    }
    let evs = parse_kernel_modules_config(&path, "HOST").unwrap();
    let _ = std::fs::remove_file(&path);
    assert_eq!(evs.len(), 0);
}

#[test]
fn test_modules_modprobe_multiple_installs() {
    let path = std::env::temp_dir().join(format!("modprobe.d_multi_{}.conf", std::process::id()));
    {
        let mut f = File::create(&path).unwrap();
        f.write_all(b"install m1 /bin/cmd1\ninstall m2 /bin/cmd2\n").unwrap();
    }
    let evs = parse_kernel_modules_config(&path, "HOST").unwrap();
    let _ = std::fs::remove_file(&path);
    assert_eq!(evs.len(), 2);
}

#[test]
fn test_modules_modprobe_parent_is_modprobe() {
    let path = std::env::temp_dir().join(format!("modprobe.d_p_{}.conf", std::process::id()));
    {
        let mut f = File::create(&path).unwrap();
        f.write_all(b"install m1 /bin/cmd1\n").unwrap();
    }
    let evs = parse_kernel_modules_config(&path, "HOST").unwrap();
    let _ = std::fs::remove_file(&path);
    assert_eq!(evs[0].parentprocessname, "modprobe");
}

#[test]
fn test_modules_event_id_zero() {
    let (p, _g) = create_temp_file("m1\n", "modules");
    let evs = parse_kernel_modules_config(&p, "HOST").unwrap();
    assert_eq!(evs[0].event_id, 0);
}

#[test]
fn test_modules_pid_zero() {
    let (p, _g) = create_temp_file("m1\n", "modules");
    let evs = parse_kernel_modules_config(&p, "HOST").unwrap();
    assert_eq!(evs[0].pid, 0);
}

#[test]
fn test_modules_computer_name() {
    let (p, _g) = create_temp_file("m1\n", "modules");
    let evs = parse_kernel_modules_config(&p, "DEBIAN-BOX").unwrap();
    assert_eq!(evs[0].computer, "DEBIAN-BOX");
}

#[test]
fn test_modules_empty_lines_ignored() {
    let (p, _g) = create_temp_file("   \n\tm1\n   \n", "modules");
    let evs = parse_kernel_modules_config(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 1);
}

#[test]
fn test_modules_target_user_root() {
    let (p, _g) = create_temp_file("m1\n", "modules");
    let evs = parse_kernel_modules_config(&p, "HOST").unwrap();
    assert_eq!(evs[0].target_username, "root");
}

#[test]
fn test_modules_filename_in_commandline() {
    let (p, _g) = create_temp_file("m1\n", "modules");
    let fname = p.file_name().unwrap().to_str().unwrap();
    let evs = parse_kernel_modules_config(&p, "HOST").unwrap();
    assert!(evs[0].commandline.as_ref().unwrap().contains(fname));
}

#[test]
fn test_modules_four_modules() {
    let (p, _g) = create_temp_file("a\nb\nc\nd\n", "modules");
    let evs = parse_kernel_modules_config(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 4);
}

// ─── PACKAGE MANAGER Tests (20) ───────────────────────────────────────────────

#[test]
fn test_pkg_apt_post_invoke() {
    let content = "APT::Update::Post-Invoke {\"/bin/sh -c 'rev.sh'\"};\n";
    let (p, _g) = create_temp_file(content, "conf");
    let evs = parse_apt_hook_file(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 1);
    assert_eq!(evs[0].artifact, "linux:apt:package_hook");
    assert_eq!(evs[0].processname, "/bin/sh");
}

#[test]
fn test_pkg_apt_pre_invoke() {
    let content = "APT::Update::Pre-Invoke {\"/usr/local/bin/check.sh\"};\n";
    let (p, _g) = create_temp_file(content, "conf");
    let evs = parse_apt_hook_file(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 1);
}

#[test]
fn test_pkg_dpkg_post_invoke() {
    let content = "DPkg::Post-Invoke {\"/usr/bin/logger updated\"};\n";
    let (p, _g) = create_temp_file(content, "conf");
    let evs = parse_apt_hook_file(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 1);
}

#[test]
fn test_pkg_apt_pre_install_pkgs() {
    let content = "APT::Update::Pre-Install-Pkgs {\"/opt/hook.py\"};\n";
    let (p, _g) = create_temp_file(content, "conf");
    let evs = parse_apt_hook_file(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 1);
}

#[test]
fn test_pkg_apt_empty_err() {
    let (p, _g) = create_temp_file("", "conf");
    let err = parse_apt_hook_file(&p, "HOST").unwrap_err();
    assert_eq!(err.code(), "ERR_LNX_EMPTY_FILE");
}

#[test]
fn test_pkg_apt_not_found_err() {
    let p = std::path::PathBuf::from("/non/existent/99hook");
    let err = parse_apt_hook_file(&p, "HOST").unwrap_err();
    assert_eq!(err.code(), "ERR_LNX_IO_NOT_FOUND");
}

#[test]
fn test_pkg_apt_comments_c_style() {
    let content = "// APT::Update::Post-Invoke {\"/bin/false\"};\n";
    let (p, _g) = create_temp_file(content, "conf");
    let evs = parse_apt_hook_file(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 0);
}

#[test]
fn test_pkg_apt_comments_hash_style() {
    let content = "# APT::Update::Post-Invoke {\"/bin/false\"};\n";
    let (p, _g) = create_temp_file(content, "conf");
    let evs = parse_apt_hook_file(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 0);
}

#[test]
fn test_pkg_apt_subject_root() {
    let (p, _g) = create_temp_file("APT::Update::Post-Invoke {\"/bin/true\"};\n", "conf");
    let evs = parse_apt_hook_file(&p, "HOST").unwrap();
    assert_eq!(evs[0].subject_username, "root");
}

#[test]
fn test_pkg_apt_parent_is_apt() {
    let (p, _g) = create_temp_file("APT::Update::Post-Invoke {\"/bin/true\"};\n", "conf");
    let evs = parse_apt_hook_file(&p, "HOST").unwrap();
    assert_eq!(evs[0].parentprocessname, "apt");
}

#[test]
fn test_pkg_apt_multiple_hooks() {
    let content = "APT::Update::Pre-Invoke {\"/1\"};\nAPT::Update::Post-Invoke {\"/2\"};\n";
    let (p, _g) = create_temp_file(content, "conf");
    let evs = parse_apt_hook_file(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 2);
}

#[test]
fn test_pkg_apt_target_user_root() {
    let (p, _g) = create_temp_file("APT::Update::Post-Invoke {\"/bin/true\"};\n", "conf");
    let evs = parse_apt_hook_file(&p, "HOST").unwrap();
    assert_eq!(evs[0].target_username, "root");
}

#[test]
fn test_pkg_apt_line_number() {
    let (p, _g) = create_temp_file("// 1\n// 2\nAPT::Update::Post-Invoke {\"/bin/true\"};\n", "conf");
    let evs = parse_apt_hook_file(&p, "HOST").unwrap();
    assert!(evs[0].commandline.as_ref().unwrap().contains("line 3"));
}

#[test]
fn test_pkg_apt_benign_settings_ignored() {
    let content = "Acquire::Languages \"none\";\nAPT::Default-Release \"stable\";\n";
    let (p, _g) = create_temp_file(content, "conf");
    let evs = parse_apt_hook_file(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 0);
}

#[test]
fn test_pkg_apt_event_id_zero() {
    let (p, _g) = create_temp_file("APT::Update::Post-Invoke {\"/bin/true\"};\n", "conf");
    let evs = parse_apt_hook_file(&p, "HOST").unwrap();
    assert_eq!(evs[0].event_id, 0);
}

#[test]
fn test_pkg_apt_pid_zero() {
    let (p, _g) = create_temp_file("APT::Update::Post-Invoke {\"/bin/true\"};\n", "conf");
    let evs = parse_apt_hook_file(&p, "HOST").unwrap();
    assert_eq!(evs[0].pid, 0);
}

#[test]
fn test_pkg_apt_computer_name() {
    let (p, _g) = create_temp_file("APT::Update::Post-Invoke {\"/bin/true\"};\n", "conf");
    let evs = parse_apt_hook_file(&p, "PROD-SERVER").unwrap();
    assert_eq!(evs[0].computer, "PROD-SERVER");
}

#[test]
fn test_pkg_apt_single_quotes_inside_block() {
    let content = "APT::Update::Post-Invoke {'/bin/script.sh'};\n";
    let (p, _g) = create_temp_file(content, "conf");
    let evs = parse_apt_hook_file(&p, "HOST").unwrap();
    assert_eq!(evs[0].processname, "/bin/script.sh");
}

#[test]
fn test_pkg_apt_unquoted_inside_block() {
    let content = "APT::Update::Post-Invoke {/bin/script.sh};\n";
    let (p, _g) = create_temp_file(content, "conf");
    let evs = parse_apt_hook_file(&p, "HOST").unwrap();
    assert_eq!(evs[0].processname, "/bin/script.sh");
}

#[test]
fn test_pkg_apt_spaces_around_block() {
    let content = "   APT::Update::Post-Invoke    {   \"/bin/spaced\"   }   ;   \n";
    let (p, _g) = create_temp_file(content, "conf");
    let evs = parse_apt_hook_file(&p, "HOST").unwrap();
    assert_eq!(evs[0].processname, "/bin/spaced");
}

// ─── AUTOSTART Tests (20) ─────────────────────────────────────────────────────

#[test]
fn test_autostart_valid_desktop() {
    let content = "[Desktop Entry]\nName=Backdoor\nExec=/usr/bin/backdoor --tray\nType=Application\n";
    let (p, _g) = create_temp_file(content, "desktop");
    let evs = parse_xdg_desktop_file(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 1);
    assert_eq!(evs[0].artifact, "linux:xdg:autostart");
    assert_eq!(evs[0].processname, "/usr/bin/backdoor");
}

#[test]
fn test_autostart_hidden_true_ignored() {
    let content = "[Desktop Entry]\nName=Disabled\nExec=/usr/bin/disabled\nHidden=true\n";
    let (p, _g) = create_temp_file(content, "desktop");
    let evs = parse_xdg_desktop_file(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 0);
}

#[test]
fn test_autostart_hidden_false_included() {
    let content = "[Desktop Entry]\nName=Enabled\nExec=/usr/bin/enabled\nHidden=false\n";
    let (p, _g) = create_temp_file(content, "desktop");
    let evs = parse_xdg_desktop_file(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 1);
}

#[test]
fn test_autostart_missing_desktop_entry_section_err() {
    let content = "Name=Broken\nExec=/bin/cmd\n";
    let (p, _g) = create_temp_file(content, "desktop");
    let err = parse_xdg_desktop_file(&p, "HOST").unwrap_err();
    assert_eq!(err.code(), "ERR_LNX_XDG_SYNTAX");
    assert_eq!(err.error_number(), 12002);
}

#[test]
fn test_autostart_missing_exec_err() {
    let content = "[Desktop Entry]\nName=NoExec\nType=Application\n";
    let (p, _g) = create_temp_file(content, "desktop");
    let err = parse_xdg_desktop_file(&p, "HOST").unwrap_err();
    assert_eq!(err.code(), "ERR_LNX_XDG_NO_EXEC");
    assert_eq!(err.error_number(), 12001);
}

#[test]
fn test_autostart_empty_err() {
    let (p, _g) = create_temp_file("", "desktop");
    let err = parse_xdg_desktop_file(&p, "HOST").unwrap_err();
    assert_eq!(err.code(), "ERR_LNX_EMPTY_FILE");
}

#[test]
fn test_autostart_not_found_err() {
    let p = std::path::PathBuf::from("/non/existent/app.desktop");
    let err = parse_xdg_desktop_file(&p, "HOST").unwrap_err();
    assert_eq!(err.code(), "ERR_LNX_IO_NOT_FOUND");
}

#[test]
fn test_autostart_subject_user() {
    let (p, _g) = create_temp_file("[Desktop Entry]\nExec=/bin/cmd\n", "desktop");
    let evs = parse_xdg_desktop_file(&p, "HOST").unwrap();
    assert_eq!(evs[0].subject_username, "user");
}

#[test]
fn test_autostart_target_user() {
    let (p, _g) = create_temp_file("[Desktop Entry]\nExec=/bin/cmd\n", "desktop");
    let evs = parse_xdg_desktop_file(&p, "HOST").unwrap();
    assert_eq!(evs[0].target_username, "user");
}

#[test]
fn test_autostart_parent_is_xdg() {
    let (p, _g) = create_temp_file("[Desktop Entry]\nExec=/bin/cmd\n", "desktop");
    let evs = parse_xdg_desktop_file(&p, "HOST").unwrap();
    assert_eq!(evs[0].parentprocessname, "xdg-autostart");
}

#[test]
fn test_autostart_ignores_comments() {
    let content = "# Comments\n[Desktop Entry]\n# Exec=/bin/false\nExec=/bin/real\n";
    let (p, _g) = create_temp_file(content, "desktop");
    let evs = parse_xdg_desktop_file(&p, "HOST").unwrap();
    assert_eq!(evs[0].processname, "/bin/real");
}

#[test]
fn test_autostart_exec_with_args() {
    let content = "[Desktop Entry]\nExec=/opt/miner --threads 4 --pool evil.org\n";
    let (p, _g) = create_temp_file(content, "desktop");
    let evs = parse_xdg_desktop_file(&p, "HOST").unwrap();
    assert_eq!(evs[0].processname, "/opt/miner");
    assert!(evs[0].commandline.as_ref().unwrap().contains("--threads 4"));
}

#[test]
fn test_autostart_computer_name() {
    let (p, _g) = create_temp_file("[Desktop Entry]\nExec=/bin/cmd\n", "desktop");
    let evs = parse_xdg_desktop_file(&p, "WS-DESKTOP").unwrap();
    assert_eq!(evs[0].computer, "WS-DESKTOP");
}

#[test]
fn test_autostart_event_id_zero() {
    let (p, _g) = create_temp_file("[Desktop Entry]\nExec=/bin/cmd\n", "desktop");
    let evs = parse_xdg_desktop_file(&p, "HOST").unwrap();
    assert_eq!(evs[0].event_id, 0);
}

#[test]
fn test_autostart_pid_zero() {
    let (p, _g) = create_temp_file("[Desktop Entry]\nExec=/bin/cmd\n", "desktop");
    let evs = parse_xdg_desktop_file(&p, "HOST").unwrap();
    assert_eq!(evs[0].pid, 0);
}

#[test]
fn test_autostart_name_in_commandline() {
    let content = "[Desktop Entry]\nName=SuperCoolApp\nExec=/bin/app\n";
    let (p, _g) = create_temp_file(content, "desktop");
    let evs = parse_xdg_desktop_file(&p, "HOST").unwrap();
    assert!(evs[0].commandline.as_ref().unwrap().contains("SuperCoolApp"));
}

#[test]
fn test_autostart_exec_spaces() {
    let content = "[Desktop Entry]\nExec=   /bin/spaces   \n";
    let (p, _g) = create_temp_file(content, "desktop");
    let evs = parse_xdg_desktop_file(&p, "HOST").unwrap();
    assert_eq!(evs[0].processname, "/bin/spaces");
}

#[test]
fn test_autostart_terminal_key_ignored() {
    let content = "[Desktop Entry]\nTerminal=true\nExec=/bin/t\n";
    let (p, _g) = create_temp_file(content, "desktop");
    let evs = parse_xdg_desktop_file(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 1);
}

#[test]
fn test_autostart_categories_ignored() {
    let content = "[Desktop Entry]\nCategories=Utility;\nExec=/bin/u\n";
    let (p, _g) = create_temp_file(content, "desktop");
    let evs = parse_xdg_desktop_file(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 1);
}

#[test]
fn test_autostart_only_desktop_entry_section() {
    let content = "[Desktop Action NewWindow]\nExec=/bin/new\n[Desktop Entry]\nExec=/bin/main\n";
    let (p, _g) = create_temp_file(content, "desktop");
    let evs = parse_xdg_desktop_file(&p, "HOST").unwrap();
    assert_eq!(evs[0].processname, "/bin/main");
}

// ─── PROC / RUNNING PROCESSES Tests (20) ──────────────────────────────────────

#[test]
fn test_proc_deleted_binary() {
    let content = "lrwxrwxrwx 1 root root 0 Sep 26 00:14 /proc/1234/exe -> /tmp/backdoor (deleted)\n";
    let (p, _g) = create_temp_file(content, "txt");
    let evs = parse_running_processes_file(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 1);
    assert_eq!(evs[0].artifact, "linux:process:deleted_binary_in_memory");
    assert_eq!(evs[0].pid, 1234);
    assert_eq!(evs[0].subject_username, "root");
}

#[test]
fn test_proc_tmp_execution() {
    let content = "lrwxrwxrwx 1 root root 0 Sep 26 00:14 /proc/5678/exe -> /tmp/miner\n";
    let (p, _g) = create_temp_file(content, "txt");
    let evs = parse_running_processes_file(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 1);
    assert_eq!(evs[0].artifact, "linux:process:temp_path_execution");
    assert_eq!(evs[0].pid, 5678);
}

#[test]
fn test_proc_dev_shm_execution() {
    let content = "lrwxrwxrwx 1 root root 0 Sep 26 00:14 /proc/9999/exe -> /dev/shm/stealer\n";
    let (p, _g) = create_temp_file(content, "txt");
    let evs = parse_running_processes_file(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 1);
    assert_eq!(evs[0].pid, 9999);
}

#[test]
fn test_proc_var_tmp_execution() {
    let content = "lrwxrwxrwx 1 root root 0 Sep 26 00:14 /proc/2222/exe -> /var/tmp/cronhook\n";
    let (p, _g) = create_temp_file(content, "txt");
    let evs = parse_running_processes_file(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 1);
}

#[test]
fn test_proc_normal_binary_ignored() {
    let content = "lrwxrwxrwx 1 root root 0 Sep 26 00:14 /proc/1/exe -> /sbin/init\n";
    let (p, _g) = create_temp_file(content, "txt");
    let evs = parse_running_processes_file(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 0);
}

#[test]
fn test_proc_normal_usr_bin_ignored() {
    let content = "lrwxrwxrwx 1 root root 0 Sep 26 00:14 /proc/500/exe -> /usr/bin/python3\n";
    let (p, _g) = create_temp_file(content, "txt");
    let evs = parse_running_processes_file(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 0);
}

#[test]
fn test_proc_comments_ignored() {
    let content = "# ls -l /proc/*/exe\n# comments\n";
    let (p, _g) = create_temp_file(content, "txt");
    let evs = parse_running_processes_file(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 0);
}

#[test]
fn test_proc_empty_err() {
    let (p, _g) = create_temp_file("", "txt");
    let err = parse_running_processes_file(&p, "HOST").unwrap_err();
    assert_eq!(err.code(), "ERR_LNX_EMPTY_FILE");
}

#[test]
fn test_proc_not_found_err() {
    let p = std::path::PathBuf::from("/non/existent/proc_list.txt");
    let err = parse_running_processes_file(&p, "HOST").unwrap_err();
    assert_eq!(err.code(), "ERR_LNX_IO_NOT_FOUND");
}

#[test]
fn test_proc_multiple_deleted() {
    let content = "/proc/100/exe -> /tmp/a (deleted)\n/proc/200/exe -> /tmp/b (deleted)\n";
    let (p, _g) = create_temp_file(content, "txt");
    let evs = parse_running_processes_file(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 2);
}

#[test]
fn test_proc_parent_is_proc() {
    let (p, _g) = create_temp_file("/proc/10/exe -> /tmp/x\n", "txt");
    let evs = parse_running_processes_file(&p, "HOST").unwrap();
    assert_eq!(evs[0].parentprocessname, "proc");
}

#[test]
fn test_proc_target_user_root() {
    let (p, _g) = create_temp_file("/proc/10/exe -> /tmp/x\n", "txt");
    let evs = parse_running_processes_file(&p, "HOST").unwrap();
    assert_eq!(evs[0].target_username, "root");
}

#[test]
fn test_proc_run_shm_path() {
    let (p, _g) = create_temp_file("/proc/30/exe -> /run/shm/payload\n", "txt");
    let evs = parse_running_processes_file(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 1);
}

#[test]
fn test_proc_computer_name() {
    let (p, _g) = create_temp_file("/proc/10/exe -> /tmp/x\n", "txt");
    let evs = parse_running_processes_file(&p, "LNX-PROD").unwrap();
    assert_eq!(evs[0].computer, "LNX-PROD");
}

#[test]
fn test_proc_event_id_zero() {
    let (p, _g) = create_temp_file("/proc/10/exe -> /tmp/x\n", "txt");
    let evs = parse_running_processes_file(&p, "HOST").unwrap();
    assert_eq!(evs[0].event_id, 0);
}

#[test]
fn test_proc_deleted_in_usr_local() {
    let (p, _g) = create_temp_file("/proc/40/exe -> /usr/local/bin/agent (deleted)\n", "txt");
    let evs = parse_running_processes_file(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 1);
    assert_eq!(evs[0].artifact, "linux:process:deleted_binary_in_memory");
}

#[test]
fn test_proc_commandline_format() {
    let (p, _g) = create_temp_file("/proc/50/exe -> /tmp/daemon\n", "txt");
    let evs = parse_running_processes_file(&p, "HOST").unwrap();
    assert!(evs[0].commandline.as_ref().unwrap().contains("Executing Binary Link: /tmp/daemon"));
}

#[test]
fn test_proc_invalid_pid_defaults_to_zero() {
    let (p, _g) = create_temp_file("/proc/invalid_pid/exe -> /tmp/d\n", "txt");
    let evs = parse_running_processes_file(&p, "HOST").unwrap();
    assert_eq!(evs[0].pid, 0);
}

#[test]
fn test_proc_three_mixed_lines() {
    let content = "/proc/1/exe -> /sbin/init\n/proc/2/exe -> /tmp/m (deleted)\n/proc/3/exe -> /bin/bash\n";
    let (p, _g) = create_temp_file(content, "txt");
    let evs = parse_running_processes_file(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 1);
}

#[test]
fn test_proc_deleted_whitespace_trimmed() {
    let (p, _g) = create_temp_file("   /proc/88/exe -> /tmp/trimmed (deleted)   \n", "txt");
    let evs = parse_running_processes_file(&p, "HOST").unwrap();
    assert_eq!(evs[0].pid, 88);
}
