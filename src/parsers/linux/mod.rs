pub mod error;
pub mod cron;
pub mod systemd;
pub mod profiles;
pub mod ld_preload;
pub mod ssh;
pub mod sudoers;
pub mod pam;
pub mod udev;
pub mod modules;
pub mod package_manager;
pub mod autostart;
pub mod proc;

use crate::event::Event;
use std::path::Path;
use walkdir::WalkDir;

/// Checks whether a given directory is a Linux filesystem or triage collection
pub fn is_linux_target(target: &Path) -> bool {
    if !target.is_dir() {
        return false;
    }

    let target_str = target.to_string_lossy().to_lowercase();
    if target_str.contains("uac") || target_str.contains("linux") {
        return true;
    }

    for entry in WalkDir::new(target).max_depth(4).into_iter().flatten() {
        let p = entry.path();
        let fname = p.file_name().unwrap_or_default().to_string_lossy().to_lowercase();

        if fname == "live_response"
            || fname == "[root]"
            || fname == "passwd"
            || fname == "shadow"
            || fname == "crontab"
            || fname == "anacrontab"
            || fname == "ld.so.preload"
            || fname == "sshd_config"
            || fname.ends_with(".service")
            || fname.ends_with(".timer")
        {
            return true;
        }

        if entry.file_type().is_dir()
            && (p.join("live_response").exists()
                || p.join("[root]").exists()
                || (p.join("etc").exists() && p.join("var").join("log").exists())
                || p.join("var").join("log").exists()
                || p.join("audit.log").exists()
                || p.join("systemd").exists()
                || p.join("cron.d").exists()
                || p.join("etc").join("shadow").exists()
                || p.join("etc").join("passwd").exists())
        {
            return true;
        }
    }

    false
}

/// Recursively scans and extracts Linux persistence events from target directory or file
pub fn process_linux_target(target: &Path, computer_name: &str) -> Vec<Event> {
    let mut events = Vec::new();

    if target.is_file() {
        process_single_file(target, computer_name, &mut events);
        return events;
    }

    for entry in WalkDir::new(target).into_iter().flatten() {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }

        process_single_file(path, computer_name, &mut events);
    }

    events
}

fn process_single_file(path: &Path, computer_name: &str, events: &mut Vec<Event>) {
    let fname = path.file_name().unwrap_or_default().to_string_lossy().to_string();
    let path_str = path.to_string_lossy().to_string();

    // 1. Systemd units
    if fname.ends_with(".service") {
        if let Ok(ev) = systemd::parse_systemd_service(path, computer_name) {
            events.extend(ev);
        }
    } else if fname.ends_with(".timer") {
        if let Ok(ev) = systemd::parse_systemd_timer(path, computer_name) {
            events.extend(ev);
        }
    } else if fname.ends_with(".socket") || fname.ends_with(".path") {
        if let Ok(ev) = systemd::parse_systemd_socket_or_path(path, computer_name) {
            events.extend(ev);
        }
    } else if path_str.contains("system-generators") {
        if let Ok(ev) = systemd::parse_systemd_generator(path, computer_name) {
            events.extend(ev);
        }
    }

    // 2. Cron
    else if fname == "crontab" || path_str.contains("/cron.d/") || path_str.contains("\\cron.d\\") {
        if let Ok(ev) = cron::parse_cron_system_file(path, computer_name) {
            events.extend(ev);
        }
    } else if path_str.contains("spool/cron") || path_str.contains("spool\\cron") {
        if let Ok(ev) = cron::parse_cron_spool_file(path, computer_name) {
            events.extend(ev);
        }
    } else if fname == "anacrontab" {
        if let Ok(ev) = cron::parse_anacrontab_file(path, computer_name) {
            events.extend(ev);
        }
    } else if path_str.contains("cron.hourly") || path_str.contains("cron.daily")
        || path_str.contains("cron.weekly") || path_str.contains("cron.monthly")
    {
        if let Ok(ev) = cron::parse_cron_periodic_script(path, computer_name) {
            events.extend(ev);
        }
    }

    // 3. Shell profiles & rc.local
    else if fname == "rc.local" || fname.ends_with(".bashrc") || fname.ends_with(".profile")
        || fname == "profile" || fname == "bash.bashrc" || fname.ends_with(".zshrc")
        || fname.ends_with(".zprofile") || fname == "environment" || path_str.contains("/profile.d/")
        || path_str.contains("\\profile.d\\")
    {
        if let Ok(ev) = profiles::parse_shell_script(path, computer_name) {
            events.extend(ev);
        }
    }

    // 4. Dynamic Linker Preload
    else if fname == "ld.so.preload" {
        if let Ok(ev) = ld_preload::parse_ld_so_preload(path, computer_name) {
            events.extend(ev);
        }
    }

    // 5. SSH
    else if fname == "authorized_keys" || fname == "authorized_keys2" {
        if let Ok(ev) = ssh::parse_ssh_authorized_keys(path, computer_name) {
            events.extend(ev);
        }
    } else if fname == "sshd_config" {
        if let Ok(ev) = ssh::parse_sshd_config(path, computer_name) {
            events.extend(ev);
        }
    }

    // 6. Sudoers
    else if fname == "sudoers" || path_str.contains("/sudoers.d/") || path_str.contains("\\sudoers.d\\") {
        if let Ok(ev) = sudoers::parse_sudoers_file(path, computer_name) {
            events.extend(ev);
        }
    }

    // 7. PAM
    else if path_str.contains("/pam.d/") || path_str.contains("\\pam.d\\") {
        if let Ok(ev) = pam::parse_pam_file(path, computer_name) {
            events.extend(ev);
        }
    }

    // 8. Udev
    else if fname.ends_with(".rules") && (path_str.contains("udev") || path_str.contains("rules.d")) {
        if let Ok(ev) = udev::parse_udev_rule_file(path, computer_name) {
            events.extend(ev);
        }
    }

    // 9. Kernel modules
    else if fname == "modules" || path_str.contains("modules-load.d") || path_str.contains("modprobe.d") {
        if let Ok(ev) = modules::parse_kernel_modules_config(path, computer_name) {
            events.extend(ev);
        }
    }

    // 10. Package manager hooks
    else if path_str.contains("apt.conf.d") {
        if let Ok(ev) = package_manager::parse_apt_hook_file(path, computer_name) {
            events.extend(ev);
        }
    }

    // 11. XDG Autostart
    else if fname.ends_with(".desktop") && (path_str.contains("autostart") || path_str.contains("xdg")) {
        if let Ok(ev) = autostart::parse_xdg_desktop_file(path, computer_name) {
            events.extend(ev);
        }
    }

    // 12. Running processes & deleted binaries
    else if fname == "running_processes_full_paths.txt" || fname == "ps.txt" {
        if let Ok(ev) = proc::parse_running_processes_file(path, computer_name) {
            events.extend(ev);
        }
    }
}
