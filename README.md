# Faramir

> *"The younger brother, wiser and swifter."*

Faramir is the evolution of [Boromir](https://github.com/skyg4mb/Persistence_Boromir) — a forensic tool designed to extract and timeline persistence artifacts from forensic disk images, triages, and offline filesystems. Rewritten from the ground up in **Rust** at the request of [@jupyterj0nes](https://github.com/jupyterj0nes), Faramir delivers native-speed performance, self-contained execution, memory-safe parsing, and cross-platform DFIR persistence hunting for both **Windows** and **Linux**.

If Boromir gave analysts a way to hunt persistence, Faramir gives them a faster, sharper blade.

---

## What's New in v0.2.0

1. **Unified DFIR Timeline Output (Caarea & Masstin format)**:
   Outputs a 10-column timeline CSV fully aligned with the Caarea and Masstin forensic ecosystem:
   `timestamp`, `computer`, `artifact`, `event_id`, `pid`, `subject_username`, `target_username`, `processname`, `commandline`, `parentprocessname`.
2. **Native Forensic Image & Triage Ingestion**:
   Directly parses and stages raw disk images (`.E01`, `.raw`, `.dd`), virtual disks (`.vmdk`, `.vhd`), and forensic archive collections (`.zip`, `.tar.gz`, KAPE, UAC, Cortex XDR, Velociraptor) without manual mounting.
3. **Cross-Platform Hunting (Windows + Linux)**:
   Extracts persistence mechanisms from Windows offline hives/filesystems as well as Linux triage distributions (cron, systemd units, shell profiles, deleted in-memory binaries).
4. **Expanded Persistence Techniques**:
   Added detection for Print Monitor DLLs, W32Time Time Providers, Netsh Helper DLLs, PowerShell Profile scripts, and full Linux persistence suite.

---

## Why Rust?

| | Boromir (Python) | Faramir (Rust) |
|---|---|---|
| Runtime required | Python 3 + pip deps | None — single binary |
| Performance | Moderate | Native speed |
| Memory safety | Runtime errors possible | Guaranteed at compile time |
| Deployment | Script + virtualenv | Drop and run |
| Triage / Disk Images | Requires manual mounting | Native E01 / RAW / ZIP ingestion |

---

## Detected Persistence Techniques

### Windows Persistence

#### Registry Run Keys (MITRE T1547.001)
- `get-run` — HKLM/HKCU Run key
- `get-run-once` — RunOnce key
- `get-run-ex` — RunEx key
- `get-run-once-ex` — RunOnceEx key

#### DLL Injection & Hijacking
- `get-app-init-dlls` — AppInit_DLLs (MITRE T1546.010)
- `get-service-dlls` — ServiceDll hijacking via registry Parameters subkey (Hexacorn N.4)
- `get-gp-extension-dlls` — Group Policy Extension DLLs
- `get-chm-helper-dll` — CHM Helper DLL (Hexacorn N.77)
- `get-hh-ctrl-hijacking` — hhctrl.ocx COM hijack (Hexacorn N.77)
- `get-com-hijacking` — HKCU COM object hijacking via `Software\Classes\CLSID\*\InprocServer32` (MITRE T1546.015)
- `get-nldp-dll-override-path` — Natural Language Development Platform DLL override (Hexacorn N.98)
- `get-print-monitors` — Print Monitor DLLs under `Control\Print\Monitors` (MITRE T1547.010)
- `get-time-providers` — W32Time Time Provider DLL hijacking (MITRE T1547.003)
- `get-netsh-helper-dlls` — Netsh helper DLL registration (MITRE T1546.007)

#### Winlogon & Authentication
- `get-winlogon-userinit` — Winlogon Userinit property (MITRE T1547.004)
- `get-winlogon-shell` — Winlogon Shell property (MITRE T1547.004)
- `get-winlogon-mp-notify` — Winlogon MPNotify property
- `get-lsa-packages` — LSA Authentication, Security and Notification Packages (MITRE T1547.002)

#### Boot & Pre-OS
- `get-boot-execute` — Session Manager BootExecute (MITRE T1542.003)

#### Process & Debugger Hooks
- `get-image-file-execution-options` — IFEO Debugger value (MITRE T1546.012)
- `get-aedebug` — AeDebug custom debugger (Hexacorn N.4)
- `get-wer-fault-hangs` — WerFault Hangs debugger (Hexacorn N.116)
- `get-silent-process-exit` — SilentProcessExit MonitorProcess (Hexacorn N.116)

#### Autorun & Startup
- `get-cmd-autorun` — Command Processor AutoRun key
- `get-explorer-load` — Explorer Load property
- `get-startup-programs` — Files in user Startup folders (MITRE T1547.001)
- `get-active-setup` — Active Setup StubPath (Hexacorn N.54)
- `get-screensaver` — SCRNSAVE.EXE in HKCU Control Panel\Desktop (MITRE T1546.002)
- `get-power-shell-profiles` — Malicious PowerShell profiles (`*profile.ps1`) (MITRE T1546.013)

#### App Paths & Certificates
- `get-app-cert-dlls` — AppCertDlls (MITRE T1546.009)
- `get-app-paths` — App Paths subkeys (Hexacorn N.3)

#### Scheduled Tasks & Services
- `get-scheduled-tasks` — Registry TaskCache + XML files from `Windows\System32\Tasks\` (MITRE T1053.005)
- `get-windows-services` — Windows Services via ControlSet (MITRE T1543.003)

#### Logon Scripts
- `get-user-init-mpr-script` — UserInitMprLogonScript environment variable (MITRE T1037.001)
- `get-terminal-profile-start-on-user-login` — Windows Terminal profiles with `startOnUserLogin: true`

---

### Linux Persistence (`get-linux-persistence`)

- **Cron Jobs**: Scheduled tasks in `/etc/crontab`, `/etc/cron.d/*`, and `/var/spool/cron/*` (MITRE T1053.003).
- **Systemd Services**: Malicious unit definitions and execution binaries in `/etc/systemd/system/*.service` (MITRE T1543.002).
- **Shell Profiles & Startup**: Execution hooks in `/etc/profile`, `/etc/rc.local`, and user `.bashrc` / `.profile` (MITRE T1546.004).
- **In-Memory Hidden Executables**: Deleted binary links running from `/proc/*/exe (deleted)` or `/tmp` execution.

---

## Installation

### From source

Requires [Rust](https://rustup.rs/) (stable).

```bash
git clone https://github.com/AI3xGP/faramir.git
cd faramir
cargo build --release
```

The binary will be generated at `target/release/faramir` (or `faramir.exe` on Windows).

---

## Usage

```
faramir [OPTIONS] [ACTION]
```

### Options

| Option | Short | Description |
|---|---|---|
| `--directory <DIR>` | `-d` | Directory, mounted filesystem, or triage path to process |
| `--file <FILE>` | `-f` | Individual evidence file (e.g. `.E01`, `.raw`, `.dd`, `.zip`, `.tar.gz`, hive) |
| `--output <OUTPUT>` | `-o` | Output CSV file path |
| `--silent` | | Suppress verbose logging |
| `--source-evidence <DIR>` | | *(Legacy flag)* Path where evidence is mounted |
| `--csv-output <DIR>` | | *(Legacy flag)* Output CSV prefix directory |

### Examples

#### Modern Caarea / Masstin-compatible syntax

Extract all persistence artifacts directly from a forensic disk image:
```bash
faramir -f /cases/evidence.E01 -o /cases/persistence_timeline.csv
```

Process a KAPE / UAC zip triage:
```bash
faramir -f /cases/triage_collection.zip -o /cases/out.csv
```

Analyze a mounted Windows or Linux folder:
```bash
faramir -d /mnt/windows_drive -o persistence.csv
```

#### Legacy Faramir syntax

```bash
faramir --source-evidence /mnt/windows --csv-output ./results all
```

Run a specific check:
```bash
faramir -d /mnt/windows get-run
faramir -d /mnt/linux get-linux-persistence
```

---

## Output Format

Results are output as a standardized CSV file compatible with Caarea and Masstin timelines:

| Column | Description |
|---|---|
| `timestamp` | UTC ISO-8601 or hive write time of the artifact |
| `computer` | Hostname identified from triage or image name |
| `artifact` | Normalized artifact descriptor (e.g. `windows:persistence:registry_run_key`, `linux:cron:scheduled_job`) |
| `event_id` | Event identifier (or `0`) |
| `pid` | Associated Process ID (if applicable) |
| `subject_username` | Identity / access gained (e.g. `System`, `User`, `root`) |
| `target_username` | Target context user |
| `processname` | Clean target binary name |
| `commandline` | Full command line or suspicious entry value |
| `parentprocessname` | Mechanism or parent origin (e.g. `Registry`, `ScheduledTasks`, `systemd`, `crond`) |

---

## Credits

- Original [Boromir](https://github.com/skyg4mb/Persistence_Boromir) concept and Rust rewrite by [@AI3xGP](https://github.com/AI3xGP) (formerly @skyg4mb)
- Co-author of Boromir: [@jupyterj0nes](https://github.com/jupyterj0nes)
- Inspired by [Persistence Sniper](https://github.com/last-byte/PersistenceSniper), [Masstin](https://github.com/jupyterjones/masstin), and [Caarea](https://github.com/jupyterjones/caarea)

---

## License

GNU General Public License v3.0
