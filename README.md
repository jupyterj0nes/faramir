<p align="center"><img src="docs/faramir.svg" alt="Faramir" width="720"></p>

<p align="center">
<img src="https://img.shields.io/badge/Rust-stable-orange?logo=rust" alt="Rust">
<img src="https://img.shields.io/badge/platform-Windows%20%7C%20Linux-blue" alt="Platform">
<img src="https://img.shields.io/badge/tests-906%20passing-brightgreen" alt="Tests">
<img src="https://img.shields.io/badge/license-GPL--3.0-lightgrey" alt="License">
</p>

**Faramir** is a persistence hunting tool for DFIR. It takes a forensic image, a triage package or a mounted volume, extracts the Windows registry hives and Linux configuration it needs, rebuilds dirty hives from their transaction logs, and writes a timeline of every autostart, hijack and backdoor it finds. Windows and Linux, one binary, no dependencies.

It is the Rust successor of [Boromir](https://github.com/Alexgpsec/Persistence_Boromir), Alejandro Gamboa's Python persistence hunter. *The younger brother, wiser and swifter... and alive!*

## Table of contents

- [Features](#features)
- [Demo](#demo)
- [Installation](#installation)
- [Usage](#usage)
- [Examples](#examples)
- [Supported evidence](#supported-evidence)
- [Detected techniques](#detected-techniques)
- [Output](#output)
- [Diagnostics](#diagnostics)
- [How it works](#how-it-works)
- [Testing](#testing)
- [Credits](#credits)
- [License](#license)

## Features

- **Reads the evidence itself.** E01, raw, VMDK, VHD/VHDX images with NTFS, ext4 or XFS volumes (plain or LVM), KAPE, Velociraptor, Cortex XDR, CyLR and UAC packages, nested archives, mounted volumes or a single hive. No mounting, no manual extraction.
- **Rebuilds dirty hives.** Finds `.LOG1`/`.LOG2` wherever the collector left them, checks they belong to the hive, validates every entry and replays them, Windows 7 / 8 logs (old `DIRT` format) included. Verified byte for byte against `rla.exe`, and against the hive Windows 7 recovered itself.
- **52 Windows techniques**, each read from the hive it lives in: HKLM `SOFTWARE`/`SYSTEM`, every `NTUSER.DAT`, `DEFAULT` and `UsrClass.dat`, including `Wow6432Node` variants.
- **Linux persistence**: cron, systemd, shell profiles, SSH, sudoers, PAM, udev, kernel modules, package hooks, `ld.so.preload` and live-process anomalies.
- **Deleted persistence**: keys and values recovered from freed hive cells, plus anything that existed in a Volume Shadow Copy but is gone from the live volume. On ext4, the jbd2 journal gives back deleted crontabs, units and keys with their name, dates and content, and the previous content of files that were rewritten.
- **Carving, when you ask for it.** `--carve` scans the raw bytes of an image, a pagefile or a memory dump for whole registry hives that no file system points to any more, and runs every technique on them. Off by default; every finding it adds is tagged `carved`. The scanner and the hive-bin chain reader are the [blockcarve](https://github.com/jupyterj0nes/blockcarve) crate shared with masstin, allymacb and caarea.
- **Every row flagged.** Two engines look at each finding: a catalogue of what known-bad persistence looks like (LOLBins fetching URLs, encoded PowerShell, `ld.so.preload`, reverse shells, system names outside their folders, scratch folders…) against what a stock Windows or Linux ships with, and a statistical test, the one masstin's graph-hunt uses, that asks how unusual the entry is compared with the rest of the run: on how many hosts it appears, how common its folder and its name are among its peers, whether it was written in a burst with other techniques. `--baseline <date>` makes everything before the date the reference and puts what came after to the test. Result: `significant`, `candidate`, `habitual`, `baseline` or `not_evaluated`, the same words masstin, caarea and allymacb write, with a 0 to 100 score and the reasons, each one saying whether a rule or the test spoke.
- **One CSV timeline, masstin's 19 columns.** The header is byte for byte the one [masstin](https://github.com/jupyterj0nes/masstin) writes: 14 event columns (faramir fills the eight that mean the same thing and leaves the logon-only ones empty) and the analysis tail (`hunt`, `hunt_score`, `hunt_why` from the hunt, `verdict`, `notes` from the analyst). Persistence and lateral movement from the same case concatenate, and a case tool reads one convention.
- **Nothing silent**: 140+ numbered diagnostic codes with a severity; a corrupt log, a renamed hive or a parser panic is reported and the run goes on.

## Demo

<p align="center"><img src="docs/demo.svg" alt="Faramir processing a Cortex XDR offline collector package" width="100%"></p>

A Cortex XDR offline-collector package with four dirty hives. The transaction logs sit in other `entry_` folders; Faramir locates them, matches each one to its hive, replays them, and then recovers a deleted Run value the attacker had cleaned up.

## Installation

### Binaries

Download the latest build from the [Releases page](../../releases/latest):

| File | Platform |
|---|---|
| `faramir-<version>-windows-x64.zip` | Windows 10/11, Server 2016+ |
| `faramir-<version>-linux-x64.tar.gz` | Linux x86_64 (glibc) |

Unzip and run. There is no installer and no runtime to install.

### From source

Requires stable Rust (pinned by `rust-toolchain.toml`).

```bash
git clone https://github.com/Alexgpsec/faramir.git
cd faramir
cargo build --release
# binary at target/release/faramir  (faramir.exe on Windows)
```

## Usage

```
faramir [OPTIONS] [ACTION]
```

| Option | Description |
|---|---|
| `-d, --directory <DIR>` | Directory to process: mounted volume, extracted collection, folder of images or packages. Repeatable. |
| `-f, --file <FILE>` | File to process: disk image, archive, single hive or Linux artifact. Repeatable. |
| `-o, --output <FILE>` | Output CSV. Default `faramir.output.csv`. |
| `--verbose` | Also print informational diagnostics (companion files skipped, logs matched outside the hive folder, hives rebuilt). |
| `--silent` | No console output. |
| `--carve` | Also scan the raw bytes of every disk image, and of any `-f` file that is not a hive, for registry hives. Reads the whole image, so it is opt-in. Findings are tagged `carved`. |
| `--baseline <DATE>` | Rows written before the date are what the machine looked like when it was trusted (`baseline`); rows after it are tested against them and are `candidate` when nothing else is said about them. `YYYY-MM-DD`, optionally with `HH:MM[:SS]`. `--investigation-from`, masstin's name for it, is an alias. |
| `--known-good <CSV>` | A faramir CSV from a clean host (this layout or the ten-column one of 0.3): its entries count as known good on every host (user names, SIDs and drive letters are neutralised). Repeatable. |
| `--alpha <ALPHA>` | False-discovery rate of the statistical test, the share of `significant` rows allowed to be false alarms. Default `0.05`. |
| `--carry-marks <CSV>` | An earlier faramir CSV of the same evidence: its `verdict` and `notes` are copied onto every row with the same 14 event columns (masstin's row hash), so marking is not lost when the evidence is parsed again. Repeatable. |
| `--no-hunt` | Leave `hunt`, `hunt_score` and `hunt_why` empty. |
| `--source-evidence <DIR>`, `--csv-output <DIR>` | Legacy Boromir flags, still accepted. |
| `[ACTION]` | `all` (default), any `get-*` technique from the tables below, `get-deleted-persistence`, `get-linux-persistence`. |

## Examples

**A forensic image.** Partitions are found (MBR and GPT). On NTFS the registry, user hives and tasks are pulled out and every Volume Shadow Copy is processed too; on ext4 (plain or inside LVM) the cron, systemd, shell, SSH, sudo, PAM, udev and module configuration comes out with the host name from `/etc/hostname`. A disk that holds both gives two hosts:

```bash
faramir -f /cases/HRSERVER.E01 -o /cases/hrserver_persistence.csv
```

**A virtual disk** from a hypervisor export:

```bash
faramir -f /cases/DC01-flat.vmdk -o dc01.csv        # VMDK descriptor or extent
faramir -f /cases/FS02.vhdx -o fs02.csv             # dynamic VHDX
```

**A triage package.** The type and host name are detected from the package itself; nested zips are expanded:

```bash
faramir -f /cases/triage/WS01_20261028_120000.zip -o ws01.csv                                       # KAPE
faramir -f /cases/triage/Collection-SRV-DC01-2026-10-28T12_00_00Z.zip -o dc01.csv                   # Velociraptor
faramir -f /cases/triage/offline_collector_output_WS01_2026-10-28_12-00-00.zip -o ws01.csv          # Cortex XDR
faramir -f /cases/triage/uac-web01-linux-20261028120000.tar.gz -o web01.csv                         # UAC (Linux)
```

**A whole folder of evidence.** Every image and package under the folder is processed, each with its own host name:

```bash
faramir -d /cases/incident-4711/triages -o incident-4711.csv
```

**A mounted volume**, Windows or Linux:

```bash
faramir -d E:\ -o persistence.csv
faramir -d /mnt/suspect_root -o persistence.csv
```

**A single hive**, with its transaction logs next to it:

```bash
faramir -f /cases/SOFTWARE -o software.csv
faramir -f "/cases/bob_NTUSER.DAT" -o bob.csv
```

**One technique only:**

```bash
faramir -d /mnt/evidence/C get-run
faramir -d /mnt/evidence/C get-scheduled-tasks
faramir -f /cases/HRSERVER.E01 get-deleted-persistence
```

**Several hosts in one run**, then merge with a masstin timeline:

```bash
faramir -f ws01.zip -f ws02.zip -f srv-dc01.E01 -o persistence.csv
masstin -a parse-windows -d /cases/logs -o lateral.csv
tail -n +2 persistence.csv >> lateral.csv
```

**See what could and could not be read:**

```bash
faramir -f /cases/WS01.zip -o ws01.csv --verbose
```

**Carve what the file system no longer has.** The image is processed as usual, then its raw bytes are scanned for hives: old `RegBack` copies, deleted user profiles, pages of snapshots that were purged, hives sitting in a pagefile or a memory dump. Every technique runs on what comes out, and only what the live registry does not already show is added, tagged `carved`:

```bash
faramir -f /cases/HRSERVER.E01 -o hrserver.csv --carve
faramir -f /cases/pagefile.sys -o pagefile.csv --carve
faramir -f /cases/WS01.mem -o ws01_memory.csv --carve
```

## Supported evidence

| Input | Handling |
|---|---|
| `.E01` / `.Ex01` | EWF reader, file systems parsed in place. MBR and GPT partitions; every partition is identified by its signature, not its type code. |
| `.dd` `.raw` `.img` `.001` | Raw and split-raw images, whole disks or single volumes. |
| NTFS volumes | Registry, user hives, tasks and event logs extracted; BitLocker volumes reported and skipped; every Volume Shadow Copy extracted and diffed against the live volume. |
| Linux volumes | ext2/ext3/ext4 and XFS (v4 and v5), as a partition or as a linear LVM logical volume (any VG, any number of LVs, one PV). The persistence surface is copied out as a root tree; usr-merged `/lib` is read once. ext4 volumes also give back deleted and rewritten files through the journal. btrfs, F2FS and LUKS volumes are recognised and reported, not read. |
| `.vmdk` | Monolithic or split, sparse or flat, streamOptimized (compressed). Snapshots, `-flat` and `-sNNN` extents are read through their descriptor. |
| `.vhd` `.vhdx` | Fixed and dynamic. Differencing disks are reported as incomplete. |
| `.zip` `.tar` `.tar.gz` `.tgz` | Only forensic artifacts are extracted. Nested archives are expanded in place. Encrypted zips are tried with the usual forensic passwords. |
| KAPE, Velociraptor, Cortex XDR, CyLR, UAC | Detected from their markers; the host name comes from the package. |
| Directory | Mounted volume or already-extracted collection, Windows or Linux. |
| Browser profiles | From images and packages: Chromium-family `Preferences`, `Secure Preferences` and extension manifests, Firefox `extensions.json`, enterprise policy files; caches are never copied. Linux: `~/.config/<browser>`, `~/.mozilla/firefox`, snap and flatpak paths, `/etc/*/policies/managed`. |
| Single file | A hive (with its logs beside it), a systemd unit, a crontab, a shell profile. With `--carve`, any other file is scanned for hives (pagefile, hiberfil, memory dump, unallocated-space dump). |

Hives are recognised by name **and** by header, so `bob_NTUSER.DAT`, `HOST-SOFTWARE`, `C_Windows_System32_config_SYSTEM`, `SOFTWARE.hve` or `artifact_0017.bin` all work.

## Detected techniques

### Windows

| Area | Action | What is read | MITRE |
|---|---|---|---|
| **Autostart keys** | `get-run` `get-run-once` `get-run-ex` `get-run-once-ex` | HKLM + Wow6432Node + every HKCU / DEFAULT profile | T1547.001 |
| | `get-startup-programs` | Files in Startup folders | T1547.001 |
| | `get-active-setup` | Active Setup `StubPath` (HKLM, Wow6432Node, HKCU) | T1547.014 |
| | `get-screensaver` | `SCRNSAVE.EXE` per user | T1546.002 |
| | `get-explorer-load` | `Windows\Load` and `Windows\Run` | T1547 |
| | `get-cmd-autorun` | Command Processor `AutoRun` | T1546 |
| | `get-terminal-profile-start-on-user-login` | Windows Terminal `startOnUserLogin` | T1547 |
| | `get-power-shell-profiles` | Every `*profile.ps1` | T1546.013 |
| **Logon** | `get-winlogon-userinit` `get-winlogon-shell` `get-winlogon-mp-notify` | Winlogon in HKLM and HKCU | T1547.004 |
| | `get-user-init-mpr-script` | `UserInitMprLogonScript` | T1037.001 |
| | `get-lsa-packages` | Authentication / Security / Notification packages, OSConfig; defaults filtered | T1547.002, T1556.002 |
| **Services & tasks** | `get-windows-services` | `ImagePath` of every service in the active ControlSet | T1543.003 |
| | `get-service-dlls` | `ServiceDll` on the service and its `Parameters` | T1543.003 |
| | `get-scheduled-tasks` | TaskCache registry + task XML on disk | T1053.005 |
| | `get-boot-execute` | `BootExecute`, `SetupExecute` (defaults filtered) | T1542.003 |
| **DLL hijacks** | `get-app-init-dlls` | `AppInit_DLLs` honouring `LoadAppInit_DLLs`, Wow6432Node | T1546.010 |
| | `get-app-cert-dlls` | `AppCertDlls` | T1546.009 |
| | `get-app-paths` | App Paths default values (HKLM, Wow6432Node, HKCU) | T1546 |
| | `get-gp-extension-dlls` | Group Policy extension `DllName` | T1547 |
| | `get-chm-helper-dll` | HtmlHelp Author `Location` | T1546 |
| | `get-hh-ctrl-hijacking` | hhctrl.ocx CLSID in SOFTWARE, Wow6432Node, NTUSER, UsrClass | T1546.015 |
| | `get-com-hijacking` | `InprocServer32` / `LocalServer32` under HKCU Classes and UsrClass | T1546.015 |
| | `get-nldp-dll-override-path` | NLDP stemmer / word-breaker override | T1546 |
| | `get-print-monitors` | Print monitor DLLs (standard ones filtered) | T1547.010 |
| | `get-time-providers` | W32Time providers (standard ones filtered) | T1547.003 |
| | `get-netsh-helper-dlls` | Netsh helpers, Wow6432Node | T1546.007 |
| **Debugger hooks** | `get-image-file-execution-options` | IFEO `Debugger`, Wow6432Node | T1546.012 |
| | `get-aedebug` | AeDebug `Debugger` / `ReflectDebugger` | T1546 |
| | `get-wer-fault-hangs` | WER Hangs debugger (HKLM and HKCU) | T1546 |
| | `get-silent-process-exit` | `MonitorProcess` | T1546.012 |
| **Policy and shell** | `get-policies-run` | `Policies\Explorer\Run` (HKLM, Wow6432Node, HKCU) | T1547.001 |
| | `get-startup-folder-redirect` | `Shell Folders` / `User Shell Folders` pointing the Startup folder somewhere else | T1547.001 |
| | `get-shell-service-object-delay-load` | `ShellServiceObjectDelayLoad` CLSIDs, resolved to their DLL | T1547 |
| | `get-shell-extensions` | Browser Helper Objects, ShellExecuteHooks, icon overlays, `shellex` context-menu / property-sheet / copy-hook / drag-drop / column handlers, CLSIDs resolved | T1546.015 |
| | `get-com-treat-as` | `CLSID\…\TreatAs` redirects | T1546.015 |
| | `get-file-associations` | `exefile`, `batfile`, `txtfile`, `regfile`, `mscfile`, `ms-settings`, `Folder`… `shell\open\command` that is not the Windows default | T1546.001 |
| | `get-gpo-scripts` | Group Policy startup / shutdown / logon / logoff scripts in the registry and in `scripts.ini` / `psscripts.ini` | T1037.001 |
| | `get-office-addins` | Office add-ins with `LoadBehavior`, Outlook add-ins, Excel `OPEN` XLL/XLA entries; ProgID resolved to its DLL | T1137.006 |
| | `get-browser-extensions` | Force-installed and external extensions from the registry (Chrome, Edge, Brave, Chromium, Firefox), and every extension in Chromium `Preferences` / `Secure Preferences` / manifests and Firefox `extensions.json`, with origin (store, policy, unpacked, sideloaded), install time and risky permissions | T1176 |
| **Logon and credentials** | `get-security-providers` | `SecurityProviders` SSP DLLs beyond the defaults | T1547.005 |
| | `get-winlogon-notify` | `Winlogon\Notify` packages | T1547.004 |
| | `get-network-providers` | `NetworkProvider\Order` and each provider's DLL (credential interception) | T1556.008 |
| | `get-credential-providers` | Credential providers, filters and PLAP providers whose DLL is not a Microsoft one | T1556 |
| | `get-terminal-server-programs` | RDP `InitialProgram`, `StartupPrograms` | T1547 |
| | `get-cor-profiler` | `COR_PROFILER` / `CORECLR_PROFILER` in the user and machine environment | T1574.012 |
| | `get-service-failure-command` | `FailureCommand` of every service | T1543.003 |
| | `get-safe-boot-alternate-shell` | SafeBoot `AlternateShell` | T1547 |
| **Removed** | `get-deleted-persistence` | Keys and values recovered from freed hive cells, placed back on their path and matched against the locations above | |
| | *(automatic on images)* | Items present in a Volume Shadow Copy but gone from the live volume | |
| | *(`--carve`)* | Every technique above, run on hives carved from the raw bytes of the image and absent from the live registry | |
| | *(automatic on ext4 images)* | Linux files deleted or rewritten under the persistence surface, recovered through the jbd2 journal and run through the Linux techniques | |

### Linux

`get-linux-persistence` runs on a disk image with ext4 volumes, a mounted root, a UAC package or any folder with the usual `etc/`, `var/`, `home/` layout.

| Area | Artifacts |
|---|---|
| Scheduled | `/etc/crontab`, `cron.d`, user spools, `cron.{hourly,daily,weekly,monthly}`, anacron |
| systemd | services, timers, sockets, paths, generators |
| Shell and session | `/etc/profile`, `profile.d`, `bashrc` / `zshrc` / `.profile`, `rc.local`, XDG autostart |
| Credentials and access | `authorized_keys`, `AuthorizedKeysCommand`, `ForceCommand`, sudoers `NOPASSWD` and `Defaults` overrides, PAM `pam_exec` backdoors, `pam_permit` placed first in a stack or with a stack-ending control (Debian's stock closers are not reported), custom module paths |
| Kernel and libraries | `ld.so.preload`, `modules-load.d`, `modprobe.d` `install` commands, udev `RUN` actions |
| Package manager | APT hooks |
| Live state | processes running a deleted binary, execution from `/tmp` |
| Browsers | Chromium and Firefox extensions per profile (origin, install time, risky permissions), policy force-installs |

## Hunting

Every row gets a state in `hunt`: the same column, in the same place, with the same six words masstin, caarea and allymacb write (masstin's `docs/csv-format.md`, "The same tail in caarea, faramir and allymacb"), so a case tool maps the tail once. masstin only tests; faramir also runs static rules, and the state comes from the strongest evidence: a high rule gives `significant`, a medium rule `candidate`, a low rule leaves the statistical state as it is, and when a test and a rule both speak the stronger state wins. No other word goes into the column: `suspicious` is the analyst's, in `verdict`. Highest first:

| `hunt` | Meaning |
|---|---|
| `significant` | A high rule fired (`mshta http://…`, `powershell -enc`, a system binary name outside its folder, a DLL slot pointing at AppData, `ld.so.preload`, a reverse shell, a cron job from `/tmp`, an SSH key forcing a command from a hidden folder…), or nothing known about it but tested and statistically rare among the rows of its technique in this run: q ≤ `--alpha`. |
| `candidate` | A medium rule (a remote-management tool, PowerShell with a hidden window, an every-minute cron, a slot that is empty on a stock system) on an entry that is not stock or known good; or tested with q above alpha (written after `--baseline`, or present on one host of the fleet); or no longer on the live system (deleted, only in a shadow copy, carved, previous version). Nothing passes the bar, but worth a look. |
| `habitual` | Stock entry, in a `--known-good` CSV, or present on several hosts of the fleet: p = 1, reference, not a test. |
| `baseline` | Written before `--baseline`: reference, not judged. |
| `not_evaluated` | No test could be made (one host and no baseline, or no other row of the technique to compare with) and no rule fired. |
| empty | `--no-hunt`. |

`hunt_score` is masstin's number, with the same meaning: how rare the row is, as −10·log10 of a probability, rounded and capped at 100, so ten points are one order of magnitude. The statistical test contributes −10·log10(q). Every rule that fired adds its own points in the same unit, since independent evidence adds in log space, and those points are **measured, not chosen**: the share of clean reference rows of the row's system the rule's pattern fires on (`src/hunt/measured.rs` holds the tables and the two references: the SYSTEM and user hives of a Windows Server lab host recovered from memory, 748 rows; the UAC collection of an Ubuntu lab host, 761 rows). A pattern that never fired on the reference is not "never": it gets the bound the corpus gives, one in `rows + 1`, 29 points on either. A rule measured below 10 points fires on more than one clean row in ten: noise on that system, it gives neither state nor points, only its clause (`H1011`, the service-DLL rule, fires on 290 of the 748 Windows reference rows and is worth 4 there). The level of a rule stays the author's claim and decides the state; the measurement decides the points. A reference row (`habitual`, `baseline`) is 0.

| Points | Read as | Where it comes from |
|---|---|---|
| 0 | no rarer than chance | habitual, baseline, a tested row with q = 1, a rule measured common |
| 13 | one in twenty | q = 0.05, the default alpha: `significant` starts here |
| 20 | one in a hundred | q = 0.01 |
| 23 to 26 | one in two hundred to one in four hundred | the rules that fired on a few reference rows (`H3013` 4 of 761 on Linux, 2 of 748 on Windows; `H2008` 3 of 761; `H1004`, `H1012` 3 of 748) |
| 29 | one in seven hundred and fifty | a rule that never fired on the reference: the bound 750 rows give |
| 30 | one in a thousand | q = 0.001 |
| 58 | | two rules that never fired, on one row |
| 60 | one in a million | q = 10⁻⁶ |
| 100 | the cap | four such rules, or q ≤ 10⁻¹⁰ |

`hunt_score >= 30` keeps what is rarer than one in a thousand, in masstin's timeline and in this one alike. A row made `significant` or `candidate` by a rule carries that rule's measured points, 29 when the pattern never fired on the reference; a larger clean corpus would raise that bound; a `significant` row from the test alone starts at 13 (the default alpha) and grows with its rarity; a low rule adds 10 and leaves the state alone.

`hunt_why` says which spoke. A rule's clause starts with its id and level, then the title and the ATT&CK technique: `rule H1001 (high): LOLBin fetching remote content [T1218]`. The test's clause is in words, with the exact p and q: `rare among 1200 windows_service row(s) (p=0.001, q=0.025): on 1 of 40 hosts, folder: ProgramData (1 of 1200), name: hex-like name (1 of 1200)`. So are the rest: `stock Windows entry`, `in known-good CSV`, `before the baseline`, `on 40 of 40 hosts`, `written after the baseline`, `deleted`. Rules first, strongest first, then the words, `; ` between. A reader that wants only the rules filters `hunt_why` on `rule `; one that wants only the statistics, on its absence. `verdict` (`suspicious`, `confirmed`, `benign`) and `notes` are the analyst's: faramir leaves them empty and `--carry-marks` brings them back from an earlier CSV of the same evidence.

**Knowledge.** The rule catalogue (`src/hunt/rules.rs`, ids `H1xxx` Windows, `H2xxx` Linux, `H3xxx` both) is what Autoruns, Trawler and PersistenceSniper look for, offline and for both systems: LOLBins with URLs, encoded or hidden PowerShell, `rundll32` script hosts, system binary names outside `System32`, Winlogon Shell/Userinit changes, IFEO debuggers, DLL slots outside the system folders, scripts and executables in Temp, Public, ProgramData, AppData, the Recycle Bin or a hidden folder, double extensions, alternate data streams, network shares, offensive and tunnelling tools, remote-management and cloud-sync tools, download-and-run, reverse shells, base64 and other obfuscation, defence tampering, commands that install further persistence or change accounts, SUID and capability changes; on Linux also `ld.so.preload`, PAM bypasses, SSH forced commands, every-minute crons, daemon names outside the package tree, modprobe install hooks, APT hooks, deleted binaries still running, shell profiles that hook `sudo`, set `LD_PRELOAD` or hide history, forced browser extensions. Against it, the stock lists (`src/hunt/known_good.rs`): the Run entries, services, LSA packages, SSPs, print monitors, netsh helpers and network providers Windows ships with, and the crontab lines, `cron.daily` scripts, APT hooks, udev helpers, `profile.d` scripts, autostart entries, kernel modules and cloud-image sudoers of Debian, Ubuntu and RHEL. A stock match never cancels a high rule; it stops a medium or low rule from making the row `candidate` on weak evidence.

**Statistics.** The same design as masstin's graph-hunt, applied to persistence rows (see `docs/graph-hunt-statistics.md` in masstin). For each row, every coordinate is a tail share measured in the run itself: the share of rows of the same technique whose folder family is at least as rare, whose name shape (plain, with digits, mostly digits, hex-like, tiny) is at least as rare, whose minute saw at least as many different techniques written on the same host; with several hosts and a baseline, the share of hosts carrying the same entry. The statistic is the sum of −ln(share); its p-value is conformal, (1 + reference rows with a statistic at least as large) / (1 + reference rows); Benjamini-Hochberg across every tested row of the run controls the false-discovery rate at `--alpha`. A conformal p-value can never go below 1/(N+1), so the rows put to the test have to be few compared with the reference, exactly as masstin tests the window days against the baseline days. Three modes, chosen per operating system: with `--baseline`, reference = rows written before the date, tested = rows after it or undated; without a baseline and with several hosts (`-d triages/`), reference = every row of the technique, tested = entries present on exactly one host (Kansa's least-frequency-of-occurrence, with the selection kept out of the statistic); one host and no baseline, the test is skipped and the run says so (`ERR_HUNT_SINGLE_HOST`), rules and stock lists still apply. Stock and known-good rows are reference, never tested.

```
faramir -d /cases/incident-4711/triages -o incident-4711.csv --baseline 2026-10-01
faramir -f /cases/WS01.E01 -o ws01.csv --baseline "2026-10-01 08:00" --known-good /baselines/ws-gold.csv
faramir -d /cases/triages -o persistence.csv --alpha 0.01
faramir -f /cases/WS01-reimaged.E01 -o ws01-v2.csv --baseline 2026-10-01 --carry-marks ws01.csv
```

## Output

One CSV with masstin's 19 columns, in masstin's order and with masstin's names, so `merge`, the loaders and a case tool read it as any other timeline. The 14 event columns:

| Column | faramir writes |
|---|---|
| `time_created` | `2024-01-17 21:20:00.000` (key last-write time, unit mtime; empty when unknown) |
| `dst_computer` | `WS01` |
| `event_type` | The technique: `windows:persistence:registry_run_key`, `windows:persistence:deleted:windows_service`, `windows:persistence:removed_since_vss:registry_run_key`, `windows:persistence:carved:registry_run_key`, `linux:ssh:authorized_key`, `linux:deleted:cron:system_job`, `linux:previous_version:sudoers:nopasswd` |
| `event_id` | `0` |
| `logon_type` | empty |
| `target_user_name` | `System`, `User`, `root`, the account of the crontab or the SSH key |
| `target_domain_name` | empty |
| `src_computer` | empty |
| `src_ip` | empty |
| `subject_user_name` | the same account |
| `subject_domain_name` | empty |
| `logon_id` | empty |
| `detail` | The entry: `C:\ProgramData\updater.exe --silent`, `Systemd Unit: x.service (Desc: …, Exec: /usr/sbin/x)`, `Sudoers [sudoers line 55]: %Leadership ALL=(ALL) NOPASSWD:ALL` |
| `log_filename` | Where it was found: the hive path, the key, the unit file, the daemon (`crond`, `systemd`, `udevd`), the snapshot, the carved hive with its write time and image offset |

The logon-only columns stay empty on purpose: they exist so the columns line up with masstin's. Then the analysis tail:

| Column | Written by | Values |
|---|---|---|
| `hunt` | faramir | `significant`, `candidate`, `habitual`, `baseline`, `not_evaluated` or empty: the six words of the shared tail (see Hunting) |
| `hunt_score` | faramir | `0`–`100`, masstin's rarity scale (see Hunting) |
| `hunt_why` | faramir | `rule H1001 (high): LOLBin fetching remote content [T1218]; rule H3001 (high): Persistence from a scratch folder [T1547]; written after the baseline` |
| `verdict` | the analyst | `suspicious`, `confirmed`, `benign` or empty |
| `notes` | the analyst | free text, `#tags` welcome |

Quoting is masstin's: an empty event field is `""`, a value with a comma, a quote or a line break is quoted, the rest is bare, and the tail is bare when empty (`,,,,,`).

```
time_created,dst_computer,event_type,event_id,logon_type,target_user_name,target_domain_name,src_computer,src_ip,subject_user_name,subject_domain_name,logon_id,detail,log_filename,hunt,hunt_score,hunt_why,verdict,notes
2026-10-28 12:00:00.000,WS01,windows:persistence:registry_run_key,0,"",User,"","","",User,"","",C:\Users\bob\bob.exe,…\entry_50_0\NTUSER.DAT,candidate,24,rule H3003 (medium): Executes from a user profile folder or a hidden directory [T1564.001]; written after the baseline,,
2026-10-28 12:00:00.000,WS01,windows:persistence:windows_service,0,"",System,"","","",System,"","",C:\Windows\Temp\evilsvc.exe,HKLM\SYSTEM\CurrentControlSet\Services\EvilSvc,significant,100,rule H1009 (high): Script run from a user-writable folder [T1059]; rule H3001 (high): Persistence from a scratch folder [T1547]; rule H1015 (medium): Runs as SYSTEM from a user-writable folder [T1053.005]; written after the baseline,confirmed,"#ir-4711 dropper, see ticket"
"",WS01,windows:persistence:deleted:deleted_registry_persistence,0,"",Unknown,"","","",Unknown,"","",C:\Users\Public\d.exe -s,deleted value Dropper (key unknown),significant,100,rule H3001 (high): Persistence from a scratch folder [T1547]; rule H3014 (low): No longer present on the live system [T1070]; deleted,,
2026-09-30 08:15:42.000,WS01,windows:persistence:carved:registry_run_key,0,"",System,"","","",System,"","",C:\ProgramData\upd.exe,"carved SOFTWARE hive written 2026-09-30 08:15:42.000 at offset 0x1c3f80000 (71303168 bytes, 17408 bin(s), complete): …\carved\carved_0001c3f80000_SOFTWARE.regf",candidate,20,rule H3002 (low): Executes from AppData, ProgramData, a home or a hidden folder [T1547]; rule H3014 (low): No longer present on the live system [T1070]; carved,,
2026-10-28 12:00:00.000,WS01,windows:persistence:registry_run_key,0,"",User,"","","",User,"","",C:\Windows\system32\SecurityHealthSystray.exe,…\NTUSER.DAT,habitual,0,stock Windows entry,,
2026-03-02 09:10:00.000,WS01,windows:persistence:windows_service,0,"",System,"","","",System,"","","""C:\Program Files\Common Files\Adobe\ARM\1.0\armsvc.exe""",…\SYSTEM,baseline,0,before the baseline,,
```

## Diagnostics

Anything that degrades a run is printed to stderr with a code, a number and a severity, and summarised at the end:

```
[WARN]  [ERR_WIN_TX_LOG_NOT_FOUND - 3028] Dirty hive but no .LOG1/.LOG2 could be located for: …\SYSTEM
[INFO]  [ERR_WIN_HIVE_RECOVERED - 3048] Dirty hive rebuilt from transaction logs: …\SOFTWARE using …\SOFTWARE.LOG1, …\SOFTWARE.LOG2
🩺 Diagnostics: 0 error(s), 1 warning(s), 6 info(s)
```

| Severity | Meaning |
|---|---|
| `ERROR` | An artifact could not be processed at all |
| `WARN` | Processed in degraded mode (dirty hive without logs, control set missing, parser panic caught) |
| `INFO` | Nothing lost (companion file skipped, log matched outside the hive folder, hive rebuilt). Shown with `--verbose` |

The catalogue is in `src/errors.rs`: `1xxx` system, `2xxx` ingestion, `3xxx` Windows registry, `4xxx` Linux, `5xxx` output, `6xxx` CLI, `7xxx` hunting.

## How it works

**Transaction logs.** A hive copied from a running system is almost always dirty: the last writes only exist in `.LOG1` / `.LOG2`. Faramir looks for the logs next to the hive, then anywhere under the evidence root, ranks the candidates by name and path, and keeps only the ones whose embedded hive name matches (so another user's `NTUSER.DAT.LOG1` is rejected). Every `HvLE` entry is checked before the parser sees it; a damaged tail is cut off and the valid prefix replayed. The replay runs in memory with [blockcarve](https://github.com/jupyterj0nes/blockcarve)'s `hive_logs` (the one caarea and masstin use): entries in consecutive sequence order, a gap stops it; an old-format (`DIRT`) log of Windows 7 / 8 is applied when its timestamp matches the hive. If nothing usable exists, the hive is scanned as it is on disk and the reason is logged.

**Right hive, right root.** Each technique declares the registry root its paths belong to. A Run key is read from `NTUSER.DAT` as `SOFTWARE\Microsoft\...` and from the `SOFTWARE` hive as `Microsoft\...`, never the other way round. A hive of unknown kind is tried against every root.

**Deleted cells.** When a key or value is deleted, Windows only flips the sign of its cell size. Faramir walks every hive bin with its own bounds-checked parser, puts deleted keys back on their path through the parent chain, and reports the ones under a persistence location, plus orphan values whose data looks like a command line.

**Shadow copies.** Every snapshot of an NTFS partition goes through the same extraction as the live volume. A finding that exists only in a snapshot is reported once, with the snapshot's creation time.

**ext4 journal.** When ext4 deletes a file it zeroes the inode's extent tree, so the live inode table leads nowhere. The jbd2 journal, though, is a write-ahead log of metadata blocks: for every transaction it keeps the inode table blocks (size, times, extents) and directory blocks (name, inode number) as they were committed. Faramir walks the whole journal area, old transactions included, maps every copy to the inode table or the directory it belongs to, and compares against the live tree. A name that is gone, or that points at another inode now, is a deleted or replaced file: its last inode copy before the deletion (same generation, so a recycled inode number is not confused with a new file) gives size, mtime and extents; if those blocks are still free, the content is read back and the file goes through the same parsers as a live one, tagged `linux:deleted:…` with its deletion time, or `linux:previous_version:…`. A live file whose journal copies point at freed blocks yields its previous content the same way. Directory slack (what an older kernel leaves after `rm`) is read too. The journal is small and circular, so this covers the last hours or days, like a shadow copy does.

**Linux volumes.** Each partition is sniffed for what it holds (NTFS, ext, LVM, XFS, btrfs, LUKS, swap, FAT). An ext volume is opened with `ext4-view` and the files the Linux techniques read are copied out keeping their tree, following symlinked units but not symlinked directories, and skipping `/lib`, `/bin` and `/sbin` when they are the usr-merge links. An XFS volume is mounted read-only with the `rust-fs-xfs` driver (short-form, block, leaf and node directories, extent and B+tree forks, v5 checksums) and walked the same way. An LVM physical volume is parsed with the `lvm2` crate and every linear logical volume with an ext or XFS signature is read in place through its extent map, no temporary dump. One image reader is shared by the NTFS, VSS, ext and XFS code paths. The same layout masstin uses for its Linux logs.

**Carving.** With `--carve`, the image is read in 4 MB blocks and every sector-aligned `regf` signature is checked: primary hive, supported version, sane sizes, a hive bin right behind it. Each bin carries its own offset, so a hive is pulled out by following the chain and stops exactly where the chain breaks; the root key is verified before anything is kept. A truncated hive keeps its valid prefix and says so. Copies identical to a hive extracted from the live file system are skipped; a copy that only matches a shadow-copy hive is still carved, because a deleted hive seen in a snapshot and in the raw bytes is two pieces of evidence. Carved hives are written to the staging folder and go through the normal pipeline, transaction-log search included. A carved finding identical to a live one (same technique, location, value and access) is dropped and counted. On E01 images every read runs with a time budget, so a damaged segment costs a skipped window instead of a hung run. The block scanner and the guarded reader are the EVTX carver design from masstin.

## Testing

```bash
cargo test
```

1150+ tests. The suite builds its own hives and transaction logs (a small regf/HvLE writer with real Marvin32 hashes), replays a real Windows 10 dirty hive and compares the result with `rla.exe` byte for byte, replays a real Windows 7 dirty hive and compares it with the copy Windows 7 recovered, cross-checks deleted-cell recovery with `RECmd --recover`, runs a synthetic Cortex XDR package through the binary end to end, reads synthetic VHD, VHDX and VMDK images through the NTFS extractor, and carves hives out of synthetic disks with bad sectors, stalled reads, overwritten bins and copies cut by the end of the image, and checks the 17 techniques added after the IRFlow and Autoruns comparison (browser profiles and policy files included) against synthetic hives and trees. The hunt is tested rule by rule (every rule has a row that fires it and stock rows that do not), on a synthetic 40-host fleet where the one odd service comes out `significant` and forty ordinary vendor agents come out `habitual`, on a single host with and without a baseline, on the stock Ubuntu rows a real collection produced, and through the binary with a UAC tree, `--baseline`, `--known-good`, `--carry-marks` and `--no-hunt`. `scripts/carve_lab.ps1` builds a real NTFS volume on a Windows host (saved hives, a shadow copy, deletions with TRIM off) and `cargo test --test test_carve_lab -- --ignored` with `FARAMIR_CARVELAB` pointing at its output checks every carved hive against the clusters NTFS had given the file. `scripts/linux_collect.sh` makes a read-only UAC-style collection of a Linux host; the one taken from an Ubuntu 22.04 domain member is what the usr-merge deduplication, host-relative paths and timestamp format were corrected against. `scripts/linux_disk_lab.sh` builds, on a Linux host, a GPT+ext4 image and an MBR+LVM+ext4 image with one canary per technique (both ship as fixtures under `tests/fixtures/linux_disk/`) plus a 256 MB ext4 image of that host's real configuration for `cargo test --test test_linux_disk -- --ignored` with `FARAMIR_LINUXDISK`.

## Credits

- [Boromir](https://github.com/Alexgpsec/Persistence_Boromir) and the first Faramir Rust port: [@Alexgpsec](https://github.com/Alexgpsec) (Alejandro Gamboa)
- Boromir co-author, evidence ingestion, Linux suite, timeline format, hive recovery and the readers ported from masstin: [@jupyterj0nes](https://github.com/jupyterj0nes)
- Dirty-hive test vector from [nt_hive2](https://codeberg.org/janstarke/nt_hive2), the registry parser Faramir is built on
- Windows 7 dirty-hive test vector from [yarp](https://github.com/msuhanov/yarp)

## License

GNU General Public License v3.0
