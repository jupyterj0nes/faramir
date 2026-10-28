<div align="center">

# ⚔️ Faramir

**Persistence hunting for DFIR, from any evidence you have.**

Point it at a disk image, a triage zip or a mounted drive. Get back one timeline
of every autostart, hijack and backdoor on the box, Windows and Linux, ready for
[Masstin](https://github.com/jupyterj0nes/masstin) and [Caarea](https://github.com/jupyterj0nes/caarea).

![Rust](https://img.shields.io/badge/Rust-stable-orange?logo=rust)
![Platforms](https://img.shields.io/badge/evidence-Windows%20%7C%20Linux-blue)
![Tests](https://img.shields.io/badge/tests-906%20passing-brightgreen)
![License](https://img.shields.io/badge/license-GPL--3.0-lightgrey)

> *"The younger brother, wiser and swifter."* Faramir is the Rust rewrite of
> [Boromir](https://github.com/Alexgpsec/Persistence_Boromir): a single binary,
> no runtime, native speed, and it reads the evidence itself instead of asking
> you to mount it.

</div>

---

## Why Faramir

| | What it means for you |
|---|---|
| **One command, any evidence** | `.E01`, raw `dd`, KAPE / Velociraptor / Cortex XDR / UAC packages, nested zips, a mounted volume or a single hive. Faramir detects what it was given, stages it and runs. |
| **Dirty hives are rebuilt, not ignored** | Live-collected hives carry their last writes only in `.LOG1`/`.LOG2`. Faramir finds those logs wherever the collector put them, verifies they belong to the hive, and replays them. The result is byte-identical to Eric Zimmerman's `rla.exe`. |
| **60+ techniques, each read from the right hive** | Every registry path is declared relative to its root (`HKLM\SOFTWARE`, `HKLM\SYSTEM`, `HKCU`, `UsrClass`), so a Run key is read from `NTUSER.DAT` as HKCU and from `SOFTWARE` as HKLM, never the other way round. |
| **Nothing fails silently** | 90+ numbered diagnostic codes with a severity. A corrupt log, a renamed hive, a technique with no hive to read: you are told, the run finishes anyway. |
| **Drops straight into your timeline** | The CSV has the same ten columns as Masstin and Caarea, so persistence sits next to logons and lateral movement in one view. |

---

## Quick start

```bash
cargo build --release          # Rust stable, pinned by rust-toolchain.toml
```

```bash
# A forensic image
faramir -f /cases/HRSERVER.E01 -o /cases/hrserver_persistence.csv

# A KAPE, Velociraptor, Cortex XDR or UAC package (nested zips included)
faramir -f /cases/offline_collector_output_WS01_2026-10-28_12-00-00.zip -o ws01.csv

# A mounted volume, Windows or Linux
faramir -d /mnt/evidence/C -o persistence.csv

# A single hive you carved out by hand, with its logs next to it
faramir -f /cases/SOFTWARE -o software.csv

# One technique only
faramir -d /mnt/evidence/C get-run
```

Several `-d` / `-f` can be combined in one run; every finding carries the host
it came from.

---

## What happens when you run it

```
 evidence ──► detect & stage ──► find hives ──► rebuild dirty hives ──► 35 Windows techniques ──► timeline.csv
   E01 ─┐      KAPE / Velociraptor      name + regf      locate LOG1/LOG2       + Linux suite         Masstin / Caarea
   zip ─┤      Cortex XDR / UAC        header sniff     verify by header         per-root paths        10 columns
   dir ─┘      nested archives         any file name    validate HvLE
```

1. **Detect & stage.** Images are opened directly (EWF/E01 or raw), NTFS is
   parsed, and the registry, user hives, event logs, Amcache and scheduled tasks
   are pulled out. Archives are unpacked keeping only forensic artifacts;
   nested archives such as Cortex XDR's `script_output.zip` per module are
   expanded in place. Known forensic zip passwords (`infected`, …) are tried.
2. **Find hives.** A file is a hive if its name says so *or* its header does.
   `bob_NTUSER.DAT`, `HOST-SOFTWARE`, `C_Windows_System32_config_SYSTEM`,
   `SOFTWARE.hve` and `artifact_0017.bin` are all recognised; the kind comes from
   the path Windows embeds in the regf base block.
3. **Rebuild dirty hives.** See [Transaction logs](#transaction-logs-the-part-everyone-gets-wrong).
4. **Hunt.** Each technique runs against the hives of the kind it needs; a hive
   of unknown kind is tried against every root so a renamed hive never loses a
   detection. Parser panics on corrupt data are caught per hive and per
   technique.
5. **Timeline.** Findings become events sorted by time, one host name per
   evidence source (taken from the collector's own naming when available).

---

## Transaction logs: the part everyone gets wrong

A hive copied from a running system is almost always *dirty*: its primary and
secondary sequence numbers differ and the most recent keys only exist in
`.LOG1` / `.LOG2`. Skip the logs and the last autostart the attacker wrote is
simply not there.

Collectors make this hard. Image extraction renames user hives
(`bob_NTUSER.DAT`), flattened collectors produce
`C_Windows_System32_config_SOFTWARE.LOG1`, Cortex XDR puts every file in its own
`entry_<N>_<M>/` folder so hive and log are never adjacent, and ten users give
you ten identical `NTUSER.DAT.LOG1`.

Faramir handles all of it:

| Step | What Faramir does | Diagnostic |
|---|---|---|
| Locate | Looks next to the hive, then indexes every `.LOG1`/`.LOG2` under the evidence root and ranks candidates by name and path similarity | `ERR_WIN_TX_LOG_REMOTE_MATCH` |
| Attribute | Compares the hive name embedded in the log's base block with the hive's own, so another user's log is rejected | `ERR_WIN_TX_LOG_HIVE_MISMATCH` |
| Validate | Checks every `HvLE` entry (sizes, page references, sequence chain) before the parser sees it; a damaged tail is cut and the valid prefix replayed | `ERR_WIN_TX_LOG_TRUNCATED`, `ERR_WIN_TX_LOG_PARTIAL` |
| Replay | Applies LOG1 and LOG2 in sequence order, reconciling the chain across both files | `ERR_WIN_HIVE_RECOVERED` |
| Degrade | If nothing usable exists the hive is still scanned in its on-disk state and you are told exactly why | `ERR_WIN_TX_LOG_NOT_FOUND`, `ERR_WIN_HIVE_DIRTY` |

The test-suite replays a real Windows 10 dirty hive and compares the result
with `rla.exe` byte for byte.

---

## Windows techniques

Run everything with `all` (the default) or pick one action.

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

Every HKCU path is also read from the `DEFAULT` hive (what SYSTEM-context
logons see), every `SOFTWARE` path from `Wow6432Node` where it exists.

### What the attacker removed

Two more sources run inside `all` and never need an extra flag:

| Source | Action | What it finds |
|---|---|---|
| **Deleted cells** | `get-deleted-persistence` | Keys and values whose cells were freed but not yet overwritten, walked with a bounds-checked parser of every hive bin. A deleted key is placed back on its path through the parent chain and matched against the persistence locations above; orphan deleted values are kept when their data looks like a command line. Reported as `windows:persistence:deleted:<technique>`. |
| **Volume Shadow Copies** | automatic on images | Every snapshot of an NTFS partition is extracted like the live volume (`partition_<n>_vss_<m>/`). A persistence item that exists in a snapshot but not on the live volume is reported once, as `windows:persistence:removed_since_vss:<technique>`, with the snapshot's creation time. |

---

## Linux techniques

`get-linux-persistence` (included in `all`) runs on a mounted root, a UAC
package or any folder with the usual `etc/`, `var/`, `home/` layout.

| Area | Artifacts |
|---|---|
| **Scheduled** | `/etc/crontab`, `cron.d`, user spools, `cron.{hourly,daily,weekly,monthly}`, anacron |
| **systemd** | services, timers, sockets, paths, generators |
| **Shell & session** | `/etc/profile`, `profile.d`, `bashrc` / `zshrc` / `.profile`, `rc.local`, XDG autostart |
| **Credentials & access** | `authorized_keys`, `AuthorizedKeysCommand`, `ForceCommand`, sudoers `NOPASSWD` and `Defaults` overrides, PAM `pam_exec` backdoors, `pam_permit` bypasses, custom module paths |
| **Kernel & libraries** | `ld.so.preload`, `modules-load.d`, `modprobe.d` `install` commands, udev `RUN` actions |
| **Package manager** | APT hooks |
| **Live state** | processes running a deleted binary, execution from `/tmp` |

---

## Evidence formats

| Input | How it is handled |
|---|---|
| `.E01` / `.Ex01` | Opened with the EWF reader, NTFS parsed in place; MBR and GPT partitions, BitLocker volumes reported and skipped, every Volume Shadow Copy extracted and diffed against the live volume |
| `.dd` `.raw` `.img` `.001` | Raw and split-raw images |
| `.vmdk` | Monolithic or split, sparse or flat, streamOptimized (compressed); snapshots, `-flat` and `-sNNN` extents are read through their descriptor |
| `.vhd` `.vhdx` | Fixed and dynamic; differencing disks are reported as incomplete |
| `.zip` `.tar` `.tar.gz` `.tgz` | Only forensic artifacts are extracted; nested archives expanded in place; encrypted zips tried with known forensic passwords |
| KAPE, Velociraptor, Cortex XDR, CyLR, UAC | Detected from their markers; the host name is taken from the package |
| Directory | Mounted volume or already-extracted collection, Windows or Linux |
| Single file | A hive (with its logs beside it), a systemd unit, a crontab, a profile |

---

## Output

One CSV, ten columns, the same schema as Masstin and Caarea:

| Column | Example |
|---|---|
| `timestamp` | `2024-01-17 21:20:00.000` (key last-write time) |
| `computer` | `WS01` |
| `artifact` | `windows:persistence:registry_run_key`, `linux:ssh:authorized_key` |
| `event_id` / `pid` | `0` for persistence rows |
| `subject_username` / `target_username` | `System`, `User`, `root` |
| `processname` | `updater.exe` |
| `commandline` | `C:\ProgramData\updater.exe --silent` |
| `parentprocessname` | Where it was found: the hive path, the key, the unit file |

```
"2026-10-28 12:00:00.000","WS01","windows:persistence:registry_run_key",0,0,"User","User","bob.exe","C:\Users\bob\bob.exe","…\entry_50_0\NTUSER.DAT"
"2026-10-28 12:00:00.000","WS01","windows:persistence:windows_service",0,0,"System","System","EvilSvc","EvilSvc","C:\Windows\Temp\evilsvc.exe"
```

---

## Diagnostics

Everything that degrades a run is printed to stderr with a code, a number and
a severity, and summarised at the end:

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

The catalogue lives in `src/errors.rs`: `1xxx` system, `2xxx` ingestion,
`3xxx` Windows registry, `4xxx` Linux, `5xxx` output, `6xxx` CLI.

---

## Options

| Option | Description |
|---|---|
| `-d, --directory <DIR>` | Directory, mounted volume or extracted collection (repeatable) |
| `-f, --file <FILE>` | Image, archive or single artifact (repeatable) |
| `-o, --output <FILE>` | Output CSV (default `faramir.output.csv`) |
| `--verbose` | Also print `INFO` diagnostics |
| `--silent` | No console output |
| `--source-evidence`, `--csv-output` | Legacy Boromir flags, still accepted |
| `[ACTION]` | `all` (default), any `get-*` technique, `get-deleted-persistence`, `get-linux-persistence` |

---

## How it is tested

906 tests, all green on stable Rust:

- a **synthetic regf and HvLE writer** builds hives and transaction logs with
  real Marvin32 hashes, so every technique is exercised in the right hive and
  in the wrong one;
- a **real Windows 10 dirty hive** with its LOG1 and LOG2 is replayed and
  compared with `rla.exe` output byte for byte;
- a **synthetic Cortex XDR offline-collector package** with hives and logs in
  separate `entry_` folders and two users with identical file names, run
  through the real binary end to end;
- collector layouts (KAPE, Velociraptor, image dumps, flattened names),
  truncated and garbage logs, checksum-damaged hives, renamed hives, and the
  full error-code catalogue;
- **synthetic virtual disks**: fixed and dynamic VHD, dynamic VHDX, split and
  descriptor-only VMDK, read back through the same path the NTFS extractor uses.

```bash
cargo test
```

---

## Credits

- [Boromir](https://github.com/Alexgpsec/Persistence_Boromir) and the Faramir
  Rust rewrite: [@Alexgpsec](https://github.com/Alexgpsec) (Alejandro Gamboa)
- Boromir co-author, ingestion, Linux suite, timeline format and the hive
  recovery engine: [@jupyterj0nes](https://github.com/jupyterj0nes)
- Inspired by [Persistence Sniper](https://github.com/last-byte/PersistenceSniper),
  [Masstin](https://github.com/jupyterj0nes/masstin) and
  [Caarea](https://github.com/jupyterj0nes/caarea)
- Dirty-hive test vector from [nt_hive2](https://codeberg.org/janstarke/nt_hive2),
  the registry parser Faramir is built on

## License

GNU General Public License v3.0
