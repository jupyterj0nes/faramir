//! What a rule adds to `hunt_score`: how rare its pattern is on clean
//! reference rows, the convention of the four tools (masstin
//! `docs/csv-format.md`, "The same tail in caarea, faramir and allymacb").
//!
//! `hunt_score` is `-10 · log10` of a probability, 0 to 100. The statistical
//! test contributes `-10 · log10(q)`. A rule contributes the same scale
//! **measured, not chosen**: the share of clean reference rows of the row's
//! system its pattern fires on, `-10 · log10(hits / rows)`. A pattern that
//! never fired is not "never": the corpus bounds what it can say, so it gets
//! `-10 · log10(1 / (rows + 1))`, 33 points on the Windows reference below,
//! 29 on the Linux one. A
//! rule measured below [`NOISE_BELOW`] points fires on more than one clean
//! row in ten: noise on that system, it gives no state and no points, only
//! its clause in `hunt_why`. The level of a rule (high, medium, low) stays
//! the author's claim and decides the state; the measurement decides the
//! points.
//!
//! How the tables were measured (2026-11-03): `faramir -d <volume>` over each
//! reference, then the rows that fired each rule id counted from `hunt_why`
//! (a row counts once per rule), the lab's own plants left out. Re-measure
//! when the catalogue or a reference changes, and keep the descriptions
//! with the tables.

use super::normalize::Os;

/// A rule measured below this many points is noise on that system.
pub const NOISE_BELOW: u32 = 10;

/// The Windows reference: two clean Windows Server 2016 hosts of the
/// RangeForge lab, a member server (SQL Server Express, IIS) and a domain
/// controller, collected live on 2026-11-03 and laid out as a volume:
/// SYSTEM, SOFTWARE, SAM, SECURITY, DEFAULT, Amcache, every NTUSER.DAT and
/// UsrClass.dat, the Tasks folder, the Startup folders. 2,004 rows:
/// services, service DLLs, scheduled tasks (live and deleted), Group Policy
/// extension DLLs, shell extensions, netsh helpers, COM TreatAs, App Paths,
/// Active Setup, credential providers, failure commands, Office add-ins,
/// AeDebug, hhctrl, Winlogon, LSA, boot execute. The one task the lab
/// planted (its beacon) is left out.
pub const REFERENCE_WINDOWS: &str = "PTR-SRV01 and PTR-DC01, Windows Server 2016, live collection 2026-11-03, the lab's beacon task left out";
pub const ROWS_WINDOWS: u32 = 2_003;

/// The Linux reference: the UAC collection of LEO-LNX01 (Ubuntu, RangeForge
/// lab, 2026-10-28, `samples/linuxlab`): systemd units, timers, sockets,
/// generators, udev run actions, cron, package hooks, sudoers. The six rows
/// the lab wrote after 2026-10-20 are left out.
pub const REFERENCE_LINUX: &str = "LEO-LNX01 UAC collection, 2026-10-28, lab rows left out";
pub const ROWS_LINUX: u32 = 761;

/// Rows of the Windows reference each rule fired on. A rule not listed
/// never fired there.
pub const MEASURED_WINDOWS: &[(&str, u32)] = &[
    ("H1004", 2),
    ("H1006", 4),
    ("H1011", 4),
    ("H1012", 10),
    ("H1015", 6),
    ("H3002", 6),
    ("H3006", 2),
    ("H3013", 17),
    ("H3014", 19),
    ("H3015", 4),
];

/// Rows of the Linux reference each rule fired on. A rule not listed never
/// fired there.
pub const MEASURED_LINUX: &[(&str, u32)] = &[("H2008", 3), ("H2012", 1), ("H3002", 1), ("H3013", 4)];

/// The points of a pattern that fired `hits` times on `rows` reference rows:
/// `-10 · log10(hits / rows)`, rounded, 0 to 100; the bound the corpus gives
/// when it never fired.
pub fn points_for(hits: u32, rows: u32) -> u32 {
    if rows == 0 {
        return 0;
    }
    let (h, n) = if hits == 0 { (1.0, rows as f64 + 1.0) } else { (hits as f64, rows as f64) };
    (-10.0 * (h / n).log10()).round().clamp(0.0, 100.0) as u32
}

fn lookup(table: &[(&str, u32)], id: &str, rows: u32) -> u32 {
    let hits = table.iter().find(|(k, _)| *k == id).map(|(_, h)| *h).unwrap_or(0);
    points_for(hits, rows)
}

/// What rule `id` adds to `hunt_score` on a row of system `os`. A row of an
/// unknown system gets the lower of the two measurements.
pub fn points(id: &str, os: Os) -> u32 {
    match os {
        Os::Windows => lookup(MEASURED_WINDOWS, id, ROWS_WINDOWS),
        Os::Linux => lookup(MEASURED_LINUX, id, ROWS_LINUX),
        Os::Unknown => lookup(MEASURED_WINDOWS, id, ROWS_WINDOWS).min(lookup(MEASURED_LINUX, id, ROWS_LINUX)),
    }
}

/// Whether the rule counts on that system: measured at `NOISE_BELOW` or more.
pub fn counts(id: &str, os: Os) -> bool {
    points(id, os) >= NOISE_BELOW
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scale_follows_masstin() {
        assert_eq!(points_for(1, 128), 21);
        assert_eq!(points_for(1, 1_000), 30);
        assert_eq!(points_for(0, 2_003), 33, "never fired: the bound 2,003 rows give");
        assert_eq!(points_for(0, 761), 29);
        assert_eq!(points_for(290, 748), 4, "a rule that fires on four clean rows in ten would be noise");
        assert_eq!(points_for(19, 2_003), 20, "H3014, the most common pattern on the Windows reference, still counts");
        assert_eq!(points_for(1_000, 1_000), 0);
        assert_eq!(points_for(0, 0), 0);
    }

    #[test]
    fn tables_name_real_rules_and_answer_per_system() {
        for (id, _) in MEASURED_WINDOWS.iter().chain(MEASURED_LINUX) {
            assert!(super::super::rules::by_id(id).is_some(), "{id} is not in the catalogue");
        }
        for t in [MEASURED_WINDOWS, MEASURED_LINUX] {
            for w in t.windows(2) {
                assert!(w[0].0 < w[1].0, "{} before {}", w[0].0, w[1].0);
            }
        }
        assert_eq!(points("H1011", Os::Windows), 27);
        assert!(counts("H1011", Os::Windows));
        assert_eq!(points("H1001", Os::Windows), 33);
        assert!(counts("H1001", Os::Windows));
        assert_eq!(points("H1001", Os::Linux), 29);
        assert_eq!(points("H3013", Os::Windows), 21);
        assert_eq!(points("H3013", Os::Linux), 23);
        assert_eq!(points("H3013", Os::Unknown), 21);
        assert_eq!(points("H2008", Os::Linux), 24);
        for (id, hits) in MEASURED_WINDOWS {
            assert!(points_for(*hits, ROWS_WINDOWS) >= NOISE_BELOW, "{id} is not noise on the Windows reference");
        }
    }
}
