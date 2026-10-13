use crate::event::Event;
use crate::utils::escape_csv;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;

/// Exports the timeline to a CSV file matching Caarea standard format
pub fn export_timeline(events: &[Event], output_file: &Path, silent: bool) -> std::io::Result<()> {
    if let Some(parent) = output_file.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let file = File::create(output_file)?;
    let mut writer = BufWriter::new(file);

    // Write the CSV header with unified artifact column
    writeln!(
        writer,
        "\"timestamp\",\"computer\",\"artifact\",\"event_id\",\"pid\",\"subject_username\",\
        \"target_username\",\"processname\",\"commandline\",\"parentprocessname\""
    )?;

    // Save each event to the file with properly escaped CSV cells
    for event in events {
        writeln!(
            writer,
            "\"{}\",\"{}\",\"{}\",{},{},\"{}\",\"{}\",\"{}\",\"{}\",\"{}\"",
            escape_csv(&event.timestamp),
            escape_csv(&event.computer),
            escape_csv(&event.artifact),
            event.event_id,
            event.pid,
            escape_csv(&event.subject_username),
            escape_csv(&event.target_username),
            escape_csv(&event.processname),
            escape_csv(event.commandline.as_deref().unwrap_or("N/A")),
            escape_csv(&event.parentprocessname)
        )?;
    }

    if !silent {
        println!("✅ Timeline successfully saved to: {}", output_file.display());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    #[test]
    fn test_export_timeline_format() {
        let temp_dir = std::env::temp_dir();
        let test_csv = temp_dir.join(format!("test_timeline_{}.csv", chrono::Utc::now().timestamp_millis()));

        let events = vec![Event {
            timestamp: "2026-10-13 10:00:00.000".to_string(),
            computer: "WIN-SRV01".to_string(),
            artifact: "windows:persistence:registry_run_key".to_string(),
            event_id: 0,
            pid: 0,
            subject_username: "User".to_string(),
            target_username: "User".to_string(),
            processname: "malware.exe".to_string(),
            commandline: Some("C:\\Users\\Admin\\malware.exe -d".to_string()),
            parentprocessname: "RunKey".to_string(),
        }];

        export_timeline(&events, &test_csv, true).expect("Failed to export timeline");

        let mut content = String::new();
        let mut file = File::open(&test_csv).expect("Failed to open test csv");
        file.read_to_string(&mut content).expect("Failed to read test csv");

        let _ = std::fs::remove_file(&test_csv);

        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 2);
        assert_eq!(
            lines[0],
            "\"timestamp\",\"computer\",\"artifact\",\"event_id\",\"pid\",\"subject_username\",\"target_username\",\"processname\",\"commandline\",\"parentprocessname\""
        );
        assert!(lines[1].contains("\"2026-10-13 10:00:00.000\",\"WIN-SRV01\",\"windows:persistence:registry_run_key\",0,0,\"User\",\"User\",\"malware.exe\",\"C:\\Users\\Admin\\malware.exe -d\",\"RunKey\""));
    }
}
