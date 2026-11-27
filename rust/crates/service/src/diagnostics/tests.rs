use super::*;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;

struct Fixture {
    _temp: tempfile::TempDir,
    root: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().to_path_buf();
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let f = Fixture { _temp: temp, root };
        let run = f.root.join("current/runtime/native-20261108-110000");
        f.write("service.json", &json!({"directory": util::text(&run), "phase": "running"}));
        f.write("current/runtime/native-20261108-110000/backend-status.json",
            &json!({"phase": "ready", "attempt": 1, "ready": true, "directory": "backend-000001"}));
        f
    }

    fn file(&self, name: &str, data: &[u8]) -> PathBuf {
        let path = self.root.join(name);
        let mut parent = path.parent().unwrap().to_path_buf();
        std::fs::create_dir_all(&parent).unwrap();
        while parent.starts_with(&self.root) {
            std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o700)).unwrap();
            if !parent.pop() {
                break;
            }
        }
        std::fs::write(&path, data).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        path
    }

    fn write(&self, name: &str, value: &Value) -> PathBuf {
        self.file(name, value.to_string().as_bytes())
    }

    fn collect(&self, cursor: &Value) -> Value {
        collect(Some(&self.root), cursor)
    }
}

fn messages(value: &Value) -> Vec<String> {
    value["entries"].as_array().unwrap().iter().map(|e| e["message"].as_str().unwrap().to_string()).collect()
}

fn cursor(value: &Value) -> Value {
    value["cursor"].clone()
}

#[test]
fn hardware_snapshot_is_persisted_without_a_cursor() {
    let f = Fixture::new();
    let report = json!({"schema_version": 1, "wifi": {"status": "unknown", "reason": "timeout"}, "native_mirroring_verified": null});
    let snapshot = hardware_snapshot(Some(&f.root), report.clone());
    assert!(snapshot.get("cursor").is_none());
    assert_eq!(snapshot["ok"], true);
    let decoded: Vec<Value> = messages(&snapshot).iter().map(|m| serde_json::from_str(m).unwrap()).collect();
    assert!(decoded.contains(&json!({"wifi": report["wifi"]})));
    assert_eq!(messages(&snapshot)[1], r#"{"wifi":{"status":"unknown","reason":"timeout"}}"#);
    let files: Vec<_> = std::fs::read_dir(f.root.join("logs")).unwrap().map(|e| e.unwrap().path()).collect();
    assert_eq!(files.len(), 1);
    assert!(files[0].file_name().unwrap().to_str().unwrap().starts_with("native-"));
    assert_eq!(std::fs::metadata(&files[0]).unwrap().permissions().mode() & 0o777, 0o600);
    let saved: Vec<String> = std::fs::read_to_string(&files[0]).unwrap().lines()
        .map(|l| serde_json::from_str::<Value>(l).unwrap()["message"].as_str().unwrap().to_string()).collect();
    assert_eq!(saved, messages(&snapshot));
}

#[test]
fn large_hardware_lists_remain_complete_json_without_truncation() {
    let f = Fixture::new();
    let drivers: Vec<Value> = (0..128).map(|i| json!({"bundle_identifier": format!("example.{}{}", "x".repeat(100), i), "loaded_version": "1.2"})).collect();
    let names: Vec<Value> = (0..16).map(|_| Value::from(format!("GPU {}", "\u{1f600}".repeat(200)))).collect();
    let snapshot = hardware_snapshot(Some(&f.root), json!({"loaded_drivers": {"entries": drivers}, "gpu_names": names}));
    let (mut recovered, mut recovered_names) = (Vec::new(), Vec::new());
    for message in messages(&snapshot) {
        assert!(message.len() <= MAX_MESSAGE && message.is_ascii());
        let decoded: Value = serde_json::from_str(&message).unwrap();
        for (key, value) in decoded.as_object().unwrap() {
            if let Value::Array(items) = value {
                if key.starts_with("gpu_names") { recovered_names.extend(items.clone()) } else { recovered.extend(items.clone()) }
            }
        }
    }
    assert_eq!(recovered, drivers);
    assert_eq!(recovered_names, names);
    assert!(snapshot["entries"].as_array().unwrap().len() < 160);
}

#[test]
fn hardware_storage_failure_preserves_snapshot_without_paths() {
    let f = Fixture::new();
    std::os::unix::fs::symlink(&f.root, f.root.join("logs")).unwrap();
    let snapshot = hardware_snapshot(Some(&f.root), json!({"wifi": {"status": "unknown"}}));
    assert_eq!(snapshot["ok"], true);
    assert!(snapshot["entries"].as_array().unwrap().iter().any(|e| e["level"] == "warning"));
    assert!(!pyjson::dumps(&snapshot).contains(&util::text(&f.root)));
}

#[test]
fn decoder_state_selects_public_fields_once() {
    let f = Fixture::new();
    let video = json!({"session_created": true, "creation_status": 0, "frame_delivery_verified": null, "presentation_verified": null});
    f.write("current/runtime/native-20261108-110000/decoder-route.json", &json!({"mode": "no_fls", "ready": true,
        "native_video_observations": video, "stage": "private-path", "native_decoder_events": ["private-event"]}));
    let snapshot = f.collect(&json!({}));
    let row = snapshot["entries"].as_array().unwrap().iter().find(|r| r["source"] == "Decoder").unwrap();
    let message: Value = serde_json::from_str(row["message"].as_str().unwrap()).unwrap();
    assert_eq!(message["native_video_observations"], video);
    assert!(!row["message"].as_str().unwrap().contains("private"));
    let again = f.collect(&cursor(&snapshot));
    assert!(!again["entries"].as_array().unwrap().iter().any(|r| r["source"] == "Decoder"));
}

#[test]
fn live_setup_output_is_read_without_repeating_unchanged_lines() {
    let f = Fixture::new();
    let path = f.file("logs/setup.log", br#"{"source":"SSH stderr","message":"debug1: Authentication succeeded (publickey).","timestamp":"2026-11-08T04:00:00.000000+00:00","level":"debug"}
"#);
    let first = f.collect(&json!({}));
    assert!(messages(&first).iter().any(|m| m.contains("Authentication succeeded (publickey).")));
    assert!(f.collect(&cursor(&first))["entries"].as_array().unwrap().is_empty());
    std::fs::OpenOptions::new().append(true).open(&path).unwrap()
        .write_all(br#"{"source":"Certificate","message":"--issue-certificate begin","fields":{"path":"/var/mobile/certificate.der"}}
"#).unwrap();
    let second = f.collect(&cursor(&first));
    assert_eq!(messages(&second), [r#"--issue-certificate begin {"path": "/var/mobile/certificate.der"}"#]);
    assert_eq!(second["entries"][0]["source"], "Certificate");
}

#[test]
fn unknown_device_errors_are_preserved() {
    let message = "RuntimeError: A11 custom failure 0xe00002bc; aks_new_function unavailable";
    let rows = project_line(message.as_bytes(), "SSH");
    assert_eq!(rows[0].message, message);
    assert_eq!(rows[0].level, "error");
    assert!(project_line(br#"{"operation":"health","ready":true}"#, "Keys").is_empty());
    assert_eq!(project_line(br#"{"operation":"health","status":-7}"#, "Keys")[0].level, "error");
    assert_eq!(project_line(b"   ", "Keys"), Vec::<Entry>::new());
    assert_eq!(project_line(b"plain progress", "Keys")[0].level, "debug");
}

#[test]
fn recent_timestamped_output_is_retained_over_old_undated_tails() {
    let f = Fixture::new();
    f.file("logs/setup.log", b"{\"source\":\"SSH stderr\",\"message\":\"real current SSH result\",\"timestamp\":\"2026-11-08T04:00:00.000000+00:00\"}\n");
    let lines: Vec<u8> = (0..300).flat_map(|i| format!("old undated line {}\n", i).into_bytes()).collect();
    f.file("logs/service.log", &lines);
    let result = f.collect(&json!({}));
    assert!(messages(&result).iter().any(|m| m == "real current SSH result"));
    assert!(result["entries"].as_array().unwrap().len() <= MAX_ENTRIES);
}

#[test]
fn partial_line_waits_and_copy_truncate_regrowth_is_detected() {
    let f = Fixture::new();
    let path = f.file("logs/setup.log", b"first real line\npartial");
    let first = f.collect(&json!({}));
    assert!(messages(&first).contains(&"first real line".to_string()));
    assert!(!messages(&first).contains(&"partial".to_string()));
    std::fs::OpenOptions::new().append(true).open(&path).unwrap().write_all(b" finished\n").unwrap();
    let second = f.collect(&cursor(&first));
    assert_eq!(messages(&second)[0], "partial finished");
    assert!(second["entries"][0]["observed_at"].is_string());
    std::fs::write(&path, b"new after rotation, longer than the old offset\n").unwrap();
    let third = f.collect(&cursor(&second));
    assert_eq!(messages(&third)[0], "new after rotation, longer than the old offset");
}

#[test]
fn symlink_and_nonprivate_logs_are_not_followed() {
    let f = Fixture::new();
    let outside = f.root.join("private-target");
    std::fs::write(&outside, "not a log secret").unwrap();
    let logs = f.root.join("logs");
    std::fs::create_dir(&logs).unwrap();
    std::fs::set_permissions(&logs, std::fs::Permissions::from_mode(0o700)).unwrap();
    std::os::unix::fs::symlink(&outside, logs.join("setup.log")).unwrap();
    let result = f.collect(&json!({}));
    assert!(!pyjson::dumps(&result).contains("not a log secret"));
    assert!(result["entries"].as_array().unwrap().iter().any(|e| e["source"] == "Logs"));
    std::fs::remove_file(logs.join("setup.log")).unwrap();
    std::fs::write(logs.join("setup.log"), "public mode secret\n").unwrap();
    std::fs::set_permissions(logs.join("setup.log"), std::fs::Permissions::from_mode(0o644)).unwrap();
    let result = f.collect(&json!({}));
    assert!(!pyjson::dumps(&result).contains("public mode secret"));
    let error = result["entries"].as_array().unwrap().iter().find(|e| e["source"] == "Logs" && e["message"].as_str().unwrap().contains("setup.log")).unwrap();
    assert_eq!(error["message"], r#"{"file": "logs/setup.log", "error": "Diagnostic path is not private and user-owned"}"#);
}

#[test]
fn arbitrary_runtime_path_and_cursor_do_not_authorize_reads() {
    let f = Fixture::new();
    let outside = f.root.join("outside");
    f.write("service.json", &json!({"directory": util::text(&outside.join("native-20261108-110000"))}));
    f.file("outside/native-20261108-110000/app.log", b"outside secret\n");
    let result = f.collect(&json!({"files": {"../../private": {"offset": 0}}}));
    assert!(!pyjson::dumps(&result).contains("outside secret"));
    assert!(!pyjson::dumps(&result["cursor"]).contains("../../private"));
}

#[test]
fn tail_is_bounded_and_never_changes_files() {
    let f = Fixture::new();
    let data: Vec<u8> = (0..5000).flat_map(|i| format!("actual line {}\n", i).into_bytes()).collect();
    let path = f.file("logs/setup.log", &data);
    let states = std::fs::read(f.root.join("service.json")).unwrap();
    let result = f.collect(&json!({}));
    assert!(result["entries"].as_array().unwrap().len() <= MAX_ENTRIES);
    assert!(messages(&result).iter().any(|m| m.contains("actual line 4999")));
    assert_eq!(std::fs::read(&path).unwrap(), data);
    assert_eq!(std::fs::read(f.root.join("service.json")).unwrap(), states);
    let position = &result["cursor"]["files"]["logs/setup.log"];
    assert_eq!(position["offset"], data.len());
    assert_eq!(position.as_object().unwrap().keys().collect::<Vec<_>>(), ["device", "inode", "offset", "anchor", "mtime_ns"]);
}

#[test]
fn short_credentials_in_json_do_not_enter_the_viewer() {
    let f = Fixture::new();
    f.file("logs/setup.log", b"{\"operation\":\"generate\",\"status\":0,\"data\":\"small-secret\",\"_auth\":\"auth-secret\"}\n");
    let text = pyjson::dumps(&f.collect(&json!({})));
    assert!(!text.contains("small-secret") && !text.contains("auth-secret"));
    assert!(text.contains("generate"));
}

#[test]
fn dated_files_are_followed_across_midnight_without_repeating_output() {
    let f = Fixture::new();
    let today = mirra_core::logfiles::today();
    let day = std::sync::Arc::new(std::sync::Mutex::new(today - TimeDelta::days(1)));
    let clock = day.clone();
    let log = FileLog::new(f.root.join("logs")).with_clock(move || *clock.lock().unwrap());
    log.write(&json!({"source": "SSH stderr", "message": "real SSH output before midnight"})).unwrap();
    let first = f.collect(&json!({}));
    assert!(messages(&first).contains(&"real SSH output before midnight".to_string()));
    *day.lock().unwrap() = today;
    log.write(&json!({"source": "SSH stderr", "message": "real SSH output after midnight"})).unwrap();
    let second = f.collect(&cursor(&first));
    assert_eq!(messages(&second), ["real SSH output after midnight"]);
    assert!(f.collect(&cursor(&second))["entries"].as_array().unwrap().is_empty());
}

#[test]
fn missing_base_is_an_empty_successful_snapshot() {
    let result = collect(Some(Path::new("/nonexistent/mirra-diagnostics")), &json!({}));
    assert_eq!(result["ok"], true);
    assert_eq!(result["entries"], json!([]));
    assert_eq!(result["cursor"], json!({"files": {}, "states": {}}));
    assert_eq!(result.as_object().unwrap().keys().collect::<Vec<_>>(), ["ok", "entries", "cursor", "observed_at"]);
}

#[test]
fn iso_timestamps_follow_python_fromisoformat() {
    assert_eq!(iso_timestamp("2026-11-08T04:00:00.000000+00:00"), Some(1_794_110_400.0));
    assert_eq!(iso_timestamp("2026-11-08T11:00:00+07:00"), Some(1_794_110_400.0));
    assert_eq!(iso_timestamp("2026-11-08T04:00:00Z"), Some(1_794_110_400.0));
    assert!(iso_timestamp("2026-11-08 04:00:00").is_some());
    assert_eq!(iso_timestamp("not a date"), None);
}

#[test]
fn native_dated_logs_are_collected_and_unicode_digits_do_not_panic() {
    let f = Fixture::new();
    let today = mirra_core::logfiles::today();
    let dated = format!("logs/native-{}.log", today.format("%Y-%m-%d"));
    f.file(&dated, b"{\"source\":\"Mirroring\",\"message\":\"stream event observed\"}\n");
    f.file("logs/setup-\u{0968}\u{0966}\u{0968}\u{096c}-\u{0967}\u{0967}-\u{0966}\u{096e}.log", b"ignored\n");
    let result = f.collect(&json!({}));
    assert_eq!(result["ok"], true);
    assert!(messages(&result).iter().any(|m| m.contains("stream event observed")));
}
