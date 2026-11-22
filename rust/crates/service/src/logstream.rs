//! Stream actual Apple Mirroring log messages to the viewer, with redaction
//! (port of `scripts/logstream.py`).
use std::os::fd::AsRawFd;
use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use mirra_core::activity::{utc_timestamp, FileLog};
use mirra_core::redaction::{redact_bytes, redact_text};
use mirra_core::{pyjson, sys};
use serde_json::{json, Value};

use crate::cli::{self, Token};
use crate::signals::StopSignals;
use crate::util::{self, py_str, truncate_chars};

pub const NOISY_FRAMEWORKS: [&str; 3] = ["com.apple.AppKit", "com.apple.defaults", "com.apple.launchservices"];
pub const PREDICATE: &str = concat!(
    "process == \"iPhone Mirroring\" OR (process == \"sharingd\" AND composedMessage BEGINSWITH \"MIRRA_KEYSTORE\")",
    " OR (process == \"avconferenced\" AND (composedMessage CONTAINS \"MIRRA_DECODER\"",
    " OR composedMessage CONTAINS \"VCPDec\" OR composedMessage CONTAINS \"video decoder lib\"",
    " OR composedMessage CONTAINS \"Dec_fps\")) OR process BEGINSWITH \"VTDecoderXPCService\"");

pub fn predicate(verbose: bool) -> String {
    if verbose {
        return PREDICATE.to_string();
    }
    let mut names = NOISY_FRAMEWORKS.to_vec();
    names.sort();
    let frameworks: Vec<String> = names.iter().map(|n| format!("subsystem == \"{}\"", n)).collect();
    format!("({}) AND NOT (logType == \"debug\" AND ({}))", PREDICATE, frameworks.join(" OR "))
}

/// `project(raw, verbose)`: one viewer entry for an ndjson log record.
pub fn project(raw: &[u8], verbose: bool) -> Option<Value> {
    let value: Value = serde_json::from_slice(raw).ok()?;
    let value = value.as_object()?;
    let event = value.get("eventMessage")?.as_str()?;
    let kind = value.get("messageType").map(py_str).unwrap_or_default().to_lowercase();
    let subsystem = value.get("subsystem");
    let noisy = subsystem.and_then(Value::as_str).is_some_and(|s| NOISY_FRAMEWORKS.contains(&s));
    if !verbose && kind == "debug" && noisy {
        return None;
    }
    let mut message = redact_text(event);
    if message.is_empty() {
        return None;
    }
    let level = value.get("messageType").map(py_str).unwrap_or_else(|| "Default".into()).to_lowercase();
    let level = if level == "error" || level == "fault" { "error" } else if level == "debug" { "debug" } else { "info" };
    if let Some(pid) = util::strict_int(value.get("processID")) {
        message = format!("pid={} {}", pid, message);
    }
    let prefix: Vec<String> = [subsystem, value.get("category")].iter()
        .filter_map(|v| v.and_then(Value::as_str)).filter(|s| !s.is_empty()).map(redact_text).collect();
    let prefix = prefix.join("/");
    if !prefix.is_empty() {
        message = format!("{}: {}", truncate_chars(&prefix, 160), message);
    }
    let process = match value.get("processImagePath") {
        None => String::new(),
        Some(Value::String(path)) => Path::new(path).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default(),
        Some(_) => String::new(),
    };
    let source = if process == "avconferenced" { "AVConference" }
        else if process.starts_with("VTDecoderXPCService") { "VideoToolbox" } else { "Apple Mirroring" };
    let timestamp = redact_text(&value.get("timestamp").map(py_str).unwrap_or_default());
    Some(json!({"source": source, "level": level, "message": truncate_chars(&message, 4000),
        "observed_at": utc_timestamp(), "event_timestamp": timestamp}))
}

fn notice(source: &str, level: &str, message: &str) -> Value {
    json!({"source": source, "level": level, "message": message, "observed_at": utc_timestamp()})
}

struct Stream {
    pending: Vec<Value>,
    last_flush: Instant,
    storage: FileLog,
    storage_error: bool,
    maintenance_day: Option<chrono::NaiveDate>,
}

impl Stream {
    fn maintain(&mut self) {
        let day = mirra_core::logfiles::today();
        if self.maintenance_day == Some(day) {
            return;
        }
        self.maintenance_day = Some(day);
        match self.storage.maintain() {
            Ok(removed) if !removed.is_empty() => {
                let message = format!("Removed {} expired log files: {}", removed.len(), removed.join(", "));
                self.pending.push(notice("Logs", "info", &message));
            }
            Ok(_) => {}
            Err(error) => self.storage_failed(&error),
        }
    }

    fn storage_failed(&mut self, error: &mirra_core::Error) {
        if !self.storage_error {
            self.storage_error = true;
            self.pending.push(notice("Log file", "error", &redact_text(&error.to_string())));
        }
    }

    fn add(&mut self, item: Value) {
        let mut record = item.clone();
        record["timestamp"] = item["observed_at"].clone();
        self.pending.push(item);
        if let Err(error) = self.storage.write(&record) {
            self.storage_failed(&error);
        }
    }

    /// False once the reader is gone (BrokenPipeError).
    fn flush(&mut self) -> bool {
        if !self.pending.is_empty() {
            let start = self.pending.len().saturating_sub(80);
            let mut line = pyjson::dumps_unicode(&json!({"ok": true, "entries": &self.pending[start..]}));
            line.push('\n');
            self.pending.clear();
            if let Err(e) = sys::write_all(1, line.as_bytes()) {
                if e.raw_os_error() == Some(libc::EPIPE) {
                    return false;
                }
            }
        }
        self.last_flush = Instant::now();
        true
    }
}

const USAGE: &str = "[-h] [--verbose]";

/// `mirra-cli logstream [--verbose]`: runs until stdin closes or SIGTERM/SIGINT.
pub fn logstream_main(args: Vec<String>) -> i32 {
    let mut verbose = false;
    for token in cli::Options::new(&args) {
        match token {
            Token::Flag(name, None) if name == "--help" => {
                println!("usage: logstream {}", USAGE);
                return 0;
            }
            Token::Flag(name, None) if name == "--verbose" => verbose = true,
            Token::Flag(name, _) | Token::Positional(name) => {
                return cli::usage_error("logstream", USAGE, &format!("unrecognized arguments: {}", name));
            }
        }
    }
    let signals = StopSignals::install();
    let command = ["/usr/bin/log", "stream", "--style", "ndjson", "--level", "debug", "--predicate"];
    let mut process = match Command::new(command[0]).args(&command[1..]).arg(predicate(verbose))
        .stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn() {
        Ok(process) => process,
        Err(error) => {
            eprintln!("{}", error);
            return 1;
        }
    };
    let stdout = process.stdout.take().unwrap();
    let stderr = process.stderr.take().unwrap();
    let storage = FileLog::new(util::home().join("Library/Application Support/Mirra/logs")).with_name("native.log");
    let mut stream = Stream { pending: Vec::new(), last_flush: Instant::now(), storage, storage_error: false, maintenance_day: None };
    // (fd, kind, buffer, registered)
    let mut sources: Vec<(i32, &str, Vec<u8>, bool)> = vec![
        (0, "parent", Vec::new(), true), (stdout.as_raw_fd(), "stdout", Vec::new(), true), (stderr.as_raw_fd(), "stderr", Vec::new(), true)];
    let mut stop = false;
    let mut alive = true;
    stream.maintain();
    while !stop && !signals.stopped() {
        stream.maintain();
        let mut fds: Vec<libc::pollfd> = sources.iter().filter(|s| s.3).map(|s| libc::pollfd { fd: s.0, events: libc::POLLIN, revents: 0 }).collect();
        let ready = unsafe { libc::poll(fds.as_mut_ptr(), fds.len() as libc::nfds_t, 200) };
        if ready > 0 {
            for pollfd in fds.iter().filter(|p| p.revents != 0) {
                let source = sources.iter_mut().find(|s| s.0 == pollfd.fd).unwrap();
                let mut chunk = vec![0u8; 16384];
                let n = unsafe { libc::read(source.0, chunk.as_mut_ptr().cast(), chunk.len()) };
                if n < 0 && sys::errno() == libc::EINTR {
                    continue;
                }
                let data = &chunk[..n.max(0) as usize];
                if source.1 == "parent" {
                    if data.is_empty() {
                        stop = true;
                    }
                    continue;
                }
                if data.is_empty() {
                    source.3 = false;
                    continue;
                }
                source.2.extend_from_slice(data);
                let kind = source.1;
                let mut items = Vec::new();
                while let Some(index) = source.2.iter().position(|b| *b == b'\n') {
                    let line: Vec<u8> = source.2.drain(..=index).collect();
                    let line = &line[..line.len() - 1];
                    let item = if kind == "stdout" { project(line, verbose) }
                        else { Some(notice("System log", "error", &redact_bytes(line))) };
                    items.extend(item);
                }
                if source.2.len() > 262144 {
                    source.2.clear();
                }
                for item in items {
                    stream.add(item);
                }
            }
        }
        if (stream.pending.len() >= 80 || stream.last_flush.elapsed() >= Duration::from_millis(500)) && !stream.flush() {
            alive = false;
            break;
        }
        if !sources.iter().any(|s| s.1 != "parent" && s.3) {
            if let Ok(Some(status)) = process.try_wait() {
                let code = mirra_core::subprocess::return_code(status);
                stream.pending.push(notice("System log", "warning", &format!("log stream exited with code {}.", code)));
                break;
            }
        }
    }
    if alive {
        stream.flush();
    }
    if let Ok(None) = process.try_wait() {
        unsafe { libc::kill(process.id() as i32, libc::SIGTERM) };
        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline && matches!(process.try_wait(), Ok(None)) {
            std::thread::sleep(Duration::from_millis(20));
        }
        if let Ok(None) = process.try_wait() {
            let _ = process.kill();
            let _ = process.wait();
        }
    }
    drop((stdout, stderr));
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_message_keeps_real_text_and_masks_tokens() {
        let value = json!({"eventMessage": "Connection failed with error 42 token=private-token", "messageType": "Error",
            "processID": 123, "subsystem": "com.apple.ScreenContinuity", "category": "connection",
            "timestamp": "2026-11-08 11:00:00.123+0700", "processImagePath": "/usr/libexec/avconferenced"});
        let row = project(pyjson::dumps(&value).as_bytes(), false).unwrap();
        let message = row["message"].as_str().unwrap();
        assert!(message.starts_with("com.apple.ScreenContinuity/connection: pid=123 Connection failed with error 42"));
        assert!(!message.contains("private-token"));
        assert_eq!(row["level"], "error");
        assert_eq!(row["source"], "AVConference");
        assert_eq!(row.as_object().unwrap().keys().collect::<Vec<_>>(), ["source", "level", "message", "observed_at", "event_timestamp"]);
    }

    #[test]
    fn verbose_hides_only_routine_framework_debug_messages() {
        for subsystem in NOISY_FRAMEWORKS {
            let mut value = json!({"eventMessage": "actual framework event", "messageType": "Debug", "subsystem": subsystem});
            assert!(project(value.to_string().as_bytes(), false).is_none());
            assert!(project(value.to_string().as_bytes(), true).unwrap()["message"].as_str().unwrap().contains("actual framework event"));
            value["messageType"] = json!("Error");
            assert_eq!(project(value.to_string().as_bytes(), false).unwrap()["level"], "error");
        }
        let value = json!({"eventMessage": "actual connection negotiation", "messageType": "Debug", "subsystem": "com.apple.ScreenContinuity"});
        assert!(project(value.to_string().as_bytes(), false).is_some());
        assert!(predicate(false).contains("logType == \"debug\""));
        assert!(!predicate(true).contains("logType == \"debug\""));
        assert_eq!(predicate(false), format!("({}) AND NOT (logType == \"debug\" AND (subsystem == \"com.apple.AppKit\" OR subsystem == \"com.apple.defaults\" OR subsystem == \"com.apple.launchservices\"))", PREDICATE));
        assert!(project(b"not json", false).is_none());
        assert!(project(br#"{"eventMessage": 4}"#, false).is_none());
    }
}
