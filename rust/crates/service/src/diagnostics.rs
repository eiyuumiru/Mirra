//! Follow actual Mirra log files; redact credentials, never replace log prose
//! (port of `scripts/diagnostics.py`).
//!
//! This read-only observer never contacts a phone or controls a service. File
//! cursors belong to the log viewer alone. Older lines have no invented event
//! clock; the native panel displays them as Earlier.
use std::cmp::Ordering;
use std::io::Read;
use std::os::fd::{AsRawFd, OwnedFd, RawFd};
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use chrono::{Local, NaiveDate, NaiveDateTime, NaiveTime, TimeDelta, TimeZone};
use mirra_core::activity::{utc_timestamp, FileLog};
use mirra_core::logfiles::RETENTION_DAYS;
use mirra_core::pyjson::{self, Options};
use mirra_core::redaction::{redact_bytes, redact_line, redact_text, redact_value};
use mirra_core::{sys, Error, Result};
use regex::Regex;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::cli::{self, Token};
use crate::util::{self, sort_keys, truncate_chars, truthy};

pub const TAIL_BYTES: usize = 32768;
pub const STATE_BYTES: usize = 65536;
pub const MAX_ENTRIES: usize = 160;
pub const MAX_MESSAGE: usize = 4000;

/// One viewer row: `{'source', 'level', 'message', 'observed_at'}`.
#[derive(Clone, Debug, PartialEq)]
pub struct Entry {
    pub source: String,
    pub level: Value,
    pub message: String,
    pub observed_at: Option<String>,
}

pub fn entry(source: &str, message: &str, level: impl Into<Value>, observed_at: Option<String>) -> Entry {
    Entry { source: source.to_string(), level: level.into(), message: truncate_chars(message, MAX_MESSAGE), observed_at }
}

impl Entry {
    pub fn to_json(&self) -> Value {
        json!({"source": self.source, "level": self.level, "message": self.message, "observed_at": self.observed_at})
    }
}

fn entries_json(entries: &[Entry]) -> Value {
    Value::Array(entries.iter().map(Entry::to_json).collect())
}

/// `json.dumps(v, ensure_ascii=True, separators=(',', ':'))`
fn dumps_ascii_compact(value: &Value) -> String {
    pyjson::dumps_with(value, &Options { indent: None, ensure_ascii: true, item_separator: ",", key_separator: ":" })
}

/// One explicit snapshot, independent of the inexpensive log polling path.
pub fn hardware_snapshot(base: Option<&Path>, report: Value) -> Value {
    let now = utc_timestamp();
    let mut entries = Vec::new();
    // Split long lists into complete JSON messages instead of truncating data.
    fn add(entries: &mut Vec<Entry>, now: &str, name: &str, value: &Value) {
        // ASCII escapes keep Python and the native viewer's UTF-16 length
        // limits identical, including hardware names containing emoji.
        let message = dumps_ascii_compact(&json!({name: value}));
        if message.len() <= MAX_MESSAGE {
            entries.push(entry("Host hardware", &message, "info", Some(now.to_string())));
        } else if let Value::Object(map) = value {
            for (key, item) in map {
                add(entries, now, &format!("{}.{}", name, key), item);
            }
        } else if let Value::Array(items) = value {
            if items.len() > 1 {
                let middle = items.len() / 2;
                add(entries, now, &format!("{}[:{}]", name, middle), &Value::Array(items[..middle].to_vec()));
                add(entries, now, &format!("{}[{}:]", name, middle), &Value::Array(items[middle..].to_vec()));
            } else if let Some(first) = items.first() {
                add(entries, now, &format!("{}[0]", name), first);
            }
        } else {
            entries.push(entry("Host hardware", &pyjson::dumps(&json!({name: {"status": "unknown", "reason": "field_limit"}})),
                "info", Some(now.to_string())));
        }
    }
    if let Value::Object(report) = &report {
        for (name, value) in report {
            add(&mut entries, &now, name, value);
        }
    }
    let base = base.map(Path::to_path_buf).unwrap_or_else(default_base);
    let storage = FileLog::new(base.join("logs")).with_name("native.log");
    let saved = entries.iter().try_for_each(|item| {
        let mut record = item.to_json();
        record["timestamp"] = Value::from(now.clone());
        storage.write(&record)
    });
    if saved.is_err() {
        entries.push(entry("Logs", "Hardware observations could not be saved to the log folder.", "warning", Some(now.clone())));
    }
    // Deliberately no cursor: this must not reset the concurrent log follower.
    json!({"ok": true, "entries": entries_json(&entries), "observed_at": now})
}

static NOISY: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?i)error|failed|failure|denied|timed out|refused").unwrap());

/// `project_line(raw, source)`
pub fn project_line(raw: &[u8], source: &str) -> Vec<Entry> {
    let value = serde_json::from_slice::<Value>(raw).ok();
    if let Some(Value::Object(value)) = &value {
        if value.get("operation").and_then(Value::as_str) == Some("health") && !truthy(value.get("error")) && !truthy(value.get("status")) {
            return Vec::new(); // Skip successful periodic health checks, retain failures.
        }
        if let (Some(Value::String(message)), Some(Value::String(origin))) = (value.get("message"), value.get("source")) {
            let mut message = redact_text(message);
            if let Some(fields @ Value::Object(_)) = value.get("fields") {
                message.push(' ');
                message.push_str(&pyjson::dumps_unicode(&redact_value(fields)));
            }
            let stamp = value.get("timestamp").and_then(Value::as_str).map(str::to_string);
            let level = value.get("level").cloned().unwrap_or_else(|| Value::from("info"));
            return vec![entry(&truncate_chars(&redact_text(origin), 24), &message, level, stamp)];
        }
        let mut level = if truthy(value.get("error")) || truthy(value.get("transport_error")) || truthy(value.get("RESTORE_ERROR")) {
            "error"
        } else {
            "debug"
        };
        if util::strict_int(value.get("status")).is_some_and(|s| s != 0) {
            level = "error";
        }
        if value.get("NATIVE_BACKEND_STATE").and_then(|s| s.get("phase")).and_then(Value::as_str) == Some("failed") {
            level = "error";
        }
        return vec![entry(source, &redact_line(raw), level, None)];
    }
    let message = redact_bytes(raw);
    if message.trim().is_empty() {
        return Vec::new();
    }
    let level = if NOISY.is_match(&message) { "error" } else { "debug" };
    vec![entry(source, &message, level, None)]
}

const DIRECTORY: i32 = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_NONBLOCK;

fn check(info: &libc::stat, directory: bool) -> Result<()> {
    if !sys::private_owned(info, directory) {
        return Err(Error::value("Diagnostic path is not private and user-owned"));
    }
    Ok(())
}

fn parts(name: &str, allow_empty: bool) -> Result<Vec<&str>> {
    let parts: Vec<&str> = name.split('/').filter(|p| !p.is_empty() && *p != ".").collect();
    if name.starts_with('/') || parts.contains(&"..") || (!allow_empty && parts.is_empty()) {
        return Err(Error::value(if allow_empty { "Unexpected diagnostic directory" } else { "Unexpected diagnostic path" }));
    }
    Ok(parts)
}

fn open_checked(directory: RawFd, part: &str, flags: i32, is_directory: bool) -> Result<OwnedFd> {
    let fd = sys::openat(directory, part, flags, 0).map_err(|e| Error::with_path(e, part))?;
    check(&sys::fstat(fd.as_raw_fd())?, is_directory)?;
    Ok(fd)
}

/// A file cursor (`{'device', 'inode', 'offset', 'anchor', 'mtime_ns'}`).
pub type Cursor = Map<String, Value>;

/// Open known paths relative to a private root, without following symlinks.
pub struct PrivateReader {
    fd: OwnedFd,
}

impl PrivateReader {
    pub fn new(base: &Path) -> Result<Self> {
        let fd = sys::open(base, DIRECTORY, 0).map_err(|e| Error::with_path(e, base))?;
        check(&sys::fstat(fd.as_raw_fd())?, true)?;
        Ok(PrivateReader { fd })
    }

    pub fn open_directory(&self, name: &str) -> Result<OwnedFd> {
        let mut directory = sys::dup(self.fd.as_raw_fd())?;
        for part in parts(name, true)? {
            directory = open_checked(directory.as_raw_fd(), part, DIRECTORY, true)?;
        }
        Ok(directory)
    }

    pub fn open(&self, name: &str) -> Result<OwnedFd> {
        let parts = parts(name, false)?;
        let mut directory = sys::dup(self.fd.as_raw_fd())?;
        for part in &parts[..parts.len() - 1] {
            directory = open_checked(directory.as_raw_fd(), part, DIRECTORY, true)?;
        }
        open_checked(directory.as_raw_fd(), parts[parts.len() - 1], libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_NONBLOCK, false)
    }

    pub fn state(&self, name: &str) -> Result<Map<String, Value>> {
        let fd = self.open(name)?;
        let mut data = Vec::new();
        std::fs::File::from(fd).take(STATE_BYTES as u64 + 1).read_to_end(&mut data)?;
        if data.len() > STATE_BYTES {
            return Err(Error::value("Oversized diagnostic state"));
        }
        match serde_json::from_slice::<Value>(&data) {
            Ok(Value::Object(map)) => Ok(map),
            Ok(_) => Err(Error::value("Invalid diagnostic state")),
            Err(e) => Err(Error::value(e.to_string())),
        }
    }

    /// Discover only log basenames in a validated directory.
    pub fn names(&self, name: &str, pattern: &Regex, limit: usize) -> Result<Vec<String>> {
        let fd = self.open_directory(name)?;
        let mut names: Vec<String> = sys::list_dir_fd(fd.as_raw_fd())?.into_iter()
            .filter_map(|n| n.into_string().ok()).filter(|n| pattern.is_match(n)).collect();
        names.sort();
        let skip = names.len().saturating_sub(limit);
        Ok(names.split_off(skip))
    }

    fn anchor(fd: RawFd, offset: u64) -> Result<String> {
        let data = sys::pread(fd, offset.min(64) as usize, offset.saturating_sub(64))?;
        Ok(hex(&Sha256::digest(&data)))
    }

    /// Complete new lines since `previous`, the new cursor and whether it continued.
    pub fn tail(&self, name: &str, previous: Option<&Value>) -> Result<(Vec<Vec<u8>>, Cursor, bool)> {
        let fd = self.open(name)?;
        let raw = fd.as_raw_fd();
        let info = sys::fstat(raw)?;
        let size = info.st_size as u64;
        let empty = Map::new();
        let previous = previous.and_then(Value::as_object).unwrap_or(&empty);
        let offset = util::strict_int(previous.get("offset"));
        let continued = util::strict_int(previous.get("device")) == Some(info.st_dev as i64)
            && util::strict_int(previous.get("inode")) == Some(info.st_ino as i64)
            && offset.is_some_and(|o| o >= 0 && o as u64 <= size)
            && previous.get("anchor").and_then(Value::as_str) == Some(Self::anchor(raw, offset.unwrap_or(0).max(0) as u64)?.as_str());
        let mut start = if continued { offset.unwrap() as u64 } else { size.saturating_sub(TAIL_BYTES as u64) };
        if size - start > TAIL_BYTES as u64 {
            start = size - TAIL_BYTES as u64;
        }
        let data = sys::pread(raw, TAIL_BYTES, start)?;
        // A partial final line waits for the next poll. Oversized lines are
        // skipped; the parser never sees a truncated line as a valid event.
        let end = data.iter().rposition(|b| *b == b'\n').map_or(0, |i| i + 1);
        let offset_after = if end > 0 { start + end as u64 } else if data.len() == TAIL_BYTES { start + data.len() as u64 } else { start };
        let mut complete = &data[..end];
        if start > 0 && (!continued || Some(start as i64) != offset) {
            complete = match complete.iter().position(|b| *b == b'\n') {
                Some(i) => &complete[i + 1..],
                None => &[],
            };
        }
        let lines = split_lines(complete);
        let mut cursor = Map::new();
        cursor.insert("device".into(), json!(info.st_dev));
        cursor.insert("inode".into(), json!(info.st_ino));
        cursor.insert("offset".into(), json!(offset_after));
        cursor.insert("anchor".into(), Value::from(Self::anchor(raw, offset_after)?));
        cursor.insert("mtime_ns".into(), json!(info.st_mtime as i64 * 1_000_000_000 + info.st_mtime_nsec));
        Ok((lines, cursor, continued))
    }
}

fn hex(data: &[u8]) -> String {
    data.iter().map(|b| format!("{:02x}", b)).collect()
}

/// `bytes.splitlines()` (`\n`, `\r`, `\r\n`).
fn split_lines(data: &[u8]) -> Vec<Vec<u8>> {
    let mut lines = Vec::new();
    let mut current = Vec::new();
    let mut i = 0;
    while i < data.len() {
        match data[i] {
            b'\n' => lines.push(std::mem::take(&mut current)),
            b'\r' => {
                lines.push(std::mem::take(&mut current));
                if data.get(i + 1) == Some(&b'\n') {
                    i += 1;
                }
            }
            byte => current.push(byte),
        }
        i += 1;
    }
    if !current.is_empty() {
        lines.push(current);
    }
    lines
}

/// `datetime.fromisoformat(text).timestamp()` (naive values are local time).
pub fn iso_timestamp(text: &str) -> Option<f64> {
    let text = text.replace('Z', "+00:00");
    if text.len() < 10 || !text.is_char_boundary(10) {
        return None;
    }
    let date = NaiveDate::parse_from_str(&text[..10], "%Y-%m-%d").ok()?;
    let rest = &text[10..];
    if rest.is_empty() {
        return Local.from_local_datetime(&date.and_hms_opt(0, 0, 0)?).earliest().map(|t| t.timestamp() as f64);
    }
    let rest = rest.get(rest.chars().next()?.len_utf8()..)?;
    let (clock, zone) = match rest.find(['+', '-']) {
        Some(i) => (&rest[..i], Some(&rest[i..])),
        None => (rest, None),
    };
    let time = ["%H:%M:%S%.f", "%H:%M:%S", "%H:%M", "%H"].iter()
        .find_map(|f| NaiveTime::parse_from_str(clock, f).ok())
        .or_else(|| (clock.len() == 2).then(|| clock.parse::<u32>().ok().and_then(|h| NaiveTime::from_hms_opt(h, 0, 0))).flatten())?;
    let moment = NaiveDateTime::new(date, time);
    let fraction = moment.and_utc().timestamp_subsec_nanos() as f64 / 1e9;
    match zone {
        None => Local.from_local_datetime(&moment).earliest().map(|t| t.timestamp() as f64 + fraction),
        Some(zone) => {
            let sign = if zone.starts_with('-') { -1 } else { 1 };
            let digits: String = zone[1..].chars().filter(|c| *c != ':').collect();
            if !digits.chars().all(|c| c.is_ascii_digit()) || !matches!(digits.len(), 2 | 4 | 6) {
                return None;
            }
            let hours: i64 = digits[..2].parse().ok()?;
            let minutes: i64 = digits.get(2..4).map_or(Some(0), |m| m.parse().ok())?;
            let seconds: i64 = digits.get(4..6).map_or(Some(0), |s| s.parse().ok())?;
            if hours > 23 || minutes > 59 || seconds > 59 {
                return None;
            }
            let offset = sign * (hours * 3600 + minutes * 60 + seconds);
            Some(moment.and_utc().timestamp() as f64 - offset as f64 + fraction)
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum Order {
    Undated(i64),
    Dated(f64),
}

fn compare(a: &Order, b: &Order) -> Ordering {
    match (a, b) {
        (Order::Undated(x), Order::Undated(y)) => x.cmp(y),
        (Order::Dated(x), Order::Dated(y)) => x.partial_cmp(y).unwrap_or(Ordering::Equal),
        (Order::Undated(_), Order::Dated(_)) => Ordering::Less,
        (Order::Dated(_), Order::Undated(_)) => Ordering::Greater,
    }
}

pub fn default_base() -> PathBuf {
    util::home().join("Library/Application Support/Mirra")
}

static DATED: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\A(?:setup|control|native)-[0-9]{4}-[0-9]{2}-[0-9]{2}\.log\z").unwrap());
static RUN: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\Anative-[0-9]{8}-[0-9]{6}(?:-[0-9]+)?\z").unwrap());
static ATTEMPT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\Abackend-[0-9]{6}\z").unwrap());
static KDEBUG: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\A(?:broker|controller)-kdebug-[0-9]{8}-[0-9]{6}\.log\z").unwrap());
static SETUP_ID: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\A[0-9a-f]{32}\z").unwrap());

struct Collection<'a> {
    reader: &'a PrivateReader,
    now: String,
    previous_states: Map<String, Value>,
    states: Map<String, Value>,
    state_entries: Vec<Entry>,
}

impl Collection<'_> {
    fn changed(&mut self, name: &str, data: &Value, source: &str, level: &str) {
        let projected = redact_value(data);
        let digest = hex(&Sha256::digest(pyjson::dumps(&sort_keys(&projected)).as_bytes()));
        self.states.insert(name.into(), Value::from(digest.clone()));
        if self.previous_states.get(name).and_then(Value::as_str) != Some(digest.as_str()) && truthy(Some(&projected)) {
            self.state_entries.push(entry(source, &pyjson::dumps_unicode(&projected), level, Some(self.now.clone())));
        }
    }

    fn state(&mut self, name: &str) -> Map<String, Value> {
        match self.reader.state(name) {
            Ok(value) => value,
            Err(e) if e.errno() == Some(libc::ENOENT) => Map::new(),
            Err(e) => {
                self.changed(&format!("unreadable:{}", name), &json!({"file": name, "error": e.to_string()}), "Logs", "error");
                Map::new()
            }
        }
    }
}

fn select(map: &Map<String, Value>, keys: &[&str]) -> Value {
    Value::Object(keys.iter().filter_map(|k| map.get(*k).map(|v| (k.to_string(), v.clone()))).collect())
}

/// `collect(base, cursor)`: new log lines and changed state since `cursor`.
pub fn collect(base: Option<&Path>, cursor: &Value) -> Value {
    collect_on(base, cursor, mirra_core::logfiles::today())
}

fn collect_on(base: Option<&Path>, cursor: &Value, today: NaiveDate) -> Value {
    let base = mirra_core::paths::absolute(&base.map(Path::to_path_buf).unwrap_or_else(default_base));
    let empty = Map::new();
    let cursor = cursor.as_object().unwrap_or(&empty);
    let previous_files = cursor.get("files").and_then(Value::as_object).cloned().unwrap_or_default();
    let previous_states = cursor.get("states").and_then(Value::as_object).cloned().unwrap_or_default();
    let now = utc_timestamp();
    let reader = match PrivateReader::new(&base) {
        Ok(reader) => reader,
        Err(e) if e.errno() == Some(libc::ENOENT) => {
            return json!({"ok": true, "entries": [], "cursor": {"files": {}, "states": {}}, "observed_at": now});
        }
        Err(e) => {
            let entries = vec![entry("Logs", &format!("open diagnostics: {}", redact_text(&e.to_string())), "error", Some(now.clone()))];
            return json!({"ok": false, "entries": entries_json(&entries), "cursor": {"files": {}, "states": {}}, "observed_at": now});
        }
    };
    let mut c = Collection { reader: &reader, now: now.clone(), previous_states, states: Map::new(), state_entries: Vec::new() };
    let mut files: Vec<(String, &str)> = [("logs/setup.log", "Setup"), ("logs/control.log", "Service"), ("logs/service.log", "Service"),
        ("logs/native.log", "Native"), ("logs/sharingd.log", "Keys")].iter().map(|(n, t)| (n.to_string(), *t)).collect();
    match reader.names("logs", &DATED, 3 * RETENTION_DAYS as usize) {
        Ok(names) => {
            for name in names {
                let Some(stamp) = name.strip_suffix(".log").and_then(|s| s.get(s.len().saturating_sub(10)..)) else { continue };
                let Ok(day) = NaiveDate::parse_from_str(stamp, "%Y-%m-%d") else { continue };
                if today - TimeDelta::days(RETENTION_DAYS) < day && day <= today {
                    let title = if name.starts_with("setup-") { "Setup" } else if name.starts_with("native-") { "Native" } else { "Service" };
                    files.push((format!("logs/{}", name), title));
                }
            }
        }
        Err(e) if e.errno() == Some(libc::ENOENT) => {}
        Err(e) => c.changed("dated-log-files", &json!({"error": e.to_string()}), "Logs", "error"),
    }
    let service = c.state("service.json");
    let directory = service.get("directory").and_then(Value::as_str);
    let run = directory.and_then(|d| Path::new(d).file_name()).and_then(|n| n.to_str()).unwrap_or("").to_string();
    let expected = base.join("current/runtime").join(&run);
    if directory.is_some_and(|d| Path::new(d) == expected) && RUN.is_match(&run) {
        let runtime = format!("current/runtime/{}", run);
        let backend = c.state(&format!("{}/backend-status.json", runtime));
        let selected = select(&backend, &["phase", "attempt", "ready", "automatic_recovery", "reason", "exit_code", "retry_seconds"]);
        c.changed(&format!("backend:{}", run), &selected, "Bridge state", "debug");
        let decoder = c.state(&format!("{}/decoder-route.json", runtime));
        let selected = select(&decoder, &["mode", "enabled", "ready", "native_video_observations"]);
        c.changed(&format!("decoder:{}", run), &selected, "Decoder", "debug");
        files.push((format!("{}/app.log", runtime), "Mirroring"));
        if let Some(attempt) = backend.get("directory").and_then(Value::as_str).filter(|a| ATTEMPT.is_match(a)) {
            let work = format!("{}/{}", runtime, attempt);
            files.push((format!("{}/backend.log", work), "Bridge"));
            files.push((format!("{}/sharingd.stderr.log", work), "Keys"));
            match reader.names(&work, &KDEBUG, 4) {
                Ok(names) => {
                    for name in names {
                        let title = if name.starts_with("broker") { "Keys" } else { "Service" };
                        files.push((format!("{}/{}", work, name), title));
                    }
                }
                Err(e) => c.changed("attempt-files", &json!({"error": e.to_string()}), "Logs", "error"),
            }
        }
    }
    let active = c.state("setup/active.json");
    if let Some(identifier) = active.get("id").and_then(Value::as_str).filter(|i| SETUP_ID.is_match(i)) {
        let setup = c.state(&format!("setup/{}/setup.json", identifier));
        let selected = select(&setup, &["phase", "error", "error_code", "product_type", "os_version", "certificate_issued", "transport"]);
        c.changed(&format!("setup:{}", identifier), &selected, "Setup state", "debug");
        if truthy(setup.get("error")) {
            let error = Value::Object(c.state(&format!("setup/{}/error.json", identifier)));
            c.changed(&format!("setup-error:{}", identifier), &error, "Setup", "error");
        }
    }
    let mut positions = Map::new();
    let mut rows: Vec<(Entry, Order)> = Vec::new();
    for (name, title) in &files {
        let (lines, position, continued) = match reader.tail(name, previous_files.get(name)) {
            Ok(result) => result,
            Err(e) if e.errno() == Some(libc::ENOENT) => continue,
            Err(e) => {
                c.changed(&format!("unreadable:{}", name), &json!({"file": name, "error": e.to_string()}), "Logs", "error");
                continue;
            }
        };
        let mtime = position["mtime_ns"].as_i64().unwrap_or(0);
        positions.insert(name.clone(), Value::Object(position));
        for line in lines {
            for mut item in project_line(&line, title) {
                let recorded = item.observed_at.clone().filter(|s| !s.is_empty());
                if item.observed_at.as_deref().is_none_or(str::is_empty) {
                    item.observed_at = if continued { Some(now.clone()) } else { None };
                }
                // Preserve old untimestamped tails first. A file's mtime
                // includes healthy polls, so it cannot date old auth lines.
                let order = match &recorded {
                    Some(stamp) => Order::Dated(iso_timestamp(stamp).unwrap_or(0.0)),
                    None => Order::Undated(mtime),
                };
                rows.push((item, order));
            }
        }
    }
    rows.sort_by(|a, b| compare(&a.1, &b.1));
    let mut entries: Vec<Entry> = rows.into_iter().map(|(item, _)| item).collect();
    entries.append(&mut c.state_entries);
    let skip = entries.len().saturating_sub(MAX_ENTRIES);
    let entries = entries.split_off(skip);
    json!({"ok": true, "entries": entries_json(&entries), "cursor": {"files": positions, "states": c.states}, "observed_at": now})
}

const USAGE: &str = "[-h] [--base BASE] [--hardware]";

/// `mirra-cli diagnostics [--base PATH] [--hardware]`: one JSON reply on stdout
/// (`json.dumps(..., ensure_ascii=False)`); the viewer cursor is read from stdin.
pub fn diagnostics_main(args: Vec<String>) -> i32 {
    let mut options = cli::Options::new(&args);
    let (mut base, mut hardware) = (None, false);
    while let Some(token) = options.next() {
        match token {
            Token::Flag(name, None) if name == "--help" => {
                println!("usage: diagnostics {}", USAGE);
                return 0;
            }
            Token::Flag(name, None) if name == "--hardware" => hardware = true,
            Token::Flag(name, inline) if name == "--base" => match options.value("--base", inline) {
                Ok(value) => base = Some(PathBuf::from(value)),
                Err(message) => return cli::usage_error("diagnostics", USAGE, &message),
            },
            Token::Flag(name, _) | Token::Positional(name) => {
                return cli::usage_error("diagnostics", USAGE, &format!("unrecognized arguments: {}", name));
            }
        }
    }
    let value = if hardware {
        let report = mirra_native::hardware::inspect_host_environment(&mirra_core::config::default_root());
        hardware_snapshot(base.as_deref(), report)
    } else {
        let mut data = Vec::new();
        let read = std::io::stdin().lock().take(STATE_BYTES as u64 + 1).read_to_end(&mut data);
        let cursor = match read {
            Err(e) => Err(Error::from(e)),
            Ok(_) if data.len() > STATE_BYTES => Err(Error::value("Oversized viewer cursor")),
            Ok(_) if data.is_empty() => Ok(json!({})),
            Ok(_) => serde_json::from_slice::<Value>(&data).map_err(|e| Error::value(e.to_string())),
        };
        match cursor {
            Ok(cursor) => collect(base.as_deref(), &cursor),
            Err(error) => json!({"ok": false, "entries": [entry("Logs", &format!("snapshot: {}", redact_text(&error.to_string())), "error", None).to_json()], "cursor": {}}),
        }
    };
    let mut line = pyjson::dumps_unicode(&value);
    line.push('\n');
    let _ = sys::write_all(1, line.as_bytes());
    0
}

#[cfg(test)]
mod tests;
