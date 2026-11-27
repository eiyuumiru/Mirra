//! Record actual operations and stream process output without changing replies.
//!
//! Python keeps the sink in a `ContextVar`; here it is thread-local. Threads
//! spawned while capturing do not inherit it: pass [`current`] explicitly and
//! wrap the thread body in [`capture`].
use std::cell::RefCell;
use std::os::fd::{AsRawFd, OwnedFd};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use chrono::{NaiveDate, Timelike, Utc};
use serde_json::{Map, Value};

use crate::error::{Error, ErrorType, Result};
use crate::logfiles::{self, dated_name};
use crate::pyfmt;
use crate::redaction::{redact_line, redact_text, redact_value};
use crate::subprocess::{self, Completed, RunOptions, StreamObserver};
use crate::sys;

/// A log sink. Errors are swallowed by [`emit`]: diagnostic storage never
/// authorizes or aborts a connection operation.
pub type Sink = Arc<dyn Fn(&Value) -> Result<()> + Send + Sync>;

pub fn sink<F: Fn(&Value) -> Result<()> + Send + Sync + 'static>(f: F) -> Sink {
    Arc::new(f)
}

/// A sink that collects records into a shared vector (tests, buffering).
pub fn collector() -> (Sink, Arc<Mutex<Vec<Value>>>) {
    let records = Arc::new(Mutex::new(Vec::new()));
    let target = records.clone();
    (sink(move |v| {
        target.lock().unwrap().push(v.clone());
        Ok(())
    }), records)
}

thread_local! {
    static SINK: RefCell<Option<Sink>> = const { RefCell::new(None) };
}

pub fn enabled() -> bool {
    SINK.with(|s| s.borrow().is_some())
}

/// The sink active on this thread (to hand to spawned threads).
pub fn current() -> Option<Sink> {
    SINK.with(|s| s.borrow().clone())
}

struct Restore(Option<Sink>);

impl Drop for Restore {
    fn drop(&mut self) {
        let previous = self.0.take();
        SINK.with(|s| *s.borrow_mut() = previous);
    }
}

/// `with capture(sink): body()` — the previous sink is restored afterwards
/// (also on panic). `None` disables logging inside `body`.
pub fn capture<R>(sink: Option<Sink>, body: impl FnOnce() -> R) -> R {
    let previous = SINK.with(|s| std::mem::replace(&mut *s.borrow_mut(), sink));
    let _restore = Restore(previous);
    body()
}

/// `datetime.now(timezone.utc).isoformat()`
pub fn utc_timestamp() -> String {
    let now = Utc::now();
    let micros = now.nanosecond() / 1000 % 1_000_000;
    if micros == 0 {
        now.format("%Y-%m-%dT%H:%M:%S+00:00").to_string()
    } else {
        format!("{}.{:06}+00:00", now.format("%Y-%m-%dT%H:%M:%S"), micros)
    }
}

fn record(source: &str, message: &str, level: &str, fields: &Value) -> Value {
    let mut value = Map::new();
    value.insert("timestamp".into(), Value::from(utc_timestamp()));
    value.insert("source".into(), Value::from(source));
    value.insert("level".into(), Value::from(level));
    value.insert("message".into(), Value::from(redact_text(message)));
    if let Value::Object(map) = fields {
        if !map.is_empty() {
            value.insert("fields".into(), redact_value(fields));
        }
    }
    Value::Object(value)
}

/// `emit(source, message, level, **fields)`; `fields` is a JSON object
/// (or `Value::Null` for none). Levels: `debug`, `info`, `warning`, `error`.
pub fn emit(source: &str, message: &str, level: &str, fields: Value) {
    if let Some(sink) = current() {
        let _ = sink(&record(source, message, level, &fields));
    }
}

/// `emit(source, message)` at level `info` without fields.
pub fn info(source: &str, message: &str) {
    emit(source, message, "info", Value::Null);
}

fn emit_to(sink: &Sink, source: &str, message: &str, level: &str, fields: Value) {
    let _ = sink(&record(source, message, level, &fields));
}

fn merged(first: Vec<(&str, Value)>, fields: &Value) -> Value {
    let mut map = Map::new();
    for (k, v) in first {
        map.insert(k.into(), v);
    }
    if let Value::Object(extra) = fields {
        for (k, v) in extra {
            map.insert(k.clone(), v.clone());
        }
    }
    Value::Object(map)
}

struct PanicGuard<'a> {
    source: &'a str,
    name: &'a str,
    fields: &'a Value,
    start: Instant,
    armed: bool,
}

impl Drop for PanicGuard<'_> {
    fn drop(&mut self) {
        if self.armed && std::thread::panicking() {
            emit(self.source, &format!("{} failed", self.name), "error", merged(vec![
                ("error_type", Value::from("panic")), ("error", Value::from("panic")),
                ("elapsed_ms", Value::from(pyfmt::elapsed_ms(self.start)))], self.fields));
        }
    }
}

/// `with operation(source, name, **fields): body()` — emits `<name> begin`,
/// then `<name> complete` (elapsed_ms, fields) or `<name> failed` at error level
/// (error_type, error, elapsed_ms, fields). The result is returned unchanged.
pub fn operation<T, E: ErrorType>(source: &str, name: &str, fields: Value, body: impl FnOnce() -> Result<T, E>) -> Result<T, E> {
    let start = Instant::now();
    emit(source, &format!("{} begin", name), "info", fields.clone());
    let mut guard = PanicGuard { source, name, fields: &fields, start, armed: true };
    let result = body();
    guard.armed = false;
    match &result {
        Ok(_) => emit(source, &format!("{} complete", name), "info",
            merged(vec![("elapsed_ms", Value::from(pyfmt::elapsed_ms(start)))], &fields)),
        Err(error) => emit(source, &format!("{} failed", name), "error", merged(vec![
            ("error_type", Value::from(error.error_type())), ("error", Value::from(error.to_string())),
            ("elapsed_ms", Value::from(pyfmt::elapsed_ms(start)))], &fields)),
    }
    result
}

/// Keep actual errors/stderr from routine polls without repeated success dumps.
pub fn poll_errors(inner: Sink) -> Sink {
    sink(move |value| {
        let level = value.get("level").and_then(Value::as_str);
        let source = value.get("source").and_then(Value::as_str).unwrap_or("");
        if matches!(level, Some("error") | Some("warning")) || source.ends_with("stderr") {
            inner(value)?;
        }
        Ok(())
    })
}

/// Private dated append log with daily retention and a single `.1` backup.
pub struct FileLog {
    pub base: PathBuf,
    pub name: String,
    pub limit: u64,
    lock: Mutex<()>,
    clock: Arc<dyn Fn() -> NaiveDate + Send + Sync>,
    cleaned_day: Mutex<Option<NaiveDate>>,
}

fn private_error(message: &str) -> Error {
    Error::value(message)
}

impl FileLog {
    /// `FileLog(base)`: name `setup.log`, limit 2 MiB, local-date clock.
    pub fn new(base: impl AsRef<Path>) -> Self {
        FileLog { base: crate::paths::absolute(base.as_ref()), name: "setup.log".into(), limit: 2 * 1024 * 1024,
            lock: Mutex::new(()), clock: Arc::new(logfiles::today), cleaned_day: Mutex::new(None) }
    }
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = name.into();
        self
    }
    pub fn with_limit(mut self, limit: u64) -> Self {
        self.limit = limit;
        self
    }
    pub fn with_clock(mut self, clock: impl Fn() -> NaiveDate + Send + Sync + 'static) -> Self {
        self.clock = Arc::new(clock);
        self
    }

    /// Today's dated log path.
    pub fn path(&self) -> PathBuf {
        self.base.join(dated_name(&self.name, (self.clock)()))
    }

    /// Create missing private ancestors (0700) and open the private log directory.
    pub fn directory(&self) -> Result<OwnedFd> {
        let mut missing = Vec::new();
        let mut ancestor = self.base.as_path();
        while !ancestor.exists() && sys::lstat(ancestor).is_err() {
            missing.push(ancestor.to_path_buf());
            match ancestor.parent() {
                Some(parent) => ancestor = parent,
                None => break,
            }
        }
        for path in missing.iter().rev() {
            use std::os::unix::fs::DirBuilderExt;
            match std::fs::DirBuilder::new().mode(0o700).create(path) {
                Ok(()) => {}
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(e) => return Err(Error::with_path(e, path)),
            }
            let info = sys::lstat(path).map_err(|e| Error::with_path(e, path))?;
            if !sys::private_owned(&info, true) {
                return Err(private_error("Activity parent directory must be private"));
            }
        }
        let info = sys::lstat(&self.base).map_err(|e| Error::with_path(e, &self.base))?;
        if !sys::private_owned(&info, true) {
            return Err(private_error("Activity log directory must be private"));
        }
        sys::open(&self.base, libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW, 0).map_err(|e| Error::with_path(e, &self.base))
    }

    fn clean(&self, folder: &OwnedFd, day: NaiveDate) -> Result<Vec<String>> {
        let mut cleaned = self.cleaned_day.lock().unwrap();
        if *cleaned == Some(day) {
            return Ok(Vec::new());
        }
        logfiles::migrate_legacy_fd(folder.as_raw_fd())?;
        let removed = logfiles::prune(folder.as_raw_fd(), day)?;
        *cleaned = Some(day);
        Ok(removed)
    }

    /// Daily migration/expiry when the date changed; returns removed names.
    pub fn maintain(&self) -> Result<Vec<String>> {
        let day = (self.clock)();
        if *self.cleaned_day.lock().unwrap() == Some(day) {
            return Ok(Vec::new());
        }
        let folder = self.directory()?;
        let _lock = self.lock.lock().unwrap();
        self.clean(&folder, day)
    }

    /// Append one record as `json.dumps(value, ensure_ascii=False) + "\n"`.
    pub fn write(&self, value: &Value) -> Result<()> {
        let day = (self.clock)();
        let name = dated_name(&self.name, day);
        let folder = self.directory()?;
        {
            let _lock = self.lock.lock().unwrap();
            self.clean(&folder, day)?;
        }
        let dir = folder.as_raw_fd();
        let fd = sys::openat(dir, &name, libc::O_WRONLY | libc::O_APPEND | libc::O_CREAT | libc::O_NOFOLLOW | libc::O_NONBLOCK, 0o600)
            .map_err(|e| Error::with_path(e, &name))?;
        let info = sys::fstat(fd.as_raw_fd())?;
        if !sys::private_owned(&info, false) {
            return Err(private_error("Activity log must be private"));
        }
        let mut data = crate::pyjson::dumps_unicode(value);
        data.push('\n');
        let data = data.into_bytes();
        let _lock = self.lock.lock().unwrap();
        sys::flock(fd.as_raw_fd(), libc::LOCK_EX)?;
        let info = sys::fstat(fd.as_raw_fd())?;
        let size = info.st_size as u64;
        if size + data.len() as u64 > self.limit {
            let half = self.limit / 2;
            let old = sys::openat(dir, &name, libc::O_RDONLY | libc::O_NOFOLLOW, 0).map_err(|e| Error::with_path(e, &name))?;
            let tail = sys::pread(old.as_raw_fd(), half as usize, size.saturating_sub(half))?;
            drop(old);
            let backup_name = format!("{}.1", name);
            let backup = sys::openat(dir, &backup_name, libc::O_WRONLY | libc::O_CREAT | libc::O_NOFOLLOW | libc::O_NONBLOCK, 0o600)
                .map_err(|e| Error::with_path(e, &backup_name))?;
            let saved = sys::fstat(backup.as_raw_fd())?;
            if !sys::private_owned(&saved, false) {
                return Err(private_error("Activity backup must be a private regular file"));
            }
            sys::ftruncate(backup.as_raw_fd(), 0)?;
            sys::write_all(backup.as_raw_fd(), &tail)?;
            drop(backup);
            sys::ftruncate(fd.as_raw_fd(), 0)?;
        }
        sys::write_all(fd.as_raw_fd(), &data)?;
        Ok(())
    }

    pub fn into_sink(self) -> Sink {
        let log = Arc::new(self);
        sink(move |value| log.write(value))
    }

    pub fn shared_sink(log: &Arc<FileLog>) -> Sink {
        let log = log.clone();
        sink(move |value| log.write(value))
    }
}

/// Insert `-v` after an `ssh` executable when logging (Python `ssh_command`).
pub fn ssh_command(arguments: &[String]) -> Vec<String> {
    let mut arguments = arguments.to_vec();
    let is_ssh = arguments.first().map(|a| Path::new(a).file_name().is_some_and(|n| n == "ssh")).unwrap_or(false);
    if enabled() && is_ssh && !arguments.iter().any(|a| a == "-v") {
        arguments.insert(1, "-v".into());
    }
    arguments
}

struct LineLogger {
    sink: Sink,
    source: String,
    kind: &'static str,
    record: bool,
    pending: Vec<u8>,
}

impl LineLogger {
    fn level(&self) -> &'static str {
        if self.kind == "stderr" { "debug" } else { "info" }
    }
    fn emit_line(&self, line: &[u8]) {
        emit_to(&self.sink, &format!("{} {}", self.source, self.kind), &redact_line(line), self.level(), Value::Null);
    }
}

impl StreamObserver for LineLogger {
    fn data(&mut self, chunk: &[u8]) {
        if !self.record {
            return;
        }
        self.pending.extend_from_slice(chunk);
        while let Some(i) = self.pending.iter().position(|b| *b == b'\n') {
            let line: Vec<u8> = self.pending.drain(..=i).collect();
            let line = &line[..line.len() - 1];
            if !line.is_empty() {
                self.emit_line(line);
            }
        }
        if self.pending.len() > 8192 {
            emit_to(&self.sink, &format!("{} {}", self.source, self.kind),
                &format!("<oversized output line: {} bytes>", self.pending.len()), "debug", Value::Null);
            self.pending.clear();
        }
    }
    fn end(&mut self) {
        if !self.pending.is_empty() {
            let pending = std::mem::take(&mut self.pending);
            self.emit_line(&pending);
        }
    }
}

/// Like `subprocess.run`; when a sink is enabled, tee output into the live
/// log: `$ <cmd>` (input counted, never logged), `process started`, redacted
/// stdout/stderr lines, then `process exited` or `process timed out`.
/// Without a sink this is exactly [`subprocess::run`].
pub fn run<S: AsRef<str>>(command: &[S], options: &RunOptions) -> Result<Completed> {
    let Some(sink) = current() else { return subprocess::run(command, options) };
    let arguments: Vec<String> = command.iter().map(|s| s.as_ref().to_string()).collect();
    let command = if options.source == "SSH" { ssh_command(&arguments) } else { arguments };
    let source = options.source.as_str();
    let input_bytes = options.input.as_ref().map_or(0, Vec::len);
    emit_to(&sink, source, &format!("$ {}", crate::shlex::join(&command)), "info",
        serde_json::json!({"input_bytes": input_bytes}));
    let started = Instant::now();
    let observers: (Box<dyn StreamObserver>, Box<dyn StreamObserver>) = (
        Box::new(LineLogger { sink: sink.clone(), source: source.into(), kind: "stdout", record: options.record_stdout, pending: Vec::new() }),
        Box::new(LineLogger { sink: sink.clone(), source: source.into(), kind: "stderr", record: true, pending: Vec::new() }),
    );
    let execution = subprocess::execute(&command, options, true, Some(observers), |pid| {
        emit_to(&sink, source, "process started", "info", serde_json::json!({"pid": pid}));
    })?;
    match execution.outcome {
        subprocess::Outcome::TimedOut => {
            emit_to(&sink, source, "process timed out", "error", serde_json::json!({
                "pid": execution.pid, "timeout_seconds": options.timeout.map(pyfmt::duration_json)}));
        }
        subprocess::Outcome::Exited { code } => {
            emit_to(&sink, source, "process exited", if code == 0 { "info" } else { "error" }, serde_json::json!({
                "pid": execution.pid, "exit_code": code, "elapsed_ms": pyfmt::elapsed_ms(started),
                "stdout_bytes": execution.stdout.len(), "stderr_bytes": execution.stderr.len()}));
        }
    }
    subprocess::finish(command, options, execution)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::Event;
    use serde_json::json;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::time::Duration;

    fn ymd(y: i32, m: u32, d: u32) -> NaiveDate {
        NaiveDate::from_ymd_opt(y, m, d).unwrap()
    }

    fn write_private(path: &Path, text: &str, mode: u32) {
        std::fs::write(path, text).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
    }

    fn private_dir(path: &Path) {
        std::fs::create_dir(path).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
    }

    fn records_json(records: &Arc<Mutex<Vec<Value>>>) -> String {
        serde_json::to_string(&*records.lock().unwrap()).unwrap()
    }

    #[test]
    fn real_stderr_is_visible_before_the_operation_completes() {
        let temp = tempfile::tempdir().unwrap();
        let gate = temp.path().join("continue");
        let script = r#"echo 'MIRRA_ENDPOINT stage=MAEIssueDCRTWithCallback_call' >&2
i=0; while [ ! -e "$1" ] && [ $i -lt 500 ]; do sleep 0.01; i=$((i+1)); done
echo '{"certificate_exported":true,"bytes":1234}'"#;
        let child = temp.path().join("child.sh");
        std::fs::write(&child, script).unwrap();
        let command = vec!["/bin/sh".to_string(), child.to_string_lossy().into(), gate.to_string_lossy().into()];
        let log = Arc::new(FileLog::new(temp.path().join("logs")));
        let first = Event::new();
        let records = Arc::new(Mutex::new(Vec::new()));
        let (target, flag, file) = (records.clone(), first.clone(), log.clone());
        let observed = sink(move |value| {
            target.lock().unwrap().push(value.clone());
            file.write(value)?;
            if value["message"].as_str().unwrap_or("").contains("MAEIssueDCRTWithCallback_call") {
                flag.set();
            }
            Ok(())
        });
        let worker = std::thread::spawn(move || {
            capture(Some(observed), || run(&command, &RunOptions::new().source("SSH").capture().timeout_secs(6.0)))
        });
        assert!(first.wait(Some(Duration::from_secs(3))), "stderr was buffered until completion");
        assert!(!worker.is_finished(), "the intermediate line was not live");
        let text = std::fs::read_to_string(log.path()).unwrap();
        assert!(text.contains("MAEIssueDCRTWithCallback_call"));
        assert!(!text.contains("certificate_exported"));
        std::fs::write(&gate, "").unwrap();
        let result = worker.join().unwrap().unwrap();
        assert_eq!(result.stdout, b"{\"certificate_exported\":true,\"bytes\":1234}\n");
        assert!(records.lock().unwrap().iter().any(|r| r["fields"]["exit_code"] == 0));
    }

    #[test]
    fn input_and_binary_certificate_do_not_enter_logs() {
        let (collect, records) = collector();
        let payload = b"\x00private certificate fixture\xff".to_vec();
        let result = capture(Some(collect), || run(&["/bin/cat"], &RunOptions::new().source("SSH").input(payload.clone())
            .capture().record_stdout(false).timeout_secs(3.0))).unwrap();
        assert_eq!(result.stdout, payload);
        assert!(!records_json(&records).contains("private certificate fixture"));
        let records = records.lock().unwrap();
        assert_eq!(records.last().unwrap()["fields"]["stdout_bytes"], payload.len());
        assert_eq!(records[0]["message"], "$ /bin/cat");
        assert_eq!(records[0]["fields"]["input_bytes"], payload.len());
    }

    #[test]
    fn nonzero_exit_keeps_real_output_and_check_semantics() {
        let (collect, records) = collector();
        let failed = capture(Some(collect), || run(&["/bin/sh", "-c",
            "echo 'unsupported_device: aks_ref_key_create is missing' >&2; exit 17"],
            &RunOptions::new().source("SSH").capture().check().timeout_secs(3.0))).unwrap_err();
        match &failed {
            Error::CalledProcess { code, stderr, .. } => {
                assert_eq!(*code, 17);
                assert!(String::from_utf8_lossy(stderr).contains("aks_ref_key_create"));
            }
            other => panic!("unexpected {other:?}"),
        }
        let records = records.lock().unwrap();
        assert!(records.iter().any(|r| r["message"].as_str().unwrap().contains("unsupported_device: aks_ref_key_create is missing")));
        assert_eq!(records.last().unwrap()["fields"]["exit_code"], 17);
        assert_eq!(records.last().unwrap()["level"], "error");
    }

    #[test]
    fn ssh_source_adds_verbose_flag_only_when_logging() {
        let arguments = vec!["/usr/bin/ssh".to_string(), "-T".into(), "host".into()];
        assert_eq!(ssh_command(&arguments), arguments);
        let (collect, _) = collector();
        capture(Some(collect), || {
            assert_eq!(ssh_command(&arguments), vec!["/usr/bin/ssh", "-v", "-T", "host"]);
            let verbose = vec!["ssh".to_string(), "-v".into()];
            assert_eq!(ssh_command(&verbose), verbose);
        });
    }

    #[test]
    fn timeout_reaps_only_the_logger_owned_child() {
        let (collect, records) = collector();
        let failed = capture(Some(collect), || run(&["/bin/sleep", "20"], &RunOptions::new().timeout_secs(0.2))).unwrap_err();
        assert_eq!(failed.type_name(), "TimeoutExpired");
        let records = records.lock().unwrap();
        let pid = records.iter().find(|r| r["message"] == "process started").unwrap()["fields"]["pid"].as_i64().unwrap();
        assert_eq!(unsafe { libc::kill(pid as i32, 0) }, -1);
        assert_eq!(sys::errno(), libc::ESRCH);
        let last = records.last().unwrap();
        assert_eq!(last["message"], "process timed out");
        assert_eq!(last["fields"]["timeout_seconds"], 0.2);
    }

    #[test]
    fn operation_records_begin_complete_and_failure() {
        let (collect, records) = collector();
        capture(Some(collect), || {
            let ok: Result<i32> = operation("Service", "restore", json!({"target": "x"}), || Ok(4));
            assert_eq!(ok.unwrap(), 4);
            let failed: Result<()> = operation("Service", "stop", Value::Null, || Err(Error::runtime("Cannot stop")));
            assert!(failed.is_err());
        });
        assert!(!enabled());
        let records = records.lock().unwrap();
        let messages: Vec<&str> = records.iter().map(|r| r["message"].as_str().unwrap()).collect();
        assert_eq!(messages, ["restore begin", "restore complete", "stop begin", "stop failed"]);
        let keys: Vec<&String> = records[1]["fields"].as_object().unwrap().keys().collect();
        assert_eq!(keys, ["elapsed_ms", "target"]);
        assert_eq!(records[3]["fields"]["error_type"], "RuntimeError");
        assert_eq!(records[3]["fields"]["error"], "Cannot stop");
        assert_eq!(records[3]["level"], "error");
        assert!(records[2].get("fields").is_none());
        let keys: Vec<&String> = records[0].as_object().unwrap().keys().collect();
        assert_eq!(keys, ["timestamp", "source", "level", "message", "fields"]);
        assert!(records[0]["timestamp"].as_str().unwrap().ends_with("+00:00"));
    }

    #[test]
    fn rotation_preserves_current_inode_and_refuses_symlinks() {
        let temp = tempfile::tempdir().unwrap();
        let folder = temp.path().join("logs");
        let logger = FileLog::new(&folder).with_limit(2048);
        logger.write(&json!({"message": "first"})).unwrap();
        let path = logger.path();
        let inode = std::fs::metadata(&path).unwrap().ino();
        for _ in 0..20 {
            logger.write(&json!({"message": "x".repeat(200)})).unwrap();
        }
        assert_eq!(std::fs::metadata(&path).unwrap().ino(), inode);
        assert!(std::fs::metadata(&path).unwrap().len() <= 2048);
        let backup = path.with_file_name(format!("{}.1", path.file_name().unwrap().to_string_lossy()));
        assert_eq!(std::fs::metadata(&backup).unwrap().permissions().mode() & 0o777, 0o600);
        let other = temp.path().join("other");
        std::fs::write(&other, "unchanged").unwrap();
        std::os::unix::fs::symlink(&other, folder.join("bad.log")).unwrap();
        let failed = FileLog::new(&folder).with_name("bad.log").write(&json!({"message": "bad"})).unwrap_err();
        assert!(failed.is_os_error());
        assert_eq!(std::fs::read_to_string(&other).unwrap(), "unchanged");
    }

    #[test]
    fn new_installation_creates_private_parent_directories() {
        let temp = tempfile::tempdir().unwrap();
        let folder = temp.path().join("new-Mirra/logs");
        let log = FileLog::new(&folder);
        log.write(&json!({"source": "SSH stderr", "message": "Authentication succeeded (publickey)."})).unwrap();
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(folder.parent().unwrap()), 0o700);
        assert_eq!(mode(&folder), 0o700);
        assert_eq!(mode(&log.path()), 0o600);
        let public = temp.path().join("public");
        std::fs::create_dir(&public).unwrap();
        std::fs::set_permissions(&public, std::fs::Permissions::from_mode(0o755)).unwrap();
        assert_eq!(FileLog::new(&public).write(&json!({})).unwrap_err().to_string(), "Activity log directory must be private");
    }

    #[test]
    fn routine_poll_suppresses_success_dump_and_keeps_actual_failure() {
        let (collect, records) = collector();
        capture(Some(poll_errors(collect)), || {
            let success = run(&["/bin/echo", "routine successful status dump"], &RunOptions::new().capture().timeout_secs(3.0)).unwrap();
            assert_eq!(success.stdout, b"routine successful status dump\n");
            assert!(records.lock().unwrap().is_empty());
            let failure = run(&["/bin/sh", "-c", "echo 'actual launchctl failure 42' >&2; exit 42"],
                &RunOptions::new().capture().timeout_secs(3.0)).unwrap();
            assert_eq!(failure.code, 42);
        });
        let records = records.lock().unwrap();
        assert!(records.iter().any(|r| r["message"].as_str().unwrap().contains("actual launchctl failure 42")));
        assert_eq!(records.last().unwrap()["fields"]["exit_code"], 42);
    }

    #[test]
    fn daily_filename_changes_at_midnight_and_preserves_yesterday() {
        let temp = tempfile::tempdir().unwrap();
        let folder = temp.path().join("logs");
        let day = Arc::new(Mutex::new(ymd(2026, 11, 8)));
        let clock = day.clone();
        let log = FileLog::new(&folder).with_clock(move || *clock.lock().unwrap());
        log.write(&json!({"message": "actual last operation before midnight"})).unwrap();
        let yesterday = folder.join("setup-2026-11-08.log");
        let before = std::fs::read(&yesterday).unwrap();
        assert_eq!(serde_json::from_slice::<Value>(&before).unwrap()["message"], "actual last operation before midnight");
        assert_eq!(before, b"{\"message\": \"actual last operation before midnight\"}\n");
        *day.lock().unwrap() = ymd(2026, 11, 9);
        log.write(&json!({"message": "actual first operation after midnight"})).unwrap();
        assert_eq!(std::fs::read(&yesterday).unwrap(), before);
        let today: Value = serde_json::from_slice(&std::fs::read(folder.join("setup-2026-11-09.log")).unwrap()).unwrap();
        assert_eq!(today["message"], "actual first operation after midnight");
    }

    #[test]
    fn seven_day_retention_removes_only_expired_private_managed_logs() {
        let temp = tempfile::tempdir().unwrap();
        let folder = temp.path().join("logs");
        private_dir(&folder);
        let names = ["setup-2026-11-01.log", "native-2026-11-01.log.1", "control-2026-11-02.log", "app-2026-11-08.log",
            "setup-2026-11-09.log", "setup-2026-02-30.log", "notes.txt", "service.log"];
        for name in names {
            write_private(&folder.join(name), "retention test", 0o600);
        }
        let outside = temp.path().join("outside");
        std::fs::write(&outside, "unrelated file").unwrap();
        std::os::unix::fs::symlink(&outside, folder.join("app-2026-10-31.log")).unwrap();
        let public = folder.join("control-2026-10-31.log");
        write_private(&public, "unmanaged public file", 0o644);
        let mut removed = FileLog::new(&folder).with_clock(|| ymd(2026, 11, 8)).maintain().unwrap();
        removed.sort();
        assert_eq!(removed, ["native-2026-11-01.log.1", "setup-2026-11-01.log"]);
        for name in &names[2..] {
            assert!(folder.join(name).exists(), "{}", name);
        }
        assert!(std::fs::symlink_metadata(folder.join("app-2026-10-31.log")).unwrap().file_type().is_symlink());
        assert_eq!(std::fs::read_to_string(&outside).unwrap(), "unrelated file");
        assert_eq!(std::fs::read_to_string(&public).unwrap(), "unmanaged public file");
    }

    #[test]
    fn idle_maintenance_expires_logs_on_the_next_date_change() {
        let temp = tempfile::tempdir().unwrap();
        let folder = temp.path().join("logs");
        private_dir(&folder);
        let path = folder.join("native-2026-11-02.log");
        write_private(&path, "six days old", 0o600);
        let day = Arc::new(Mutex::new(ymd(2026, 11, 8)));
        let clock = day.clone();
        let log = FileLog::new(&folder).with_clock(move || *clock.lock().unwrap());
        assert!(log.maintain().unwrap().is_empty());
        assert!(path.exists());
        *day.lock().unwrap() = ymd(2026, 11, 9);
        assert_eq!(log.maintain().unwrap(), ["native-2026-11-02.log"]);
        assert!(!path.exists());
    }

    #[test]
    fn legacy_migration_preserves_bytes_inode_and_existing_dated_files() {
        let temp = tempfile::tempdir().unwrap();
        let folder = temp.path().join("logs");
        private_dir(&folder);
        let path = folder.join("setup.log");
        write_private(&path, "original SSH output\n", 0o600);
        let inode = std::fs::metadata(&path).unwrap().ino();
        let old = folder.join("control.log");
        write_private(&old, "existing legacy", 0o600);
        let today = logfiles::today().format("%Y-%m-%d").to_string();
        let current = folder.join(format!("control-{}.log", today));
        write_private(&current, "existing dated", 0o600);
        let renamed = logfiles::migrate_legacy(&folder).unwrap();
        let target = folder.join(format!("setup-{}.log", today));
        assert_eq!(std::fs::read_to_string(&target).unwrap(), "original SSH output\n");
        assert_eq!(std::fs::metadata(&target).unwrap().ino(), inode);
        assert!(!path.exists());
        assert_eq!(std::fs::read_to_string(&current).unwrap(), "existing dated");
        assert_eq!(std::fs::read_to_string(&old).unwrap(), "existing legacy");
        assert_eq!(renamed, vec![json!({"from": "setup.log", "to": format!("setup-{}.log", today)})]);
    }

    #[test]
    fn app_event_startup_performs_expiration_without_touching_other_files() {
        let temp = tempfile::tempdir().unwrap();
        let folder = temp.path().join("logs");
        private_dir(&folder);
        let today = logfiles::today();
        let old = folder.join(format!("native-{}.log", (today - chrono::TimeDelta::days(8)).format("%Y-%m-%d")));
        write_private(&old, "expiration fixture", 0o600);
        let legacy = folder.join("setup.log");
        write_private(&legacy, "earlier SSH output\n", 0o600);
        let other = folder.join("keep.txt");
        std::fs::write(&other, "owner file").unwrap();
        FileLog::new(&folder).with_name("app.log").write(&json!({"source": "Mirra", "message": "capture started"})).unwrap();
        let stamp = today.format("%Y-%m-%d");
        assert!(!old.exists());
        assert_eq!(std::fs::read_to_string(&other).unwrap(), "owner file");
        assert!(folder.join(format!("app-{}.log", stamp)).is_file());
        assert_eq!(std::fs::read_to_string(folder.join(format!("setup-{}.log", stamp))).unwrap(), "earlier SSH output\n");
        assert!(!legacy.exists());
    }

    #[test]
    fn timestamps_match_python_isoformat() {
        let value = utc_timestamp();
        assert!(value.ends_with("+00:00"));
        assert!(value.len() == 32 || value.len() == 25, "{}", value);
    }
}
