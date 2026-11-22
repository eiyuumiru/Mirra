//! `subprocess.run` equivalent (bytes output, timeout kill, check), shared by
//! the logged runner in [`crate::activity::run`].
use std::ffi::OsString;
use std::io::{Read, Write};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::error::{Error, Result};

#[derive(Clone, Debug)]
pub struct RunOptions {
    /// Activity source label (`source=` in Python; default `Process`).
    pub source: String,
    /// When false, stdout is captured but never logged (`record_stdout=False`).
    pub record_stdout: bool,
    /// Bytes fed to stdin (`input=`); stdin is otherwise inherited when unlogged.
    pub input: Option<Vec<u8>>,
    pub timeout: Option<Duration>,
    pub check: bool,
    /// `capture_output=True`. Logged runs always capture.
    pub capture_output: bool,
    /// Full replacement environment (`env=`).
    pub env: Option<Vec<(OsString, OsString)>>,
    pub cwd: Option<PathBuf>,
    pub start_new_session: bool,
}

impl Default for RunOptions {
    fn default() -> Self {
        RunOptions { source: "Process".into(), record_stdout: true, input: None, timeout: None, check: false,
            capture_output: false, env: None, cwd: None, start_new_session: false }
    }
}

impl RunOptions {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn source(mut self, source: impl Into<String>) -> Self {
        self.source = source.into();
        self
    }
    pub fn record_stdout(mut self, record: bool) -> Self {
        self.record_stdout = record;
        self
    }
    pub fn input(mut self, data: impl Into<Vec<u8>>) -> Self {
        self.input = Some(data.into());
        self
    }
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }
    pub fn timeout_secs(self, seconds: f64) -> Self {
        self.timeout(Duration::from_secs_f64(seconds))
    }
    pub fn check(mut self) -> Self {
        self.check = true;
        self
    }
    pub fn capture(mut self) -> Self {
        self.capture_output = true;
        self
    }
    pub fn env(mut self, env: Vec<(OsString, OsString)>) -> Self {
        self.env = Some(env);
        self
    }
    pub fn cwd(mut self, cwd: impl Into<PathBuf>) -> Self {
        self.cwd = Some(cwd.into());
        self
    }
    pub fn new_session(mut self) -> Self {
        self.start_new_session = true;
        self
    }
}

/// `subprocess.CompletedProcess` with bytes output.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Completed {
    pub args: Vec<String>,
    /// Exit status; `-signal` when killed by a signal (Python `returncode`).
    pub code: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

impl Completed {
    pub fn success(&self) -> bool {
        self.code == 0
    }
    pub fn stdout_text(&self) -> String {
        String::from_utf8_lossy(&self.stdout).into_owned()
    }
    pub fn stderr_text(&self) -> String {
        String::from_utf8_lossy(&self.stderr).into_owned()
    }
}

pub fn return_code(status: ExitStatus) -> i32 {
    status.code().unwrap_or_else(|| -status.signal().unwrap_or(0))
}

/// Receives the live bytes of one output stream (drain thread).
pub(crate) trait StreamObserver: Send {
    fn data(&mut self, chunk: &[u8]);
    fn end(&mut self);
}

pub(crate) enum Outcome {
    Exited { code: i32 },
    TimedOut,
}

pub(crate) struct Execution {
    pub pid: u32,
    pub outcome: Outcome,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

fn drain<R: Read + Send + 'static>(mut stream: R, buffer: Arc<Mutex<Vec<u8>>>, mut observer: Option<Box<dyn StreamObserver>>)
    -> mpsc::Receiver<()> {
    let (done, finished) = mpsc::channel::<()>();
    std::thread::spawn(move || {
        let _done = done;
        let mut chunk = vec![0u8; 16384];
        loop {
            match stream.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => {
                    buffer.lock().unwrap().extend_from_slice(&chunk[..n]);
                    if let Some(observer) = observer.as_mut() {
                        observer.data(&chunk[..n]);
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(_) => break,
            }
        }
        if let Some(observer) = observer.as_mut() {
            observer.end();
        }
    });
    finished
}

fn wait_with_timeout(child: &mut Child, timeout: Option<Duration>) -> std::io::Result<Option<ExitStatus>> {
    let Some(timeout) = timeout else { return child.wait().map(Some) };
    let deadline = Instant::now() + timeout;
    let mut pause = Duration::from_micros(500);
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(Some(status));
        }
        let now = Instant::now();
        if now >= deadline {
            return Ok(None);
        }
        std::thread::sleep(pause.min(deadline - now));
        pause = (pause * 2).min(Duration::from_millis(20));
    }
}

/// Spawn and collect. `logged` forces stdin/stdout/stderr pipes (activity mode).
pub(crate) fn execute(command: &[String], options: &RunOptions, logged: bool,
    observers: Option<(Box<dyn StreamObserver>, Box<dyn StreamObserver>)>, started: impl FnOnce(u32))
    -> Result<Execution> {
    let Some(program) = command.first() else { return Err(Error::value("Command must not be empty")) };
    let capture = logged || options.capture_output;
    let pipe_stdin = logged || options.input.is_some();
    let mut builder = Command::new(program);
    builder.args(&command[1..]);
    builder.stdin(if pipe_stdin { Stdio::piped() } else { Stdio::inherit() });
    builder.stdout(if capture { Stdio::piped() } else { Stdio::inherit() });
    builder.stderr(if capture { Stdio::piped() } else { Stdio::inherit() });
    if let Some(env) = &options.env {
        builder.env_clear();
        builder.envs(env.iter().map(|(k, v)| (k, v)));
    }
    if let Some(cwd) = &options.cwd {
        builder.current_dir(cwd);
    }
    if options.start_new_session {
        unsafe {
            builder.pre_exec(|| {
                if libc::setsid() < 0 { Err(std::io::Error::last_os_error()) } else { Ok(()) }
            });
        }
    }
    let mut child = builder.spawn().map_err(|e| Error::with_path(e, program))?;
    let pid = child.id();
    started(pid);
    let stdout = Arc::new(Mutex::new(Vec::new()));
    let stderr = Arc::new(Mutex::new(Vec::new()));
    let (out_observer, err_observer) = match observers {
        Some((a, b)) => (Some(a), Some(b)),
        None => (None, None),
    };
    let mut waits = Vec::new();
    if let Some(stream) = child.stdout.take() {
        waits.push(drain(stream, stdout.clone(), out_observer));
    }
    if let Some(stream) = child.stderr.take() {
        waits.push(drain(stream, stderr.clone(), err_observer));
    }
    if let Some(mut stdin) = child.stdin.take() {
        let data = options.input.clone().unwrap_or_default();
        let (done, finished) = mpsc::channel::<()>();
        std::thread::spawn(move || {
            let _done = done;
            if !data.is_empty() {
                let _ = stdin.write_all(&data).and_then(|_| stdin.flush());
            }
            drop(stdin);
        });
        waits.push(finished);
    }
    let status = match wait_with_timeout(&mut child, options.timeout) {
        Ok(status) => status,
        Err(error) => {
            let _ = child.kill();
            let _ = child.wait();
            return Err(error.into());
        }
    };
    let outcome = match status {
        Some(status) => Outcome::Exited { code: return_code(status) },
        None => {
            let _ = child.kill();
            let _ = child.wait();
            Outcome::TimedOut
        }
    };
    for finished in waits {
        let _ = finished.recv_timeout(Duration::from_secs(2));
    }
    let stdout = stdout.lock().unwrap().clone();
    let stderr = stderr.lock().unwrap().clone();
    Ok(Execution { pid, outcome, stdout, stderr })
}

/// Plain `subprocess.run(command, input=, capture_output=, timeout=, check=, env=, cwd=,
/// start_new_session=)`. Never logs; see [`crate::activity::run`] for the logged form.
pub fn run<S: AsRef<str>>(command: &[S], options: &RunOptions) -> Result<Completed> {
    let command: Vec<String> = command.iter().map(|s| s.as_ref().to_string()).collect();
    let execution = execute(&command, options, false, None, |_| {})?;
    finish(command, options, execution)
}

pub(crate) fn finish(command: Vec<String>, options: &RunOptions, execution: Execution) -> Result<Completed> {
    match execution.outcome {
        Outcome::TimedOut => Err(Error::TimeoutExpired {
            command, timeout: options.timeout.unwrap_or_default(), stdout: execution.stdout, stderr: execution.stderr,
        }),
        Outcome::Exited { code } if options.check && code != 0 => Err(Error::CalledProcess {
            code, command, stdout: execution.stdout, stderr: execution.stderr,
        }),
        Outcome::Exited { code } => Ok(Completed { args: command, code, stdout: execution.stdout, stderr: execution.stderr }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_run_captures_feeds_and_checks() {
        let reply = run(&["/bin/cat"], &RunOptions::new().input(b"abc".to_vec()).capture()).unwrap();
        assert_eq!(reply.stdout, b"abc");
        let failed = run(&["/bin/sh", "-c", "echo bad >&2; exit 3"], &RunOptions::new().capture().check()).unwrap_err();
        assert_eq!(failed.to_string(), "Command '['/bin/sh', '-c', 'echo bad >&2; exit 3']' returned non-zero exit status 3.");
        assert_eq!(failed.output().1, b"bad\n");
        let timed = run(&["/bin/sleep", "5"], &RunOptions::new().timeout_secs(0.1)).unwrap_err();
        assert_eq!(timed.type_name(), "TimeoutExpired");
        assert_eq!(timed.to_string(), "Command '['/bin/sleep', '5']' timed out after 0.1 seconds");
        let missing = run(&["/nonexistent/tool"], &RunOptions::new()).unwrap_err();
        assert_eq!(missing.to_string(), "[Errno 2] No such file or directory: '/nonexistent/tool'");
        assert_eq!(missing.type_name(), "FileNotFoundError");
        let killed = run(&["/bin/sh", "-c", "kill -9 $$"], &RunOptions::new()).unwrap();
        assert_eq!(killed.code, -9);
    }
}
