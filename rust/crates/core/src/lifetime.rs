//! Explicit session deadlines and a pipe lifeline for restoration controllers.
use std::os::fd::RawFd;
use std::sync::Mutex;
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use serde_json::Value;

use crate::sys;

pub const DURATION_ERROR: &str = "Bounded session duration must be 30..1800 seconds";
/// argparse's message when `--seconds` and `--until-stopped` are combined.
pub const EXCLUSIVE_ERROR: &str = "argument --until-stopped: not allowed with argument --seconds";

/// `duration_from_arguments`: `None` = continuous (`--until-stopped`).
pub fn duration_from_arguments(seconds: Option<i64>, until_stopped: bool, default: i64) -> Result<Option<u64>, String> {
    if until_stopped {
        if seconds.is_some() {
            return Err(EXCLUSIVE_ERROR.into());
        }
        return Ok(None);
    }
    let seconds = seconds.unwrap_or(default);
    if !(30..=1800).contains(&seconds) {
        return Err(DURATION_ERROR.into());
    }
    Ok(Some(seconds as u64))
}

/// A monotonic deadline; `Deadline(None)` is Python's `float('inf')`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Deadline(pub Option<Instant>);

impl Deadline {
    pub fn infinite() -> Self {
        Deadline(None)
    }
    pub fn after(duration: Duration) -> Self {
        Deadline(Some(Instant::now() + duration))
    }
    pub fn is_infinite(&self) -> bool {
        self.0.is_none()
    }
    /// `time.monotonic() >= deadline`
    pub fn expired(&self) -> bool {
        matches!(self.0, Some(at) if Instant::now() >= at)
    }
    /// Remaining time (`None` when infinite; zero once expired).
    pub fn remaining(&self) -> Option<Duration> {
        self.0.map(|at| at.saturating_duration_since(Instant::now()))
    }
}

/// `deadline_for(seconds)`: `None` gives an infinite deadline.
pub fn deadline_for(seconds: Option<u64>) -> Deadline {
    match seconds {
        None => Deadline::infinite(),
        Some(s) => Deadline::after(Duration::from_secs(s)),
    }
}

static STDOUT: Mutex<()> = Mutex::new(());

/// Print `json.dumps(event)` as one line on fd 1 and flush. A lost diagnostic
/// reader must not prevent native-agent restoration: on EPIPE, /dev/null is
/// installed as fd 1 and the event is dropped.
pub fn emit_event(event: &Value) -> std::io::Result<()> {
    let mut line = crate::pyjson::dumps(event);
    line.push('\n');
    let _guard = STDOUT.lock().unwrap_or_else(|e| e.into_inner());
    match sys::write_all(1, line.as_bytes()) {
        Err(error) if error.raw_os_error() == Some(libc::EPIPE) => {
            let sink = sys::open(std::path::Path::new("/dev/null"), libc::O_WRONLY, 0)?;
            use std::os::fd::AsRawFd;
            if unsafe { libc::dup2(sink.as_raw_fd(), 1) } < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        }
        other => other,
    }
}

/// Parent retains the write end; EOF (or a read error) calls `stop` once,
/// even after the parent is SIGKILLed. Input bytes are ignored.
pub fn watch_parent_pipe<F: FnOnce() + Send + 'static>(fd: RawFd, stop: F) -> JoinHandle<()> {
    std::thread::Builder::new()
        .name("parent-lifeline".into())
        .spawn(move || {
            let mut buffer = [0u8; 256];
            loop {
                let n = unsafe { libc::read(fd, buffer.as_mut_ptr().cast(), buffer.len()) };
                if n < 0 && sys::errno() == libc::EINTR {
                    continue;
                }
                if n <= 0 {
                    stop();
                    return;
                }
            }
        })
        .expect("cannot start parent lifeline thread")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::event::Event;

    #[test]
    fn continuous_mode_is_explicit() {
        assert_eq!(duration_from_arguments(None, false, 1800), Ok(Some(1800)));
        assert_eq!(duration_from_arguments(None, true, 1800), Ok(None));
        assert!(deadline_for(None).is_infinite());
        assert!(!deadline_for(None).expired());
        assert!(deadline_for(Some(0)).expired());
    }

    #[test]
    fn duration_and_continuous_mode_cannot_be_combined() {
        assert_eq!(duration_from_arguments(Some(30), true, 1800), Err(EXCLUSIVE_ERROR.into()));
    }

    #[test]
    fn zero_seconds_is_not_an_implicit_continuous_session() {
        assert_eq!(duration_from_arguments(Some(0), false, 1800), Err(DURATION_ERROR.into()));
    }

    #[test]
    fn parent_pipe_eof_requests_cleanup() {
        let mut fds = [0; 2];
        assert_eq!(unsafe { libc::pipe(fds.as_mut_ptr()) }, 0);
        let (reader, writer) = (fds[0], fds[1]);
        // Children spawned by concurrent tests must not inherit the write end.
        for fd in fds {
            unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) };
        }
        let stopped = Event::new();
        let flag = stopped.clone();
        let thread = watch_parent_pipe(reader, move || flag.set());
        sys::write_all(writer, b"ignored input").unwrap();
        assert!(!stopped.wait(Some(Duration::from_millis(30))));
        unsafe { libc::close(writer) };
        assert!(stopped.wait(Some(Duration::from_secs(1))));
        thread.join().unwrap();
        unsafe { libc::close(reader) };
    }
}
