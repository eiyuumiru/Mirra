//! Observe broker health without treating an unanswered query as process loss.
use std::io::{ErrorKind, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, Instant};

use serde_json::{Map, Value};

use crate::error::{Error, Result};
use crate::event::Event;

pub const MAX_REPLY: usize = 262144;

fn socket_error(error: std::io::Error) -> Error {
    match error.kind() {
        // Python's socket.timeout (TimeoutError) reads "timed out".
        ErrorKind::WouldBlock | ErrorKind::TimedOut => Error::Timeout("timed out".into()),
        _ => Error::Os(error),
    }
}

/// Wait until `fd` is ready for `events` before `deadline` (Python socket
/// timeouts use poll, not SO_RCVTIMEO, which macOS rejects once a peer closes).
fn ready(fd: i32, events: i16, deadline: Instant) -> Result<()> {
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(Error::Timeout("timed out".into()));
        }
        let mut entry = libc::pollfd { fd, events, revents: 0 };
        let millis = remaining.as_millis().clamp(1, i32::MAX as u128) as i32;
        let result = unsafe { libc::poll(&mut entry, 1, millis) };
        if result < 0 {
            let error = std::io::Error::last_os_error();
            if error.kind() == ErrorKind::Interrupted {
                continue;
            }
            return Err(Error::Os(error));
        }
        if result > 0 {
            return Ok(());
        }
    }
}

/// One `{"operation":"health"}` request over the broker's length-prefixed
/// (big-endian u32) unix socket protocol, within a single overall deadline.
/// Errors: `Timeout`, `Connection`, `Os` (observation) or `Value` (bad reply).
pub fn health(path: &Path, timeout: Duration) -> Result<Map<String, Value>> {
    let deadline = Instant::now() + timeout;
    let mut connection = UnixStream::connect(path).map_err(socket_error)?;
    connection.set_nonblocking(true).map_err(socket_error)?;
    let fd = connection.as_raw_fd();
    let message = br#"{"operation":"health"}"#;
    let mut frame = (message.len() as u32).to_be_bytes().to_vec();
    frame.extend_from_slice(message);
    let mut sent = 0;
    while sent < frame.len() {
        ready(fd, libc::POLLOUT, deadline)?;
        match connection.write(&frame[sent..]) {
            Ok(n) => sent += n,
            Err(e) if matches!(e.kind(), ErrorKind::Interrupted | ErrorKind::WouldBlock) => continue,
            Err(e) => return Err(socket_error(e)),
        }
    }

    let mut readn = |count: usize| -> Result<Vec<u8>> {
        let mut data = vec![0u8; count];
        let mut filled = 0;
        while filled < count {
            if Instant::now() >= deadline {
                return Err(Error::Timeout("Broker health observation expired".into()));
            }
            ready(fd, libc::POLLIN, deadline)?;
            match connection.read(&mut data[filled..]) {
                Ok(0) => return Err(Error::Connection("Broker closed health connection".into())),
                Ok(n) => filled += n,
                Err(e) if matches!(e.kind(), ErrorKind::Interrupted | ErrorKind::WouldBlock) => continue,
                Err(e) => return Err(socket_error(e)),
            }
        }
        Ok(data)
    };
    let header = readn(4)?;
    let size = u32::from_be_bytes([header[0], header[1], header[2], header[3]]) as usize;
    if !(0 < size && size <= MAX_REPLY) {
        return Err(Error::value("Invalid broker reply length"));
    }
    let body = readn(size)?;
    match serde_json::from_slice::<Value>(&body) {
        Ok(Value::Object(map)) => Ok(map),
        Ok(_) => Err(Error::value("Invalid broker health reply")),
        Err(e) => Err(Error::value(e.to_string())),
    }
}

/// A child process handle: `Some(code)` once it has terminated (`Popen.poll`).
pub trait ProcessPoll {
    fn poll(&mut self) -> Option<i32>;
}

impl ProcessPoll for std::process::Child {
    fn poll(&mut self) -> Option<i32> {
        match self.try_wait() {
            Ok(Some(status)) => Some(crate::subprocess::return_code(status)),
            _ => None,
        }
    }
}

/// `threading.Event`-like stop signal.
pub trait StopSignal {
    /// Wait up to `timeout`; true when stopped.
    fn wait(&self, timeout: Duration) -> bool;
    fn is_set(&self) -> bool;
}

impl StopSignal for Event {
    fn wait(&self, timeout: Duration) -> bool {
        Event::wait(self, Some(timeout))
    }
    fn is_set(&self) -> bool {
        Event::is_set(self)
    }
}

/// Return a confirmed failure reason (`broker_exited` or
/// `broker_reported_unhealthy`), or `None` when the caller stops watching.
///
/// A terminal process result establishes process loss. Two explicit unhealthy
/// replies establish broker failure. A missing/malformed/timed-out observation
/// establishes neither; poll the same process and socket again.
pub fn wait_for_backend_loss(process: &mut dyn ProcessPoll, path: &Path, stop: &dyn StopSignal,
    timeout: Duration, interval: Duration) -> Option<&'static str> {
    wait_for_backend_loss_with(process, stop, interval, &mut || health(path, timeout))
}

/// As [`wait_for_backend_loss`] with an injectable health observation.
pub fn wait_for_backend_loss_with(process: &mut dyn ProcessPoll, stop: &dyn StopSignal, interval: Duration,
    observe: &mut dyn FnMut() -> Result<Map<String, Value>>) -> Option<&'static str> {
    let mut failures = 0;
    while !stop.wait(interval) {
        if process.poll().is_some() {
            return Some("broker_exited");
        }
        let Ok(response) = observe() else { continue };
        match response.get("ready") {
            Some(Value::Bool(true)) => failures = 0,
            Some(Value::Bool(false)) => {
                failures += 1;
                if failures >= 2 && !stop.is_set() {
                    return Some("broker_reported_unhealthy");
                }
            }
            _ => {}
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::cell::{Cell, RefCell};
    use std::collections::VecDeque;
    use std::os::unix::net::UnixListener;

    struct ScriptedStop(RefCell<VecDeque<bool>>);
    impl StopSignal for ScriptedStop {
        fn wait(&self, _: Duration) -> bool {
            self.0.borrow_mut().pop_front().unwrap_or(true)
        }
        fn is_set(&self) -> bool {
            false
        }
    }

    struct ScriptedProcess {
        polls: VecDeque<Option<i32>>,
        count: Cell<usize>,
    }
    impl ProcessPoll for ScriptedProcess {
        fn poll(&mut self) -> Option<i32> {
            self.count.set(self.count.get() + 1);
            self.polls.pop_front().unwrap_or(None)
        }
    }

    fn watch(observations: Vec<Result<Value>>, polls: Vec<Option<i32>>) -> (Option<&'static str>, usize, usize) {
        let stop = ScriptedStop(RefCell::new(std::iter::repeat_n(false, observations.len()).chain([true]).collect()));
        let mut process = ScriptedProcess { polls: polls.into(), count: Cell::new(0) };
        let mut queue: VecDeque<Result<Value>> = observations.into();
        let mut queries = 0;
        let result = wait_for_backend_loss_with(&mut process, &stop, Duration::ZERO, &mut || {
            queries += 1;
            queue.pop_front().unwrap().map(|v| v.as_object().cloned().unwrap())
        });
        (result, process.count.get(), queries)
    }

    fn timeout() -> Result<Value> {
        Err(Error::Timeout("timed out".into()))
    }

    #[test]
    fn missing_or_malformed_observations_do_not_authorize_restart() {
        let observations = vec![timeout(), Err(Error::Connection("closed".into())),
            Err(Error::Os(std::io::Error::from_raw_os_error(libc::ENOENT))), Err(Error::value("bad")),
            Ok(json!({})), Ok(json!({"ready": null})), Ok(json!({"ready": 0})), Ok(json!({"error": "unknown"})), Ok(json!({"ready": true}))];
        let count = observations.len();
        assert_eq!(watch(observations, vec![]), (None, count, count));
    }

    #[test]
    fn explicit_failure_requires_confirmation_and_healthy_reply_clears_it() {
        let (result, _, _) = watch(vec![Ok(json!({"ready": false})), Ok(json!({"ready": true})), Ok(json!({"ready": false}))], vec![]);
        assert_eq!(result, None);
        let (result, _, queries) = watch(vec![Ok(json!({"ready": false})), timeout(), Ok(json!({"ready": false}))], vec![]);
        assert_eq!(result, Some("broker_reported_unhealthy"));
        assert_eq!(queries, 3);
    }

    #[test]
    fn process_exit_after_missed_observation_is_authoritative() {
        let (result, polls, queries) = watch(vec![timeout(), Ok(json!({"ready": true}))], vec![None, Some(7)]);
        assert_eq!((result, polls, queries), (Some("broker_exited"), 2, 1));
    }

    #[test]
    fn actual_terminal_process_needs_no_health_query() {
        let mut child = std::process::Command::new("/bin/sh").args(["-c", "exit 7"]).spawn().unwrap();
        assert_eq!(child.wait().unwrap().code(), Some(7));
        let mut queries = 0;
        let result = wait_for_backend_loss_with(&mut child, &Event::new(), Duration::ZERO, &mut || {
            queries += 1;
            Ok(Map::new())
        });
        assert_eq!(result, Some("broker_exited"));
        assert_eq!(queries, 0);
    }

    fn serve(reply: impl FnOnce(&mut UnixStream) + Send + 'static) -> (tempfile::TempDir, std::path::PathBuf) {
        let temp = tempfile::Builder::new().prefix("hm-health-").tempdir_in("/tmp").unwrap();
        let path = temp.path().join("broker.sock");
        let listener = UnixListener::bind(&path).unwrap();
        std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut header = [0u8; 4];
            stream.read_exact(&mut header).unwrap();
            let mut body = vec![0u8; u32::from_be_bytes(header) as usize];
            stream.read_exact(&mut body).unwrap();
            assert_eq!(serde_json::from_slice::<Value>(&body).unwrap(), json!({"operation": "health"}));
            reply(&mut stream);
        });
        (temp, path)
    }

    fn send(stream: &mut UnixStream, value: &Value) {
        let data = serde_json::to_vec(value).unwrap();
        let _ = stream.write_all(&[(data.len() as u32).to_be_bytes().to_vec(), data].concat());
    }

    #[test]
    fn healthy_reply_is_returned() {
        let (_temp, path) = serve(|s| send(s, &json!({"ready": true, "sessions": 0})));
        assert_eq!(Value::Object(health(&path, Duration::from_secs(2)).unwrap()), json!({"ready": true, "sessions": 0}));
    }

    #[test]
    fn partial_reply_obeys_one_overall_observation_deadline() {
        let (_temp, path) = serve(|stream| {
            let data = br#"{"ready":true}"#;
            let _ = stream.write_all(&(data.len() as u32).to_be_bytes());
            for byte in data {
                std::thread::sleep(Duration::from_millis(30));
                if stream.write_all(&[*byte]).is_err() {
                    return;
                }
            }
        });
        let start = Instant::now();
        let error = health(&path, Duration::from_millis(100)).unwrap_err();
        assert_eq!(error.type_name(), "TimeoutError");
        assert!(start.elapsed() < Duration::from_millis(300));
    }

    #[test]
    fn invalid_wire_reply_is_an_observation_error() {
        let (_temp, path) = serve(|s| send(s, &json!([])));
        assert_eq!(health(&path, Duration::from_secs(2)).unwrap_err().to_string(), "Invalid broker health reply");
        let (_temp, path) = serve(|s| {
            let _ = s.write_all(&0u32.to_be_bytes());
        });
        assert_eq!(health(&path, Duration::from_secs(2)).unwrap_err().to_string(), "Invalid broker reply length");
    }
}
