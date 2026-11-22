//! Observe owned native apps without DNS lookup or treating timeouts as exits.
use std::collections::HashMap;
use std::ffi::CStr;
use std::time::{Duration, Instant};

use crate::error::{Error, Result};
use crate::subprocess::{self, Completed, RunOptions};
use crate::sys;

/// Darwin `struct proc_bsdinfo` (sys/proc_info.h, PROC_PIDTBSDINFO = 3).
#[repr(C)]
#[derive(Clone, Copy)]
pub struct BsdInfo {
    pub flags: u32,
    pub status: u32,
    pub xstatus: u32,
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub ruid: u32,
    pub rgid: u32,
    pub svuid: u32,
    pub svgid: u32,
    pub reserved: u32,
    pub comm: [u8; 16],
    pub name: [u8; 32],
    pub nfiles: u32,
    pub pgid: u32,
    pub jobc: u32,
    pub tdev: u32,
    pub tpgid: u32,
    pub nice: u32,
    pub start_seconds: u64,
    pub start_microseconds: u64,
}

const _: () = assert!(std::mem::size_of::<BsdInfo>() == 136);

pub const PROC_PIDTBSDINFO: i32 = 3;

/// `(pid, uid, start_seconds, start_microseconds)`; stable across PID reuse.
pub type Birth = (i32, u32, u64, u64);
/// `(pid, start_seconds, start_microseconds)` of a verified native app.
pub type Identity = (i32, u64, u64);

/// `proc_pidinfo(PROC_PIDTBSDINFO)`. `Ok(None)` only for ESRCH; any other
/// failure is an observation error (`[Errno N] <message>`).
pub fn bsd_info(pid: i32, message: &str) -> Result<Option<BsdInfo>> {
    let mut info: BsdInfo = unsafe { std::mem::zeroed() };
    let size = std::mem::size_of::<BsdInfo>() as i32;
    sys::set_errno(0);
    let result = unsafe { libc::proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, (&mut info as *mut BsdInfo).cast(), size) };
    if result != size {
        let error = sys::errno();
        if error == libc::ESRCH {
            return Ok(None);
        }
        return Err(Error::os_message(error, message));
    }
    Ok(Some(info))
}

/// Identify a process across PID reuse; an observation error is not death.
pub fn process_birth(pid: i32) -> Result<Option<Birth>> {
    Ok(bsd_info(pid, "Cannot determine process lifetime")?
        .map(|i| (i.pid as i32, i.uid, i.start_seconds, i.start_microseconds)))
}

/// `proc_pidpath`: `Ok(None)` for ESRCH.
pub fn proc_pidpath(pid: i32) -> Result<Option<Vec<u8>>> {
    let mut buffer = vec![0u8; 4096];
    sys::set_errno(0);
    if unsafe { libc::proc_pidpath(pid, buffer.as_mut_ptr().cast(), buffer.len() as u32) } <= 0 {
        let error = sys::errno();
        if error == libc::ESRCH {
            return Ok(None);
        }
        return Err(Error::os_message(error, "Cannot observe executable path"));
    }
    Ok(Some(unsafe { CStr::from_ptr(buffer.as_ptr().cast()) }.to_bytes().to_vec()))
}

/// Runs `pgrep`/`lsof` with a timeout (replaceable for tests).
pub type Runner = Box<dyn FnMut(&[String], Duration) -> Result<Completed> + Send>;
pub type IdentityProbe = Box<dyn Fn(i32) -> Result<Option<Identity>> + Send>;

pub struct NativeAppObserver {
    pub executable: String,
    pub adapter: String,
    pub verified: HashMap<i32, Identity>,
    /// Python exception class names from the last poll.
    pub last_errors: Vec<String>,
    pub error_count: u64,
    runner: Runner,
    probe: Option<IdentityProbe>,
}

fn default_runner() -> Runner {
    Box::new(|command, timeout| subprocess::run(command, &RunOptions::new().capture().timeout(timeout)))
}

impl NativeAppObserver {
    pub fn new(executable: impl Into<String>, adapter: impl Into<String>) -> Self {
        NativeAppObserver { executable: executable.into(), adapter: adapter.into(), verified: HashMap::new(),
            last_errors: Vec::new(), error_count: 0, runner: default_runner(), probe: None }
    }

    /// Replace subprocess execution and/or identity observation (tests).
    pub fn with_hooks(mut self, runner: Option<Runner>, identity: Option<IdentityProbe>) -> Self {
        if let Some(runner) = runner {
            self.runner = runner;
        }
        self.probe = identity;
        self
    }

    pub fn set_identity_probe(&mut self, identity: Option<IdentityProbe>) {
        self.probe = identity;
    }

    /// `(pid, start)` when `pid` is this user's process running `executable`.
    pub fn identity(&self, pid: i32) -> Result<Option<Identity>> {
        if let Some(probe) = &self.probe {
            return probe(pid);
        }
        let Some(info) = bsd_info(pid, "Cannot observe process identity")? else { return Ok(None) };
        let Some(path) = proc_pidpath(pid)? else { return Ok(None) };
        if info.pid as i32 != pid || info.uid != sys::getuid() || path != self.executable.as_bytes() {
            return Ok(None);
        }
        Ok(Some((pid, info.start_seconds, info.start_microseconds)))
    }

    fn run(&mut self, command: &[&str]) -> Result<Completed> {
        let command: Vec<String> = command.iter().map(|s| s.to_string()).collect();
        (self.runner)(&command, Duration::from_secs(3))
    }

    fn check_pid(&mut self, pid: i32, value: &str) -> Result<bool> {
        let Some(identity) = self.identity(pid)? else {
            self.verified.remove(&pid);
            return Ok(false);
        };
        if self.verified.get(&pid) != Some(&identity) {
            self.verified.remove(&pid);
            // Text mappings only, numeric addresses and ports: never
            // wait for a live media socket's reverse DNS lookup.
            let images = self.run(&["/usr/sbin/lsof", "-n", "-P", "-a", "-p", value, "-d", "txt", "-Fn"])?;
            if images.code != 0 && images.code != 1 {
                return Err(Error::runtime("Image observation failed"));
            }
            let wanted = format!("n{}", self.adapter);
            let text = images.stdout_text();
            if !crate::pyfmt::splitlines(&text).contains(&wanted.as_str()) {
                return Ok(false);
            }
            if self.identity(pid)? != Some(identity) {
                return Ok(false);
            }
            self.verified.insert(pid, identity);
        }
        Ok(true)
    }

    /// PIDs of verified owned app instances; observation failures are recorded
    /// in `last_errors` (never treated as exits).
    pub fn poll(&mut self) -> Vec<i32> {
        self.last_errors.clear();
        let mut found = Vec::new();
        let listing = self.run(&["pgrep", "-x", "iPhone Mirroring"]).and_then(|result| {
            if result.code != 0 && result.code != 1 {
                Err(Error::runtime("Process enumeration failed"))
            } else {
                Ok(result.stdout_text())
            }
        });
        match listing {
            Ok(text) => {
                for value in text.split_whitespace() {
                    if !value.chars().all(|c| c.is_ascii_digit()) {
                        continue;
                    }
                    let Ok(pid) = value.parse::<i32>() else { continue };
                    match self.check_pid(pid, value) {
                        Ok(true) => found.push(pid),
                        Ok(false) => {}
                        Err(error) => self.last_errors.push(error.type_name()),
                    }
                }
            }
            Err(error) => self.last_errors.push(error.type_name()),
        }
        self.error_count += self.last_errors.len() as u64;
        found
    }

    fn signal_owned(&mut self, signal: i32) -> Result<()> {
        for pid in self.poll() {
            if unsafe { libc::kill(pid, signal) } < 0 {
                let error = sys::errno();
                if error != libc::ESRCH {
                    return Err(std::io::Error::from_raw_os_error(error).into());
                }
            }
        }
        Ok(())
    }

    /// SIGTERM, wait up to `timeout`, SIGKILL, wait 3 s; a failed observation
    /// remains a cleanup error (`Cannot verify native app cleanup`).
    pub fn terminate_owned(&mut self, timeout: Duration) -> Result<()> {
        self.signal_owned(libc::SIGTERM)?;
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if self.poll().is_empty() && self.last_errors.is_empty() {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(200));
        }
        self.signal_owned(libc::SIGKILL)?;
        let deadline = Instant::now() + Duration::from_secs(3);
        while Instant::now() < deadline {
            if self.poll().is_empty() && self.last_errors.is_empty() {
                return Ok(());
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        Err(Error::runtime("Cannot verify native app cleanup"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::{Arc, Mutex};

    type Script = Arc<Mutex<VecDeque<Result<Completed>>>>;
    type Calls = Arc<Mutex<Vec<Vec<String>>>>;

    fn reply(command: &str, stdout: &str) -> Result<Completed> {
        Ok(Completed { args: vec![command.into()], code: 0, stdout: stdout.as_bytes().to_vec(), stderr: Vec::new() })
    }
    fn pids() -> Result<Completed> {
        reply("pgrep", "42\n")
    }
    fn images() -> Result<Completed> {
        reply("lsof", "p42\nn/session/adapter.dylib\n")
    }

    fn observer(script: Vec<Result<Completed>>, identity: Arc<Mutex<Identity>>) -> (NativeAppObserver, Calls, Script) {
        let script: Script = Arc::new(Mutex::new(script.into()));
        let calls: Calls = Arc::new(Mutex::new(Vec::new()));
        let (queue, log) = (script.clone(), calls.clone());
        let runner: Runner = Box::new(move |command, _| {
            log.lock().unwrap().push(command.to_vec());
            queue.lock().unwrap().pop_front().expect("unexpected command")
        });
        let probe: IdentityProbe = Box::new(move |_| Ok(Some(*identity.lock().unwrap())));
        let observer = NativeAppObserver::new("/system/original/app", "/session/adapter.dylib").with_hooks(Some(runner), Some(probe));
        (observer, calls, script)
    }

    #[test]
    fn image_timeout_is_retried_without_marking_process_owned_or_dead() {
        let timeout = Err(Error::TimeoutExpired { command: vec!["lsof".into()], timeout: Duration::from_secs(3), stdout: vec![], stderr: vec![] });
        let (mut observer, _, _) = observer(vec![pids(), timeout, pids(), images()], Arc::new(Mutex::new((42, 100, 1))));
        assert_eq!(observer.poll(), Vec::<i32>::new());
        assert_eq!(observer.last_errors, ["TimeoutExpired"]);
        assert_eq!(observer.poll(), [42]);
        assert!(observer.last_errors.is_empty());
        assert_eq!(observer.error_count, 1);
    }

    #[test]
    fn known_process_does_not_repeat_expensive_image_inspection() {
        let (mut observer, calls, _) = observer(vec![pids(), images(), pids()], Arc::new(Mutex::new((42, 100, 1))));
        assert_eq!(observer.poll(), [42]);
        assert_eq!(observer.poll(), [42]);
        let calls = calls.lock().unwrap();
        assert_eq!(calls.iter().filter(|c| c[0] == "/usr/sbin/lsof").count(), 1);
        assert!(calls[1].contains(&"-n".to_string()));
        assert!(calls[1].contains(&"txt".to_string()));
        assert_eq!(calls[0], ["pgrep", "-x", "iPhone Mirroring"]);
    }

    #[test]
    fn reused_pid_does_not_inherit_previous_adapter_ownership() {
        let identity = Arc::new(Mutex::new((42, 100, 1)));
        let (mut observer, _, script) = observer(vec![pids(), images()], identity.clone());
        assert_eq!(observer.poll(), [42]);
        *identity.lock().unwrap() = (42, 200, 3);
        script.lock().unwrap().extend([pids(), reply("lsof", "p42\nn/system/original/app\n")]);
        assert_eq!(observer.poll(), Vec::<i32>::new());
        assert!(!observer.verified.contains_key(&42));
    }

    #[test]
    fn enumeration_failure_is_an_observation_error() {
        let failed = Ok(Completed { args: vec![], code: 2, stdout: vec![], stderr: vec![] });
        let (mut observer, _, _) = observer(vec![failed], Arc::new(Mutex::new((42, 100, 1))));
        assert!(observer.poll().is_empty());
        assert_eq!(observer.last_errors, ["RuntimeError"]);
    }

    #[test]
    fn own_birth_and_missing_process() {
        let pid = std::process::id() as i32;
        let birth = process_birth(pid).unwrap().unwrap();
        assert_eq!(birth.0, pid);
        assert_eq!(birth.1, sys::getuid());
        assert!(birth.2 > 0);
        assert_eq!(process_birth(pid).unwrap(), Some(birth));
        assert_eq!(process_birth(999_999).unwrap(), None);
        let executable = String::from_utf8(proc_pidpath(pid).unwrap().unwrap()).unwrap();
        let observer = NativeAppObserver::new(executable, "/x");
        assert_eq!(observer.identity(pid).unwrap(), Some((pid, birth.2, birth.3)));
        assert_eq!(NativeAppObserver::new("/other", "/x").identity(pid).unwrap(), None);
    }
}
