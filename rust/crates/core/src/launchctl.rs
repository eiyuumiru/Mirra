//! `launchctl` invocation helpers.
use std::time::Duration;

use crate::activity;
use crate::error::Result;
use crate::subprocess::{self, Completed, RunOptions};

/// Text reply of a `launchctl` call (`capture_output=True, text=True`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reply {
    pub code: i32,
    pub stdout: String,
    pub stderr: String,
}

impl From<Completed> for Reply {
    fn from(c: Completed) -> Self {
        Reply { code: c.code, stdout: c.stdout_text(), stderr: c.stderr_text() }
    }
}

fn command<S: AsRef<str>>(arguments: &[S]) -> Vec<String> {
    std::iter::once("launchctl".to_string()).chain(arguments.iter().map(|a| a.as_ref().to_string())).collect()
}

/// `subprocess.run(['launchctl', *args], capture_output=True, text=True, timeout=…)`
/// (sharingd.py / launcher.py). A non-zero status is returned, not raised;
/// expiry is `Error::TimeoutExpired`.
pub fn run<S: AsRef<str>>(arguments: &[S], timeout: Duration) -> Result<Reply> {
    subprocess::run(&command(arguments), &RunOptions::new().capture().timeout(timeout)).map(Reply::from)
}

/// `activity.run(['launchctl', *args], source='launchctl', capture_output=True,
/// text=True, timeout=…)` (installation.py): logged when a sink is active.
pub fn run_logged<S: AsRef<str>>(arguments: &[S], timeout: Duration) -> Result<Reply> {
    activity::run(&command(arguments), &RunOptions::new().source("launchctl").capture().timeout(timeout)).map(Reply::from)
}

/// `gui/<uid>` launchd domain of the current user.
pub fn gui_domain() -> String {
    format!("gui/{}", crate::sys::getuid())
}

/// Whether `launchctl print` shows any of `names` in the job itself. The
/// `inherited environment` block is the user domain's `launchctl setenv`
/// environment, shared by every job: the sharingd adapter sets its
/// `DYLD_INSERT_LIBRARIES` there for a few seconds while sharingd restarts,
/// which says nothing about the printed job's own configuration.
pub fn job_mentions(printed: &str, names: &[&str]) -> bool {
    let mut sections: Vec<&str> = Vec::new();
    for line in printed.lines() {
        let trimmed = line.trim();
        if let Some(name) = trimmed.strip_suffix(" = {") {
            sections.push(name);
            continue;
        }
        if trimmed == "}" {
            sections.pop();
            continue;
        }
        if sections.contains(&"inherited environment") {
            continue;
        }
        if names.iter().any(|name| trimmed.contains(name)) {
            return true;
        }
    }
    false
}

/// Wait until the user domain no longer carries `DYLD_INSERT_LIBRARIES`
/// (`launchctl getenv`). A job bootstrapped meanwhile would inherit another
/// adapter's library, so callers wait before registering a system job.
pub fn wait_domain_clear(command: &dyn Fn(&[&str]) -> Result<Reply>, timeout: Duration, interval: Duration) -> Result<()> {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        let reply = command(&["getenv", "DYLD_INSERT_LIBRARIES"])?;
        if reply.code != 0 || reply.stdout.trim().is_empty() {
            return Ok(());
        }
        if std::time::Instant::now() >= deadline {
            return Err(crate::error::Error::runtime(
                "launchd still carries another adapter's DYLD_INSERT_LIBRARIES; no system job was changed"));
        }
        std::thread::sleep(interval);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_status_without_raising() {
        let reply = run(&["print", "gui/0/com.example.mirra.nonexistent"], Duration::from_secs(10)).unwrap();
        assert_ne!(reply.code, 0);
        assert!(gui_domain().starts_with("gui/"));
    }

    const PRINTED: &str = "gui/501/com.example = {\n\tactive count = 1\n\tinherited environment = {\n\
        \t\tDYLD_INSERT_LIBRARIES => /tmp/keystore.dylib\n\t\tMIRRA_KEYSTORE_CONFIG => /tmp/keystore.json\n\t}\n\
        \tdefault environment = {\n\t\tPATH => /usr/bin:/bin\n\t}\n\tenvironment = {\n\t\tXPC_SERVICE_NAME => x\n\t}\n\
        \tprogram = /usr/libexec/example\n}\n";

    #[test]
    fn inherited_domain_environment_is_not_the_job() {
        assert!(!job_mentions(PRINTED, &["DYLD_INSERT_LIBRARIES"]));
        assert!(job_mentions(PRINTED, &["XPC_SERVICE_NAME"]));
        let own = PRINTED.replace("XPC_SERVICE_NAME => x", "DYLD_INSERT_LIBRARIES => /tmp/launch.dylib");
        assert!(job_mentions(&own, &["DYLD_INSERT_LIBRARIES"]));
        // Older fixtures print the variable without any section.
        assert!(job_mentions("\tpath = /x\n\tDYLD_INSERT_LIBRARIES => test\n", &["DYLD_INSERT_LIBRARIES"]));
    }

    #[test]
    fn domain_wait_polls_until_the_variable_is_gone() {
        let answers = std::sync::Mutex::new(vec![1, 0, 0]);
        let command = |args: &[&str]| -> Result<Reply> {
            assert_eq!(args, ["getenv", "DYLD_INSERT_LIBRARIES"]);
            let set = answers.lock().unwrap().pop().unwrap() == 0;
            Ok(if set { Reply { code: 0, stdout: "/tmp/keystore.dylib\n".into(), stderr: String::new() } }
               else { Reply { code: 1, stdout: String::new(), stderr: String::new() } })
        };
        wait_domain_clear(&command, Duration::from_secs(5), Duration::from_millis(1)).unwrap();
        assert!(answers.lock().unwrap().is_empty());
        let always = |_: &[&str]| -> Result<Reply> { Ok(Reply { code: 0, stdout: "x\n".into(), stderr: String::new() }) };
        let error = wait_domain_clear(&always, Duration::ZERO, Duration::from_millis(1)).unwrap_err();
        assert!(error.to_string().contains("DYLD_INSERT_LIBRARIES"));
    }
}
