//! Scoped, reversible CoreServicesUIAgent support for ordinary app launches
//! (port of `scripts/launcher.py`). Lock and journal paths are shared with
//! the Python service: `~/Library/Caches/Mirra/native-launch-agent.lock` and
//! `~/Library/Caches/Mirra/launch.json`.
use std::fs::File;
use std::os::fd::AsRawFd;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use mirra_core::event::Event;
use mirra_core::launchctl::{self, Reply};
use mirra_core::processes::NativeAppObserver;
use mirra_core::{sys, Error, Result};
use serde_json::{json, Map, Value};

use crate::ownership::{cleanup_abandoned_socket_in, LaunchOwnerJournal};
use crate::plist::{self, Plist};
use crate::startup::MIRRORING_EXECUTABLE;
use crate::util::{self, BirthProbe};

pub const ORIGINAL: &str = "/System/Library/LaunchAgents/com.apple.coreservices.uiagent.plist";
pub const AGENT: &str = "/System/Library/CoreServices/CoreServicesUIAgent.app/Contents/MacOS/CoreServicesUIAgent";
pub const LABEL: &str = "com.apple.coreservices.uiagent";

/// `launchctl <args>` returning the text reply (non-zero status is not an error).
pub type Launchctl = Arc<dyn Fn(&[String]) -> Result<Reply> + Send + Sync>;
/// Terminates owned apps of an abandoned session (adapter path given).
pub type AppCleanup = Arc<dyn Fn(&Path) -> Result<()> + Send + Sync>;

/// Replaceable environment of a [`NativeLaunchAgent`] (tests use fakes).
#[derive(Clone)]
pub struct LaunchContext {
    pub command: Launchctl,
    /// Package root (`build/launch.dylib`, default `runtime/`).
    pub root: PathBuf,
    /// Apple's job definition.
    pub original: PathBuf,
    /// `Path.home()`: lock and journal under `Library/Caches/Mirra`.
    pub home: PathBuf,
    pub birth: BirthProbe,
    pub app_cleanup: AppCleanup,
    /// `wait_unloaded` / `wait_original` timeouts (8 s) and adapter readiness (16 s).
    pub unload_timeout: Duration,
    pub register_timeout: Duration,
    pub ready_timeout: Duration,
    /// How long another adapter may keep variables in the user domain
    /// (the sharingd restart window is 8 s plus launchctl calls).
    pub domain_timeout: Duration,
    pub interval: Duration,
}

impl Default for LaunchContext {
    fn default() -> Self {
        LaunchContext {
            command: Arc::new(|args| launchctl::run(args, Duration::from_secs(12))),
            root: mirra_core::config::default_root(),
            original: PathBuf::from(ORIGINAL),
            home: util::home(),
            birth: util::real_birth(),
            app_cleanup: Arc::new(|adapter| {
                NativeAppObserver::new(MIRRORING_EXECUTABLE, util::text(adapter)).terminate_owned(Duration::from_secs(8))
            }),
            unload_timeout: Duration::from_secs(8),
            register_timeout: Duration::from_secs(8),
            ready_timeout: Duration::from_secs(16),
            domain_timeout: Duration::from_secs(20),
            interval: Duration::from_millis(200),
        }
    }
}

impl LaunchContext {
    fn cache(&self) -> PathBuf {
        self.home.join("Library/Caches/Mirra")
    }

    fn lock(&self) -> Result<File> {
        let directory = self.cache();
        util::mkdir_private(&directory)?;
        let path = directory.join("native-launch-agent.lock");
        let lock = std::fs::OpenOptions::new().append(true).create(true).open(&path).map_err(|e| Error::with_path(e, &path))?;
        sys::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB)?;
        Ok(lock)
    }
}

pub type State = Map<String, Value>;

pub struct NativeLaunchAgent {
    pub directory: PathBuf,
    pub environment: Map<String, Value>,
    pub stop: Event,
    pub domain: String,
    pub target: String,
    pub settings: PathBuf,
    pub plist: PathBuf,
    pub log: PathBuf,
    pub changed: bool,
    pub lock: Option<File>,
    pub journal: LaunchOwnerJournal,
    pub journal_owned: bool,
    pub context: LaunchContext,
}

fn get<'a>(state: &'a State, key: &str) -> Option<&'a str> {
    state.get(key).and_then(Value::as_str)
}

impl NativeLaunchAgent {
    /// `NativeLaunchAgent(directory, environment, stop=None, runtime_root=None)`.
    pub fn new(directory: &Path, environment: Map<String, Value>, stop: Option<Event>, runtime_root: Option<&Path>) -> Self {
        Self::with_context(directory, environment, stop, runtime_root, LaunchContext::default())
    }

    pub fn with_context(directory: &Path, environment: Map<String, Value>, stop: Option<Event>, runtime_root: Option<&Path>,
        context: LaunchContext) -> Self {
        let domain = launchctl::gui_domain();
        let runtime = runtime_root.map(Path::to_path_buf).unwrap_or_else(|| context.root.join("runtime"));
        let journal = LaunchOwnerJournal::with_home(&runtime, &context.home).with_birth_probe(context.birth.clone());
        NativeLaunchAgent {
            directory: directory.to_path_buf(),
            environment,
            stop: stop.unwrap_or_default(),
            target: format!("{}/{}", domain, LABEL),
            domain,
            settings: directory.join("native-launch-settings.json"),
            plist: directory.join("native-launch-agent.plist"),
            log: directory.join("native-launch-agent.stderr.log"),
            changed: false,
            lock: None,
            journal,
            journal_owned: false,
            context,
        }
    }

    fn command(&self, args: &[&str]) -> Result<Reply> {
        let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        (self.context.command)(&args)
    }

    fn recover_under_lock(&self) -> Result<Option<Value>> {
        let Some(previous) = self.journal.abandoned()? else { return Ok(None) };
        let directory = PathBuf::from(previous["directory"].as_str().unwrap_or(""));
        let mut old = NativeLaunchAgent::with_context(&directory, Map::new(), None, Some(&self.journal.runtime_root),
            self.context.clone());
        old.changed = true;
        // close() accepts only the journal's exact plist or Apple's original job.
        let restored = old.close()?;
        (self.context.app_cleanup)(&directory.join("sockets.dylib"))?;
        cleanup_abandoned_socket_in(previous.get("helper_socket").and_then(Value::as_str), &self.context.home)?;
        self.journal.clear(&directory)?;
        Ok(Some(json!({"directory": util::text(&directory), "original_agent_restored": restored.is_some()})))
    }

    /// Restore an abandoned session's agent under the shared lock.
    pub fn recover_abandoned(runtime_root: Option<&Path>) -> Result<Option<Value>> {
        Self::recover_abandoned_with(runtime_root, LaunchContext::default())
    }

    pub fn recover_abandoned_with(runtime_root: Option<&Path>, context: LaunchContext) -> Result<Option<Value>> {
        let root = runtime_root.map(Path::to_path_buf).unwrap_or_else(|| context.root.join("runtime"));
        let _lock = context.lock()?;
        NativeLaunchAgent::with_context(&root.join("native-recovery"), Map::new(), None, Some(&root), context)
            .recover_under_lock()
    }

    /// Observed job: `{}` when missing, else `injected` plus the first
    /// `program`, `path`, `pid`, `state` values (strings).
    pub fn state(&self) -> Result<State> {
        let reply = self.command(&["print", &self.target])?;
        if reply.code != 0 {
            // Missing is distinct from a failed observation of a live job.
            if reply.stderr.contains("Could not find service") {
                return Ok(Map::new());
            }
            return Err(Error::runtime(format!("Cannot inspect CoreServicesUIAgent: {}", util::strip(&reply.stderr))));
        }
        let mut values = Map::new();
        values.insert("injected".into(), Value::from(launchctl::job_mentions(&reply.stdout, &["DYLD_INSERT_LIBRARIES"])));
        for line in mirra_core::pyfmt::splitlines(&reply.stdout) {
            if let Some((key, value)) = line.trim().split_once(" = ") {
                if matches!(key, "program" | "path" | "pid" | "state") && !values.contains_key(key) {
                    values.insert(key.into(), Value::from(value));
                }
            }
        }
        Ok(values)
    }

    /// A job (re)started while another adapter's library is in the user
    /// domain would inherit it, so the agent is neither replaced nor
    /// restored before launchd drops it.
    pub fn wait_domain_clear(&self) -> Result<()> {
        launchctl::wait_domain_clear(&|args| self.command(args), self.context.domain_timeout, self.context.interval)
    }

    /// bootout may return before print stops exposing the exiting job.
    /// Observe that exact job until it disappears or changes; never repeat a
    /// mutation because a query failed or still shows the old job.
    pub fn wait_unloaded(&self, path: &str) -> Result<State> {
        let deadline = Instant::now() + self.context.unload_timeout;
        loop {
            let current = self.state()?;
            if current.is_empty() || get(&current, "path") != Some(path) {
                return Ok(current);
            }
            if Instant::now() >= deadline {
                return Err(Error::runtime("CoreServicesUIAgent is still unloading; restoration remains pending"));
            }
            std::thread::sleep(self.context.interval);
        }
    }

    pub fn wait_original(&self) -> Result<State> {
        let deadline = Instant::now() + self.context.register_timeout;
        let original = util::text(&self.context.original);
        loop {
            let current = self.state()?;
            if !current.is_empty() {
                if get(&current, "path") == Some(original.as_str()) && get(&current, "program") == Some(AGENT)
                    && current.get("injected") != Some(&Value::Bool(true)) {
                    return Ok(current);
                }
                return Err(Error::runtime("Original CoreServicesUIAgent restoration could not be verified"));
            }
            if Instant::now() >= deadline {
                return Err(Error::runtime("Original CoreServicesUIAgent registration is still pending"));
            }
            std::thread::sleep(self.context.interval);
        }
    }

    /// Replace Apple's agent with the adapter-injected copy; on any failure the
    /// original is restored before the error is returned.
    pub fn start(&mut self) -> Result<State> {
        match self.start_inner() {
            Ok(state) => Ok(state),
            Err(error) => {
                self.close()?;
                Err(error)
            }
        }
    }

    fn start_inner(&mut self) -> Result<State> {
        self.lock = Some(self.context.lock()?);
        self.recover_under_lock()?;
        self.wait_domain_clear()?;
        let before = self.state()?;
        if get(&before, "program") != Some(AGENT) || before.get("injected") == Some(&Value::Bool(true)) {
            return Err(Error::runtime("CoreServicesUIAgent has an unexpected configuration; no change made"));
        }
        let library = self.directory.join("launch.dylib");
        copy2(&self.context.root.join("build/launch.dylib"), &library)?;
        util::chmod(&library, 0o600)?;
        let mut settings = mirra_core::pyjson::dumps(&Value::Object(self.environment.clone()));
        settings.push('\n');
        std::fs::write(&self.settings, settings).map_err(|e| Error::with_path(e, &self.settings))?;
        util::chmod(&self.settings, 0o600)?;
        let original = std::fs::read(&self.context.original).map_err(|e| Error::with_path(e, &self.context.original))?;
        let mut config = plist::loads(&original)?;
        if !config.is_dict() {
            return Err(Error::value("Unexpected CoreServicesUIAgent definition"));
        }
        let stdout = self.directory.join("native-launch-agent.stdout.log");
        config.insert("RunAtLoad", Plist::Bool(true));
        config.insert("EnablePressuredExit", Plist::Bool(false));
        config.insert("Umask", Plist::Integer(0o077));
        config.insert("EnvironmentVariables", Plist::Dict(vec![
            ("DYLD_INSERT_LIBRARIES".into(), Plist::String(util::text(&library))),
            ("MIRRA_LAUNCH_SETTINGS".into(), Plist::String(util::text(&self.settings))),
        ]));
        config.insert("StandardOutPath", Plist::String(util::text(&stdout)));
        config.insert("StandardErrorPath", Plist::String(util::text(&self.log)));
        util::touch_new(&stdout)?;
        util::touch_new(&self.log)?;
        std::fs::write(&self.plist, plist::dumps(&config)?).map_err(|e| Error::with_path(e, &self.plist))?;
        util::chmod(&self.plist, 0o600)?;
        self.journal.publish(&self.directory, &self.environment)?;
        self.journal_owned = true;
        self.changed = true; // bootout can succeed before a timeout is reported.
        let reply = self.command(&["bootout", &self.target])?;
        if reply.code != 0 {
            return Err(Error::runtime(format!("CoreServicesUIAgent bootout failed: {}", util::strip(&reply.stderr))));
        }
        let Some(before_path) = get(&before, "path") else { return Err(Error::runtime("'path'")) };
        if !self.wait_unloaded(before_path)?.is_empty() {
            return Err(Error::runtime("CoreServicesUIAgent changed during startup; no replacement attempted"));
        }
        let plist_path = util::text(&self.plist);
        let reply = self.command(&["bootstrap", &self.domain, &plist_path])?;
        if reply.code != 0 {
            return Err(Error::runtime(format!("CoreServicesUIAgent bootstrap failed: {}", util::strip(&reply.stderr))));
        }
        let deadline = Instant::now() + self.context.ready_timeout;
        while Instant::now() < deadline && !self.stop.is_set() {
            let state = self.state()?;
            let log = std::fs::read(&self.log).map(|d| String::from_utf8_lossy(&d).into_owned()).unwrap_or_default();
            if let Some(pid) = get(&state, "pid").filter(|p| !p.is_empty()) {
                if log.contains(&format!("MIRRA_LAUNCH_ADAPTER_READY pid={}", pid)) {
                    return Ok(state);
                }
            }
            self.stop.wait(Some(self.context.interval));
        }
        Err(Error::runtime("CoreServicesUIAgent did not load its adapter, or startup was interrupted"))
    }

    /// Disable the settings and restore Apple's agent. `None` when nothing
    /// was changed; otherwise the verified original state (with
    /// `settings_disable_error` when the settings could not be disabled).
    pub fn close(&mut self) -> Result<Option<State>> {
        let result = self.close_inner();
        self.lock = None;
        result
    }

    fn close_inner(&mut self) -> Result<Option<State>> {
        let mut settings_error = None;
        if self.settings.exists() {
            let disabled = self.settings.with_extension("disabled");
            if let Err(error) = std::fs::rename(&self.settings, &disabled) {
                // A file cleanup failure must not skip restoration of the
                // system agent. Unloading it also disables the launch hook.
                settings_error = Some(Error::with_path(error, &self.settings).to_string());
            }
        }
        if !self.changed {
            return Ok(None);
        }
        let plist_path = util::text(&self.plist);
        let original = util::text(&self.context.original);
        let mut current = self.state()?;
        if !current.is_empty() && get(&current, "path") == Some(plist_path.as_str()) {
            let reply = self.command(&["bootout", &self.target])?;
            if reply.code != 0 {
                return Err(Error::runtime(format!("Cannot unload the owned launch adapter: {}", util::strip(&reply.stderr))));
            }
            current = self.wait_unloaded(&plist_path)?;
        }
        if !current.is_empty() && (get(&current, "path") != Some(original.as_str())
            || current.get("injected") == Some(&Value::Bool(true)) || get(&current, "program") != Some(AGENT)) {
            return Err(Error::runtime("CoreServicesUIAgent ownership changed; refusing to replace another configuration"));
        }
        if current.is_empty() {
            // Apple's job has no environment of its own, so it would inherit
            // a transient adapter variable from the domain.
            self.wait_domain_clear()?;
            let reply = self.command(&["bootstrap", &self.domain, &original])?;
            if reply.code != 0 {
                return Err(Error::runtime(format!("Cannot restore CoreServicesUIAgent: {}", util::strip(&reply.stderr))));
            }
        }
        let mut after = self.wait_original()?;
        self.changed = false;
        let socket = self.environment.get("MIRRA_BIND_SOCKET");
        if socket.is_none_or(|v| v.is_null() || v.as_str() == Some("")) {
            self.release_ownership()?;
        }
        if let Some(error) = settings_error {
            after.insert("settings_disable_error".into(), Value::from(error));
        }
        Ok(Some(after))
    }

    /// Call only after the helper and owned apps have also been cleaned up.
    pub fn release_ownership(&mut self) -> Result<()> {
        if self.journal_owned && !self.changed {
            self.journal.clear(&self.directory)?;
            self.journal_owned = false;
        }
        Ok(())
    }
}

/// `shutil.copy2`: contents, permission bits and timestamps.
pub(crate) fn copy2(source: &Path, target: &Path) -> Result<()> {
    std::fs::copy(source, target).map_err(|e| Error::with_path(e, source))?;
    let info = std::fs::metadata(source).map_err(|e| Error::with_path(e, source))?;
    if let (Ok(accessed), Ok(modified)) = (info.accessed(), info.modified()) {
        let file = std::fs::OpenOptions::new().write(true).open(target).map_err(|e| Error::with_path(e, target))?;
        let _ = file.set_times(std::fs::FileTimes::new().set_accessed(accessed).set_modified(modified));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::Mutex;

    #[derive(Default)]
    struct Fake {
        job: Option<PathBuf>,
        calls: Vec<Vec<String>>,
        fail_probe_bootstrap: bool,
        /// Scripted `print` outputs (state dictionaries) used before `job`.
        script: VecDeque<std::result::Result<State, String>>,
        original: PathBuf,
        /// Adapter log that receives the readiness marker on bootstrap.
        ready_log: Option<PathBuf>,
        /// Scripted `getenv DYLD_INSERT_LIBRARIES` answers (`true`: set).
        domain: VecDeque<bool>,
    }

    struct Fixture {
        _temp: tempfile::TempDir,
        root: PathBuf,
        run: PathBuf,
        original: PathBuf,
        fake: Arc<Mutex<Fake>>,
        agent: NativeLaunchAgent,
    }

    fn print_text(state: &State) -> String {
        let mut text = String::new();
        for key in ["path", "program", "state", "pid"] {
            if let Some(value) = get(state, key) {
                text.push_str(&format!("\t{} = {}\n", key, value));
            }
        }
        if state.get("injected") == Some(&Value::Bool(true)) {
            text.push_str("\tDYLD_INSERT_LIBRARIES => test\n");
        }
        text
    }

    fn launchctl(fake: &Arc<Mutex<Fake>>, args: &[String]) -> Result<Reply> {
        let mut fake = fake.lock().unwrap();
        fake.calls.push(args.to_vec());
        let ok = |stdout: String| Ok(Reply { code: 0, stdout, stderr: String::new() });
        match args[0].as_str() {
            "print" => {
                if let Some(next) = fake.script.pop_front() {
                    return match next {
                        Ok(state) if state.is_empty() => Ok(Reply { code: 113, stdout: String::new(), stderr: "Could not find service test".into() }),
                        Ok(state) => ok(print_text(&state)),
                        Err(message) => Err(Error::runtime(message)),
                    };
                }
                match fake.job.clone() {
                    None => Ok(Reply { code: 113, stdout: String::new(), stderr: "Could not find service test".into() }),
                    Some(job) => {
                        let mut out = format!("\tpath = {}\n\tprogram = {}\n\tstate = running\n\tpid = 123\n", job.display(), AGENT);
                        if job != fake.original {
                            out.push_str("\tDYLD_INSERT_LIBRARIES => test\n");
                        }
                        ok(out)
                    }
                }
            }
            "bootout" => {
                fake.job = None;
                ok(String::new())
            }
            "bootstrap" => {
                let path = PathBuf::from(&args[2]);
                if fake.fail_probe_bootstrap && path != fake.original {
                    return Ok(Reply { code: 5, stdout: String::new(), stderr: "injected startup failure".into() });
                }
                if path != fake.original {
                    if let Some(log) = &fake.ready_log {
                        std::fs::write(log, "MIRRA_LAUNCH_ADAPTER_READY pid=123\n").unwrap();
                    }
                }
                fake.job = Some(path);
                ok(String::new())
            }
            "getenv" => match fake.domain.pop_front() {
                Some(true) => ok("/tmp/keystore.dylib\n".into()),
                _ => Ok(Reply { code: 1, stdout: String::new(), stderr: String::new() }),
            },
            _ => ok(String::new()),
        }
    }

    fn fixture() -> Fixture {
        let temp = tempfile::tempdir().unwrap();
        let root = mirra_core::paths::resolve(temp.path());
        std::fs::create_dir(root.join("build")).unwrap();
        std::fs::write(root.join("build/launch.dylib"), b"test artifact").unwrap();
        let original = root.join("original.plist");
        let definition = Plist::Dict(vec![("Program".into(), Plist::String(AGENT.into())), ("Label".into(), Plist::String(LABEL.into()))]);
        std::fs::write(&original, plist::dumps(&definition).unwrap()).unwrap();
        let run = root.join("runtime/native-test");
        std::fs::create_dir_all(&run).unwrap();
        let fake = Arc::new(Mutex::new(Fake { job: Some(original.clone()), original: original.clone(), ..Default::default() }));
        let handle = fake.clone();
        let context = LaunchContext {
            command: Arc::new(move |args| launchctl(&handle, args)),
            root: root.clone(),
            original: original.clone(),
            home: root.clone(),
            app_cleanup: Arc::new(|_| panic!("no abandoned session expected")),
            interval: Duration::from_millis(1),
            ready_timeout: Duration::from_millis(200),
            ..LaunchContext::default()
        };
        let mut environment = Map::new();
        environment.insert("DYLD_INSERT_LIBRARIES".into(), Value::from("/fixture/keystore.dylib"));
        let agent = NativeLaunchAgent::with_context(&run, environment, None, None, context);
        Fixture { _temp: temp, root, run, original, fake, agent }
    }

    fn state(path: &Path, injected: bool) -> State {
        let mut value = Map::new();
        value.insert("path".into(), Value::from(util::text(path)));
        value.insert("program".into(), Value::from(AGENT));
        value.insert("injected".into(), Value::from(injected));
        value
    }

    fn verbs(f: &Fixture) -> Vec<String> {
        f.fake.lock().unwrap().calls.iter().map(|c| c[0].clone()).filter(|c| c != "print" && c != "getenv").collect()
    }

    #[test]
    fn failed_bootstrap_restores_original() {
        let mut f = fixture();
        f.fake.lock().unwrap().fail_probe_bootstrap = true;
        let error = f.agent.start().unwrap_err();
        assert!(error.to_string().contains("bootstrap failed"), "{}", error);
        assert_eq!(f.fake.lock().unwrap().job.as_deref(), Some(f.original.as_path()));
        assert!(!f.agent.settings.exists());
        assert!(f.agent.settings.with_extension("disabled").exists());
        assert!(f.agent.lock.is_none());
        // The journal is released once the original is verified.
        assert!(!f.root.join("Library/Caches/Mirra/launch.json").exists());
        let definition = plist::loads(&std::fs::read(&f.agent.plist).unwrap()).unwrap();
        assert_eq!(definition.get("Umask"), Some(&Plist::Integer(63)));
        let environment = definition.get("EnvironmentVariables").unwrap();
        assert_eq!(environment.get("DYLD_INSERT_LIBRARIES").and_then(Plist::as_str), Some(util::text(&f.run.join("launch.dylib")).as_str()));
        assert_eq!(std::fs::read_to_string(f.agent.settings.with_extension("disabled")).unwrap(), "{\"DYLD_INSERT_LIBRARIES\": \"/fixture/keystore.dylib\"}\n");
    }

    #[test]
    fn interrupted_start_restores_original() {
        let mut f = fixture();
        f.agent.stop.set();
        let error = f.agent.start().unwrap_err();
        assert!(error.to_string().contains("interrupted"));
        assert_eq!(f.fake.lock().unwrap().job.as_deref(), Some(f.original.as_path()));
        assert!(!f.agent.settings.exists());
    }

    #[test]
    fn successful_start_waits_for_adapter_marker() {
        let mut f = fixture();
        f.fake.lock().unwrap().ready_log = Some(f.agent.log.clone());
        let state = f.agent.start().unwrap();
        assert_eq!(state["pid"], "123");
        assert_eq!(state["injected"], true);
        assert!(f.root.join("Library/Caches/Mirra/launch.json").exists());
        let restored = f.agent.close().unwrap().unwrap();
        assert_eq!(restored["path"], Value::from(util::text(&f.original)));
        assert!(!f.root.join("Library/Caches/Mirra/launch.json").exists());
    }

    #[test]
    fn foreign_injected_job_is_not_replaced() {
        let mut f = fixture();
        let foreign = f.root.join("someone-else.plist");
        f.fake.lock().unwrap().job = Some(foreign.clone());
        let error = f.agent.start().unwrap_err();
        assert!(error.to_string().contains("unexpected configuration"));
        assert_eq!(f.fake.lock().unwrap().job.as_deref(), Some(foreign.as_path()));
        assert!(verbs(&f).is_empty());
    }

    #[test]
    fn failed_observation_is_not_treated_as_missing_job() {
        let mut f = fixture();
        f.agent.context.command = Arc::new(|_| Ok(Reply { code: 1, stdout: String::new(), stderr: "temporary service communication error".into() }));
        assert!(f.agent.state().unwrap_err().to_string().contains("Cannot inspect"));
        assert_eq!(f.fake.lock().unwrap().job.as_deref(), Some(f.original.as_path()));
    }

    #[test]
    fn settings_cleanup_failure_does_not_skip_agent_restoration() {
        let mut f = fixture();
        std::fs::write(&f.agent.settings, "{}").unwrap();
        // A non-empty directory at the target makes the rename fail.
        std::fs::create_dir_all(f.agent.settings.with_extension("disabled").join("blocker")).unwrap();
        f.agent.changed = true;
        f.fake.lock().unwrap().job = Some(f.agent.plist.clone());
        let result = f.agent.close().unwrap().unwrap();
        assert_eq!(f.fake.lock().unwrap().job.as_deref(), Some(f.original.as_path()));
        assert!(result.contains_key("settings_disable_error"));
    }

    #[test]
    fn close_waits_for_exiting_owned_job_before_restoring_original() {
        let mut f = fixture();
        f.agent.changed = true;
        let owned = state(&f.agent.plist, true);
        let restored = state(&f.original, false);
        f.fake.lock().unwrap().script = [Ok(owned.clone()), Ok(owned.clone()), Ok(owned), Ok(Map::new()), Ok(restored.clone())].into();
        let result = f.agent.close().unwrap().unwrap();
        assert_eq!(result["path"], restored["path"]);
        assert_eq!(verbs(&f), ["bootout", "bootstrap"]);
        assert!(!f.agent.changed);
    }

    #[test]
    fn close_waits_for_original_registration_to_be_observable() {
        let mut f = fixture();
        f.agent.changed = true;
        let restored = state(&f.original, false);
        f.fake.lock().unwrap().script = [Ok(Map::new()), Ok(Map::new()), Ok(Map::new()), Ok(restored)].into();
        f.fake.lock().unwrap().job = None;
        f.agent.close().unwrap().unwrap();
        assert_eq!(verbs(&f), ["bootstrap"]);
    }

    #[test]
    fn unload_timeout_preserves_pending_cleanup_without_bootstrap() {
        let mut f = fixture();
        f.agent.changed = true;
        f.agent.context.unload_timeout = Duration::ZERO;
        let owned = state(&f.agent.plist, true);
        f.fake.lock().unwrap().script = [Ok(owned.clone()), Ok(owned)].into();
        let error = f.agent.close().unwrap_err();
        assert!(error.to_string().contains("still unloading"));
        assert!(f.agent.changed);
        assert_eq!(verbs(&f), ["bootout"]);
    }

    #[test]
    fn foreign_job_after_unload_is_preserved() {
        let mut f = fixture();
        f.agent.changed = true;
        let owned = state(&f.agent.plist, true);
        let foreign = state(Path::new("/other/agent.plist"), false);
        f.fake.lock().unwrap().script = [Ok(owned), Ok(foreign)].into();
        assert!(f.agent.close().unwrap_err().to_string().contains("ownership changed"));
        assert_eq!(verbs(&f), ["bootout"]);
    }

    #[test]
    fn failed_unload_observation_never_bootstraps_over_unknown_job() {
        let mut f = fixture();
        f.agent.changed = true;
        let owned = state(&f.agent.plist, true);
        f.fake.lock().unwrap().script = [Ok(owned), Err("query timed out".into())].into();
        assert!(f.agent.close().unwrap_err().to_string().contains("query timed out"));
        assert!(f.agent.changed);
        assert_eq!(verbs(&f), ["bootout"]);
    }

    #[test]
    fn abandoned_session_is_recovered_under_lock() {
        let f = fixture();
        // A journal from a dead controller with the owned plist registered.
        let previous = f.root.join("runtime/native-previous");
        std::fs::create_dir_all(&previous).unwrap();
        let dead = LaunchOwnerJournal::with_home(&f.root.join("runtime"), &f.root)
            .with_birth_probe(Arc::new(|pid| Ok(Some((pid, sys::getuid(), 1, 1)))));
        dead.publish(&previous, &Map::new()).unwrap();
        f.fake.lock().unwrap().job = Some(previous.join("native-launch-agent.plist"));
        let cleaned = Arc::new(Mutex::new(Vec::new()));
        let seen = cleaned.clone();
        let context = LaunchContext {
            app_cleanup: Arc::new(move |adapter| { seen.lock().unwrap().push(adapter.to_path_buf()); Ok(()) }),
            ..f.agent.context.clone()
        };
        let result = NativeLaunchAgent::recover_abandoned_with(Some(&f.root.join("runtime")), context).unwrap().unwrap();
        assert_eq!(result["original_agent_restored"], true);
        assert_eq!(result["directory"], Value::from(util::text(&previous)));
        assert_eq!(*cleaned.lock().unwrap(), vec![previous.join("sockets.dylib")]);
        assert_eq!(f.fake.lock().unwrap().job.as_deref(), Some(f.original.as_path()));
        assert!(!f.root.join("Library/Caches/Mirra/launch.json").exists());
    }


    #[test]
    fn inherited_domain_variable_is_not_the_job_configuration() {
        let mut f = fixture();
        let printed = format!("gui/501/{label} = {{\n\tactive count = 1\n\tpath = {original}\n\tinherited environment = {{\n\
            \t\tDYLD_INSERT_LIBRARIES => /tmp/keystore.dylib\n\t\tMIRRA_KEYSTORE_CONFIG => /tmp/keystore.json\n\t}}\n\
            \tdefault environment = {{\n\t\tPATH => /usr/bin:/bin\n\t}}\n\tstate = running\n\tprogram = {agent}\n\
            \tresource coalition = {{\n\t\tstate = active\n\t}}\n\tpid = 608\n}}\n", label = LABEL, original = ORIGINAL, agent = AGENT);
        f.agent.context.command = Arc::new(move |_| Ok(Reply { code: 0, stdout: printed.clone(), stderr: String::new() }));
        let observed = f.agent.state().unwrap();
        assert_eq!(observed["injected"], false);
        assert_eq!(observed["path"], ORIGINAL);
        assert_eq!(observed["program"], AGENT);
        assert_eq!(observed["state"], "running");
        assert_eq!(observed["pid"], "608");
    }

    #[test]
    fn own_environment_variable_is_injection() {
        let mut f = fixture();
        let printed = format!("gui/501/{} = {{\n\tpath = /tmp/owned.plist\n\tenvironment = {{\n\
            \t\tDYLD_INSERT_LIBRARIES => /tmp/launch.dylib\n\t}}\n\tprogram = {}\n}}\n", LABEL, AGENT);
        f.agent.context.command = Arc::new(move |_| Ok(Reply { code: 0, stdout: printed.clone(), stderr: String::new() }));
        let observed = f.agent.state().unwrap();
        assert_eq!(observed["injected"], true);
    }

    #[test]
    fn start_waits_while_sharingd_adapter_variables_are_in_the_domain() {
        let mut f = fixture();
        {
            let mut fake = f.fake.lock().unwrap();
            fake.ready_log = Some(f.agent.log.clone());
            fake.domain = [true, true].into();
        }
        let started = f.agent.start().unwrap();
        assert_eq!(started["injected"], true);
        let first: Vec<String> = f.fake.lock().unwrap().calls.iter().take(4).map(|c| c[0].clone()).collect();
        assert_eq!(first, ["getenv", "getenv", "getenv", "print"]);
        assert_eq!(verbs(&f), ["bootout", "bootstrap"]);
        f.agent.close().unwrap().unwrap();
    }

    #[test]
    fn start_gives_up_without_changes_when_the_domain_stays_injected() {
        let mut f = fixture();
        f.agent.context.domain_timeout = Duration::ZERO;
        f.fake.lock().unwrap().domain = [true].into();
        let error = f.agent.start().unwrap_err();
        assert!(error.to_string().contains("DYLD_INSERT_LIBRARIES"), "{}", error);
        assert!(verbs(&f).is_empty());
        assert_eq!(f.fake.lock().unwrap().job.as_deref(), Some(f.original.as_path()));
    }

    #[test]
    fn original_is_not_restored_into_an_injected_domain() {
        let mut f = fixture();
        f.agent.changed = true;
        let restored = state(&f.original, false);
        {
            let mut fake = f.fake.lock().unwrap();
            fake.job = None;
            fake.script = [Ok(Map::new()), Ok(restored)].into();
            fake.domain = [true, true].into();
        }
        f.agent.close().unwrap().unwrap();
        let calls: Vec<String> = f.fake.lock().unwrap().calls.iter().map(|c| c[0].clone()).collect();
        // bootstrap only after launchd reported the variable gone.
        assert_eq!(calls, ["print", "getenv", "getenv", "getenv", "bootstrap", "print"]);
    }
}
