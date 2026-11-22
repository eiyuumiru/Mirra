//! Port of tests/test_sharingd.py (plus the sharingd parts of
//! tests/test_supervisor.py) against a simulated launchd; nothing here
//! touches the real launchctl, sharingd or ~/Library.
use std::collections::{BTreeMap, VecDeque};
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::sync::Mutex;

use super::*;

#[derive(Clone, Debug, Default)]
pub(crate) struct Job {
    pub path: String,
    pub program: String,
    pub pid: Option<u32>,
    pub adapter: Option<String>,
    pub stdout_path: Option<String>,
    pub stderr_path: Option<String>,
}

#[derive(Default)]
pub(crate) struct FakeState {
    pub job: Option<Job>,
    /// Scripted `print` replies taking precedence over `job` (None = missing).
    pub prints: VecDeque<Option<String>>,
    pub print_failure: Option<String>,
    pub environment: BTreeMap<String, String>,
    pub commands: Vec<Vec<String>>,
    pub next_pid: u32,
    /// Where a kickstarted sharingd "logs" the adapter marker.
    pub marker_log: Option<PathBuf>,
}

/// Simulated per-user launchd for com.apple.sharingd.
#[derive(Clone)]
pub(crate) struct FakeLaunchd(pub Arc<Mutex<FakeState>>);

fn reply(code: i32, stdout: &str, stderr: &str) -> Result<Reply> {
    Ok(Reply { code, stdout: stdout.into(), stderr: stderr.into() })
}

pub(crate) fn render(job: &Job) -> String {
    let mut text = format!("gui/501/com.apple.sharingd = {{\n\tpath = {}\n\tprogram = {}\n\tstate = {}\n",
        job.path, job.program, if job.pid.is_some() { "running" } else { "waiting" });
    if let Some(pid) = job.pid {
        text.push_str(&format!("\tpid = {}\n", pid));
    }
    if let Some(path) = &job.stdout_path {
        text.push_str(&format!("\tstdout path = {}\n", path));
    }
    if let Some(path) = &job.stderr_path {
        text.push_str(&format!("\tstderr path = {}\n", path));
    }
    if let Some(adapter) = &job.adapter {
        text.push_str(&format!("\tenvironment = {{\n\t\tDYLD_INSERT_LIBRARIES => {}\n\t}}\n", adapter));
    }
    text.push_str("}\n");
    text
}

impl FakeLaunchd {
    pub fn new(job: Option<Job>) -> Self {
        FakeLaunchd(Arc::new(Mutex::new(FakeState { job, next_pid: 1000, ..Default::default() })))
    }

    pub fn original(pid: u32) -> Job {
        Job { path: ORIGINAL_PLIST.into(), program: PROGRAM.into(), pid: Some(pid), ..Default::default() }
    }

    pub fn state(&self) -> std::sync::MutexGuard<'_, FakeState> {
        self.0.lock().unwrap()
    }

    /// Mutating commands (everything except print/getenv), by verb.
    pub fn mutations(&self) -> Vec<String> {
        self.state().commands.iter().filter(|c| c[0] != "print" && c[0] != "getenv").map(|c| c[0].clone()).collect()
    }

    pub fn launchctl(&self) -> Launchctl {
        let shared = self.0.clone();
        Arc::new(move |arguments: &[String], _timeout| {
            let mut state = shared.lock().unwrap();
            state.commands.push(arguments.to_vec());
            let verb = arguments[0].as_str();
            match verb {
                "print" => {
                    if let Some(failure) = state.print_failure.clone() {
                        return reply(1, "", &failure);
                    }
                    let text = match state.prints.pop_front() {
                        Some(scripted) => scripted,
                        None => state.job.as_ref().map(render),
                    };
                    match text {
                        Some(text) => reply(0, &text, ""),
                        None => reply(113, "", "Could not find service \"com.apple.sharingd\" in domain for user gui: 501\n"),
                    }
                }
                "getenv" => match state.environment.get(&arguments[1]) {
                    Some(value) => reply(0, &format!("{}\n", value), ""),
                    None => reply(1, "", ""),
                },
                "setenv" => {
                    state.environment.insert(arguments[1].clone(), arguments[2].clone());
                    reply(0, "", "")
                }
                "unsetenv" => {
                    state.environment.remove(&arguments[1]);
                    reply(0, "", "")
                }
                "bootout" => {
                    state.job = None;
                    reply(0, "", "")
                }
                "bootstrap" => {
                    assert_eq!(arguments[2], ORIGINAL_PLIST);
                    state.next_pid += 1;
                    state.job = Some(Self::original(state.next_pid));
                    reply(0, "", "")
                }
                "kickstart" => {
                    state.next_pid += 1;
                    let pid = state.next_pid;
                    let loaded = state.environment.contains_key("DYLD_INSERT_LIBRARIES");
                    if let Some(job) = state.job.as_mut() {
                        job.pid = Some(pid);
                    }
                    if let (true, Some(log)) = (loaded, state.marker_log.clone()) {
                        use std::io::Write;
                        let mut file = std::fs::OpenOptions::new().append(true).create(true).open(log).unwrap();
                        writeln!(file, "MIRRA_KEYSTORE_SHIM_LOADED pid={} enabled=1", pid).unwrap();
                    }
                    reply(0, "", "")
                }
                other => panic!("Unexpected sharingd mutation: {:?} {}", arguments, other),
            }
        })
    }
}

#[derive(Clone)]
pub(crate) enum Births {
    Dead,
    Alive(Birth),
    Fails,
}

pub(crate) fn context(home: &Path, launchd: &FakeLaunchd, births: Arc<Mutex<Births>>) -> SharingdContext {
    SharingdContext {
        home: home.to_path_buf(),
        uid: sys::getuid(),
        launchctl: launchd.launchctl(),
        process_birth: Arc::new(move |pid| {
            if pid == std::process::id() as i32 {
                return processes::process_birth(pid);
            }
            match &*births.lock().unwrap() {
                Births::Dead => Ok(None),
                Births::Alive(birth) => Ok(Some(*birth)),
                Births::Fails => Err(Error::os_message(libc::EPERM, "not observable")),
            }
        }),
        restart: Duration::from_millis(300),
        interval: Duration::from_millis(5),
    }
}

struct Setup {
    _temporary: tempfile::TempDir,
    root: PathBuf,
    directory: PathBuf,
    plist: PathBuf,
    journal: PathBuf,
    births: Arc<Mutex<Births>>,
    birth: Birth,
}

impl Setup {
    fn new() -> Self {
        let temporary = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(temporary.path()).unwrap();
        // tempfile.TemporaryDirectory (mkdtemp) is private; mirror that.
        std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700)).unwrap();
        let directory = root.join("backend-000001");
        std::fs::DirBuilder::new().mode(0o700).create(&directory).unwrap();
        let plist = directory.join("sharing.plist");
        std::fs::write(&plist, b"owned test configuration").unwrap();
        std::fs::set_permissions(&plist, std::fs::Permissions::from_mode(0o600)).unwrap();
        let cache = root.join("Library/Caches/Mirra");
        std::fs::create_dir_all(&cache).unwrap();
        std::fs::set_permissions(&cache, std::fs::Permissions::from_mode(0o700)).unwrap();
        let birth: Birth = (12345, sys::getuid(), 50, 6);
        let journal = cache.join("sharing.json");
        write_state(&journal, &json!({"schema_version": 1, "controller_birth": [birth.0, birth.1, birth.2, birth.3],
            "directory": text(&directory), "plist_sha256": util::sha256_hex(b"owned test configuration")})).unwrap();
        Setup { _temporary: temporary, root, directory, plist, journal, births: Arc::new(Mutex::new(Births::Dead)), birth }
    }

    fn owned(&self) -> Job {
        Job { path: text(&self.plist), program: PROGRAM.into(), pid: Some(77),
            adapter: Some(text(&self.directory.join("keystore.dylib"))),
            stdout_path: Some(text(&self.directory.join("sharingd.stdout.log"))),
            stderr_path: Some(text(&self.directory.join("sharingd.stderr.log"))) }
    }

    fn context(&self, launchd: &FakeLaunchd) -> SharingdContext {
        context(&self.root, launchd, self.births.clone())
    }

    fn recover(&self, launchd: &FakeLaunchd) -> Result<Option<Value>> {
        SharingdAgent::recover_abandoned_with(false, self.context(launchd))
    }
}

fn scripted(states: Vec<Option<Job>>) -> FakeLaunchd {
    let launchd = FakeLaunchd::new(None);
    launchd.state().prints = states.into_iter().map(|s| s.as_ref().map(render)).collect();
    launchd
}

fn original_state() -> Value {
    json!({"injected": false, "environment": {}, "path": ORIGINAL_PLIST, "program": PROGRAM, "state": "running", "pid": "5"})
}

#[test]
fn dead_controller_restores_owned_job_and_clears_journal() {
    let setup = Setup::new();
    let launchd = scripted(vec![Some(setup.owned()), None, Some(FakeLaunchd::original(5))]);
    let result = setup.recover(&launchd).unwrap().unwrap();
    assert_eq!(result["original_restored"], true);
    assert_eq!(result["directory"], text(&setup.directory));
    assert_eq!(launchd.mutations(), ["bootout", "bootstrap"]);
    assert!(!setup.journal.exists());
    let saved: Value = serde_json::from_slice(&std::fs::read(setup.directory.join("sharingd-last-restore.json")).unwrap()).unwrap();
    assert_eq!(saved, original_state());
}

#[test]
fn live_controller_is_not_recovered_even_if_lock_is_free() {
    let setup = Setup::new();
    *setup.births.lock().unwrap() = Births::Alive(setup.birth);
    let launchd = FakeLaunchd::new(Some(setup.owned()));
    let error = setup.recover(&launchd).unwrap_err();
    assert!(error.to_string().contains("still running"));
    assert!(launchd.state().commands.is_empty());
    assert!(setup.journal.exists());
}

#[test]
fn held_agent_lock_is_a_blocking_error() {
    let setup = Setup::new();
    let launchd = FakeLaunchd::new(Some(FakeLaunchd::original(5)));
    let mut holder = SharingdAgent::with_context(None, setup.context(&launchd));
    holder.acquire().unwrap();
    let error = setup.recover(&launchd).unwrap_err();
    assert_eq!(error.type_name(), "BlockingIOError");
    holder.close(false).unwrap();
    assert!(setup.recover(&launchd).is_ok());
}

fn detached_journal(setup: &Setup, injected: u32, adapter: &str) {
    write_state(&setup.journal, &json!({"schema_version": 2, "controller_birth": null, "directory": text(&setup.directory),
        "config_sha256": "c".repeat(64), "previous_pid": "4", "injected_pid": injected, "adapter_sha256": adapter,
        "detached": true})).unwrap();
}

#[test]
fn update_keeps_only_an_identical_live_detached_adapter() {
    let setup = Setup::new();
    for (alive, digest, expected) in [(true, "a", true), (true, "b", false), (false, "a", false)] {
        detached_journal(&setup, 600, &"a".repeat(64));
        let launchd = FakeLaunchd::new(Some(FakeLaunchd::original(if alive { 600 } else { 601 })));
        assert_eq!(SharingdAgent::detached_matches_with(&digest.repeat(64), setup.context(&launchd)).unwrap(), expected);
        assert!(launchd.mutations().is_empty());
    }
    // A live detached adapter stays during ordinary recovery...
    let launchd = FakeLaunchd::new(Some(FakeLaunchd::original(600)));
    assert_eq!(setup.recover(&launchd).unwrap(), None);
    assert!(setup.journal.exists());
    // ...and is restored (exactly that process restarted) on request.
    let result = SharingdAgent::restore_detached_with(setup.context(&launchd)).unwrap().unwrap();
    assert_eq!(result["original_restored"], true);
    assert_eq!(launchd.mutations(), ["unsetenv", "unsetenv", "kickstart"]);
    assert!(!setup.journal.exists());
}

#[test]
fn detached_adapter_is_not_adopted_after_the_bridge_loses_its_sessions() {
    let setup = Setup::new();
    let adapter = setup.directory.join("keystore.dylib");
    std::fs::write(&adapter, b"test adapter").unwrap();
    detached_journal(&setup, 600, &util::sha256_hex(b"test adapter"));
    let launchd = FakeLaunchd::new(Some(FakeLaunchd::original(600)));
    let mut agent = SharingdAgent::with_context(Some(&setup.directory), setup.context(&launchd));
    agent.start(&adapter, &json!({"k": "v"}), None, false).unwrap();
    assert!(!agent.adopted);
    // The detached adapter was restored first, then a fresh one loaded.
    assert_eq!(launchd.mutations(), ["unsetenv", "unsetenv", "kickstart", "setenv", "setenv", "kickstart", "unsetenv", "unsetenv"]);
    assert!(launchd.state().environment.is_empty());
    agent.close(false).unwrap();
}

#[test]
fn identity_observation_failure_is_not_death() {
    let setup = Setup::new();
    *setup.births.lock().unwrap() = Births::Fails;
    let launchd = FakeLaunchd::new(Some(setup.owned()));
    assert!(setup.recover(&launchd).unwrap_err().is_os_error());
    assert!(launchd.state().commands.is_empty());
}

#[test]
fn changed_job_or_plist_is_not_unloaded() {
    let setup = Setup::new();
    let foreign = Job { path: "/another/agent.plist".into(), ..setup.owned() };
    for (job, change) in [(foreign, false), (setup.owned(), true)] {
        if change {
            std::fs::write(&setup.plist, b"changed").unwrap();
        }
        let launchd = FakeLaunchd::new(Some(job));
        assert!(setup.recover(&launchd).is_err());
        assert!(launchd.mutations().is_empty());
        assert!(setup.journal.exists());
    }
}

#[test]
fn partial_restore_retries_from_missing_job_without_second_bootout() {
    let setup = Setup::new();
    let launchd = FakeLaunchd::new(None);
    assert_eq!(setup.recover(&launchd).unwrap().unwrap()["original_restored"], true);
    assert_eq!(launchd.mutations(), ["bootstrap"]);
}

#[test]
fn observation_error_does_not_look_like_missing_service() {
    let setup = Setup::new();
    let launchd = FakeLaunchd::new(None);
    launchd.state().print_failure = Some("Operation not permitted".into());
    let error = setup.context(&launchd).service(None, Duration::from_secs(1)).unwrap_err();
    assert_eq!(error.to_string(), "Cannot inspect sharingd registration: Operation not permitted");
}

#[test]
fn missing_runtime_is_recovered_without_recreating_the_directory() {
    let setup = Setup::new();
    std::fs::remove_dir_all(&setup.directory).unwrap();
    let launchd = scripted(vec![Some(setup.owned()), None, Some(FakeLaunchd::original(5))]);
    assert_eq!(setup.recover(&launchd).unwrap().unwrap()["original_restored"], true);
    assert_eq!(launchd.mutations(), ["bootout", "bootstrap"]);
    assert!(!setup.journal.exists());
    assert!(!setup.directory.exists());
    let saved: Value = serde_json::from_slice(&std::fs::read(setup.root.join("Library/Caches/Mirra/sharingd-last-restore.json")).unwrap()).unwrap();
    assert_eq!(saved, json!({"directory": text(&setup.directory), "state": original_state()}));
}

#[test]
fn missing_plist_requires_the_live_job_to_match_the_mirra_adapter() {
    let setup = Setup::new();
    std::fs::remove_file(&setup.plist).unwrap();
    let launchd = scripted(vec![Some(setup.owned()), None, Some(FakeLaunchd::original(5))]);
    assert_eq!(setup.recover(&launchd).unwrap().unwrap()["original_restored"], true);
    assert!(!setup.journal.exists());
    assert!(setup.directory.join("sharingd-last-restore.json").exists());
}

#[test]
fn missing_runtime_does_not_make_a_live_controller_abandoned() {
    let setup = Setup::new();
    std::fs::remove_dir_all(&setup.directory).unwrap();
    *setup.births.lock().unwrap() = Births::Alive(setup.birth);
    let launchd = FakeLaunchd::new(Some(setup.owned()));
    assert!(setup.recover(&launchd).unwrap_err().to_string().contains("still running"));
    assert!(launchd.state().commands.is_empty());
    assert!(setup.journal.exists());
}

#[test]
fn original_job_with_missing_runtime_can_retire_its_old_journal() {
    let setup = Setup::new();
    std::fs::remove_dir_all(&setup.directory).unwrap();
    let launchd = FakeLaunchd::new(Some(FakeLaunchd::original(5)));
    assert_eq!(setup.recover(&launchd).unwrap().unwrap()["original_restored"], true);
    assert!(launchd.mutations().is_empty());
    assert!(!setup.journal.exists());
    assert!(!setup.directory.exists());
}

#[test]
fn missing_job_and_runtime_can_restore_the_original_job() {
    let setup = Setup::new();
    std::fs::remove_dir_all(&setup.directory).unwrap();
    let launchd = FakeLaunchd::new(None);
    assert_eq!(setup.recover(&launchd).unwrap().unwrap()["original_restored"], true);
    assert_eq!(launchd.mutations(), ["bootstrap"]);
    assert!(!setup.directory.exists());
}

#[test]
fn missing_runtime_preserves_changed_or_unrecognized_jobs() {
    let setup = Setup::new();
    std::fs::remove_dir_all(&setup.directory).unwrap();
    let adapter = text(&setup.directory.join("keystore.dylib"));
    let states = [
        Job { path: "/another/sharing.plist".into(), ..setup.owned() },
        Job { program: "/another/sharingd".into(), ..setup.owned() },
        Job { adapter: None, ..setup.owned() },
        Job { adapter: Some("/another/keystore.dylib".into()), ..setup.owned() },
        Job { adapter: Some(format!("{}:/another/adapter.dylib", adapter)), ..setup.owned() },
        Job { stderr_path: Some("/another/log".into()), ..setup.owned() },
    ];
    for job in states {
        let launchd = FakeLaunchd::new(Some(job.clone()));
        assert!(setup.recover(&launchd).is_err(), "{:?}", job);
        assert!(launchd.mutations().is_empty());
        assert!(setup.journal.exists());
    }
}

#[test]
fn missing_runtime_keeps_the_journal_until_restoration_is_verified() {
    let setup = Setup::new();
    std::fs::remove_dir_all(&setup.directory).unwrap();
    let launchd = scripted(vec![Some(setup.owned()), None, None]);
    launchd.state().job = None;
    // bootstrap would install the original; keep the scripted "missing" reply.
    let error = setup.recover(&launchd).unwrap_err();
    assert!(error.to_string().contains("not verified"));
    assert!(setup.journal.exists());
}

#[test]
fn missing_runtime_requires_a_private_owned_ancestor() {
    let setup = Setup::new();
    std::fs::remove_dir_all(&setup.directory).unwrap();
    std::fs::set_permissions(&setup.root, std::fs::Permissions::from_mode(0o755)).unwrap();
    let launchd = FakeLaunchd::new(Some(setup.owned()));
    let error = setup.recover(&launchd).unwrap_err();
    std::fs::set_permissions(&setup.root, std::fs::Permissions::from_mode(0o700)).unwrap();
    assert!(error.to_string().contains("not private"));
    assert!(launchd.state().commands.is_empty());
    assert!(setup.journal.exists());
}

#[test]
fn invalid_journals_are_rejected_without_launchd_changes() {
    let setup = Setup::new();
    let launchd = FakeLaunchd::new(Some(setup.owned()));
    let directory = text(&setup.directory);
    for record in [json!([]), json!({"schema_version": 3}),
        json!({"schema_version": 1, "controller_birth": [0, sys::getuid(), 1, 1], "directory": directory, "plist_sha256": "a".repeat(64)}),
        json!({"schema_version": 1, "controller_birth": [1, sys::getuid(), true, 1], "directory": directory, "plist_sha256": "a".repeat(64)}),
        json!({"schema_version": 1, "controller_birth": [1, sys::getuid(), 1, 1], "directory": "relative", "plist_sha256": "a".repeat(64)}),
        json!({"schema_version": 1, "controller_birth": [1, sys::getuid(), 1, 1], "directory": directory, "plist_sha256": "A".repeat(64)}),
        json!({"schema_version": 2, "controller_birth": null, "detached": true, "directory": directory,
            "config_sha256": "a".repeat(64), "injected_pid": "12a"})] {
        write_state(&setup.journal, &record).unwrap();
        assert!(setup.recover(&launchd).is_err(), "{}", record);
    }
    std::fs::set_permissions(&setup.journal, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(setup.recover(&launchd).unwrap_err().to_string().contains("not a private owned file"));
    assert!(launchd.state().commands.is_empty());
}

#[test]
fn job_environment_is_read_from_the_explicit_registration() {
    let setup = Setup::new();
    let stdout = format!("path = {plist}\nprogram = {PROGRAM}\nstdout path = {d}/sharingd.stdout.log\nstderr path = {d}/sharingd.stderr.log\n\
        inherited environment = {{\n\tDYLD_INSERT_LIBRARIES => /unrelated/inherited.dylib\n}}\nenvironment = {{\n\
        \tDYLD_INSERT_LIBRARIES => {d}/keystore.dylib\n\tMIRRA_KEYSTORE_BROKER_TOKEN => private-test-token\n}}\n",
        plist = text(&setup.plist), d = text(&setup.directory));
    let observed = parse_service(&stdout);
    assert_eq!(observed["environment"], json!({"DYLD_INSERT_LIBRARIES": text(&setup.directory.join("keystore.dylib"))}));
    assert!(!mirra_core::pyjson::dumps(&Value::Object(observed.clone())).contains("private-test-token"));
    assert_eq!(observed["stdout path"], text(&setup.directory.join("sharingd.stdout.log")));
    assert_eq!(observed.keys().collect::<Vec<_>>(), ["injected", "environment", "path", "program", "stdout path", "stderr path"]);
    assert!(!is_original(&observed));
    assert!(is_original(&parse_service(&format!("path = {}\nprogram = {}\n", ORIGINAL_PLIST, PROGRAM))));
    assert!(!is_original(&parse_service(&format!("path = {}\nprogram = {}\nDYLD_INSERT_LIBRARIES = other", ORIGINAL_PLIST, PROGRAM))));
}

#[test]
fn session_detaches_then_adopts_then_restores_with_python_journal_layout() {
    let setup = Setup::new();
    std::fs::remove_file(&setup.journal).unwrap();
    let adapter = setup.directory.join("keystore.dylib");
    std::fs::write(&adapter, b"adapter").unwrap();
    let launchd = FakeLaunchd::new(Some(FakeLaunchd::original(500)));
    let settings = json!({"broker_file": "/x/broker.json", "environment": {"A": "1"}});
    let mut agent = SharingdAgent::with_context(Some(&setup.directory), setup.context(&launchd));
    agent.start(&adapter, &settings, None, true).unwrap();
    assert!(agent.owned && !agent.adopted);
    let config = setup.directory.join("keystore.json");
    assert_eq!(std::fs::read_to_string(&config).unwrap(), r#"{"broker_file": "/x/broker.json", "environment": {"A": "1"}}"#);
    assert_eq!(std::fs::metadata(&config).unwrap().permissions().mode() & 0o777, 0o600);
    {
        let state = launchd.state();
        let sets: Vec<&Vec<String>> = state.commands.iter().filter(|c| c[0] == "setenv").collect();
        assert_eq!(sets[0][1..], ["DYLD_INSERT_LIBRARIES".to_string(), text(&adapter)]);
        assert_eq!(sets[1][1..], ["MIRRA_KEYSTORE_CONFIG".to_string(), text(&config)]);
        assert!(state.environment.is_empty());
    }
    let pid = launchd.state().job.as_ref().unwrap().pid.unwrap();
    agent.record_injected(i64::from(pid)).unwrap();
    let birth = processes::process_birth(std::process::id() as i32).unwrap().unwrap();
    let journal = std::fs::read_to_string(&setup.journal).unwrap();
    let expected = format!("{{\n  \"schema_version\": 2,\n  \"controller_birth\": [\n    {},\n    {},\n    {},\n    {}\n  ],\n  \"directory\": \"{}\",\n  \"config_sha256\": \"{}\",\n  \"previous_pid\": \"500\",\n  \"injected_pid\": {},\n  \"adapter_sha256\": \"{}\"\n}}\n",
        birth.0, birth.1, birth.2, birth.3, text(&setup.directory), util::sha256_hex(&std::fs::read(&config).unwrap()), pid,
        util::sha256_hex(b"adapter"));
    assert_eq!(journal, expected);
    let state = agent.close(true).unwrap().unwrap();
    assert_eq!(state["pid"], pid.to_string());
    let detached: Value = serde_json::from_str(&std::fs::read_to_string(&setup.journal).unwrap()).unwrap();
    assert_eq!(detached["detached"], true);
    assert_eq!(detached["controller_birth"], Value::Null);
    assert_eq!(detached.as_object().unwrap().keys().next_back().unwrap(), "detached");
    assert!(config.exists());

    // Next session adopts the still-loaded adapter without restarting sharingd.
    let before = launchd.mutations().len();
    let mut next = SharingdAgent::with_context(Some(&setup.directory), setup.context(&launchd));
    next.start(&adapter, &settings, None, true).unwrap();
    assert!(next.adopted);
    assert_eq!(launchd.mutations().len(), before);
    assert_eq!(next.record.as_ref().unwrap()["injected_pid"], pid);
    let adopted: Value = serde_json::from_str(&std::fs::read_to_string(&setup.journal).unwrap()).unwrap();
    assert_eq!(adopted["detached"], false);
    assert_eq!(adopted["controller_birth"], json!([birth.0, birth.1, birth.2, birth.3]));
    let restored = next.close(false).unwrap().unwrap();
    assert!(is_original(&restored));
    assert_ne!(restored["pid"], pid.to_string());
    assert!(!setup.journal.exists());
    assert!(!config.exists());
    assert!(setup.directory.join("sharingd-last-restore.json").exists());
}

#[test]
fn start_refuses_foreign_sharingd_and_existing_variables() {
    let setup = Setup::new();
    std::fs::remove_file(&setup.journal).unwrap();
    let adapter = setup.directory.join("keystore.dylib");
    std::fs::write(&adapter, b"adapter").unwrap();
    let launchd = FakeLaunchd::new(Some(FakeLaunchd::original(500)));
    launchd.state().environment.insert("MIRRA_KEYSTORE_CONFIG".into(), "/elsewhere".into());
    let mut agent = SharingdAgent::with_context(Some(&setup.directory), setup.context(&launchd));
    let error = agent.start(&adapter, &json!({}), None, true).unwrap_err();
    assert!(error.to_string().contains("already carries"));
    assert!(!agent.owned);
    let foreign = FakeLaunchd::new(Some(Job { path: "/tmp/other.plist".into(), ..FakeLaunchd::original(5) }));
    let mut agent = SharingdAgent::with_context(Some(&setup.directory), setup.context(&foreign));
    assert!(agent.start(&adapter, &json!({}), None, true).unwrap_err().to_string().contains("original configuration"));
    assert!(!setup.journal.exists());
}

fn ltk_entry(byte: u8) -> Plist {
    Plist::Dict([("Attested LTK Data".to_string(), Plist::Data(vec![byte; 4])), ("Other".to_string(), Plist::Integer(1))].into())
}

#[test]
fn pairing_backup_copies_attested_entries_and_restores_missing_ones() {
    let temporary = tempfile::tempdir().unwrap();
    let auto = temporary.path().join("AutoUnlock");
    std::fs::create_dir_all(&auto).unwrap();
    let ltks = Plist::Dict([("Remote LTKs".to_string(), Plist::Dict([
        ("PHONE".to_string(), ltk_entry(7)),
        ("PLAIN".to_string(), Plist::Dict([("Other".to_string(), Plist::Integer(2))].into())),
    ].into())), ("Local".to_string(), Plist::String("keep".into()))].into());
    std::fs::write(auto.join("ltk.plist"), plist::dumps(&ltks, Format::Binary).unwrap()).unwrap();
    let records = Plist::Dict([("PHONE".to_string(), Plist::Dict([("ID".to_string(), Plist::String("pair".into()))].into()))].into());
    std::fs::write(auto.join("pairing-records.plist"), plist::dumps(&records, Format::Xml).unwrap()).unwrap();
    let backup = temporary.path().join("state/pairing.plist");
    assert_eq!(backup_pairing_in(&auto, &backup).unwrap(), 1);
    assert_eq!(std::fs::metadata(&backup).unwrap().permissions().mode() & 0o777, 0o600);
    assert_eq!(std::fs::metadata(backup.parent().unwrap()).unwrap().permissions().mode() & 0o777, 0o700);
    let (saved, format) = plist::loads(&std::fs::read(&backup).unwrap()).unwrap();
    assert_eq!(format, Format::Binary);
    assert_eq!(saved.get("PHONE").unwrap().get("ltk"), Some(&ltk_entry(7)));
    assert_eq!(saved.get("PHONE").unwrap().get("pairing").unwrap().get("ID"), Some(&Plist::String("pair".into())));
    let modified = std::fs::metadata(&backup).unwrap().modified().unwrap();
    assert_eq!(backup_pairing_in(&auto, &backup).unwrap(), 1); // Unchanged: not rewritten.
    assert_eq!(std::fs::metadata(&backup).unwrap().modified().unwrap(), modified);
    assert!(std::fs::read_dir(backup.parent().unwrap()).unwrap().count() == 1);

    // Apple's sharingd removed the entries; restoring keeps each file's format.
    let stripped = Plist::Dict([("Remote LTKs".to_string(), Plist::Dict([
        ("PHONE".to_string(), Plist::Dict([("Fresh".to_string(), Plist::Bool(true))].into()))].into()))].into());
    std::fs::write(auto.join("ltk.plist"), plist::dumps(&stripped, Format::Xml).unwrap()).unwrap();
    std::fs::remove_file(auto.join("pairing-records.plist")).unwrap();
    assert_eq!(restore_pairing_in(&auto, &backup).unwrap(), 2);
    let (restored, format) = plist::loads(&std::fs::read(auto.join("ltk.plist")).unwrap()).unwrap();
    assert_eq!(format, Format::Xml);
    let phone = restored.get("Remote LTKs").unwrap().get("PHONE").unwrap();
    assert_eq!(phone.get("Fresh"), Some(&Plist::Bool(true)));
    assert_eq!(phone.get("Attested LTK Data"), Some(&Plist::Data(vec![7; 4])));
    let (records, format) = plist::loads(&std::fs::read(auto.join("pairing-records.plist")).unwrap()).unwrap();
    assert_eq!(format, Format::Binary);
    assert!(records.get("PHONE").is_some());
    assert_eq!(std::fs::metadata(auto.join("ltk.plist")).unwrap().permissions().mode() & 0o777, 0o644);
    assert_eq!(restore_pairing_in(&auto, &backup).unwrap(), 0);
    assert_eq!(restore_pairing_in(&auto, &temporary.path().join("missing.plist")).unwrap(), 0);
    assert_eq!(backup_pairing_in(&temporary.path().join("none"), &backup).unwrap(), 0);
}

#[test]
fn forgetting_pairing_removes_only_attested_entries_and_their_records() {
    let temporary = tempfile::tempdir().unwrap();
    let auto = temporary.path().join("AutoUnlock");
    assert_eq!(forget_pairing_in(&auto).unwrap(), 0); // No files yet.
    std::fs::create_dir_all(&auto).unwrap();
    let plain = Plist::Dict([("Other".to_string(), Plist::Integer(2))].into());
    let ltks = Plist::Dict([("Remote LTKs".to_string(), Plist::Dict([
        ("PHONE".to_string(), ltk_entry(7)),
        ("WATCH".to_string(), plain.clone()),
    ].into())), ("Local".to_string(), Plist::String("keep".into()))].into());
    std::fs::write(auto.join("ltk.plist"), plist::dumps(&ltks, Format::Xml).unwrap()).unwrap();
    let record = Plist::Dict([("ID".to_string(), Plist::String("pair".into()))].into());
    let records = Plist::Dict([("PHONE".to_string(), record.clone()), ("WATCH".to_string(), record.clone())].into());
    std::fs::write(auto.join("pairing-records.plist"), plist::dumps(&records, Format::Binary).unwrap()).unwrap();

    assert_eq!(forget_pairing_in(&auto).unwrap(), 1);
    let (left, format) = plist::loads(&std::fs::read(auto.join("ltk.plist")).unwrap()).unwrap();
    assert_eq!(format, Format::Xml);
    assert_eq!(left.get("Local"), Some(&Plist::String("keep".into())));
    let remote = left.get("Remote LTKs").unwrap();
    assert!(remote.get("PHONE").is_none());
    assert_eq!(remote.get("WATCH"), Some(&plain));
    let (records, format) = plist::loads(&std::fs::read(auto.join("pairing-records.plist")).unwrap()).unwrap();
    assert_eq!(format, Format::Binary);
    assert!(records.get("PHONE").is_none());
    assert_eq!(records.get("WATCH"), Some(&record));
    assert_eq!(forget_pairing_in(&auto).unwrap(), 0); // Nothing left to remove.
}
