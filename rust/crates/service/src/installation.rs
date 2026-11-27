//! Runtime subset of `scripts/installation.py`: observe, start and stop the
//! installed per-user support, and validate its package.
//!
//! Package preparation, installation, updates, removal and writing the login
//! definition (`prepare`, `install`, `update_saved`, `write_definition`,
//! `remove`, `validate_source`) stay in Python. [`NativeService::definition`]
//! and [`NativeService::previous_definitions`] are ported only so `start`
//! can verify the installed plist; when `start` finds an interrupted upgrade
//! (the plist is still a previous definition) Python's `start` would call
//! `install()`, so the Rust port returns [`Error::Delegate`] instead.
use std::collections::BTreeSet;
use std::path::{Component, Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use mirra_core::activity;
use mirra_core::config::{default_root, load_config, Config};
use mirra_core::launchctl::{self, Reply};
use mirra_core::state::write_state;
use mirra_core::subprocess::RunOptions;
use mirra_core::workspace;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};
use crate::sharingd::{self, Sharingd, SystemSharingd};
use crate::supervisor_lease::{backend_children_stopped, backend_lease};
use crate::util::{self, get, get_str, object, private_file, strict_int, truthy, BirthProbe};

pub const LABEL: &str = "local.mirra.agent";
pub const ADAPTERS: [&str; 4] = ["keystore.dylib", "media.dylib", "sockets.dylib", "launch.dylib"];
pub const HOST_TOOLS: [&str; 1] = ["inspector"];
pub const CLI_NAME: &str = "mirra-cli";
pub const SUPPORT_TOOLS: [&str; 2] = ["inspector", CLI_NAME];
pub const DECODER_ADAPTERS: [&str; 1] = ["decoder-route.dylib"];
pub const PACKAGE_ADAPTERS: [&str; 5] = ["keystore.dylib", "media.dylib", "sockets.dylib", "launch.dylib", "decoder-route.dylib"];
pub const PACKAGE_SCHEMA: i64 = 5;
pub const CLI_SUPPORT_REVISION: i64 = 40;
pub const CERTIFICATE_LOCK_REVISION: i64 = 45;
pub const BRIDGE_UPDATE_REVISION: i64 = 47;
pub const SUPPORT_REVISION: i64 = 54;
pub const BRIDGE_UPDATE_FILES: [&str; 2] = ["build/endpoint", "config/endpoint.plist"];
/// `interpreter.ENTRYPOINT`
pub const ENTRYPOINT: &str = "bin/python3";

pub type Object = Map<String, Value>;

/// The service operations the readiness/control layer uses; implemented by
/// [`NativeService`] and by test fakes.
pub trait SupportService {
    /// `<base>/current`
    fn package(&self) -> PathBuf;
    fn validate_package(&self) -> Result<Object>;
    fn status(&self) -> Result<Object>;
    fn start(&self) -> Result<Object>;
    fn stop(&self) -> Result<Object>;
    /// `NativeService.registration()`
    fn registration(&self) -> Result<Object>;
}

/// `NativeService.needs_update(manifest)`
pub fn needs_update(manifest: &Object) -> Result<bool> {
    let schema = manifest.get("schema_version").map_or(Ok(0.0), |v| util::number(v, "schema_version"))?;
    let revision = manifest.get("support_revision").map_or(Ok(0.0), |v| util::number(v, "support_revision"))?;
    Ok(schema < PACKAGE_SCHEMA as f64 || revision < SUPPORT_REVISION as f64)
}

pub type Launchctl = Arc<dyn Fn(&[String]) -> mirra_core::Result<Reply> + Send + Sync>;
/// Runs the app helper (`<app>/Contents/MacOS/Mirra --background-action ACTION`) and returns stdout.
pub type HelperRunner = Arc<dyn Fn(&[String]) -> Result<String> + Send + Sync>;

/// `NativeLaunchAgent.recover_abandoned(runtime_root=...)`
pub type LaunchRecovery = Arc<dyn Fn(&Path) -> Result<Option<Value>> + Send + Sync>;

/// Replaceable side effects of [`NativeService`] (tests use fakes).
#[derive(Clone)]
pub struct ServiceHooks {
    /// `launchctl <args>` logged through the activity sink (15 s timeout).
    pub launchctl: Launchctl,
    pub helper: HelperRunner,
    pub birth: BirthProbe,
    pub sleep: Arc<dyn Fn(Duration) + Send + Sync>,
    pub sharingd: Arc<dyn Sharingd>,
    /// `NativeLaunchAgent.recover_abandoned(runtime_root=...)`
    pub recover_launch: LaunchRecovery,
    /// `decoder_route.JOURNAL`
    pub decoder_journal: PathBuf,
    /// `os.close(decoder_route.acquire())`
    pub acquire_decoder: Arc<dyn Fn() -> Result<()> + Send + Sync>,
    /// How long `stop` waits for the supervisor to finish restoring (110 s).
    pub stop_timeout: Duration,
    /// Package root used to resolve relative profile paths (`configuration.ROOT`).
    pub config_root: PathBuf,
}

impl ServiceHooks {
    pub fn system(home: &Path) -> Self {
        ServiceHooks {
            launchctl: Arc::new(|args| launchctl::run_logged(args, Duration::from_secs(15))),
            helper: Arc::new(|command| {
                let options = RunOptions::new().source("ServiceManagement").capture().check().timeout(Duration::from_secs(15));
                Ok(activity::run(command, &options)?.stdout_text())
            }),
            birth: util::real_birth(),
            sleep: Arc::new(std::thread::sleep),
            sharingd: Arc::new(SystemSharingd::new(home)),
            recover_launch: Arc::new(|runtime| Ok(mirra_native::launcher::NativeLaunchAgent::recover_abandoned(Some(runtime))?)),
            decoder_journal: home.join("Library/Caches/Mirra/decoder-route.json"),
            acquire_decoder: Arc::new(|| {
                drop(mirra_native::decoder_route::acquire()?);
                Ok(())
            }),
            stop_timeout: Duration::from_secs(110),
            config_root: default_root(),
        }
    }
}

pub struct NativeService {
    pub base: PathBuf,
    pub home: PathBuf,
    pub package: PathBuf,
    pub plist: PathBuf,
    pub domain: String,
    pub target: String,
    pub log: PathBuf,
    pub state: PathBuf,
    pub hooks: ServiceHooks,
}

impl Default for NativeService {
    fn default() -> Self {
        Self::new()
    }
}

impl NativeService {
    /// `NativeService()`: `~/Library/Application Support/Mirra`.
    pub fn new() -> Self {
        let home = util::home();
        Self::with_home(None, &home, ServiceHooks::system(&home))
    }

    /// `NativeService(base)` with an explicit home directory and hooks.
    pub fn with_home(base: Option<&Path>, home: &Path, hooks: ServiceHooks) -> Self {
        let base = mirra_core::paths::resolve(&base.map(Path::to_path_buf)
            .unwrap_or_else(|| home.join("Library/Application Support/Mirra")));
        let domain = launchctl::gui_domain();
        NativeService {
            package: base.join("current"),
            plist: home.join("Library/LaunchAgents").join(format!("{}.plist", LABEL)),
            target: format!("{}/{}", domain, LABEL),
            domain,
            log: base.join("logs/service.log"),
            state: base.join("service.json"),
            base,
            home: home.to_path_buf(),
            hooks,
        }
    }

    pub fn load_config(&self) -> Result<Config> {
        Ok(load_config(Some(&self.package.join("config.json")), &self.hooks.config_root)?)
    }

    /// Recognize the app-managed registration used only by support revision 41.
    pub fn managed_app(&self, manifest: Option<&Object>) -> Result<Option<PathBuf>> {
        let loaded;
        let manifest = match manifest {
            Some(m) => m,
            None => {
                let path = self.package.join("manifest.json");
                if !path.exists() {
                    return Ok(None);
                }
                private_file(&path)?;
                loaded = util::read_object(&path, "Invalid Mirra package manifest")?;
                &loaded
            }
        };
        let app = match manifest.get("managed_app") {
            None | Some(Value::Null) => return Ok(None),
            Some(Value::String(app)) => PathBuf::from(app),
            Some(_) => return Err(Error::type_error("managed_app must be a path")),
        };
        if !app.is_absolute() || app.extension().and_then(|e| e.to_str()) != Some("app") {
            return Err(Error::runtime("Invalid installed Mirra app path"));
        }
        Ok(Some(app))
    }

    pub fn background_action(&self, action: &str, app: Option<&Path>) -> Result<String> {
        let app = match app {
            Some(app) => app.to_path_buf(),
            None => self.managed_app(None)?
                .ok_or_else(|| Error::runtime("No Mirra app registered to manage background support"))?,
        };
        let helper = app.join("Contents/MacOS/Mirra");
        let stdout = (self.hooks.helper)(&[util::text(&helper), "--background-action".into(), action.into()])?;
        let status = stdout.trim();
        if !matches!(status, "enabled" | "requires_approval" | "not_registered" | "not_found") {
            return Err(Error::runtime("Mirra did not return a background registration status"));
        }
        Ok(status.to_string())
    }

    pub fn command(&self, args: &[&str]) -> Result<Reply> {
        let args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        Ok((self.hooks.launchctl)(&args)?)
    }

    pub fn registration(&self) -> Result<Object> {
        let reply = self.command(&["print", &self.target])?;
        if reply.code != 0 {
            if reply.stderr.contains("Could not find service") {
                return Ok(Map::new());
            }
            return Err(Error::runtime(format!("Cannot inspect native support service: {}", reply.stderr.trim())));
        }
        let mut values = Map::new();
        for line in mirra_core::pyfmt::splitlines(&reply.stdout) {
            if let Some((key, value)) = line.trim().split_once(" = ") {
                if matches!(key, "path" | "program" | "pid" | "state" | "last exit code") && !values.contains_key(key) {
                    values.insert(key.into(), Value::from(value));
                }
            }
        }
        let path = values.get("path").and_then(Value::as_str).unwrap_or("").to_string();
        if path != util::text(&self.plist)
            && !(path.starts_with("(submitted by smd.") && self.managed_app(None)?.is_some()
                && self.background_action("status", None)? == "enabled") {
            return Err(Error::runtime("The service label belongs to another configuration"));
        }
        Ok(values)
    }

    pub fn python(&self) -> String {
        util::text(&self.package.join("python").join(ENTRYPOINT))
    }

    /// The login job definition (for verification only; writing it stays in Python).
    pub fn definition(&self, manifest: Option<&Object>) -> Value {
        let revision = match manifest {
            None => SUPPORT_REVISION,
            Some(m) => m.get("support_revision").and_then(Value::as_i64).unwrap_or(0),
        };
        let arguments: Vec<String> = if revision >= CLI_SUPPORT_REVISION {
            vec![util::text(&self.package.join("build").join(CLI_NAME)), "run-service".into()]
        } else {
            // Match older installed plists exactly so updates can verify ownership.
            vec![self.python(), "-E".into(), "-s".into(), "-B".into(), util::text(&self.package.join("scripts/native.py")),
                "--config".into(), util::text(&self.package.join("config.json")), "--launch-services".into(),
                "--recover-backend".into(), "--until-stopped".into(), "--service-log".into(), util::text(&self.log),
                "--service-state".into(), util::text(&self.state)]
        };
        json!({"Label": LABEL, "ProgramArguments": arguments,
            "WorkingDirectory": util::text(&self.package), "RunAtLoad": true, "KeepAlive": true,
            "LimitLoadToSessionType": "Aqua", "ThrottleInterval": 10, "ExitTimeOut": 120,
            "ProcessType": "Background", "Umask": 0o077,
            "StandardOutPath": util::text(&self.log), "StandardErrorPath": util::text(&self.log)})
    }

    pub fn previous_definitions(&self, manifest: &Object) -> Vec<Value> {
        let mut definitions = Vec::new();
        if manifest.get("support_revision").and_then(Value::as_f64).unwrap_or(0.0) < CLI_SUPPORT_REVISION as f64 {
            let mut legacy = self.definition(Some(manifest));
            legacy["ProgramArguments"].as_array_mut().unwrap().push(Value::from("--manage-usb"));
            definitions.push(legacy);
        }
        if truthy(manifest.get("previous_definition")) {
            definitions.push(manifest["previous_definition"].clone());
        }
        definitions
    }

    /// Check the manifest contract and every installed file's sha256.
    pub fn validate_package(&self) -> Result<Object> {
        let manifest = self.package.join("manifest.json");
        private_file(&manifest)?;
        let value = util::read_object(&manifest, "Invalid Mirra package manifest")?;
        let schema = value.get("schema_version");
        if !(util::equals_number(schema, 4) || util::equals_number(schema, PACKAGE_SCHEMA))
            || value.get("product").and_then(Value::as_str) != Some("Mirra")
            || value.get("package").and_then(Value::as_str) != Some(util::text(&self.package).as_str())
            || !value.get("files").is_some_and(Value::is_object) {
            return Err(Error::runtime("Invalid Mirra package manifest"));
        }
        let mut required: BTreeSet<String> = ["scripts/native.py", "config.json"].iter().map(|s| s.to_string()).collect();
        required.extend(ADAPTERS.iter().chain(HOST_TOOLS.iter()).map(|n| format!("build/{}", n)));
        required.extend([format!("python/{}", ENTRYPOINT), "python/manifest.json".into(), "python/licenses/LICENSE.cpython.txt".into()]);
        if util::equals_number(schema, PACKAGE_SCHEMA) {
            required.extend(["scripts/decoder.py", "scripts/decoder_route.py", "build/decoder-route.dylib"].map(String::from));
            let revision = match strict_int(value.get("support_revision")) {
                Some(r) if r >= 1 => r,
                _ => return Err(Error::runtime("Invalid Mirra support revision")),
            };
            if revision >= 20 {
                required.insert("scripts/startup.py".into());
            }
            if revision >= CLI_SUPPORT_REVISION {
                required.insert(format!("build/{}", CLI_NAME));
            }
            if revision >= BRIDGE_UPDATE_REVISION {
                required.extend(BRIDGE_UPDATE_FILES.map(String::from));
            }
        }
        let files = value["files"].as_object().unwrap();
        if !required.iter().all(|name| files.contains_key(name)) {
            return Err(Error::runtime("Native support package is missing required files"));
        }
        let root = mirra_core::paths::resolve(&self.package);
        for (name, digest) in files {
            let relative = Path::new(name);
            let path = self.package.join(relative);
            if !mirra_core::paths::resolve(&path).starts_with(&root)
                || relative.components().any(|c| c == Component::ParentDir) || relative.is_absolute() {
                return Err(Error::runtime("Package manifest contains an unexpected path"));
            }
            private_file(&path)?;
            let data = std::fs::read(&path).map_err(|e| mirra_core::Error::with_path(e, &path))?;
            let actual: String = Sha256::digest(&data).iter().map(|b| format!("{:02x}", b)).collect();
            if digest.as_str() != Some(actual.as_str()) {
                return Err(Error::runtime(format!("Installed support file changed: {}", name)));
            }
        }
        Ok(value)
    }

    fn read_plist(&self) -> Result<Value> {
        let data = std::fs::read(&self.plist).map_err(|e| mirra_core::Error::with_path(e, &self.plist))?;
        Ok(mirra_native::plist::loads(&data)?.to_json())
    }

    pub fn start(&self) -> Result<Object> {
        let manifest = self.validate_package()?;
        private_file(&self.plist)?;
        self.load_config()?;
        let current = self.read_plist()?;
        if current != self.definition(Some(&manifest)) {
            if self.previous_definitions(&manifest).contains(&current) {
                // Python resumes an upgrade interrupted between staging and
                // writing the plist with install(), which stays in Python.
                return Err(Error::Delegate("An interrupted support update must be finished by install".into()));
            }
            return Err(Error::runtime("Service plist no longer matches the installed package"));
        }
        if self.registration()?.is_empty() {
            let reply = self.command(&["bootstrap", &self.domain, &util::text(&self.plist)])?;
            if reply.code != 0 {
                return Err(Error::runtime(format!("Cannot start native support: {}", reply.stderr.trim())));
            }
        }
        self.status()
    }

    fn saved_birth(&self) -> Result<Value> {
        private_file(&self.state)?;
        let state = util::read_object(&self.state, "Invalid native support state")?;
        Ok(get(&state, "supervisor_birth")?.clone())
    }

    pub fn stop(&self) -> Result<Object> {
        let before = self.registration()?;
        let mut birth: Option<Value> = None;
        if let Some(pid) = before.get("pid").filter(|v| truthy(Some(v))) {
            let pid: i32 = pid.as_str().unwrap_or("").trim().parse()
                .map_err(|_| Error::value(format!("invalid literal for int() with base 10: {}", pid)))?;
            birth = (self.hooks.birth)(pid)?.as_ref().map(mirra_core::retention::birth_json);
        }
        if birth.is_none() && self.state.exists() {
            let saved = self.saved_birth()?;
            if util::alive(&self.hooks.birth, &saved)? {
                birth = Some(saved);
            }
        }
        if !before.is_empty() {
            if before.get("path").and_then(Value::as_str) == Some(util::text(&self.plist).as_str())
                || self.managed_app(None)?.is_none() {
                let reply = self.command(&["bootout", &self.target])?;
                if reply.code != 0 {
                    return Err(Error::runtime(format!("Cannot stop native support: {}", reply.stderr.trim())));
                }
            } else {
                self.background_action("unregister", None)?;
            }
        } else if self.managed_app(None)?.is_some() {
            self.background_action("unregister", None)?;
        }
        let deadline = Instant::now() + self.hooks.stop_timeout;
        if let Some(birth) = &birth {
            while util::alive(&self.hooks.birth, birth)? {
                if Instant::now() > deadline {
                    return Err(Error::runtime("Native support is still restoring; leave it running and inspect status"));
                }
                (self.hooks.sleep)(Duration::from_millis(200));
            }
        }
        // Inspect the installed controller's last report, not just job removal.
        let mut current = self.status()?;
        if !truthy(current.get("last_cleanup_verified")) {
            activity::operation("Service", "recover stopped support", Value::Null, || {
                let _lease = backend_lease(&self.home)?;
                self.recover_pending()
            })?;
            current = self.status()?;
        }
        if birth.is_some() && !truthy(current.get("last_cleanup_verified")) {
            return Err(Error::runtime("Service process ended but native cleanup is not verified; restart support to recover before removing it"));
        }
        Ok(current)
    }

    /// Restore a stopped installation before moving its journaled runtime.
    pub fn recover_pending(&self) -> Result<()> {
        let cache = self.home.join("Library/Caches/Mirra");
        let pending = ["launch.json", "sharing.json", "decoder-route.json"].iter().any(|n| cache.join(n).exists());
        let current = self.status()?;
        if !pending && (!truthy(current.get("run")) || truthy(current.get("last_cleanup_verified"))) {
            return Ok(());
        }
        if truthy(current.get("registered")) || truthy(current.get("supervisor_alive")) {
            return Err(Error::runtime("Stop native support before recovering its previous session"));
        }
        let sharingd = &self.hooks.sharingd;
        let runtime = self.package.join("runtime");
        if let Some(sharing) = sharingd.read_journal()? {
            let previous = PathBuf::from(get_str(&sharing, "directory")?);
            if !self.backend_directory(&previous) {
                return Err(Error::runtime("Pending sharingd recovery belongs to another installation; it was preserved"));
            }
            if !backend_children_stopped(Some(&previous), sharingd.as_ref(), &self.hooks.birth)? {
                return Err(Error::runtime("Previous backend children are still running; package update was deferred"));
            }
        }
        activity::operation("Service", "recover previous app launch support", Value::Null, || {
            (self.hooks.recover_launch)(&runtime)
        })?;
        if self.hooks.decoder_journal.exists() {
            activity::operation("Service", "recover previous decoder", Value::Null, || (self.hooks.acquire_decoder)())?;
        }
        // Cleanup could not be verified while stopping, so hand sharingd back
        // to Apple (a detached adapter included) to complete verification.
        let recovered = activity::operation("Service", "recover previous sharing support", Value::Null, || {
            sharingd.recover_abandoned(true)
        })?;
        if truthy(current.get("run")) {
            self.record_cleanup_recovery(&current, recovered)?;
        }
        Ok(())
    }

    fn backend_directory(&self, previous: &Path) -> bool {
        let runtime = self.package.join("runtime");
        let parent = previous.parent();
        parent.and_then(Path::parent) == Some(runtime.as_path())
            && parent.and_then(Path::file_name).and_then(|n| n.to_str()).is_some_and(|n| n.starts_with("native-"))
            && previous.file_name().and_then(|n| n.to_str()).is_some_and(|n| n.starts_with("backend-"))
    }

    /// Record fresh restoration proof without replacing the controller's failed report.
    pub fn record_cleanup_recovery(&self, current: &Object, recovered: Option<Value>) -> Result<()> {
        let run = self.package.join("runtime").join(get_str(current, "run")?);
        let path = run.join("result.json");
        if !path.exists() {
            return Ok(());
        }
        private_file(&path)?;
        let mut data = util::read_object(&path, "Invalid cleanup report")?;
        let birth = get(current, "supervisor_birth")?.clone();
        if data.get("supervisor_birth").unwrap_or(&birth) != &birth {
            return Err(Error::runtime("Stopped cleanup report belongs to another controller"));
        }
        let recovered = match recovered {
            Some(value) if !value.is_null() => value,
            _ => {
                let recovery = object(&data, "cleanup_recovery");
                if recovery.get("supervisor_birth") != Some(&birth) {
                    return Ok(());
                }
                match recovery.get("sharingd") {
                    None | Some(Value::Null) => return Ok(()),
                    Some(value) => value.clone(),
                }
            }
        };
        let restored = recovered.get("original_restored") == Some(&Value::Bool(true));
        if !restored || !sharingd::is_original(&self.hooks.sharingd.service()?) {
            return Err(Error::runtime("Original sharingd restoration is not verified"));
        }
        let previous = PathBuf::from(recovered.get("directory").and_then(Value::as_str)
            .ok_or_else(|| Error::key("directory"))?);
        if mirra_core::paths::resolve(&previous) != previous || !self.backend_directory(&previous) {
            return Err(Error::runtime("Pending sharingd recovery belongs to another installation; it was preserved"));
        }
        let mut directories = BTreeSet::from([previous]);
        if let Some(name) = object(&data, "backend_cleanup").get("directory").filter(|v| truthy(Some(v))) {
            let valid = name.as_str().filter(|n| Path::new(n).file_name().and_then(|f| f.to_str()) == Some(n) && n.starts_with("backend-"));
            let Some(name) = valid else {
                return Err(Error::runtime("Unexpected backend directory during stopped recovery"));
            };
            directories.insert(run.join(name));
        }
        let mut recovery = json!({"backend_cleanup_verified": false, "supervisor_birth": birth, "sharingd": recovered,
            "workspaces": [], "observed_at": util::local_isoformat()});
        data.insert("cleanup_recovery".into(), recovery.clone());
        // Keep restoration proof if a remaining child/lease defers workspace
        // cleanup: sharingd's journal has already been cleared at this point.
        write_state(&path, &Value::Object(data.clone()))?;
        for directory in &directories {
            if !backend_children_stopped(Some(directory), self.hooks.sharingd.as_ref(), &self.hooks.birth)? {
                return Err(Error::runtime("Previous backend children are still running; cleanup was deferred"));
            }
            let cleaned = workspace::cleanup(directory)?;
            if cleaned.get("reason").and_then(Value::as_str) == Some("lease_in_use") {
                return Err(Error::runtime("Previous broker workspace is still in use; cleanup was deferred"));
            }
            let mut entry = json!({"directory": util::text(directory)});
            if let Value::Object(fields) = cleaned {
                entry.as_object_mut().unwrap().extend(fields);
            }
            recovery["workspaces"].as_array_mut().unwrap().push(entry);
        }
        recovery["backend_cleanup_verified"] = Value::Bool(true);
        data.insert("cleanup_recovery".into(), recovery);
        write_state(&path, &Value::Object(data))?;
        Ok(())
    }

    pub fn status(&self) -> Result<Object> {
        let registration = self.registration()?;
        let mut value = Map::new();
        value.insert("installed".into(), Value::from(self.package.exists()));
        value.insert("login_enabled".into(), Value::from(self.plist.exists()));
        value.insert("registered".into(), Value::from(!registration.is_empty()));
        value.insert("registration".into(), Value::Object(registration));
        value.insert("native_launch_support_ready".into(), Value::from(false));
        value.insert("backend_ready".into(), Value::from(false));
        if !self.state.exists() {
            return Ok(value);
        }
        private_file(&self.state)?;
        let state = util::read_object(&self.state, "Invalid native support state")?;
        let birth = get(&state, "supervisor_birth")?.clone();
        let alive = util::alive(&self.hooks.birth, &birth)?;
        let phase = get(&state, "phase")?.clone();
        value.insert("supervisor_alive".into(), Value::from(alive));
        value.insert("supervisor_birth".into(), birth.clone());
        value.insert("phase".into(), phase.clone());
        if truthy(state.get("startup_failure")) {
            value.insert("startup_failure".into(), state["startup_failure"].clone());
        }
        let Some(directory) = state.get("directory") else {
            if !matches!(phase.as_str(), Some("startup_checks" | "waiting_for_mirroring_exit" | "startup_failed" | "stopped")) {
                return Err(Error::runtime("Unexpected native startup state"));
            }
            value.insert("last_cleanup_verified".into(),
                Value::from(!alive && truthy(state.get("startup_cleanup_verified"))));
            return Ok(value);
        };
        let directory = PathBuf::from(directory.as_str().ok_or_else(|| Error::type_error("directory must be a path"))?);
        let name = directory.file_name().and_then(|n| n.to_str()).unwrap_or("").to_string();
        if directory.parent() != Some(self.package.join("runtime").as_path()) || !name.starts_with("native-") {
            return Err(Error::runtime("Unexpected native support state directory"));
        }
        value.insert("run".into(), Value::from(name));
        if !alive {
            let result = directory.join("result.json");
            if result.exists() {
                let data = util::read_object(&result, "Invalid cleanup report")?;
                value.insert("last_cleanup_verified".into(), Value::from(cleanup_verified(&data, &birth)));
            }
            return Ok(value);
        }
        value.insert("native_launch_support_ready".into(), Value::from(phase.as_str() == Some("running")));
        if truthy(object(&state, "decoder_route").get("enabled")) {
            // Startup state cannot establish that a later decoder process has
            // loaded the hook. Use the supervisor's current observation.
            let path = directory.join("decoder-route.json");
            let ready = private_file(&path).and_then(|_| util::read_json(&path))
                .map(|decoder| decoder.get("ready") == Some(&Value::Bool(true)))
                .unwrap_or(false);
            if !ready {
                value.insert("native_launch_support_ready".into(), Value::from(false));
            }
        }
        let backend = directory.join("backend-status.json");
        if backend.exists() {
            let info = util::read_object(&backend, "Invalid backend state")?;
            let worker = info.get("worker_birth");
            let ready = truthy(info.get("ready")) && truthy(worker)
                && util::alive(&self.hooks.birth, worker.unwrap())?;
            value.insert("backend_phase".into(), get(&info, "phase")?.clone());
            value.insert("backend_attempt".into(), get(&info, "attempt")?.clone());
            value.insert("backend_ready".into(), Value::from(ready));
        }
        Ok(value)
    }
}

/// Whether a stopped controller's `result.json` proves complete cleanup.
fn cleanup_verified(data: &Object, birth: &Value) -> bool {
    let mut launch_clean = truthy(data.get("launch_agent_restored")) || data.get("launch_agent_attempted") == Some(&Value::Bool(false));
    if !data.contains_key("launch_agent_attempted") {
        // Builds 341/342 save only the selected decoder decision when
        // decoder.start() fails, before trying a launch agent. Accept that
        // old record only with verified AVC restoration.
        let decoder = object(data, "decoder_route");
        launch_clean = launch_clean || (decoder.get("enabled") == Some(&Value::Bool(true)) && !decoder.contains_key("ready")
            && !truthy(data.get("launch_agent"))
            && object(data, "decoder_cleanup").get("original_avc_restored") == Some(&Value::Bool(true)));
    }
    let recovery = object(data, "cleanup_recovery");
    let backend_clean = truthy(object(data, "backend_cleanup").get("cleanup_verified"))
        || (recovery.get("backend_cleanup_verified") == Some(&Value::Bool(true)) && recovery.get("supervisor_birth") == Some(birth));
    backend_clean && launch_clean && !truthy(data.get("launch_agent_restore_error"))
        && !truthy(data.get("app_cleanup_error")) && !truthy(data.get("decoder_restore_error"))
        && (!truthy(object(data, "decoder_route").get("enabled")) || truthy(object(data, "decoder_cleanup").get("cleanup_verified")))
}

impl SupportService for NativeService {
    fn package(&self) -> PathBuf {
        self.package.clone()
    }
    fn validate_package(&self) -> Result<Object> {
        NativeService::validate_package(self)
    }
    fn status(&self) -> Result<Object> {
        NativeService::status(self)
    }
    fn start(&self) -> Result<Object> {
        NativeService::start(self)
    }
    fn stop(&self) -> Result<Object> {
        NativeService::stop(self)
    }
    fn registration(&self) -> Result<Object> {
        NativeService::registration(self)
    }
}

#[cfg(test)]
mod tests;
