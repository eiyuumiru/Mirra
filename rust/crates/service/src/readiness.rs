//! Read-only, public-safe status for the support window and command line
//! (port of `scripts/readiness.py`).
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use mirra_bridge::bridgeclient::{self, BRIDGE_REVISION};
use mirra_core::activity::{self, utc_timestamp};
use mirra_core::config::{default_root, load_config, Config};
use mirra_core::processes::{Identity, NativeAppObserver};
use mirra_core::sys;
use mirra_native::launcher::{NativeLaunchAgent, AGENT};
use serde_json::{json, Map, Value};

use crate::error::{Error, Result};
use crate::installation::{needs_update, Object, SupportService};
use crate::util::{self, get, get_str, private_file, strict_int, truthy, BirthProbe};

/// `report(code, title, detail, actions=..., transport=...)`
pub fn report(code: &str, title: &str, detail: &str, actions: &[&str], transport: Option<&str>) -> Value {
    json!({"schema_version": 1, "observed_at": utc_timestamp(), "state": code, "title": title, "detail": detail,
        "actions": actions, "bridge_transport": transport, "mirroring_connection_verified": null})
}

/// `bridge_update_report(config, timeout=2)`: `None` unless the enrolled
/// bridge answers with an older revision. Unreachable bridges are `None`.
#[allow(clippy::result_large_err)]
pub fn bridge_update_report(config: &Config, timeout: Duration) -> Result<Option<Value>> {
    if !config.token_file.is_file() {
        return Ok(None);
    }
    let reply = bridgeclient::read_token(&config.token_file)
        .and_then(|token| bridgeclient::request_json(config, &token, "GET", "/v1/status", None, Some(timeout)));
    let (status, reply) = match reply {
        Ok(reply) => reply,
        Err(e) if e.is_os_error() => return Ok(None),
        Err(e) => return Err(e.into()),
    };
    let revision = if status == 200 { bridgeclient::bridge_revision(&reply) } else { None };
    Ok(update_report(config, revision))
}

fn update_report(config: &Config, revision: Option<i64>) -> Option<Value> {
    let revision = revision?;
    if revision >= BRIDGE_REVISION {
        return None;
    }
    let (detail, actions): (&str, &[&str]) = if bridgeclient::has_ssh_access(config) {
        ("Update Mirra Bridge on the iPhone through its saved SSH connection.", &["update_bridge", "refresh"])
    } else {
        ("Update the iPhone from a Mac with verified SSH access to this bridge, then check again here.", &["refresh", "guide"])
    };
    Some(report("bridge_update_available", "Bridge update available", detail, actions, Some(&config.transport)))
}

/// The native app observation readiness needs (`NativeAppObserver`).
pub trait AppObservation {
    fn poll(&mut self) -> Vec<i32>;
    fn last_errors(&self) -> Vec<String>;
    fn verified(&self, pid: i32) -> Option<Identity>;
    fn identity(&self, pid: i32) -> mirra_core::Result<Option<Identity>>;
}

impl AppObservation for NativeAppObserver {
    fn poll(&mut self) -> Vec<i32> {
        NativeAppObserver::poll(self)
    }
    fn last_errors(&self) -> Vec<String> {
        self.last_errors.clone()
    }
    fn verified(&self, pid: i32) -> Option<Identity> {
        self.verified.get(&pid).copied()
    }
    fn identity(&self, pid: i32) -> mirra_core::Result<Option<Identity>> {
        NativeAppObserver::identity(self, pid)
    }
}

pub type Health = Arc<dyn Fn(&Path, Duration) -> mirra_core::Result<Map<String, Value>> + Send + Sync>;
pub type LaunchState = Arc<dyn Fn(&Path) -> Result<Map<String, Value>> + Send + Sync>;
pub type AppFactory = Arc<dyn Fn(&Path, &Path) -> Box<dyn AppObservation> + Send + Sync>;
pub type UpdateCheck = Arc<dyn Fn(&Config, Duration) -> Result<Option<Value>> + Send + Sync>;

/// Live observations used by [`observe`] (tests replace them).
#[derive(Clone)]
pub struct Probes {
    pub birth: BirthProbe,
    pub health: Health,
    /// `NativeLaunchAgent(run, {}).state()`
    pub launch_state: LaunchState,
    /// `NativeAppObserver(executable, adapter)`
    pub apps: AppFactory,
    pub bridge_update: UpdateCheck,
    pub config_root: PathBuf,
}

impl Default for Probes {
    fn default() -> Self {
        Probes {
            birth: util::real_birth(),
            health: Arc::new(mirra_core::health::health),
            launch_state: Arc::new(|run| Ok(NativeLaunchAgent::new(run, Map::new(), None, None).state()?)),
            apps: Arc::new(|executable, adapter| {
                Box::new(NativeAppObserver::new(util::text(executable), util::text(adapter)))
            }),
            bridge_update: Arc::new(bridge_update_report),
            config_root: default_root(),
        }
    }
}

fn read_private(path: &Path) -> Result<Object> {
    private_file(path)?;
    util::read_object(path, "Invalid support state")
}

fn broker_socket(directory: &Path) -> Result<PathBuf> {
    let record = read_private(&directory.join("broker-workspace.json"))?;
    let path = PathBuf::from(get_str(&record, "path")?);
    let parent = path.parent().map(Path::to_path_buf).unwrap_or_default();
    if !util::equals_number(record.get("schema_version"), 1)
        || mirra_core::paths::resolve(&parent) != mirra_core::paths::resolve(Path::new("/tmp"))
        || !path.file_name().and_then(|n| n.to_str()).is_some_and(|n| n.starts_with("mirra-")) {
        return Err(Error::value("Unexpected broker workspace"));
    }
    let info = sys::lstat(&path).map_err(|e| mirra_core::Error::with_path(e, &path))?;
    if !sys::private_owned(&info, true) || strict_int(record.get("device")) != Some(info.st_dev as i64)
        || strict_int(record.get("inode")) != Some(info.st_ino as i64) {
        return Err(Error::value("Broker workspace changed"));
    }
    let endpoint = path.join("broker.sock");
    let info = sys::lstat(&endpoint).map_err(|e| mirra_core::Error::with_path(e, &endpoint))?;
    if !sys::is_sock(info.st_mode) || info.st_uid != sys::getuid() || info.st_mode & 0o077 != 0 {
        return Err(Error::value("Unexpected broker socket"));
    }
    Ok(endpoint)
}

fn mirroring_needs_relaunch(probes: &Probes, configuration: &Config, run: &Path, backend: &Object, children: &Object) -> Result<bool> {
    let attempt = match strict_int(backend.get("attempt")) {
        Some(attempt) if attempt >= 1 => attempt,
        _ => return Err(Error::value("Invalid backend attempt")),
    };
    if attempt == 1 {
        return Ok(false);
    }
    let birth = get(children, "sharingd")?;
    let parts: Option<Vec<i64>> = birth.as_array().filter(|items| items.len() == 4)
        .and_then(|items| items.iter().map(|v| strict_int(Some(v))).collect());
    let valid = parts.as_ref().is_some_and(|b| b[0] > 0 && b[1] == sys::getuid() as i64 && b[2] > 0 && (0..1_000_000).contains(&b[3]));
    if !valid || !util::alive(&probes.birth, birth)? {
        return Err(Error::value("Recovered sharingd changed during observation"));
    }
    let parts = parts.unwrap();
    let mut observer = (probes.apps)(&configuration.system_app.join("Contents/MacOS/iPhone Mirroring"), &run.join("sockets.dylib"));
    let pids = observer.poll();
    if !observer.last_errors().is_empty() {
        return Err(Error::runtime("Mirroring app observation did not finish"));
    }
    let mut stale = false;
    for pid in pids {
        let identity = observer.verified(pid).ok_or_else(|| Error::Key(pid.to_string()))?;
        if observer.identity(pid)? != Some(identity) {
            return Err(Error::runtime("Mirroring app changed during observation"));
        }
        stale = stale || (identity.1 as i64, identity.2 as i64) <= (parts[2], parts[3]);
    }
    if !util::alive(&probes.birth, birth)? {
        return Err(Error::value("Recovered sharingd changed during observation"));
    }
    Ok(stale)
}

/// `observe(service, timeout=2)` with the system probes.
pub fn observe(service: &dyn SupportService) -> Value {
    observe_with(service, &Probes::default(), Duration::from_secs(2))
}

/// Never starts/stops a service, repairs a file, or infers video from health.
///
/// The snapshot is rechecked after the live query. Missing observations and
/// changing generations remain unknown, so the UI cannot offer stale readiness.
/// Only selected fields leave this function; private paths, addresses, tokens,
/// identifiers, exception messages and notification contents are not included.
pub fn observe_with(service: &dyn SupportService, probes: &Probes, timeout: Duration) -> Value {
    if !service.package().exists() {
        return report("setup_required", "Set up your bridge",
            "Open Setup to connect to an existing Mirra Bridge or set up a new bridge iPhone.", &["setup"], None);
    }
    let manifest = match service.validate_package() {
        Ok(manifest) => manifest,
        Err(error) => {
            activity::emit("Status", "installation validation failed", "error",
                json!({"error_type": error.type_name(), "error": error.to_string()}));
            return report("installation_changed", "The support installation needs attention",
                "Some installed files are missing or changed. Keep the existing diagnostics and use the setup guide to repair the package.",
                &["guide", "refresh"], None);
        }
    };
    match observe_installed(service, probes, timeout, &manifest) {
        Ok(value) => value,
        Err(error) => {
            activity::emit("Status", "observation failed", "error",
                json!({"error_type": error.type_name(), "error": error.to_string()}));
            report("unknown", "Couldn’t confirm the current connection",
                "The check did not finish or support changed while being checked. Refresh in a moment. This check has not restarted support.",
                &["refresh", "guide"], None)
        }
    }
}

fn observe_installed(service: &dyn SupportService, probes: &Probes, timeout: Duration, manifest: &Object) -> Result<Value> {
    let package = service.package();
    let configuration = load_config(Some(&package.join("config.json")), &probes.config_root)?;
    let transport = Some(configuration.transport.as_str());
    let t = transport;
    if needs_update(manifest)? {
        return Ok(report("update_available", "Update Mirra support",
            "Choose Update and connect to install this version’s support using your saved bridge setup.", &["install", "guide"], t));
    }
    let update = (probes.bridge_update)(&configuration, timeout)?;
    let before = service.status()?;
    if let Some(mut update) = update.clone() {
        if !truthy(before.get("backend_ready")) {
            if truthy(before.get("registered")) {
                update["actions"].as_array_mut().unwrap().push(Value::from("stop"));
            }
            return Ok(update);
        }
    }
    if !truthy(before.get("registered")) {
        if truthy(before.get("supervisor_alive")) {
            return Ok(report("stopping", "Finishing shutdown",
                "Support is still closing its previous session. Wait before starting it again.", &["refresh"], t));
        }
        let enabled = truthy(before.get("login_enabled"));
        return Ok(report("stopped", "Support is stopped",
            if enabled { "Start support, then open Apple’s iPhone Mirroring." } else { "Enable support at login to use your saved bridge setup." },
            &[if enabled { "start" } else { "install" }, "setup", "guide"], t));
    }
    if truthy(before.get("startup_failure")) {
        let code = before["startup_failure"].as_str().unwrap_or("");
        let (title, detail) = match code {
            "container_access_denied" => ("Allow access to Mirroring support",
                "macOS denied access to iPhone Mirroring’s temporary folder. Go back to Settings, stop support, then start it and choose Allow in the macOS prompt."),
            "container_missing" => ("Open iPhone Mirroring once",
                "Apple’s iPhone Mirroring has not created its temporary folder. Open the app once and quit it, then go back to Settings and stop and start support."),
            "support_access_denied" => ("Support needs file access",
                "macOS denied a file operation during startup. Check the service log, then go back to Settings and stop and start support when you are ready to retry."),
            "startup_interrupted" => ("Support startup was interrupted",
                "The previous startup ended unexpectedly. Automatic retries are paused. Check the service log, then go back to Settings and stop and start support."),
            _ => ("Support could not start",
                "Automatic retries are paused after a support failure. Check the service log for the reason, then go back to Settings and stop and start support."),
        };
        return Ok(report("startup_failed", title, detail, &["stop", "refresh", "guide"], t));
    }
    if truthy(before.get("supervisor_alive")) && before.get("phase").and_then(Value::as_str) == Some("waiting_for_mirroring_exit") {
        return Ok(report("waiting_for_mirroring_exit", "Quit iPhone Mirroring",
            "Quit Apple’s iPhone Mirroring with Command-Q. Support will continue automatically; wait until Mirra is ready before opening it again.",
            &["refresh", "stop"], t));
    }
    if !truthy(before.get("supervisor_alive")) || !truthy(before.get("native_launch_support_ready")) {
        return Ok(report("starting", "Preparing app support",
            "The background service is starting or restoring its previous session. Check again shortly.", &["refresh", "stop"], t));
    }
    let run = package.join("runtime").join(get_str(&before, "run")?);
    let backend = read_private(&run.join("backend-status.json"))?;
    if !truthy(before.get("backend_ready")) {
        let issue = backend.get("certificate_issue").and_then(Value::as_str);
        match issue {
            Some("renewing") => return Ok(report("renewing_certificate", "Renewing bridge certificate",
                "Mirra is requesting a current certificate from your bridge.", &["refresh", "stop"], t)),
            Some("expired") => return Ok(report("bridge_certificate_expired", "Bridge certificate expired",
                "Keep the bridge iPhone online. Mirra will retry automatically, or you can request another renewal now.",
                &["renew", "refresh", "stop"], t)),
            Some(code @ ("clock" | "invalid" | "unavailable")) => {
                let detail = if code == "clock" { "Check the date and time on the Mac and bridge iPhone." }
                    else { "Mirra could not read a valid certificate from the bridge." };
                return Ok(report("bridge_certificate_unavailable", "Couldn’t validate the bridge certificate", detail,
                    &["refresh", "stop", "guide"], t));
            }
            _ => {}
        }
        let phase = backend.get("phase").and_then(Value::as_str);
        if matches!(phase, Some("failed" | "stopped")) || !truthy(backend.get("automatic_recovery")) {
            return Ok(report("needs_attention", "Background support needs attention",
                "Automatic reconnection is not running. Check the bridge connection, then stop and start support.",
                &["refresh", "stop", "guide"], t));
        }
        let cleanup = matches!(phase, Some("waiting_for_cleanup" | "restoring" | "stopping_worker"));
        let detail = if cleanup {
            "Support is finishing cleanup before reconnecting. Check again shortly."
        } else if configuration.transport == "ssh" {
            "Keep the bridge reachable on Wi-Fi with its jailbreak active. Support will retry automatically."
        } else {
            "Connect the selected bridge by USB and keep its jailbreak active. Support will retry automatically."
        };
        return Ok(report(if cleanup { "restoring" } else { "waiting_for_bridge" },
            if cleanup { "Restoring the previous connection" } else { "Waiting for the bridge" }, detail,
            &["refresh", "stop", "guide"], t));
    }
    let name = match backend.get("directory") {
        None => "",
        Some(Value::String(name)) => name.as_str(),
        Some(_) => return Err(Error::value("Unexpected backend directory")),
    };
    if !name.starts_with("backend-") || Path::new(name).file_name().and_then(|n| n.to_str()) != Some(name) {
        return Err(Error::value("Unexpected backend directory"));
    }
    let directory = run.join(name);
    let children = read_private(&directory.join("backend-children.json"))?;
    let birth = get(&children, "broker")?.clone();
    if !util::alive(&probes.birth, &birth)? {
        return Err(Error::value("Broker changed during observation"));
    }
    let endpoint = broker_socket(&directory)?;
    let response = (probes.health)(&endpoint, timeout)?;
    let launch = (probes.launch_state)(&run)?;
    let ready = response.get("ready");
    let relaunch = ready == Some(&Value::Bool(true))
        && mirroring_needs_relaunch(probes, &configuration, &run, &backend, &children)?;
    let after = service.status()?;
    let current = read_private(&run.join("backend-status.json"))?;
    if before != after || backend != current || !util::alive(&probes.birth, &birth)? || !truthy(after.get("backend_ready")) {
        return Err(Error::value("Support changed during observation"));
    }
    let launch_pid = launch.get("pid").filter(|v| truthy(Some(v)));
    let launch_ready = launch.get("path").and_then(Value::as_str) == Some(util::text(&run.join("native-launch-agent.plist")).as_str())
        && launch.get("program").and_then(Value::as_str) == Some(AGENT)
        && launch.get("injected") == Some(&Value::Bool(true))
        && match launch_pid {
            None => false,
            Some(pid) => {
                let text = match pid { Value::String(s) => s.trim().to_string(), other => other.to_string() };
                let pid: i32 = text.parse().map_err(|_| Error::value(format!("invalid literal for int() with base 10: '{}'", text)))?;
                (probes.birth)(pid)?.is_some()
            }
        };
    if !launch_ready {
        return Ok(report("launch_support_unavailable", "App launch support is unavailable",
            "The bridge answered, but normal app startup is not confirmed. Check again; if this persists, stop and start support after closing Mirroring.",
            &["refresh", "stop", "guide"], t));
    }
    if ready == Some(&Value::Bool(false)) {
        return Ok(report("recovering", "The bridge connection needs recovery",
            "The bridge reported a failure. Background support is monitoring it and will reconnect after cleanup. Check again shortly.",
            &["refresh", "stop", "guide"], t));
    }
    if ready != Some(&Value::Bool(true)) {
        return Err(Error::value("Unknown broker health"));
    }
    if relaunch {
        return Ok(report("waiting_for_mirroring_exit", "Quit iPhone Mirroring",
            "Support has reconnected. Quit Apple’s iPhone Mirroring with Command-Q to close the previous session, then refresh Mirra and choose Connect to start a fresh one.",
            &["refresh", "stop"], t));
    }
    let mut ready = report("ready", "Bridge is ready",
        "Choose Connect to find your iPhone in Apple’s iPhone Mirroring. Keep it locked and nearby, with Wi-Fi and Bluetooth on. The bridge is available; the iPhone connection is not yet confirmed.",
        &["open_mirroring", "refresh", "stop"], t);
    if let Some(update) = update {
        ready["bridge_update_detail"] = update["detail"].clone();
        if update["actions"].as_array().is_some_and(|a| a.contains(&Value::from("update_bridge"))) {
            ready["actions"].as_array_mut().unwrap().push(Value::from("update_bridge"));
        }
    }
    Ok(ready)
}

#[cfg(test)]
mod tests;
