//! Explicit support-window actions (port of `scripts/control.py`).
//!
//! `status`, `start`, `stop`, `preflight`, `renew` and `reset` ([`crate::reset`]) run here and print the
//! same one-line `json.dumps` reply with the same exit codes (0 when `ok`).
//!
//! Routing to Python: `control install` (with or without `--profile`) stays
//! in Python because it prepares/installs/updates the package.
//! [`control_dispatch`] returns [`ControlDispatch::DelegateToPython`] for it
//! without logging or printing anything, and also when a Rust action reaches
//! work that is still Python-only ([`Error::Delegate`]: `start` resuming an
//! interrupted install). sharingd recovery during `stop` runs in Rust. The
//! delegation happens before any reply is printed, so stdout carries exactly
//! one reply. [`control_main`] performs the delegation itself by running
//! `<root>/python/bin/python3 -E -s -B <root>/scripts/control.py ARGS` with
//! inherited stdio, so the CLI can route every `control` invocation (or the
//! hidden `__control` used by `observe_main`) to `control_main` unchanged.
use std::path::Path;
use std::time::Duration;

use mirra_bridge::certificates::current_certificate;
use mirra_core::activity::{self, FileLog};
use mirra_core::config::{load_config, Config};
use serde_json::{json, Value};

use crate::cli::{self, Options, Token};
use crate::error::{Error, Result};
use crate::installation::{NativeService, SupportService, CERTIFICATE_LOCK_REVISION};
use crate::preflight;
use crate::readiness::{self, Probes};
use crate::reset;
use crate::util;

pub const ACTIONS: [&str; 7] = ["status", "start", "stop", "install", "preflight", "renew", "reset"];
const USAGE: &str = "[-h] [--profile PROFILE] {status,start,stop,install,preflight,renew,reset}";
const FAILURE: &str = "The action could not finish. Refresh status before trying again. If the problem persists, use the setup guide and keep the existing diagnostics.";

#[derive(Debug, PartialEq, Eq)]
pub enum ControlDispatch {
    /// The reply was printed; exit with this status.
    Exit(i32),
    /// Run `scripts/control.py` with these arguments (unchanged argv).
    DelegateToPython(Vec<String>),
}

/// Parsed `control` arguments.
#[derive(Debug, PartialEq, Eq)]
pub struct ControlArgs {
    pub action: String,
    pub profile: Option<String>,
}

/// argparse equivalent; `Err(status)` after printing usage/help.
pub fn parse_args(args: &[String]) -> std::result::Result<ControlArgs, i32> {
    let mut options = Options::new(args);
    let mut action = None;
    let mut profile = None;
    while let Some(token) = options.next() {
        match token {
            Token::Flag(name, inline) if name == "--help" && inline.is_none() => {
                println!("usage: control {}\n\nExplicit support-window actions using the existing service controller.", USAGE);
                return Err(0);
            }
            Token::Flag(name, inline) if name == "--profile" => match options.value("--profile", inline) {
                Ok(value) => profile = Some(value),
                Err(message) => return Err(cli::usage_error("control", USAGE, &message)),
            },
            Token::Flag(name, inline) => {
                let text = inline.map_or(name.clone(), |v| format!("{}={}", name, v));
                return Err(cli::usage_error("control", USAGE, &format!("unrecognized arguments: {}", text)));
            }
            Token::Positional(value) if action.is_none() => {
                if !ACTIONS.contains(&value.as_str()) {
                    return Err(cli::usage_error("control", USAGE, &format!(
                        "argument action: invalid choice: {} (choose from {})", mirra_core::pyfmt::repr_str(&value),
                        ACTIONS.map(mirra_core::pyfmt::repr_str).join(", "))));
                }
                action = Some(value);
            }
            Token::Positional(value) => {
                return Err(cli::usage_error("control", USAGE, &format!("unrecognized arguments: {}", value)));
            }
        }
    }
    let Some(action) = action else {
        return Err(cli::usage_error("control", USAGE, "the following arguments are required: action"));
    };
    if profile.is_some() && action != "install" {
        return Err(cli::usage_error("control", USAGE, "A profile can only be selected for installation"));
    }
    Ok(ControlArgs { action, profile })
}

/// The action and profile of a command line without reporting errors
/// (`None` when argparse would reject it).
pub fn parse_args_quiet(args: &[String]) -> Option<ControlArgs> {
    let mut options = Options::new(args);
    let (mut action, mut profile) = (None, None);
    while let Some(token) = options.next() {
        match token {
            Token::Flag(name, inline) if name == "--profile" => profile = Some(options.value("--profile", inline).ok()?),
            Token::Positional(value) if action.is_none() && ACTIONS.contains(&value.as_str()) => action = Some(value),
            _ => return None,
        }
    }
    Some(ControlArgs { action: action?, profile })
}

/// What `control` needs from the system (tests substitute fakes).
pub trait ControlEnv {
    fn service(&self) -> &dyn SupportService;
    /// `readiness.observe(service)`
    fn observe(&self) -> Value;
    fn load_config(&self, path: &Path) -> Result<Config>;
    /// `readiness.bridge_update_report(config)` (2 s timeout)
    fn bridge_update_report(&self, config: &Config) -> Result<Option<Value>>;
    /// `current_certificate(config, state, on_renewal, force=True)`
    #[allow(clippy::result_large_err)]
    fn renew(&self, config: &Config, state: &Path) -> std::result::Result<(), mirra_bridge::Error>;
    /// Reset: give sharingd back to Apple.
    fn restore_sharingd(&self) -> Result<()>;
    /// Reset: the bridge forgets this Mac.
    fn forget_bridge(&self, config: &Config) -> Result<()>;
    /// Reset: remove the keychain key, backups and AutoUnlock entries.
    fn forget_local_pairing(&self) -> Result<Value>;
}

/// The installed service and live probes.
#[derive(Default)]
pub struct SystemControl {
    pub service: NativeService,
    pub probes: Probes,
}

impl ControlEnv for SystemControl {
    fn service(&self) -> &dyn SupportService {
        &self.service
    }
    fn observe(&self) -> Value {
        readiness::observe_with(&self.service, &self.probes, Duration::from_secs(2))
    }
    fn load_config(&self, path: &Path) -> Result<Config> {
        Ok(load_config(Some(path), &self.probes.config_root)?)
    }
    fn bridge_update_report(&self, config: &Config) -> Result<Option<Value>> {
        (self.probes.bridge_update)(config, Duration::from_secs(2))
    }
    #[allow(clippy::result_large_err)]
    fn renew(&self, config: &Config, state: &Path) -> std::result::Result<(), mirra_bridge::Error> {
        current_certificate(config, state, &mut || activity::info("Certificate", "manual renewal requested"), true).map(|_| ())
    }
    fn restore_sharingd(&self) -> Result<()> {
        reset::restore_sharingd()
    }
    fn forget_bridge(&self, config: &Config) -> Result<()> {
        reset::forget_bridge(config)
    }
    fn forget_local_pairing(&self) -> Result<Value> {
        reset::forget_local_pairing(&util::home())
    }
}

/// `renew_certificate(service)`
pub fn renew_certificate(env: &dyn ControlEnv) -> Result<Value> {
    let service = env.service();
    let manifest = service.validate_package()?;
    let revision = manifest.get("support_revision").map_or(Ok(0.0), |v| util::number(v, "support_revision"))?;
    if revision < CERTIFICATE_LOCK_REVISION as f64 {
        return Ok(json!({"ok": false, "message": "Update Mirra support before requesting renewal.", "report": env.observe()}));
    }
    let package = service.package();
    let config = env.load_config(&package.join("config.json"))?;
    if let Some(update) = env.bridge_update_report(&config)? {
        return Ok(json!({"ok": false, "message": update["detail"], "report": update}));
    }
    match env.renew(&config, &package.join("runtime").join("certificate-renewal.json")) {
        Ok(()) => {}
        Err(mirra_bridge::Error::Certificate(error)) => {
            return Ok(json!({"ok": false, "message": error.to_string(), "report": env.observe()}));
        }
        Err(error) => return Err(error.into()),
    }
    let report = env.observe();
    let detail = if report["state"] == "ready" { "Background support is ready." }
        else { "Mirra will use it the next time background support connects." };
    Ok(json!({"ok": true, "message": format!("A valid bridge certificate is available. {}", detail), "report": report}))
}

fn act(action: &str, env: &dyn ControlEnv) -> Result<Value> {
    match action {
        "preflight" => {
            let checked = preflight::check(&|| env.observe());
            Ok(json!({"ok": true, "report": checked["report"], "preflight": checked}))
        }
        "renew" => renew_certificate(env),
        "reset" => reset::reset_mirroring(env),
        "start" | "stop" => {
            if action == "start" { env.service().start()?; } else { env.service().stop()?; }
            Ok(json!({"ok": true, "report": env.observe()}))
        }
        "status" => Ok(json!({"ok": true, "report": env.observe()})),
        _ => Err(Error::Delegate(format!("{} is handled by the Python controller", action))),
    }
}

/// `control()`: one reply on stdout (via `write`), activity records for the
/// request and reply. Python-only work is returned as a delegation before
/// anything is written.
pub fn control(args: &ControlArgs, env: &dyn ControlEnv, write: &mut dyn FnMut(&Value)) -> ControlDispatch {
    if args.action == "install" {
        return delegate(args);
    }
    activity::emit("Service", "request", "info", json!({"action": args.action}));
    let value = match act(&args.action, env) {
        Ok(value) => value,
        Err(error) if error.is_delegate() => return delegate(args),
        // Exception messages can contain private paths/account information.
        // The separate CLI remains available for owner-local detailed diagnosis.
        Err(_) => json!({"ok": false, "message": FAILURE, "report": env.observe()}),
    };
    write(&value);
    activity::emit("Service", "reply", "info", json!({"result": value}));
    ControlDispatch::Exit(if value["ok"] == Value::Bool(true) { 0 } else { 1 })
}

fn delegate(args: &ControlArgs) -> ControlDispatch {
    let mut argv = vec![args.action.clone()];
    if let Some(profile) = &args.profile {
        argv.extend(["--profile".to_string(), profile.clone()]);
    }
    ControlDispatch::DelegateToPython(argv)
}

/// Parse, log to `~/Library/Application Support/Mirra/logs/control.log`
/// (errors/stderr only for `status`) and run one action against `env`.
pub fn control_dispatch(args: &[String], env: &dyn ControlEnv, home: &Path) -> ControlDispatch {
    let parsed = match parse_args(args) {
        Ok(parsed) => parsed,
        Err(code) => return ControlDispatch::Exit(code),
    };
    if parsed.action == "install" {
        return delegate(&parsed);
    }
    let log = FileLog::new(home.join("Library/Application Support/Mirra/logs")).with_name("control.log").into_sink();
    let log = if args.first().map(String::as_str) == Some("status") { activity::poll_errors(log) } else { log };
    activity::capture(Some(log), || control(&parsed, env, &mut util::print_json))
}

/// `mirra-cli control ARGS` (and the hidden `__control`): returns the exit status.
pub fn control_main(args: Vec<String>) -> i32 {
    let env = SystemControl::default();
    match control_dispatch(&args, &env, &util::home()) {
        ControlDispatch::Exit(code) => code,
        ControlDispatch::DelegateToPython(argv) => cli::run_python("control.py", &argv),
    }
}

#[cfg(test)]
mod tests;
