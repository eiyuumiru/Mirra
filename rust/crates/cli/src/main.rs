//! `mirra-cli`: the single executable of the Mirra background service.
//!
//! It is used by the app (`setup`, `control`, `diagnostics`, `logstream`) and
//! by the login service (`run-service`, launched by launchd from
//! `<package>/build/mirra-cli`). Former Python child scripts are hidden
//! subcommands of this same binary, started through
//! `mirra_service::cli::child_command`.
//!
//! | subcommand | entry |
//! |---|---|
//! | `--help` | usage on stdout, exit 0 |
//! | `setup ARGS`, `control ARGS` | `observe_main(["setup"/"control", ARGS])` |
//! | `diagnostics ARGS` | `diagnostics_main` |
//! | `logstream ARGS` | `logstream_main` |
//! | `run-service` (no arguments) | `native_main` in this process (keeps launchd's PID) |
//! | `__backend`, `__control` | `backend_main`, `control_main` |
//! | `__broker`, `__sharing` | `mirra_keystore::{broker_main, sharing_main}` |
//! | `__decoder-guardian` | `mirra_native::guardian_main` |
//!
//! Anything else prints `mirra-cli: USAGE` on stderr and exits 1.
use std::env;
use std::ffi::OsString;
use std::io::Write;
use std::path::{Path, PathBuf};

use mirra_service::cli::{BACKEND_SUBCOMMAND, BROKER_SUBCOMMAND, CONTROL_SUBCOMMAND, SHARING_SUBCOMMAND};

const USAGE: &str = "Usage: mirra-cli <setup|control|diagnostics|logstream|run-service> [arguments]";

/// `run-service`: the fixed session arguments of the installed package.
/// Both the app resources and the installed package use `build/mirra-cli`
/// next to `config.json`; the package lives in `<base>/current`.
fn service_arguments(executable: &Path) -> Result<Vec<String>, String> {
    let root = executable.parent().and_then(Path::parent).ok_or("Mirra support directory is missing")?;
    let base = root.parent().ok_or("Mirra installation directory is missing")?;
    let text = |path: PathBuf| path.to_string_lossy().into_owned();
    Ok(vec!["--config".into(), text(root.join("config.json")), "--launch-services".into(), "--recover-backend".into(),
        "--until-stopped".into(), "--service-log".into(), text(base.join("logs/service.log")), "--service-state".into(),
        text(base.join("service.json"))])
}

fn dispatch(arguments: Vec<OsString>) -> Result<i32, String> {
    let mut arguments = arguments.into_iter().map(|a| a.to_string_lossy().into_owned());
    let action = arguments.next();
    let rest: Vec<String> = arguments.collect();
    Ok(match action.as_deref() {
        Some("--help") => {
            println!("{}", USAGE);
            0
        }
        Some(helper @ ("setup" | "control")) => {
            let mut args = vec![helper.to_string()];
            args.extend(rest);
            mirra_service::observe_main(args)
        }
        Some("diagnostics") => mirra_service::diagnostics_main(rest),
        Some("logstream") => mirra_service::logstream_main(rest),
        Some("run-service") if rest.is_empty() => {
            let executable = env::current_exe().map_err(|e| e.to_string())?;
            mirra_service::native_main(service_arguments(&executable)?)
        }
        Some(BACKEND_SUBCOMMAND) => mirra_service::backend_main(rest),
        Some(CONTROL_SUBCOMMAND) => mirra_service::control_main(rest),
        Some(BROKER_SUBCOMMAND) => mirra_keystore::broker_main(rest),
        Some(SHARING_SUBCOMMAND) => mirra_keystore::sharing_main(rest),
        Some(mirra_native::GUARDIAN_SUBCOMMAND) => mirra_native::guardian_main(&rest),
        _ => return Err(USAGE.into()),
    })
}

fn main() {
    let code = match dispatch(env::args_os().skip(1).collect()) {
        Ok(code) => code,
        Err(message) => {
            eprintln!("mirra-cli: {}", message);
            1
        }
    };
    let _ = std::io::stdout().flush();
    std::process::exit(code);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_arguments_match_the_installed_layout() {
        let arguments = service_arguments(Path::new("/base/current/build/mirra-cli")).unwrap();
        assert_eq!(arguments, ["--config", "/base/current/config.json", "--launch-services", "--recover-backend",
            "--until-stopped", "--service-log", "/base/logs/service.log", "--service-state", "/base/service.json"]);
        assert!(service_arguments(Path::new("/mirra-cli")).is_err());
    }

    #[test]
    fn unknown_or_extended_actions_are_usage_errors() {
        for arguments in [vec![], vec!["bogus"], vec!["run-service", "--extra"], vec!["-h"]] {
            let arguments = arguments.into_iter().map(OsString::from).collect();
            assert_eq!(dispatch(arguments), Err(USAGE.to_string()));
        }
        assert_eq!(dispatch(vec!["--help".into()]), Ok(0));
    }
}
