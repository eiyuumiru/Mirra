//! Run an app helper, retain its exact stdout, and record live stderr
//! (port of `scripts/observe.py`).
//!
//! `mirra-cli setup ...` and `mirra-cli control ...` both enter
//! [`observe_main`]. The helper runs as a child whose stdout is captured and
//! copied byte-for-byte to our stdout, while the command, its stderr and exit
//! are recorded in `logs/<helper>.log`:
//!
//! * `setup` stays Python: the child is
//!   `<root>/python/bin/python3 -E -s -B <root>/scripts/setup.py ARGS` and
//!   receives up to 16385 bytes read from our stdin, as before.
//! * `control install` stays Python: the child is `scripts/control.py install ...`.
//! * every other `control` action runs the Rust controller as the hidden
//!   subcommand `mirra-cli __control ARGS` ([`crate::control::control_main`]).
use std::io::{Read, Write};
use std::path::Path;

use mirra_core::activity::{self, FileLog};
use mirra_core::config::default_root;
use mirra_core::subprocess::RunOptions;

use crate::cli::{self, CONTROL_SUBCOMMAND};
use crate::control;

const USAGE: &str = "[-h] {setup,control} ...";

/// The child argv for `helper ARGS` (see the module documentation).
pub fn helper_command(helper: &str, arguments: &[String], root: &Path) -> Vec<String> {
    let python = helper == "setup"
        || matches!(control::parse_args_quiet(arguments), Some(parsed) if parsed.action == "install");
    let mut command = if python {
        cli::python_argv(root, &format!("{}.py", helper))
    } else {
        vec![cli::current_exe().to_string_lossy().into_owned(), CONTROL_SUBCOMMAND.to_string()]
    };
    command.extend(arguments.iter().cloned());
    command
}

/// `mirra-cli <setup|control> ARGS` → exit status of the helper.
pub fn observe_main(args: Vec<String>) -> i32 {
    let Some(helper) = args.first().cloned() else {
        return cli::usage_error("observe", USAGE, "the following arguments are required: helper, arguments");
    };
    if helper == "-h" || helper == "--help" {
        println!("usage: observe {}\n\nRun an app helper, retain its exact stdout, and record live stderr.", USAGE);
        return 0;
    }
    if helper != "setup" && helper != "control" {
        return cli::usage_error("observe", USAGE, &format!(
            "argument helper: invalid choice: {} (choose from 'setup', 'control')", mirra_core::pyfmt::repr_str(&helper)));
    }
    let arguments = &args[1..];
    let data = if helper == "setup" {
        let mut buffer = Vec::new();
        let _ = std::io::stdin().lock().take(16385).read_to_end(&mut buffer);
        Some(buffer)
    } else {
        None
    };
    let command = helper_command(&helper, arguments, &default_root());
    let base = crate::util::home().join("Library/Application Support/Mirra/logs");
    let log = FileLog::new(base).with_name(format!("{}.log", helper)).into_sink();
    let first = arguments.first().map(String::as_str);
    let log = if matches!(first, Some("status") | Some("devices")) { activity::poll_errors(log) } else { log };
    let source = format!("{}{} helper", helper[..1].to_uppercase(), &helper[1..]);
    let mut options = RunOptions::new().source(source).capture();
    if let Some(data) = data {
        options = options.input(data);
    }
    let result = activity::capture(Some(log), || activity::run(&command, &options));
    match result {
        Ok(completed) => {
            // Progress/stderr is in the log file; the existing JSON reply
            // channel is byte-identical to running the helper directly.
            let mut stdout = std::io::stdout().lock();
            let _ = stdout.write_all(&completed.stdout).and_then(|_| stdout.flush());
            completed.code
        }
        Err(error) => {
            eprintln!("{}", error);
            1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strings(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn setup_and_install_stay_python_other_control_actions_run_in_rust() {
        let root = Path::new("/pkg");
        assert_eq!(helper_command("setup", &strings(&["status", "--askpass", "/a"]), root),
            strings(&["/pkg/python/bin/python3", "-E", "-s", "-B", "/pkg/scripts/setup.py", "status", "--askpass", "/a"]));
        assert_eq!(helper_command("control", &strings(&["install", "--profile", "/p.json"]), root),
            strings(&["/pkg/python/bin/python3", "-E", "-s", "-B", "/pkg/scripts/control.py", "install", "--profile", "/p.json"]));
        assert_eq!(helper_command("control", &strings(&["--profile", "/p.json", "install"]), root)[4], "/pkg/scripts/control.py");
        let status = helper_command("control", &strings(&["status"]), root);
        assert_eq!(&status[1..], &strings(&[CONTROL_SUBCOMMAND, "status"])[..]);
        assert_eq!(status[0], cli::current_exe().to_string_lossy());
    }
}
