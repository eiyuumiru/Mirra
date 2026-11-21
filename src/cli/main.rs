use std::env;
use std::ffi::OsStr;
use std::io;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Command, ExitCode};

const USAGE: &str =
    "Usage: mirra-cli <setup|control|diagnostics|logstream|run-service> [arguments]";

fn run() -> io::Error {
    let mut arguments = env::args_os().skip(1);
    let action = arguments.next();
    let action = action.as_deref().and_then(OsStr::to_str);
    let executable = match env::current_exe() {
        Ok(executable) => executable,
        Err(error) => return error,
    };
    // Both the app resources and the installed package use build/mirra-cli
    // alongside scripts/ and python/.
    let Some(root) = executable.parent().and_then(Path::parent) else {
        return io::Error::new(
            io::ErrorKind::NotFound,
            "Mirra support directory is missing",
        );
    };

    let mut command = Command::new(root.join("python/bin/python3"));
    command.args(["-E", "-s", "-B"]);
    match action {
        Some(action @ ("setup" | "control")) => {
            command
                .arg(root.join("scripts/observe.py"))
                .arg(action)
                .args(arguments);
        }
        Some(action @ ("diagnostics" | "logstream")) => {
            command
                .arg(root.join("scripts").join(format!("{action}.py")))
                .args(arguments);
        }
        Some("run-service") if arguments.next().is_none() => {
            let Some(base) = root.parent() else {
                return io::Error::new(
                    io::ErrorKind::NotFound,
                    "Mirra installation directory is missing",
                );
            };
            command
                .arg(root.join("scripts/native.py"))
                .arg("--config")
                .arg(root.join("config.json"))
                .args(["--launch-services", "--recover-backend", "--until-stopped"])
                .arg("--service-log")
                .arg(base.join("logs/service.log"))
                .arg("--service-state")
                .arg(base.join("service.json"));
        }
        _ => return io::Error::new(io::ErrorKind::InvalidInput, USAGE),
    }
    // Keep launchd's PID and signal handling with the existing supervisor.
    command.exec()
}

fn main() -> ExitCode {
    if env::args_os().nth(1).as_deref() == Some(OsStr::new("--help")) {
        println!("{USAGE}");
        return ExitCode::SUCCESS;
    }
    let error = run();
    eprintln!("mirra-cli: {error}");
    ExitCode::FAILURE
}
