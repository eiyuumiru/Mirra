//! Child-process construction and argparse-compatible argument errors.
//!
//! Python children (`broker.py`, `sharing.py`, `backend.py`, `control.py`)
//! become hidden subcommands of the same `mirra-cli` binary; the CLI maps
//! each `*_SUBCOMMAND` to the matching entry function. Setup and installation
//! remain Python and are started through [`python_command`].
use std::path::{Path, PathBuf};
use std::process::Command;

use mirra_core::config::default_root;

/// `mirra-cli __backend ...` → [`crate::backend::backend_main`]
pub const BACKEND_SUBCOMMAND: &str = "__backend";
/// `mirra-cli __broker ...` (broker.py; ported in mirra-keystore)
pub const BROKER_SUBCOMMAND: &str = "__broker";
/// `mirra-cli __sharing ...` (sharing.py; ported in mirra-keystore)
pub const SHARING_SUBCOMMAND: &str = "__sharing";
/// `mirra-cli __control ...` → [`crate::control::control_main`] (spawned by `observe_main`)
pub const CONTROL_SUBCOMMAND: &str = "__control";

/// Hidden subcommand of a former Python child script.
pub fn subcommand(name: &str) -> String {
    format!("__{}", name)
}

/// `<current exe> __<name>`: the one place child commands are built.
pub fn child_command(name: &str) -> Command {
    let mut command = Command::new(current_exe());
    command.arg(subcommand(name));
    command
}

pub fn current_exe() -> PathBuf {
    std::env::current_exe().unwrap_or_else(|_| PathBuf::from("mirra-cli"))
}

/// The bundled interpreter of the package containing this executable.
pub fn python(root: &Path) -> PathBuf {
    root.join("python/bin/python3")
}

/// `[python3, -E, -s, -B, <root>/scripts/<script>]` for code that stays in Python.
pub fn python_argv(root: &Path, script: &str) -> Vec<String> {
    vec![python(root).to_string_lossy().into_owned(), "-E".into(), "-s".into(), "-B".into(),
        root.join("scripts").join(script).to_string_lossy().into_owned()]
}

/// `Command` running `<root>/scripts/<script>` with the bundled interpreter.
pub fn python_command(script: &str) -> Command {
    let argv = python_argv(&default_root(), script);
    let mut command = Command::new(&argv[0]);
    command.args(&argv[1..]);
    command
}

/// Run a Python helper with inherited stdio; its exit status is returned.
pub fn run_python(script: &str, args: &[String]) -> i32 {
    match python_command(script).args(args).status() {
        Ok(status) => mirra_core::subprocess::return_code(status),
        Err(error) => {
            eprintln!("mirra-cli: {}", error);
            1
        }
    }
}

/// argparse usage error: message on stderr, exit status 2.
pub fn usage_error(prog: &str, usage: &str, message: &str) -> i32 {
    eprintln!("usage: {} {}\n{}: error: {}", prog, usage, prog, message);
    2
}

/// Split `--name=value` / `--name value` style options (argparse subset).
pub struct Options {
    pub items: Vec<String>,
    position: usize,
}

impl Options {
    pub fn new(args: &[String]) -> Self {
        Options { items: args.to_vec(), position: 0 }
    }
}

/// One parsed token.
pub enum Token {
    /// `--flag` or `--flag=value` (value inline).
    Flag(String, Option<String>),
    Positional(String),
}

impl Iterator for Options {
    type Item = Token;
    fn next(&mut self) -> Option<Token> {
        let item = self.items.get(self.position)?.clone();
        self.position += 1;
        if item.starts_with("--") && item.len() > 2 {
            return Some(match item.split_once('=') {
                Some((name, value)) => Token::Flag(name.to_string(), Some(value.to_string())),
                None => Token::Flag(item, None),
            });
        }
        if item == "-h" {
            return Some(Token::Flag("--help".into(), None));
        }
        Some(Token::Positional(item))
    }
}

impl Options {
    /// The value of an option taking an argument (`inline` or the next token).
    pub fn value(&mut self, name: &str, inline: Option<String>) -> Result<String, String> {
        if let Some(value) = inline {
            return Ok(value);
        }
        match self.items.get(self.position) {
            Some(value) if !value.starts_with("--") => {
                self.position += 1;
                Ok(value.clone())
            }
            _ => Err(format!("argument {}: expected one argument", name)),
        }
    }
}
