//! Read the host ABI probe shared with the media adapter before starting
//! support (port of `scripts/compatibility.py`).
use std::path::Path;
use std::sync::LazyLock;
use std::time::Duration;

use mirra_core::subprocess::{self, Completed, RunOptions};
use mirra_core::{Error, Result};
use regex::Regex;
use serde_json::Value;

use crate::plist::Plist;
use crate::util;

/// Accept Apple's 1.x app family (from `Contents/Info.plist`); framework
/// contracts are checked separately.
pub fn supported_apple_app(info: &Plist) -> bool {
    static VERSION: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^1(?:\.\d+){1,2}$").unwrap());
    static BUILD: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\d+(?:\.\d+)*$").unwrap());
    if !info.is_dict() {
        return false;
    }
    info.get("CFBundleIdentifier").and_then(Plist::as_str) == Some("com.apple.ScreenContinuity")
        && info.get("CFBundleShortVersionString").and_then(Plist::as_str).is_some_and(|v| VERSION.is_match(v))
        && info.get("CFBundleVersion").and_then(Plist::as_str).is_some_and(|b| BUILD.is_match(b))
}

/// Runs the probe (`[tool]`, 15 s timeout).
pub type ProbeRunner<'a> = &'a dyn Fn(&[String], Duration) -> Result<Completed>;

/// Run `<root>/build/inspector` and validate its report.
pub fn inspect_media_profile(root: &Path) -> Result<Value> {
    inspect_media_profile_with(root, &|command, timeout| subprocess::run(command, &RunOptions::new().capture().timeout(timeout)))
}

pub fn inspect_media_profile_with(root: &Path, run: ProbeRunner) -> Result<Value> {
    let tool = root.join("build/inspector");
    if !tool.is_file() {
        return Err(Error::runtime("Build the media profile checker first: make build"));
    }
    let reply = run(&[util::text(&tool)], Duration::from_secs(15))?;
    if reply.code != 0 && reply.code != 1 {
        return Err(Error::runtime("Media profile checker failed; run build/inspector for diagnostics"));
    }
    let report: Value = serde_json::from_str(&reply.stdout_text())
        .map_err(|_| Error::runtime("Media profile checker returned invalid JSON"))?;
    let compatible = report.get("compatible").and_then(Value::as_bool);
    if !report.is_object() || !util::eq_int(report.get("schema_version"), 1)
        || report.get("profile").and_then(Value::as_str) != Some("awdl-single-tile")
        || compatible != Some(reply.code == 0) {
        return Err(Error::runtime("Media profile checker returned inconsistent compatibility data"));
    }
    Ok(report)
}

/// [`inspect_media_profile`], refusing an incompatible host.
pub fn require_media_profile(root: &Path) -> Result<Value> {
    require_media_profile_with(root, &|command, timeout| subprocess::run(command, &RunOptions::new().capture().timeout(timeout)))
}

pub fn require_media_profile_with(root: &Path, run: ProbeRunner) -> Result<Value> {
    let report = inspect_media_profile_with(root, run)?;
    if report["compatible"] != Value::Bool(true) {
        return Err(Error::runtime(format!("Media profile is unsupported on this host ({}, {}). Mirra requires Intel macOS 15 or later \
            with matching private framework interfaces. Inspect build/inspector for the failed checks.",
            util::py_str(report.get("architecture")), util::py_str(report.get("os_build")))));
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn reply(compatible: bool, code: i32) -> Result<Completed> {
        let body = json!({"schema_version": 1, "profile": "awdl-single-tile", "compatible": compatible,
            "architecture": "x86_64", "os_build": "unreviewed", "reference_build": "25G332"});
        Ok(Completed { args: vec![], code, stdout: body.to_string().into_bytes(), stderr: vec![] })
    }

    fn root() -> tempfile::TempDir {
        let temp = tempfile::tempdir().unwrap();
        std::fs::create_dir(temp.path().join("build")).unwrap();
        std::fs::write(temp.path().join("build/inspector"), "").unwrap();
        temp
    }

    #[test]
    fn incompatible_host_is_reportable_but_cannot_start_support() {
        let temp = root();
        let run = |_: &[String], timeout: Duration| { assert_eq!(timeout, Duration::from_secs(15)); reply(false, 1) };
        assert_eq!(inspect_media_profile_with(temp.path(), &run).unwrap()["compatible"], false);
        let error = require_media_profile_with(temp.path(), &run).unwrap_err().to_string();
        assert!(error.contains("unsupported on this host (x86_64, unreviewed)"), "{}", error);
    }

    #[test]
    fn inconsistent_and_failed_probe_are_rejected() {
        let temp = root();
        let replies: Vec<Box<dyn Fn() -> Result<Completed>>> = vec![
            Box::new(|| reply(true, 1)), Box::new(|| reply(false, 0)),
            Box::new(|| Ok(Completed { args: vec![], code: 0, stdout: b"{}".to_vec(), stderr: vec![] })),
            Box::new(|| Ok(Completed { args: vec![], code: -11, stdout: vec![], stderr: b"crash".to_vec() })),
        ];
        for make in replies {
            let run = |_: &[String], _: Duration| make();
            assert!(matches!(require_media_profile_with(temp.path(), &run), Err(Error::Runtime(_))));
        }
        let run = |_: &[String], _: Duration| reply(true, 0);
        assert_eq!(require_media_profile_with(temp.path(), &run).unwrap()["compatible"], true);
    }

    #[test]
    fn missing_probe_has_an_actionable_build_error() {
        let temp = root();
        let run = |_: &[String], _: Duration| -> Result<Completed> { panic!("must not run") };
        assert!(require_media_profile_with(&temp.path().join("absent"), &run).unwrap_err().to_string().contains("make build"));
    }

    fn info(identifier: Option<Plist>, version: Option<Plist>, build: Option<Plist>) -> Plist {
        let mut value = Plist::dict();
        for (key, item) in [("CFBundleIdentifier", identifier), ("CFBundleShortVersionString", version), ("CFBundleVersion", build)] {
            if let Some(item) = item {
                value.insert(key, item);
            }
        }
        value
    }

    fn s(text: &str) -> Option<Plist> {
        Some(Plist::String(text.into()))
    }

    #[test]
    fn app_identity_check() {
        for (version, build) in [("1.0", "1"), ("1.3", "40.2"), ("1.6", "98.5")] {
            assert!(supported_apple_app(&info(s("com.apple.ScreenContinuity"), s(version), s(build))));
        }
        let id = s("com.apple.ScreenContinuity");
        for value in [info(s("other.app"), s("1.6"), s("98.5")), info(None, s("1.6"), s("98.5")),
                      info(id.clone(), s("2.0"), s("98.5")), info(id.clone(), Some(Plist::Integer(1)), s("98.5")),
                      info(id.clone(), s("1.6"), s("")), info(id.clone(), s("1.6"), None), Plist::Array(vec![])] {
            assert!(!supported_apple_app(&value));
        }
    }
}
