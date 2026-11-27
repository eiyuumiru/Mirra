//! Launch native helpers from the bridge's actual filesystem namespace
//! (port of `scripts/bridgepaths.py`).
use std::collections::BTreeSet;

use mirra_core::{Error, Result};

pub const ROOTHIDE_CODE_ROOT: &str = "/usr/local/libexec/Mirra";
pub const ROOTLESS_DEPLOYMENT_ROOT: &str = "/var/jb/var/mobile/MirraCache";
pub const ROOTHIDE_ENTITLEMENTS: [&str; 4] = [
    "platform-application",
    "com.apple.private.security.no-sandbox",
    "com.apple.private.security.storage.AppBundles",
    "com.apple.private.security.storage.AppDataContainers",
];

/// RootHide's bootstrap tools use a virtual root. Verify the documented path
/// converters rather than guessing a randomized jailbreak directory.
pub const ENVIRONMENT_SCRIPT: &str = r#"
mirra_environment_error() {
    printf '%s\n' '{"error":"roothide_path_translation_unavailable"}'
    exit 1
}
if command -v jbroot >/dev/null 2>&1 || command -v rootfs >/dev/null 2>&1; then
    command -v jbroot >/dev/null 2>&1 && command -v rootfs >/dev/null 2>&1 || mirra_environment_error
    mirra_bootstrap=$(jbroot /) || mirra_environment_error
    mirra_rootfs=$(rootfs /) || mirra_environment_error
    case "$mirra_bootstrap" in
        /) mirra_environment_error ;;
        /*) ;;
        *) mirra_environment_error ;;
    esac
    case "$mirra_rootfs" in
        /rootfs|/rootfs/) printf '%s\n' '{"path_mode":"roothide","path_translation_verified":true}' ;;
        *) mirra_environment_error ;;
    esac
elif test -d /var/jb/usr/bin; then
    printf '%s\n' '{"path_mode":"native","path_translation_verified":false,"rootless":true}'
else
    printf '%s\n' '{"path_mode":"native","path_translation_verified":false}'
fi
"#;

const ROOTHIDE_PRELUDE: &str = r#"mirra_path_error() {
    printf '%s\n' '{"ready":false,"error":"roothide_path_translation_unavailable"}'
    exit 1
}
command -v jbroot >/dev/null 2>&1 || mirra_path_error
"#;

/// `helper_command(arguments, path_mode='native', *, observed=False)`: keep
/// JSON stdout/stdin intact, optionally report the child's exit status.
///
/// Paths in a RootHide profile stay relative to the bootstrap's virtual root.
/// Its bootstrap shell translates executable paths through vroot; convert
/// only paths passed as data to the native program. Repeating the conversion
/// on an executable would prefix its jailbreak root twice. Resolve data paths
/// at every launch so a changed root cannot stale a saved profile.
pub fn helper_command<S: AsRef<str>>(arguments: &[S], path_mode: &str, observed: bool) -> Result<Vec<String>> {
    let arguments: Vec<String> = arguments.iter().map(|a| a.as_ref().to_string()).collect();
    if path_mode != "native" && path_mode != "roothide" {
        return Err(Error::Value("Unsupported bridge path mode".into()));
    }
    if arguments.is_empty() {
        return Err(Error::Value("A helper command is required".into()));
    }
    if path_mode == "native" && !observed {
        return Ok(arguments);
    }
    let (paths, stage): (BTreeSet<usize>, String) = if arguments.len() == 2 && arguments[1] == "--capabilities" {
        (BTreeSet::new(), "capabilities".into())
    } else if arguments.len() == 3 && (arguments[1] == "--export-certificate" || arguments[1] == "--issue-certificate") {
        ([2].into(), arguments[1][2..].replace('-', "_"))
    } else if arguments.len() == 2 && arguments[1].starts_with('/') {
        ([1].into(), "serve".into())
    } else {
        return Err(Error::Value("Unsupported helper arguments".into()));
    };
    let mut script = String::new();
    if path_mode == "roothide" {
        script.push_str(ROOTHIDE_PRELUDE);
    }
    for index in 0..arguments.len() {
        let position = index + 1;
        let name = format!("mirra_arg{}", position);
        if path_mode == "roothide" && paths.contains(&index) {
            script.push_str(&format!("{}=$(jbroot \"${}\") || mirra_path_error\n", name, position));
            script.push_str(&format!("case \"${}\" in /*) ;; *) mirra_path_error ;; esac\n", name));
        } else {
            script.push_str(&format!("{}=${}\n", name, position));
        }
    }
    let invocation = (0..arguments.len()).map(|i| format!("\"$mirra_arg{}\"", i + 1)).collect::<Vec<_>>().join(" ");
    if observed {
        script.push_str(&format!("printf 'MIRRA_HELPER {{\"stage\":\"{stage}\",\"event\":\"launch\"}}\\n' >&2\n{invocation}\nmirra_helper_status=$?\nprintf 'MIRRA_HELPER {{\"stage\":\"{stage}\",\"event\":\"exit\",\"exit_status\":%s}}\\n' \"$mirra_helper_status\" >&2\nexit \"$mirra_helper_status\"\n"));
    } else {
        script.push_str(&format!("exec {}\n", invocation));
    }
    let mut command = vec!["sh".to_string(), "-c".into(), script, "mirra-helper".into()];
    command.extend(arguments);
    Ok(command)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};
    use std::process::Command;

    struct Fixture {
        _temp: tempfile::TempDir,
        root: PathBuf,
        bin: PathBuf,
        bundle: PathBuf,
        data: PathBuf,
    }

    fn tool(path: &Path, body: &str) {
        std::fs::write(path, format!("#!/bin/sh\n{}", body)).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
    }

    impl Fixture {
        fn new() -> Self {
            let temp = tempfile::Builder::new().prefix("Mirra path test ").tempdir().unwrap();
            let root = temp.path().to_path_buf();
            let (bin, bundle, data) = (root.join("bin"), root.join("bundle"), root.join("data"));
            for d in [&bin, &bundle, &data] {
                std::fs::create_dir(d).unwrap();
            }
            tool(&bin.join("jbroot"), r#"case "$1" in /var|/var/*) base=$MIRRA_TEST_DATA ;; *) base=$MIRRA_TEST_BUNDLE ;; esac
p=${1#/}; printf '%s/%s\n' "$base" "$p"
"#);
            tool(&bin.join("rootfs"), "printf '/rootfs%s\\n' \"$1\"\n");
            Fixture { _temp: temp, root, bin, bundle, data }
        }

        fn run(&self, command: &[String]) -> std::process::Output {
            Command::new(&command[0]).args(&command[1..])
                .env("PATH", format!("{}:/usr/bin:/bin", self.bin.display()))
                .env("MIRRA_TEST_BUNDLE", &self.bundle).env("MIRRA_TEST_DATA", &self.data)
                .output().unwrap()
        }

        fn helper(&self, body: &str) -> (String, PathBuf) {
            let virtual_path = format!("{}/helper with 'quotes' $(touch unwanted)", ROOTHIDE_CODE_ROOT);
            let physical = self.bundle.join(virtual_path.trim_start_matches('/'));
            std::fs::create_dir_all(physical.parent().unwrap()).unwrap();
            tool(&physical, body);
            (virtual_path, physical)
        }
    }

    fn environment(fixture: &Fixture, script: &str) -> (i32, serde_json::Value) {
        let out = fixture.run(&["/bin/sh".into(), "-c".into(), script.into()]);
        (out.status.code().unwrap(), serde_json::from_slice(&out.stdout).unwrap())
    }

    #[test]
    fn environment_detection_matches_the_python_script() {
        let fixture = Fixture::new();
        let (status, report) = environment(&fixture, ENVIRONMENT_SCRIPT);
        assert_eq!((status, report), (0, serde_json::json!({"path_mode": "roothide", "path_translation_verified": true})));
        std::fs::remove_file(fixture.bin.join("rootfs")).unwrap();
        let (status, report) = environment(&fixture, ENVIRONMENT_SCRIPT);
        assert_eq!((status, &report["error"]), (1, &serde_json::json!("roothide_path_translation_unavailable")));
        std::fs::remove_file(fixture.bin.join("jbroot")).unwrap();
        let bootstrap = fixture.root.join("bootstrap with spaces");
        let script = ENVIRONMENT_SCRIPT.replace("/var/jb", &mirra_core::shlex::quote(&bootstrap.to_string_lossy()));
        assert_eq!(environment(&fixture, &script).1, serde_json::json!({"path_mode": "native", "path_translation_verified": false}));
        std::fs::create_dir_all(bootstrap.join("usr/bin")).unwrap();
        assert_eq!(environment(&fixture, &script).1,
            serde_json::json!({"path_mode": "native", "path_translation_verified": false, "rootless": true}));
    }

    #[test]
    fn native_launch_keeps_the_existing_argv() {
        let args = ["/var/mobile/endpoint with spaces", "/var/mobile/certificate.der"];
        assert_eq!(helper_command(&args, "native", false).unwrap(), args);
        assert!(helper_command(&args, "guess", false).is_err());
        assert!(helper_command::<&str>(&[], "native", false).is_err());
        assert_eq!(helper_command(&["/x", "--other"], "roothide", false).unwrap_err().to_string(), "Unsupported helper arguments");
    }

    #[test]
    fn roothide_launch_translates_only_data_paths_and_reports_status() {
        let fixture = Fixture::new();
        let (virtual_path, physical) = fixture.helper("printf '%s|' \"$0\" \"$@\"\nexit 4\n");
        // The host shell does not apply vroot; run the helper by its physical path
        // while checking that the data path was translated by jbroot.
        let mut command = helper_command(&[virtual_path.as_str(), "--export-certificate", "/var/mobile/cert 'q'.der"], "roothide", true).unwrap();
        command[4] = physical.to_string_lossy().into_owned();
        let out = fixture.run(&command);
        assert_eq!(out.status.code(), Some(4));
        assert_eq!(String::from_utf8_lossy(&out.stdout),
            format!("{}|--export-certificate|{}/var/mobile/cert 'q'.der|", physical.display(), fixture.data.display()));
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(stderr.contains(r#"MIRRA_HELPER {"stage":"export_certificate","event":"launch"}"#), "{}", stderr);
        assert!(stderr.contains(r#"MIRRA_HELPER {"stage":"export_certificate","event":"exit","exit_status":4}"#), "{}", stderr);
        assert!(!fixture.root.join("unwanted").exists());
        std::fs::remove_file(fixture.bin.join("jbroot")).unwrap();
        let out = fixture.run(&command);
        assert_eq!(out.status.code(), Some(1));
        assert_eq!(String::from_utf8_lossy(&out.stdout), "{\"ready\":false,\"error\":\"roothide_path_translation_unavailable\"}\n");
    }

    #[test]
    fn script_text_matches_python() {
        let command = helper_command(&["/e", "/var/s"], "roothide", false).unwrap();
        assert_eq!(command[2], format!("{}mirra_arg1=$1\nmirra_arg2=$(jbroot \"$2\") || mirra_path_error\ncase \"$mirra_arg2\" in /*) ;; *) mirra_path_error ;; esac\nexec \"$mirra_arg1\" \"$mirra_arg2\"\n", ROOTHIDE_PRELUDE));
        assert_eq!(&command[3..], ["mirra-helper", "/e", "/var/s"]);
        let observed = helper_command(&["/e", "--capabilities"], "native", true).unwrap();
        assert_eq!(observed[2], "mirra_arg1=$1\nmirra_arg2=$2\nprintf 'MIRRA_HELPER {\"stage\":\"capabilities\",\"event\":\"launch\"}\\n' >&2\n\"$mirra_arg1\" \"$mirra_arg2\"\nmirra_helper_status=$?\nprintf 'MIRRA_HELPER {\"stage\":\"capabilities\",\"event\":\"exit\",\"exit_status\":%s}\\n' \"$mirra_helper_status\" >&2\nexit \"$mirra_helper_status\"\n");
    }
}
