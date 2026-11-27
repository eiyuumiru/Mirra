//! Validated device and host settings shared by the command-line tools
//! (port of `scripts/configuration.py`).
use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use regex::Regex;
use serde_json::{json, Map, Value};

use crate::paths;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigError(pub String);

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ConfigError {}

fn error<T>(message: impl Into<String>) -> Result<T, ConfigError> {
    Err(ConfigError(message.into()))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    pub source: PathBuf,
    pub transport: String,
    pub product_type: String,
    pub serial: String,
    pub listen_port: u16,
    pub device_port: u16,
    pub ssh_host: String,
    pub ssh_port: u16,
    pub user_file: PathBuf,
    pub identity_file: PathBuf,
    pub known_hosts_file: PathBuf,
    pub host_key_alias: String,
    pub remote_endpoint: String,
    pub remote_certificate: String,
    pub timeout: u64,
    pub certificate_file: PathBuf,
    pub runtime_directory: PathBuf,
    pub system_app: PathBuf,
    pub seconds: u64,
    /// `native` (default) or `roothide`
    pub path_mode: String,
    /// `auto` (default), `normal` or `no_fls`
    pub decoder_route: String,
    pub service_port: u16,
    pub token_file: PathBuf,
}

fn text_of(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

static ACCOUNT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\A[A-Za-z0-9_][A-Za-z0-9_.-]*\z").unwrap());
static PRODUCT: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\A(iPhone|iPad|iPod)[0-9]+,[0-9]+\z").unwrap());
static SERIAL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\A[A-Za-z0-9-]+\z").unwrap());
static HOSTNAME: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\A[A-Za-z0-9_.:%\[\]-]+\z").unwrap());

impl Config {
    /// Profile JSON with Python's exact key order.
    pub fn as_dict(&self) -> Value {
        let mut value = json!({"schema_version": 1, "backend": {
            "transport": self.transport,
            "usb": {"product_type": self.product_type, "serial": self.serial,
                    "listen_port": self.listen_port, "device_port": self.device_port},
            "ssh": {"host": self.ssh_host, "port": self.ssh_port, "user_file": text_of(&self.user_file),
                    "identity_file": text_of(&self.identity_file), "known_hosts_file": text_of(&self.known_hosts_file),
                    "host_key_alias": self.host_key_alias, "remote_endpoint": self.remote_endpoint,
                    "remote_certificate": self.remote_certificate, "timeout_seconds": self.timeout},
            "service": {"port": self.service_port, "token_file": text_of(&self.token_file)},
            "certificate_file": text_of(&self.certificate_file)},
            "host": {"runtime_directory": text_of(&self.runtime_directory), "system_app": text_of(&self.system_app)},
            "session": {"seconds": self.seconds}});
        if self.path_mode != "native" {
            value["backend"]["ssh"]["path_mode"] = Value::from(self.path_mode.clone());
        }
        if self.decoder_route != "auto" {
            value["host"]["decoder_route"] = Value::from(self.decoder_route.clone());
        }
        value
    }

    /// SSH is used only during setup, to install and configure the bridge service.
    pub fn ssh_command<S: AsRef<str>>(&self, remote_arguments: &[S]) -> Result<Vec<String>, ConfigError> {
        let user = match std::fs::read(&self.user_file) {
            Ok(data) => String::from_utf8_lossy(&data).trim().to_string(),
            Err(_) => return error("Missing SSH account file; import or configure device access first"),
        };
        if !ACCOUNT.is_match(&user) {
            return error("SSH account must be a single account name");
        }
        let usb = self.transport == "usb";
        let host = if usb { "127.0.0.1".to_string() } else { self.ssh_host.clone() };
        let port = if usb { self.listen_port } else { self.ssh_port };
        let mut command: Vec<String> = [
            "ssh", "-T", "-p", &port.to_string(), "-l", &user, "-i", &text_of(&self.identity_file),
            "-o", "BatchMode=yes", "-o", "IdentitiesOnly=yes", "-o", "ConnectTimeout=8",
            "-o", "ServerAliveInterval=5", "-o", "ServerAliveCountMax=2",
            "-o", "StrictHostKeyChecking=yes", "-o", &format!("UserKnownHostsFile={}", ssh_config_path(&self.known_hosts_file)),
        ].iter().map(|s| s.to_string()).collect();
        if !self.host_key_alias.is_empty() {
            command.push("-o".into());
            command.push(format!("HostKeyAlias={}", self.host_key_alias));
        }
        // OpenSSH invokes a remote shell even when the local call uses argv.
        if remote_arguments.is_empty() || remote_arguments.iter().any(|a| a.as_ref().contains('\0')) {
            return error("Remote command must contain text arguments without NUL bytes");
        }
        command.push(host);
        command.push(crate::shlex::join(remote_arguments));
        Ok(command)
    }
}

/// OpenSSH parses -o values again, including whitespace-separated filenames
/// and percent tokens. Local argv quoting alone does not protect this path.
pub fn ssh_config_path(path: &Path) -> String {
    let value = text_of(path).replace('%', "%%").replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{}\"", value)
}

/// The package root: parent of the directory holding the executable
/// (`<package>/build/mirra-cli` → `<package>`).
pub fn default_root() -> PathBuf {
    let exe = std::env::current_exe().unwrap_or_else(|_| PathBuf::from("."));
    let exe = std::fs::canonicalize(&exe).unwrap_or(exe);
    exe.parent().and_then(Path::parent).map(Path::to_path_buf).unwrap_or_else(|| PathBuf::from("/"))
}

static EMPTY: LazyLock<Map<String, Value>> = LazyLock::new(Map::new);

fn object<'a>(value: Option<&'a Value>, allowed: &[&str], place: &str) -> Result<&'a Map<String, Value>, ConfigError> {
    let map = match value {
        None => &*EMPTY,
        Some(Value::Object(map)) => map,
        Some(_) => return error(format!("{} must be an object", place)),
    };
    let mut unknown: Vec<&str> = map.keys().map(String::as_str).filter(|k| !allowed.contains(k)).collect();
    if !unknown.is_empty() {
        unknown.sort();
        unknown.dedup();
        return error(format!("{}: unknown setting {}", place, unknown.join(", ")));
    }
    Ok(map)
}

fn text<'a>(value: Option<&'a Value>, default: &'a str, place: &str, empty: bool) -> Result<String, ConfigError> {
    let value = match value {
        None => default,
        Some(Value::String(s)) => s.as_str(),
        Some(_) => return error(format!("{} must be a string without control characters", place)),
    };
    if (value.is_empty() && !empty) || value.chars().any(|c| (c as u32) < 32) {
        return error(format!("{} must be a string without control characters", place));
    }
    Ok(value.to_string())
}

fn integer(value: Option<&Value>, default: i64, low: i64, high: i64, place: &str) -> Result<i64, ConfigError> {
    let number = match value {
        None => Some(default),
        Some(Value::Number(n)) if !n.is_f64() => n.as_i64(),
        _ => None,
    };
    match number {
        Some(n) if low <= n && n <= high => Ok(n),
        _ => error(format!("{} must be an integer in {}..{}", place, low, high)),
    }
}

/// Load and validate a profile. `path` overrides `MIRRA_CONFIG`, which
/// overrides `<root>/config/local.json` (absent default = all defaults).
pub fn load_config(path: Option<&Path>, root: &Path) -> Result<Config, ConfigError> {
    let root = paths::resolve(root);
    let environment = std::env::var_os("MIRRA_CONFIG").filter(|v| !v.is_empty());
    let explicit = path.is_some() || environment.is_some();
    let chosen = match path.filter(|p| !p.as_os_str().is_empty()) {
        Some(p) => p.to_path_buf(),
        None => match &environment {
            Some(v) => PathBuf::from(v),
            None => root.join("config/local.json"),
        },
    };
    let source = paths::resolve(&paths::expanduser(&chosen));
    let raw: Value = if source.is_file() {
        let parsed = std::fs::read(&source).ok()
            .and_then(|data| String::from_utf8(data).ok())
            .and_then(|text| serde_json::from_str::<Value>(&text).ok());
        match parsed {
            Some(value) => value,
            None => return error(format!("Cannot read configuration: {}", text_of(&source))),
        }
    } else if explicit {
        return error(format!("Configuration file does not exist: {}", text_of(&source)));
    } else {
        Value::Object(Map::new())
    };
    let raw = object(Some(&raw), &["schema_version", "backend", "host", "session"], "configuration")?;
    match raw.get("schema_version") {
        None => {}
        Some(Value::Number(n)) if !n.is_f64() && n.as_i64() == Some(1) => {}
        _ => return error("Unsupported configuration schema_version"),
    }
    let backend = object(raw.get("backend"), &["transport", "usb", "ssh", "service", "certificate_file"], "backend")?;
    let service = object(backend.get("service"), &["port", "token_file"], "backend.service")?;
    let usb = object(backend.get("usb"), &["product_type", "serial", "listen_port", "device_port"], "backend.usb")?;
    let ssh = object(backend.get("ssh"), &["host", "port", "user_file", "identity_file", "known_hosts_file",
        "host_key_alias", "remote_endpoint", "remote_certificate", "timeout_seconds", "path_mode"], "backend.ssh")?;
    let host = object(raw.get("host"), &["runtime_directory", "system_app", "decoder_route"], "host")?;
    let session = object(raw.get("session"), &["seconds"], "session")?;
    let transport = match backend.get("transport") {
        None => "ssh",
        Some(Value::String(s)) if s == "usb" || s == "ssh" => s.as_str(),
        _ => return error("backend.transport must be usb or ssh"),
    };
    let path_mode = match ssh.get("path_mode") {
        None => "native",
        Some(Value::String(s)) if s == "native" || s == "roothide" => s.as_str(),
        _ => return error("backend.ssh.path_mode must be native or roothide"),
    };
    let decoder_route = match host.get("decoder_route") {
        None => "auto",
        Some(Value::String(s)) if s == "auto" || s == "normal" || s == "no_fls" => s.as_str(),
        _ => return error("host.decoder_route must be auto, normal or no_fls"),
    };
    let local = |map: &Map<String, Value>, key: &str, default: &str, name: &str| -> Result<PathBuf, ConfigError> {
        let candidate = paths::expanduser(Path::new(&text(map.get(key), default, name, false)?));
        let candidate = if candidate.is_absolute() { candidate } else { root.join(candidate) };
        Ok(paths::resolve(&candidate))
    };
    let remote = |map: &Map<String, Value>, key: &str, default: &str, name: &str| -> Result<String, ConfigError> {
        let value = text(map.get(key), default, name, false)?;
        if !value.starts_with('/') {
            return error(format!("{} must be an absolute device path", name));
        }
        Ok(value)
    };
    let product = text(usb.get("product_type"), "", "backend.usb.product_type", true)?;
    let serial = text(usb.get("serial"), "", "backend.usb.serial", true)?;
    if transport == "usb" && product.is_empty() && serial.is_empty() {
        return error("Select a backend USB serial or product_type");
    }
    if !product.is_empty() && !PRODUCT.is_match(&product) {
        return error("backend.usb.product_type must be an Apple product identifier");
    }
    if !serial.is_empty() && !SERIAL.is_match(&serial) {
        return error("backend.usb.serial must be a device identifier");
    }
    let hostname = text(ssh.get("host"), "127.0.0.1", "backend.ssh.host", false)?;
    let alias = text(ssh.get("host_key_alias"), "", "backend.ssh.host_key_alias", true)?;
    for (value, name) in [(&hostname, "host"), (&alias, "host_key_alias")] {
        if !value.is_empty() && (value.starts_with('-') || !HOSTNAME.is_match(value)) {
            return error(format!("Invalid backend.ssh.{}", name));
        }
    }
    let listen_port = integer(usb.get("listen_port"), 2222, 1, 65535, "backend.usb.listen_port")? as u16;
    let device_port = integer(usb.get("device_port"), 22, 1, 65535, "backend.usb.device_port")? as u16;
    let ssh_port = integer(ssh.get("port"), 22, 1, 65535, "backend.ssh.port")? as u16;
    let user_file = local(ssh, "user_file", "private/bridge/user", "backend.ssh.user_file")?;
    let identity_file = local(ssh, "identity_file", "private/bridge/identity", "backend.ssh.identity_file")?;
    let known_hosts_file = local(ssh, "known_hosts_file", "private/bridge/known_hosts", "backend.ssh.known_hosts_file")?;
    let remote_endpoint = remote(ssh, "remote_endpoint", "/var/mobile/Library/Caches/Mirra/bridge/endpoint", "backend.ssh.remote_endpoint")?;
    let remote_certificate = remote(ssh, "remote_certificate", "/var/mobile/Library/Caches/Mirra/bridge/certificate.der", "backend.ssh.remote_certificate")?;
    let timeout = integer(ssh.get("timeout_seconds"), 12, 1, 60, "backend.ssh.timeout_seconds")? as u64;
    let certificate_file = local(backend, "certificate_file", "private/bridge/certificate.der", "backend.certificate_file")?;
    let runtime_directory = local(host, "runtime_directory", "runtime/host", "host.runtime_directory")?;
    let system_app = local(host, "system_app", "/System/Applications/iPhone Mirroring.app", "host.system_app")?;
    let seconds = integer(session.get("seconds"), 1800, 30, 1800, "session.seconds")? as u64;
    let service_port = integer(service.get("port"), 47820, 1, 65535, "backend.service.port")? as u16;
    let token_file = local(service, "token_file", "private/bridge/token", "backend.service.token_file")?;
    Ok(Config {
        source, transport: transport.into(), product_type: product, serial, listen_port, device_port,
        ssh_host: hostname, ssh_port, user_file, identity_file, known_hosts_file, host_key_alias: alias,
        remote_endpoint, remote_certificate, timeout, certificate_file, runtime_directory, system_app, seconds,
        path_mode: path_mode.into(), decoder_route: decoder_route.into(), service_port, token_file,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shlex;

    struct Fixture {
        _temp: tempfile::TempDir,
        root: PathBuf,
        path: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let temp = tempfile::tempdir().unwrap();
            let root = paths::resolve(temp.path());
            let path = root.join("settings.json");
            Fixture { _temp: temp, root, path }
        }
        fn config(&self, data: Value) -> Result<Config, ConfigError> {
            std::fs::write(&self.path, serde_json::to_string(&data).unwrap()).unwrap();
            load_config(Some(&self.path), &self.root)
        }
    }

    #[test]
    fn defaults_do_not_select_a_reference_phone() {
        let f = Fixture::new();
        let c = f.config(json!({})).unwrap();
        assert_eq!((c.transport.as_str(), c.product_type.as_str(), c.listen_port, c.device_port, c.seconds), ("ssh", "", 2222, 22, 1800));
        assert_eq!(c.certificate_file, f.root.join("private/bridge/certificate.der"));
        assert_eq!(c.system_app, PathBuf::from("/System/Applications/iPhone Mirroring.app"));
    }

    #[test]
    fn another_device_and_custom_paths() {
        let f = Fixture::new();
        let c = f.config(json!({"backend": {"usb": {"product_type": "iPhone12,3", "serial": "TEST-DEVICE", "listen_port": 2323},
            "ssh": {"identity_file": "private/other/key"}, "certificate_file": "private/other/cert.der"}})).unwrap();
        assert_eq!(c.product_type, "iPhone12,3");
        assert_eq!(c.serial, "TEST-DEVICE");
        assert_eq!(c.identity_file, f.root.join("private/other/key"));
    }

    #[test]
    fn ssh_remote_command_preserves_literal_paths() {
        let f = Fixture::new();
        let remote = "/var/mobile/path with spaces/$(touch unwanted);'endpoint";
        let c = f.config(json!({"backend": {"transport": "ssh", "ssh": {"host": "192.0.2.5", "port": 2223,
            "host_key_alias": "owned-backend", "user_file": "user", "remote_endpoint": remote}}})).unwrap();
        std::fs::write(&c.user_file, "mobile\n").unwrap();
        let command = c.ssh_command(&[remote, &c.remote_certificate]).unwrap();
        assert!(command.contains(&"StrictHostKeyChecking=yes".to_string()));
        assert!(command.contains(&"HostKeyAlias=owned-backend".to_string()));
        assert!(command.contains(&"-l".to_string()) && command.contains(&"mobile".to_string()));
        assert_eq!(command[command.len() - 2], "192.0.2.5");
        assert_eq!(shlex::split(command.last().unwrap()).unwrap(), vec![remote.to_string(), c.remote_certificate.clone()]);
        let empty: [&str; 0] = [];
        assert_eq!(c.ssh_command(&empty).unwrap_err().0, "Remote command must contain text arguments without NUL bytes");
        assert!(c.ssh_command(&["a\0b"]).is_err());
    }

    #[test]
    fn missing_or_invalid_account_is_rejected() {
        let f = Fixture::new();
        let c = f.config(json!({"backend": {"ssh": {"user_file": "user"}}})).unwrap();
        assert_eq!(c.ssh_command(&["true"]).unwrap_err().0, "Missing SSH account file; import or configure device access first");
        std::fs::write(&c.user_file, "two words").unwrap();
        assert_eq!(c.ssh_command(&["true"]).unwrap_err().0, "SSH account must be a single account name");
    }

    #[test]
    fn usb_port_overrides_ssh_port() {
        let f = Fixture::new();
        let c = f.config(json!({"backend": {"transport": "usb", "usb": {"product_type": "iPhone11,2", "listen_port": 2323},
            "ssh": {"port": 8888, "user_file": "user"}}})).unwrap();
        std::fs::write(&c.user_file, "mobile").unwrap();
        let command = c.ssh_command(&["true"]).unwrap();
        let p = command.iter().position(|a| a == "-p").unwrap();
        assert_eq!(command[p + 1], "2323");
        assert_eq!(command[command.len() - 2], "127.0.0.1");
    }

    #[test]
    fn ssh_known_host_path_with_spaces_is_one_configuration_token() {
        let f = Fixture::new();
        let c = f.config(json!({"backend": {"ssh": {"known_hosts_file": "Application Support/backend/known_hosts", "user_file": "user"}}})).unwrap();
        std::fs::write(&c.user_file, "mobile").unwrap();
        let command = c.ssh_command(&["true"]).unwrap();
        let option = command.iter().find(|a| a.starts_with("UserKnownHostsFile=")).unwrap();
        let value = option.split_once('=').unwrap().1;
        assert_eq!(shlex::split(value).unwrap(), vec![text_of(&c.known_hosts_file)]);
        assert_eq!(ssh_config_path(Path::new("/a%b\\c\"d")), "\"/a%%b\\\\c\\\"d\"");
    }

    #[test]
    fn invalid_settings_fail_before_device_access() {
        let f = Fixture::new();
        let invalid = [
            (json!([]), "configuration must be an object"),
            (json!({"schema_version": true}), "Unsupported configuration schema_version"),
            (json!({"backend": {"usb": {"listen_port": true}}}), "backend.usb.listen_port must be an integer in 1..65535"),
            (json!({"backend": {"usb": {"listen_port": 65536}}}), "backend.usb.listen_port must be an integer in 1..65535"),
            (json!({"backend": {"usb": {"listen_port": 22.0}}}), "backend.usb.listen_port must be an integer in 1..65535"),
            (json!({"backend": {"tranpsort": "ssh", "a": 1}}), "backend: unknown setting a, tranpsort"),
            (json!({"backend": {"transport": "usb", "usb": {"product_type": "", "serial": ""}}}), "Select a backend USB serial or product_type"),
            (json!({"backend": {"ssh": {"host": "-oProxyCommand=bad"}}}), "Invalid backend.ssh.host"),
            (json!({"backend": {"ssh": {"remote_endpoint": "relative"}}}), "backend.ssh.remote_endpoint must be an absolute device path"),
            (json!({"backend": {"ssh": {"remote_certificate": "/path\ncommand"}}}), "backend.ssh.remote_certificate must be a string without control characters"),
            (json!({"backend": null}), "backend must be an object"),
            (json!({"backend": {"usb": {"product_type": "Mac1,1"}}}), "backend.usb.product_type must be an Apple product identifier"),
            (json!({"host": {"decoder_route": "fast"}}), "host.decoder_route must be auto, normal or no_fls"),
            (json!({"session": {"seconds": 29}}), "session.seconds must be an integer in 30..1800"),
        ];
        for (data, message) in invalid {
            assert_eq!(f.config(data.clone()).unwrap_err().0, message, "{}", data);
        }
        std::fs::write(&f.path, "{not json").unwrap();
        assert_eq!(load_config(Some(&f.path), &f.root).unwrap_err().0, format!("Cannot read configuration: {}", f.path.display()));
    }

    #[test]
    fn missing_explicit_config_is_not_defaulted() {
        let f = Fixture::new();
        let missing = f.root.join("missing.json");
        assert_eq!(load_config(Some(&missing), &f.root).unwrap_err().0, format!("Configuration file does not exist: {}", missing.display()));
    }

    #[test]
    fn session_staging_preserves_device_settings() {
        let f = Fixture::new();
        let original = f.config(json!({"backend": {"transport": "ssh", "ssh": {"host": "192.0.2.4", "port": 2223}},
            "host": {"runtime_directory": "runtime/staged"}})).unwrap();
        let staged = f.config(original.as_dict()).unwrap();
        assert_eq!(original, staged);
        let dict = original.as_dict();
        let keys: Vec<&String> = dict.as_object().unwrap().keys().collect();
        assert_eq!(keys, ["schema_version", "backend", "host", "session"]);
    }

    #[test]
    fn roothide_profile_round_trip_preserves_mode_and_literal_paths() {
        let f = Fixture::new();
        let original = f.config(json!({"backend": {"ssh": {"path_mode": "roothide", "user_file": "user",
            "remote_endpoint": "/usr/local/libexec/Mirra/endpoint 'with' spaces"}}, "host": {"decoder_route": "no_fls"}})).unwrap();
        assert_eq!(original.as_dict()["backend"]["ssh"]["path_mode"], "roothide");
        assert_eq!(original.as_dict()["host"]["decoder_route"], "no_fls");
        assert_eq!(f.config(original.as_dict()).unwrap(), original);
    }

    #[test]
    fn native_profile_does_not_add_a_new_setting() {
        let f = Fixture::new();
        let original = f.config(json!({})).unwrap();
        assert_eq!(original.path_mode, "native");
        assert!(original.as_dict()["backend"]["ssh"].get("path_mode").is_none());
        assert!(original.as_dict()["host"].get("decoder_route").is_none());
    }

    #[test]
    fn invalid_path_modes_are_rejected_before_access() {
        let f = Fixture::new();
        for mode in [json!("guess"), json!(""), Value::Null, json!([]), json!(true)] {
            assert_eq!(f.config(json!({"backend": {"ssh": {"path_mode": mode}}})).unwrap_err().0,
                "backend.ssh.path_mode must be native or roothide");
        }
    }
}
