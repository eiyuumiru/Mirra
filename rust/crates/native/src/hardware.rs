//! Optional, read-only host observations; never used to gate a connection
//! (port of `scripts/hardware.py`).
use std::collections::BTreeSet;
use std::path::Path;
use std::sync::{LazyLock, Mutex};
use std::time::Duration;

use mirra_core::redaction::{normalize_key, redact_text};
use mirra_core::subprocess::{self, RunOptions};
use mirra_core::Error;
use regex::Regex;
use serde_json::{json, Map, Value};

use crate::plist::{self, Plist};
use crate::util;

pub const DECODE_STATUSES: [&str; 9] = ["format_status", "session_status", "hardware_query_status", "block_status", "copy_status",
    "sample_status", "submit_status", "wait_status", "output_status"];

const CONTROLLER_FIELDS: [(&str, &str); 12] = [
    ("chipset", "chipset"), ("firmwareversion", "firmware_version"), ("vendorid", "vendor_id"), ("productid", "product_id"),
    ("transport", "transport"), ("state", "state"), ("supportedservices", "supported_services"), ("lmpversion", "lmp_version"),
    ("lowenergysupported", "low_energy_supported"), ("bluetoothlowenergysupported", "low_energy_supported"),
    ("handoffsupported", "handoff_supported"), ("manufacturer", "manufacturer"),
];

static DRIVERS: LazyLock<Regex> = LazyLock::new(|| Regex::new(concat!(
    r"(?i)BlueToolFixup|Brcm|Airport|itlwm|IntelBluetooth|IntelBTPatcher|",
    r"IOBluetooth|IO80211|AppleBluetooth|BT4LEContinuity|MtkWireless|",
    r"Lilu|WhateverGreen|NootedRed|NootRX|AMDRadeon|AMD.*(?:Controller|Framebuffer)|",
    r"AppleIntel.*(?:Graphics|Framebuffer)|IOGraphics|IOAccelerator|",
    r"NVDA|NVIDIA|GeForce|NVMTL|NullMoth")).unwrap());

fn regex(pattern: &str) -> Regex {
    Regex::new(pattern).unwrap()
}

pub fn unknown(reason: &str) -> Value {
    json!({"status": "unknown", "reason": reason})
}

fn object(value: Value) -> Map<String, Value> {
    match value {
        Value::Object(map) => map,
        _ => Map::new(),
    }
}

/// Only for selected hardware fields, never whole command output.
pub fn safe_hardware_text(value: &str) -> String {
    static ADDRESS: LazyLock<Regex> = LazyLock::new(|| regex(r"(?i)(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}"));
    static ACCOUNT: LazyLock<Regex> = LazyLock::new(|| regex(r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}"));
    let value = redact_text(value).replace(&util::text(&util::home()), "<home>");
    let value = ADDRESS.replace_all(&value, "<address>");
    let value = ACCOUNT.replace_all(&value, "<account>");
    value.replace(['\n', '\t'], " ").chars().take(256).collect()
}

/// `(stdout, observation)` of one command; stderr and command error text
/// (which may contain personal data) are discarded.
pub type CommandResult = (Option<String>, Value);

pub fn command(arguments: &[String], timeout: u64) -> CommandResult {
    let result = subprocess::run(arguments, &RunOptions::new().input(Vec::new()).capture().timeout(Duration::from_secs(timeout)));
    match result {
        Err(Error::TimeoutExpired { .. }) => (None, unknown("timeout")),
        Err(_) => (None, unknown("tool_unavailable")),
        Ok(reply) if reply.code != 0 => {
            let mut status = object(unknown("command_failed"));
            status.insert("exit_code".into(), Value::from(reply.code));
            (None, Value::Object(status))
        }
        Ok(reply) => {
            // Parse locally without retaining raw profiler inventories or driver UUIDs.
            let text = reply.stdout_text();
            if text.chars().count() > 4 * 1024 * 1024 {
                return (None, unknown("output_limit"));
            }
            (Some(text), json!({"status": "observed"}))
        }
    }
}

fn scalar(value: &Value) -> Option<Value> {
    match value {
        Value::String(s) => Some(Value::from(safe_hardware_text(s))),
        Value::Bool(_) => Some(value.clone()),
        Value::Number(n) if !n.is_f64() => Some(value.clone()),
        _ => None,
    }
}

/// Read local controllers only; never traverse paired/connected devices.
pub fn bluetooth_controllers(value: &Value) -> Vec<Value> {
    let Some(rows) = value.get("SPBluetoothDataType").and_then(Value::as_array).filter(|_| value.is_object()) else { return Vec::new() };
    let mut controllers = Vec::new();
    for row in rows.iter().take(16) {
        let Some(row) = row.as_object() else { continue };
        let mut candidates = vec![(row, true)];
        for name in ["controller_properties", "local_device", "local_controller"] {
            if let Some(item) = row.get(name).and_then(Value::as_object) {
                candidates.push((item, false));
            }
        }
        let mut controller = Map::new();
        for (candidate, is_row) in candidates {
            for (key, item) in candidate {
                let mut name = normalize_key(key);
                if let Some(rest) = name.strip_prefix("controller") {
                    name = rest.to_string();
                } else if is_row {
                    continue;
                }
                if let Some((_, field)) = CONTROLLER_FIELDS.iter().find(|(k, _)| *k == name) {
                    if let Some(selected) = scalar(item) {
                        controller.insert(field.to_string(), selected);
                    }
                }
            }
        }
        if !controller.is_empty() {
            controllers.push(Value::Object(controller));
        }
    }
    controllers
}

/// Select loaded bundle IDs and versions, excluding paths and UUIDs.
pub fn loaded_drivers(output: &str) -> Vec<Value> {
    static ENTRY: LazyLock<Regex> = LazyLock::new(|| regex(r"\b([A-Za-z0-9_.-]{1,128})\s+\(([^()\r\n]{1,48})\)"));
    static VERSION: LazyLock<Regex> = LazyLock::new(|| regex(r"^[0-9][A-Za-z0-9.+_-]{0,47}$"));
    let mut entries: Vec<Value> = Vec::new();
    for line in mirra_core::pyfmt::splitlines(output) {
        let Some(m) = ENTRY.captures(line) else { continue };
        if !DRIVERS.is_match(&m[1]) || !VERSION.is_match(&m[2]) {
            continue;
        }
        let entry = json!({"bundle_identifier": &m[1], "loaded_version": &m[2]});
        if !entries.contains(&entry) {
            entries.push(entry);
        }
        if entries.len() == 128 {
            break;
        }
    }
    entries
}

/// Select local AirPort interface fields, never current/nearby networks.
pub fn wifi_report(value: &Value) -> Value {
    static INTERFACE: LazyLock<Regex> = LazyLock::new(|| regex(r"^en\d{1,4}$"));
    let Some(rows) = value.get("SPAirPortDataType").and_then(Value::as_array).filter(|_| value.is_object()) else {
        return unknown("interface_report_unavailable");
    };
    let mut interfaces: Vec<Value> = Vec::new();
    for row in rows.iter().take(16) {
        let Some(items) = row.as_object().and_then(|r| r.get("spairport_airport_interfaces")).and_then(Value::as_array) else { continue };
        for item in items.iter().take(32) {
            let Some(item) = item.as_object() else { continue };
            let Some(name) = item.get("_name").and_then(Value::as_str).filter(|n| INTERFACE.is_match(n)) else { continue };
            let mut selected = Map::new();
            selected.insert("interface".into(), Value::from(name));
            for (source, field) in [("spairport_wireless_card_type", "reported_card_type"),
                                    ("spairport_wireless_firmware_version", "reported_firmware_version"),
                                    ("spairport_status_information", "reported_status")] {
                if let Some(text) = item.get(source).and_then(Value::as_str) {
                    // The card description is kept verbatim (board/subsystem
                    // IDs are not relabelled as PCI IDs).
                    selected.insert(field.into(), Value::from(safe_hardware_text(text)));
                }
            }
            let selected = Value::Object(selected);
            if !interfaces.contains(&selected) {
                interfaces.push(selected);
            }
        }
    }
    if interfaces.is_empty() {
        return unknown("interface_fields_unavailable");
    }
    interfaces.truncate(32);
    json!({"status": "observed", "interfaces": interfaces, "pci_identity_verified": null,
        "complete_inventory": false, "peer_connectivity_verified": null})
}

/// Controller registry ID → PCI identity (`vendor_id`, `device_id`, …).
pub type PciBindings = Vec<(i128, Value)>;

fn binding<'a>(bindings: &'a PciBindings, identifier: Option<&Plist>) -> Option<&'a Value> {
    let identifier = identifier?.as_int()?;
    bindings.iter().find(|(id, _)| *id == identifier).map(|(_, v)| v)
}

/// Match controller objects to their nearest observed PCI device.
pub fn pci_network_bindings(devices: &Plist, controllers: &Plist) -> PciBindings {
    let (Some(devices), Some(controllers)) = (devices.as_array(), controllers.as_array()) else { return Vec::new() };
    let targets: BTreeSet<i128> = controllers.iter().filter(|r| r.is_dict())
        .filter_map(|r| r.get("IORegistryEntryID").and_then(Plist::as_int)).collect();
    let identity_for = |device: &Plist| -> Option<Value> {
        let mut identity = Map::new();
        for (key, field) in [("vendor-id", "vendor_id"), ("device-id", "device_id"),
                             ("subsystem-vendor-id", "subsystem_vendor_id"), ("subsystem-id", "subsystem_id")] {
            let number = match device.get(key) {
                Some(Plist::Data(raw)) if raw.len() == 4 => Some(u32::from_le_bytes(raw[..].try_into().unwrap()) as i128),
                Some(Plist::Integer(n)) => Some(*n),
                _ => None,
            };
            if let Some(n) = number.filter(|n| (0..=0xffff).contains(n)) {
                identity.insert(field.into(), Value::from(format!("0x{:04x}", n)));
            }
        }
        (identity.contains_key("vendor_id") && identity.contains_key("device_id")).then_some(Value::Object(identity))
    };
    let mut matches: Vec<(i128, Vec<Value>)> = Vec::new();
    for device in devices.iter().take(256) {
        if !device.is_dict() {
            continue;
        }
        // (node, depth, identity, provider class, provider hops)
        type Pending<'a> = (&'a Plist, usize, Option<Value>, Option<String>, usize);
        let mut pending: Vec<Pending> = vec![(device, 0, None, None, 0)];
        let mut visited = 0;
        while visited < 512 {
            let Some((node, depth, mut identity, mut provider, mut hops)) = pending.pop() else { break };
            visited += 1;
            // Reset at each PCI device, including invalid IDs, rather than
            // borrowing an upstream bridge's identity.
            if depth == 0 || node.get("IOObjectClass").and_then(Plist::as_str) == Some("IOPCIDevice")
                || (node.contains_key("vendor-id") && node.contains_key("device-id")) {
                identity = identity_for(node);
                provider = Some("IOPCIDevice".into());
                hops = 0;
            } else {
                // Accept a direct client or one verified provider wrapper; a
                // device behind a USB/Thunderbolt bus must not inherit the
                // bus controller's PCI identity.
                let object_class = match node.get("IOObjectClass") {
                    None => Some(String::new()),
                    Some(Plist::String(s)) => Some(s.clone()),
                    Some(_) => None,
                };
                let same_provider = provider.is_some() && node.get("IOProviderClass").and_then(Plist::as_str) == provider.as_deref();
                let bus = object_class.as_deref().is_none_or(|c|
                    ["IOUSB", "AppleUSB", "IOThunderbolt", "AppleThunderbolt"].iter().any(|p| c.starts_with(p)));
                if hops >= 2 || !same_provider || bus {
                    identity = None;
                }
                provider = object_class;
                hops += 1;
            }
            if let (Some(identity), Some(identifier)) = (&identity, node.get("IORegistryEntryID").and_then(Plist::as_int)) {
                if targets.contains(&identifier) {
                    match matches.iter_mut().find(|(id, _)| *id == identifier) {
                        Some((_, rows)) => rows.push(identity.clone()),
                        None => matches.push((identifier, vec![identity.clone()])),
                    }
                }
            }
            if depth < 6 {
                if let Some(children) = node.get("IORegistryEntryChildren").and_then(Plist::as_array) {
                    for child in children.iter().take(64).filter(|c| c.is_dict()) {
                        pending.push((child, depth + 1, identity.clone(), provider.clone(), hops));
                    }
                }
            }
        }
    }
    // Conflicting or duplicate observations do not authorize an identity guess.
    matches.into_iter().filter(|(_, rows)| rows.len() == 1).map(|(id, mut rows)| (id, rows.remove(0))).collect()
}

/// Associate local interface names with their actual IORegistry controller.
pub fn network_controllers(value: &Plist, pci_bindings: &PciBindings) -> Value {
    static IDENTIFIER: LazyLock<Regex> = LazyLock::new(|| regex(r"^[A-Za-z_][A-Za-z0-9_.-]{0,127}$"));
    static NAME: LazyLock<Regex> = LazyLock::new(|| regex(r"^(?:en|awdl|llw)\d{1,4}$"));
    let Some(rows) = value.as_array() else { return unknown("invalid_registry_report") };
    let mut controllers = Vec::new();
    for row in rows.iter().take(64) {
        if !row.is_dict() {
            continue;
        }
        let mut selected = Map::new();
        for (source, field) in [("IOClass", "controller_class"), ("IOProviderClass", "provider_class"), ("CFBundleIdentifier", "bundle_identifier")] {
            if let Some(item) = row.get(source).and_then(Plist::as_str).filter(|i| IDENTIFIER.is_match(i)) {
                selected.insert(field.into(), Value::from(item));
            }
        }
        let mut names = BTreeSet::new();
        let mut pending = vec![(row, 0usize)];
        let mut visited = 0;
        while visited < 512 {
            let Some((node, depth)) = pending.pop() else { break };
            visited += 1;
            // Use only direct interface properties, not arbitrary entry names.
            let name = match node.get("BSD Name") {
                Some(Plist::String(name)) => Some(name.clone()),
                _ => match (node.get("IOInterfaceNamePrefix").and_then(Plist::as_str), node.get("IOInterfaceUnit").and_then(Plist::as_int)) {
                    (Some(prefix @ ("en" | "awdl" | "llw")), Some(unit)) => Some(format!("{}{}", prefix, unit)),
                    _ => None,
                },
            };
            if let Some(name) = name.filter(|n| NAME.is_match(n)) {
                names.insert(name);
            }
            if depth < 3 {
                if let Some(children) = node.get("IORegistryEntryChildren").and_then(Plist::as_array) {
                    pending.extend(children.iter().take(64).filter(|c| c.is_dict()).map(|c| (c, depth + 1)));
                }
            }
        }
        if !selected.is_empty() && !names.is_empty() {
            if let Some(pci) = binding(pci_bindings, row.get("IORegistryEntryID")) {
                selected.insert("pci_identity".into(), pci.clone());
            }
            selected.insert("interfaces".into(), json!(names.into_iter().collect::<Vec<_>>()));
            selected.insert("fork_provenance_verified".into(), Value::Null);
            controllers.push(Value::Object(selected));
        }
    }
    json!({"status": "observed", "controllers": controllers, "complete_inventory": false})
}

/// Correlate by exact interface/bundle ID; ambiguity remains unknown.
pub fn attach_wifi_bindings(wifi: &mut Value, registry: &Value, drivers: &Value) {
    let empty = Vec::new();
    let controllers = registry.get("controllers").and_then(Value::as_array).unwrap_or(&empty);
    let entries = drivers.get("entries").and_then(Value::as_array).unwrap_or(&empty);
    let Some(interfaces) = wifi.get_mut("interfaces").and_then(Value::as_array_mut) else { return };
    for interface in interfaces {
        let name = interface["interface"].clone();
        let matched: Vec<&Value> = controllers.iter()
            .filter(|row| row["interfaces"].as_array().is_some_and(|list| list.contains(&name))).collect();
        let binding = if matched.len() == 1 { matched[0].clone() } else { Value::Null };
        let versions: BTreeSet<String> = entries.iter()
            .filter(|row| !binding.is_null() && row.get("bundle_identifier") == binding.get("bundle_identifier"))
            .filter_map(|row| row["loaded_version"].as_str().map(str::to_string)).collect();
        let verified = !binding.is_null() && binding.get("pci_identity").is_some_and(|p| !p.is_null());
        interface["controller_binding"] = binding;
        interface["loaded_version"] = if versions.len() == 1 { Value::from(versions.into_iter().next().unwrap()) } else { Value::Null };
        interface["pci_identity_verified"] = if verified { Value::from(true) } else { Value::Null };
    }
}

fn int32(value: &Value) -> Option<bool> {
    // Some(valid) for `type(x) is int`, None otherwise.
    util::strict_int(Some(value)).map(|n| (-(1i64 << 31)..(1i64 << 31)).contains(&n))
}

pub fn graphics_report(value: &Value) -> Value {
    let invalid = || unknown("invalid_probe_report");
    let Some(report) = value.as_object() else { return invalid() };
    let count = util::strict_int(report.get("metal_device_count"));
    if !util::eq_int(report.get("schema_version"), 1) || report.get("probe").and_then(Value::as_str) != Some("host-environment")
        || !count.is_some_and(|c| (0..=65535).contains(&c)) || !report.get("metal_devices").is_some_and(Value::is_array) {
        return invalid();
    }
    let count = count.unwrap();
    let Some(h264) = report.get("h264").and_then(Value::as_object) else { return invalid() };
    if h264.get("sample_profile").and_then(Value::as_str) != Some("Baseline") || !util::eq_int(h264.get("sample_width"), 64)
        || !util::eq_int(h264.get("sample_height"), 64) {
        return invalid();
    }
    let mut decoders = Map::new();
    for (name, required) in [("default", false), ("hardware_required", true)] {
        let Some(item) = h264.get(name).and_then(Value::as_object) else { return invalid() };
        let accel = item.get("using_hardware_acceleration");
        if item.get("hardware_required").and_then(Value::as_bool) != Some(required) || !item.get("fixture_valid").is_some_and(Value::is_boolean)
            || !item.get("frame_decoded").is_some_and(Value::is_boolean) || accel.is_none()
            || !accel.is_some_and(|a| a.is_null() || a.is_boolean()) {
            return invalid();
        }
        let mut selected = Map::new();
        for key in ["hardware_required", "fixture_valid", "frame_decoded", "using_hardware_acceleration"] {
            selected.insert(key.into(), item[key].clone());
        }
        for key in DECODE_STATUSES {
            if let Some(status) = item.get(key) {
                if !status.is_null() && int32(status) != Some(true) {
                    return invalid();
                }
                selected.insert(key.into(), status.clone());
            }
        }
        if item["fixture_valid"] != Value::Bool(true) {
            return unknown("invalid_probe_fixture");
        }
        if item["frame_decoded"] == Value::Bool(true)
            && DECODE_STATUSES.iter().any(|k| *k != "hardware_query_status" && !util::eq_int(item.get(*k), 0)) {
            return unknown("inconsistent_probe_report");
        }
        let gpu_status = item.get("gpu_query_status").cloned().unwrap_or(Value::Null);
        if !gpu_status.is_null() && int32(&gpu_status) != Some(true) {
            return invalid();
        }
        let gpu_name = item.get("gpu_name").cloned().unwrap_or(Value::Null);
        if !gpu_name.is_null() && (!gpu_name.is_string() || !util::eq_int(Some(&gpu_status), 0)) {
            return unknown("inconsistent_probe_report");
        }
        selected.insert("gpu_query_status".into(), gpu_status);
        selected.insert("gpu_name".into(), gpu_name.as_str().map(|n| Value::from(safe_hardware_text(n))).unwrap_or(Value::Null));
        decoders.insert(name.into(), Value::Object(selected));
    }
    let mut metal = Vec::new();
    for item in report["metal_devices"].as_array().unwrap().iter().take(16) {
        let Some(name) = item.as_object().and_then(|i| i.get("name")).and_then(Value::as_str) else { return invalid() };
        let mut selected = Map::new();
        selected.insert("name".into(), Value::from(safe_hardware_text(name)));
        for key in ["low_power", "removable"] {
            selected.insert(key.into(), item.get(key).filter(|v| v.is_boolean()).cloned().unwrap_or(Value::Null));
        }
        metal.push(Value::Object(selected));
    }
    if metal.len() as i64 != count.min(16) {
        return unknown("inconsistent_probe_report");
    }
    let mut h264_out = object(json!({"sample_profile": "Baseline", "sample_width": 64, "sample_height": 64}));
    h264_out.extend(decoders);
    json!({"status": "observed", "metal_device_count": count, "metal_devices": metal, "h264": h264_out,
        "native_mirroring_verified": null})
}

pub fn awdl_report(output: &str, interface: &str) -> Value {
    static FLAGS: LazyLock<Regex> = LazyLock::new(|| regex(r"flags=\d+<([^>]+)>"));
    static INET6: LazyLock<Regex> = LazyLock::new(|| regex(r"(?m)^\s+inet6\s"));
    static LINK_LOCAL: LazyLock<Regex> = LazyLock::new(|| regex(r"(?mi)^\s+inet6\s+fe80:"));
    let header = regex(&format!(r"^{}:\s", regex::escape(interface)));
    if !matches!(interface, "awdl0" | "llw0") || !header.is_match(output) {
        return unknown("interface_report_unavailable");
    }
    let flags: Option<Vec<String>> = FLAGS.captures(output).map(|m| m[1].split(',').map(str::to_string).collect());
    let has = |flag: &str| flags.as_ref().map(|f| Value::from(f.iter().any(|x| x == flag))).unwrap_or(Value::Null);
    json!({"status": "observed", "interface_present": true, "up": has("UP"), "running": has("RUNNING"),
        "ipv6_configured": INET6.is_match(output), "link_local_ipv6": LINK_LOCAL.is_match(output),
        "peer_connectivity_verified": null})
}

pub fn sip_report(output: &str) -> Value {
    static HEADLINE: LazyLock<Regex> = LazyLock::new(|| regex(r"(?i)System Integrity Protection status:\s*([^\r\n]+)"));
    let Some(m) = HEADLINE.captures(output) else { return unknown("status_unavailable") };
    let text = m[1].to_lowercase();
    let trimmed = text.trim_matches([' ', '.']);
    let state = if text.contains("custom configuration") {
        "custom"
    } else if trimmed == "enabled" {
        "fully_enabled"
    } else if trimmed == "disabled" {
        "disabled"
    } else {
        return unknown("status_unavailable");
    };
    json!({"status": "observed", "state": state, "native_support_verified": null})
}

/// Platform facts for [`inspect_host_environment_with`].
pub struct Platform {
    pub darwin: bool,
    pub machine: String,
}

impl Platform {
    pub fn current() -> Self {
        Platform { darwin: cfg!(target_os = "macos"), machine: util::machine() }
    }
}

/// Bounded independent reads; observations are returned independently of readiness.
pub fn inspect_host_environment(root: &Path) -> Value {
    inspect_host_environment_with(root, &command, &Platform::current())
}

pub fn inspect_host_environment_with(root: &Path, run: &(dyn Fn(&[String], u64) -> CommandResult + Sync), platform: &Platform) -> Value {
    let mut report = object(json!({"schema_version": 1, "read_only": true, "native_mirroring_verified": null, "daily_use_verified": null}));
    if !platform.darwin {
        for name in ["host", "graphics", "bluetooth", "wifi", "network_controllers", "pci_inventory", "loaded_drivers", "awdl", "llw", "sip"] {
            report.insert(name.into(), unknown("platform_unavailable"));
        }
        return Value::Object(report);
    }
    let inspector = util::text(&root.join("build/inspector"));
    let commands: Vec<(&str, Vec<&str>, u64)> = vec![
        ("os", vec!["/usr/bin/sw_vers"], 5),
        ("model", vec!["/usr/sbin/sysctl", "-n", "hw.model"], 5),
        ("graphics", vec![inspector.as_str(), "--environment"], 15),
        ("bluetooth", vec!["/usr/sbin/system_profiler", "-json", "-timeout", "10", "SPBluetoothDataType"], 15),
        ("wifi", vec!["/usr/sbin/system_profiler", "-json", "-timeout", "10", "SPAirPortDataType"], 15),
        ("network_controllers", vec!["/usr/sbin/ioreg", "-a", "-l", "-r", "-c", "IONetworkController", "-d", "3"], 5),
        ("pci_inventory", vec!["/usr/sbin/ioreg", "-a", "-l", "-r", "-c", "IOPCIDevice", "-d", "6"], 5),
        ("loaded_drivers", vec!["/usr/bin/kmutil", "showloaded", "--list-only"], 12),
        ("awdl", vec!["/sbin/ifconfig", "awdl0"], 5),
        ("llw", vec!["/sbin/ifconfig", "llw0"], 5),
        ("sip", vec!["/usr/bin/csrutil", "status"], 5),
    ];
    // Four workers, like ThreadPoolExecutor(max_workers=4).
    let next = Mutex::new(0usize);
    let results: Vec<Mutex<Option<CommandResult>>> = commands.iter().map(|_| Mutex::new(None)).collect();
    std::thread::scope(|scope| {
        for _ in 0..4 {
            scope.spawn(|| loop {
                let index = {
                    let mut next = next.lock().unwrap();
                    let index = *next;
                    *next += 1;
                    index
                };
                let Some((_, arguments, timeout)) = commands.get(index) else { return };
                let arguments: Vec<String> = arguments.iter().map(|s| s.to_string()).collect();
                *results[index].lock().unwrap() = Some(run(&arguments, *timeout));
            });
        }
    });
    let mut results: std::collections::HashMap<&str, CommandResult> = commands.iter().zip(results)
        .map(|((name, _, _), slot)| (*name, slot.into_inner().unwrap().unwrap())).collect();
    let (os_text, host) = results.remove("os").unwrap();
    let mut host = object(host);
    if let Some(text) = &os_text {
        for (key, label, pattern) in [("os_version", "ProductVersion", r"\d+(?:\.\d+){1,2}"), ("os_build", "BuildVersion", r"\d+[A-Z]\d+[a-z]?")] {
            let found = regex(&format!(r"(?m)^{}:\s*({})\s*$", label, pattern)).captures(text).map(|m| Value::from(&m[1]));
            host.insert(key.into(), found.unwrap_or(Value::Null));
        }
    }
    let (model_text, _) = results.remove("model").unwrap();
    static MODEL: LazyLock<Regex> = LazyLock::new(|| regex(r"^[A-Za-z][A-Za-z0-9]{0,31}\d+,\d+\s*$"));
    host.insert("model".into(), model_text.filter(|m| MODEL.is_match(m)).map(|m| Value::from(m.trim())).unwrap_or(Value::Null));
    let architecture = platform.machine.as_str();
    host.insert("architecture".into(), if matches!(architecture, "x86_64" | "arm64") { Value::from(architecture) } else { Value::Null });
    report.insert("host".into(), Value::Object(host));
    let mut bindings = PciBindings::new();
    let (raw_pci, mut pci_status) = results.remove("pci_inventory").unwrap();
    let raw_controllers = results.get("network_controllers").and_then(|(raw, _)| raw.clone());
    if let Some(raw) = raw_pci {
        let parsed = (|| -> mirra_core::Result<PciBindings> {
            let devices = plist::loads(raw.as_bytes())?;
            if devices.as_array().is_none() {
                return Err(Error::value("Invalid PCI inventory"));
            }
            match &raw_controllers {
                Some(controllers) => Ok(pci_network_bindings(&devices, &plist::loads(controllers.as_bytes())?)),
                None => Ok(PciBindings::new()),
            }
        })();
        pci_status = match parsed {
            Ok(found) => {
                bindings = found;
                json!({"status": "observed", "matched_controller_count": bindings.len()})
            }
            Err(_) => unknown("invalid_registry_report"),
        };
    }
    let mut pci_status = object(pci_status);
    pci_status.insert("complete_inventory".into(), Value::from(false));
    report.insert("pci_inventory".into(), Value::Object(pci_status));
    for name in ["graphics", "bluetooth", "wifi", "network_controllers"] {
        let (raw, mut observation) = results.remove(name).unwrap();
        if let Some(raw) = raw {
            observation = if name == "network_controllers" {
                match plist::loads(raw.as_bytes()) {
                    Ok(value) => network_controllers(&value, &bindings),
                    Err(_) => unknown("invalid_registry_report"),
                }
            } else {
                match serde_json::from_str::<Value>(&raw) {
                    Err(_) => unknown("invalid_json"),
                    Ok(value) => match name {
                        "graphics" => graphics_report(&value),
                        "wifi" => wifi_report(&value),
                        _ => {
                            let controllers = bluetooth_controllers(&value);
                            if controllers.is_empty() { unknown("controller_fields_unavailable") }
                            else { json!({"status": "observed", "controllers": controllers}) }
                        }
                    },
                }
            };
        }
        report.insert(name.into(), observation);
    }
    let (mut raw, drivers) = results.remove("loaded_drivers").unwrap();
    let mut drivers = object(drivers);
    if raw.is_none() {
        let (fallback, status) = run(&["/usr/sbin/kextstat".to_string(), "-l".to_string()], 8);
        raw = fallback;
        drivers = object(status);
        drivers.insert("source".into(), Value::from("kextstat"));
    } else {
        drivers.insert("source".into(), Value::from("kmutil"));
    }
    if let Some(raw) = &raw {
        drivers.insert("entries".into(), Value::Array(loaded_drivers(raw)));
    }
    // Codeless/injected/user-space drivers may not appear.
    drivers.insert("complete_inventory".into(), Value::from(false));
    let drivers = Value::Object(drivers);
    let registry = report["network_controllers"].clone();
    attach_wifi_bindings(report.get_mut("wifi").unwrap(), &registry, &drivers);
    report.insert("loaded_drivers".into(), drivers);
    for name in ["awdl", "llw", "sip"] {
        let (raw, observation) = results.remove(name).unwrap();
        let value = match raw {
            None => observation,
            Some(raw) => match name {
                "awdl" => awdl_report(&raw, "awdl0"),
                "llw" => awdl_report(&raw, "llw0"),
                _ => sip_report(&raw),
            },
        };
        report.insert(name.into(), value);
    }
    Value::Object(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn fixture_graphics() -> Value {
        let mut decoder = Map::new();
        for key in DECODE_STATUSES {
            decoder.insert(key.into(), json!(0));
        }
        decoder.insert("fixture_valid".into(), json!(true));
        decoder.insert("frame_decoded".into(), json!(true));
        decoder.insert("using_hardware_acceleration".into(), json!(true));
        let mut default = decoder.clone();
        default.insert("hardware_required".into(), json!(false));
        let mut required = decoder;
        required.insert("hardware_required".into(), json!(true));
        json!({"schema_version": 1, "probe": "host-environment", "metal_device_count": 1,
            "metal_devices": [{"name": "Fixture GPU", "low_power": false, "removable": false}],
            "h264": {"sample_profile": "Baseline", "sample_width": 64, "sample_height": 64,
                     "default": default, "hardware_required": required}})
    }

    fn p(value: Value) -> Plist {
        Plist::from_json(&value)
    }

    fn device(vendor: u32, product: u32, children: Vec<Plist>) -> Plist {
        Plist::Dict(vec![
            ("vendor-id".into(), Plist::Data(vendor.to_le_bytes().to_vec())),
            ("device-id".into(), Plist::Data(product.to_le_bytes().to_vec())),
            ("IORegistryEntryChildren".into(), Plist::Array(children)),
            ("IORegistryEntryName".into(), Plist::String("private-pci-path".into())),
        ])
    }

    fn with(mut value: Plist, key: &str, item: Plist) -> Plist {
        value.insert(key, item);
        value
    }

    #[test]
    fn pci_binding_requires_exact_object_and_does_not_use_parent_bridge_ids() {
        let controller = p(json!({"IORegistryEntryID": 123, "IOClass": "FixtureController", "IOProviderClass": "IOPCIDevice",
            "IORegistryEntryChildren": [{"BSD Name": "en2"}]}));
        let controllers = Plist::Array(vec![controller.clone()]);
        let card = device(0x14c3, 0x7961, vec![controller.clone()]);
        let bridge = device(0x8086, 0x1234, vec![card.clone()]);
        let bindings = pci_network_bindings(&Plist::Array(vec![bridge.clone()]), &controllers);
        let expected = json!({"vendor_id": "0x14c3", "device_id": "0x7961"});
        assert_eq!(bindings, vec![(123, expected.clone())]);
        let report = network_controllers(&controllers, &bindings);
        assert_eq!(report["controllers"][0]["pci_identity"], expected);
        let text = mirra_core::pyjson::dumps(&report);
        assert!(!text.contains("123") && !text.contains("private"));
        assert!(pci_network_bindings(&Plist::Array(vec![card.clone(), card.clone()]), &controllers).is_empty());
        assert!(pci_network_bindings(&Plist::Array(vec![bridge, card]), &controllers).is_empty());
        assert!(pci_network_bindings(&Plist::Array(vec![device(0x10000, 1, vec![controller.clone()])]), &controllers).is_empty());
        assert!(pci_network_bindings(&Plist::Array(vec![device(1, 2, vec![device(0x10000, 1, vec![controller.clone()])])]), &controllers).is_empty());
        assert!(pci_network_bindings(&Plist::Array(vec![device(1, 2, vec![p(json!({"IORegistryEntryID": 456}))])]), &controllers).is_empty());
        let usb_controller = with(controller.clone(), "IOProviderClass", Plist::String("IOUSBHostDevice".into()));
        let usb = p(json!({"IOObjectClass": "IOUSBHostDevice", "IOProviderClass": "IOPCIDevice"}));
        let usb = with(usb, "IORegistryEntryChildren", Plist::Array(vec![usb_controller.clone()]));
        assert!(pci_network_bindings(&Plist::Array(vec![device(1, 2, vec![usb])]), &Plist::Array(vec![usb_controller])).is_empty());
        let wrapped = with(controller, "IOProviderClass", Plist::String("FixtureWrapper".into()));
        let wrapper = with(p(json!({"IOObjectClass": "FixtureWrapper", "IOProviderClass": "IOPCIDevice"})),
            "IORegistryEntryChildren", Plist::Array(vec![wrapped.clone()]));
        let wrapped_list = Plist::Array(vec![wrapped]);
        assert_eq!(pci_network_bindings(&Plist::Array(vec![device(0x14c3, 0x7961, vec![wrapper.clone()])]), &wrapped_list), bindings);
        let unverified = with(wrapper, "IOProviderClass", Plist::String("UnverifiedProvider".into()));
        assert!(pci_network_bindings(&Plist::Array(vec![device(1, 2, vec![unverified])]), &wrapped_list).is_empty());
    }

    #[test]
    fn wifi_selects_card_fields_without_network_inventories() {
        let raw = json!({"SPAirPortDataType": [{"spairport_airport_interfaces": [{
            "_name": "en2", "spairport_wireless_card_type": "Fixture (0x14C3, 0x7961)",
            "spairport_wireless_firmware_version": "Fixture 1.2", "spairport_status_information": "spairport_status_connected",
            "spairport_current_network_information": {"_name": "private-ssid"},
            "spairport_airport_other_local_wireless_networks": ["private-nearby"],
            "spairport_hardware_address": "aa:bb:cc:dd:ee:ff"},
            {"_name": "private-device-name", "spairport_wireless_card_type": "private-card"}, {"_name": "awdl0"}]}]});
        let value = wifi_report(&raw);
        assert_eq!(value["interfaces"], json!([{"interface": "en2", "reported_card_type": "Fixture (0x14C3, 0x7961)",
            "reported_firmware_version": "Fixture 1.2", "reported_status": "spairport_status_connected"}]));
        assert_eq!(value["pci_identity_verified"], Value::Null);
        assert_eq!(value["complete_inventory"], false);
        let text = mirra_core::pyjson::dumps(&value);
        assert!(!text.contains("private") && !text.contains("aa:bb"));
        for raw in [Value::Null, json!({}), json!({"SPAirPortDataType": []}), json!({"SPAirPortDataType": [null]})] {
            assert_eq!(wifi_report(&raw)["status"], "unknown");
        }
    }

    #[test]
    fn registry_bindings_preserve_ethernet_style_interfaces_without_vendor_guesses() {
        let row = p(json!({"IOClass": "FixtureController", "IOProviderClass": "IOPCIDevice",
            "CFBundleIdentifier": "example.Driver", "private-property": "private-secret"}));
        let row = with(row, "IORegistryEntryChildren", Plist::Array(vec![
            Plist::Dict(vec![("BSD Name".into(), Plist::String("en2".into())), ("IOMACAddress".into(), Plist::Data(b"private-address".to_vec()))]),
            p(json!({"IOInterfaceNamePrefix": "en", "IOInterfaceUnit": 2})), p(json!({"BSD Name": "awdl0"})),
            p(json!({"IORegistryEntryName": "en9"})), p(json!({"BSD Name": "private-device-name"}))]));
        let mut value = network_controllers(&Plist::Array(vec![row]), &PciBindings::new());
        assert_eq!(value["controllers"][0]["interfaces"], json!(["awdl0", "en2"]));
        assert_eq!(value["controllers"][0]["fork_provenance_verified"], Value::Null);
        assert!(!mirra_core::pyjson::dumps(&value).contains("private"));
        let mut wifi = json!({"interfaces": [{"interface": "en2"}, {"interface": "en9"}]});
        let drivers = json!({"entries": [{"bundle_identifier": "example.Driver", "loaded_version": "1.2"}]});
        attach_wifi_bindings(&mut wifi, &value, &drivers);
        assert_eq!(wifi["interfaces"][0]["loaded_version"], "1.2");
        assert_eq!(wifi["interfaces"][0]["controller_binding"]["controller_class"], "FixtureController");
        assert_eq!(wifi["interfaces"][1]["controller_binding"], Value::Null);
        let doubled: Vec<Value> = value["controllers"].as_array().unwrap().iter().chain(value["controllers"].as_array().unwrap()).cloned().collect();
        value["controllers"] = Value::Array(doubled);
        attach_wifi_bindings(&mut wifi, &value, &drivers);
        assert_eq!(wifi["interfaces"][0]["controller_binding"], Value::Null);
        assert_eq!(wifi["interfaces"][0]["loaded_version"], Value::Null);
    }

    #[test]
    fn graphics_gpu_name_requires_successful_property_query() {
        let mut value = fixture_graphics();
        value["h264"]["default"]["gpu_query_status"] = json!(0);
        value["h264"]["default"]["gpu_name"] = json!("Fixture GPU");
        value["h264"]["default"]["registry_id"] = json!("private-id");
        let selected = graphics_report(&value)["h264"]["default"].clone();
        assert_eq!(selected["gpu_name"], "Fixture GPU");
        assert!(!selected.to_string().contains("private"));
        value["h264"]["default"]["gpu_query_status"] = json!(-1);
        assert_eq!(graphics_report(&value)["status"], "unknown");
        value["h264"]["default"]["gpu_name"] = Value::Null;
        assert_eq!(graphics_report(&value)["h264"]["default"]["gpu_query_status"], -1);
    }

    #[test]
    fn bluetooth_ignores_paired_devices_addresses_and_names() {
        let report = json!({"SPBluetoothDataType": [{
            "controller_properties": {"controller_chipset": "BCM_20702A3", "controller_firmwareVersion": "v14 c5681",
                "controller_transport": "USB", "controller_address": "aa:bb:cc:dd:ee:ff", "controller_name": "Private Mac"},
            "device_connected": {"Private iPhone": {"controller_chipset": "private-pairing", "controller_properties": {"chipset": "private-device"}}},
            "device_paired": ["private-inventory"]}]});
        let selected = bluetooth_controllers(&report);
        assert_eq!(selected, vec![json!({"chipset": "BCM_20702A3", "firmware_version": "v14 c5681", "transport": "USB"})]);
        let older = json!({"SPBluetoothDataType": [{"local_device": {"lmp_version": "0x6", "manufacturer": "Broadcom",
            "name": "private-name", "address": "private-address"}}]});
        assert_eq!(bluetooth_controllers(&older), vec![json!({"lmp_version": "0x6", "manufacturer": "Broadcom"})]);
        for value in [Value::Null, json!([]), json!({}), json!({"SPBluetoothDataType": "bad"}), json!({"SPBluetoothDataType": [null]})] {
            assert!(bluetooth_controllers(&value).is_empty());
        }
    }

    #[test]
    fn driver_list_excludes_unrelated_kexts_paths_and_uuids() {
        let output = "11 0 0xffffff00 0x1000 0x1000 as.vit9696.BlueToolFixup (2.6.9) PRIVATE-UUID <1 2>\n\
            12 0 0xffffff00 0x1000 0x1000 as.vit9696.Lilu (1.7.1) ANOTHER-UUID <1>\n\
            13 0 com.example.privateDriver (1.0) secret\n\
            14 0 com.example.IntelBluetoothFirmware (private-secret) secret\n\
            /Users/private-path/Library/Example\n";
        assert_eq!(loaded_drivers(output), vec![
            json!({"bundle_identifier": "as.vit9696.BlueToolFixup", "loaded_version": "2.6.9"}),
            json!({"bundle_identifier": "as.vit9696.Lilu", "loaded_version": "1.7.1"})]);
    }

    #[test]
    fn metal_and_real_frame_decoding_are_distinct_observations() {
        let mut fixture = fixture_graphics();
        let required = fixture["h264"]["hardware_required"].as_object_mut().unwrap();
        required.insert("session_status".into(), json!(-12906));
        required.insert("frame_decoded".into(), json!(false));
        required.insert("using_hardware_acceleration".into(), Value::Null);
        for key in ["submit_status", "wait_status", "output_status"] {
            required.remove(key);
        }
        let report = graphics_report(&fixture);
        assert_eq!(report["metal_device_count"], 1);
        assert_eq!(report["h264"]["default"]["frame_decoded"], true);
        assert_eq!(report["h264"]["hardware_required"]["frame_decoded"], false);
        assert_eq!(report["h264"]["hardware_required"]["using_hardware_acceleration"], Value::Null);
        assert_eq!(report["native_mirroring_verified"], Value::Null);
    }

    #[test]
    fn invalid_fixture_and_inconsistent_success_are_unknown() {
        for (key, change) in [("fixture_valid", json!(false)), ("frame_decoded", json!(1)), ("output_status", json!(-12909)), ("session_status", json!(true))] {
            let mut fixture = fixture_graphics();
            fixture["h264"]["default"][key] = change;
            assert_eq!(graphics_report(&fixture)["status"], "unknown", "{}", key);
        }
        let mut fixture = fixture_graphics();
        fixture["h264"]["default"].as_object_mut().unwrap().remove("using_hardware_acceleration");
        assert_eq!(graphics_report(&fixture)["status"], "unknown");
        assert_eq!(graphics_report(&Value::Null)["status"], "unknown");
    }

    #[test]
    fn graphics_filters_nonhardware_fields() {
        let mut fixture = fixture_graphics();
        fixture["certificate"] = json!("secret");
        fixture["paired_devices"] = json!(["private"]);
        fixture["metal_devices"][0]["registry_id"] = json!("unique-id");
        fixture["metal_devices"][0]["address"] = json!("private-address");
        fixture["h264"]["default"]["sample"] = json!("private-frame");
        let text = graphics_report(&fixture).to_string();
        assert!(!text.contains("private") && !text.contains("unique-id"));
        assert_eq!(graphics_report(&fixture)["status"], "observed");
    }

    #[test]
    fn awdl_report_retains_flags_without_addresses_or_connectivity_claims() {
        let output = "awdl0: flags=8943<UP,BROADCAST,RUNNING,MULTICAST> mtu 1500\n\tether aa:bb:cc:dd:ee:ff\n\tinet6 fe80::private%awdl0 prefixlen 64\n";
        let report = awdl_report(output, "awdl0");
        assert_eq!(report["up"], true);
        assert_eq!(report["ipv6_configured"], true);
        assert_eq!(report["link_local_ipv6"], true);
        assert_eq!(report["peer_connectivity_verified"], Value::Null);
        assert!(!report.to_string().contains("private") && !report.to_string().contains("aa:bb"));
        assert_eq!(awdl_report("unknown", "awdl0")["status"], "unknown");
        assert_eq!(awdl_report(&output.replace("awdl0", "llw0"), "llw0")["interface_present"], true);
        assert_eq!(awdl_report(output, "llw0")["status"], "unknown");
    }

    #[test]
    fn sip_custom_is_not_treated_as_fully_enabled_or_verified() {
        for (text, state) in [("enabled.", "fully_enabled"), ("disabled.", "disabled"),
                              ("unknown (Custom Configuration).", "custom"), ("disabled (Custom Configuration).", "custom")] {
            let report = sip_report(&format!("System Integrity Protection status: {}", text));
            assert_eq!(report["state"], state);
            assert_eq!(report["native_support_verified"], Value::Null);
        }
        assert_eq!(sip_report("permission denied")["status"], "unknown");
    }

    #[test]
    fn errors_never_copy_stderr_or_partial_command_output() {
        let (raw, status) = command(&["/nonexistent/private-path".to_string()], 1);
        assert!(raw.is_none());
        assert_eq!(status, unknown("tool_unavailable"));
        let (raw, status) = command(&["/bin/sh".into(), "-c".into(), "echo private-output; sleep 5".into()], 1);
        assert!(raw.is_none());
        assert_eq!(status, unknown("timeout"));
        let (raw, status) = command(&["/bin/sh".into(), "-c".into(), "echo private-output; echo private-error >&2; exit 1".into()], 1);
        assert!(raw.is_none());
        assert_eq!(status, json!({"status": "unknown", "reason": "command_failed", "exit_code": 1}));
    }

    fn darwin() -> Platform {
        Platform { darwin: true, machine: "x86_64".into() }
    }

    #[test]
    fn inspection_is_bounded_optional_and_has_safe_fallbacks() {
        let calls = AtomicUsize::new(0);
        let registry = String::from_utf8(plist::dumps(&p(json!([{"IOClass": "FixtureController",
            "CFBundleIdentifier": "as.vit9696.BlueToolFixup", "IORegistryEntryChildren": [{"BSD Name": "en2"}]}]))).unwrap()).unwrap();
        let run = |arguments: &[String], timeout: u64| -> CommandResult {
            calls.fetch_add(1, Ordering::SeqCst);
            assert!(timeout <= 15);
            assert!(!arguments.iter().any(|a| a == "sudo"));
            let observed = json!({"status": "observed"});
            let has = |needle: &str| arguments.iter().any(|a| a == needle);
            if has("--environment") {
                return (Some(fixture_graphics().to_string()), observed);
            }
            if arguments[0].ends_with("sw_vers") {
                return (Some("ProductName:\tmacOS\nProductVersion:\t15.7.2\nBuildVersion:\t24G325\n".into()), observed);
            }
            if arguments.last().map(String::as_str) == Some("hw.model") {
                return (Some("iMac20,2\n".into()), observed);
            }
            if has("SPBluetoothDataType") {
                return (Some(json!({"SPBluetoothDataType": [{"controller_properties": {"controller_chipset": "BCM_20702A3",
                    "controller_address": "private-address"}}]}).to_string()), observed);
            }
            if has("SPAirPortDataType") {
                return (Some(json!({"SPAirPortDataType": [{"spairport_airport_interfaces": [
                    {"_name": "en2", "spairport_current_network_information": "private-ssid"}]}]}).to_string()), observed);
            }
            if arguments[0].ends_with("ioreg") {
                return (Some(registry.clone()), observed);
            }
            if arguments[0].ends_with("kmutil") {
                return (None, json!({"status": "unknown", "reason": "command_failed"}));
            }
            if arguments[0].ends_with("kextstat") {
                return (Some("1 0 as.vit9696.BlueToolFixup (2.6.9) PRIVATE-UUID".into()), observed);
            }
            (None, json!({"status": "unknown", "reason": "tool_unavailable"}))
        };
        let report = inspect_host_environment_with(Path::new("/fixture"), &run, &darwin());
        assert_eq!(calls.load(Ordering::SeqCst), 12);
        assert_eq!(report["host"]["os_build"], "24G325");
        assert_eq!(report["host"]["os_version"], "15.7.2");
        assert_eq!(report["host"]["model"], "iMac20,2");
        assert_eq!(report["host"]["architecture"], "x86_64");
        assert_eq!(report["loaded_drivers"]["source"], "kextstat");
        assert_eq!(report["loaded_drivers"]["complete_inventory"], false);
        assert_eq!(report["awdl"]["status"], "unknown");
        assert_eq!(report["llw"]["status"], "unknown");
        assert_eq!(report["wifi"]["interfaces"][0]["loaded_version"], "2.6.9");
        assert!(!report.to_string().to_lowercase().contains("private"));
        assert_eq!(report["native_mirroring_verified"], Value::Null);
        let keys: Vec<&String> = report.as_object().unwrap().keys().collect();
        assert_eq!(keys, ["schema_version", "read_only", "native_mirroring_verified", "daily_use_verified", "host", "pci_inventory",
            "graphics", "bluetooth", "wifi", "network_controllers", "loaded_drivers", "awdl", "llw", "sip"]);
    }

    #[test]
    fn malformed_registry_does_not_discard_other_observations() {
        for raw in ["not a plist", "<?xml version=\"1.0\"?><plist><array><dict>"] {
            let run = |arguments: &[String], _: u64| -> CommandResult {
                if arguments[0].ends_with("ioreg") {
                    return (Some(raw.into()), json!({"status": "observed"}));
                }
                (None, json!({"status": "unknown", "reason": "timeout"}))
            };
            let value = inspect_host_environment_with(Path::new("/fixture"), &run, &darwin());
            assert_eq!(value["network_controllers"]["reason"], "invalid_registry_report");
            assert_eq!(value["pci_inventory"]["reason"], "invalid_registry_report");
            assert_eq!(value["wifi"]["reason"], "timeout");
        }
    }

    #[test]
    fn other_platforms_do_not_run_host_commands() {
        let run = |_: &[String], _: u64| -> CommandResult { panic!("must not run") };
        let report = inspect_host_environment_with(Path::new("/fixture"), &run, &Platform { darwin: false, machine: "x".into() });
        assert_eq!(report["graphics"]["status"], "unknown");
    }
}
