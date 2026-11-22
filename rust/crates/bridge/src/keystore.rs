//! `keystore.bridge_capabilities`, needed by the transport greeting check.
use std::sync::LazyLock;

use regex::Regex;
use serde_json::{Map, Value};

static PATTERNS: LazyLock<[(&str, Regex); 4]> = LazyLock::new(|| {
    let full = |p: &str| Regex::new(&format!(r"\A(?:{})\z", p)).unwrap();
    [("product_type", full(r"iPhone\d+,\d+")), ("os_version", full(r"\d+(?:\.\d+){1,2}")),
     ("os_build", full(r"\d+[A-Z]\d+[a-z]?")), ("minimum_ios", full(r"\d+(?:\.\d+){1,2}"))]
});
static SYMBOL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\Aaks_[a-z0-9_]{1,64}\z").unwrap());

/// Select hardware/API observations without certificates or device identities.
pub fn bridge_capabilities(report: &Map<String, Value>) -> Map<String, Value> {
    let mut selected = Map::new();
    for (name, pattern) in PATTERNS.iter() {
        if let Some(Value::String(value)) = report.get(*name) {
            if value.chars().count() <= 32 && pattern.is_match(value) {
                selected.insert((*name).into(), Value::from(value.clone()));
            }
        }
    }
    if let Some(Value::String(arch)) = report.get("process_architecture") {
        if ["arm64", "arm64e", "x86_64"].contains(&arch.as_str()) {
            selected.insert("process_architecture".into(), Value::from(arch.clone()));
        }
    }
    if let Some(Value::Array(missing)) = report.get("missing_symbols") {
        if missing.len() <= 18 && missing.iter().all(|v| v.as_str().is_some_and(|s| SYMBOL.is_match(s))) {
            selected.insert("missing_symbols".into(), Value::Array(missing.clone()));
        }
    }
    selected
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn selects_only_well_formed_observations() {
        let report = json!({"ready": false, "error": "required_keystore_symbols_unavailable",
            "missing_symbols": ["aks_remote_session"], "os_version": "15.8.4", "os_build": "19H390",
            "product_type": "iPhone10,5", "minimum_ios": "15.0", "process_architecture": "arm64",
            "serial": "private-serial", "dcrt": "private-certificate"});
        let selected = bridge_capabilities(report.as_object().unwrap());
        assert_eq!(Value::Object(selected), json!({"product_type": "iPhone10,5", "os_version": "15.8.4",
            "os_build": "19H390", "minimum_ios": "15.0", "process_architecture": "arm64",
            "missing_symbols": ["aks_remote_session"]}));
        let bad = json!({"product_type": "iPhone10,5\n", "os_version": "15", "process_architecture": "ppc",
            "missing_symbols": ["aks_ok", "AKS_bad"], "os_build": "1".repeat(31) + "A1"});
        assert!(bridge_capabilities(bad.as_object().unwrap()).is_empty());
        let many = json!({"missing_symbols": vec!["aks_x"; 19]});
        assert!(bridge_capabilities(many.as_object().unwrap()).is_empty());
    }
}
