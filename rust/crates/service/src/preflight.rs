//! Check only the configured bridge before opening Apple's Mirroring app
//! (port of `scripts/preflight.py`).
use mirra_core::activity;
use serde_json::{json, Value};

/// Observe live bridge/launch health without changing the service.
///
/// Apple's app owns target discovery and radio eligibility. Do not query them
/// here: a permission-restricted radio reading can appear to be powered off.
pub fn check(observer: &dyn Fn() -> Value) -> Value {
    let report = observer();
    activity::emit("Connection check", "bridge result", "info", json!({"state": report["state"]}));
    if report.get("state").and_then(Value::as_str) != Some("ready") {
        let title = report.get("title").cloned().unwrap_or_else(|| Value::from("Your setup phone isn’t ready"));
        return json!({"state": "blocked", "title": title, "message": report["detail"], "report": report});
    }
    json!({"state": "ready", "report": report, "mirroring_connection_verified": null})
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn ready_bridge_opens_without_other_queries() {
        let calls = Cell::new(0);
        let report = json!({"state": "ready", "detail": "Bridge answered.", "actions": ["open_mirroring"]});
        let result = check(&|| { calls.set(calls.get() + 1); report.clone() });
        assert_eq!(calls.get(), 1);
        assert_eq!(result, json!({"state": "ready", "report": report, "mirroring_connection_verified": null}));
    }

    #[test]
    fn unavailable_bridge_blocks_and_keeps_app_guidance() {
        for state in ["waiting_for_bridge", "unknown", "recovering", "stopped", "starting", "setup_required", "launch_support_unavailable"] {
            let report = json!({"state": state, "detail": "Check the configured bridge."});
            let result = check(&|| report.clone());
            assert_eq!(result["state"], "blocked");
            assert_eq!(result["message"], report["detail"]);
            assert_eq!(result["title"], "Your setup phone isn’t ready");
            assert_eq!(result["report"], report);
        }
        let report = json!({"state": "waiting_for_mirroring_exit", "title": "Quit iPhone Mirroring", "detail": "Quit."});
        let result = check(&|| report.clone());
        assert_eq!(result["title"], "Quit iPhone Mirroring");
        assert_eq!(result["message"], "Quit.");
        // Key order matches the Python dict literal.
        assert_eq!(result.as_object().unwrap().keys().collect::<Vec<_>>(), ["state", "title", "message", "report"]);
    }
}
