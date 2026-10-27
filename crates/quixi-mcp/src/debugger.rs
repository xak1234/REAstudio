//! Optional x64dbg Automate stdio connection. The debugger outlives this bridge.
use crate::rea::Client;
use anyhow::{bail, Context, Result};
use parking_lot::Mutex;
use serde_json::{json, Value};
use std::{path::Path, sync::atomic::{AtomicU32, Ordering}, time::Duration};

pub const READ_TOOLS: &[&str] = &[
    "get_debugger_status", "get_all_registers", "get_register", "read_memory",
    "get_memory_map", "disassemble", "list_breakpoints", "get_symbol", "get_label", "get_comment",
];
pub const CONTROL_TOOLS: &[&str] = &[
    "go", "pause", "step_into", "step_over", "set_breakpoint", "clear_breakpoint", "toggle_breakpoint",
];

#[derive(Default)]
pub struct DebuggerPlugin {
    client: Mutex<Option<Client>>,
    catalog: Mutex<Vec<Value>>,
    pid: AtomicU32,
}

pub fn text_result(response: &Value) -> String {
    response["content"].as_array().into_iter().flatten()
        .filter_map(|c| c["text"].as_str()).collect::<Vec<_>>().join("\n")
}

/// Automate also reports errors as ordinary text; never turn those into success.
pub fn normalize(mut response: Value) -> Value {
    let text = text_result(&response).to_lowercase();
    if text.starts_with("error:") || text.starts_with("failed ")
        || text.trim_end().ends_with(" failed.") || text.starts_with("evaluation failed") {
        response["isError"] = json!(true);
    }
    response
}

impl DebuggerPlugin {
    pub fn connected(&self) -> bool {
        if let Some(mut guard) = self.client.try_lock() {
            if guard.as_mut().is_some_and(|client| !client.running()) {
                *guard = None;
                self.pid.store(0, Ordering::Release);
                self.catalog.lock().clear();
            }
        }
        self.pid.load(Ordering::Acquire) != 0
    }
    pub fn tools(&self, read_only: bool) -> Vec<Value> {
        self.catalog.lock().iter().filter(|t| t["name"].as_str().is_some_and(|name|
            READ_TOOLS.contains(&name) || (!read_only && CONTROL_TOOLS.contains(&name))))
            .cloned().collect()
    }
    pub fn connect(&self, server: &Path, debugger: &Path) -> Result<()> {
        let mut guard = self.client.lock();
        if guard.is_some() { return Ok(()); }
        let mut command = quixi_platform::background_command(server);
        command.env("X64DBG_PATH", debugger).env("X64DBG_MCP_MAX_RESPONSE_CHARS", "48000");
        let mut client = Client::spawn(command, false)?;
        let mut tools = vec![];
        let mut params = json!({});
        loop {
            let page = client.request("tools/list", params, Duration::from_secs(30))?;
            tools.extend(page["tools"].as_array().context("Invalid debugger catalog")?.iter().cloned());
            if tools.len() > 300 { bail!("Debugger catalog exceeds the supported size"); }
            match page["nextCursor"].as_str() {
                Some(cursor) => params = json!({"cursor":cursor}),
                None => break,
            }
        }
        for name in ["get_debugger_status", "start_session", "connect_to_session", "disconnect"] {
            if !tools.iter().any(|t| t["name"] == name) { bail!("This server does not advertise x64dbg Automate's {name}"); }
        }
        self.pid.store(client.pid(), Ordering::Release);
        *self.catalog.lock() = tools;
        *guard = Some(client);
        Ok(())
    }
    pub fn call(&self, name: &str, arguments: Value) -> Result<Value> {
        let mut guard = self.client.lock();
        let client = guard.as_mut().context("Enable the x64dbg connection in Reverse engineering first")?;
        if !self.catalog.lock().iter().any(|t| t["name"] == name) { bail!("Tool not advertised by the connected debugger"); }
        let result = client.request("tools/call", json!({"name":name,"arguments":arguments}),
            Duration::from_secs(if name == "start_session" { 90 } else { 45 }));
        if result.is_err() {
            *guard = None;
            self.pid.store(0, Ordering::Release);
            self.catalog.lock().clear();
        }
        result.map(normalize)
    }
    pub fn disconnect(&self) {
        let mut guard = self.client.lock();
        if let Some(client) = guard.as_mut() {
            let _ = client.request("tools/call", json!({"name":"disconnect","arguments":{}}), Duration::from_secs(5));
        }
        *guard = None;
        self.pid.store(0, Ordering::Release);
        self.catalog.lock().clear();
    }
    pub fn shutdown(&self) {
        let pid = self.pid.swap(0, Ordering::AcqRel);
        if pid == 0 { return; }
        #[cfg(windows)]
        {
            // Do not use /T: an owned debugger and its debuggee must remain open.
            let _ = quixi_platform::background_command("taskkill.exe")
                .args(["/PID", &pid.to_string(), "/F"])
                .stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null()).status();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn provider_text_failures_are_not_successes() {
        for text in ["Error: Not connected", "Failed to resume.", "Step over failed."] {
            assert_eq!(normalize(json!({"content":[{"type":"text","text":text}]}))["isError"], true);
        }
        assert_ne!(normalize(json!({"content":[{"type":"text","text":"Paused."}]}))["isError"], true);
    }
    #[test]
    fn inspect_tools_do_not_execute_or_attach() {
        for name in ["execute_command", "connect_remote", "start_session", "terminate_session", "write_memory"] {
            assert!(!READ_TOOLS.contains(&name));
            assert!(!CONTROL_TOOLS.contains(&name));
        }
        assert!(!READ_TOOLS.contains(&"go"));
    }
}
