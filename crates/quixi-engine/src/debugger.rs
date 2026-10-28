//! Live debugger observations share the analysis evidence store.
use crate::QuixiEngine;
use anyhow::{bail, Context, Result};
use parking_lot::Mutex;
use quixi_mcp::debugger::{text_result, DebuggerPlugin, CONTROL_TOOLS, READ_TOOLS};
use serde_json::{json, Value};
use std::{fs, path::Path};

#[derive(Default)]
pub struct DebuggerWorkspace {
    pub plugin: DebuggerPlugin,
    operation: Mutex<()>,
    session: Mutex<bool>,
}

fn debuggee_pid(status: &Value) -> Option<u32> {
    if status["isError"] == true { return None; }
    text_result(status).lines().find_map(|line| line.strip_prefix("Debuggee PID: ")?.trim().parse::<u32>().ok()).filter(|pid| *pid > 0)
}
fn process_path(pid: u32) -> Result<String> {
    if !cfg!(windows) { bail!("Live x64dbg analysis requires Windows"); }
    let output = quixi_platform::background_command("powershell.exe")
        .args(["-NoProfile", "-NonInteractive", "-Command",
            &format!("$ErrorActionPreference='Stop'; [Console]::OutputEncoding=[Text.UTF8Encoding]::new(); (Get-Process -Id {pid}).Path")])
        .output().context("Could not verify the debuggee process")?;
    if !output.status.success() { bail!("The debuggee exited or its executable path is inaccessible"); }
    let path = String::from_utf8(output.stdout)?.trim().to_owned();
    if path.is_empty() { bail!("The debugger did not identify a readable target path"); }
    Ok(fs::canonicalize(path)?.to_string_lossy().trim_start_matches("\\\\?\\").to_owned())
}
fn same_target(a: &str, b: &str) -> bool {
    !a.is_empty() && a.replace('/', "\\").trim_start_matches("\\\\?\\").eq_ignore_ascii_case(b.replace('/', "\\").trim_start_matches("\\\\?\\"))
}

fn validate_call(tool: &str, args: &Value, read_only: bool) -> Result<()> {
    if !READ_TOOLS.contains(&tool) && (read_only || !CONTROL_TOOLS.contains(&tool)) {
        bail!("This debugger operation is unavailable in this mode. Ask mode only reads observations; Code mode also controls the selected session.");
    }
    let map = args.as_object().context("Debugger arguments must be an object")?;
    if serde_json::to_vec(args)?.len() > 16_384 { bail!("Debugger arguments exceed 16 KiB"); }
    let bounded = |key: &str, default: u64, maximum: u64| -> Result<()> {
        let value = match map.get(key) { Some(v) => v.as_u64().context("Use a positive integer")?, None => default };
        if value == 0 || value > maximum { bail!("{key} must be between 1 and {maximum}"); }
        Ok(())
    };
    match tool {
        "read_memory" => bounded("size", 256, 8192)?,
        "get_memory_map" => bounded("limit", 200, 200)?,
        "disassemble" => bounded("count", 10, 100)?,
        "step_into" | "step_over" => bounded("count", 1, 100)?,
        _ => (),
    }
    Ok(())
}

impl DebuggerWorkspace {
    /// A session cannot outlive the bridge that selected it.
    fn session_connected(&self) -> bool {
        let mut session = self.session.lock();
        if !self.plugin.connected() {
            *session = false;
        }
        *session
    }
    pub fn status(&self, engine: &QuixiEngine) -> Result<Value> {
        let session = self.session_connected();
        Ok(json!({"connected":self.plugin.connected(), "sessionConnected":session,
            "server":crate::toolchain::path_for(engine,"x64dbg-bridge")?,
            "debugger":crate::toolchain::path_for(engine,"x64dbg")?,
            "tools":self.plugin.tools(false)}))
    }
    pub fn catalog(&self, tool: Option<&str>, read_only: bool) -> Result<Value> {
        if !self.plugin.connected() { bail!("Enable the x64dbg connection in Reverse engineering first"); }
        let tools = self.plugin.tools(read_only);
        if let Some(name) = tool {
            return tools.into_iter().find(|t| t["name"] == name).context("Tool not available in this mode");
        }
        Ok(json!({"connected":true,"tools":tools.iter().map(|t|json!({"name":t["name"],"description":t["description"]})).collect::<Vec<_>>()}))
    }
    pub fn call(&self, engine: &QuixiEngine, tool: &str, args: Value, read_only: bool) -> Result<Value> {
        validate_call(tool, &args, read_only)?;
        let _guard = self.operation.lock();
        let status = self.plugin.call("get_debugger_status", json!({}))?;
        let selected = engine.analysis.target.lock().clone();
        let pid = debuggee_pid(&status);
        let target = pid.map(process_path).transpose()?.unwrap_or_default();
        if tool != "get_debugger_status" {
            if pid.is_none() { bail!("No live debuggee is available. Start a target or connect an existing debugger session."); }
            if !same_target(&selected, &target) { bail!("The debuggee differs from the selected analysis artifact. Select its actual executable before reading or controlling it."); }
        }
        let response = if tool == "get_debugger_status" { status.clone() } else { self.plugin.call(tool, args.clone())? };
        engine.analysis.save_external("x64dbg", "runtime", tool, args, &target, response,
            json!({"debuggeePid":pid,"statusBefore":status,"selectedTarget":selected,
            "limitations":["This is an observation from one debugger session, not whole-program coverage.","Registers and memory can change while the debuggee is running; pause it for a stable observation."]}))
    }
    pub fn handle(&self, engine: &QuixiEngine, route: &str, body: &Value) -> Result<Value> {
        match route {
            "status" => self.status(engine),
            "catalog" => self.catalog(body["tool"].as_str(), body["readOnly"].as_bool().unwrap_or(false)),
            "call" => self.call(engine, body["tool"].as_str().context("Choose a debugger tool")?, body["arguments"].clone(), false),
            "enable" => {
                let _guard = self.operation.lock();
                let server = crate::toolchain::path_for(engine,"x64dbg-bridge")?.context("Install x64dbg Automate or choose its MCP executable in Toolchain")?;
                let debugger = crate::toolchain::path_for(engine,"x64dbg")?.context("Install x64dbg or choose its executable in Toolchain")?;
                self.plugin.connect(Path::new(&server), Path::new(&debugger))?;
                self.status(engine)
            }
            "disable" => {
                let _guard = self.operation.lock();
                self.plugin.disconnect();
                *self.session.lock() = false;
                self.status(engine)
            }
            "sessions" => self.plugin.call("list_sessions", json!({})),
            "start" | "attach" => {
                let _guard = self.operation.lock();
                if self.session_connected() { bail!("Disable the bridge before selecting another debugger session. The existing debugger remains open."); }
                let (tool, args) = if route == "start" {
                    let target = engine.analysis.target.lock().clone();
                    let path = Path::new(&target);
                    if !path.is_absolute() || !path.is_file() { bail!("Select an existing executable artifact first"); }
                    let extension = path.extension().and_then(|s|s.to_str()).unwrap_or("");
                    if !extension.eq_ignore_ascii_case("exe") && !extension.eq_ignore_ascii_case("dll") { bail!("Select a Windows EXE or DLL"); }
                    ("start_session", json!({"target_exe":target,"current_dir":path.parent(),"cmdline":body["cmdline"].as_str().unwrap_or("")}))
                } else {
                    let pid = body["sessionPid"].as_u64().filter(|p|*p>0 && *p<=u32::MAX as u64).context("Enter the PID of an existing x64dbg or x32dbg debugger, not the application PID")?;
                    ("connect_to_session", json!({"session_pid":pid}))
                };
                let response = self.plugin.call(tool, args.clone())?;
                if response["isError"] != true { *self.session.lock() = true; }
                // A start/attach response alone does not establish the target identity.
                let status = if response["isError"] != true { self.plugin.call("get_debugger_status",json!({})).ok() } else { None };
                let pid = status.as_ref().and_then(debuggee_pid);
                let target = pid.map(process_path).transpose()?.unwrap_or_default();
                engine.analysis.save_external("x64dbg","runtime",tool,args,&target,response,json!({"debuggeePid":pid,"statusAfter":status}))
            }
            _ => bail!("Unknown debugger operation"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounds_and_modes_prevent_implicit_execution() {
        assert!(validate_call("go", &json!({}), true).is_err());
        assert!(validate_call("go", &json!({}), false).is_ok());
        assert!(validate_call("execute_command", &json!({"command":"run"}), false).is_err());
        for n in [0,8193] { assert!(validate_call("read_memory", &json!({"size":n}),false).is_err()); }
        assert!(validate_call("read_memory", &json!({"address":"rip","size":32}),true).is_ok());
        assert!(validate_call("get_memory_map", &json!({"limit":0}),true).is_err());
        assert!(same_target("C:/apps/test.exe", "\\\\?\\c:\\apps\\TEST.exe"));
        assert!(!same_target("", ""));
    }
    #[test]
    fn target_identity_comes_from_a_real_status_pid() {
        assert_eq!(debuggee_pid(&json!({"content":[{"text":"Has debuggee: True\nDebuggee PID: 42\nState: paused"}]})),Some(42));
        assert_eq!(debuggee_pid(&json!({"content":[{"text":"Debuggee PID: n/a"}]})),None);
    }
}
