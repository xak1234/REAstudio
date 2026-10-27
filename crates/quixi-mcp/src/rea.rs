//! Bundled REA plugin. One owned MCP process preserves targets and Evidence IDs.
use anyhow::{bail, Context, Result};
use parking_lot::Mutex;
use serde_json::{json, Value};
use std::sync::atomic::{AtomicU32, Ordering};
use std::{
    collections::VecDeque,
    io::{BufRead, BufReader, Read, Write},
    path::{Path, PathBuf},
    process::{Child, ChildStdin, Command, Stdio},
    sync::{mpsc, Arc},
    time::{Duration, Instant},
};

const FRAME_LIMIT: u64 = 16 * 1024 * 1024;
pub const AGENT_TOOLS: &[&str] = &[
    "binary_session",
    "open_binary",
    "close_binary",
    "binary_overview",
    "inspect_artifact",
    "inspect_pe_resources",
    "inspect_pe_imports",
    "inspect_native_exports",
    "inspect_managed_artifact",
    "inspect_managed_members",
    "inspect_managed_native_boundaries",
    "project_managed_application_graph",
    "inspect_android_package",
    "search_android_classes",
    "inspect_android_class",
    "inspect_android_method",
    "trace_android_references",
    "inspect_web_network_capture",
    "inspect_rust_binary",
    "inspect_go_binary",
    "analyze_javascript_application",
    "inspect_analysis_view",
    "trace_application_feature",
    "trace_feature",
    "list_procedures",
    "list_strings",
    "search_strings",
    "search_procedures",
    "get_procedure",
    "procedure_pseudo_code",
    "procedure_info",
    "procedure_references",
    "procedure_assembly",
    "analyze_function",
    "procedure_list",
    "procedure_address",
    "procedure_name",
    "procedure_callers",
    "procedure_callees",
    "inspect_native_api",
    "inspect_native_instruction",
    "read_function_instructions",
    "get_call_graph",
    "trace_call_path",
    "get_xrefs",
    "get_evidence_bundle",
    "read_bytes",
    "search_bytes",
    "find_xrefs_to_name",
    "list_imports",
    "list_exports",
];

struct Client {
    child: Child,
    input: ChildStdin,
    responses: mpsc::Receiver<Result<Value, String>>,
    stderr: Arc<Mutex<VecDeque<String>>>,
    id: u64,
}
impl Client {
    fn start(root: &Path, mode: &str) -> Result<Self> {
        let node = root.join(if cfg!(windows) {
            "node/node.exe"
        } else {
            "node/bin/node"
        });
        let script = root.join("node_modules/rea-agents/scripts/rea.mjs");
        let mut command = if mode == "installed" {
            let wrapper = installed_wrapper();
            if !wrapper.is_file() {
                bail!(
                    "The existing REA wrapper was not found at {}",
                    wrapper.display()
                );
            }
            #[cfg(windows)]
            {
                use std::os::windows::process::CommandExt;
                let text = wrapper.to_string_lossy();
                if text.contains(['"', '%', '\r', '\n']) {
                    bail!("REA wrapper path contains unsupported shell characters");
                }
                let mut command = Command::new("cmd.exe");
                command
                    .args(["/d", "/s", "/c"])
                    .raw_arg(format!("\"\"{}\" mcp\"", text));
                command
            }
            #[cfg(not(windows))]
            {
                let mut command = Command::new(wrapper);
                command.arg("mcp");
                command
            }
        } else {
            if !node.is_file() || !script.is_file() {
                bail!("Bundled REA files are missing. Run scripts/package-windows.ps1 to prepare the complete application.");
            }
            let mut command = Command::new(&node);
            command.arg(script).arg("mcp").current_dir(root);
            command
        };
        command
            .env("REA_MCP_INPUT_SCHEMA_PROFILE", "compact")
            .env("REA_MCP_OUTPUT_SCHEMA_PROFILE", "off")
            .env("REA_MCP_MAX_RESPONSE_BYTES", "10485760")
            .env("REA_GHIDRA_STARTUP_TIMEOUT_MS", "540000")
            .env("GHIDRA_HEADLESS_MAXMEM", "1536M")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if mode == "bundled" && root.join("ghidra/Ghidra/application.properties").is_file() {
            command.env("GHIDRA_INSTALL_DIR", root.join("ghidra"));
        }
        if mode == "bundled" && root.join("jdk").is_dir() {
            command.env("JAVA_HOME", root.join("jdk"));
        }
        if mode == "bundled" && std::env::var_os("REA_JADX_MCP_JAR").is_none() {
            if let Some(resources) = root.parent().and_then(Path::parent) {
                let jar = resources.join("toolchain/jadx-mcp/jadx-headless-mcp-0.7.1-all.jar");
                if jar.is_file() {
                    command.env("REA_JADX_MCP_JAR", jar);
                }
            }
        }
        if let Ok(bytes) =
            std::fs::read(quixi_platform::app_data_dir().join("toolchain-paths.json"))
        {
            if let Ok(paths) = serde_json::from_slice::<Value>(&bytes) {
                for (id, key) in [
                    ("ida", "REA_IDA_MCP_CONFIG"),
                    ("jadx-mcp", "REA_JADX_MCP_JAR"),
                ] {
                    if let Some(path) = paths[id].as_str() {
                        command.env(key, path.trim_start_matches("\\\\?\\"));
                    }
                }
            }
        }
        let mut paths = vec![node.parent().unwrap().to_path_buf(), root.join("jdk/bin")];
        // App-local VC runtime DLLs also serve Ghidra's native child processes.
        if let Some(app_root) = root.ancestors().nth(3) {
            paths.push(app_root.to_path_buf());
        }
        paths.extend(std::env::split_paths(
            &std::env::var_os("PATH").unwrap_or_default(),
        ));
        if mode == "bundled" {
            command.env("PATH", std::env::join_paths(paths)?);
        }
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            command.creation_flags(0x08000000);
        }
        let mut child = command.spawn().context("Could not launch bundled REA")?;
        let input = child.stdin.take().context("REA stdin unavailable")?;
        let stdout = child.stdout.take().context("REA stdout unavailable")?;
        let stderr_pipe = child.stderr.take().context("REA stderr unavailable")?;
        let (tx, responses) = mpsc::sync_channel(32);
        std::thread::spawn(move || {
            let mut reader = BufReader::new(stdout);
            loop {
                let mut line = String::new();
                let result = reader.by_ref().take(FRAME_LIMIT + 1).read_line(&mut line);
                match result {
                    Ok(0) => break,
                    Ok(n) if n as u64 > FRAME_LIMIT => {
                        let _ = tx.send(Err("REA response exceeded the transport limit".into()));
                        break;
                    }
                    Ok(_) => {
                        if line.trim().is_empty() {
                            continue;
                        }
                        let value = serde_json::from_str(&line)
                            .map_err(|e| format!("Invalid MCP response: {e}"));
                        if tx.send(value).is_err() {
                            break;
                        }
                    }
                    Err(error) => {
                        let _ = tx.send(Err(error.to_string()));
                        break;
                    }
                }
            }
        });
        let stderr = Arc::new(Mutex::new(VecDeque::new()));
        let captured = stderr.clone();
        std::thread::spawn(move || {
            let mut reader = BufReader::new(stderr_pipe);
            loop {
                let mut line = String::new();
                match reader.by_ref().take(8192).read_line(&mut line) {
                    Ok(0) | Err(_) => break,
                    Ok(_) => {
                        let mut tail = captured.lock();
                        tail.push_back(line);
                        if tail.len() > 30 {
                            tail.pop_front();
                        }
                    }
                }
            }
        });
        let mut client = Self {
            child,
            input,
            responses,
            stderr,
            id: 0,
        };
        let initialized = client.request(
            "initialize",
            json!({"protocolVersion":"2025-03-26", "capabilities":{},
            "clientInfo":{"name":"QuixiDesk REA workspace","version":"1.0.0"}}),
            Duration::from_secs(45),
        )?;
        if initialized.get("protocolVersion").is_none() {
            bail!("REA returned an invalid initialization response");
        }
        client.send(json!({"jsonrpc":"2.0","method":"notifications/initialized"}))?;
        Ok(client)
    }
    fn send(&mut self, value: Value) -> Result<()> {
        serde_json::to_writer(&mut self.input, &value)?;
        self.input.write_all(b"\n")?;
        self.input.flush()?;
        Ok(())
    }
    fn request(&mut self, method: &str, params: Value, timeout: Duration) -> Result<Value> {
        self.id += 1;
        let id = self.id;
        self.send(json!({"jsonrpc":"2.0","id":id,"method":method,"params":params}))?;
        let deadline = Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let message = self
                .responses
                .recv_timeout(remaining)
                .map_err(|e| {
                    anyhow::anyhow!(
                "REA connection ended or timed out ({e}). Reconnect to start a new session. {}",
                self.stderr.lock().iter().cloned().collect::<String>())
                })?
                .map_err(anyhow::Error::msg)?;
            if let Some(method) = message.get("method").and_then(Value::as_str) {
                if let Some(request_id) = message.get("id") {
                    // This client does not advertise sampling, roots or elicitation.
                    if method == "ping" {
                        self.send(json!({"jsonrpc":"2.0","id":request_id,"result":{}}))?;
                    } else {
                        self.send(json!({"jsonrpc":"2.0","id":request_id,"error":{"code":-32601,"message":"Client method not supported"}}))?;
                    }
                }
                continue;
            }
            if message.get("id").and_then(Value::as_u64) != Some(id) {
                continue;
            }
            if let Some(error) = message.get("error") {
                bail!("REA: {error}");
            }
            return message
                .get("result")
                .cloned()
                .context("MCP result is missing");
        }
    }
    fn tool(&mut self, name: &str, arguments: Value) -> Result<Value> {
        self.request(
            "tools/call",
            json!({"name":name,"arguments":arguments}),
            Duration::from_secs(600),
        )
    }
}
impl Drop for Client {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_some() {
            return;
        }
        // Closing stdin alone can leave a Ghidra JVM alive. Terminate the owned tree.
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            let _ = Command::new("taskkill.exe")
                .args(["/PID", &self.child.id().to_string(), "/T", "/F"])
                .creation_flags(0x08000000)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// The MCP envelope is retained in full; this helper only projects its JSON payload.
pub fn payload(result: &Value) -> Value {
    if let Some(value) = result.get("structuredContent") {
        return value.clone();
    }
    result["content"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|v| v.get("text").and_then(Value::as_str))
        .find_map(|text| serde_json::from_str(text).ok())
        .unwrap_or_else(|| result.clone())
}

fn installed_wrapper() -> PathBuf {
    dirs::home_dir()
        .unwrap_or_else(std::env::temp_dir)
        .join(if cfg!(windows) {
            ".local/bin/rea.cmd"
        } else {
            ".local/bin/rea"
        })
}
fn preference_path() -> PathBuf {
    quixi_platform::app_data_dir().join("rea-plugin.json")
}
pub struct ReaPlugin {
    root: PathBuf,
    client: Mutex<Option<Client>>,
    catalog: Mutex<Vec<Value>>,
    pid: AtomicU32,
    mode: Mutex<String>,
}
impl ReaPlugin {
    pub fn workflow(&self, request: &Value) -> Result<Value> {
        let name = request["path"].as_str().unwrap_or("SKILL.md");
        let guides = [
            "SKILL.md",
            "references/android-applications.md",
            "references/connection-and-recovery.md",
            "references/environments.md",
            "references/evidence-workflows.md",
            "references/javascript-applications.md",
            "references/native-and-artifacts.md",
            "references/runtime-observation.md",
        ];
        if !guides.contains(&name) {
            bail!("Choose a bundled REA workflow from the returned guide list");
        }
        let root = self
            .root
            .join("node_modules/rea-agents/skills/reverse-engineer-anything");
        let text = String::from_utf8(quixi_platform::SafeFs::read_file_beneath(
            &root,
            Path::new(name),
        )?)?;
        let offset = request["offset"].as_u64().unwrap_or(0) as usize;
        let limit = request["limit"].as_u64().unwrap_or(12_000).clamp(1, 16_000) as usize;
        let total = text.chars().count();
        Ok(
            json!({"package":"rea-agents","version":"6.8.0","path":name,"guides":guides,
            "content":text.chars().skip(offset).take(limit).collect::<String>(),"totalCharacters":total,
            "nextOffset":offset.saturating_add(limit).min(total),"partial":offset>0||total>limit,
            "note":"These are the bundled version's workflows. The connected runtime's live tool schemas and availability take precedence."}),
        )
    }
    pub fn status(&self) -> Value {
        let connected = self.pid.load(Ordering::Acquire) != 0;
        json!({"name":"rea", "uuid":"quixi-bundled-rea", "isInternal":false,
            "serverSource":"bundled_plugin", "builtin":true, "transport":"stdio",
            "isConnected":connected,"status":if connected {"connected"} else {"disconnected"},
            "toolsEnumerated":connected, "tools":if connected { self.catalog.lock().clone() } else {vec![]},
            "resources":[],"prompts":[]})
    }
    pub fn is_connected(&self) -> bool {
        self.pid.load(Ordering::Acquire) != 0
    }
    pub fn new(resources: &Path) -> Self {
        let mode = std::fs::read(preference_path())
            .ok()
            .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
            .and_then(|v| {
                v["mode"]
                    .as_str()
                    .filter(|s| matches!(*s, "bundled" | "installed"))
                    .map(str::to_owned)
            })
            .unwrap_or_else(|| "bundled".into());
        Self {
            mode: Mutex::new(mode),
            root: resources.join("plugins/rea"),
            client: Mutex::new(None),
            catalog: Mutex::new(vec![]),
            pid: AtomicU32::new(0),
        }
    }
    pub fn connect(&self, requested_mode: Option<&str>) -> Result<Value> {
        if let Some(mode) = requested_mode {
            if !matches!(mode, "bundled" | "installed") {
                bail!("Unknown REA runtime");
            }
            if *self.mode.lock() != mode {
                self.disconnect()?;
                *self.mode.lock() = mode.into();
                std::fs::write(
                    preference_path(),
                    serde_json::to_vec_pretty(&json!({"mode":mode}))?,
                )?;
            }
        }
        let mode = self.mode.lock().clone();
        let mut guard = self.client.lock();
        if guard.is_none() {
            let mut client = Client::start(&self.root, &mode)?;
            let mut tools = vec![];
            let mut params = json!({});
            for _ in 0..100 {
                let page = client.request("tools/list", params, Duration::from_secs(45))?;
                tools.extend(
                    page["tools"]
                        .as_array()
                        .context("Invalid REA tool catalog")?
                        .iter()
                        .cloned(),
                );
                match page.get("nextCursor").and_then(Value::as_str) {
                    Some(cursor) => params = json!({"cursor":cursor}),
                    None => break,
                }
            }
            *self.catalog.lock() = tools;
            self.pid.store(client.child.id(), Ordering::Release);
            *guard = Some(client);
        }
        let supports_detail = self
            .catalog
            .lock()
            .iter()
            .find(|t| t["name"] == "binary_session")
            .and_then(|t| t.pointer("/inputSchema/properties/detail"))
            .is_some();
        let session = guard.as_mut().unwrap().tool(
            "binary_session",
            if supports_detail {
                json!({"detail":"complete"})
            } else {
                json!({})
            },
        );
        match session {
            Ok(session) if session["isError"] == true => {
                bail!("REA session inspection failed: {}", payload(&session))
            }
            Ok(session) => Ok(
                json!({"connected":true,"mode":mode,"installedWrapper":installed_wrapper(),"session":payload(&session),"tools":*self.catalog.lock()}),
            ),
            Err(error) => {
                *guard = None;
                self.pid.store(0, Ordering::Release);
                Err(error)
            }
        }
    }
    pub fn disconnect(&self) -> Result<()> {
        let mut guard = self.client.lock();
        if let Some(client) = guard.as_mut() {
            let _ = client.tool("close_binary", json!({}));
        }
        *guard = None;
        self.pid.store(0, Ordering::Release);
        self.catalog.lock().clear();
        Ok(())
    }
    pub fn shutdown(&self) {
        let pid = self.pid.swap(0, Ordering::AcqRel);
        if pid == 0 {
            return;
        }
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            let _ = Command::new("taskkill.exe")
                .args(["/PID", &pid.to_string(), "/T", "/F"])
                .creation_flags(0x08000000)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
        if let Some(mut guard) = self.client.try_lock() {
            *guard = None;
        }
    }
    pub fn call(&self, name: &str, args: Value) -> Result<Value> {
        if !args.is_object() {
            bail!("Tool arguments must be a JSON object");
        }
        if !self.catalog.lock().iter().any(|t| t["name"] == name) {
            bail!("Tool is not advertised by the connected REA server: {name}");
        }
        let mut guard = self.client.lock();
        let client = guard
            .as_mut()
            .context("Connect the bundled REA plugin first")?;
        match client.tool(name, args) {
            Ok(value) => Ok(value),
            Err(error) => {
                *guard = None;
                self.pid.store(0, Ordering::Release);
                Err(error)
            }
        }
    }
    pub fn agent_tools(&self) -> Vec<Value> {
        self.catalog.lock().iter().filter(|t| t["name"].as_str().map(|n| AGENT_TOOLS.contains(&n)).unwrap_or(false))
            .map(|t| json!({"name":t["name"],"description":t["description"],"inputSchema":t["inputSchema"]})).collect()
    }
}
