//! Bundled REA plugin. One owned MCP process preserves targets and Evidence IDs.
use anyhow::{bail, Context, Result};
use parking_lot::Mutex;
use quixi_platform::ProcessJob;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::{
    collections::VecDeque,
    io::{BufRead, BufReader, Read, Write},
    path::{Path, PathBuf},
    process::{Child, ChildStdin, Command, Stdio},
    sync::{mpsc, Arc},
    time::{Duration, Instant},
};

const FRAME_LIMIT: u64 = 16 * 1024 * 1024;
/// Ghidra's first import may use most of REA_GHIDRA_STARTUP_TIMEOUT_MS before analysis starts.
const DEFAULT_CALL_TIMEOUT_SECS: u64 = 1800;
const CLOSE_TIMEOUT: Duration = Duration::from_secs(30);
const SESSION_TIMEOUT: Duration = Duration::from_secs(120);
const DIAGNOSTIC_LINES: usize = 30;

#[derive(Clone, Debug, Deserialize, PartialEq, Eq, Serialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
struct RuntimeSettings {
    mode: String,
    #[serde(rename = "ghidraHeapMiB")]
    ghidra_heap_mib: u32,
    ghidra_startup_timeout_secs: u64,
    call_timeout_secs: u64,
}

impl Default for RuntimeSettings {
    fn default() -> Self {
        Self {
            mode: "bundled".into(),
            ghidra_heap_mib: 4096,
            ghidra_startup_timeout_secs: 900,
            call_timeout_secs: DEFAULT_CALL_TIMEOUT_SECS,
        }
    }
}

impl RuntimeSettings {
    fn validate(&self) -> Result<()> {
        if !matches!(self.mode.as_str(), "bundled" | "installed") {
            bail!("Unknown REA runtime; choose bundled or installed");
        }
        if !(512..=65536).contains(&self.ghidra_heap_mib) {
            bail!("Ghidra heap must be between 512 and 65536 MiB");
        }
        if !(60..=7200).contains(&self.ghidra_startup_timeout_secs) {
            bail!("Ghidra startup timeout must be between 60 and 7200 seconds");
        }
        if !(30..=14400).contains(&self.call_timeout_secs) {
            bail!("REA call timeout must be between 30 and 14400 seconds");
        }
        if self.call_timeout_secs < self.ghidra_startup_timeout_secs {
            bail!("REA call timeout must be at least the Ghidra startup timeout");
        }
        Ok(())
    }

    fn patched(&self, patch: &Value) -> Result<Self> {
        let patch = patch
            .as_object()
            .context("REA settings must be a JSON object")?;
        let mut value = serde_json::to_value(self)?;
        let object = value.as_object_mut().context("Invalid REA settings")?;
        for (key, value) in patch {
            object.insert(key.clone(), value.clone());
        }
        let settings: Self =
            serde_json::from_value(value).context("Invalid REA runtime settings")?;
        settings.validate()?;
        Ok(settings)
    }

    fn load(path: &Path) -> Result<Self> {
        let bytes = match std::fs::read(path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                return Ok(Self::default())
            }
            Err(error) => return Err(error.into()),
        };
        let settings: Self =
            serde_json::from_slice(&bytes).context("Could not parse REA settings")?;
        settings.validate()?;
        Ok(settings)
    }

    fn save(&self, path: &Path) -> Result<()> {
        self.validate()?;
        let parent = path
            .parent()
            .context("REA settings have no parent directory")?;
        let name = path.file_name().context("REA settings have no file name")?;
        std::fs::create_dir_all(parent)?;
        quixi_platform::SafeFs::write_file_beneath(
            parent,
            Path::new(name),
            &serde_json::to_vec_pretty(self)?,
        )
        .context("Could not save REA runtime settings")
    }

    fn apply_environment(&self, command: &mut Command) {
        command
            .env(
                "REA_GHIDRA_STARTUP_TIMEOUT_MS",
                (self.ghidra_startup_timeout_secs * 1000).to_string(),
            )
            .env(
                "GHIDRA_HEADLESS_MAXMEM",
                format!("{}M", self.ghidra_heap_mib),
            );
    }
}

fn timeout_override(value: Option<&str>) -> Option<u64> {
    value
        .and_then(|v| v.trim().parse::<u64>().ok())
        .filter(|secs| (30..=14400).contains(secs))
}

fn configured_call_timeout(settings: &RuntimeSettings) -> Duration {
    Duration::from_secs(
        timeout_override(std::env::var("QUIXI_REA_CALL_TIMEOUT_SECS").ok().as_deref())
            .unwrap_or(settings.call_timeout_secs),
    )
}

/// Legacy default budget; a plugin's calls use its persisted settings instead.
pub fn call_timeout() -> Duration {
    configured_call_timeout(&RuntimeSettings::default())
}

/// Names must exist in REA 6.8.0's catalog (resources/plugins/rea/tool-catalog-6.8.0.txt).
/// Annotation tools edit only REA's ephemeral session database, never the artifact.
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
    "procedure_pseudo_code",
    "procedure_info",
    "procedure_references",
    "procedure_assembly",
    "analyze_function",
    "procedure_address",
    "procedure_callers",
    "procedure_callees",
    "inspect_native_api",
    "inspect_native_instruction",
    "read_function_instructions",
    "get_call_graph",
    "trace_call_path",
    "get_evidence_bundle",
    "read_bytes",
    "search_bytes",
    "find_xrefs_to_name",
    "xrefs",
    "list_names",
    "list_segments",
    "resolve_containing_procedure",
    "batch_decompile",
    "inspect_address_context",
    "address_name",
    "set_address_name",
    "set_addresses_names",
    "set_comment",
    "set_inline_comment",
    "set_bookmark",
    "list_bookmarks",
];

pub(crate) struct Client {
    child: Child,
    job: Option<Arc<ProcessJob>>,
    input: ChildStdin,
    responses: mpsc::Receiver<Result<Value, String>>,
    stderr: Arc<Mutex<VecDeque<String>>>,
    id: u64,
    terminate_tree: bool,
    /// Requests cancelled after a timeout; their late replies are discarded.
    abandoned: VecDeque<u64>,
    /// The transport ended or failed. Only then is the session unusable.
    broken: bool,
    server_info: Value,
}
impl Client {
    pub(crate) fn pid(&self) -> u32 {
        self.child.id()
    }
    pub(crate) fn running(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }
    pub(crate) fn usable(&mut self) -> bool {
        !self.broken && self.running()
    }
    fn job(&self) -> Option<Arc<ProcessJob>> {
        self.job.clone()
    }
    fn diagnostics(&self) -> String {
        self.stderr.lock().iter().cloned().collect()
    }
    fn start(root: &Path, settings: &RuntimeSettings) -> Result<Self> {
        settings.validate()?;
        let mode = settings.mode.as_str();
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
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        settings.apply_environment(&mut command);
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
        Self::spawn(command, true)
    }
    pub(crate) fn spawn(mut command: Command, terminate_tree: bool) -> Result<Self> {
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = command.spawn().context("Could not launch MCP provider")?;
        // A kill-on-close job ends node and its Ghidra JVM even if node crashes first.
        // Bridges that must leave their debugger running (terminate_tree=false) stay outside.
        let job = if terminate_tree {
            match ProcessJob::assign(&child) {
                Ok(job) => Some(Arc::new(job)),
                Err(error) => {
                    tracing::warn!("MCP provider process tree is not job-owned: {error:#}");
                    None
                }
            }
        } else {
            None
        };
        let input = child.stdin.take().context("REA stdin unavailable")?;
        let stdout = child.stdout.take().context("REA stdout unavailable")?;
        let stderr_pipe = child.stderr.take().context("REA stderr unavailable")?;
        let stderr = Arc::new(Mutex::new(VecDeque::new()));
        let noise = stderr.clone();
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
                        match serde_json::from_str(&line) {
                            Ok(value) => {
                                if tx.send(Ok(value)).is_err() {
                                    break;
                                }
                            }
                            // Stray stdout output (a log line, a banner) is not a frame.
                            // Keep it for diagnostics; only EOF or an I/O error is fatal.
                            Err(error) => {
                                let excerpt: String = line.trim_end().chars().take(400).collect();
                                tracing::debug!("Skipped non-JSON MCP stdout line: {error}");
                                push_diagnostic(&noise, format!("[stdout, not JSON] {excerpt}\n"));
                            }
                        }
                    }
                    Err(error) => {
                        let _ = tx.send(Err(error.to_string()));
                        break;
                    }
                }
            }
        });
        let captured = stderr.clone();
        std::thread::spawn(move || {
            let mut reader = BufReader::new(stderr_pipe);
            loop {
                let mut line = String::new();
                match reader.by_ref().take(8192).read_line(&mut line) {
                    Ok(0) | Err(_) => break,
                    Ok(_) => push_diagnostic(&captured, line),
                }
            }
        });
        let mut client = Self {
            child,
            job,
            input,
            responses,
            stderr,
            id: 0,
            terminate_tree,
            abandoned: VecDeque::new(),
            broken: false,
            server_info: Value::Null,
        };
        let initialized = client.request(
            "initialize",
            json!({"protocolVersion":"2025-03-26", "capabilities":{},
            "clientInfo":{"name":"REA Studio","version":env!("CARGO_PKG_VERSION")}}),
            Duration::from_secs(45),
        )?;
        if initialized.get("protocolVersion").is_none() {
            bail!("REA returned an invalid initialization response");
        }
        client.server_info = initialized
            .get("serverInfo")
            .cloned()
            .unwrap_or(Value::Null);
        client.send(json!({"jsonrpc":"2.0","method":"notifications/initialized"}))?;
        Ok(client)
    }
    /// Any write failure means the pipe is gone; the session cannot recover.
    fn send(&mut self, value: Value) -> Result<()> {
        let written = (|| -> Result<()> {
            serde_json::to_writer(&mut self.input, &value)?;
            self.input.write_all(b"\n")?;
            self.input.flush()?;
            Ok(())
        })();
        if written.is_err() {
            self.broken = true;
        }
        written
    }
    pub(crate) fn request(
        &mut self,
        method: &str,
        params: Value,
        timeout: Duration,
    ) -> Result<Value> {
        if self.broken {
            bail!("The MCP connection has ended. Reconnect before continuing.");
        }
        self.id += 1;
        let id = self.id;
        self.send(json!({"jsonrpc":"2.0","id":id,"method":method,"params":params}))
            .context("Could not send the MCP request")?;
        let deadline = Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let message = match self.responses.recv_timeout(remaining) {
                Ok(Ok(message)) => message,
                Ok(Err(error)) => {
                    self.broken = true;
                    bail!("MCP connection failed ({error}). Reconnect before continuing; the last operation may have completed. {}", self.diagnostics())
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    self.broken = true;
                    bail!("MCP connection ended. Reconnect before continuing; the last operation may have completed. {}", self.diagnostics())
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    // Cancel only this request. The process, its open target and
                    // retained Evidence IDs stay available for the next call.
                    let reason = format!(
                        "REA Studio stopped waiting for {method} after {} s",
                        timeout.as_secs()
                    );
                    let _ = self.send(json!({"jsonrpc":"2.0","method":"notifications/cancelled",
                        "params":{"requestId":id,"reason":reason}}));
                    self.abandoned.push_back(id);
                    if self.abandoned.len() > 256 {
                        self.abandoned.pop_front();
                    }
                    if self.broken {
                        bail!("{reason}, and the connection has ended. Reconnect before continuing. {}", self.diagnostics());
                    }
                    bail!("{reason}. The request was cancelled and the session was kept; retry with a narrower request or a longer timeout.");
                }
            };
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
            let response_id = message.get("id").and_then(Value::as_u64);
            if response_id != Some(id) {
                // A late reply to a cancelled request is not this request's answer.
                if let Some(position) = self.abandoned.iter().position(|a| Some(*a) == response_id)
                {
                    self.abandoned.remove(position);
                }
                continue;
            }
            if let Some(error) = message.get("error") {
                bail!("MCP provider: {error}");
            }
            return message
                .get("result")
                .cloned()
                .context("MCP result is missing");
        }
    }
    fn tool(&mut self, name: &str, arguments: Value, timeout: Duration) -> Result<Value> {
        self.request(
            "tools/call",
            json!({"name":name,"arguments":arguments}),
            timeout,
        )
    }
}
fn push_diagnostic(tail: &Mutex<VecDeque<String>>, line: String) {
    let mut tail = tail.lock();
    tail.push_back(line);
    while tail.len() > DIAGNOSTIC_LINES {
        tail.pop_front();
    }
}
impl Drop for Client {
    fn drop(&mut self) {
        // The job reaches descendants (Ghidra JVM) even after node itself has exited.
        if let Some(job) = &self.job {
            job.terminate();
        }
        if self.child.try_wait().ok().flatten().is_some() {
            return;
        }
        // Without a job, closing stdin alone can leave a Ghidra JVM alive.
        #[cfg(windows)]
        if self.terminate_tree && self.job.is_none() {
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
    preferences: PathBuf,
    client: Mutex<Option<Client>>,
    catalog: Mutex<Vec<Value>>,
    pid: AtomicU32,
    settings: Mutex<RuntimeSettings>,
    settings_error: Mutex<Option<String>>,
    /// Serializes startup with configuration changes, without blocking disconnect.
    configuration: Mutex<()>,
    server_info: Mutex<Value>,
    /// The live process tree, reachable while a call holds `client`, so
    /// disconnect and shutdown can end it immediately.
    process: Mutex<Option<(u32, Option<Arc<ProcessJob>>)>>,
    /// Incremented by disconnect/shutdown so a racing connect does not respawn.
    generation: AtomicU64,
}
impl ReaPlugin {
    fn runtime_metadata(&self, settings: &RuntimeSettings, connected: bool) -> Value {
        let manifest = std::fs::read(self.root.join("plugin.json"))
            .ok()
            .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
            .unwrap_or(Value::Null);
        let bundled_rea = std::fs::read(self.root.join("node_modules/rea-agents/package.json"))
            .ok()
            .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
            .and_then(|package| package["version"].as_str().map(str::to_owned));
        let server_info = if connected {
            self.server_info.lock().clone()
        } else {
            Value::Null
        };
        let mut warnings = Vec::new();
        if settings.mode == "installed" {
            warnings.push("External REA runtime selected. Bundled component versions do not describe the external launcher; use the connected server identity and returned analysis provenance.");
        }
        if let (Some(actual), Some(bundled)) =
            (server_info["version"].as_str(), bundled_rea.as_deref())
        {
            if actual != bundled {
                warnings.push("The connected REA version differs from the bundled version. Live tool schemas take precedence over bundled guides.");
            }
        }
        let override_value = std::env::var("QUIXI_REA_CALL_TIMEOUT_SECS").ok();
        let override_secs = timeout_override(override_value.as_deref());
        if override_value.is_some() && override_secs.is_none() {
            warnings.push(
                "QUIXI_REA_CALL_TIMEOUT_SECS is invalid; the saved call timeout is being used.",
            );
        }
        if configured_call_timeout(settings).as_secs() < settings.ghidra_startup_timeout_secs {
            warnings.push("The environment call timeout is shorter than the Ghidra startup timeout and can cancel a cold import early.");
        }
        json!({"mode":settings.mode,"serverInfo":server_info,
            "bundled":{"rea":bundled_rea,"declaredComponents":manifest["runtime"]},
            "catalogTools":if connected {self.catalog.lock().len()} else {0},
            "catalogStatus":if connected {"live"} else {"not_connected"},
            "effectiveCallTimeoutSecs":configured_call_timeout(settings).as_secs(),
            "callTimeoutSource":if override_secs.is_some(){"environment"}else{"settings"},
            "warnings":warnings})
    }

    /// Reading settings never starts an analysis process.
    pub fn runtime_settings(&self) -> Value {
        let connected = self.is_connected();
        let settings = self.settings.lock().clone();
        json!({"settings":settings,"settingsError":*self.settings_error.lock(),
            "connected":connected,"runtime":self.runtime_metadata(&settings,connected),
            "limits":{"ghidraHeapMiB":{"min":512,"max":65536},
                "ghidraStartupTimeoutSecs":{"min":60,"max":7200},
                "callTimeoutSecs":{"min":30,"max":14400}}})
    }

    /// Validate and atomically persist a partial settings update. A changed
    /// configuration ends the old session, so no call runs with mixed settings.
    pub fn configure(&self, patch: &Value) -> Result<Value> {
        let _configuration = self.configuration.try_lock()
            .context("REA is connecting or changing settings. Disconnect it, then retry the settings change.")?;
        let previous = self.settings.lock().clone();
        let next = previous.patched(patch)?;
        let changed = previous != next || self.settings_error.lock().is_some();
        if changed {
            // A failed disk write leaves the current runtime and settings intact.
            next.save(&self.preferences)?;
            self.disconnect()?;
            *self.settings.lock() = next;
            *self.settings_error.lock() = None;
        }
        let mut response = self.runtime_settings();
        response["changed"] = json!(changed);
        response["reconnectRequired"] = json!(changed);
        Ok(response)
    }

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
            "unpack-packed-binary/SKILL.md",
        ];
        if !guides.contains(&name) {
            bail!("Choose a bundled REA workflow from the returned guide list");
        }
        let studio_guide = name == "unpack-packed-binary/SKILL.md";
        let root = self.root.join(if studio_guide {
            "node_modules/rea-agents/skills"
        } else {
            "node_modules/rea-agents/skills/reverse-engineer-anything"
        });
        let text = String::from_utf8(quixi_platform::SafeFs::read_file_beneath(
            &root,
            Path::new(name),
        )?)?;
        let offset = request["offset"].as_u64().unwrap_or(0) as usize;
        let limit = request["limit"].as_u64().unwrap_or(12_000).clamp(1, 16_000) as usize;
        let total = text.chars().count();
        Ok(
            json!({"package":if studio_guide {"rea-studio"} else {"rea-agents"},
            "version":if studio_guide {env!("CARGO_PKG_VERSION")} else {"6.8.0"},"path":name,"guides":guides,
            "content":text.chars().skip(offset).take(limit).collect::<String>(),"totalCharacters":total,
            "nextOffset":offset.saturating_add(limit).min(total),"partial":offset>0||total>limit,
            "note":"These are the bundled version's workflows. The connected runtime's live tool schemas and availability take precedence."}),
        )
    }
    pub fn status(&self) -> Value {
        let connected = self.is_connected();
        let settings = self.settings.lock().clone();
        let tools = if connected {
            self.catalog.lock().clone()
        } else {
            vec![]
        };
        let runtime = self.runtime_metadata(&settings, connected);
        json!({"name":"rea", "uuid":"quixi-bundled-rea", "isInternal":false,
            "serverSource":if settings.mode == "bundled" {"bundled_plugin"} else {"installed_launcher"}, "builtin":true, "transport":"stdio",
            "isConnected":connected,"status":if connected {"connected"} else {"disconnected"},
            "toolsEnumerated":connected, "tools":tools,
            "settings":settings,"settingsError":*self.settings_error.lock(),
            "runtime":runtime,"resources":[],"prompts":[]})
    }
    pub fn is_connected(&self) -> bool {
        // A busy request owns the client lock; never block UI status on analysis.
        if let Some(mut guard) = self.client.try_lock() {
            if guard.as_mut().is_some_and(|client| !client.usable()) {
                self.forget_client(&mut guard);
            }
        }
        self.pid.load(Ordering::Acquire) != 0
    }
    /// Drop the client (its Drop ends the process tree) and every cached view of it.
    fn forget_client(&self, guard: &mut Option<Client>) {
        *guard = None;
        self.pid.store(0, Ordering::Release);
        self.catalog.lock().clear();
        *self.server_info.lock() = Value::Null;
        *self.process.lock() = None;
    }
    /// End the REA process tree without waiting for the client lock.
    fn kill_out_of_band(&self) {
        match self.process.lock().take() {
            Some((_, Some(job))) => job.terminate(),
            #[cfg(windows)]
            Some((pid, None)) => {
                use std::os::windows::process::CommandExt;
                let _ = Command::new("taskkill.exe")
                    .args(["/PID", &pid.to_string(), "/T", "/F"])
                    .creation_flags(0x08000000)
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .status();
            }
            _ => {}
        }
    }
    pub fn process_id(&self) -> u32 {
        self.pid.load(Ordering::Acquire)
    }
    pub fn new(resources: &Path) -> Self {
        Self::with_preferences(resources, preference_path())
    }
    fn with_preferences(resources: &Path, preferences: PathBuf) -> Self {
        let (settings, error) = match RuntimeSettings::load(&preferences) {
            Ok(settings) => (settings, None),
            Err(error) => (
                RuntimeSettings::default(),
                Some(format!(
                    "{error:#}. Review and save the runtime settings before connecting."
                )),
            ),
        };
        Self {
            preferences,
            settings: Mutex::new(settings),
            settings_error: Mutex::new(error),
            configuration: Mutex::new(()),
            server_info: Mutex::new(Value::Null),
            root: resources.join("plugins/rea"),
            client: Mutex::new(None),
            catalog: Mutex::new(vec![]),
            pid: AtomicU32::new(0),
            process: Mutex::new(None),
            generation: AtomicU64::new(0),
        }
    }
    pub fn connect(&self, requested_mode: Option<&str>) -> Result<Value> {
        if let Some(error) = self.settings_error.lock().as_ref() {
            bail!("{error}");
        }
        if let Some(mode) = requested_mode {
            self.configure(&json!({"mode":mode}))?;
        }
        let _configuration = self.configuration.lock();
        if let Some(error) = self.settings_error.lock().as_ref() {
            bail!("{error}");
        }
        let settings = self.settings.lock().clone();
        let mode = settings.mode.as_str();
        let generation = self.generation.load(Ordering::Acquire);
        let mut guard = self.client.lock();
        for attempt in 0..2 {
            // A cached client whose process or transport ended is replaced.
            if guard.as_mut().is_some_and(|client| !client.usable()) {
                self.forget_client(&mut guard);
            }
            let fresh = guard.is_none();
            if fresh {
                let mut client = Client::start(&self.root, &settings)?;
                *self.process.lock() = Some((client.pid(), client.job()));
                // A disconnect during start found no process to end, and one during the
                // catalog request ends it; either way the new client must not be kept.
                let disconnected = || self.generation.load(Ordering::Acquire) != generation;
                let tools = if disconnected() {
                    Err(anyhow::anyhow!("Disconnected while connecting"))
                } else {
                    Self::list_tools(&mut client)
                };
                match tools {
                    Ok(tools) if !disconnected() => {
                        *self.catalog.lock() = tools;
                        *self.server_info.lock() = client.server_info.clone();
                        self.pid.store(client.pid(), Ordering::Release);
                        *guard = Some(client);
                    }
                    result => {
                        drop(client);
                        self.forget_client(&mut guard);
                        match result {
                            Err(error) if !disconnected() => return Err(error),
                            _ => bail!("Disconnected while connecting"),
                        }
                    }
                }
            }
            let supports_detail = self
                .catalog
                .lock()
                .iter()
                .find(|t| t["name"] == "binary_session")
                .and_then(|t| t.pointer("/inputSchema/properties/detail"))
                .is_some();
            let Some(client) = guard.as_mut() else {
                bail!("REA is not connected");
            };
            let session = client.tool(
                "binary_session",
                if supports_detail {
                    json!({"detail":"complete"})
                } else {
                    json!({})
                },
                SESSION_TIMEOUT,
            );
            match session {
                Ok(session) if session["isError"] == true => {
                    bail!("REA session inspection failed: {}", payload(&session))
                }
                Ok(session) => {
                    let runtime = self.runtime_metadata(&settings, true);
                    let tools = self.catalog.lock().clone();
                    return Ok(json!({"connected":true,"mode":mode,"settings":settings,
                            "runtime":runtime,"installedWrapper":installed_wrapper(),
                            "session":payload(&session),"tools":tools}));
                }
                Err(error) => {
                    if !client.usable() {
                        self.forget_client(&mut guard);
                        // Respawn a dead cached client once, unless a disconnect intervened.
                        if !fresh
                            && attempt == 0
                            && self.generation.load(Ordering::Acquire) == generation
                        {
                            continue;
                        }
                    }
                    return Err(error);
                }
            }
        }
        bail!("REA could not be restarted")
    }
    fn list_tools(client: &mut Client) -> Result<Vec<Value>> {
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
        Ok(tools)
    }
    pub fn disconnect(&self) -> Result<()> {
        self.generation.fetch_add(1, Ordering::AcqRel);
        if let Some(mut guard) = self.client.try_lock() {
            if let Some(client) = guard.as_mut() {
                if client.usable() {
                    let _ = client.tool("close_binary", json!({}), CLOSE_TIMEOUT);
                }
            }
            self.forget_client(&mut guard);
            return Ok(());
        }
        // A call owns the client. End the tree now; that call then fails with a
        // transport error and releases the lock.
        self.kill_out_of_band();
        self.pid.store(0, Ordering::Release);
        self.catalog.lock().clear();
        *self.server_info.lock() = Value::Null;
        if let Some(mut guard) = self.client.try_lock_for(Duration::from_secs(10)) {
            self.forget_client(&mut guard);
        }
        Ok(())
    }
    pub fn shutdown(&self) {
        self.generation.fetch_add(1, Ordering::AcqRel);
        self.kill_out_of_band();
        self.pid.store(0, Ordering::Release);
        self.catalog.lock().clear();
        *self.server_info.lock() = Value::Null;
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
        let timeout = configured_call_timeout(&self.settings.lock());
        self.call_locked(&mut guard, name, args, timeout)
    }
    /// Only a transport failure ends the session; a timeout or tool error keeps it.
    fn call_locked(
        &self,
        guard: &mut Option<Client>,
        name: &str,
        args: Value,
        timeout: Duration,
    ) -> Result<Value> {
        let client = guard
            .as_mut()
            .context("Connect the bundled REA plugin first")?;
        let result = client.tool(name, args, timeout);
        if result.is_err() && !client.usable() {
            self.forget_client(guard);
        }
        result
    }
    /// Call without queueing behind a running request; fails if REA stays busy.
    fn call_when_idle(&self, name: &str, args: Value, timeout: Duration) -> Result<Value> {
        let mut guard = self
            .client
            .try_lock_for(Duration::from_secs(2))
            .context("An REA call is still running. Wait for it to finish, or disconnect REA.")?;
        self.call_locked(&mut guard, name, args, timeout)
    }
    /// The binary REA currently has open, as REA itself reports it.
    pub fn open_target(&self) -> Result<Option<String>> {
        if !self.is_connected() {
            return Ok(None);
        }
        let response = self.call_when_idle("binary_session", json!({}), CLOSE_TIMEOUT)?;
        if response["isError"] == true {
            bail!("REA session inspection failed: {}", payload(&response));
        }
        let session = payload(&response);
        let session = session.get("result").unwrap_or(&session);
        if session["open"] != true {
            return Ok(None);
        }
        Ok(session["path"].as_str().map(str::to_owned))
    }
    /// Close REA's open binary with a short timeout.
    pub fn close_target(&self) -> Result<()> {
        let response = self.call_when_idle("close_binary", json!({}), CLOSE_TIMEOUT)?;
        if response["isError"] == true {
            bail!(
                "REA could not close its open binary: {}",
                payload(&response)
            );
        }
        Ok(())
    }
    pub fn agent_tools(&self) -> Vec<Value> {
        self.catalog.lock().iter().filter(|t| t["name"].as_str().map(|n| AGENT_TOOLS.contains(&n)).unwrap_or(false))
            .map(|t| json!({"name":t["name"],"description":t["description"],"inputSchema":t["inputSchema"]})).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings_directory() -> PathBuf {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root =
            std::env::temp_dir().join(format!("rea-settings-{}-{nonce}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        root
    }

    #[test]
    fn studio_import_workflow_uses_its_own_version_and_keeps_the_path_allowlist() {
        let root = settings_directory();
        let guide = root.join("plugins/rea/node_modules/rea-agents/skills/unpack-packed-binary/SKILL.md");
        std::fs::create_dir_all(guide.parent().unwrap()).unwrap();
        std::fs::write(&guide, "Capture evidence; review imports before rebuilding.").unwrap();
        let plugin = ReaPlugin::with_preferences(&root, root.join("rea-plugin.json"));
        let result = plugin.workflow(&json!({"path":"unpack-packed-binary/SKILL.md"})).unwrap();
        assert_eq!(result["package"], "rea-studio");
        assert_eq!(result["version"], env!("CARGO_PKG_VERSION"));
        assert_eq!(result["content"], "Capture evidence; review imports before rebuilding.");
        assert!(plugin.workflow(&json!({"path":"../unpack-packed-binary/SKILL.md"})).is_err());
        assert!(plugin.workflow(&json!({"path":"unpack-packed-binary/other.md"})).is_err());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn runtime_settings_migrate_mode_only_and_round_trip() {
        let root = settings_directory();
        let path = root.join("rea-plugin.json");
        assert_eq!(
            RuntimeSettings::load(&path).unwrap(),
            RuntimeSettings::default()
        );
        std::fs::write(&path, br#"{"mode":"installed"}"#).unwrap();
        let previous = RuntimeSettings::load(&path).unwrap();
        assert_eq!(previous.mode, "installed");
        assert_eq!(previous.ghidra_heap_mib, 4096);
        let updated = previous.patched(&json!({"ghidraHeapMiB":8192,"ghidraStartupTimeoutSecs":1200,"callTimeoutSecs":2400})).unwrap();
        updated.save(&path).unwrap();
        assert_eq!(RuntimeSettings::load(&path).unwrap(), updated);
        assert_eq!(updated.mode, "installed");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn invalid_runtime_settings_do_not_change_saved_or_running_configuration() {
        let root = settings_directory();
        let path = root.join("rea-plugin.json");
        RuntimeSettings::default().save(&path).unwrap();
        let original = std::fs::read(&path).unwrap();
        let plugin = ReaPlugin::with_preferences(&root, path.clone());
        for patch in [
            json!({"ghidraHeapMiB":511}),
            json!({"ghidraHeapMiB":65537}),
            json!({"ghidraHeapMiB":4096.5}),
            json!({"ghidraHeapMiB":null}),
            json!({"ghidraStartupTimeoutSecs":7201}),
            json!({"callTimeoutSecs":29}),
            json!({"callTimeoutSecs":14401}),
            json!({"callTimeoutSecs":600}),
            json!({"mode":"remote"}),
            json!({"unknown":true}),
            json!([]),
        ] {
            assert!(plugin.configure(&patch).is_err(), "accepted {patch}");
            assert_eq!(std::fs::read(&path).unwrap(), original);
            assert_eq!(*plugin.settings.lock(), RuntimeSettings::default());
        }
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn corrupt_preferences_are_preserved_until_explicit_settings_save() {
        let root = settings_directory();
        let path = root.join("rea-plugin.json");
        std::fs::write(&path, b"{broken").unwrap();
        let plugin = ReaPlugin::with_preferences(&root, path.clone());
        assert!(plugin.runtime_settings()["settingsError"].is_string());
        assert!(plugin.connect(None).is_err());
        assert!(plugin.connect(Some("bundled")).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), b"{broken");
        let saved = plugin
            .configure(&json!({"mode":"bundled","ghidraHeapMiB":2048}))
            .unwrap();
        assert_eq!(saved["changed"], true);
        assert!(saved["settingsError"].is_null());
        assert_eq!(RuntimeSettings::load(&path).unwrap().ghidra_heap_mib, 2048);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn runtime_settings_reach_child_environment_and_timeout_override_is_bounded() {
        let settings = RuntimeSettings::default()
            .patched(&json!({"ghidraHeapMiB":8192,"ghidraStartupTimeoutSecs":1200}))
            .unwrap();
        let mut command = Command::new("unused-test-command");
        settings.apply_environment(&mut command);
        let environment: std::collections::HashMap<_, _> = command
            .get_envs()
            .map(|(key, value)| {
                (
                    key.to_string_lossy().into_owned(),
                    value.unwrap().to_string_lossy().into_owned(),
                )
            })
            .collect();
        assert_eq!(environment["GHIDRA_HEADLESS_MAXMEM"], "8192M");
        assert_eq!(environment["REA_GHIDRA_STARTUP_TIMEOUT_MS"], "1200000");
        assert_eq!(timeout_override(Some(" 3600 ")), Some(3600));
        for invalid in [None, Some("0"), Some("-1"), Some("invalid"), Some("14401")] {
            assert_eq!(timeout_override(invalid), None);
        }
    }

    #[test]
    fn settings_changes_are_serialized_and_failed_saves_leave_state_unchanged() {
        let root = settings_directory();
        let path = root.join("rea-plugin.json");
        let plugin = ReaPlugin::with_preferences(&root, path);
        let guard = plugin.configuration.lock();
        assert!(plugin.configure(&json!({"ghidraHeapMiB":8192})).is_err());
        drop(guard);
        let blocking_file = root.join("not-a-directory");
        std::fs::write(&blocking_file, b"keep").unwrap();
        let plugin = ReaPlugin::with_preferences(&root, blocking_file.join("rea-plugin.json"));
        assert!(plugin.configure(&json!({"ghidraHeapMiB":8192})).is_err());
        assert_eq!(plugin.settings.lock().ghidra_heap_mib, 4096);
        assert_eq!(std::fs::read(blocking_file).unwrap(), b"keep");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn runtime_identity_distinguishes_bundle_metadata_from_live_server() {
        let root = settings_directory();
        let plugin = ReaPlugin::with_preferences(&root, root.join("rea-plugin.json"));
        std::fs::create_dir_all(plugin.root.join("node_modules/rea-agents")).unwrap();
        std::fs::write(
            plugin.root.join("node_modules/rea-agents/package.json"),
            br#"{"version":"6.8.0"}"#,
        )
        .unwrap();
        *plugin.server_info.lock() = json!({"name":"rea","version":"6.3.0"});
        let settings = RuntimeSettings::default()
            .patched(&json!({"mode":"installed"}))
            .unwrap();
        let metadata = plugin.runtime_metadata(&settings, true);
        assert_eq!(metadata["serverInfo"]["version"], "6.3.0");
        assert_eq!(metadata["bundled"]["rea"], "6.8.0");
        assert!(metadata["warnings"].as_array().unwrap().len() >= 2);
        assert!(plugin.runtime_metadata(&settings, false)["serverInfo"].is_null());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn agent_tools_exist_in_the_bundled_rea_catalog() {
        let catalog = include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../resources/plugins/rea/tool-catalog-6.8.0.txt"
        ));
        let names: std::collections::HashSet<&str> = catalog
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .collect();
        assert!(names.len() > 200, "catalog looks truncated");
        let missing: Vec<_> = AGENT_TOOLS.iter().filter(|t| !names.contains(*t)).collect();
        assert!(
            missing.is_empty(),
            "not advertised by REA 6.8.0: {missing:?}"
        );
        let mut unique = AGENT_TOOLS.to_vec();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(
            unique.len(),
            AGENT_TOOLS.len(),
            "duplicate agent tool names"
        );
    }

    /// A scripted stdio server: never answers `slow`, exits on `exit`, echoes
    /// cancellations as non-JSON stdout, and answers everything else.
    #[cfg(windows)]
    fn scripted_server() -> (Client, PathBuf) {
        let script =
            std::env::temp_dir().join(format!("quixi-mcp-fake-{}.ps1", std::process::id()));
        std::fs::write(&script, r#"
while ($null -ne ($line = [Console]::In.ReadLine())) {
  $m = $line | ConvertFrom-Json
  if ($null -eq $m.id) {
    if ($m.method -eq 'notifications/cancelled') { [Console]::Out.WriteLine('cancelled ' + $m.params.requestId); [Console]::Out.Flush() }
    continue
  }
  if ($m.method -eq 'initialize') { [Console]::Out.WriteLine('{"jsonrpc":"2.0","id":' + $m.id + ',"result":{"protocolVersion":"2025-03-26"}}') }
  elseif ($m.params.name -eq 'exit') { exit 0 }
  elseif ($m.params.name -ne 'slow') { [Console]::Out.WriteLine('{"jsonrpc":"2.0","id":' + $m.id + ',"result":{"ok":true}}') }
  [Console]::Out.Flush()
}
"#).unwrap();
        let mut command = quixi_platform::background_command("powershell.exe");
        command
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-File",
            ])
            .arg(&script);
        (Client::spawn(command, true).unwrap(), script)
    }

    #[cfg(windows)]
    #[test]
    fn timeout_cancels_the_request_and_keeps_the_session() {
        let (mut client, script) = scripted_server();
        let error = client
            .tool("slow", json!({}), Duration::from_secs(2))
            .unwrap_err();
        assert!(error.to_string().contains("session was kept"), "{error}");
        assert!(client.usable());
        // The server's non-JSON stdout line is skipped, not fatal.
        assert_eq!(
            client
                .tool("fast", json!({}), Duration::from_secs(30))
                .unwrap()["ok"],
            true
        );
        assert!(
            client.diagnostics().contains("cancelled 2"),
            "{}",
            client.diagnostics()
        );
        assert!(client
            .tool("exit", json!({}), Duration::from_secs(30))
            .is_err());
        assert!(!client.usable());
        drop(client);
        let _ = std::fs::remove_file(script);
    }
}
