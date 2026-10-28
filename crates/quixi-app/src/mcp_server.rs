//! Opt-in, authenticated loopback MCP transport for the public workspace APIs.
use anyhow::{bail, Context, Result};
use parking_lot::Mutex;
use quixi_engine::{playground::Playground, QuixiEngine};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::{
    collections::VecDeque,
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use tiny_http::{Method, Request, Server};
use uuid::Uuid;

const VERSIONS: &[&str] = &["2025-11-25", "2025-06-18", "2025-03-26"];
const MAX_BODY: usize = 3 * 1024 * 1024;
#[derive(Serialize, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct Settings {
    port: u16,
    token: String,
    classic_path: Option<PathBuf>,
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            port: 19456,
            token: String::new(),
            classic_path: None,
        }
    }
}
struct Running {
    stop: Arc<AtomicBool>,
    thread: JoinHandle<()>,
}
pub struct McpServer {
    settings: Mutex<Settings>,
    running: Mutex<Option<Running>>,
    path: PathBuf,
    active: Arc<AtomicUsize>,
    events: Arc<Mutex<VecDeque<Value>>>,
}
impl McpServer {
    pub fn new(data: &Path) -> Self {
        let path = data.join("mcp-server.json");
        let mut settings: Settings = fs::read(&path)
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        if settings.port < 1024 {
            settings.port = 19456;
        }
        if settings.token.len() != 64 || !settings.token.bytes().all(|b| b.is_ascii_hexdigit()) {
            settings.token.clear();
        }
        Self {
            settings: Mutex::new(settings),
            running: Mutex::new(None),
            path,
            active: Arc::new(AtomicUsize::new(0)),
            events: Arc::new(Mutex::new(VecDeque::new())),
        }
    }
    fn save(&self) -> Result<()> {
        fs::write(
            &self.path,
            serde_json::to_vec_pretty(&*self.settings.lock())?,
        )
        .context("Could not save MCP settings")
    }
    fn ensure_token(&self) -> Result<()> {
        if self.settings.lock().token.is_empty() {
            self.settings.lock().token =
                format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
            self.save()?;
        }
        Ok(())
    }
    pub fn status(&self) -> Value {
        let running = self.running.lock();
        let settings = self.settings.lock();
        json!({"enabled":running.as_ref().is_some_and(|r| !r.thread.is_finished()),"port":settings.port,
            "url":format!("http://127.0.0.1:{}/mcp",settings.port),"transport":"Streamable HTTP","protocolVersion":VERSIONS[0],
            "activeRequests":self.active.load(Ordering::Acquire),"events":*self.events.lock(),"classicAvailable":self.classic_path(&settings).is_some()})
    }
    pub fn stop(&self) {
        if let Some(running) = self.running.lock().take() {
            running.stop.store(true, Ordering::Release);
            let _ = running.thread.join();
        }
    }
    fn start(&self, engine: Arc<QuixiEngine>, port: u16) -> Result<()> {
        if port < 1024 {
            bail!("Choose a port from 1024 to 65535");
        }
        let mut running = self.running.lock();
        if running.as_ref().is_some_and(|r| !r.thread.is_finished()) {
            bail!("Disable the MCP server before changing its port");
        }
        if let Some(previous) = running.take() {
            let _ = previous.thread.join();
        }
        if self.active.load(Ordering::Acquire) > 0 {
            bail!("Wait for the previously accepted MCP call to finish");
        }
        self.ensure_token()?;
        let server = Server::http(("127.0.0.1", port))
            .map_err(|e| anyhow::anyhow!("Cannot bind local MCP port {port}: {e}"))?;
        self.settings.lock().port = port;
        self.save()?;
        let token = self.settings.lock().token.clone();
        let stop = Arc::new(AtomicBool::new(false));
        let stopped = Arc::clone(&stop);
        let active = Arc::clone(&self.active);
        let events = Arc::clone(&self.events);
        let worker = thread::Builder::new()
            .name("rea-studio-mcp".into())
            .spawn(move || {
                while !stopped.load(Ordering::Acquire) {
                    let request = match server.recv_timeout(Duration::from_millis(100)) {
                        Ok(Some(r)) => r,
                        Ok(None) => continue,
                        Err(_) => break,
                    };
                    if active.load(Ordering::Acquire) >= 4 {
                        reply(
                            request,
                            503,
                            json!({"error":"MCP is busy; retry after the current calls finish"}),
                        );
                        continue;
                    }
                    active.fetch_add(1, Ordering::AcqRel);
                    let active = Arc::clone(&active);
                    let engine = Arc::clone(&engine);
                    let token = token.clone();
                    let stopped = Arc::clone(&stopped);
                    let events = Arc::clone(&events);
                    thread::spawn(move || {
                        let _guard = ActiveRequest(active);
                        handle_http(request, &engine, &token, port, &stopped, &events);
                    });
                }
                // Dropping Server closes the listener. Already accepted calls may complete.
            })?;
        *running = Some(Running {
            stop,
            thread: worker,
        });
        Ok(())
    }
    pub fn control(&self, engine: &Arc<QuixiEngine>, route: &str, body: &Value) -> Result<Value> {
        match route {
            "status" => {}
            "enable" => {
                let port = body["port"]
                    .as_u64()
                    .filter(|p| (1024..=65535).contains(p))
                    .context("Choose a port from 1024 to 65535")?;
                self.start(Arc::clone(engine), port as u16)?;
            }
            "disable" => self.stop(),
            "rotate" => {
                self.stop();
                self.settings.lock().token.clear();
                self.ensure_token()?;
            }
            "config" => {
                self.ensure_token()?;
                let s = self.settings.lock();
                return Ok(
                    json!({"mcpServers":{"rea-studio":{"type":"http","url":format!("http://127.0.0.1:{}/mcp",s.port),"headers":{"Authorization":format!("Bearer {}",s.token)}}}}),
                );
            }
            "classic-configure" => {
                let path = body["path"].as_str().map(str::to_owned).or_else(|| {
                    quixi_platform::ComputerUse::pick_file(Some(
                        "Choose the earlier QuixiDesk Classic executable",
                    ))
                });
                if let Some(path) = path {
                    let path = fs::canonicalize(path)?;
                    if !valid_classic(&path) {
                        bail!("Choose an earlier QuixiDesk executable with resources/ion-dist/index.html beside it");
                    }
                    self.settings.lock().classic_path = Some(path);
                    self.save()?;
                }
            }
            "classic-open" => {
                let path = self
                    .classic_path(&self.settings.lock())
                    .context("Choose the earlier Classic executable first")?;
                let profile = engine.data_dir.join("classic");
                fs::create_dir_all(&profile)?;
                let providers = profile.join("providers.json");
                if !providers.exists() && engine.data_dir.join("providers.json").exists() {
                    fs::copy(engine.data_dir.join("providers.json"), &providers)?;
                }
                let child = std::process::Command::new(&path)
                    .arg("--classic")
                    .current_dir(path.parent().context("Classic path has no parent")?)
                    .env("QUIXI_DATA_DIR", &profile)
                    .env("WEBVIEW2_USER_DATA_FOLDER", profile.join("WebView"))
                    .env_remove("QUIXI_RESOURCES_DIR")
                    .env_remove("WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS")
                    .env_remove("QUIXI_DEVTOOLS")
                    .spawn()?;
                return Ok(json!({"opened":true,"pid":child.id()}));
            }
            _ => bail!("Unknown MCP settings operation"),
        }
        Ok(self.status())
    }
    fn classic_path(&self, settings: &Settings) -> Option<PathBuf> {
        let mut paths = Vec::new();
        if let Some(path) = &settings.classic_path {
            paths.push(path.clone());
        }
        if let Some(path) = std::env::var_os("REA_STUDIO_CLASSIC_EXE") {
            paths.push(PathBuf::from(path));
        }
        if let Ok(exe) = std::env::current_exe() {
            if let Some(parent) = exe.parent().and_then(Path::parent) {
                paths.push(parent.join("QuixiDesk/QuixiDesk.exe"));
            }
        }
        paths.into_iter().find(|path| valid_classic(path))
    }
}
fn valid_classic(path: &Path) -> bool {
    path.is_file()
        && path
            .extension()
            .and_then(|e| e.to_str())
            .is_some_and(|e| e.eq_ignore_ascii_case("exe"))
        && path
            .parent()
            .is_some_and(|p| p.join("resources/ion-dist/index.html").is_file())
        && std::env::current_exe()
            .ok()
            .and_then(|p| fs::canonicalize(p).ok())
            != fs::canonicalize(path).ok()
}
struct ActiveRequest(Arc<AtomicUsize>);
impl Drop for ActiveRequest {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}
fn header<'a>(request: &'a Request, name: &'static str) -> Option<&'a str> {
    let mut values = request.headers().iter().filter(|h| h.field.equiv(name));
    let first = values.next()?;
    if values.next().is_some() {
        return None;
    }
    Some(first.value.as_str())
}
fn token_matches(given: &str, token: &str) -> bool {
    let expected = format!("Bearer {token}");
    given.len() == expected.len()
        && given
            .bytes()
            .zip(expected.bytes())
            .fold(0u8, |diff, (a, b)| diff | (a ^ b))
            == 0
}
fn allowed_origin(origin: &str, port: u16) -> bool {
    origin == format!("http://127.0.0.1:{port}") || origin == format!("http://localhost:{port}")
}
fn reply(request: Request, status: u16, value: Value) {
    let body = if status == 202 {
        String::new()
    } else {
        value.to_string()
    };
    // tiny_http strips Connection from Response headers. Write its documented raw
    // response stream so clients close each stateless connection; otherwise pooled
    // sockets outlive Server and can hang after disable/re-enable on the same port.
    let reason = match status {
        200 => "OK", 202 => "Accepted", 400 => "Bad Request", 401 => "Unauthorized",
        403 => "Forbidden", 404 => "Not Found", 405 => "Method Not Allowed",
        406 => "Not Acceptable", 413 => "Payload Too Large", 415 => "Unsupported Media Type",
        503 => "Service Unavailable", _ => "Error",
    };
    let mut writer = request.into_writer();
    let _ = write!(writer, "HTTP/1.1 {status} {reason}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\n\r\n{body}", body.len());
    let _ = writer.flush();
}
fn rpc_error(id: Value, code: i32, message: &str) -> Value {
    json!({"jsonrpc":"2.0","id":id,"error":{"code":code,"message":message}})
}
fn handle_http(
    mut request: Request,
    engine: &Arc<QuixiEngine>,
    token: &str,
    port: u16,
    stop: &AtomicBool,
    events: &Mutex<VecDeque<Value>>,
) {
    let origin_present = request.headers().iter().any(|h| h.field.equiv("Origin"));
    if header(&request, "Host")
        .is_none_or(|h| h != format!("127.0.0.1:{port}") && h != format!("localhost:{port}"))
        || (origin_present && header(&request, "Origin").is_none_or(|o| !allowed_origin(o, port)))
    {
        reply(
            request,
            403,
            json!({"error":"Origin or host is not allowed"}),
        );
        return;
    }
    if !header(&request, "Authorization").is_some_and(|s| token_matches(s, token)) {
        reply(
            request,
            401,
            json!({"error":"A valid MCP bearer token is required"}),
        );
        return;
    }
    if request.url() != "/mcp" {
        reply(request, 404, json!({"error":"Use /mcp"}));
        return;
    }
    if request.method() != &Method::Post {
        reply(
            request,
            405,
            json!({"error":"Use POST. This server returns JSON responses and does not offer an SSE subscription."}),
        );
        return;
    }
    if header(&request, "MCP-Protocol-Version").is_some_and(|v| !VERSIONS.contains(&v)) {
        reply(
            request,
            400,
            rpc_error(Value::Null, -32600, "Unsupported MCP protocol version"),
        );
        return;
    }
    if !header(&request, "Content-Type")
        .is_some_and(|v| v.split(';').next().unwrap_or("").trim() == "application/json")
    {
        reply(request, 415, json!({"error":"Use application/json"}));
        return;
    }
    let accept = header(&request, "Accept").unwrap_or("");
    if !accept.contains("application/json") || !accept.contains("text/event-stream") {
        reply(
            request,
            406,
            json!({"error":"Accept must include application/json and text/event-stream"}),
        );
        return;
    }
    if request.body_length().is_some_and(|n| n > MAX_BODY) {
        reply(request, 413, json!({"error":"Request exceeds 3 MiB"}));
        return;
    }
    let mut bytes = Vec::new();
    if request
        .as_reader()
        .take(MAX_BODY as u64 + 1)
        .read_to_end(&mut bytes)
        .is_err()
    {
        reply(
            request,
            400,
            rpc_error(Value::Null, -32700, "Could not read JSON"),
        );
        return;
    }
    if bytes.len() > MAX_BODY {
        reply(request, 413, json!({"error":"Request exceeds 3 MiB"}));
        return;
    }
    let value: Value = match serde_json::from_slice(&bytes) {
        Ok(value) => value,
        Err(_) => {
            reply(request, 400, rpc_error(Value::Null, -32700, "Invalid JSON"));
            return;
        }
    };
    if !value.is_object() || value["jsonrpc"] != "2.0" {
        reply(
            request,
            400,
            rpc_error(
                Value::Null,
                -32600,
                "A single JSON-RPC 2.0 message is required",
            ),
        );
        return;
    }
    let method = value["method"].as_str().unwrap_or("");
    if value.get("id").is_none() && method.starts_with("notifications/") {
        reply(request, 202, Value::Null);
        return;
    }
    if value.get("method").is_none()
        && value.get("id").is_some()
        && (value.get("result").is_some() || value.get("error").is_some())
    {
        reply(request, 202, Value::Null);
        return;
    }
    let id = value["id"].clone();
    if !id.is_string() && !id.is_number() {
        reply(
            request,
            400,
            rpc_error(Value::Null, -32600, "Request id is required"),
        );
        return;
    }
    if stop.load(Ordering::Acquire) {
        reply(
            request,
            503,
            rpc_error(id, -32000, "MCP server was disabled"),
        );
        return;
    }
    let params = &value["params"];
    let result = match method {
        "initialize" => {
            let requested = params["protocolVersion"].as_str().unwrap_or("");
            let version = if VERSIONS.contains(&requested) {
                requested
            } else {
                VERSIONS[0]
            };
            json!({"protocolVersion":version,"capabilities":{"tools":{}},"serverInfo":{"name":"rea-studio","title":"REA Studio","version":env!("CARGO_PKG_VERSION")},"instructions":"Control the currently running REA Studio workspace. Open a project first; use returned project IDs. File writes require the hash from studio_read_file (empty hash for a new file). Commands and Code runs execute as the Windows user. REA and debugger tools expose live schemas; inspect them before calling. The desktop enables and selects the debugger session and configures the separate decompilation specialist. Imported reports have user-associated target provenance; model suggestions are unverified. Poll studio_run_status after starting tasks. Disabling MCP closes the listener; accepted work can finish."})
        }
        "ping" => json!({}),
        "tools/list" => json!({"tools":tool_catalog()}),
        "tools/call" => {
            let name = params["name"].as_str().unwrap_or("");
            let args = params
                .get("arguments")
                .cloned()
                .unwrap_or_else(|| json!({}));
            let declared = tool_catalog().into_iter().find(|t| t["name"] == name);
            let Some(declared) = declared else {
                reply(request, 200, rpc_error(id, -32602, "Unknown tool"));
                return;
            };
            if let Err(e) = validate_arguments(&declared["inputSchema"], &args) {
                reply(request, 200, rpc_error(id, -32602, &e.to_string()));
                return;
            }
            let started = Instant::now();
            let output = dispatch_tool(engine, name, &args);
            let failed = output
                .as_ref()
                .map(|v| v["failed"] == true || v["isError"] == true)
                .unwrap_or(true);
            {
                let mut log = events.lock();
                log.push_front(json!({"time":chrono::Utc::now().to_rfc3339(),"tool":name,"failed":failed,"durationMs":started.elapsed().as_millis()}));
                log.truncate(50);
            }
            match output {
                Ok(v) => {
                    json!({"content":[{"type":"text","text":v.to_string()}],"structuredContent":v,"isError":failed})
                }
                Err(e) => json!({"content":[{"type":"text","text":e.to_string()}],"isError":true}),
            }
        }
        _ => {
            reply(request, 200, rpc_error(id, -32601, "Method not found"));
            return;
        }
    };
    reply(
        request,
        200,
        json!({"jsonrpc":"2.0","id":id,"result":result}),
    );
}
fn tool(
    name: &str,
    description: &str,
    properties: Value,
    required: &[&str],
    read_only: bool,
) -> Value {
    json!({"name":name,"description":description,"inputSchema":{"type":"object","properties":properties,"required":required,"additionalProperties":false},"annotations":{"readOnlyHint":read_only,"destructiveHint":!read_only,"openWorldHint":true}})
}
fn tool_catalog() -> Vec<Value> {
    let string = json!({"type":"string"});
    let boolean = json!({"type":"boolean"});
    vec![
        tool("studio_analysis_sources","List detected analysis sources and whether they use a live provider or imported reports. File detection is not provider readiness.",json!({}),&[],true),
        tool("studio_decompile_status","Read the separately configured LLM4Decompile specialist settings and request state. Settings are chosen in the desktop UI.",json!({}),&[],true),
        tool("studio_decompile_assist","Ask the enabled decompilation specialist to refine one function from a successful original evidence record. Optional input supplies reviewed function text. Saves an unverified suggestion linked to the source; never executes generated code.",json!({"recordId":string,"input":string}),&["recordId"],false),
        tool("studio_import_analysis","Save an installed tool's exported UTF-8 report against the selected artifact. Preserves source path/hash and labels target association as unverified. Does not execute the file.",json!({"id":string,"path":string}),&["id","path"],false),
        tool("studio_debugger_status","Inspect x64dbg bridge configuration and connection state. Enable and select the session from the desktop UI.",json!({}),&[],true),
        tool("studio_debugger_catalog","List the connected x64dbg tools, or return one live input schema. The desktop must enable the bridge first.",json!({"tool":string,"readOnly":boolean}),&[],true),
        tool("studio_debugger_call","Read or control the user-selected x64dbg session using a live schema. Checks the debuggee executable against the selected artifact and saves runtime evidence. Session selection and enablement stay in the desktop UI.",json!({"tool":string,"arguments":{"type":"object"}}),&["tool","arguments"],false),
        tool("studio_ida_status","Inspect the IDA bridge (headless idalib or attached IDA): installation, connection, the bound artifact and SHA-256, and live tools with kind read/annotate/blocked. Provide tool for its live input schema (the bridge supplies database). Enabling and opening the artifact happen in the desktop UI.",json!({"tool":string}),&[],true),
        tool("studio_ida_call","Call a live IDA tool on the database bound to the selected artifact. Read tools and (when allowed) annotations of the private IDA database only; code execution, patching, debugger and database-switching tools are refused. Saves evidence; long text is bounded with paging guidance.",json!({"tool":string,"arguments":{"type":"object"}}),&["tool","arguments"],false),
        tool("studio_state","List projects, configured model IDs and task summaries (no credentials).",json!({}),&[],true),
        tool("studio_open_project","Open an existing absolute project directory; returns its project ID.",json!({"path":string}),&["path"],false),
        tool("studio_import_code","Push UTF-8 source files into a new REA Studio project for the user. Returns project ID and analysisTarget. Import never executes code. Use studio_rea_select and static REA tools to analyse the returned target, or studio_start_run for coding assistance.",json!({"name":{"type":"string","minLength":1,"maxLength":80},"purpose":{"type":"string","enum":["coding","analysis"]},"analysisPath":{"type":"string","description":"Optional imported file/directory relative to the new project; defaults to its root."},"files":{"type":"array","minItems":1,"maxItems":64,"items":{"type":"object","properties":{"path":{"type":"string"},"content":{"type":"string"}},"required":["path","content"],"additionalProperties":false}}}),&["name","files"],false),
        tool("studio_files","List project files, optionally filtered by query.",json!({"project":string,"query":string}),&["project"],true),
        tool("studio_read_file","Read a project-relative UTF-8 file and its conflict-detection hash.",json!({"project":string,"path":string}),&["project","path"],true),
        tool("studio_write_file","Write a project file using the hash returned by read; use empty hash only for new files.",json!({"project":string,"path":string,"content":string,"hash":string}),&["project","path","content","hash"],false),
        tool("studio_diff","Read actual Git status and diffs: changed files with status, staged flag and line counts, plus working-tree and staged diffs bounded to 2 MiB each (truncated flag). Outside a Git repository the lists are empty.",json!({"project":string}),&["project"],true),
        tool("studio_command","Run a noninteractive command in a project as the Windows user. Output and timeout are bounded.",json!({"project":string,"command":string}),&["project","command"],false),
        tool("studio_start_run","Start one model task. Poll studio_run_status for actual progress and results.",json!({"project":string,"prompt":string,"model":string,"provider":{"type":"string","description":"Optional exact connection ID; keeps same-named models on different connections separate."},"mode":{"type":"string","enum":["ask","code"]},"reaEnabled":boolean,"maxSteps":{"type":"integer","minimum":1,"maximum":100,"description":"Model/tool step limit; default 40."},"contextBudget":{"type":"integer","minimum":50000,"maximum":2000000,"description":"Requested UTF-8 input byte budget; default 300000. Capped conservatively by configured model context after output and system reserves; effective contextLimits are recorded."},"maxOutputTokens":{"type":"integer","minimum":256,"maximum":128000,"description":"Model output token limit per step; default at most 16384 and one quarter of configured context."},"confirmCommands":{"type":"string","enum":["risky","all","never"],"description":"Which Code-mode agent commands wait for the user's approval in the REA Studio window (there is no MCP approval tool); default risky. While waiting, studio_run_status reports status awaiting_approval and pendingCommand."},"parentRun":{"type":"string","description":"Optional earlier task ID in the same project; its prompt, bounded answer, durable checkpoint and change list are given to this follow-up task. No automatic action replay."}}),&["project","prompt","model","mode"],false),
        tool("studio_run_status","Read a task's saved status, answer and actual activity.",json!({"id":string}),&["id"],true),
        tool("studio_stop_run","Stop a model task using its id. For a direct oracle suite, pass its operationId as id together with project. An analysis operation already sent to REA/IDA may still finish in that provider.",json!({"id":string,"project":{"type":"string","description":"Only for cancelling a direct oracle suite; id must match its operationId."}}),&["id"],false),
        tool("studio_rea_catalog","Connect REA and list static tool names/availability; provide tool for its full live input schema.",json!({"tool":string}),&[],true),
        tool("studio_rea_select","Select an existing absolute artifact path for static REA analysis.",json!({"path":string}),&["path"],false),
        tool("studio_rea_call","Call an advertised static REA tool with its exact live arguments. Saves real evidence.",json!({"tool":string,"arguments":{"type":"object"}}),&["tool","arguments"],false),
        tool("studio_rea_evidence","Read a saved evidence record by its UUID.",json!({"id":string}),&["id"],true),
        tool("studio_investigation","Manage project-scoped, immutable SHA-256 snapshots of named artifact sets. list and inspect read saved sets and current evidence status; create pins local files; export stages a version-pinned evidence bundle without executing targets or claiming complete application coverage. delete removes only snapshot metadata and requires confirmDelete=true; evidence, originals and exported bundles remain.",json!({"action":{"type":"string","enum":["list","create","inspect","export","delete"]},"project":string,"name":{"type":"string","minLength":1,"maxLength":120,"description":"Required only for create."},"targets":{"type":"array","minItems":1,"maxItems":32,"items":{"type":"string"},"description":"Required only for create: absolute local file paths to snapshot."},"id":{"type":"string","format":"uuid","description":"Required for inspect, export and delete: saved investigation ID in this project."},"confirmDelete":{"type":"boolean","description":"Required and true only for delete."}}),&["action","project"],false),
        tool("studio_export_spec","Save a reconstruction dossier into a separate project using an optional completed brief.",json!({"project":string,"scope":{"type":"string","enum":["feature","application"]},"goal":string,"observations":string,"briefId":string}),&["project","scope","goal"],false),
        tool("studio_oracle_preview","Read an oracle suite's cases, SHA-256 and whether the user has approved this exact file. Approval is only possible in the desktop UI.",json!({"project":string,"config":string}),&["project","config"],true),
        tool("studio_oracle_run","Execute a user-approved oracle suite in a project and save actual output comparisons. Refused unless the user approved the file's current SHA-256 in the desktop UI; MCP clients cannot approve.",json!({"project":string,"config":string,"operationId":{"type":"string","description":"Optional caller-generated UUID to cancel this suite using studio_stop_run with id=operationId and project."}}),&["project","config"],false),
    ]
}
fn validate_arguments(schema: &Value, args: &Value) -> Result<()> {
    let map = args
        .as_object()
        .context("Tool arguments must be an object")?;
    for key in schema["required"].as_array().into_iter().flatten() {
        let key = key.as_str().unwrap_or("");
        if !map.contains_key(key) {
            bail!("Missing required argument: {key}");
        }
    }
    for (key, value) in map {
        let rule = &schema["properties"][key];
        if rule.is_null() {
            bail!("Unknown argument: {key}");
        }
        let valid = match rule["type"].as_str() {
            Some("string") => value.is_string(),
            Some("boolean") => value.is_boolean(),
            Some("object") => value.is_object(),
            Some("array") => value.is_array(),
            Some("integer") => value.as_i64().is_some_and(|n| {
                rule["minimum"].as_i64().is_none_or(|min| n >= min)
                    && rule["maximum"].as_i64().is_none_or(|max| n <= max)
            }),
            _ => false,
        };
        if !valid {
            bail!("Wrong type for argument: {key}");
        }
        if rule["enum"].as_array().is_some_and(|v| !v.contains(value)) {
            bail!("Unsupported value for argument: {key}");
        }
    }
    Ok(())
}
fn dispatch_tool(engine: &Arc<QuixiEngine>, name: &str, args: &Value) -> Result<Value> {
    let state = || Playground::handle(engine, "GET", "state", &json!({}));
    if matches!(
        name,
        "studio_write_file"
            | "studio_command"
            | "studio_rea_select"
            | "studio_rea_call"
            | "studio_export_spec"
            | "studio_debugger_call"
            | "studio_ida_call"
            | "studio_import_analysis"
            | "studio_decompile_assist"
    ) && state()?["runs"]
        .as_array()
        .into_iter()
        .flatten()
        .any(|r| matches!(r["status"].as_str(), Some("running" | "stopping")))
    {
        bail!("Finish or stop the active model task before changing its workspace or REA session");
    }
    let route = match name {
        "studio_decompile_status" => "decompile/status",
        "studio_decompile_assist" => "decompile/assist",
        "studio_analysis_sources" => "toolchain/sources",
        "studio_import_analysis" => {
            if !Path::new(args["path"].as_str().unwrap_or("")).is_absolute() {
                bail!("Provide an absolute exported report path");
            }
            "toolchain/import-report"
        }
        "studio_debugger_status" => "debugger/status",
        "studio_debugger_catalog" => "debugger/catalog",
        "studio_debugger_call" => {
            return engine.debugger.call(engine,args["tool"].as_str().context("Tool required")?,
                args["arguments"].clone(),false);
        }
        "studio_ida_status" => {
            return Ok(match args["tool"].as_str() {
                Some(tool) => engine.ida.catalog(engine, Some(tool)),
                None => engine.ida.status(engine),
            });
        }
        "studio_ida_call" => {
            return engine.ida.agent_call(engine, args["tool"].as_str().context("Tool required")?, args["arguments"].clone());
        }
        "studio_state" => {
            let mut v = state()?;
            if let Some(runs) = v["runs"].as_array_mut() {
                for r in runs {
                    if let Some(o) = r.as_object_mut() {
                        o.remove("events");
                        o.remove("reply");
                        o.remove("prompt");
                    }
                }
            }
            return Ok(v);
        }
        "studio_run_status" => {
            return state()?["runs"]
                .as_array()
                .into_iter()
                .flatten()
                .find(|r| r["id"] == args["id"])
                .cloned()
                .context("Task not found")
        }
        "studio_rea_catalog" => {
            let mut v = engine.rea.connect(None)?;
            let tools = v["tools"]
                .as_array()
                .context("REA catalog is unavailable")?;
            if let Some(name) = args["tool"].as_str() {
                if !quixi_mcp::rea::AGENT_TOOLS.contains(&name) {
                    bail!("Tool is outside the static MCP control surface");
                }
                return tools
                    .iter()
                    .find(|t| t["name"] == name)
                    .cloned()
                    .context("Tool not advertised");
            }
            v["tools"]=json!(tools.iter().filter(|t|t["name"].as_str().is_some_and(|n|quixi_mcp::rea::AGENT_TOOLS.contains(&n))).map(|t|json!({"name":t["name"],"description":t["description"].as_str().unwrap_or("").chars().take(240).collect::<String>()})).collect::<Vec<_>>());
            return Ok(v);
        }
        "studio_rea_call" => {
            let tool = args["tool"].as_str().context("Tool name required")?;
            if !quixi_mcp::rea::AGENT_TOOLS.contains(&tool) {
                bail!("Only the advertised static REA tools are exposed through MCP");
            }
            "rea/tool"
        }
        "studio_open_project" => {
            if !Path::new(args["path"].as_str().unwrap_or("")).is_absolute() {
                bail!("Provide an absolute project directory");
            }
            "project"
        }
        "studio_files" => "files",
        "studio_import_code" => "import",
        "studio_read_file" => "read",
        "studio_write_file" => "write",
        "studio_diff" => "diff",
        "studio_command" => "command",
        "studio_start_run" => "run",
        "studio_stop_run" => {
            if args["project"].is_string() {
                return Playground::handle(engine, "POST", "oracle-stop",
                    &json!({"project":args["project"],"operationId":args["id"]}));
            }
            if !state()?["runs"].as_array().into_iter().flatten().any(|r| r["id"] == args["id"]) {
                bail!("Task not found");
            }
            "cancel"
        }
        "studio_rea_select" => "rea/select",
        "studio_rea_evidence" => "rea/evidence",
        "studio_investigation" => {
            let (route, body) = investigation_request(args)?;
            if matches!(args["action"].as_str(), Some("create" | "export" | "delete"))
                && state()?["runs"].as_array().into_iter().flatten()
                    .any(|r| matches!(r["status"].as_str(), Some("running" | "stopping")))
            {
                bail!("Finish or stop the active model task before changing its workspace or REA session");
            }
            return Playground::handle(engine, "POST", &route, &body);
        }
        "studio_export_spec" => "reconstruction-export",
        "studio_oracle_preview" => "oracle-preview",
        "studio_oracle_run" => {
            let mut body = args.clone();
            body["mode"] = json!("code");
            return Playground::handle(engine, "POST", "oracle-run", &body);
        }
        _ => bail!("Unknown tool"),
    };
    Playground::handle(engine, "POST", route, args)
}

/// Validate conditional arguments before passing this combined MCP tool to native routes.
fn investigation_request(args: &Value) -> Result<(String, Value)> {
    let map = args.as_object().context("Tool arguments must be an object")?;
    let action = args["action"].as_str().context("Investigation action required")?;
    let allowed: &[&str] = match action {
        "list" => &["action", "project"],
        "create" => &["action", "project", "name", "targets"],
        "inspect" | "export" => &["action", "project", "id"],
        "delete" => &["action", "project", "id", "confirmDelete"],
        _ => bail!("Unsupported investigation action"),
    };
    for key in map.keys() {
        if !allowed.contains(&key.as_str()) {
            bail!("Argument {key} is not used by investigation action {action}");
        }
    }
    if args["project"].as_str().is_none_or(|p| p.trim().is_empty()) {
        bail!("Project ID required");
    }
    if action == "create" {
        let name = args["name"].as_str().context("Investigation name required")?.trim();
        if name.is_empty() || name.chars().count() > 120 || name.chars().any(char::is_control) {
            bail!("Use an investigation name of 1 to 120 characters without control characters");
        }
        let targets = args["targets"].as_array().context("Investigation targets must be an array")?;
        if targets.is_empty() || targets.len() > 32
            || targets.iter().any(|v| v.as_str().is_none_or(|s| s.trim().is_empty()))
        {
            bail!("Provide 1 to 32 nonempty artifact file paths");
        }
    } else if action != "list" {
        let id = args["id"].as_str().context("Investigation ID required")?;
        Uuid::parse_str(id).context("Invalid investigation ID")?;
    }
    if action == "delete" && args["confirmDelete"].as_bool() != Some(true) {
        bail!("Deleting investigation metadata requires confirmDelete: true");
    }
    let mut body = map.clone();
    body.remove("action");
    body.remove("confirmDelete");
    Ok((format!("investigation/{action}"), Value::Object(body)))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn auth_and_origin_are_exact() {
        assert!(token_matches("Bearer test-token", "test-token"));
        assert!(!token_matches("Bearer test-token-extra", "test-token"));
        assert!(!token_matches("bearer test-token", "test-token"));
        assert!(allowed_origin("http://127.0.0.1:19456", 19456));
        assert!(!allowed_origin(
            "http://127.0.0.1.evil.invalid:19456",
            19456
        ));
        assert!(!allowed_origin("null", 19456));
        assert!(!allowed_origin("http://localhost:19455", 19456));
    }
    #[test]
    fn tool_contracts_require_hashes_and_explicit_access() {
        let tools = tool_catalog();
        let write = tools
            .iter()
            .find(|t| t["name"] == "studio_write_file")
            .unwrap();
        assert!(validate_arguments(
            &write["inputSchema"],
            &json!({"project":"p","path":"a","content":"text"})
        )
        .is_err());
        assert!(validate_arguments(
            &write["inputSchema"],
            &json!({"project":"p","path":"a","content":"text","hash":""})
        )
        .is_ok());
        let run = tools
            .iter()
            .find(|t| t["name"] == "studio_start_run")
            .unwrap();
        assert!(validate_arguments(
            &run["inputSchema"],
            &json!({"project":"p","prompt":"test","model":"m","mode":"invalid"})
        )
        .is_err());
        assert!(!tools.iter().any(|t| t["name"] == "studio_config"));
    }
    #[test]
    fn ida_tools_are_exposed_with_exact_contracts() {
        let tools = tool_catalog();
        assert_eq!(tools.len(), 28);
        assert!(!tools.iter().any(|t| t["name"].as_str().is_some_and(|n| n.contains("approve"))));
        let run = tools.iter().find(|t| t["name"] == "studio_start_run").unwrap();
        let base = json!({"project":"p","prompt":"t","model":"m","mode":"ask"});
        let with = |k: &str, v: Value| { let mut a = base.clone(); a[k] = v; a };
        assert!(validate_arguments(&run["inputSchema"], &with("maxSteps", json!(40))).is_ok());
        assert!(validate_arguments(&run["inputSchema"], &with("maxSteps", json!(101))).is_err());
        assert!(validate_arguments(&run["inputSchema"], &with("maxSteps", json!("40"))).is_err());
        // The schema matches the backend clamps, so no value is silently changed.
        assert!(validate_arguments(&run["inputSchema"], &with("contextBudget", json!(50_000))).is_ok());
        assert!(validate_arguments(&run["inputSchema"], &with("contextBudget", json!(20_000))).is_err());
        assert!(validate_arguments(&run["inputSchema"], &with("maxOutputTokens", json!(128_000))).is_ok());
        assert!(validate_arguments(&run["inputSchema"], &with("maxOutputTokens", json!(200_000))).is_err());
        assert!(validate_arguments(&run["inputSchema"], &with("confirmCommands", json!("all"))).is_ok());
        assert!(validate_arguments(&run["inputSchema"], &with("confirmCommands", json!("sometimes"))).is_err());
        assert!(validate_arguments(&run["inputSchema"], &with("parentRun", json!("run-id"))).is_ok());
        let call = tools.iter().find(|t| t["name"] == "studio_ida_call").unwrap();
        assert!(validate_arguments(&call["inputSchema"], &json!({"tool":"decompile"})).is_err());
        assert!(validate_arguments(&call["inputSchema"], &json!({"tool":"decompile","arguments":{"addr":"main"}})).is_ok());
        let status = tools.iter().find(|t| t["name"] == "studio_ida_status").unwrap();
        assert_eq!(status["annotations"]["readOnlyHint"], true);
        assert!(validate_arguments(&status["inputSchema"], &json!({})).is_ok());
    }
    #[test]
    fn investigation_tool_validates_action_specific_arguments_and_delete_confirmation() {
        let tools = tool_catalog();
        let tool = tools.iter().find(|t| t["name"] == "studio_investigation").unwrap();
        let schema = &tool["inputSchema"];
        assert_eq!(tool["annotations"]["readOnlyHint"], false);
        assert_eq!(schema["required"], json!(["action", "project"]));
        for invalid in [
            json!({"action":"list"}),
            json!({"action":"replace","project":"p"}),
            json!({"action":"list","project":"p","unknown":true}),
            json!({"action":"delete","project":"p","confirmDelete":"true"}),
        ] {
            assert!(validate_arguments(schema, &invalid).is_err(), "{invalid}");
        }
        let id = Uuid::new_v4().to_string();
        for invalid in [
            json!({"action":"list","project":""}),
            json!({"action":"list","project":"p","id":id}),
            json!({"action":"inspect","project":"p","id":"not-a-uuid"}),
            json!({"action":"export","project":"p"}),
            json!({"action":"delete","project":"p","id":id}),
            json!({"action":"delete","project":"p","id":id,"confirmDelete":false}),
            json!({"action":"delete","project":"p","id":id,"confirmDelete":"true"}),
            json!({"action":"create","project":"p","name":"case"}),
            json!({"action":"create","project":"p","name":"case","targets":[]}),
            json!({"action":"create","project":"p","name":"case","targets":[1]}),
            json!({"action":"create","project":"p","name":"case","targets":[""]}),
            json!({"action":"create","project":"p","name":"case","targets":["a"],"id":id}),
            json!({"action":"create","project":"p","name":"in\nvalid","targets":["a"]}),
        ] {
            assert!(investigation_request(&invalid).is_err(), "{invalid}");
        }
        let create = json!({"action":"create","project":"p","name":"case","targets":["C:\\fixture\\app.exe"]});
        assert!(validate_arguments(schema, &create).is_ok());
        let (route, body) = investigation_request(&create).unwrap();
        assert_eq!(route, "investigation/create");
        assert_eq!(body, json!({"project":"p","name":"case","targets":["C:\\fixture\\app.exe"]}));
        for action in ["list", "inspect", "export", "delete"] {
            let mut args = json!({"action":action,"project":"p"});
            if action != "list" { args["id"] = json!(id); }
            if action == "delete" { args["confirmDelete"] = json!(true); }
            assert!(validate_arguments(schema, &args).is_ok());
            let (route, body) = investigation_request(&args).unwrap();
            assert_eq!(route, format!("investigation/{action}"));
            assert_eq!(body["project"], "p");
            assert!(body.get("action").is_none());
            assert!(body.get("confirmDelete").is_none());
            if action != "list" { assert_eq!(body["id"], id); }
        }
    }
}
