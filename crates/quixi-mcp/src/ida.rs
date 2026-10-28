//! IDA Pro MCP transports for the IDA bridge.
//!
//! Headless: an owned `idalib-mcp --stdio` supervisor (ida-pro-mcp) placed in a kill-on-close
//! Job Object, so neither it nor its idalib workers can outlive REA Studio.
//! Attached: a loopback-only Streamable HTTP endpoint served by a modern ida-pro-mcp GUI plugin.
//! The HTTP client is std-only on purpose: it never leaves the loopback interface, needs no TLS,
//! and is safe to call from any thread (no async runtime nesting).
use anyhow::{bail, Context, Result};
use parking_lot::Mutex;
use serde_json::{json, Value};
use std::{
    collections::{HashSet, VecDeque},
    io::{BufRead, BufReader, Read, Write},
    net::{SocketAddr, TcpStream, ToSocketAddrs},
    path::{Path, PathBuf},
    process::{Child, ChildStdin, Stdio},
    sync::{mpsc, Arc},
    time::{Duration, Instant},
};

pub const FRAME_LIMIT: u64 = 16 * 1024 * 1024;
const STDERR_LINES: usize = 40;
const PROTOCOL_VERSION: &str = "2025-06-18";
pub const DEFAULT_ATTACHED_URL: &str = "http://127.0.0.1:13337/mcp";

// ---------------------------------------------------------------------------------------------
// Tool classification
// ---------------------------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ToolKind {
    /// Reads the database. Allowed for the UI and agents in Ask and Code mode.
    Read,
    /// Changes only the private IDB (names, comments, types, code/data definitions), never the
    /// artifact. Allowed in Ask and Code mode while the workspace's allowAnnotations is on.
    Annotate,
    /// Never callable through the bridge by the UI or agents.
    Blocked,
}
impl ToolKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ToolKind::Read => "read",
            ToolKind::Annotate => "annotate",
            ToolKind::Blocked => "blocked",
        }
    }
}

/// Code execution, byte/memory patching, debugger control, and session management (the bridge
/// owns idb_open/idb_close/idb_list so a caller cannot switch the bound database).
pub const BLOCKED_TOOLS: &[&str] = &[
    "py_eval", "py_exec_file", "patch", "patch_asm", "put_int", "idb_open", "idb_close", "idb_list",
    // Upstream marks this composite rename/type/comment helper @unsafe; keep it out.
    "diff_before_after",
];
/// Modifies the private IDB only. `idb_save` is accepted only without a destination path.
pub const ANNOTATE_TOOLS: &[&str] = &[
    "rename", "rename_at_ea", "set_comments", "append_comments", "add_bookmark", "declare_type",
    "enum_upsert", "set_type", "type_apply_batch", "infer_types", "declare_stack", "delete_stack",
    "define_func", "define_code", "make_data", "undefine", "set_op_type", "force_recompile",
    "invalidate_strings_cache", "init_caches", "idb_save",
];
/// Reviewed against ida-pro-mcp c133c385 sources; these only query the database.
pub const READ_TOOLS: &[&str] = &[
    "lookup_funcs", "int_convert", "list_funcs", "func_query", "func_profile", "list_globals",
    "entity_query", "imports", "imports_query", "decompile", "disasm", "xrefs_to", "xref_query",
    "xrefs_to_field", "callees", "find_bytes", "find_regex", "search_text", "basic_blocks", "find",
    "insn_query", "find_insns", "export_funcs", "callgraph", "analyze_function", "analyze_batch",
    "analyze_component", "trace_data_flow", "server_health", "get_bytes", "get_int", "get_string",
    "get_global_value", "stack_frame", "read_struct", "search_structs", "type_query",
    "type_inspect", "survey_binary", "make_signature", "make_signature_for_function",
    "make_signature_for_range", "find_xref_signatures", "get_metadata",
];
/// Words that block any tool, including reviewed names, when they appear in its name or live
/// description: code execution, byte patching or debugger control.
const EXECUTION_WORDS: &[&str] = &[
    "eval", "exec", "execute", "executes", "executing", "patch", "patches", "patching", "patched",
    "debugger", "shell",
];
const EXECUTION_PHRASES: &[&str] = &[
    "python code", "python script", "idapython script", "arbitrary code", "run python",
    "write bytes", "write memory", "modify memory",
];
/// Broader words that keep an unreviewed tool blocked. (Reviewed tools may mention, e.g., that
/// they iterate "in pure Python"; that alone is not execution of caller-supplied code.)
const UNKNOWN_DANGER_WORDS: &[&str] = &[
    "python", "idapython", "idc", "script", "scripts", "assemble", "debug", "breakpoint",
    "breakpoints", "process", "inject",
];
/// Additional words that disqualify an unknown tool from the read-only default.
const MUTATION_WORDS: &[&str] = &[
    "write", "writes", "set", "sets", "rename", "renames", "modify", "modifies", "delete", "deletes",
    "remove", "save", "saves", "apply", "applies", "create", "creates", "define", "declare",
    "upsert", "change", "changes", "run", "runs", "start", "attach", "file", "path", "open", "close",
    "undefine", "update", "updates", "put", "store", "import", "load", "export",
];

fn words(text: &str) -> Vec<String> {
    text.split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|w| !w.is_empty())
        .map(str::to_ascii_lowercase)
        .collect()
}

/// Classify a live tool by name and description. Known names follow the reviewed lists; a
/// description that advertises execution or patching still blocks them. Unknown tools are
/// blocked unless their description explicitly states they are read-only and mentions no
/// mutation, execution or file access: a new upstream tool must not silently gain access.
pub fn classify(name: &str, description: &str) -> ToolKind {
    let lower = name.to_ascii_lowercase();
    if lower.starts_with("dbg_") || lower.starts_with("debug") || lower.starts_with("py_")
        || BLOCKED_TOOLS.contains(&lower.as_str())
    {
        return ToolKind::Blocked;
    }
    let name_words = words(&lower);
    let description_words = words(description);
    let text = description.to_ascii_lowercase();
    let executes = |w: &Vec<String>| w.iter().any(|w| EXECUTION_WORDS.contains(&w.as_str()));
    if executes(&name_words) || executes(&description_words)
        || EXECUTION_PHRASES.iter().any(|p| text.contains(p))
    {
        return ToolKind::Blocked;
    }
    if ANNOTATE_TOOLS.contains(&lower.as_str()) {
        return ToolKind::Annotate;
    }
    if READ_TOOLS.contains(&lower.as_str()) {
        return ToolKind::Read;
    }
    if name_words.iter().chain(description_words.iter()).any(|w| UNKNOWN_DANGER_WORDS.contains(&w.as_str())) {
        return ToolKind::Blocked;
    }
    let says_read_only = text.contains("read-only") || text.contains("read only")
        || text.contains("does not modify") || text.contains("without modifying");
    let mutates = name_words.iter().chain(description_words.iter())
        .any(|w| MUTATION_WORDS.contains(&w.as_str()));
    if says_read_only && !mutates { ToolKind::Read } else { ToolKind::Blocked }
}

// ---------------------------------------------------------------------------------------------
// Registration (REA-compatible headless JSON)
// ---------------------------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct Registration {
    pub path: PathBuf,
    pub command: PathBuf,
    pub args: Vec<String>,
    pub env: Vec<(String, String)>,
    pub mode: String,
}

/// Parse `{"command","args","mode","env"}`. Only a stdio headless profile without upstream's
/// `--unsafe` switch (which exposes py_eval) is accepted for the bridge.
pub fn load_registration(path: &Path) -> Result<Registration> {
    let bytes = std::fs::read(path).with_context(|| format!("Could not read IDA registration {}", path.display()))?;
    let bytes = bytes.strip_prefix(b"\xEF\xBB\xBF".as_slice()).unwrap_or(&bytes);
    let value: Value = serde_json::from_slice(bytes).context("The IDA registration is not valid JSON")?;
    parse_registration(path, &value)
}
pub fn parse_registration(path: &Path, value: &Value) -> Result<Registration> {
    let command = PathBuf::from(value["command"].as_str().context("The IDA registration has no command")?);
    if !command.is_absolute() || !command.is_file() {
        bail!("The IDA registration command must be an existing absolute executable: {}", command.display());
    }
    let args: Vec<String> = match &value["args"] {
        Value::Null => vec![],
        Value::Array(items) => items.iter().map(|a| a.as_str().map(str::to_owned).context("Registration args must be strings")).collect::<Result<_>>()?,
        _ => bail!("Registration args must be an array"),
    };
    if !args.iter().any(|a| a == "--stdio") { bail!("The headless IDA registration must use --stdio"); }
    if args.iter().any(|a| a == "--unsafe") { bail!("Registrations with --unsafe expose code execution and are refused"); }
    let mode = value["mode"].as_str().unwrap_or("").to_owned();
    if mode != "headless" { bail!("Choose a headless IDA registration (mode \"headless\"); attached registrations are for REA's legacy profile"); }
    let mut env = vec![];
    if let Some(map) = value["env"].as_object() {
        for (key, value) in map {
            env.push((key.clone(), value.as_str().context("Registration env values must be strings")?.to_owned()));
        }
    } else if !value["env"].is_null() {
        bail!("Registration env must be an object");
    }
    Ok(Registration { path: path.to_path_buf(), command, args, env, mode })
}

// ---------------------------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------------------------

/// A timed-out request was cancelled with notifications/cancelled; the session remains usable.
#[derive(Debug)]
pub struct Timeout(pub String);
impl std::fmt::Display for Timeout {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { f.write_str(&self.0) }
}
impl std::error::Error for Timeout {}

pub struct StdioClient {
    child: Child,
    _job: Option<quixi_platform::ProcessJob>,
    input: ChildStdin,
    responses: mpsc::Receiver<Result<Value, String>>,
    stderr: Arc<Mutex<VecDeque<String>>>,
    id: u64,
    /// Requests that timed out; their late replies are discarded.
    abandoned: HashSet<u64>,
    broken: bool,
}

/// The top-level `id` of a JSON-RPC response frame, read from the frame's start (servers
/// write `jsonrpc`/`id` before `result`/`error`). `None` when it cannot be attributed.
fn frame_id(frame: &[u8]) -> Option<u64> {
    let text = String::from_utf8_lossy(&frame[..frame.len().min(256)]);
    let (end, first) = ["\"result\"", "\"error\"", "\"method\"", "\"params\""]
        .iter()
        .filter_map(|key| text.find(key).map(|at| (at, *key)))
        .min()?;
    let head = &text[..end];
    // Only the frame's own object may be open, and server requests are never ours.
    if first == "\"method\"" || first == "\"params\"" || head.matches(['{', '[']).count() != 1 {
        return None;
    }
    let rest = head[head.find("\"id\"")? + 4..].trim_start().strip_prefix(':')?.trim_start();
    let digits: String = rest.chars().take_while(char::is_ascii_digit).collect();
    digits.parse().ok()
}

fn push_tail(tail: &Mutex<VecDeque<String>>, line: String) {
    let mut tail = tail.lock();
    tail.push_back(line.chars().take(2000).collect());
    while tail.len() > STDERR_LINES { tail.pop_front(); }
}

impl StdioClient {
    pub fn spawn(registration: &Registration) -> Result<Self> {
        let mut command = quixi_platform::background_command(&registration.command);
        command.args(&registration.args)
            .env("PYTHONUNBUFFERED", "1")
            .env("PYTHONIOENCODING", "utf-8")
            .stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
        for (key, value) in &registration.env { command.env(key, value); }
        if let Some(dir) = registration.command.parent() { command.current_dir(dir); }
        let mut child = command.spawn().context("Could not start idalib-mcp")?;
        // Workers are spawned later by the supervisor and inherit this job.
        let job = match quixi_platform::ProcessJob::assign(&child) {
            Ok(job) => Some(job),
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(error.context("Could not contain idalib-mcp in a Job Object"));
            }
        };
        let input = child.stdin.take().context("idalib-mcp stdin unavailable")?;
        let stdout = child.stdout.take().context("idalib-mcp stdout unavailable")?;
        let stderr_pipe = child.stderr.take().context("idalib-mcp stderr unavailable")?;
        let stderr = Arc::new(Mutex::new(VecDeque::new()));
        let (tx, responses) = mpsc::sync_channel(64);
        let noise = stderr.clone();
        std::thread::spawn(move || {
            let mut reader = BufReader::new(stdout);
            loop {
                let mut line = Vec::new();
                match reader.by_ref().take(FRAME_LIMIT + 1).read_until(b'\n', &mut line) {
                    Ok(0) => break,
                    Ok(n) if n as u64 > FRAME_LIMIT && line.last() != Some(&b'\n') => {
                        // Discard the remainder of the oversized frame and stay in sync.
                        let mut rest = Vec::new();
                        loop {
                            rest.clear();
                            match reader.by_ref().take(1 << 20).read_until(b'\n', &mut rest) {
                                Ok(0) | Err(_) => return,
                                Ok(_) if rest.last() == Some(&b'\n') => break,
                                Ok(_) => continue,
                            }
                        }
                        let marker = match frame_id(&line) {
                            Some(id) => json!({"__oversized": true, "id": id}),
                            None => json!({"__oversized": true}),
                        };
                        if tx.send(Ok(marker)).is_err() { break; }
                    }
                    Ok(_) => {
                        let text = String::from_utf8_lossy(&line);
                        let text = text.trim();
                        if text.is_empty() { continue; }
                        match serde_json::from_str::<Value>(text) {
                            Ok(value) if value.is_object() => {
                                if tx.send(Ok(value)).is_err() { break; }
                            }
                            // Library banners or prints on stdout are not protocol frames.
                            _ => push_tail(&noise, format!("[stdout] {text}\n")),
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
                let mut line = Vec::new();
                match reader.by_ref().take(8192).read_until(b'\n', &mut line) {
                    Ok(0) | Err(_) => break,
                    Ok(_) => push_tail(&captured, String::from_utf8_lossy(&line).into_owned()),
                }
            }
        });
        let mut client = Self { child, _job: job, input, responses, stderr, id: 0, abandoned: HashSet::new(), broken: false };
        let initialized = client.request("initialize", initialize_params(), Duration::from_secs(60))?;
        if initialized.get("protocolVersion").is_none() { bail!("idalib-mcp returned an invalid initialization response"); }
        client.send(&json!({"jsonrpc":"2.0","method":"notifications/initialized"}))?;
        Ok(client)
    }
    pub fn pid(&self) -> u32 { self.child.id() }
    fn send(&mut self, value: &Value) -> Result<()> {
        let result = (|| -> std::io::Result<()> {
            serde_json::to_writer(&mut self.input, value)?;
            self.input.write_all(b"\n")?;
            self.input.flush()
        })();
        if let Err(error) = result {
            self.broken = true;
            bail!("idalib-mcp is no longer accepting requests ({error}). {}", self.stderr_tail());
        }
        Ok(())
    }
    pub fn stderr_tail(&self) -> String {
        self.stderr.lock().iter().cloned().collect::<String>()
    }
    pub fn alive(&mut self) -> bool {
        !self.broken && matches!(self.child.try_wait(), Ok(None))
    }
    pub fn request(&mut self, method: &str, params: Value, timeout: Duration) -> Result<Value> {
        self.id += 1;
        let id = self.id;
        self.send(&json!({"jsonrpc":"2.0","id":id,"method":method,"params":params}))?;
        let deadline = Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let message = match self.responses.recv_timeout(remaining) {
                Ok(Ok(message)) => message,
                Ok(Err(error)) => {
                    self.broken = true;
                    bail!("idalib-mcp transport failed: {error}. {}", self.stderr_tail());
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    self.abandoned.insert(id);
                    let _ = self.send(&json!({"jsonrpc":"2.0","method":"notifications/cancelled",
                        "params":{"requestId":id,"reason":"Timed out in REA Studio"}}));
                    return Err(Timeout(format!("IDA did not answer {method} within {}s. The request was cancelled; the session remains open, but the operation may still finish in IDA.", timeout.as_secs())).into());
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    self.broken = true;
                    bail!("idalib-mcp exited. {}", self.stderr_tail());
                }
            };
            if message.get("__oversized").is_some() {
                // Framing is intact (the reader skipped to the next line); only fail this
                // request when the frame is its reply or cannot belong to anything else.
                let frame = message.get("id").and_then(Value::as_u64);
                let late = match frame {
                    Some(other) => other != id,
                    None => !self.abandoned.is_empty(),
                };
                if late {
                    if let Some(other) = frame { self.abandoned.remove(&other); }
                    let owner = frame.map_or("an abandoned request".to_owned(), |other| format!("abandoned request {other}"));
                    push_tail(&self.stderr, format!("[REA Studio] Discarded an oversized (>16 MiB) late reply to {owner}.\n"));
                    continue;
                }
                bail!("IDA's response exceeded 16 MiB and was discarded. Narrow the query or page it (offset/count).");
            }
            if let Some(server_method) = message.get("method").and_then(Value::as_str) {
                if let Some(request_id) = message.get("id") {
                    let reply = if server_method == "ping" {
                        json!({"jsonrpc":"2.0","id":request_id,"result":{}})
                    } else {
                        json!({"jsonrpc":"2.0","id":request_id,"error":{"code":-32601,"message":"Client method not supported"}})
                    };
                    self.send(&reply)?;
                }
                continue;
            }
            if let Some(other) = message.get("id").and_then(Value::as_u64).filter(|other| *other != id) {
                self.abandoned.remove(&other);
                continue;
            }
            if message.get("id").and_then(Value::as_u64) != Some(id) { continue; }
            if let Some(error) = message.get("error") { bail!("IDA MCP error: {error}"); }
            return message.get("result").cloned().context("IDA MCP result is missing");
        }
    }
}
impl Drop for StdioClient {
    fn drop(&mut self) {
        // The job terminates the supervisor and every idalib worker it started.
        if let Some(job) = &self._job { job.terminate(); }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn initialize_params() -> Value {
    json!({"protocolVersion":PROTOCOL_VERSION,"capabilities":{},
        "clientInfo":{"name":"REA Studio","version":env!("CARGO_PKG_VERSION")}})
}

/// Parsed loopback URL. Only http://127.0.0.1, http://localhost and http://[::1] are accepted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LoopbackUrl {
    pub host: String,
    pub port: u16,
    pub path: String,
}
pub fn parse_loopback_url(url: &str) -> Result<LoopbackUrl> {
    let rest = url.trim().strip_prefix("http://").context("Use an http:// loopback URL (for example http://127.0.0.1:13337/mcp)")?;
    let (authority, path) = match rest.find('/') {
        Some(index) => (&rest[..index], &rest[index..]),
        None => (rest, "/mcp"),
    };
    if authority.contains('@') { bail!("Credentials in the IDA URL are not supported"); }
    let (host, port) = if let Some(stripped) = authority.strip_prefix('[') {
        let end = stripped.find(']').context("Invalid IPv6 address")?;
        let port = stripped[end + 1..].strip_prefix(':');
        (format!("[{}]", &stripped[..end]), port)
    } else {
        match authority.rsplit_once(':') {
            Some((host, port)) => (host.to_owned(), Some(port)),
            None => (authority.to_owned(), None),
        }
    };
    let host = host.to_ascii_lowercase();
    if !matches!(host.as_str(), "127.0.0.1" | "localhost" | "[::1]") {
        bail!("Only a local IDA (127.0.0.1, localhost or [::1]) can be attached");
    }
    let port = match port {
        Some(p) => p.parse::<u16>().ok().filter(|p| *p > 0).context("Invalid port in the IDA URL")?,
        None => 80,
    };
    let path = if path.is_empty() || path == "/" { "/mcp".to_owned() } else { path.to_owned() };
    if path.contains(['\r', '\n', ' ']) { bail!("Invalid path in the IDA URL"); }
    Ok(LoopbackUrl { host, port, path })
}

pub struct HttpClient {
    url: LoopbackUrl,
    address: SocketAddr,
    session: Option<String>,
    protocol: String,
    id: u64,
    broken: bool,
}

/// Decodes HTTP/1.1 chunked bodies as a byte stream.
struct Chunked<R> { inner: R, remaining: usize, done: bool }
impl<R: BufRead> Read for Chunked<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.done { return Ok(0); }
        if self.remaining == 0 {
            let mut line = String::new();
            self.inner.by_ref().take(1024).read_line(&mut line)?;
            let size = usize::from_str_radix(line.trim().split(';').next().unwrap_or(""), 16)
                .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid chunk size"))?;
            if size == 0 { self.done = true; return Ok(0); }
            self.remaining = size;
        }
        let limit = buf.len().min(self.remaining);
        let n = self.inner.read(&mut buf[..limit])?;
        if n == 0 { return Err(std::io::ErrorKind::UnexpectedEof.into()); }
        self.remaining -= n;
        if self.remaining == 0 {
            let mut crlf = String::new();
            self.inner.by_ref().take(2).read_line(&mut crlf)?;
        }
        Ok(n)
    }
}

impl HttpClient {
    pub fn connect(url: &str) -> Result<Self> {
        let url = parse_loopback_url(url)?;
        let address = (url.host.trim_start_matches('[').trim_end_matches(']'), url.port)
            .to_socket_addrs().context("Could not resolve the local IDA address")?
            .find(|a| a.ip().is_loopback())
            .context("The IDA address does not resolve to a loopback interface")?;
        let mut client = Self { url, address, session: None, protocol: PROTOCOL_VERSION.into(), id: 0, broken: false };
        let initialized = client.request("initialize", initialize_params(), Duration::from_secs(20))?;
        let version = initialized.get("protocolVersion").and_then(Value::as_str)
            .context("The local endpoint did not answer MCP initialize. Use a current ida-pro-mcp plugin (the legacy 1.4.0 plugin is REA's attached profile, not this bridge)")?;
        client.protocol = version.to_owned();
        client.post(&json!({"jsonrpc":"2.0","method":"notifications/initialized"}), None, Duration::from_secs(10))?;
        Ok(client)
    }
    pub fn alive(&self) -> bool { !self.broken }
    pub fn url(&self) -> String { format!("http://{}:{}{}", self.url.host, self.url.port, self.url.path) }
    pub fn request(&mut self, method: &str, params: Value, timeout: Duration) -> Result<Value> {
        self.id += 1;
        let id = self.id;
        let message = json!({"jsonrpc":"2.0","id":id,"method":method,"params":params});
        let response = match self.post(&message, Some(id), timeout) {
            Ok(response) => response,
            Err(error) if error.downcast_ref::<std::io::Error>().is_some_and(|e| matches!(e.kind(), std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock)) => {
                let cancel = json!({"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":id,"reason":"Timed out in REA Studio"}});
                let _ = self.post(&cancel, None, Duration::from_secs(5));
                return Err(Timeout(format!("IDA did not answer {method} within {}s. The request was cancelled; the session remains open, but the operation may still finish in IDA.", timeout.as_secs())).into());
            }
            Err(error) => {
                if error.downcast_ref::<std::io::Error>().is_some() { self.broken = true; }
                return Err(error);
            }
        };
        let message = response.context("The local IDA endpoint returned no response")?;
        if let Some(error) = message.get("error") { bail!("IDA MCP error: {error}"); }
        message.get("result").cloned().context("IDA MCP result is missing")
    }
    fn post(&mut self, message: &Value, id: Option<u64>, timeout: Duration) -> Result<Option<Value>> {
        let deadline = Instant::now() + timeout;
        let body = serde_json::to_vec(message)?;
        let mut stream = TcpStream::connect_timeout(&self.address, timeout.min(Duration::from_secs(10)))?;
        stream.set_nodelay(true).ok();
        stream.set_write_timeout(Some(Duration::from_secs(30)))?;
        let mut head = format!(
            "POST {} HTTP/1.1\r\nHost: {}:{}\r\nContent-Type: application/json\r\nAccept: application/json, text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\nMCP-Protocol-Version: {}\r\n",
            self.url.path, self.url.host, self.url.port, body.len(), self.protocol);
        if let Some(session) = &self.session { head.push_str(&format!("Mcp-Session-Id: {session}\r\n")); }
        head.push_str("\r\n");
        stream.write_all(head.as_bytes())?;
        stream.write_all(&body)?;
        stream.flush()?;
        let remaining = || deadline.saturating_duration_since(Instant::now()).max(Duration::from_millis(10));
        stream.set_read_timeout(Some(remaining()))?;
        // A second handle to the socket so the SSE loop can shrink the read timeout.
        let control = stream.try_clone()?;
        let mut reader = BufReader::new(stream);
        let mut status_line = String::new();
        reader.by_ref().take(4096).read_line(&mut status_line)?;
        let status: u16 = status_line.split_whitespace().nth(1).and_then(|s| s.parse().ok())
            .with_context(|| format!("Invalid HTTP response from the local IDA endpoint: {}", status_line.trim()))?;
        let (mut length, mut chunked, mut content_type) = (None::<u64>, false, String::new());
        let mut header_bytes = 0;
        loop {
            let mut line = String::new();
            header_bytes += reader.by_ref().take(16384).read_line(&mut line)?;
            if header_bytes > 65536 { bail!("HTTP headers from the local IDA endpoint are too large"); }
            let line = line.trim_end();
            if line.is_empty() { break; }
            let Some((name, value)) = line.split_once(':') else { continue };
            let (name, value) = (name.trim().to_ascii_lowercase(), value.trim());
            match name.as_str() {
                "content-length" => length = value.parse().ok(),
                "transfer-encoding" => chunked = value.to_ascii_lowercase().contains("chunked"),
                "content-type" => content_type = value.to_ascii_lowercase(),
                "mcp-session-id" if !value.is_empty() && value.len() < 256 && value.is_ascii() => self.session = Some(value.to_owned()),
                _ => {}
            }
        }
        if length.is_some_and(|l| l > FRAME_LIMIT) { bail!("IDA's response exceeds 16 MiB. Narrow the query or page it (offset/count)."); }
        let mut body: Box<dyn BufRead> = if chunked {
            Box::new(BufReader::new(Chunked { inner: reader, remaining: 0, done: false }).take(FRAME_LIMIT + 1))
        } else if let Some(length) = length {
            Box::new(reader.take(length))
        } else {
            Box::new(reader.take(FRAME_LIMIT + 1))
        };
        if status == 202 || (id.is_none() && (200..300).contains(&status)) { return Ok(None); }
        if status == 404 && self.session.is_some() {
            self.broken = true;
            bail!("The IDA MCP session expired. Disable and re-enable the attached IDA connection.");
        }
        if !(200..300).contains(&status) {
            let mut text = String::new();
            let _ = body.by_ref().take(2000).read_to_string(&mut text);
            bail!("The local IDA endpoint answered HTTP {status}: {}", text.trim());
        }
        if content_type.starts_with("text/event-stream") {
            // Dispatch SSE events until the response to this request arrives.
            let mut data = String::new();
            let mut total = 0u64;
            loop {
                // Each read is bounded by what is left of the whole request, not per read.
                if Instant::now() >= deadline {
                    return Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "The IDA event stream did not answer before the request deadline").into());
                }
                control.set_read_timeout(Some(remaining()))?;
                let mut line = String::new();
                let n = body.read_line(&mut line)?;
                total += n as u64;
                if total > FRAME_LIMIT { bail!("IDA's response exceeds 16 MiB. Narrow the query or page it."); }
                let ended = n == 0;
                let line = line.trim_end_matches(['\r', '\n']);
                if line.is_empty() {
                    if !data.is_empty() {
                        if let Ok(value) = serde_json::from_str::<Value>(&data) {
                            if value.get("id").and_then(Value::as_u64) == id && value.get("method").is_none() {
                                return Ok(Some(value));
                            }
                        }
                        data.clear();
                    }
                    if ended { bail!("The IDA event stream ended without a response"); }
                } else if let Some(rest) = line.strip_prefix("data:") {
                    if !data.is_empty() { data.push('\n'); }
                    data.push_str(rest.strip_prefix(' ').unwrap_or(rest));
                }
            }
        }
        let mut bytes = Vec::new();
        body.read_to_end(&mut bytes)?;
        if bytes.len() as u64 > FRAME_LIMIT { bail!("IDA's response exceeds 16 MiB. Narrow the query or page it."); }
        let value: Value = serde_json::from_slice(&bytes).context("The local IDA endpoint returned invalid JSON")?;
        Ok(Some(value))
    }
}

pub enum Connection {
    Stdio(StdioClient),
    Http(HttpClient),
}
impl Connection {
    pub fn transport(&self) -> &'static str {
        match self { Connection::Stdio(_) => "headless", Connection::Http(_) => "attached" }
    }
    pub fn request(&mut self, method: &str, params: Value, timeout: Duration) -> Result<Value> {
        match self {
            Connection::Stdio(client) => client.request(method, params, timeout),
            Connection::Http(client) => client.request(method, params, timeout),
        }
    }
    pub fn alive(&mut self) -> bool {
        match self { Connection::Stdio(client) => client.alive(), Connection::Http(client) => client.alive() }
    }
    pub fn diagnostics(&self) -> String {
        match self { Connection::Stdio(client) => client.stderr_tail(), Connection::Http(_) => String::new() }
    }
    /// The full live catalog, following pagination.
    pub fn list_tools(&mut self, timeout: Duration) -> Result<Vec<Value>> {
        let mut tools = vec![];
        let mut params = json!({});
        for _ in 0..50 {
            let page = self.request("tools/list", params, timeout)?;
            tools.extend(page["tools"].as_array().context("Invalid IDA tool catalog")?.iter().cloned());
            if tools.len() > 1000 { bail!("IDA tool catalog exceeds the supported size"); }
            match page.get("nextCursor").and_then(Value::as_str) {
                Some(cursor) => params = json!({"cursor":cursor}),
                None => break,
            }
        }
        Ok(tools)
    }
    pub fn call_tool(&mut self, name: &str, arguments: Value, timeout: Duration) -> Result<Value> {
        self.request("tools/call", json!({"name":name,"arguments":arguments}), timeout)
    }
}

/// Text content of a tool result.
pub fn text_result(response: &Value) -> String {
    response["content"].as_array().into_iter().flatten()
        .filter_map(|c| c["text"].as_str()).collect::<Vec<_>>().join("\n")
}
/// Structured payload of a tool result: structuredContent, else the first JSON text item.
pub fn payload(response: &Value) -> Value {
    if let Some(value) = response.get("structuredContent").filter(|v| !v.is_null()) {
        return value.clone();
    }
    response["content"].as_array().into_iter().flatten()
        .filter_map(|c| c["text"].as_str())
        .find_map(|t| serde_json::from_str(t).ok())
        .unwrap_or(Value::Null)
}
/// ida-pro-mcp reports many failures as `{"error": ...}` payloads; never treat them as success.
pub fn normalize(mut response: Value) -> Value {
    let payload = payload(&response);
    let failed = payload.get("error").is_some_and(|e| !e.is_null() && e != "")
        || payload.get("success") == Some(&Value::Bool(false));
    if failed { response["isError"] = json!(true); }
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn execution_patching_and_session_tools_are_blocked() {
        for name in ["py_eval", "py_exec_file", "patch", "patch_asm", "put_int", "dbg_start", "dbg_write",
            "dbg_regs", "idb_open", "idb_close", "idb_list", "diff_before_after", "DBG_step_into"] {
            assert_eq!(classify(name, "Read things"), ToolKind::Blocked, "{name}");
        }
        // A known read tool whose live description advertises execution is still blocked.
        assert_eq!(classify("decompile", "Execute Python in IDA"), ToolKind::Blocked);
        assert_eq!(classify("decompile", "Decompile function at the given address"), ToolKind::Read);
    }

    #[test]
    fn annotations_only_change_the_private_database() {
        for name in ["rename", "set_comments", "add_bookmark", "declare_type", "set_type", "declare_stack",
            "delete_stack", "define_func", "define_code", "undefine", "infer_types", "idb_save"] {
            assert_eq!(classify(name, "Annotate the database"), ToolKind::Annotate, "{name}");
        }
        for name in ["lookup_funcs", "list_funcs", "decompile", "disasm", "xrefs_to", "callees",
            "find_regex", "survey_binary", "server_health", "get_bytes", "stack_frame"] {
            assert_eq!(classify(name, "Query the database"), ToolKind::Read, "{name}");
        }
    }

    #[test]
    fn unknown_tools_default_to_blocked() {
        assert_eq!(classify("new_tool", "Does something useful"), ToolKind::Blocked);
        assert_eq!(classify("new_lister", "List functions (read-only)."), ToolKind::Read);
        assert_eq!(classify("new_writer", "Read-only preview, then write bytes"), ToolKind::Blocked);
        assert_eq!(classify("new_loader", "Read-only: load a file from a path"), ToolKind::Blocked);
        assert_eq!(classify("run_script", "read-only"), ToolKind::Blocked);
    }

    #[test]
    fn only_loopback_urls_are_accepted() {
        assert_eq!(parse_loopback_url("http://127.0.0.1:13337/mcp").unwrap(),
            LoopbackUrl { host: "127.0.0.1".into(), port: 13337, path: "/mcp".into() });
        assert_eq!(parse_loopback_url("http://localhost:8744").unwrap().path, "/mcp");
        assert_eq!(parse_loopback_url("http://[::1]:9000/mcp").unwrap().host, "[::1]");
        for url in ["https://127.0.0.1:1/mcp", "http://10.0.0.1:13337/mcp", "http://127.0.0.1.evil:1/",
            "http://user@127.0.0.1:1/", "http://example.com/mcp", "http://127.0.0.1:0/", "ftp://localhost/"] {
            assert!(parse_loopback_url(url).is_err(), "{url}");
        }
    }

    #[test]
    fn registrations_must_be_headless_stdio_without_unsafe() {
        let exe = std::env::current_exe().unwrap();
        let good = json!({"command":exe,"args":["--stdio","--max-workers","1"],"mode":"headless","env":{"IDADIR":"C:\\IDA"}});
        let parsed = parse_registration(Path::new("r.json"), &good).unwrap();
        assert_eq!(parsed.env, vec![("IDADIR".to_owned(), "C:\\IDA".to_owned())]);
        let mut unsafe_args = good.clone();
        unsafe_args["args"] = json!(["--stdio", "--unsafe"]);
        assert!(parse_registration(Path::new("r.json"), &unsafe_args).is_err());
        let mut attached = good.clone();
        attached["mode"] = json!("attached");
        assert!(parse_registration(Path::new("r.json"), &attached).is_err());
        let mut relative = good.clone();
        relative["command"] = json!("idalib-mcp");
        assert!(parse_registration(Path::new("r.json"), &relative).is_err());
    }

    #[test]
    fn error_payloads_are_failures() {
        let failed = normalize(json!({"content":[{"type":"text","text":"{\"error\":\"Session not found: x\"}"}]}));
        assert_eq!(failed["isError"], true);
        let ok = normalize(json!({"content":[{"type":"text","text":"{\"addr\":\"0x1\"}"}],"structuredContent":{"addr":"0x1"}}));
        assert!(ok.get("isError").is_none());
        assert_eq!(text_result(&ok), "{\"addr\":\"0x1\"}");
    }

    #[test]
    fn chunked_bodies_decode() {
        let raw = b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        let mut out = String::new();
        Chunked { inner: BufReader::new(&raw[..]), remaining: 0, done: false }.read_to_string(&mut out).unwrap();
        assert_eq!(out, "hello world");
    }

    #[test]
    fn oversized_frames_are_attributed_by_their_leading_id() {
        assert_eq!(frame_id(br#"{"jsonrpc":"2.0","id":7,"result":{"content":[{"id":9}]}}"#), Some(7));
        assert_eq!(frame_id(br#"{ "id" : 12 , "jsonrpc": "2.0", "error": {}}"#), Some(12));
        // `id` only inside the result, a server request, or a cut-off start: unattributable.
        assert_eq!(frame_id(br#"{"jsonrpc":"2.0","result":{"id":3}}"#), None);
        assert_eq!(frame_id(br#"{"jsonrpc":"2.0","id":4,"method":"sampling/createMessage"}"#), None);
        assert_eq!(frame_id(br#"{"jsonrpc":"2.0","id":"#), None);
    }

    /// An event stream that keeps sending keep-alive comments must still end at the
    /// request deadline, not after each read's timeout.
    #[test]
    fn event_stream_respects_the_overall_request_deadline() {
        use std::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for stream in listener.incoming().take(2).flatten() {
                std::thread::spawn(move || {
                    let mut reader = BufReader::new(stream.try_clone().unwrap());
                    let mut length = 0;
                    loop {
                        let mut line = String::new();
                        if reader.read_line(&mut line).unwrap_or(0) == 0 { return; }
                        if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                            length = value.trim().parse().unwrap_or(0);
                        }
                        if line == "\r\n" { break; }
                    }
                    let mut body = vec![0; length];
                    let _ = reader.read_exact(&mut body);
                    let mut stream = stream;
                    if String::from_utf8_lossy(&body).contains("notifications/cancelled") {
                        let _ = stream.write_all(b"HTTP/1.1 202 Accepted\r\nContent-Length: 0\r\n\r\n");
                        return;
                    }
                    let _ = stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\r\n");
                    for _ in 0..100 {
                        if stream.write_all(b": keep-alive\n").is_err() { return; }
                        std::thread::sleep(Duration::from_millis(100));
                    }
                });
            }
        });
        let url = parse_loopback_url(&format!("http://127.0.0.1:{port}/mcp")).unwrap();
        let address = SocketAddr::from(([127, 0, 0, 1], port));
        let mut client = HttpClient { url, address, session: None, protocol: PROTOCOL_VERSION.into(), id: 0, broken: false };
        let started = Instant::now();
        let error = client.request("tools/call", json!({}), Duration::from_secs(1)).unwrap_err();
        assert!(error.downcast_ref::<Timeout>().is_some(), "{error}");
        assert!(started.elapsed() < Duration::from_secs(4), "took {:?}", started.elapsed());
        assert!(client.alive());
    }

    /// Names and descriptions from the live `tools/list` of idalib-mcp (ida-pro-mcp c133c385,
    /// IDA Professional 9.3), captured by the headless bridge probe.
    const LIVE_CATALOG: &[(&str, &str)] = &[
        ("server_health", "Health/ready probe for MCP server and current IDB state."),
        ("lookup_funcs", "Get functions by address or name (auto-detects)"),
        ("int_convert", "Convert numbers to different formats"),
        ("list_funcs", "List functions with optional filtering and offset/count pagination."),
        ("func_query", "Query functions with richer filtering than list_funcs."),
        ("list_globals", "List globals with optional filtering and offset/count pagination."),
        ("entity_query", "Query IDB entities with typed filters, projection, and pagination."),
        ("imports", "List imports with module names using offset/count pagination."),
        ("imports_query", "Query imports with richer filtering than imports(offset,count)."),
        ("idb_save", "Save active IDB to disk, optionally to a provided path. The open database is backed by loose working files (.id0/.id1/.id2/.nam/.til) that IDA actively manages, headless included. Killing them out from under the open database corrupts it (issues #446, #498), so DBFL_KILL is never used here: an in-place save uses IDA's native save (Ctrl+W), and an explicit different destination gets a compressed copy while the working files stay."),
        ("find_regex", "Search strings by case-insensitive regex with offset/limit pagination."),
        ("search_text", "Search the rendered listing for `pattern` over [start, end). Iterates `idautils.Heads()` in pure Python and renders each via `ida_lines.generate_disassembly()`. Per-head iteration is cheap and yields between heads, so the per-tool deadline (sync_wrapper) and the UI Cancel button both interrupt the walk reliably — unlike the C-level `ida_search.find_text()` it replaced, which on huge .text segments could run for minutes without polling `user_cancelled()`. Use `start`/`end` to scope the work for predictable performance on large binaries; without them the scan covers the whole image."),
        ("decompile", "Decompile a function. Follow cursor.next for more code; refs appear on the first page."),
        ("disasm", "Disassemble function with offset/max_instructions pagination and optional total count."),
        ("func_profile", "Profile functions with summary metrics and optional sampled details."),
        ("analyze_batch", "Run comprehensive analysis over one or more target functions."),
        ("xrefs_to", "Return xrefs to address(es) or named symbols, capped per target with truncation flag."),
        ("xref_query", "Query xrefs with direction/type filters and pagination."),
        ("xrefs_to_field", "Get cross-references to structure fields"),
        ("callees", "Return unique callees per function, capped by limit."),
        ("find_bytes", "Search byte patterns (supports ??) with offset/limit pagination."),
        ("basic_blocks", "Return function CFG blocks with offset/max_blocks pagination."),
        ("find", "Search strings/immediates/refs for targets with offset/limit pagination."),
        ("insn_query", "Query instructions with mnemonic/operand filters and scoped scans."),
        ("export_funcs", "Export function data for addresses in json/c_header/prototypes formats."),
        ("callgraph", "Build bounded callgraph from roots with depth/node/edge limits."),
        ("get_bytes", "Read bytes from memory addresses"),
        ("get_int", "Read integer values from memory addresses"),
        ("get_string", "Read strings from memory addresses"),
        ("get_global_value", "Read global variable values by address or symbol name."),
        ("patch", "Patch bytes at memory addresses with hex data"),
        ("put_int", "Write integer values to memory addresses"),
        ("declare_type", "Declare C type definitions in local type library."),
        ("enum_upsert", "Create or extend local enums in an idempotent way."),
        ("read_struct", "Read struct fields from memory at address; auto-detect type when possible."),
        ("search_structs", "Search local structs/unions by name pattern."),
        ("type_query", "Query local types with structured filters/projection-friendly output."),
        ("type_inspect", "Inspect named types (size/kind/declaration/members)."),
        ("set_type", "Apply types (function/global/local/stack)"),
        ("type_apply_batch", "Apply multiple type edits and return aggregate status."),
        ("infer_types", "Infer and apply likely types at target addresses."),
        ("add_bookmark", "Add or replace the IDA bookmark at an address. Set prefix=\"\" for no prefix."),
        ("set_comments", "Set comments at addresses (both disassembly and decompiler views)"),
        ("append_comments", "Append comments at addresses, deduping exact text by default."),
        ("patch_asm", "Patch assembly instructions at addresses"),
        ("rename", "Batch-rename funcs/globals/locals/stack vars with dry-run options."),
        ("define_func", "Define functions; IDA infers bounds unless end is provided."),
        ("define_code", "Convert bytes to code instruction(s) at address(es)."),
        ("undefine", "Undefine item(s) at address(es), converting back to raw bytes."),
        ("force_recompile", "Invalidate the Hex-Rays decompile cache for one or more functions. Use after `set_type`, `rename` (especially of locals), `set_op_type`, or `make_data` so the next `decompile` call regenerates fresh pseudocode instead of returning a cached, stale view."),
        ("set_op_type", "Set the type of an instruction operand. GUI 'Y' / 'O' / '#' equivalent. Tags an operand at a specific instruction with a desired interpretation. Useful when the decompiler picks an awkward expression form (e.g., the \"earlier-named-symbol + offset\" form for contiguous globals). `kind` values: - `\"stroff\"`: struct-offset reference. Requires `struct`, optional `delta`. - `\"offset\"`: absolute offset / pointer. Optional `target_addr`. - `\"hex\" | \"dec\" | \"char\" | \"binary\" | \"octal\"`: numeric format. - `\"stkvar\"`: stack-variable reference (function-local)."),
        ("make_data", "Create a typed data symbol at an address, replacing any prior items. Use this to harden a symbol boundary that the decompiler is currently expressing through a neighboring global plus offset. `set_type` alone leaves the underlying byte items unchanged; this tool deletes them first, then re-creates them at the right size with the right type, then optionally renames. The `type` field is a full C declaration with a placeholder name, e.g. `\"ISP_SNS_STATE_S * g_pastImx290[4]\"` — IDA parses it via SetType."),
        ("stack_frame", "Return stack variables for function address(es)."),
        ("declare_stack", "Create stack variables from typed stack declarations."),
        ("delete_stack", "Delete stack variables by name or offset."),
        ("survey_binary", "Get a compact overview of the binary in one call. Returns file metadata, segment layout, entry points, statistics, top 15 strings and functions ranked by xref count (functions include classification: thunk/wrapper/leaf/dispatcher/ complex), imports by category, and call graph summary. Use this as your FIRST tool call when starting analysis. Do not call list_funcs, imports, or find_regex separately for triage — this returns all of that. Use detail_level='minimal' for binaries with >10k functions."),
        ("analyze_function", "Compact single-function analysis: pseudocode, strings, constants, callers, callees, xrefs, blocks."),
        ("analyze_component", "Analyze related functions as a group: per-function summaries, internal call graph, shared data."),
        ("trace_data_flow", "Follow cross-references from or to an address, automatically traversing multiple hops. Use 'forward' to see where data flows TO (xrefs-from), or 'backward' to see where data flows FROM (xrefs-to). At each node in the traversal, returns the function name, instruction, and whether it's code or data. Use this when you find an interesting string, constant, or global and want to understand every code path that touches it without manually chaining xrefs_to calls. Do not use for call graph traversal — use callgraph for that. max_depth controls how many hops to follow (default 5, max 20)."),
        ("make_signature", "Create unique byte signatures for addresses. Generates the shortest unique signature starting at each address by walking instructions and wildcarding operands. Useful for finding stable patterns that survive recompilation."),
        ("make_signature_for_function", "Create unique byte signatures for function entry points. Resolves each name/address to a function, then generates the shortest unique signature starting at the function start."),
        ("make_signature_for_range", "Create a byte signature for a specific address range (e.g. a selected region). Unlike make_signature, this does NOT guarantee uniqueness — it simply encodes the bytes in the range with optional operand wildcarding."),
        ("find_xref_signatures", "Find signatures for code locations that reference an address. For each input address, finds all code cross-references TO it, generates a unique signature at each xref site, and returns the shortest ones. Ideal for creating signatures for data addresses, vtable entries, or string references that can't be signatured directly."),
        ("idb_open", "Open a binary and warm it up. Returns the existing session if the file is already open under the supervisor; otherwise creates one according to `mode`."),
        ("idb_list", "List adopted sessions and discovered GUI/worker instances not yet opened through idb_open."),
        ("idb_close", "Close a session: optionally save it, unregister it from the supervisor, and terminate its owned worker (freeing a worker slot). Adopted GUI/worker instances are detached, not killed."),
    ];

    #[test]
    fn live_headless_catalog_classification() {
        let mut blocked = vec![];
        for (name, description) in LIVE_CATALOG {
            let kind = classify(name, description);
            match kind {
                ToolKind::Blocked => blocked.push(*name),
                ToolKind::Annotate => assert!(ANNOTATE_TOOLS.contains(name), "{name}"),
                ToolKind::Read => assert!(READ_TOOLS.contains(name), "{name}"),
            }
        }
        blocked.sort();
        assert_eq!(blocked, ["idb_close", "idb_list", "idb_open", "patch", "patch_asm", "put_int"]);
        let kind = |n: &str| LIVE_CATALOG.iter().find(|(name, _)| *name == n).map(|(n, d)| classify(n, d));
        assert_eq!(kind("search_text"), Some(ToolKind::Read));
        assert_eq!(kind("idb_save"), Some(ToolKind::Annotate));
        assert_eq!(kind("infer_types"), Some(ToolKind::Annotate));
        assert_eq!(kind("decompile"), Some(ToolKind::Read));
    }
}
