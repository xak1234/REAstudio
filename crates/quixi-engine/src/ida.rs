//! IDA Pro bridge: live ida-pro-mcp schemas bound to the selected artifact.
//!
//! Headless: the bridge owns an `idalib-mcp --stdio` supervisor and opens a private copy of the
//! selected artifact (app data `ida/<sha256>/<name>`), so the .i64 with renames, comments and
//! types persists across sessions without writing beside the original. Attached: a modern
//! ida-pro-mcp GUI plugin on a loopback URL, accepted only when IDA's input SHA-256 matches.
//! Every call re-checks that binding and is saved as evidence (provider "ida-bridge").
use crate::QuixiEngine;
use anyhow::{bail, Context, Result};
use parking_lot::Mutex;
use quixi_mcp::ida::{
    classify, load_registration, normalize, payload, text_result, Connection, HttpClient,
    StdioClient, Timeout, ToolKind, DEFAULT_ATTACHED_URL,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
    time::{Duration, SystemTime},
};

const AGENT_TEXT_LIMIT: usize = 24_000;
const ARGUMENT_LIMIT: usize = 64 * 1024;
const PROVIDER: &str = "ida-bridge";
/// (connection, live catalog, registration path, attached URL)
type Enabled = (Connection, Vec<Value>, Option<String>, Option<String>);
/// (input SHA-256, input path, IDB path, raw identity evidence)
type Identity = (Option<String>, Option<String>, Option<String>, Value);

#[derive(Clone, Debug)]
struct Session {
    /// Selected artifact path (canonical, as stored by the analysis workspace).
    target: String,
    sha256: String,
    size: u64,
    modified: Option<SystemTime>,
    /// Path IDA analyses: the private cached copy (headless) or IDA's input path (attached).
    input_path: String,
    idb_path: Option<String>,
    /// Supervisor session ID injected as `database` into every headless call.
    database: Option<String>,
}

struct State {
    transport: Option<&'static str>,
    url: Option<String>,
    registration: Option<String>,
    catalog: Vec<Value>,
    session: Option<Session>,
    allow_annotations: Option<bool>,
    last_error: Option<String>,
}

pub struct IdaWorkspace {
    connection: Mutex<Option<Connection>>,
    state: Mutex<State>,
    operation: Mutex<()>,
}

impl Default for IdaWorkspace {
    fn default() -> Self {
        // Starts disabled on every launch.
        Self {
            connection: Mutex::new(None),
            state: Mutex::new(State { transport: None, url: None, registration: None, catalog: vec![],
                session: None, allow_annotations: None, last_error: None }),
            operation: Mutex::new(()),
        }
    }
}

fn clean(path: &Path) -> String {
    path.to_string_lossy().trim_start_matches("\\\\?\\").to_owned()
}
fn same_path(a: &str, b: &str) -> bool {
    let normalize = |p: &str| p.replace('/', "\\").trim_start_matches("\\\\?\\").trim_end_matches('\\').to_owned();
    !a.is_empty() && normalize(a).eq_ignore_ascii_case(&normalize(b))
}
fn sha256_file(path: &Path) -> Result<String> {
    let mut file = fs::File::open(path).with_context(|| format!("Could not read {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buffer = vec![0u8; 1 << 20];
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 { break; }
        hasher.update(&buffer[..n]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}
fn timeout_for(tool: &str) -> Duration {
    match tool {
        "idb_open" => Duration::from_secs(900),
        "server_health" => Duration::from_secs(30),
        _ => Duration::from_secs(300),
    }
}
fn settings_path(engine: &QuixiEngine) -> PathBuf {
    engine.data_dir.join("ida").join("bridge-settings.json")
}

/// Validate a caller's tool request against the live classification and argument limits.
fn validate_call(kind: ToolKind, tool: &str, args: &Value, allow_annotations: bool) -> Result<()> {
    match kind {
        ToolKind::Blocked => bail!("{tool} is not available through the IDA bridge: code execution, byte patching, debugger control and database switching are never exposed. The bridge manages idb_open/idb_close itself."),
        ToolKind::Annotate if !allow_annotations => bail!("{tool} changes the private IDA database. Turn on Allow annotations in the IDA bridge settings first."),
        _ => {}
    }
    let map = args.as_object().context("IDA tool arguments must be a JSON object")?;
    if serde_json::to_vec(args)?.len() > ARGUMENT_LIMIT { bail!("IDA tool arguments exceed 64 KiB"); }
    // idb_save carries only the bridge-injected database and, at most, an empty path.
    let save_argument = |key: &str, value: &Value| {
        key == "database" || (key == "path" && (value.is_null() || value.as_str() == Some("")))
    };
    if tool == "idb_save" && !map.iter().all(|(key, value)| save_argument(key, value)) {
        bail!("idb_save may only save the bridge's own database in place; no destination or other argument is accepted");
    }
    Ok(())
}

/// Write `ida` to the headless registration, backing up the previous value once.
fn register_rea_paths(paths_file: &Path, registration: &str) -> Result<Value> {
    let mut paths: Value = fs::read(paths_file).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_else(|| json!({}));
    if !paths.is_object() { paths = json!({}); }
    let current = paths.get("ida").cloned().unwrap_or(Value::Null);
    if current.as_str().is_some_and(|c| same_path(c, registration)) {
        return Ok(json!({"changed":false,"ida":registration,"previous":paths.get("ida-attached-previous")}));
    }
    // Keep the original attached registration so it can be restored exactly.
    if paths.get("ida-attached-previous").is_none() {
        paths["ida-attached-previous"] = current;
    }
    paths["ida"] = json!(registration);
    if let Some(parent) = paths_file.parent() { fs::create_dir_all(parent)?; }
    fs::write(paths_file, serde_json::to_vec_pretty(&paths)?)?;
    Ok(json!({"changed":true,"ida":registration,"previous":paths["ida-attached-previous"]}))
}
fn restore_rea_paths(paths_file: &Path) -> Result<Value> {
    let mut paths: Value = fs::read(paths_file).ok().and_then(|b| serde_json::from_slice(&b).ok()).context("No toolchain configuration to restore")?;
    let map = paths.as_object_mut().context("Invalid toolchain configuration")?;
    let previous = map.remove("ida-attached-previous").context("No previous IDA registration was saved by Register for REA")?;
    match previous.as_str() {
        Some(path) => { map.insert("ida".into(), json!(path)); }
        None => { map.remove("ida"); }
    }
    fs::write(paths_file, serde_json::to_vec_pretty(&paths)?)?;
    Ok(json!({"restored":true,"ida":paths.get("ida")}))
}

impl IdaWorkspace {
    pub fn connected(&self) -> bool {
        if let Some(mut guard) = self.connection.try_lock() {
            if guard.as_mut().is_some_and(|c| !c.alive()) {
                let diagnostics = guard.as_ref().map(Connection::diagnostics).unwrap_or_default();
                *guard = None;
                let mut state = self.state.lock();
                state.transport = None;
                state.catalog.clear();
                state.session = None;
                state.last_error = Some(format!("The IDA connection ended. {}", diagnostics.trim()));
            }
        }
        self.state.lock().transport.is_some()
    }

    fn allow_annotations(&self, engine: &QuixiEngine) -> bool {
        let mut state = self.state.lock();
        *state.allow_annotations.get_or_insert_with(|| {
            fs::read(settings_path(engine)).ok().and_then(|b| serde_json::from_slice::<Value>(&b).ok())
                .and_then(|v| v["allowAnnotations"].as_bool()).unwrap_or(true)
        })
    }

    fn registration_path(engine: &QuixiEngine) -> Option<String> {
        crate::toolchain::path_for(engine, "ida-headless").ok().flatten()
    }

    fn tool_list(&self, catalog: &[Value], allow_annotations: bool) -> Vec<Value> {
        catalog.iter().filter_map(|t| {
            let name = t["name"].as_str()?;
            let kind = classify(name, t["description"].as_str().unwrap_or(""));
            Some(json!({"name":name,"kind":kind.as_str(),
                "enabled":kind == ToolKind::Read || (kind == ToolKind::Annotate && allow_annotations),
                "description":t["description"].as_str().unwrap_or("").chars().take(300).collect::<String>()}))
        }).collect()
    }

    pub fn status(&self, engine: &QuixiEngine) -> Value {
        let connected = self.connected();
        let allow = self.allow_annotations(engine);
        let registration = Self::registration_path(engine);
        let registration_error = registration.as_ref().and_then(|p| load_registration(Path::new(p)).err()).map(|e| e.to_string());
        let rea_registration = fs::read(engine.data_dir.join("toolchain-paths.json")).ok()
            .and_then(|b| serde_json::from_slice::<Value>(&b).ok()).and_then(|v| v["ida"].as_str().map(str::to_owned));
        let state = self.state.lock();
        json!({
            "installed": registration.is_some() && registration_error.is_none(),
            "registrationPath": registration, "registrationError": registration_error,
            "reaUsesHeadless": rea_registration.as_deref().zip(registration.as_deref()).is_some_and(|(a, b)| same_path(a, b)),
            "enabled": connected, "connected": connected, "transport": state.transport,
            "url": state.url, "defaultUrl": DEFAULT_ATTACHED_URL,
            "session": state.session.as_ref().map(|s| json!({"target":s.target,"sha256":s.sha256,
                "idbPath":s.idb_path,"inputPath":s.input_path,"database":s.database})),
            "tools": self.tool_list(&state.catalog, allow),
            "allowAnnotations": allow, "lastError": state.last_error,
        })
    }

    fn fail<T>(&self, error: anyhow::Error) -> Result<T> {
        self.state.lock().last_error = Some(error.to_string());
        Err(error)
    }

    pub fn enable(&self, engine: &QuixiEngine, transport: &str, url: Option<&str>) -> Result<Value> {
        let _op = self.operation.lock();
        if self.connected() {
            let current = self.state.lock().transport;
            if current == Some(transport) { return Ok(self.status(engine)); }
            bail!("Disable the current IDA connection before switching transport");
        }
        let result = (|| -> Result<Enabled> {
            let (mut connection, registration, url) = match transport {
                "headless" => {
                    let path = Self::registration_path(engine).context("Install the headless IDA bridge (Install-IDA-Bridge.ps1) or choose its rea-headless-registration.json in Toolchain")?;
                    let registration = load_registration(Path::new(&path))?;
                    (Connection::Stdio(StdioClient::spawn(&registration)?), Some(path), None)
                }
                "attached" => {
                    let url = url.filter(|u| !u.trim().is_empty()).unwrap_or(DEFAULT_ATTACHED_URL);
                    let client = HttpClient::connect(url)?;
                    let url = client.url();
                    (Connection::Http(client), None, Some(url))
                }
                _ => bail!("Choose transport \"headless\" or \"attached\""),
            };
            // The first headless catalog request starts a schema worker, which loads idalib.
            let catalog = connection.list_tools(Duration::from_secs(240))?;
            let has = |n: &str| catalog.iter().any(|t| t["name"] == n);
            if transport == "headless" && !(has("idb_open") && has("idb_close")) {
                bail!("This server does not advertise idalib-mcp's idb_open/idb_close");
            }
            if !has("decompile") || !(has("lookup_funcs") || has("list_funcs")) {
                bail!("This endpoint is not a current ida-pro-mcp server (no decompile/list_funcs). The legacy 1.4.0 plugin is REA's attached profile, not this bridge.");
            }
            Ok((connection, catalog, registration, url))
        })();
        match result {
            Ok((connection, catalog, registration, url)) => {
                *self.connection.lock() = Some(connection);
                let mut state = self.state.lock();
                state.transport = Some(if transport == "headless" { "headless" } else { "attached" });
                state.catalog = catalog;
                state.registration = registration;
                state.url = url;
                state.session = None;
                state.last_error = None;
                drop(state);
                Ok(self.status(engine))
            }
            Err(error) => self.fail(error),
        }
    }

    /// Save and close a headless database. Attached GUI databases belong to the user.
    fn close_session(&self, connection: &mut Connection, timeout: Duration) -> Result<Option<Value>> {
        let Some(session) = self.state.lock().session.take() else { return Ok(None) };
        let Some(database) = session.database else { return Ok(None) };
        let response = connection.call_tool("idb_close", json!({"database":database,"save":true}), timeout)?;
        Ok(Some(normalize(response)))
    }

    pub fn disable(&self, engine: &QuixiEngine) -> Value {
        let _op = self.operation.lock();
        let mut guard = self.connection.lock();
        if let Some(connection) = guard.as_mut() {
            if let Err(error) = self.close_session(connection, Duration::from_secs(120)) {
                self.state.lock().last_error = Some(format!("The database could not be closed cleanly: {error}"));
            }
        }
        // Dropping a headless connection terminates its job (supervisor and workers).
        *guard = None;
        drop(guard);
        let mut state = self.state.lock();
        state.transport = None;
        state.catalog.clear();
        state.session = None;
        state.url = None;
        drop(state);
        self.status(engine)
    }

    /// Best-effort save on application exit; the job still terminates everything afterwards.
    pub fn shutdown(&self) {
        if let Some(mut guard) = self.connection.try_lock() {
            if let Some(connection) = guard.as_mut() {
                let _ = self.close_session(connection, Duration::from_secs(15));
            }
            *guard = None;
        }
    }

    fn selected_target(engine: &QuixiEngine) -> Result<(String, fs::Metadata)> {
        let target = engine.analysis.target.lock().clone();
        if target.is_empty() { bail!("Select an artifact in Reverse engineering first"); }
        let metadata = fs::metadata(&target).context("The selected artifact is no longer available")?;
        if !metadata.is_file() { bail!("Select a file artifact; IDA cannot open a directory"); }
        Ok((target, metadata))
    }

    /// Copy the artifact into the private cache, keyed by content hash. Never writes beside it.
    fn cache_copy(engine: &QuixiEngine, target: &str, sha256: &str) -> Result<PathBuf> {
        let source = Path::new(target);
        let name = source.file_name().context("The artifact has no file name")?;
        let directory = engine.data_dir.join("ida").join(sha256);
        fs::create_dir_all(&directory)?;
        let copy = directory.join(name);
        if copy.is_file() {
            if sha256_file(&copy)? != sha256 {
                bail!("The cached copy {} no longer matches the artifact. Move that folder aside (it may contain your IDA database) and open again.", copy.display());
            }
            return Ok(copy);
        }
        let partial = directory.join(format!("{}.partial", name.to_string_lossy()));
        fs::copy(source, &partial).context("Could not copy the artifact into the IDA cache")?;
        if sha256_file(&partial)? != sha256 {
            let _ = fs::remove_file(&partial);
            bail!("The artifact changed while it was being copied; select it again");
        }
        fs::rename(&partial, &copy)?;
        Ok(copy)
    }

    fn open_headless(&self, connection: &mut Connection, catalog: &[Value], copy: &Path) -> Result<(String, String, Option<String>, Value)> {
        let properties = catalog.iter().find(|t| t["name"] == "idb_open")
            .and_then(|t| t.pointer("/inputSchema/properties")).cloned().unwrap_or_else(|| json!({}));
        let input = clean(copy);
        let mut args = json!({"input_path":input,"mode":"force_headless"});
        if properties.get("idle_ttl_sec").is_some() { args["idle_ttl_sec"] = json!(3600); }
        let response = normalize(connection.call_tool("idb_open", args, timeout_for("idb_open"))?);
        let opened = payload(&response);
        if response["isError"] == true {
            bail!("IDA could not open the cached artifact: {}", opened.get("error").map(Value::to_string).unwrap_or_else(|| text_result(&response)));
        }
        let database = opened.pointer("/session/session_id").and_then(Value::as_str).context("idb_open returned no session ID")?.to_owned();
        let opened_path = opened.pointer("/session/input_path").and_then(Value::as_str).unwrap_or("");
        if !same_path(opened_path, &input) {
            bail!("IDA bound a different input ({opened_path}) instead of the cached artifact; refusing");
        }
        let health = normalize(connection.call_tool("server_health", json!({"database":database}), timeout_for("server_health"))?);
        let idb_path = payload(&health)["idb_path"].as_str().map(str::to_owned);
        Ok((database, input, idb_path, response))
    }

    /// Read IDA's own view of the attached database: (sha256, input path, idb path).
    fn attached_identity(connection: &mut Connection, catalog: &[Value]) -> Result<Identity> {
        let metadata = match connection.request("resources/read", json!({"uri":"ida://idb/metadata"}), Duration::from_secs(120)) {
            Ok(result) => result["contents"].as_array().into_iter().flatten()
                .filter_map(|c| c["text"].as_str()).find_map(|t| serde_json::from_str::<Value>(t).ok())
                .unwrap_or(Value::Null),
            Err(_) if catalog.iter().any(|t| t["name"] == "get_metadata") => {
                payload(&normalize(connection.call_tool("get_metadata", json!({}), Duration::from_secs(120))?))
            }
            Err(error) => return Err(error.context("IDA did not provide ida://idb/metadata")),
        };
        let health = if catalog.iter().any(|t| t["name"] == "server_health") {
            payload(&normalize(connection.call_tool("server_health", json!({}), timeout_for("server_health"))?))
        } else { Value::Null };
        let sha = metadata["sha256"].as_str().filter(|s| s.len() == 64).map(str::to_ascii_lowercase);
        let input = health["input_path"].as_str().map(str::to_owned);
        let idb = health["idb_path"].as_str().or_else(|| metadata["path"].as_str()).map(str::to_owned);
        Ok((sha, input, idb, json!({"metadata":metadata,"health":health})))
    }

    pub fn open(&self, engine: &QuixiEngine) -> Result<Value> {
        let _op = self.operation.lock();
        let (target, metadata) = Self::selected_target(engine)?;
        let sha256 = sha256_file(Path::new(&target))?;
        let mut guard = self.connection.lock();
        let connection = guard.as_mut().context("Enable the IDA bridge first")?;
        let catalog = self.state.lock().catalog.clone();
        let result = (|| -> Result<Value> {
            let previous = self.close_session(connection, Duration::from_secs(120))?;
            let session = if connection.transport() == "headless" {
                let copy = Self::cache_copy(engine, &target, &sha256)?;
                let (database, input, idb_path, response) = self.open_headless(connection, &catalog, &copy)?;
                (Session { target: target.clone(), sha256: sha256.clone(), size: metadata.len(), modified: metadata.modified().ok(),
                    input_path: input, idb_path, database: Some(database) }, response)
            } else {
                let (sha, input, idb_path, identity) = Self::attached_identity(connection, &catalog)?;
                match sha {
                    Some(sha) if sha == sha256 => {}
                    Some(sha) => bail!("The database open in IDA belongs to another input (SHA-256 {sha}). Open the selected artifact in IDA, or select the artifact IDA has open."),
                    None => bail!("IDA did not report its input SHA-256 (the input file may have moved). The attached database cannot be bound to the selected artifact."),
                }
                (Session { target: target.clone(), sha256: sha256.clone(), size: metadata.len(), modified: metadata.modified().ok(),
                    input_path: input.unwrap_or_default(), idb_path, database: None },
                    json!({"isError":false,"content":[{"type":"text","text":identity.to_string()}],"structuredContent":identity}))
            };
            let (session, response) = session;
            let record = engine.analysis.save_external(PROVIDER, "ida", "idb_open", json!({"transport":connection.transport()}),
                &target, response, json!({"sha256":sha256,"transport":connection.transport(),"database":session.database,
                    "idbPath":session.idb_path,"inputPath":session.input_path,"previousSessionClosed":previous,
                    "limitations":["The database is a private IDA analysis of the artifact's bytes; annotations change only that database.",
                        "Auto-analysis results depend on the IDA version, loaders and settings."]}))?;
            self.state.lock().session = Some(session);
            Ok(record)
        })();
        match result {
            Ok(record) => { self.state.lock().last_error = None; Ok(record) }
            Err(error) => {
                if !connection.alive() { *guard = None; self.state.lock().transport = None; }
                self.fail(error)
            }
        }
    }

    pub fn close(&self, engine: &QuixiEngine) -> Result<Value> {
        let _op = self.operation.lock();
        let mut guard = self.connection.lock();
        let connection = guard.as_mut().context("Enable the IDA bridge first")?;
        let session = self.state.lock().session.clone().context("No IDA database is open")?;
        let closed = self.close_session(connection, Duration::from_secs(120))?;
        drop(guard);
        let response = closed.unwrap_or_else(|| json!({"content":[{"type":"text","text":"Detached from the attached IDA database; the GUI database was left open."}]}));
        engine.analysis.save_external(PROVIDER, "ida", "idb_close", json!({}), &session.target, response,
            json!({"sha256":session.sha256,"database":session.database,"idbPath":session.idb_path}))
    }

    /// The selected artifact must still be the bound one, with unchanged content.
    fn verify_binding(engine: &QuixiEngine, session: &Session) -> Result<()> {
        let selected = engine.analysis.target.lock().clone();
        if !same_path(&selected, &session.target) {
            bail!("The selected artifact differs from the database open in IDA. Open the selected artifact in the IDA bridge first.");
        }
        let metadata = fs::metadata(&session.target).context("The bound artifact is no longer available")?;
        let unchanged = metadata.len() == session.size && metadata.modified().ok() == session.modified;
        if !unchanged && sha256_file(Path::new(&session.target))? != session.sha256 {
            bail!("The artifact changed after it was opened in IDA. Open it again to analyse the current bytes.");
        }
        Ok(())
    }

    fn attached_still_bound(connection: &mut Connection, catalog: &[Value], session: &Session) -> Result<()> {
        if !catalog.iter().any(|t| t["name"] == "server_health") { return Ok(()); }
        let health = payload(&normalize(connection.call_tool("server_health", json!({}), timeout_for("server_health"))?));
        let idb = health["idb_path"].as_str().unwrap_or("");
        if session.idb_path.as_deref().is_some_and(|bound| !same_path(bound, idb)) {
            bail!("IDA switched to another database ({idb}). Open the selected artifact again before continuing.");
        }
        Ok(())
    }

    /// Call one live tool. `persist` saves the response as an evidence record.
    pub fn call(&self, engine: &QuixiEngine, tool: &str, mut args: Value, persist: bool) -> Result<Value> {
        let _op = self.operation.lock();
        let allow = self.allow_annotations(engine);
        let (catalog, session) = {
            let state = self.state.lock();
            (state.catalog.clone(), state.session.clone())
        };
        if args.is_null() { args = json!({}); }
        let Some(advertised) = catalog.iter().find(|t| t["name"] == tool) else {
            // Refuse blocked names explicitly even when the server hides them.
            validate_call(classify(tool, ""), tool, &args, allow)?;
            if catalog.is_empty() { bail!("Enable the IDA bridge first"); }
            bail!("{tool} is not advertised by the connected IDA server");
        };
        let kind = classify(tool, advertised["description"].as_str().unwrap_or(""));
        validate_call(kind, tool, &args, allow)?;
        let session = session.context("Open the selected artifact in the IDA bridge first")?;
        Self::verify_binding(engine, &session)?;
        let mut guard = self.connection.lock();
        let connection = guard.as_mut().context("Enable the IDA bridge first")?;
        if let Some(database) = &session.database {
            if args.get("database").is_some_and(|d| d.as_str() != Some(database)) {
                bail!("The bridge binds calls to its own database; omit the database argument");
            }
            args["database"] = json!(database);
        } else {
            Self::attached_still_bound(connection, &catalog, &session)?;
        }
        let mut result = connection.call_tool(tool, args.clone(), timeout_for(tool)).map(normalize);
        let mut reopened = false;
        // Workers self-exit after their idle TTL; reopen the same cached database once.
        if session.database.is_some() && result.as_ref().is_ok_and(|r| r["isError"] == true && text_result(r).contains("Session not found")) {
            let copy = PathBuf::from(&session.input_path);
            if let Ok((database, _, idb_path, _)) = self.open_headless(connection, &catalog, &copy) {
                args["database"] = json!(database);
                let mut state = self.state.lock();
                if let Some(bound) = state.session.as_mut() { bound.database = Some(database); bound.idb_path = idb_path; }
                drop(state);
                reopened = true;
                result = connection.call_tool(tool, args.clone(), timeout_for(tool)).map(normalize);
            }
        }
        let response = match result {
            Ok(response) => response,
            Err(error) => {
                if error.downcast_ref::<Timeout>().is_none() && !connection.alive() {
                    *guard = None;
                    let mut state = self.state.lock();
                    state.transport = None;
                    state.catalog.clear();
                    state.session = None;
                }
                return self.fail(error);
            }
        };
        let mut saved = Value::Null;
        if kind == ToolKind::Annotate && tool != "idb_save" && response["isError"] != true {
            if let Some(database) = &args["database"].as_str() {
                // Persist each accepted annotation so it survives crashes and worker idle exits.
                saved = connection.call_tool("idb_save", json!({"database":database}), Duration::from_secs(120))
                    .map(|r| json!(r["isError"] != true && payload(&r)["ok"] != false)).unwrap_or(json!(false));
            }
        }
        drop(guard);
        let session = self.state.lock().session.clone().unwrap_or(session);
        let provenance = json!({"sha256":session.sha256,"transport":if session.database.is_some() {"headless"} else {"attached"},
            "database":session.database,"idbPath":session.idb_path,"inputPath":session.input_path,"toolKind":kind.as_str(),
            "savedAfterAnnotation":saved,"reopenedSession":reopened,
            "limitations":["IDA's analysis of one database, not proof of runtime behaviour.",
                "Names, types and comments may include earlier user or agent annotations in this database."]});
        let mut stored_args = args;
        if let Some(map) = stored_args.as_object_mut() { map.remove("database"); }
        if persist {
            engine.analysis.save_external(PROVIDER, "ida", tool, stored_args, &session.target, response, provenance)
        } else {
            Ok(json!({"provider":PROVIDER,"kind":"ida","tool":tool,"arguments":stored_args,"target":session.target,
                "failed":response["isError"]==true,"response":response,"provenance":provenance,"persisted":false}))
        }
    }

    /// Agent catalog: names/kinds/descriptions, or one tool's live input schema. The bridge-
    /// injected `database` argument is hidden. Blocked tools are never listed.
    pub fn catalog(&self, engine: &QuixiEngine, tool: Option<&str>) -> Value {
        if !self.connected() {
            return json!({"connected":false,"tools":[],"error":"The IDA bridge is not enabled. The user enables it and opens the artifact in Reverse engineering."});
        }
        // The same persisted setting the call path enforces.
        let allow = self.allow_annotations(engine);
        let state = self.state.lock();
        let session = state.session.as_ref().map(|s| json!({"target":s.target,"sha256":s.sha256}));
        let usable = |t: &&Value| {
            let kind = classify(t["name"].as_str().unwrap_or(""), t["description"].as_str().unwrap_or(""));
            kind == ToolKind::Read || (kind == ToolKind::Annotate && allow)
        };
        if let Some(name) = tool {
            return match state.catalog.iter().filter(usable).find(|t| t["name"] == name) {
                Some(found) => {
                    let mut schema = found.clone();
                    if let Some(properties) = schema.pointer_mut("/inputSchema/properties").and_then(Value::as_object_mut) { properties.remove("database"); }
                    if let Some(required) = schema.pointer_mut("/inputSchema/required").and_then(Value::as_array_mut) { required.retain(|r| r != "database"); }
                    schema["kind"] = json!(classify(name, found["description"].as_str().unwrap_or("")).as_str());
                    schema
                }
                None => json!({"error":format!("{name} is not available through the IDA bridge in this mode")}),
            };
        }
        json!({"connected":true,"transport":state.transport,"session":session,"allowAnnotations":allow,
            "tools":state.catalog.iter().filter(usable).map(|t| json!({"name":t["name"],
                "kind":classify(t["name"].as_str().unwrap_or(""), t["description"].as_str().unwrap_or("")).as_str(),
                "description":t["description"].as_str().unwrap_or("").chars().take(240).collect::<String>()})).collect::<Vec<_>>(),
            "note":"Call tools with their live arguments; the bridge supplies the database. Large results are bounded: page with offset/count or narrow queries."})
    }

    /// Agent entry point (Ask and Code mode): READ and ANNOTATE tools only, evidence saved,
    /// response text bounded.
    pub fn agent_call(&self, engine: &QuixiEngine, tool: &str, args: Value) -> Result<Value> {
        let record = self.call(engine, tool, args, true)?;
        let text = text_result(&record["response"]);
        let total = text.chars().count();
        let truncated = total > AGENT_TEXT_LIMIT;
        Ok(json!({"id":record["id"],"provider":PROVIDER,"tool":tool,"failed":record["failed"],"target":record["target"],
            "sha256":record["provenance"]["sha256"],"kind":record["provenance"]["toolKind"],
            "text":text.chars().take(AGENT_TEXT_LIMIT).collect::<String>(),"truncated":truncated,"totalCharacters":total,
            "note":if truncated {"Output truncated. Page with offset/count (or max_lines/max_instructions), narrow the query, or read the full evidence record by id."} else {"Complete response."}}))
    }

    pub fn handle(&self, engine: &QuixiEngine, route: &str, body: &Value) -> Result<Value> {
        match route {
            "status" => Ok(self.status(engine)),
            "enable" => self.enable(engine, body["transport"].as_str().unwrap_or("headless"), body["url"].as_str()),
            "disable" => Ok(self.disable(engine)),
            "open" => self.open(engine),
            "close" => self.close(engine),
            "tools" => {
                if !self.connected() { bail!("Enable the IDA bridge first"); }
                let state = self.state.lock();
                match body["tool"].as_str() {
                    Some(name) => {
                        let tool = state.catalog.iter().find(|t| t["name"] == name).cloned().context("Tool not advertised by IDA")?;
                        let kind = classify(name, tool["description"].as_str().unwrap_or(""));
                        Ok(json!({"tool":tool,"kind":kind.as_str()}))
                    }
                    None => Ok(json!({"tools":state.catalog.iter().map(|t| {
                        let mut t = t.clone();
                        t["kind"] = json!(classify(t["name"].as_str().unwrap_or(""), t["description"].as_str().unwrap_or("")).as_str());
                        t
                    }).collect::<Vec<_>>()})),
                }
            }
            "call" => self.call(engine, body["tool"].as_str().context("Choose an IDA tool")?,
                body.get("arguments").cloned().unwrap_or_else(|| json!({})), body["persist"].as_bool().unwrap_or(true)),
            "settings" => {
                if let Some(allow) = body["allowAnnotations"].as_bool() {
                    let path = settings_path(engine);
                    if let Some(parent) = path.parent() { fs::create_dir_all(parent)?; }
                    fs::write(&path, serde_json::to_vec_pretty(&json!({"allowAnnotations":allow}))?)?;
                    self.state.lock().allow_annotations = Some(allow);
                }
                Ok(self.status(engine))
            }
            "register-rea" => {
                let registration = Self::registration_path(engine).context("Install the headless IDA bridge first")?;
                load_registration(Path::new(&registration))?;
                let mut result = register_rea_paths(&engine.data_dir.join("toolchain-paths.json"), &registration)?;
                result["note"] = json!("Disconnect and reconnect REA so its IDA provider uses the headless profile.");
                Ok(result)
            }
            "restore-rea-attached" => {
                let mut result = restore_rea_paths(&engine.data_dir.join("toolchain-paths.json"))?;
                result["note"] = json!("Disconnect and reconnect REA so its IDA provider uses the restored registration.");
                Ok(result)
            }
            _ => bail!("Unknown IDA bridge operation"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("rea-ida-test-{name}-{}", uuid::Uuid::new_v4()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn blocked_and_disabled_annotation_calls_are_refused() {
        assert!(validate_call(ToolKind::Blocked, "py_eval", &json!({"code":"1"}), true).is_err());
        assert!(validate_call(ToolKind::Annotate, "rename", &json!({}), false).is_err());
        assert!(validate_call(ToolKind::Annotate, "rename", &json!({}), true).is_ok());
        assert!(validate_call(ToolKind::Read, "decompile", &json!({"addr":"main"}), false).is_ok());
        assert!(validate_call(ToolKind::Read, "decompile", &json!(["main"]), false).is_err());
        assert!(validate_call(ToolKind::Annotate, "idb_save", &json!({"path":"C:\\elsewhere.i64"}), true).is_err());
        assert!(validate_call(ToolKind::Annotate, "idb_save", &json!({"path":""}), true).is_ok());
        assert!(validate_call(ToolKind::Annotate, "idb_save", &json!({}), true).is_ok());
        assert!(validate_call(ToolKind::Annotate, "idb_save", &json!({"database":"db1","path":null}), true).is_ok());
        for args in [json!({"output":"C:\\elsewhere.i64"}), json!({"database":"db1","flags":1}), json!({"path":7})] {
            assert!(validate_call(ToolKind::Annotate, "idb_save", &args, true).is_err(), "{args}");
        }
        let huge = json!({"pattern":"x".repeat(70_000)});
        assert!(validate_call(ToolKind::Read, "find_regex", &huge, false).is_err());
    }

    #[test]
    fn identity_paths_compare_windows_style() {
        assert!(same_path("C:/a/b.dll", "\\\\?\\c:\\A\\B.dll"));
        assert!(!same_path("", ""));
        assert!(!same_path("C:\\a\\b.dll", "C:\\a\\c.dll"));
    }

    #[test]
    fn rea_registration_switch_is_reversible() {
        let dir = scratch("paths");
        let file = dir.join("toolchain-paths.json");
        fs::write(&file, br#"{"ida":"E:\\legacy\\rea-registration.json","jadx":"x"}"#).unwrap();
        let first = register_rea_paths(&file, "C:\\bridge\\rea-headless-registration.json").unwrap();
        assert_eq!(first["changed"], true);
        // Registering again must not overwrite the saved attached registration.
        assert_eq!(register_rea_paths(&file, "C:\\bridge\\rea-headless-registration.json").unwrap()["changed"], false);
        let saved: Value = serde_json::from_slice(&fs::read(&file).unwrap()).unwrap();
        assert_eq!(saved["ida-attached-previous"], "E:\\legacy\\rea-registration.json");
        assert_eq!(saved["jadx"], "x");
        restore_rea_paths(&file).unwrap();
        let restored: Value = serde_json::from_slice(&fs::read(&file).unwrap()).unwrap();
        assert_eq!(restored["ida"], "E:\\legacy\\rea-registration.json");
        assert!(restored.get("ida-attached-previous").is_none());
        assert!(restore_rea_paths(&file).is_err());
        // Without a previous registration, restoring removes the key again.
        fs::write(&file, b"{}").unwrap();
        register_rea_paths(&file, "C:\\bridge\\r.json").unwrap();
        restore_rea_paths(&file).unwrap();
        assert!(serde_json::from_slice::<Value>(&fs::read(&file).unwrap()).unwrap().get("ida").is_none());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn hashing_streams_file_contents() {
        let dir = scratch("hash");
        let file = dir.join("a.bin");
        fs::write(&file, b"abc").unwrap();
        assert_eq!(sha256_file(&file).unwrap(), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        let _ = fs::remove_dir_all(dir);
    }

    /// Live end-to-end check. Set QUIXI_TEST_IDA_HEADLESS to a rea-headless-registration.json
    /// and optionally QUIXI_TEST_IDA_TARGET to a PE file (default: this test executable).
    #[test]
    #[ignore = "requires a licensed IDA headless bridge; run explicitly with --ignored"]
    fn live_headless_bridge_round_trip() {
        let registration = std::env::var("QUIXI_TEST_IDA_HEADLESS")
            .expect("set QUIXI_TEST_IDA_HEADLESS before explicitly running this integration test");
        let data = scratch("live");
        std::env::set_var("QUIXI_DATA_DIR", &data);
        let resources = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../resources");
        let engine = QuixiEngine::new(resources);
        fs::write(data.join("toolchain-paths.json"), serde_json::to_vec(&json!({"ida-headless":registration})).unwrap()).unwrap();
        let source = std::env::var("QUIXI_TEST_IDA_TARGET").map(PathBuf::from).unwrap_or_else(|_| std::env::current_exe().unwrap());
        let artifacts = data.join("artifact");
        fs::create_dir_all(&artifacts).unwrap();
        let target = artifacts.join(source.file_name().unwrap());
        fs::copy(&source, &target).unwrap();
        let canonical = clean(&fs::canonicalize(&target).unwrap());
        *engine.analysis.target.lock() = canonical.clone();
        let ida = &engine.ida;
        assert_eq!(ida.status(&engine)["installed"], true, "{}", ida.status(&engine));
        let enabled = ida.handle(&engine, "enable", &json!({"transport":"headless"})).unwrap();
        assert!(enabled["tools"].as_array().unwrap().iter().any(|t| t["name"] == "py_eval" || t["name"] == "patch"));
        let opened = ida.handle(&engine, "open", &json!({})).unwrap();
        assert_eq!(opened["provider"], "ida-bridge");
        let idb = ida.status(&engine)["session"]["idbPath"].as_str().unwrap().to_owned();
        assert!(idb.starts_with(&clean(&data.join("ida"))), "IDB {idb} must live in the private cache");
        assert!(!artifacts.read_dir().unwrap().any(|e| e.unwrap().file_name().to_string_lossy().ends_with(".i64")));
        let funcs = ida.agent_call(&engine, "list_funcs", json!({"queries":{"count":5}})).unwrap();
        assert_eq!(funcs["failed"], false, "{funcs}");
        let first: Value = serde_json::from_str(funcs["text"].as_str().unwrap()).unwrap();
        let first = first.pointer("/0/data/0").or_else(|| first.pointer("/result/0/data/0")).cloned().unwrap();
        let addr = first["addr"].as_str().unwrap().to_owned();
        let decompiled = ida.agent_call(&engine, "decompile", json!({"addr":addr})).unwrap();
        assert_eq!(decompiled["failed"], false, "{decompiled}");
        assert_eq!(engine.analysis.read_record(decompiled["id"].as_str().unwrap()).unwrap()["provenance"]["sha256"],
            opened["provenance"]["sha256"]);
        assert!(ida.agent_call(&engine, "xrefs_to", json!({"addrs":addr})).is_ok());
        assert!(ida.agent_call(&engine, "py_eval", json!({"code":"1"})).is_err());
        assert!(ida.agent_call(&engine, "patch", json!({})).is_err());
        assert!(ida.agent_call(&engine, "idb_open", json!({"input_path":"C:\\Windows\\notepad.exe"})).is_err());
        let renamed = ida.agent_call(&engine, "rename", json!({"batch":{"func":[{"addr":addr,"name":"rea_bridge_test_fn"}]}})).unwrap();
        assert_eq!(renamed["failed"], false, "{renamed}");
        // Annotation toggle off blocks writes but not reads.
        ida.handle(&engine, "settings", &json!({"allowAnnotations":false})).unwrap();
        assert!(ida.agent_call(&engine, "set_comments", json!({"items":{"addr":addr,"comment":"x"}})).is_err());
        ida.handle(&engine, "settings", &json!({"allowAnnotations":true})).unwrap();
        // Selecting another artifact invalidates the binding.
        *engine.analysis.target.lock() = clean(&std::env::current_exe().unwrap());
        assert!(ida.agent_call(&engine, "list_funcs", json!({"queries":{"count":1}})).is_err());
        *engine.analysis.target.lock() = canonical;
        ida.handle(&engine, "close", &json!({})).unwrap();
        ida.handle(&engine, "disable", &json!({})).unwrap();
        // A new supervisor reopens the cached database with the annotation intact.
        ida.handle(&engine, "enable", &json!({"transport":"headless"})).unwrap();
        ida.handle(&engine, "open", &json!({})).unwrap();
        let looked = ida.agent_call(&engine, "lookup_funcs", json!({"queries":addr})).unwrap();
        assert!(looked["text"].as_str().unwrap().contains("rea_bridge_test_fn"), "{looked}");
        // Abandoning the connection (as on a crash) must not orphan the detached idalib worker.
        let listed = ida.connection.lock().as_mut().unwrap().call_tool("idb_list", json!({}), Duration::from_secs(30)).unwrap();
        let worker = payload(&listed).pointer("/sessions/0/worker_pid").and_then(Value::as_u64).expect("worker pid");
        *ida.connection.lock() = None;
        std::thread::sleep(Duration::from_secs(2));
        let alive = quixi_platform::background_command("powershell.exe")
            .args(["-NoProfile", "-Command", &format!("if (Get-Process -Id {worker} -ErrorAction SilentlyContinue) {{ 'alive' }}")])
            .output().unwrap();
        assert!(!String::from_utf8_lossy(&alive.stdout).contains("alive"), "worker {worker} outlived the job");
        ida.handle(&engine, "disable", &json!({})).unwrap();
        assert_eq!(ida.status(&engine)["connected"], false);
        std::env::remove_var("QUIXI_DATA_DIR");
    }

    /// Live attached check against a running modern ida-pro-mcp HTTP endpoint. Set
    /// QUIXI_TEST_IDA_ATTACHED to its URL and QUIXI_TEST_IDA_ATTACHED_TARGET to the input it has open.
    #[test]
    #[ignore = "requires a running licensed IDA GUI bridge; run explicitly with --ignored"]
    fn live_attached_bridge_requires_matching_input() {
        let url = std::env::var("QUIXI_TEST_IDA_ATTACHED")
            .expect("set QUIXI_TEST_IDA_ATTACHED before explicitly running this integration test");
        let target = std::env::var("QUIXI_TEST_IDA_ATTACHED_TARGET")
            .expect("set QUIXI_TEST_IDA_ATTACHED_TARGET before explicitly running this integration test");
        let data = scratch("attached");
        std::env::set_var("QUIXI_DATA_DIR", &data);
        let engine = QuixiEngine::new(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../resources"));
        let ida = &engine.ida;
        ida.handle(&engine, "enable", &json!({"transport":"attached","url":url})).unwrap();
        // A different selected artifact is refused.
        *engine.analysis.target.lock() = clean(&std::env::current_exe().unwrap());
        assert!(ida.handle(&engine, "open", &json!({})).unwrap_err().to_string().contains("another input"));
        *engine.analysis.target.lock() = clean(&fs::canonicalize(&target).unwrap());
        let opened = ida.handle(&engine, "open", &json!({})).unwrap();
        assert_eq!(opened["failed"], false, "{opened}");
        let decompiled = ida.agent_call(&engine, "decompile", json!({"addr":"0x180001000"})).unwrap();
        assert_eq!(decompiled["failed"], false, "{decompiled}");
        assert!(ida.agent_call(&engine, "py_eval", json!({"code":"1"})).is_err());
        ida.handle(&engine, "disable", &json!({})).unwrap();
        std::env::remove_var("QUIXI_DATA_DIR");
    }
}
