//! User-selected artifacts, durable REA results, and the agent's analysis tools.
use crate::QuixiEngine;
use anyhow::{bail, Context, Result};
use parking_lot::Mutex;
use quixi_platform::ComputerUse;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    fs,
    path::{Component, Path, PathBuf, Prefix},
    sync::Arc,
};
use uuid::Uuid;

/// Summaries of saved records, so listing does not parse every full response.
const INDEX_FILE: &str = "index.json";

pub struct AnalysisWorkspace {
    dir: PathBuf,
    pub target: Mutex<String>,
    pub provider_sessions: Mutex<HashMap<String,u32>>,
    /// The binary REA reports open, keyed by the REA process that opened it.
    rea_target: Mutex<Option<(u32, String)>>,
    index: Mutex<()>,
}

/// True for UNC, device and non-disk verbatim paths. Touching these (even
/// canonicalizing) can make Windows authenticate to a remote host.
fn is_non_local_path(path: &Path) -> bool {
    match path.components().next() {
        Some(Component::Prefix(prefix)) => {
            !matches!(prefix.kind(), Prefix::Disk(_) | Prefix::VerbatimDisk(_))
        }
        _ => false,
    }
}

const NON_LOCAL_PATH: &str =
    "Network, device and UNC paths are not permitted. Select a local artifact in the REA workspace.";

fn is_path_key(key: &str) -> bool {
    key == "path" || key.ends_with("_path") || key.ends_with("_directory")
}

/// Refuse network, device and UNC paths in any path-like argument (`path`, `*_path`,
/// `*_directory`, and path lists), lexically, before anything touches the filesystem.
/// Applies to every REA call; it does not restrict which local paths may be used.
fn reject_non_local_paths(value: &Value) -> Result<()> {
    match value {
        Value::Object(map) => {
            for (key, value) in map {
                match value {
                    Value::String(raw) if is_path_key(key) => {
                        if is_non_local_path(Path::new(raw)) {
                            bail!(NON_LOCAL_PATH);
                        }
                    }
                    Value::Array(items) if key == "paths" || key.ends_with("_paths") => {
                        for item in items {
                            match item.as_str() {
                                Some(raw) if is_non_local_path(Path::new(raw)) => bail!(NON_LOCAL_PATH),
                                Some(_) => {}
                                None => reject_non_local_paths(item)?,
                            }
                        }
                    }
                    _ => reject_non_local_paths(value)?,
                }
            }
        }
        Value::Array(array) => {
            for value in array {
                reject_non_local_paths(value)?;
            }
        }
        _ => {}
    }
    Ok(())
}

/// Lexical comparison key: no verbatim prefix, one separator, no `.`/`..`,
/// case-folded on Windows. Never touches the filesystem.
fn lexical_key(path: &str) -> String {
    let path = path.replace('/', "\\");
    let path = path.trim_start_matches("\\\\?\\");
    let mut parts: Vec<&str> = Vec::new();
    for (index, part) in path.split('\\').enumerate() {
        match part {
            "" if index > 0 => {}
            "." => {}
            ".." => {
                if parts.len() > 1 {
                    parts.pop();
                }
            }
            _ => parts.push(part),
        }
    }
    let key = parts.join("\\");
    if cfg!(windows) {
        key.to_lowercase()
    } else {
        key
    }
}

fn lexically_within(path: &str, base: &str) -> bool {
    let (path, base) = (lexical_key(path), lexical_key(base));
    !base.is_empty() && (path == base || path.starts_with(&format!("{base}\\")))
}

/// Stored targets compare equal regardless of separator, case or verbatim prefix.
pub(crate) fn same_target(a: &str, b: &str) -> bool {
    !a.is_empty() && !b.is_empty() && lexical_key(a) == lexical_key(b)
}

/// One spelling per artifact (UI `C:/x.exe` and REA `C:\x.exe` match). Remote
/// paths are normalised lexically only, so no network access is attempted.
fn canonical_target(raw: &str) -> String {
    let path = Path::new(raw);
    let resolved = if raw.is_empty() || is_non_local_path(path) || !path.is_absolute() {
        None
    } else {
        fs::canonicalize(path).ok()
    };
    match resolved {
        Some(path) => path.to_string_lossy().trim_start_matches("\\\\?\\").to_owned(),
        None if cfg!(windows) => raw.replace('/', "\\").trim_start_matches("\\\\?\\").to_owned(),
        None => raw.to_owned(),
    }
}

/// binary_session reports `{"result":{"open":bool,"path":...}}`.
fn observe_session(session: &Value, process_id: u32, open: &mut Option<(u32, String)>) {
    let session = session.get("result").unwrap_or(session);
    match session["open"].as_bool() {
        Some(false) => *open = None,
        Some(true) => {
            if let Some(path) = session["path"].as_str() {
                *open = Some((process_id, canonical_target(path)));
            }
        }
        None => {}
    }
}

fn record_summary(record: &Value) -> Value {
    json!({"id":record["id"],"tool":record["tool"],"provider":record["provider"],"kind":record["kind"],
        "created":record["created"],"target":record["target"],"failed":record["failed"]})
}

/// A model may inspect the selected artifact or its current project, not choose an
/// unrelated installation. Remote paths are refused before any filesystem access.
fn validate_paths(value: &mut Value, root: &Path, selected: &Path) -> Result<()> {
    reject_non_local_paths(value)?;
    match value {
        Value::Object(map) => {
            for (key, value) in map {
                if is_path_key(key) && value.is_string() {
                    let raw = value.as_str().unwrap();
                    let candidate = if Path::new(raw).is_absolute() {
                        // Check containment lexically before canonicalize touches the path.
                        let root_text = root.to_string_lossy();
                        let selected_text = selected.to_string_lossy();
                        let lexically_permitted = lexically_within(raw, &root_text)
                            || same_target(raw, &selected_text)
                            || (selected.is_dir() && lexically_within(raw, &selected_text));
                        if !lexically_permitted {
                            bail!("Select this artifact in the REA workspace before analysing it");
                        }
                        fs::canonicalize(raw)?
                    } else {
                        quixi_platform::SafeFs::resolve_beneath(root, Path::new(raw))?
                    };
                    let permitted = candidate.starts_with(root)
                        || candidate == selected
                        || (selected.is_dir() && candidate.starts_with(selected));
                    if !permitted {
                        bail!("Select this artifact in the REA workspace before analysing it");
                    }
                    *value = json!(candidate.to_string_lossy().trim_start_matches("\\\\?\\"));
                } else if key == "source_paths" {
                    if let Some(paths) = value.as_array_mut() {
                        for path in paths {
                            let mut wrapped = json!({"path":path.clone()});
                            validate_paths(&mut wrapped, root, selected)?;
                            *path = wrapped["path"].clone();
                        }
                    }
                } else {
                    validate_paths(value, root, selected)?;
                }
            }
        }
        Value::Array(array) => {
            for value in array {
                validate_paths(value, root, selected)?;
            }
        }
        _ => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn bare() -> AnalysisWorkspace {
        AnalysisWorkspace {
            dir: PathBuf::new(),
            target: Mutex::new(String::new()),
            provider_sessions: Mutex::new(HashMap::new()),
            rea_target: Mutex::new(None),
            index: Mutex::new(()),
        }
    }

    #[test]
    fn provider_badge_requires_live_evidence_and_clears_after_failure() {
        let analysis = bare();
        // Opening a target only binds a lazy provider; IDA has not answered yet.
        analysis.observe_provider_result("open_binary", &json!({"result":{"path":"sample.exe"}}), false, false, 42);
        assert!(analysis.provider_sessions.lock().is_empty());
        let evidence = json!({"provider":{"id":"ida"},"operation":"list_procedures"});
        analysis.observe_provider_result("list_procedures", &evidence, false, false, 42);
        assert_eq!(analysis.provider_sessions.lock().get("ida"), Some(&42));
        // A tool error that names no provider is not a provider failure.
        analysis.observe_provider_result("search_strings", &json!({"error":{"code":"invalid_request"}}), true, false, 42);
        assert_eq!(analysis.provider_sessions.lock().get("ida"), Some(&42));
        // A failure reported by IDA clears IDA.
        analysis.observe_provider_result("list_procedures", &json!({"error":{"code":"unreadable_output"},"provider":{"id":"ida"}}), true, false, 42);
        assert!(analysis.provider_sessions.lock().is_empty());
        analysis.observe_provider_result("list_procedures", &evidence, false, false, 42);
        // A transport failure clears every provider.
        analysis.observe_provider_result("list_procedures", &json!({}), true, true, 42);
        assert!(analysis.provider_sessions.lock().is_empty());
        // Reading retained evidence cannot re-establish a live connection.
        analysis.observe_provider_result("inspect_analysis_view", &evidence, false, false, 42);
        assert!(analysis.provider_sessions.lock().is_empty());
        analysis.observe_provider_result("list_procedures", &evidence, false, false, 43);
        assert_eq!(analysis.provider_sessions.lock().get("ida"), Some(&43));
        analysis.observe_provider_result("close_binary", &json!({}), false, false, 43);
        assert!(analysis.provider_sessions.lock().is_empty());
    }

    #[test]
    fn selecting_another_native_target_invalidates_the_previous_provider() {
        let analysis = bare();
        let evidence = json!({"provider":{"id":"ghidra"},"operation":"procedure_pseudo_code"});
        analysis.observe_provider_result("procedure_pseudo_code", &evidence, false, false, 42);
        assert_eq!(analysis.provider_sessions.lock().get("ghidra"), Some(&42));
        analysis.observe_provider_result("open_binary", &json!({"result":{"path":"another.exe"}}), false, false, 42);
        assert!(analysis.provider_sessions.lock().is_empty());
    }

    #[test]
    fn open_rea_target_follows_open_close_and_process() {
        let analysis = bare();
        analysis.observe_rea_target("open_binary", &json!({}), &json!({"result":{"path":"C:/apps/one.exe"}}), false, 7);
        assert!(same_target(&analysis.open_rea_target(7).unwrap(), "c:\\APPS\\one.exe"));
        // A new REA process does not inherit the previous open binary.
        assert!(analysis.open_rea_target(8).is_none());
        analysis.observe_rea_target("binary_session", &json!({}), &json!({"result":{"open":false}}), false, 7);
        assert!(analysis.open_rea_target(7).is_none());
        analysis.observe_rea_target("binary_session", &json!({}), &json!({"result":{"open":true,"path":"C:\\apps\\two.exe"}}), false, 7);
        assert!(analysis.open_rea_target(7).is_some());
        analysis.observe_rea_target("close_binary", &json!({}), &json!({"result":null}), false, 7);
        assert!(analysis.open_rea_target(7).is_none());
    }

    #[test]
    fn stored_targets_compare_by_canonical_spelling() {
        assert!(same_target("C:/x/app.exe", "\\\\?\\c:\\X\\app.exe"));
        assert!(same_target("C:\\x\\.\\y\\..\\app.exe", "C:\\x\\app.exe"));
        assert!(!same_target("C:\\x\\app.exe", "C:\\x\\app.exe.bak"));
        assert!(!same_target("", ""));
        assert!(lexically_within("C:\\root\\sub\\a.bin", "\\\\?\\C:\\Root"));
        assert!(!lexically_within("C:\\rootless\\a.bin", "C:\\root"));
        assert!(!lexically_within("C:\\root\\..\\other\\a.bin", "C:\\root"));
    }

    #[cfg(windows)]
    #[test]
    fn network_and_device_paths_are_refused_before_filesystem_access() {
        let root = std::env::temp_dir().join(format!("quixi-paths-{}", Uuid::new_v4()));
        fs::create_dir_all(&root).unwrap();
        let root = fs::canonicalize(&root).unwrap();
        fs::write(root.join("inside.bin"), b"x").unwrap();
        for raw in [
            r"\\attacker.invalid\share\a.exe",
            "//attacker.invalid/share/a.exe",
            r"\\?\UNC\attacker.invalid\share\a.exe",
            r"\\.\pipe\x",
            r"\\?\GLOBALROOT\Device\Mup\attacker.invalid\share",
        ] {
            let error = validate_paths(&mut json!({"path":raw}), &root, Path::new("")).unwrap_err();
            assert!(error.to_string().contains("not permitted"), "{raw}: {error}");
            let mut nested = json!({"source_paths":[raw]});
            assert!(validate_paths(&mut nested, &root, Path::new("")).is_err(), "{raw}");
        }
        // Outside the project and selection: rejected lexically.
        let outside = r"C:\Windows\System32\kernel32.dll";
        assert!(validate_paths(&mut json!({"path":outside}), &root, Path::new("")).is_err());
        let inside_path = root.join("inside.bin");
        let local = inside_path.to_string_lossy().trim_start_matches("\\\\?\\").replace('\\', "/");
        let mut inside = json!({"path":local});
        validate_paths(&mut inside, &root, Path::new("")).unwrap();
        assert!(same_target(inside["path"].as_str().unwrap(), &root.join("inside.bin").to_string_lossy()));
        fs::remove_dir_all(root).unwrap();
    }

    /// `AnalysisWorkspace::call` (UI and MCP `rea/tool`) runs this before REA sees the arguments.
    #[cfg(windows)]
    #[test]
    fn rea_tool_calls_refuse_non_local_paths_without_project_scoping() {
        for raw in [
            r"\\attacker.invalid\share\a.exe",
            "//attacker.invalid/share/a.exe",
            r"\\?\UNC\attacker.invalid\share\a.exe",
            r"\\.\pipe\x",
            r"\\?\GLOBALROOT\Device\Mup\attacker.invalid\share",
        ] {
            for args in [
                json!({"path":raw}),
                json!({"binary_path":raw}),
                json!({"output_directory":raw}),
                json!({"source_paths":["C:/a.js", raw]}),
                json!({"options":{"nested":[{"database_path":raw}]}}),
            ] {
                let error = reject_non_local_paths(&args).unwrap_err();
                assert!(error.to_string().contains("not permitted"), "{args}: {error}");
            }
        }
        // Without project scoping: any local path, inside or outside the project, is fine.
        let local = json!({"path":r"C:\Windows\System32\kernel32.dll","name":r"\\not-a-path-key","source_paths":["D:/x.js"]});
        reject_non_local_paths(&local).unwrap();
    }

    #[test]
    fn inventory_uses_and_repairs_the_sidecar_index() {
        let base = std::env::temp_dir().join(format!("quixi-index-{}", Uuid::new_v4()));
        let analysis = AnalysisWorkspace::new(&base);
        let saved = analysis
            .save_external("test", "static", "list_names", json!({}), "C:/a.exe", json!({}), json!({}))
            .unwrap();
        assert_eq!(analysis.inventory()["records"].as_array().unwrap().len(), 1);
        let index_path = analysis.dir.join(INDEX_FILE);
        assert!(index_path.is_file());
        // The index answers listings without re-reading records.
        let id = saved["id"].as_str().unwrap();
        fs::write(analysis.record_path(id).unwrap(), b"not json").unwrap();
        let listed = analysis.inventory();
        assert_eq!(listed["records"][0]["tool"], "list_names");
        assert_eq!(listed["records"][0]["target"], canonical_target("C:/a.exe"));
        // A record saved by another version, and a corrupt index, are both recovered.
        let other = Uuid::new_v4().to_string();
        fs::write(analysis.record_path(&other).unwrap(), serde_json::to_vec(&json!({"id":other,"tool":"xrefs","created":"2026-01-01"})).unwrap()).unwrap();
        fs::write(&index_path, b"{corrupt").unwrap();
        fs::write(analysis.record_path(id).unwrap(), serde_json::to_vec(&saved).unwrap()).unwrap();
        let listed = analysis.inventory();
        assert_eq!(listed["records"].as_array().unwrap().len(), 2);
        // Deleted records leave the index.
        fs::remove_file(analysis.record_path(&other).unwrap()).unwrap();
        assert_eq!(analysis.inventory()["records"].as_array().unwrap().len(), 1);
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn dossier_preserves_failures_and_excludes_other_artifacts() {
        let base = std::env::temp_dir().join(format!("quixi-dossier-{}", Uuid::new_v4()));
        let original = base.join("original");
        let destination = base.join("rebuild");
        fs::create_dir_all(&original).unwrap();
        fs::create_dir_all(&destination).unwrap();
        let artifact = original.join("target.bin");
        fs::write(&artifact, b"analysis input").unwrap();
        let analysis = AnalysisWorkspace::new(&base.join("profile"));
        *analysis.target.lock() = artifact.to_string_lossy().into_owned();
        let id = Uuid::new_v4().to_string();
        let record = json!({"id":id,"target":artifact,"tool":"inspect_pe_resources","failed":true,"response":{"isError":true},"created":"2026-01-01"});
        let bytes = serde_json::to_vec_pretty(&record).unwrap();
        fs::write(analysis.record_path(&id).unwrap(), &bytes).unwrap();
        let unrelated = Uuid::new_v4().to_string();
        fs::write(
            analysis.record_path(&unrelated).unwrap(),
            serde_json::to_vec(&json!({"id":unrelated,"target":"other-artifact","failed":false}))
                .unwrap(),
        )
        .unwrap();
        assert!(analysis
            .export_dossier(&original, &json!({}), None)
            .is_err());
        let exported = analysis
            .export_dossier(&destination, &json!({"scope":"feature"}), None)
            .unwrap();
        assert_eq!(exported["records"], 1);
        let folder = Path::new(exported["path"].as_str().unwrap());
        assert_eq!(
            fs::read(folder.join(format!("evidence/{id}.json"))).unwrap(),
            bytes
        );
        let manifest: Value =
            serde_json::from_slice(&fs::read(folder.join("manifest.json")).unwrap()).unwrap();
        assert_eq!(manifest["records"][0]["failed"], true);
        assert!(!folder.join(format!("evidence/{unrelated}.json")).exists());
        let next = analysis
            .export_dossier(&destination, &json!({}), None)
            .unwrap();
        assert_ne!(exported["path"], next["path"]);
        assert_eq!(fs::read(artifact).unwrap(), b"analysis input");
        fs::remove_dir_all(base).unwrap();
    }
}
impl AnalysisWorkspace {
    /// `transport_failed`: the call itself failed (connection lost, timeout and
    /// cancellation, protocol error), so no provider session can be assumed.
    fn observe_provider_result(&self, tool: &str, evidence: &Value, failed: bool, transport_failed: bool, process_id: u32) {
        let mut sessions = self.provider_sessions.lock();
        if transport_failed || matches!(tool, "open_binary" | "close_binary") {
            sessions.clear();
            return;
        }
        let provider = ["/provider/id", "/error/provider/id", "/error/details/provider/id", "/error/details/provider"]
            .iter()
            .find_map(|pointer| evidence.pointer(pointer).and_then(Value::as_str));
        if failed {
            // Only the provider that reported this failure loses its badge.
            if let Some(provider) = provider {
                sessions.remove(provider);
            }
            return;
        }
        // open_binary is lazy. Only a provider observation from this operation
        // confirms readiness; inspecting retained evidence is not a live check.
        if evidence["operation"] == tool {
            if let Some(provider) = provider.filter(|p| matches!(*p, "ghidra" | "ida")) {
                sessions.remove("ghidra");
                sessions.remove("ida");
                sessions.insert(provider.into(), process_id);
            }
        }
        if tool == "inspect_android_package" {
            sessions.insert("jadx-mcp".into(), process_id);
        }
    }

    /// Track the binary REA has open so no-path tools are attributed to it.
    fn observe_rea_target(&self, tool: &str, args: &Value, evidence: &Value, failed: bool, process_id: u32) {
        let mut open = self.rea_target.lock();
        if open.as_ref().is_some_and(|(pid, _)| *pid != process_id) {
            *open = None;
        }
        if failed {
            return;
        }
        match tool {
            "open_binary" => {
                *open = evidence
                    .pointer("/result/path")
                    .and_then(Value::as_str)
                    .or_else(|| args["path"].as_str())
                    .map(|path| (process_id, canonical_target(path)));
            }
            "close_binary" => *open = None,
            "binary_session" => observe_session(evidence, process_id, &mut open),
            _ => {}
        }
    }
    fn open_rea_target(&self, process_id: u32) -> Option<String> {
        self.rea_target
            .lock()
            .as_ref()
            .filter(|(pid, _)| *pid == process_id && process_id != 0)
            .map(|(_, path)| path.clone())
    }

    pub fn new(data_dir: &Path) -> Self {
        let dir = data_dir.join("playground/analysis");
        let _ = fs::create_dir_all(&dir);
        let target = fs::read_to_string(dir.join("target.txt")).unwrap_or_default();
        Self {
            dir,
            target: Mutex::new(target),
            provider_sessions: Mutex::new(HashMap::new()),
            rea_target: Mutex::new(None),
            index: Mutex::new(()),
        }
    }
    /// Reads summaries from the sidecar index. Only records missing from it are
    /// parsed (a missing or corrupt index is rebuilt this way); stale entries are dropped.
    pub fn inventory(&self) -> Value {
        let _index = self.index.lock();
        let index_path = self.dir.join(INDEX_FILE);
        let mut index: serde_json::Map<String, Value> = fs::read(&index_path)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
            .and_then(|value| value.as_object().cloned())
            .unwrap_or_default();
        let mut changed = false;
        let mut present = HashSet::new();
        if let Ok(entries) = fs::read_dir(&self.dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|s| s.to_str()) != Some("json") {
                    continue;
                }
                let Some(id) = path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .and_then(|s| Uuid::parse_str(s).ok())
                    .map(|id| id.to_string())
                else {
                    continue;
                };
                if !index.contains_key(&id) {
                    let Some(record) = fs::read(&path)
                        .ok()
                        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
                    else {
                        continue;
                    };
                    index.insert(id.clone(), record_summary(&record));
                    changed = true;
                }
                present.insert(id);
            }
        }
        let before = index.len();
        index.retain(|id, _| present.contains(id));
        if changed || index.len() != before {
            self.write_index(&index);
        }
        let mut records: Vec<Value> = index.into_values().collect();
        records.sort_by(|a, b| b["created"].as_str().cmp(&a["created"].as_str()));
        let target = self.target.lock().clone();
        json!({"targetIsDirectory":Path::new(&target).is_dir(),"target":target,"records":records})
    }
    fn write_index(&self, index: &serde_json::Map<String, Value>) {
        let temporary = self.dir.join(format!("{INDEX_FILE}.tmp"));
        // The index is a cache; a failed write only means the next listing rebuilds it.
        if serde_json::to_vec(index)
            .ok()
            .and_then(|bytes| fs::write(&temporary, bytes).ok())
            .is_some()
        {
            let _ = fs::rename(&temporary, self.dir.join(INDEX_FILE));
        }
    }
    /// Save a full record and add its summary to the index.
    fn save_record(&self, record: &Value) -> Result<()> {
        let id = record["id"].as_str().context("Record has no ID")?;
        fs::write(self.record_path(id)?, serde_json::to_vec_pretty(record)?)?;
        let _index = self.index.lock();
        let index_path = self.dir.join(INDEX_FILE);
        if let Some(mut index) = fs::read(&index_path)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok())
            .and_then(|value| value.as_object().cloned())
        {
            index.insert(id.to_owned(), record_summary(record));
            self.write_index(&index);
        }
        Ok(())
    }
    fn record_path(&self, id: &str) -> Result<PathBuf> {
        let id = Uuid::parse_str(id).context("Invalid evidence record ID")?;
        Ok(self.dir.join(format!("{id}.json")))
    }
    pub fn read_record(&self, id: &str) -> Result<Value> {
        Ok(serde_json::from_slice(&fs::read(self.record_path(id)?)?)?)
    }
    #[allow(clippy::too_many_arguments)] // Explicit provenance fields at each observation boundary.
    pub fn save_external(&self, provider: &str, kind: &str, tool: &str, arguments: Value,
        target: &str, response: Value, provenance: Value) -> Result<Value> {
        let id = Uuid::new_v4().to_string();
        let record = json!({"id":id,"provider":provider,"kind":kind,"tool":tool,
            "arguments":arguments,"target":canonical_target(target),"selectedTarget":*self.target.lock(),
            "created":chrono::Utc::now().to_rfc3339(),"failed":response["isError"]==true,
            "response":response,"provenance":provenance});
        self.save_record(&record)
            .context("Could not save the analysis observation")?;
        Ok(record)
    }
    pub fn export_dossier(
        &self,
        root: &Path,
        request: &Value,
        brief: Option<Value>,
    ) -> Result<Value> {
        let target = self.target.lock().clone();
        if target.is_empty() {
            bail!("Select an artifact first");
        }
        let original =
            fs::canonicalize(&target).context("The selected artifact is no longer available")?;
        let root = fs::canonicalize(root)?;
        let original_folder = if original.is_dir() {
            original.as_path()
        } else {
            original
                .parent()
                .context("Artifact has no parent directory")?
        };
        if root.starts_with(original_folder) || original.starts_with(&root) {
            bail!("Choose a separate destination project outside the original application, with no original artifact inside it");
        }
        let mut records = Vec::new();
        let mut total = 0usize;
        let inventory = self.inventory();
        for item in inventory["records"].as_array().into_iter().flatten() {
            // Selection and stored records both use canonical paths. Do not copy
            // evidence from other targets into a reconstruction dossier.
            let matches = item["target"]
                .as_str()
                .is_some_and(|p| same_target(p, &target));
            if !matches {
                continue;
            }
            let id = item["id"].as_str().context("Invalid saved record")?;
            let bytes = fs::read(self.record_path(id)?)?;
            total += bytes.len();
            if total > 128 * 1024 * 1024 {
                bail!("This target has more than 128 MiB of saved evidence. Export individual records instead.");
            }
            records.push((item.clone(), bytes));
        }
        let name = format!("quixi-reconstruction-{}", Uuid::new_v4());
        let destination = quixi_platform::SafeFs::resolve_beneath(&root, Path::new(&name))?;
        fs::create_dir(&destination).context("Could not create a new dossier directory")?;
        fs::create_dir(destination.join("evidence"))?;
        let mut manifest = Vec::new();
        for (item, bytes) in &records {
            let id = item["id"].as_str().unwrap();
            let file = format!("evidence/{id}.json");
            fs::write(destination.join(&file), bytes)?;
            manifest.push(json!({"id":id,"file":file,"tool":item["tool"],"provider":item["provider"],"kind":item["kind"],"failed":item["failed"],"created":item["created"],"sha256":format!("{:x}",Sha256::digest(bytes))}));
        }
        let has_brief = brief.is_some();
        let brief_text = brief.as_ref().and_then(|b| b["reply"].as_str()).unwrap_or("No completed analysis brief was selected. Prepare an analysis task and save another dossier after reviewing its result.");
        fs::write(destination.join("SPEC.md"), format!("# Reconstruction specification\n\nStatus: DRAFT — review coverage, requirements and unknowns before implementing.\n\n{brief_text}\n"))?;
        fs::write(
            destination.join("oracle-cases.json"),
            b"{\n  \"version\": 1,\n  \"cases\": []\n}\n",
        )?;
        fs::write(
            destination.join("manifest.json"),
            serde_json::to_vec_pretty(&json!({
                "format":"quixidesk-reconstruction-v1","created":chrono::Utc::now().to_rfc3339(),
                "target":target,"scope":request["scope"],"goal":request["goal"],
                "userObservations":request["observations"],"brief":brief,"records":manifest,
                "limitations":["Static evidence does not prove runtime equivalence.","Failed records remain failures; absence of findings is not proof of absence.","Live retained REA references may expire; inline saved responses remain available.","User observations and model inferences require independent verification."]
            }))?,
        )?;
        fs::write(destination.join("README.md"), "# Reconstruction evidence dossier\n\nWorkflow: binary -> REA -> SPEC.md -> rebuild -> oracle -> retry.\n\nReview SPEC.md and manifest.json. Add explicit cases to oracle-cases.json; an empty suite is UNVERIFIED. Use the app's Run oracle checks action to execute those commands in the destination project, then Prepare retry to fix recorded mismatches. See docs/RECONSTRUCTION.md in the application for the case schema.\n\nThe evidence directory contains original saved REA responses, including failures, with SHA-256 digests in the manifest. Record IDs link the specification to those responses; Evidence IDs identify REA observations. Keep implementation tasks on SPEC.md and observed test outputs; analysis tasks own original/decompiled material. This export contains analysis data, not a runnable duplicate or the original application.\n\n## Coverage checklist\n\n- [ ] Target version, identity and selected feature are established.\n- [ ] UI flows, inputs, outputs, state, error cases and data formats are documented.\n- [ ] Dependencies and platform boundaries are identified.\n- [ ] Every supported behaviour links to evidence or a labelled user observation.\n- [ ] Inferences, unavailable resources and remaining unknowns are listed.\n- [ ] New implementation lives outside the original application.\n- [ ] Build checks and behavioural comparisons have actually run.\n\nMark an item complete only after checking it. Passing declared cases does not prove whole-application equivalence. Keep original and reconstructed code/results distinct.\n")?;
        Ok(
            json!({"path":destination,"relativePath":name,"records":records.len(),"hasBrief":has_brief}),
        )
    }
    /// `persist: false` returns the same record shape without saving it or adding
    /// it to history (for paging retained views).
    pub fn call(engine: &QuixiEngine, tool: &str, args: Value, persist: bool) -> Result<Value> {
        // UI, MCP and agent calls alike; local paths outside the project stay allowed here.
        reject_non_local_paths(&args)?;
        let id = Uuid::new_v4().to_string();
        let selected_target = engine.analysis.target.lock().clone();
        let result = engine.rea.call(tool, args.clone());
        let transport_failed = result.is_err();
        let failed = result
            .as_ref()
            .map(|r| r["isError"].as_bool().unwrap_or(false))
            .unwrap_or(true);
        let response = match result {
            Ok(value) => value,
            Err(error) => {
                json!({"isError":true,"content":[{"type":"text","text":error.to_string()}]})
            }
        };
        let evidence = quixi_mcp::rea::payload(&response);
        let process_id = engine.rea.process_id();
        engine.analysis.observe_provider_result(tool, &evidence, failed, transport_failed, process_id);
        // Tools without a path act on REA's open binary, which may differ from the selection.
        let open = engine.analysis.open_rea_target(process_id);
        engine.analysis.observe_rea_target(tool, &args, &evidence, failed, process_id);
        let target = args["path"]
            .as_str()
            .or_else(|| args["input_path"].as_str())
            .or_else(|| evidence.pointer("/target/path").and_then(Value::as_str))
            .or_else(|| evidence.pointer("/result/path").and_then(Value::as_str))
            .or(open.as_deref())
            .unwrap_or(&selected_target);
        let mut record = json!({"provider":"rea","kind":"static","selectedTarget":selected_target,"id":id,"tool":tool,"arguments":args,"target":canonical_target(target),
            "created":chrono::Utc::now().to_rfc3339(),"failed":failed,"response":response});
        if persist {
            engine
                .analysis
                .save_record(&record)
                .context("Could not save the analysis result")?;
        } else {
            record["persisted"] = json!(false);
        }
        Ok(record)
    }
    /// Before the selection changes, close a different binary REA still has open so
    /// later no-path evidence cannot be saved under the newly selected artifact.
    fn close_other_rea_target(engine: &QuixiEngine, selected: &str) -> Result<()> {
        if !engine.rea.is_connected() {
            return Ok(());
        }
        let process_id = engine.rea.process_id();
        let open = match engine.rea.open_target() {
            Ok(open) => open,
            // The connection ended, so nothing remains open.
            Err(_) if !engine.rea.is_connected() => return Ok(()),
            Err(error) => {
                return Err(error.context(
                    "Could not confirm which binary REA has open; the selection was not changed",
                ))
            }
        };
        observe_session(
            &json!({"open":open.is_some(),"path":open}),
            process_id,
            &mut engine.analysis.rea_target.lock(),
        );
        if let Some(open) = open.filter(|open| !same_target(open, selected)) {
            engine.rea.close_target().with_context(|| {
                format!("REA still has {open} open; the selection was not changed")
            })?;
            *engine.analysis.rea_target.lock() = None;
            engine.analysis.provider_sessions.lock().clear();
        }
        Ok(())
    }
    pub fn handle(engine: &Arc<QuixiEngine>, route: &str, body: &Value) -> Result<Value> {
        match route {
            "workflow" => engine.rea.workflow(body),
            "connect" => {
                let connected = engine.rea.connect(body["mode"].as_str())?;
                observe_session(
                    &connected["session"],
                    engine.rea.process_id(),
                    &mut engine.analysis.rea_target.lock(),
                );
                Ok(connected)
            }
            "disconnect" => {
                engine.rea.disconnect()?;
                *engine.analysis.rea_target.lock() = None;
                Ok(json!({"connected":false}))
            }
            "inventory" => Ok(engine.analysis.inventory()),
            "select" => {
                let path = body["path"]
                    .as_str()
                    .filter(|s| !s.is_empty())
                    .map(str::to_owned)
                    .or_else(|| {
                        if body["directory"] == true {
                            ComputerUse::pick_folder(Some(
                                "Select a JavaScript application or extracted package",
                            ))
                        } else {
                            ComputerUse::pick_file(Some("Select an artifact to analyse"))
                        }
                    });
                let Some(path) = path else {
                    return Ok(json!({"cancelled":true}));
                };
                let path = fs::canonicalize(path).context("The artifact does not exist")?;
                let path = path
                    .to_string_lossy()
                    .trim_start_matches("\\\\?\\")
                    .to_string();
                let previous = engine.analysis.target.lock().clone();
                if !same_target(&previous, &path) {
                    Self::close_other_rea_target(engine, &path)?;
                }
                fs::write(engine.analysis.dir.join("target.txt"), &path)?;
                *engine.analysis.target.lock() = path;
                Ok(engine.analysis.inventory())
            }
            "tool" => {
                let name = body["tool"].as_str().context("Choose an analysis tool")?;
                Self::call(
                    engine,
                    name,
                    body.get("arguments").cloned().unwrap_or_else(|| json!({})),
                    body["persist"].as_bool().unwrap_or(true),
                )
            }
            "evidence" => {
                let path = engine
                    .analysis
                    .record_path(body["id"].as_str().context("Choose an evidence record")?)?;
                Ok(serde_json::from_slice(&fs::read(path)?)?)
            }
            "export" => {
                let id = body["id"].as_str().context("Choose an evidence record")?;
                let source = engine.analysis.record_path(id)?;
                let Some(folder) =
                    ComputerUse::pick_folder(Some("Export analysis evidence to folder"))
                else {
                    return Ok(json!({"cancelled":true}));
                };
                let destination = Path::new(&folder).join(format!("quixi-evidence-{id}.json"));
                let bytes = fs::read(source)?;
                use std::io::Write;
                let mut file = fs::OpenOptions::new()
                    .create_new(true)
                    .write(true)
                    .open(&destination)
                    .context(
                        "Evidence already exists in this folder or the folder is not writable",
                    )?;
                file.write_all(&bytes)?;
                Ok(json!({"path":destination}))
            }
            _ => bail!("Unknown REA workspace operation"),
        }
    }
    pub fn agent_call(
        engine: &QuixiEngine,
        root: &Path,
        tool: &str,
        mut args: Value,
    ) -> Result<Value> {
        if !quixi_mcp::rea::AGENT_TOOLS.contains(&tool) {
            bail!("This tool is not enabled for the coding agent. Use the REA workspace to invoke it directly.");
        }
        let selected = engine.analysis.target.lock().clone();
        // Runtime/patch/extraction tools are not in this set.
        validate_paths(
            &mut args,
            &fs::canonicalize(root)?,
            &fs::canonicalize(&selected).unwrap_or_default(),
        )?;
        Self::call(engine, tool, args, true)
    }
}
