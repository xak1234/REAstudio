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
    io::Read,
    path::{Component, Path, PathBuf, Prefix},
    sync::Arc,
};
use uuid::Uuid;

mod investigations;

/// Summaries of saved records, so listing does not parse every full response.
const INDEX_FILE: &str = "index.json";

pub struct AnalysisWorkspace {
    dir: PathBuf,
    pub target: Mutex<String>,
    pub provider_sessions: Mutex<HashMap<String,u32>>,
    /// The binary REA reports open, keyed by the REA process that opened it.
    rea_target: Mutex<Option<(u32, String)>>,
    /// Content identity established when this process opened its native target.
    rea_identity: Mutex<Option<(u32, String, Value)>>,
    /// Keep snapshots, the provider operation and evidence attribution together.
    operation: Mutex<()>,
    index: Mutex<()>,
    investigation_lock: Mutex<()>,
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

fn valid_sha256(value: &Value) -> Option<String> {
    value.as_str().filter(|hash| hash.len() == 64 && hash.bytes().all(|c| c.is_ascii_hexdigit()))
        .map(str::to_ascii_lowercase)
}

pub(crate) fn verified_sha256(identity: &Value) -> Option<String> {
    if identity["status"] == "verified" && identity["kind"] == "file" {
        valid_sha256(&identity["sha256"])
    } else { None }
}

/// Hash file bytes, without loading a large artifact into memory. Directories do not
/// have a content identity until a complete, stable file manifest is implemented.
pub(crate) fn capture_artifact_identity(target: &str) -> Value {
    if target.is_empty() || is_non_local_path(Path::new(target)) {
        return json!({"status":"unverified","kind":"unavailable","reason":"No local artifact is available"});
    }
    let captured = (|| -> Result<Value> {
        let mut file = fs::File::open(target)?;
        let before = file.metadata()?;
        if !before.is_file() {
            return Ok(json!({"status":"unverified","kind":"directory","reason":"Directory content identity is not supported; no complete file manifest was captured"}));
        }
        let mut digest = Sha256::new();
        let mut buffer = [0u8; 64 * 1024];
        loop {
            let count = file.read(&mut buffer)?;
            if count == 0 { break; }
            digest.update(&buffer[..count]);
        }
        let after = file.metadata()?;
        if before.len() != after.len() || before.modified().ok() != after.modified().ok() {
            return Ok(json!({"status":"changed","kind":"file","reason":"The artifact changed while its identity was being captured"}));
        }
        Ok(json!({"status":"verified","kind":"file","algorithm":"sha256",
            "sha256":format!("{:x}", digest.finalize()),"size":after.len()}))
    })();
    // Opening a directory as a File is unsupported on Windows.
    if fs::metadata(target).is_ok_and(|metadata| metadata.is_dir()) {
        return json!({"status":"unverified","kind":"directory","reason":"Directory content identity is not supported; no complete file manifest was captured"});
    }
    captured.unwrap_or_else(|error| json!({"status":"unverified","kind":"unavailable","reason":format!("Could not establish artifact identity: {error}")}))
}

fn checked_identity(before: &Value, after: &Value) -> Value {
    match (verified_sha256(before), verified_sha256(after)) {
        (Some(first), Some(last)) if first == last => {
            let mut identity = after.clone();
            identity["verification"] = json!("hashed-before-and-after");
            identity
        }
        (Some(first), last) => json!({"status":"changed","kind":"file",
            "beforeSha256":first,"afterSha256":last,"reason":"Artifact bytes changed or became unavailable during analysis"}),
        _ if before["status"] == "changed" || after["status"] == "changed" =>
            json!({"status":"changed","kind":"file","reason":"Artifact identity was unstable during analysis"}),
        _ => before.clone(),
    }
}

fn checked_analysis_identity(before: &Value, after: &Value, process_before: u32, process_after: u32) -> Value {
    let identity = checked_identity(before, after);
    if identity["status"] == "changed" { return identity; }
    if process_before == 0 || process_before != process_after {
        return json!({"status":"unverified","kind":identity["kind"],"observedSha256":verified_sha256(&identity),
            "reason":"The REA process ended or changed during this operation","reasonCode":"provider-session-ended"});
    }
    identity
}

fn retained_result_identity(tool: &str, identity: Value) -> Value {
    if matches!(tool, "inspect_analysis_view" | "get_evidence_bundle") && verified_sha256(&identity).is_some() {
        // A retained view can originate from an earlier open of the same path.
        // Current filesystem bytes cannot establish that view's content identity.
        json!({"status":"unverified","kind":"file","observedSha256":verified_sha256(&identity),
            "reason":"The retained reference has no verified link to its original artifact version",
            "reasonCode":"retained-reference-origin-unverified"})
    } else { identity }
}

/// Playground calls carry routing context as well as settings. It is not a
/// RuntimeSettings field and must not turn a read into a configuration write.
fn runtime_settings_patch(body: &Value) -> Result<Value> {
    let mut patch = body.as_object().context("REA settings must be a JSON object")?.clone();
    patch.remove("project");
    Ok(Value::Object(patch))
}

/// Recheck the brief at the export boundary. The UI/agent may have validated it
/// before a different artifact was selected or the source file was rebuilt.
fn validate_dossier_brief(brief: &Value, target: &str, current: &Value) -> Result<()> {
    let brief_target = brief["target"].as_str()
        .context("This analysis brief has no captured artifact target. Create a new brief or export without it; the original brief is preserved.")?;
    if !same_target(brief_target, target) {
        bail!("This analysis brief belongs to another artifact. The selected target changed before export; select its artifact or create a new brief. The original brief is preserved.");
    }
    let saved = &brief["artifactIdentity"];
    if current["kind"] == "file" {
        let expected = verified_sha256(current);
        if expected.is_none() || verified_sha256(saved) != expected {
            bail!("This analysis brief was created for a different or unverified artifact build. Create a new brief for the captured file, or export without the old brief. The original brief is preserved.");
        }
    } else if current["kind"] != "directory" || saved["kind"] != "directory" {
        bail!("The analysis brief and captured artifact do not have matching identity kinds. Create a new brief or export without it; the original brief is preserved.");
    }
    // Directory exports remain explicitly unverified: matching paths/kinds are
    // not a claim that every file in the directory stayed unchanged.
    Ok(())
}

/// Old IDA records already carry a provider-verified input digest. Other historical
/// records cannot be assigned today's hash: doing so would relabel old evidence.
fn record_identity(record: &Value) -> Value {
    if let Some(identity) = record.get("artifactIdentity").filter(|value| value.is_object()) {
        if identity["status"] != "verified" || verified_sha256(identity).is_some() {
            return identity.clone();
        }
    }
    if record["provider"] == "ida-bridge" {
        if let Some(sha256) = valid_sha256(&record["provenance"]["sha256"]) {
            return json!({"status":"verified","kind":"file","algorithm":"sha256","sha256":sha256,
                "verification":"ida-provider-input-hash"});
        }
    }
    json!({"status":"unverified","kind":"unknown","reason":"This record has no verified artifact content identity"})
}

fn record_summary(record: &Value) -> Value {
    json!({"id":record["id"],"tool":record["tool"],"provider":record["provider"],"kind":record["kind"],
        "created":record["created"],"target":record["target"],"failed":record["failed"],
        "artifactIdentity":record_identity(record),"identitySchemaVersion":1})
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
            rea_identity: Mutex::new(None),
            operation: Mutex::new(()),
            index: Mutex::new(()),
            investigation_lock: Mutex::new(()),
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
        let record = json!({"id":id,"target":artifact,"tool":"inspect_pe_resources","failed":true,"response":{"isError":true},"created":"2026-01-01",
            "artifactIdentity":capture_artifact_identity(&artifact.to_string_lossy())});
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

    #[test]
    fn artifact_hashes_detect_changed_bytes_and_do_not_claim_directory_identity() {
        let base = std::env::temp_dir().join(format!("quixi-artifact-{}", Uuid::new_v4()));
        fs::create_dir_all(&base).unwrap();
        let file = base.join("target.bin");
        fs::write(&file, b"abc").unwrap();
        let before = capture_artifact_identity(&file.to_string_lossy());
        assert_eq!(before["sha256"], "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        assert_eq!(checked_identity(&before, &capture_artifact_identity(&file.to_string_lossy()))["status"], "verified");
        // Identical bytes must not make a disconnected/replaced provider session verified.
        assert_eq!(checked_analysis_identity(&before, &before, 42, 42)["status"], "verified");
        for process_after in [0, 43] {
            let interrupted = checked_analysis_identity(&before, &before, 42, process_after);
            assert_eq!(interrupted["status"], "unverified");
            assert_eq!(interrupted["reasonCode"], "provider-session-ended");
        }
        for tool in ["inspect_analysis_view", "get_evidence_bundle"] {
            let retained = retained_result_identity(tool, before.clone());
            assert!(verified_sha256(&retained).is_none());
            assert_eq!(retained["reasonCode"], "retained-reference-origin-unverified");
        }
        // Same length, different bytes: identity must use content, not file size.
        fs::write(&file, b"abd").unwrap();
        let after = capture_artifact_identity(&file.to_string_lossy());
        let changed = checked_identity(&before, &after);
        assert_eq!(changed["status"], "changed");
        assert_eq!(changed["beforeSha256"], before["sha256"]);
        assert_eq!(changed["afterSha256"], after["sha256"]);
        let directory = capture_artifact_identity(&base.to_string_lossy());
        assert_eq!(directory["status"], "unverified");
        assert_eq!(directory["kind"], "directory");
        assert!(verified_sha256(&directory).is_none());
        fs::remove_dir_all(&base).unwrap();
        assert_eq!(checked_identity(&before, &capture_artifact_identity(&file.to_string_lossy()))["status"], "changed");
    }

    #[test]
    fn runtime_settings_ignores_playground_project_context() {
        assert_eq!(runtime_settings_patch(&json!({"project":"project-123"})).unwrap(), json!({}));
        assert_eq!(runtime_settings_patch(&json!({"project":"project-123","mode":"bundled","ghidraHeapMiB":4096})).unwrap(),
            json!({"mode":"bundled","ghidraHeapMiB":4096}));
        assert!(runtime_settings_patch(&json!([])).is_err());
    }

    #[test]
    fn dossier_filters_replaced_binary_versions_without_relabelling_legacy_records() {
        let base = std::env::temp_dir().join(format!("quixi-versioned-dossier-{}", Uuid::new_v4()));
        let original = base.join("original");
        let destination = base.join("rebuild");
        fs::create_dir_all(&original).unwrap();
        fs::create_dir_all(&destination).unwrap();
        let artifact = original.join("target.bin");
        let target = artifact.to_string_lossy().into_owned();
        fs::write(&artifact, b"version-one").unwrap();
        let old_identity = capture_artifact_identity(&target);
        let analysis = AnalysisWorkspace::new(&base.join("profile"));
        *analysis.target.lock() = target.clone();
        let old_id = Uuid::new_v4().to_string();
        analysis.save_record(&json!({"id":old_id,"target":target,"provider":"rea","tool":"list_procedures",
            "created":"2026-01-01","artifactIdentity":old_identity})).unwrap();
        let legacy_id = Uuid::new_v4().to_string();
        let legacy = json!({"id":legacy_id,"target":target,"provider":"rea","tool":"procedure_pseudo_code","created":"2026-01-02"});
        analysis.save_record(&legacy).unwrap();
        let legacy_bytes = fs::read(analysis.record_path(&legacy_id).unwrap()).unwrap();
        fs::write(&artifact, b"version-two").unwrap();
        let current = capture_artifact_identity(&target);
        let current_id = Uuid::new_v4().to_string();
        analysis.save_record(&json!({"id":current_id,"target":target,"provider":"rea","tool":"inspect_pe_resources",
            "created":"2026-01-03","failed":true,"response":{"isError":true},"artifactIdentity":current})).unwrap();
        // Historical IDA observations already have a trustworthy provider input hash.
        let ida_id = Uuid::new_v4().to_string();
        analysis.save_record(&json!({"id":ida_id,"target":target,"provider":"ida-bridge","tool":"decompile",
            "created":"2026-01-03","provenance":{"sha256":current["sha256"]}})).unwrap();
        let changed_id = Uuid::new_v4().to_string();
        analysis.save_record(&json!({"id":changed_id,"target":target,"provider":"rea","tool":"list_procedures",
            "created":"2026-01-04","failed":true,"artifactIdentity":checked_identity(&old_identity,&current)})).unwrap();

        let exported = analysis.export_dossier(&destination, &json!({}), None).unwrap();
        assert_eq!(exported["records"], 2);
        assert_eq!(exported["excludedRecordCount"], 3);
        let excluded = exported["excludedRecords"].as_array().unwrap();
        assert!(excluded.iter().any(|r| r["id"] == old_id && r["reason"] == "different-artifact-version"));
        assert!(excluded.iter().any(|r| r["id"] == legacy_id && r["reason"] == "unverified-artifact-identity"));
        assert!(excluded.iter().any(|r| r["id"] == changed_id && r["reason"] == "artifact-changed-during-analysis"));
        let folder = Path::new(exported["path"].as_str().unwrap());
        let manifest: Value = serde_json::from_slice(&fs::read(folder.join("manifest.json")).unwrap()).unwrap();
        assert_eq!(manifest["artifactIdentity"]["sha256"], format!("{:x}",Sha256::digest(b"version-two")));
        for record in manifest["records"].as_array().unwrap() {
            let bytes = fs::read(folder.join(record["file"].as_str().unwrap())).unwrap();
            assert_eq!(record["sha256"], format!("{:x}",Sha256::digest(&bytes)));
            assert_eq!(record["artifactIdentity"]["sha256"], current["sha256"]);
        }
        assert_eq!(fs::read(analysis.record_path(&legacy_id).unwrap()).unwrap(), legacy_bytes);
        assert!(analysis.record_path(&old_id).unwrap().is_file());
        let groups = analysis.inventory()["artifactGroups"].as_array().unwrap().clone();
        assert!(groups.iter().any(|group| group["sha256"] == old_identity["sha256"] && group["recordCount"] == 1));
        assert!(groups.iter().any(|group| group["sha256"] == current["sha256"] && group["recordCount"] == 2));
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn old_index_is_upgraded_without_modifying_evidence_and_directories_stay_available() {
        let base = std::env::temp_dir().join(format!("quixi-identity-index-{}", Uuid::new_v4()));
        let original = base.join("javascript-app");
        let destination = base.join("rebuild");
        fs::create_dir_all(&original).unwrap();
        fs::create_dir_all(&destination).unwrap();
        fs::write(original.join("app.js"), b"console.log('example');").unwrap();
        let analysis = AnalysisWorkspace::new(&base.join("profile"));
        *analysis.target.lock() = original.to_string_lossy().into_owned();
        let id = Uuid::new_v4().to_string();
        let record = json!({"id":id,"target":original,"provider":"rea","tool":"analyze_javascript_application","created":"2026-01-01"});
        analysis.save_record(&record).unwrap();
        let original_bytes = fs::read(analysis.record_path(&id).unwrap()).unwrap();
        let mut old_index = serde_json::Map::new();
        old_index.insert(id.clone(), json!({"id":id,"target":original,"tool":"analyze_javascript_application","created":"2026-01-01"}));
        fs::write(analysis.dir.join(INDEX_FILE), serde_json::to_vec(&old_index).unwrap()).unwrap();
        let inventory = analysis.inventory();
        assert_eq!(inventory["records"][0]["identitySchemaVersion"], 1);
        assert_eq!(inventory["records"][0]["artifactIdentity"]["status"], "unverified");
        assert_eq!(fs::read(analysis.record_path(&id).unwrap()).unwrap(), original_bytes);
        let exported = analysis.export_dossier(&destination, &json!({}), None).unwrap();
        assert_eq!(exported["records"], 1);
        assert_eq!(exported["artifactIdentity"]["kind"], "directory");
        assert_eq!(exported["artifactIdentity"]["status"], "unverified");
        let brief = json!({"target":original,"artifactIdentity":capture_artifact_identity(&original.to_string_lossy()),"reply":"Directory analysis remains unverified."});
        let with_brief = analysis.export_dossier(&destination, &json!({}), Some(brief)).unwrap();
        assert_eq!(with_brief["hasBrief"], true);
        assert_eq!(with_brief["artifactIdentity"]["status"], "unverified");
        fs::remove_dir_all(base).unwrap();
    }

    #[test]
    fn dossier_rechecks_brief_against_its_own_target_and_content_snapshot() {
        let base = std::env::temp_dir().join(format!("quixi-brief-snapshot-{}", Uuid::new_v4()));
        let original = base.join("original");
        let destination = base.join("rebuild");
        fs::create_dir_all(&original).unwrap();
        fs::create_dir_all(&destination).unwrap();
        let artifact = original.join("first.bin");
        let other = original.join("second.bin");
        fs::write(&artifact, b"first version").unwrap();
        fs::write(&other, b"first version").unwrap();
        let target = artifact.to_string_lossy().into_owned();
        let analysis = AnalysisWorkspace::new(&base.join("profile"));
        *analysis.target.lock() = target.clone();
        // This models a brief accepted by the caller before the export boundary.
        let brief = json!({"target":target,"artifactIdentity":capture_artifact_identity(&target),"reply":"Original build specification."});
        fs::write(&artifact, b"later version").unwrap();
        let changed = analysis.export_dossier(&destination, &json!({}), Some(brief.clone())).unwrap_err();
        assert!(changed.to_string().contains("different or unverified artifact build"));
        assert_eq!(fs::read_dir(&destination).unwrap().count(), 0);

        // Even identical bytes at another selected path must not substitute a
        // different artifact under the already reviewed brief.
        *analysis.target.lock() = other.to_string_lossy().into_owned();
        let switched = analysis.export_dossier(&destination, &json!({}), Some(brief.clone())).unwrap_err();
        assert!(switched.to_string().contains("another artifact"));
        assert_eq!(fs::read_dir(&destination).unwrap().count(), 0);
        let mut matching = brief;
        matching["target"] = json!(other);
        let exported = analysis.export_dossier(&destination, &json!({}), Some(matching)).unwrap();
        let manifest: Value = serde_json::from_slice(&fs::read(Path::new(exported["path"].as_str().unwrap()).join("manifest.json")).unwrap()).unwrap();
        assert_eq!(manifest["brief"]["target"], manifest["target"]);
        assert_eq!(manifest["brief"]["artifactIdentity"]["sha256"], manifest["artifactIdentity"]["sha256"]);
        assert_eq!(manifest["artifactIdentity"]["sha256"], format!("{:x}",Sha256::digest(b"first version")));
        fs::remove_dir_all(base).unwrap();
    }
}
impl AnalysisWorkspace {
    /// Read-only native-close check; never waits behind a provider or file hash.
    pub fn is_busy(&self) -> bool {
        self.operation.try_lock().is_none() || self.investigation_lock.try_lock().is_none()
    }

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
            rea_identity: Mutex::new(None),
            operation: Mutex::new(()),
            index: Mutex::new(()),
            investigation_lock: Mutex::new(()),
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
                if index.get(&id).is_none_or(|summary| summary["identitySchemaVersion"] != 1) {
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
        let mut groups: std::collections::BTreeMap<(String, String), Value> = std::collections::BTreeMap::new();
        for record in &records {
            let target = record["target"].as_str().unwrap_or("");
            if target.is_empty() { continue; }
            let identity = &record["artifactIdentity"];
            let sha256 = verified_sha256(identity);
            let identity_key = sha256.clone().unwrap_or_else(|| format!("{}:{}",
                identity["status"].as_str().unwrap_or("unverified"), identity["kind"].as_str().unwrap_or("unknown")));
            let group = groups.entry((lexical_key(target), identity_key)).or_insert_with(||
                json!({"target":target,"sha256":sha256,"identityStatus":identity["status"],"artifactKind":identity["kind"],
                    "recordCount":0,"failedRecordCount":0,"latestRecordAt":record["created"]}));
            group["recordCount"] = json!(group["recordCount"].as_u64().unwrap_or(0) + 1);
            if record["failed"] == true {
                group["failedRecordCount"] = json!(group["failedRecordCount"].as_u64().unwrap_or(0) + 1);
            }
        }
        let target = self.target.lock().clone();
        json!({"targetIsDirectory":Path::new(&target).is_dir(),"target":target,"records":records,
            "artifactGroups":groups.into_values().collect::<Vec<_>>(),"identitySchemaVersion":1})
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
        let mut record = json!({"id":id,"provider":provider,"kind":kind,"tool":tool,
            "arguments":arguments,"target":canonical_target(target),"selectedTarget":*self.target.lock(),
            "created":chrono::Utc::now().to_rfc3339(),"failed":response["isError"]==true,
            "response":response,"provenance":provenance});
        let mut identity = record_identity(&record);
        if identity["status"] != "verified" {
            if let Some(source_id) = record["provenance"]["sourceRecordId"].as_str() {
                if let Ok(source) = self.read_record(source_id) {
                    if same_target(source["target"].as_str().unwrap_or(""), target) {
                        identity = record_identity(&source);
                        identity["verification"] = json!("inherited-from-source-record");
                        identity["sourceRecordId"] = json!(source_id);
                    }
                }
            }
        }
        record["artifactIdentity"] = identity;
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
        let artifact_identity = capture_artifact_identity(&target);
        let current_sha256 = verified_sha256(&artifact_identity);
        if original.is_file() && current_sha256.is_none() {
            bail!("Cannot export a file dossier without a stable artifact identity: {}", artifact_identity["reason"]);
        }
        if let Some(brief) = &brief {
            validate_dossier_brief(brief, &target, &artifact_identity)?;
        }
        let mut records = Vec::new();
        let mut excluded_records = Vec::new();
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
            let record: Value = serde_json::from_slice(&bytes).context("Saved evidence is not valid JSON")?;
            let identity = record_identity(&record);
            if let Some(expected) = &current_sha256 {
                let reason = match verified_sha256(&identity) {
                    Some(actual) if &actual == expected => None,
                    Some(_) => Some("different-artifact-version"),
                    None if identity["status"] == "changed" => Some("artifact-changed-during-analysis"),
                    None => Some("unverified-artifact-identity"),
                };
                if let Some(reason) = reason {
                    excluded_records.push(json!({"id":id,"tool":item["tool"],"reason":reason,"artifactIdentity":identity}));
                    continue;
                }
            }
            total += bytes.len();
            if total > 128 * 1024 * 1024 {
                bail!("This target has more than 128 MiB of saved evidence. Export individual records instead.");
            }
            let mut summary = item.clone();
            summary["artifactIdentity"] = identity;
            records.push((summary, bytes));
        }
        if current_sha256.is_some() && checked_identity(&artifact_identity, &capture_artifact_identity(&target))["status"] != "verified" {
            bail!("The artifact changed while preparing the dossier. Select the current build and try again.");
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
            manifest.push(json!({"id":id,"file":file,"tool":item["tool"],"provider":item["provider"],"kind":item["kind"],"failed":item["failed"],"created":item["created"],"sha256":format!("{:x}",Sha256::digest(bytes)),"artifactIdentity":item["artifactIdentity"]}));
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
                "format":"quixidesk-reconstruction-v1","identitySchemaVersion":1,"created":chrono::Utc::now().to_rfc3339(),
                "target":target,"scope":request["scope"],"goal":request["goal"],
                "userObservations":request["observations"],"brief":brief,"records":manifest,
                "artifactIdentity":artifact_identity,"excludedRecords":excluded_records,
                "limitations":["Static evidence does not prove runtime equivalence.","Failed records remain failures; absence of findings is not proof of absence.","Live retained REA references may expire; inline saved responses remain available.","User observations and model inferences require independent verification.","Directory evidence has no verified whole-directory content identity.","Records from another file version or without a verified file identity are excluded, not deleted."]
            }))?,
        )?;
        fs::write(destination.join("README.md"), "# Reconstruction evidence dossier\n\nWorkflow: binary -> REA -> SPEC.md -> rebuild -> oracle -> retry.\n\nReview SPEC.md and manifest.json. Add explicit cases to oracle-cases.json; an empty suite is UNVERIFIED. Use the app's Run oracle checks action to execute those commands in the destination project, then Prepare retry to fix recorded mismatches. See docs/RECONSTRUCTION.md in the application for the case schema.\n\nThe evidence directory contains original saved REA responses, including failures, with SHA-256 digests in the manifest. Record IDs link the specification to those responses; Evidence IDs identify REA observations. Keep implementation tasks on SPEC.md and observed test outputs; analysis tasks own original/decompiled material. This export contains analysis data, not a runnable duplicate or the original application.\n\n## Coverage checklist\n\n- [ ] Target version, identity and selected feature are established.\n- [ ] UI flows, inputs, outputs, state, error cases and data formats are documented.\n- [ ] Dependencies and platform boundaries are identified.\n- [ ] Every supported behaviour links to evidence or a labelled user observation.\n- [ ] Inferences, unavailable resources and remaining unknowns are listed.\n- [ ] New implementation lives outside the original application.\n- [ ] Build checks and behavioural comparisons have actually run.\n\nMark an item complete only after checking it. Passing declared cases does not prove whole-application equivalence. Keep original and reconstructed code/results distinct.\n")?;
        Ok(
            json!({"path":destination,"relativePath":name,"records":records.len(),"hasBrief":has_brief,
                "artifactIdentity":artifact_identity,"excludedRecordCount":excluded_records.len(),"excludedRecords":excluded_records}),
        )
    }
    /// `persist: false` returns the same record shape without saving it or adding
    /// it to history (for paging retained views).
    pub fn call(engine: &QuixiEngine, tool: &str, args: Value, persist: bool) -> Result<Value> {
        // UI, MCP and agent calls alike; local paths outside the project stay allowed here.
        reject_non_local_paths(&args)?;
        let _operation = engine.analysis.operation.lock();
        let id = Uuid::new_v4().to_string();
        let selected_target = engine.analysis.target.lock().clone();
        let process_before = engine.rea.process_id();
        let open_before = engine.analysis.open_rea_target(process_before);
        let explicit_target = args["path"].as_str().or_else(|| args["input_path"].as_str());
        let target_before = canonical_target(explicit_target.or(open_before.as_deref()).unwrap_or(&selected_target));
        let identity_before = capture_artifact_identity(&target_before);
        let uses_open_target = explicit_target.is_none() && open_before.is_some()
            && !matches!(tool, "open_binary" | "close_binary" | "binary_session");
        let bound_identity = engine.analysis.rea_identity.lock().as_ref()
            .filter(|(pid, path, _)| *pid == process_before && same_target(path, &target_before))
            .map(|(_, _, identity)| identity.clone());
        let stale_session = uses_open_target && bound_identity.as_ref().and_then(verified_sha256)
            .is_some_and(|bound| verified_sha256(&identity_before).as_ref() != Some(&bound));
        let result = if stale_session {
            Err(anyhow::anyhow!("The artifact bytes differ from the open REA session. Reopen the selected artifact before continuing."))
        } else {
            engine.rea.call(tool, args.clone())
        };
        let transport_failed = result.is_err() && !stale_session;
        let mut failed = result
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
        let provider_failed = failed;
        // Tools without a path act on REA's open binary, which may differ from the selection.
        let target = args["path"]
            .as_str()
            .or_else(|| args["input_path"].as_str())
            .or_else(|| evidence.pointer("/target/path").and_then(Value::as_str))
            .or_else(|| evidence.pointer("/result/path").and_then(Value::as_str))
            .or(open_before.as_deref())
            .unwrap_or(&selected_target);
        let target = canonical_target(target);
        let identity_after = capture_artifact_identity(&target);
        let process_id = engine.rea.process_id();
        let session_ended = process_before == 0 || process_before != process_id;
        let mut identity = if stale_session {
            json!({"status":"changed","kind":"file","boundSha256":bound_identity.as_ref().and_then(verified_sha256),
                "currentSha256":verified_sha256(&identity_before),"reason":"The artifact no longer matches the open REA session"})
        } else if !same_target(&target_before, &target) {
            json!({"status":"unverified","kind":"unknown","reason":"The reported artifact differs from the artifact identified before the call"})
        } else {
            checked_analysis_identity(&identity_before, &identity_after, process_before, process_id)
        };
        if uses_open_target && !stale_session && bound_identity.as_ref().and_then(verified_sha256).is_none()
            && identity["status"] == "verified" {
            identity = json!({"status":"unverified","kind":"file","observedSha256":verified_sha256(&identity),
                "reason":"This existing REA session was not opened with a verified artifact identity; reopen the artifact"});
        }
        identity = retained_result_identity(tool, identity);
        if identity["status"] == "changed" || session_ended { failed = true; }
        engine.analysis.observe_provider_result(tool, &evidence, failed, transport_failed || session_ended, process_id);
        if identity["status"] == "changed" { engine.analysis.provider_sessions.lock().clear(); }
        engine.analysis.observe_rea_target(tool, &args, &evidence, provider_failed || session_ended, process_id);
        if tool == "open_binary" {
            *engine.analysis.rea_identity.lock() = if !failed && verified_sha256(&identity).is_some() {
                Some((process_id, target.clone(), identity.clone()))
            } else { None };
        } else if tool == "close_binary" && !failed {
            *engine.analysis.rea_identity.lock() = None;
        }
        let mut record = json!({"provider":"rea","kind":"static","selectedTarget":selected_target,"id":id,"tool":tool,"arguments":args,"target":target,
            "created":chrono::Utc::now().to_rfc3339(),"failed":failed,"response":response,"artifactIdentity":identity});
        if record["artifactIdentity"]["status"] == "changed" {
            record["identityError"] = json!("Artifact identity changed; this response must not be used as evidence for the current build. Reopen the artifact.");
        }
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
            "settings" => {
                let patch = runtime_settings_patch(body)?;
                // configure can interrupt the provider; never queue it behind the
                // analysis operation lock held by an in-flight provider call.
                if patch.as_object().is_some_and(|object| !object.is_empty()) {
                    let response = engine.rea.configure(&patch)?;
                    if response["changed"] == true {
                        *engine.analysis.rea_target.lock() = None;
                        *engine.analysis.rea_identity.lock() = None;
                        engine.analysis.provider_sessions.lock().clear();
                    }
                    Ok(response)
                } else {
                    Ok(engine.rea.runtime_settings())
                }
            }
            "connect" => {
                let _operation = engine.analysis.operation.lock();
                let connected = engine.rea.connect(body["mode"].as_str())?;
                observe_session(
                    &connected["session"],
                    engine.rea.process_id(),
                    &mut engine.analysis.rea_target.lock(),
                );
                Ok(connected)
            }
            "disconnect" => {
                // REA's out-of-band cancellation must run before any waiting for
                // an analysis call. Calls reject a retired process's identity.
                engine.rea.disconnect()?;
                *engine.analysis.rea_target.lock() = None;
                *engine.analysis.rea_identity.lock() = None;
                engine.analysis.provider_sessions.lock().clear();
                Ok(json!({"connected":false}))
            }
            "inventory" => Ok(engine.analysis.inventory()),
            "select" => {
                let _operation = engine.analysis.operation.lock();
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
