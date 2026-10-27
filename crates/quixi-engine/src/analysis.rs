//! User-selected artifacts, durable REA results, and the agent's analysis tools.
use crate::QuixiEngine;
use anyhow::{bail, Context, Result};
use parking_lot::Mutex;
use quixi_platform::ComputerUse;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
    sync::Arc,
};
use uuid::Uuid;

pub struct AnalysisWorkspace {
    dir: PathBuf,
    pub target: Mutex<String>,
    pub provider_sessions: Mutex<HashMap<String,u32>>,
}

#[cfg(test)]
mod tests {
    use super::*;
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
    pub fn new(data_dir: &Path) -> Self {
        let dir = data_dir.join("playground/analysis");
        let _ = fs::create_dir_all(&dir);
        let target = fs::read_to_string(dir.join("target.txt")).unwrap_or_default();
        Self {
            dir,
            target: Mutex::new(target),
            provider_sessions: Mutex::new(HashMap::new()),
        }
    }
    pub fn inventory(&self) -> Value {
        let mut records = vec![];
        if let Ok(entries) = fs::read_dir(&self.dir) {
            for entry in entries.flatten() {
                if entry.path().extension().and_then(|s| s.to_str()) != Some("json") {
                    continue;
                }
                if let Ok(bytes) = fs::read(entry.path()) {
                    if let Ok(v) = serde_json::from_slice::<Value>(&bytes) {
                        records.push(json!({"id":v["id"],"tool":v["tool"],"provider":v["provider"],"kind":v["kind"],"created":v["created"],"target":v["target"],"failed":v["failed"]}));
                    }
                }
            }
        }
        records.sort_by(|a, b| b["created"].as_str().cmp(&a["created"].as_str()));
        let target = self.target.lock().clone();
        json!({"targetIsDirectory":Path::new(&target).is_dir(),"target":target,"records":records})
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
            "arguments":arguments,"target":target,"selectedTarget":*self.target.lock(),
            "created":chrono::Utc::now().to_rfc3339(),"failed":response["isError"]==true,
            "response":response,"provenance":provenance});
        fs::write(self.record_path(&id)?, serde_json::to_vec_pretty(&record)?)
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
                .map(|p| {
                    if cfg!(windows) {
                        p.eq_ignore_ascii_case(&target)
                    } else {
                        p == target
                    }
                })
                .unwrap_or(false);
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
    pub fn call(engine: &QuixiEngine, tool: &str, args: Value) -> Result<Value> {
        let id = Uuid::new_v4().to_string();
        let selected_target = engine.analysis.target.lock().clone();
        let result = engine.rea.call(tool, args.clone());
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
        if !failed {
            if tool=="close_binary" { engine.analysis.provider_sessions.lock().clear(); }
            if tool=="open_binary" {
                if let Some(provider)=args["provider_id"].as_str().filter(|p|matches!(*p,"ghidra"|"ida")) {
                    let mut sessions=engine.analysis.provider_sessions.lock();
                    sessions.remove("ghidra");sessions.remove("ida");
                    sessions.insert(provider.into(),engine.rea.process_id());
                }
            }
            if tool=="inspect_android_package" { engine.analysis.provider_sessions.lock().insert("jadx-mcp".into(),engine.rea.process_id()); }
        }
        let target = args["path"]
            .as_str()
            .or_else(|| args["input_path"].as_str())
            .or_else(|| evidence.pointer("/target/path").and_then(Value::as_str))
            .or_else(|| evidence.pointer("/result/path").and_then(Value::as_str))
            .unwrap_or(&selected_target);
        let record = json!({"provider":"rea","kind":"static","selectedTarget":selected_target,"id":id,"tool":tool,"arguments":args,"target":target,
            "created":chrono::Utc::now().to_rfc3339(),"failed":failed,"response":response});
        fs::write(
            engine.analysis.record_path(&id)?,
            serde_json::to_vec_pretty(&record)?,
        )
        .context("Could not save the analysis result")?;
        Ok(record)
    }
    pub fn handle(engine: &Arc<QuixiEngine>, route: &str, body: &Value) -> Result<Value> {
        match route {
            "workflow" => engine.rea.workflow(body),
            "connect" => engine.rea.connect(body["mode"].as_str()),
            "disconnect" => {
                engine.rea.disconnect()?;
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
        // A model may inspect the selected artifact or its current project, not choose
        // an unrelated installation. Runtime/patch/extraction tools are not in this set.
        fn validate_paths(value: &mut Value, root: &Path, selected: &Path) -> Result<()> {
            match value {
                Value::Object(map) => {
                    for (key, value) in map {
                        let is_path =
                            key == "path" || key.ends_with("_path") || key.ends_with("_directory");
                        if is_path && value.is_string() {
                            let raw = value.as_str().unwrap();
                            let candidate = if Path::new(raw).is_absolute() {
                                fs::canonicalize(raw)?
                            } else {
                                quixi_platform::SafeFs::resolve_beneath(root, Path::new(raw))?
                            };
                            let permitted = candidate.starts_with(root)
                                || candidate == selected
                                || (selected.is_dir() && candidate.starts_with(selected));
                            if !permitted {
                                bail!(
                                    "Select this artifact in the REA workspace before analysing it"
                                );
                            }
                            *value =
                                json!(candidate.to_string_lossy().trim_start_matches("\\\\?\\"));
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
        validate_paths(
            &mut args,
            &fs::canonicalize(root)?,
            &fs::canonicalize(&selected).unwrap_or_default(),
        )?;
        Self::call(engine, tool, args)
    }
}
