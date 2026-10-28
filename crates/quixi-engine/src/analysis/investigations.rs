//! Immutable, project-scoped snapshots of a multi-file investigation.
//!
//! This is an evidence bundle, not an implementation specification or a claim
//! that separately captured files form an atomic application-wide snapshot.
use super::{is_non_local_path, record_identity, same_target, verified_sha256, AnalysisWorkspace};
use anyhow::{bail, Context, Result};
use quixi_platform::SafeFs;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::Read,
    path::{Component, Path, PathBuf},
};
use uuid::Uuid;

const MAX_SETS: usize = 32;
const MAX_ARTIFACTS: usize = 32;
const MAX_FILE_BYTES: u64 = 4 * 1024 * 1024 * 1024;
const MAX_ARTIFACT_BYTES: u64 = 8 * 1024 * 1024 * 1024;
const MAX_SET_BYTES: u64 = 2 * 1024 * 1024;
const MAX_RECORD_BYTES: u64 = 16 * 1024 * 1024;
const MAX_EVIDENCE_BYTES: u64 = 128 * 1024 * 1024;
const MAX_EXCLUSION_BYTES: usize = 16 * 1024 * 1024;
const MAX_RECORDS: usize = 4096;
const MAX_SCAN_RECORDS: usize = 10_000;
const MAX_SCAN_BYTES: u64 = 512 * 1024 * 1024;
const MAX_PATH_BYTES: usize = 32_768;

fn limits() -> Value {
    json!({"maxSets":MAX_SETS,"maxArtifacts":MAX_ARTIFACTS,"maxFileBytes":MAX_FILE_BYTES,
        "maxArtifactBytes":MAX_ARTIFACT_BYTES,"maxEvidenceRecords":MAX_RECORDS,
        "maxEvidenceBytes":MAX_EVIDENCE_BYTES,"maxRecordBytes":MAX_RECORD_BYTES,
        "maxScanRecords":MAX_SCAN_RECORDS,"maxScanBytes":MAX_SCAN_BYTES,
        "maxExcludedRecords":MAX_RECORDS,"maxExclusionBytes":MAX_EXCLUSION_BYTES})
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Artifact {
    target: String,
    artifact_identity: PinnedIdentity,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct PinnedIdentity {
    status: String,
    kind: String,
    algorithm: String,
    sha256: String,
    size: u64,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Investigation {
    version: u32,
    id: String,
    name: String,
    created: String,
    project: String,
    total_bytes: u64,
    artifacts: Vec<Artifact>,
}

// Unknown fields, including the entire provider response, are skipped by serde.
// We never build an unbounded response AST just to discover its target/hash.
#[derive(Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct IdentityFields {
    status: Option<String>,
    kind: Option<String>,
    algorithm: Option<String>,
    sha256: Option<String>,
    size: Option<u64>,
    verification: Option<String>,
    reason: Option<String>,
    source_record_id: Option<String>,
}

#[derive(Default, Deserialize, Serialize)]
struct ProvenanceFields {
    sha256: Option<String>,
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct EvidenceHeader {
    id: String,
    target: String,
    tool: Option<String>,
    provider: Option<String>,
    kind: Option<String>,
    created: Option<String>,
    failed: Option<bool>,
    artifact_identity: Option<IdentityFields>,
    provenance: Option<ProvenanceFields>,
}

struct Evidence {
    summary: Value,
    bytes: Vec<u8>,
}

#[derive(Default)]
struct Collected {
    records: Vec<Evidence>,
    excluded: Vec<Value>,
    scanned: usize,
    other_artifacts: usize,
}

fn path_text(path: &Path) -> String {
    path.to_string_lossy()
        .trim_start_matches("\\\\?\\")
        .to_owned()
}

fn validate_local_path(path: &Path) -> Result<()> {
    let text = path.to_string_lossy();
    if text.is_empty()
        || text.len() > MAX_PATH_BYTES
        || !path.is_absolute()
        || is_non_local_path(path)
        || text.chars().any(char::is_control)
    {
        bail!("Choose an absolute local file path; network, device and control-character paths are not permitted");
    }
    if path.components().any(|c| matches!(c, Component::ParentDir)) {
        bail!("Parent traversal is not permitted in investigation paths");
    }
    #[cfg(windows)]
    for component in path.components() {
        if let Component::Normal(part) = component {
            let part = part.to_string_lossy();
            let stem = part.split('.').next().unwrap_or("").to_ascii_uppercase();
            if part.contains(':')
                || part.ends_with(['.', ' '])
                || matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
                || (stem.len() == 4
                    && (stem.starts_with("COM") || stem.starts_with("LPT"))
                    && matches!(stem.as_bytes()[3], b'1'..=b'9'))
            {
                bail!("Windows device, alternate-stream and ambiguous path components are not permitted");
            }
        }
    }
    Ok(())
}

fn reject_reparse_components(path: &Path) -> Result<()> {
    validate_local_path(path)?;
    let mut current = PathBuf::new();
    for part in path.components() {
        current.push(part.as_os_str());
        // A verbatim drive prefix (\\\\?\\C:) reports is_absolute() on Windows,
        // but is not itself an inspectable directory until RootDir is appended.
        if matches!(part, Component::Prefix(_)) || !current.is_absolute() {
            continue;
        }
        let metadata = fs::symlink_metadata(&current).with_context(|| {
            format!(
                "Could not inspect investigation path component {}",
                current.display()
            )
        })?;
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if metadata.file_attributes() & 0x400 != 0 {
                bail!("Investigation paths cannot contain Windows reparse points");
            }
        }
        if metadata.file_type().is_symlink() {
            bail!("Investigation paths cannot contain symbolic links");
        }
    }
    Ok(())
}

fn canonical_project(root: &Path) -> Result<PathBuf> {
    reject_reparse_components(root)?;
    let root = fs::canonicalize(root)?;
    if !root.is_dir() {
        bail!("Open a destination project folder first");
    }
    Ok(root)
}

fn canonical_file(raw: &str) -> Result<String> {
    let path = Path::new(raw);
    reject_reparse_components(path)?;
    let path = fs::canonicalize(path)?;
    validate_local_path(&path)?;
    let metadata = fs::metadata(&path)?;
    if !metadata.is_file() {
        bail!("Investigation snapshots support files, not directories");
    }
    if metadata.len() > MAX_FILE_BYTES {
        bail!("An investigation artifact exceeds 4 GiB");
    }
    Ok(path_text(&path))
}

/// A bounded, streaming hash; growth after the metadata check cannot bypass the
/// read budget. The final export check opens the path again with a new handle.
#[cfg(test)]
fn capture(target: &str) -> Result<PinnedIdentity> {
    let mut budget = MAX_FILE_BYTES;
    capture_with_budget(target, &mut budget)
}

fn capture_with_budget(target: &str, remaining: &mut u64) -> Result<PinnedIdentity> {
    reject_reparse_components(Path::new(target))?;
    let mut file = fs::File::open(target)?;
    let before = file.metadata()?;
    if !before.is_file() {
        bail!("The pinned artifact is no longer a regular file");
    }
    if before.len() > MAX_FILE_BYTES {
        bail!("An investigation artifact exceeds 4 GiB");
    }
    if before.len() > *remaining {
        bail!("The investigation hash pass exceeds its remaining byte budget");
    }
    let maximum = MAX_FILE_BYTES.min(*remaining);
    let mut digest = Sha256::new();
    let mut read_bytes = 0u64;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let capacity = ((maximum.saturating_sub(read_bytes) + 1).min(buffer.len() as u64)) as usize;
        let count = file.read(&mut buffer[..capacity])?;
        if count == 0 {
            break;
        }
        read_bytes += count as u64;
        *remaining = remaining.saturating_sub(count as u64);
        if read_bytes > maximum {
            bail!("An investigation artifact grew beyond its hash byte budget");
        }
        digest.update(&buffer[..count]);
    }
    let after = file.metadata()?;
    if read_bytes != before.len()
        || after.len() != before.len()
        || before.modified().ok() != after.modified().ok()
    {
        bail!("The artifact changed while its identity was captured");
    }
    Ok(PinnedIdentity {
        status: "verified".into(),
        kind: "file".into(),
        algorithm: "sha256".into(),
        sha256: format!("{:x}", digest.finalize()),
        size: after.len(),
    })
}

fn read_bounded(path: &Path, maximum: u64) -> Result<Vec<u8>> {
    reject_reparse_components(path)?;
    let file = fs::File::open(path)?;
    if !file.metadata()?.is_file() || file.metadata()?.len() > maximum {
        bail!("Saved investigation data exceeds its file limit or is not a regular file");
    }
    let mut bytes = Vec::new();
    file.take(maximum + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > maximum {
        bail!("Saved investigation data grew beyond its file limit");
    }
    Ok(bytes)
}

fn valid_name(name: &str) -> bool {
    !name.trim().is_empty() && name.chars().count() <= 120 && !name.chars().any(char::is_control)
}

impl Investigation {
    fn validate(&self, project: &Path, id: &str) -> Result<()> {
        if self.version != 1
            || self.id != id
            || Uuid::parse_str(&self.id).is_err()
            || !valid_name(&self.name)
            || chrono::DateTime::parse_from_rfc3339(&self.created).is_err()
            || !same_target(&self.project, &path_text(project))
        {
            bail!("The saved investigation metadata is invalid or belongs to another project; it was preserved");
        }
        if self.artifacts.is_empty() || self.artifacts.len() > MAX_ARTIFACTS {
            bail!("A saved investigation must contain 1 to 32 artifacts");
        }
        let mut total = 0u64;
        for (i, artifact) in self.artifacts.iter().enumerate() {
            validate_local_path(Path::new(&artifact.target))?;
            if self.artifacts[..i]
                .iter()
                .any(|a| same_target(&a.target, &artifact.target))
            {
                bail!("The saved investigation contains a duplicate artifact path");
            }
            let identity = &artifact.artifact_identity;
            if identity.status != "verified"
                || identity.kind != "file"
                || identity.algorithm != "sha256"
                || identity.sha256.len() != 64
                || !identity.sha256.bytes().all(|c| c.is_ascii_hexdigit())
                || identity.size > MAX_FILE_BYTES
            {
                bail!("A saved investigation artifact has an invalid pinned identity");
            }
            total = total
                .checked_add(identity.size)
                .context("Artifact size overflow")?;
        }
        if total != self.total_bytes || total > MAX_ARTIFACT_BYTES {
            bail!("A saved investigation has an invalid size budget");
        }
        Ok(())
    }

    fn summary(&self) -> Value {
        json!({"id":self.id,"name":self.name,"created":self.created,
            "artifactCount":self.artifacts.len(),"totalBytes":self.total_bytes})
    }

    fn require_current(&self) -> Result<()> {
        let mut remaining = MAX_ARTIFACT_BYTES;
        for artifact in &self.artifacts {
            reject_reparse_components(Path::new(&artifact.target))?;
            if fs::metadata(&artifact.target)?.len() != artifact.artifact_identity.size {
                bail!("Pinned artifact changed size: {}. Capture a new investigation; the old snapshot is preserved.",artifact.target);
            }
            let current = capture_with_budget(&artifact.target, &mut remaining)
                .with_context(|| format!("Pinned artifact is unavailable: {}", artifact.target))?;
            if current.sha256 != artifact.artifact_identity.sha256.to_ascii_lowercase()
                || current.size != artifact.artifact_identity.size
            {
                bail!("Pinned artifact changed: {}. Capture a new investigation; the old snapshot is preserved.",artifact.target);
            }
        }
        Ok(())
    }

    fn check_destination(&self, root: &Path) -> Result<()> {
        for artifact in &self.artifacts {
            reject_reparse_components(Path::new(&artifact.target))?;
            let source = fs::canonicalize(&artifact.target)?;
            let folder = source.parent().context("Artifact has no parent folder")?;
            if root.starts_with(folder) || source.starts_with(root) {
                bail!("Choose a separate destination project outside every original artifact folder, with no original artifact inside it");
            }
        }
        Ok(())
    }
}

impl AnalysisWorkspace {
    fn investigation_dir(&self, root: &Path) -> Result<PathBuf> {
        reject_reparse_components(&self.dir)?;
        let text = path_text(root);
        let key = if cfg!(windows) {
            text.to_lowercase()
        } else {
            text
        };
        let relative =
            PathBuf::from("investigations").join(format!("{:x}", Sha256::digest(key.as_bytes())));
        SafeFs::resolve_beneath(&self.dir, &relative)
    }

    fn investigation_ids(&self, root: &Path) -> Result<Vec<String>> {
        let directory = self.investigation_dir(root)?;
        if !directory.exists() {
            return Ok(Vec::new());
        }
        reject_reparse_components(&directory)?;
        let mut ids = Vec::new();
        for entry in fs::read_dir(directory)? {
            let path = entry?.path();
            if path.extension().and_then(|v| v.to_str()) != Some("json") {
                continue;
            }
            let id = path
                .file_stem()
                .and_then(|v| v.to_str())
                .context("Invalid investigation filename")?;
            let id = Uuid::parse_str(id)
                .context("Invalid investigation filename")?
                .to_string();
            ids.push(id);
            if ids.len() > MAX_SETS {
                bail!("This project exceeds 32 saved investigations; its existing files were preserved");
            }
        }
        Ok(ids)
    }

    fn load_investigation(&self, root: &Path, id: &str) -> Result<Investigation> {
        let id = Uuid::parse_str(id)
            .context("Choose a valid investigation ID")?
            .to_string();
        let path = self.investigation_dir(root)?.join(format!("{id}.json"));
        let bytes = read_bounded(&path, MAX_SET_BYTES)
            .context("The investigation is unavailable in this project")?;
        let investigation: Investigation = serde_json::from_slice(&bytes)
            .context("Saved investigation metadata is invalid; its original file was preserved")?;
        investigation.validate(root, &id)?;
        Ok(investigation)
    }

    fn create_investigation(&self, root: &Path, body: &Value) -> Result<Value> {
        if self.investigation_ids(root)?.len() >= MAX_SETS {
            bail!("This project already has 32 investigations. Remove an unused snapshot before capturing another.");
        }
        let name = body["name"]
            .as_str()
            .context("Name the investigation")?
            .trim();
        if !valid_name(name) {
            bail!("Use an investigation name of 1 to 120 characters without control characters");
        }
        let targets = body["targets"]
            .as_array()
            .context("Choose artifact file paths")?;
        if targets.is_empty() || targets.len() > MAX_ARTIFACTS {
            bail!("Choose 1 to 32 artifact files");
        }
        let mut artifacts: Vec<Artifact> = Vec::new();
        let mut total = 0u64;
        // Check every file's size and every path before reading artifact bytes.
        let mut paths = Vec::new();
        for target in targets {
            let path = canonical_file(
                target
                    .as_str()
                    .context("Every artifact path must be text")?,
            )?;
            if paths.iter().any(|other: &String| same_target(other, &path)) {
                bail!("Choose each artifact path only once");
            }
            total = total
                .checked_add(fs::metadata(&path)?.len())
                .context("Artifact size overflow")?;
            if total > MAX_ARTIFACT_BYTES {
                bail!("Investigation artifacts exceed the 8 GiB total limit");
            }
            paths.push(path);
        }
        total = 0;
        let mut remaining = MAX_ARTIFACT_BYTES;
        for target in paths {
            let artifact_identity = capture_with_budget(&target, &mut remaining)?;
            total = total
                .checked_add(artifact_identity.size)
                .context("Artifact size overflow")?;
            if total > MAX_ARTIFACT_BYTES {
                bail!("Investigation artifacts exceed the 8 GiB total limit");
            }
            artifacts.push(Artifact {
                target,
                artifact_identity,
            });
        }
        let investigation = Investigation {
            version: 1,
            id: Uuid::new_v4().to_string(),
            name: name.to_owned(),
            created: chrono::Utc::now().to_rfc3339(),
            project: path_text(root),
            total_bytes: total,
            artifacts,
        };
        investigation.validate(root, &investigation.id)?;
        investigation.require_current()?;
        let bytes = serde_json::to_vec_pretty(&investigation)?;
        if bytes.len() as u64 > MAX_SET_BYTES {
            bail!("Investigation metadata exceeds 2 MiB");
        }
        let dir = self.investigation_dir(root)?;
        fs::create_dir_all(&dir)?;
        reject_reparse_components(&dir)?;
        SafeFs::write_file_beneath(
            &dir,
            Path::new(&format!("{}.json", investigation.id)),
            &bytes,
        )?;
        Ok(json!({"investigation":investigation}))
    }

    fn collect_investigation_evidence(
        &self,
        investigation: &Investigation,
        retain_bytes: bool,
    ) -> Result<Collected> {
        let mut collected = Collected::default();
        let mut scan_bytes = 0u64;
        let mut evidence_bytes = 0u64;
        let mut exclusion_bytes = 0usize;
        // Deliberately bypass the legacy summary index: stale summaries must not
        // decide exported identity, and inventory() has unbounded cache reads.
        for entry in fs::read_dir(&self.dir)? {
            let path = entry?.path();
            if path.extension().and_then(|v| v.to_str()) != Some("json") {
                continue;
            }
            let Some(id) = path
                .file_stem()
                .and_then(|v| v.to_str())
                .and_then(|s| Uuid::parse_str(s).ok())
            else {
                continue;
            };
            collected.scanned += 1;
            if collected.scanned > MAX_SCAN_RECORDS {
                bail!("Evidence history exceeds the 10,000-record investigation scan limit");
            }
            let remaining = MAX_SCAN_BYTES.saturating_sub(scan_bytes);
            if remaining == 0 {
                bail!("Evidence history exceeds the 512 MiB investigation scan limit");
            }
            let bytes =
                read_bounded(&path, MAX_RECORD_BYTES.min(remaining)).with_context(|| {
                    format!("Cannot scan saved evidence {id}; investigation scan limits apply")
                })?;
            scan_bytes += bytes.len() as u64;
            if scan_bytes > MAX_SCAN_BYTES {
                bail!("Evidence history exceeds the 512 MiB investigation scan limit");
            }
            let header: EvidenceHeader = serde_json::from_slice(&bytes).with_context(|| {
                format!("Saved evidence {id} is invalid; the original was preserved")
            })?;
            if Uuid::parse_str(&header.id).ok() != Some(id) {
                bail!("Saved evidence ID does not match its filename: {id}");
            }
            if header.target.len() > MAX_PATH_BYTES {
                bail!("Saved evidence target exceeds the path limit: {id}");
            }
            for field in [
                &header.tool,
                &header.provider,
                &header.kind,
                &header.created,
            ] {
                if field.as_ref().is_some_and(|s| s.len() > 1024) {
                    bail!("Saved evidence metadata exceeds its field limit: {id}");
                }
            }
            if let Some(identity) = &header.artifact_identity {
                for field in [
                    &identity.status,
                    &identity.kind,
                    &identity.algorithm,
                    &identity.sha256,
                    &identity.verification,
                    &identity.source_record_id,
                ] {
                    if field.as_ref().is_some_and(|s| s.len() > 256) {
                        bail!("Saved evidence identity exceeds its field limit: {id}");
                    }
                }
                if identity.reason.as_ref().is_some_and(|s| s.len() > 4096) {
                    bail!("Saved evidence identity reason exceeds its field limit: {id}");
                }
            }
            let Some(artifact) = investigation
                .artifacts
                .iter()
                .find(|a| same_target(&a.target, &header.target))
            else {
                collected.other_artifacts += 1;
                continue;
            };
            let mut summary = serde_json::to_value(&header)?;
            let identity = record_identity(&summary);
            summary.as_object_mut().unwrap().remove("provenance");
            summary["artifactIdentity"] = identity.clone();
            let reason = match verified_sha256(&identity) {
                Some(actual)
                    if actual == artifact.artifact_identity.sha256.to_ascii_lowercase() =>
                {
                    None
                }
                Some(_) => Some("different-artifact-version"),
                None if identity["status"] == "changed" => Some("artifact-changed-during-analysis"),
                None => Some("unverified-artifact-identity"),
            };
            if let Some(reason) = reason {
                let exclusion = json!({"id":header.id,"target":header.target,"tool":header.tool,
                    "reason":reason,"artifactIdentity":identity});
                exclusion_bytes += serde_json::to_vec(&exclusion)?.len();
                if collected.excluded.len() >= MAX_RECORDS || exclusion_bytes > MAX_EXCLUSION_BYTES
                {
                    bail!("Excluded evidence exceeds 4,096 records or 16 MiB of metadata; no partial bundle was exported");
                }
                collected.excluded.push(exclusion);
                continue;
            }
            evidence_bytes += bytes.len() as u64;
            if evidence_bytes > MAX_EVIDENCE_BYTES || collected.records.len() >= MAX_RECORDS {
                bail!("Matching evidence exceeds 4,096 records or 128 MiB. Use a narrower investigation or export individual evidence records.");
            }
            if header.kind.as_deref() == Some("model-suggestion") {
                summary["interpretation"] = json!("unverified-model-suggestion");
                summary["verified"] = json!(false);
            }
            collected.records.push(Evidence {
                summary,
                bytes: if retain_bytes { bytes } else { Vec::new() },
            });
        }
        collected
            .records
            .sort_by(|a, b| a.summary["id"].as_str().cmp(&b.summary["id"].as_str()));
        collected
            .excluded
            .sort_by(|a, b| a["id"].as_str().cmp(&b["id"].as_str()));
        Ok(collected)
    }

    fn inspect_investigation(&self, investigation: &Investigation) -> Result<Value> {
        let mut current = true;
        let mut remaining = MAX_ARTIFACT_BYTES;
        let evidence = self.collect_investigation_evidence(investigation, false)?;
        let artifacts: Vec<Value> = investigation.artifacts.iter().map(|artifact| {
            let observed = (|| -> Result<(&str,Value)> {
                reject_reparse_components(Path::new(&artifact.target))?;
                let metadata = fs::metadata(&artifact.target)?;
                if !metadata.is_file() { bail!("The pinned artifact is no longer a regular file"); }
                if metadata.len() != artifact.artifact_identity.size {
                    return Ok(("changed",json!({"status":"changed","kind":"file","size":metadata.len(),
                        "reason":"File size differs from the pinned snapshot; hashing was not necessary"})));
                }
                let identity = capture_with_budget(&artifact.target,&mut remaining)?;
                Ok((if identity.sha256 == artifact.artifact_identity.sha256.to_ascii_lowercase() {"current"} else {"changed"},json!(identity)))
            })();
            let (status,identity) = match observed {
                Ok(value) => value,
                Err(error) => {
                    let missing = error.chain().filter_map(|e|e.downcast_ref::<std::io::Error>())
                        .any(|e|e.kind()==std::io::ErrorKind::NotFound);
                    (if missing {"missing"} else {"unavailable"},json!({"status":"unverified","reason":error.to_string()}))
                }
            };
            if status != "current" {current=false;}
            let matching: Vec<&Evidence> = evidence.records.iter().filter(|r|same_target(r.summary["target"].as_str().unwrap_or(""),&artifact.target)).collect();
            json!({"target":artifact.target,"pinnedIdentity":artifact.artifact_identity,"currentIdentity":identity,"status":status,
                "matchingRecordCount":matching.len(),"excludedRecordCount":evidence.excluded.iter().filter(|r|same_target(r["target"].as_str().unwrap_or(""),&artifact.target)).count(),
                "failedRecordCount":matching.iter().filter(|r|r.summary["failed"]==true).count(),
                "modelSuggestionCount":matching.iter().filter(|r|r.summary["kind"]=="model-suggestion").count()})
        }).collect();
        Ok(
            json!({"investigation":investigation,"artifacts":artifacts,"allArtifactsCurrent":current,
            "readyToExport":current&&!evidence.records.is_empty(),"totalMatchingRecordCount":evidence.records.len(),
            "checkedAt":chrono::Utc::now().to_rfc3339(),"limits":limits()}),
        )
    }

    fn export_investigation<F: FnOnce()>(
        &self,
        root: &Path,
        investigation: &Investigation,
        after_staging: F,
    ) -> Result<Value> {
        investigation.require_current()?;
        investigation.check_destination(root)?;
        let evidence = self.collect_investigation_evidence(investigation, true)?;
        if evidence.records.is_empty() {
            bail!("No saved evidence matches the pinned artifacts. Analyse at least one captured artifact before exporting.");
        }
        let export_id = Uuid::new_v4();
        let name = format!("rea-investigation-{export_id}");
        let staging_name = format!(".{name}.partial");
        let staging = SafeFs::resolve_beneath(root, Path::new(&staging_name))?;
        fs::create_dir(&staging)
            .context("Could not create a private staging directory for this export")?;
        let result = (|| -> Result<Value> {
            let mut records = Vec::new();
            for record in &evidence.records {
                let id = record.summary["id"]
                    .as_str()
                    .context("Saved evidence has no ID")?;
                let file = format!("evidence/{id}.json");
                SafeFs::write_file_beneath(&staging, Path::new(&file), &record.bytes)?;
                let mut summary = record.summary.clone();
                summary["file"] = json!(file);
                summary["sha256"] = json!(format!("{:x}", Sha256::digest(&record.bytes)));
                summary["bytes"] = json!(record.bytes.len());
                records.push(summary);
            }
            let artifacts: Vec<Value> = investigation.artifacts.iter().map(|artifact| {
                let matching: Vec<&Value> = records.iter().filter(|r|same_target(r["target"].as_str().unwrap_or(""),&artifact.target)).collect();
                let count = matching.len();
                json!({"target":artifact.target,"artifactIdentity":artifact.artifact_identity,"recordCount":count,
                    "failedRecordCount":matching.iter().filter(|r|r["failed"]==true).count(),
                    "modelSuggestionCount":matching.iter().filter(|r|r["kind"]=="model-suggestion").count(),
                    "evidenceCoverage":if count==0 {"no-matching-saved-evidence"} else {"saved-observations-only"}})
            }).collect();
            let manifest = json!({"format":"rea-investigation-v1","created":chrono::Utc::now().to_rfc3339(),
            "investigation":investigation,"artifacts":artifacts,"records":records,"excludedRecords":evidence.excluded,
            "scannedRecordCount":evidence.scanned,"otherArtifactRecordCount":evidence.other_artifacts,
            "limits":limits(),"limitations":[
                "Independent per-file hashes do not establish an atomic whole-application snapshot.",
                "Only saved observations matching each path and pinned SHA-256 are included; this is not analysis coverage of every function.",
                "Failed observations remain failures and model suggestions remain unverified.",
                "Hash integrity does not authenticate a provider's conclusions or establish runtime equivalence.",
                "Original artifacts are not copied or executed. Live retained references can expire.",
                "This is an investigation evidence bundle, not a reviewed specification, runnable reconstruction or oracle result."
            ]});
            SafeFs::write_file_beneath(
                &staging,
                Path::new("manifest.json"),
                &serde_json::to_vec_pretty(&manifest)?,
            )?;
            SafeFs::write_file_beneath(&staging,Path::new("README.md"),b"# Investigation evidence bundle\n\nReview manifest.json for each artifact's pinned SHA-256, available observations, excluded records and explicit coverage gaps. evidence/ contains the original saved response bytes; their content hashes are in the manifest. Failed observations remain failures. Model suggestions are unverified, even when their source artifact identity is known.\n\nThis bundle does not contain or run the original artifacts. It is not a reconstruction specification or a claim of application equivalence. Use a separately reviewed specification and independent behavioral tests for implementation work. Capture a new investigation when artifact bytes change; the earlier snapshot and evidence remain available.\n")?;
            after_staging();
            investigation.require_current()?;
            reject_reparse_components(&staging)?;
            let destination = SafeFs::resolve_beneath(root, Path::new(&name))?;
            if destination.exists() {
                bail!("The new export destination unexpectedly exists; it was not overwritten");
            }
            fs::rename(&staging, &destination)
                .context("Could not promote the completed investigation bundle")?;
            Ok(
                json!({"id":investigation.id,"name":investigation.name,"path":destination,"relativePath":name,
                "artifactCount":investigation.artifacts.len(),"recordCount":evidence.records.len(),"excludedRecordCount":evidence.excluded.len()}),
            )
        })();
        if result.is_err() {
            // Only this newly created, uniquely named staging path is ours.
            // Never touch an earlier or final bundle on an error.
            if reject_reparse_components(&staging).is_ok() {
                let _ = fs::remove_dir_all(&staging);
            }
        }
        result
    }

    pub fn handle_investigation(&self, root: &Path, action: &str, body: &Value) -> Result<Value> {
        let _guard = self
            .investigation_lock
            .try_lock()
            .context("Another investigation operation is running; retry after it finishes")?;
        let root = canonical_project(root)?;
        match action {
            "list" => {
                let mut sets = self
                    .investigation_ids(&root)?
                    .iter()
                    .map(|id| self.load_investigation(&root, id))
                    .collect::<Result<Vec<_>>>()?;
                sets.sort_by(|a, b| b.created.cmp(&a.created));
                Ok(
                    json!({"investigations":sets.iter().map(Investigation::summary).collect::<Vec<_>>(),"limits":limits()}),
                )
            }
            "create" => self.create_investigation(&root, body),
            "inspect" | "export" => {
                let investigation = self.load_investigation(
                    &root,
                    body["id"].as_str().context("Choose an investigation")?,
                )?;
                if action == "inspect" {
                    self.inspect_investigation(&investigation)
                } else {
                    self.export_investigation(&root, &investigation, || {})
                }
            }
            "delete" => {
                let id = Uuid::parse_str(body["id"].as_str().context("Choose an investigation")?)
                    .context("Invalid investigation ID")?
                    .to_string();
                let directory = self.investigation_dir(&root)?;
                let file = SafeFs::resolve_beneath(&directory, Path::new(&format!("{id}.json")))?;
                reject_reparse_components(&file)?;
                fs::remove_file(file)
                    .context("Could not remove this project's investigation snapshot")?;
                Ok(json!({"deleted":id}))
            }
            _ => bail!("Unknown investigation action"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Fixture {
        base: PathBuf,
        data: PathBuf,
        project: PathBuf,
        other: PathBuf,
        first: String,
        second: String,
    }
    impl Fixture {
        fn new() -> Self {
            let base =
                std::env::temp_dir().join(format!("rea-investigation-test-{}", Uuid::new_v4()));
            for part in [
                "data",
                "destination",
                "other-destination",
                "original-a",
                "original-b",
            ] {
                fs::create_dir_all(base.join(part)).unwrap();
            }
            // Production targets are canonical before evidence is saved. TEMP may use
            // an 8.3 alias on Windows CI, so raw fixture spellings are not equivalent.
            let base = fs::canonicalize(base).unwrap();
            let first = base.join("original-a/module-a.bin");
            let second = base.join("original-b/module-b.bin");
            fs::write(&first, b"source-known fixture A").unwrap();
            fs::write(&second, b"source-known fixture B").unwrap();
            Self {
                data: base.join("data"),
                project: base.join("destination"),
                other: base.join("other-destination"),
                first: path_text(&first),
                second: path_text(&second),
                base,
            }
        }
        fn create(&self, analysis: &AnalysisWorkspace) -> String {
            analysis
                .handle_investigation(
                    &self.project,
                    "create",
                    &json!({"name":"Two modules","targets":[self.first,self.second]}),
                )
                .unwrap()["investigation"]["id"]
                .as_str()
                .unwrap()
                .to_owned()
        }
        fn record(
            &self,
            analysis: &AnalysisWorkspace,
            target: &str,
            kind: &str,
            failed: bool,
        ) -> Value {
            let record = json!({"id":Uuid::new_v4().to_string(),"target":target,"tool":"unit_fixture",
                "provider":"unit-fixture","kind":kind,"created":chrono::Utc::now().to_rfc3339(),"failed":failed,
                "artifactIdentity":capture(target).unwrap(),"response":{"verified":false,"fixture":"not a provider integration"}});
            analysis.save_record(&record).unwrap();
            record
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.base);
        }
    }

    #[test]
    fn snapshots_persist_and_are_scoped_by_project_not_merely_by_uuid() {
        let f = Fixture::new();
        let analysis = AnalysisWorkspace::new(&f.data);
        // Identical bytes at different paths remain distinct modules.
        fs::copy(&f.first, &f.second).unwrap();
        let id = f.create(&analysis);
        assert!(analysis
            .handle_investigation(
                &f.project,
                "create",
                &json!({"name":"duplicate","targets":[f.first,f.first.replace('\\',"/")]})
            )
            .is_err());
        drop(analysis);
        let analysis = AnalysisWorkspace::new(&f.data);
        let listed = analysis
            .handle_investigation(&f.project, "list", &json!({}))
            .unwrap();
        assert_eq!(listed["investigations"][0]["artifactCount"], 2);
        let inspected = analysis
            .handle_investigation(&f.project, "inspect", &json!({"id":id}))
            .unwrap();
        assert_eq!(inspected["allArtifactsCurrent"], true);
        assert_eq!(inspected["readyToExport"], false); // No fabricated analysis coverage.
        assert!(analysis
            .handle_investigation(&f.other, "inspect", &json!({"id":id}))
            .is_err());
        assert!(analysis
            .handle_investigation(&f.other, "delete", &json!({"id":id}))
            .is_err());
        assert_eq!(
            analysis
                .handle_investigation(&f.project, "list", &json!({}))
                .unwrap()["investigations"]
                .as_array()
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn changed_missing_and_overlapping_artifacts_cannot_be_exported() {
        let f = Fixture::new();
        let analysis = AnalysisWorkspace::new(&f.data);
        let id = f.create(&analysis);
        f.record(&analysis, &f.first, "static", false);
        fs::write(&f.first, b"a different build").unwrap();
        let result = analysis
            .handle_investigation(&f.project, "inspect", &json!({"id":id}))
            .unwrap();
        assert_eq!(result["artifacts"][0]["status"], "changed");
        assert_eq!(result["readyToExport"], false);
        assert!(analysis
            .handle_investigation(&f.project, "export", &json!({"id":id}))
            .is_err());
        fs::write(&f.first, b"source-known fixture A").unwrap();
        fs::remove_file(&f.second).unwrap();
        let result = analysis
            .handle_investigation(&f.project, "inspect", &json!({"id":id}))
            .unwrap();
        assert_eq!(result["artifacts"][1]["status"], "missing");
        assert!(analysis
            .handle_investigation(&f.project, "export", &json!({"id":id}))
            .is_err());
        assert_eq!(fs::read_dir(&f.project).unwrap().count(), 0);
        fs::write(&f.second, b"source-known fixture B").unwrap();
        let saved = analysis
            .load_investigation(&canonical_project(&f.project).unwrap(), &id)
            .unwrap();
        assert!(saved
            .check_destination(&canonical_project(Path::new(&f.first).parent().unwrap()).unwrap())
            .is_err());
        assert!(saved
            .check_destination(&canonical_project(&f.base).unwrap())
            .is_err());
    }

    #[test]
    fn export_rechecks_raw_identity_and_preserves_failures_suggestions_and_exclusions() {
        let f = Fixture::new();
        let analysis = AnalysisWorkspace::new(&f.data);
        let id = f.create(&analysis);
        let failed = f.record(&analysis, &f.first, "static", true);
        let suggestion = f.record(&analysis, &f.first, "model-suggestion", false);
        let mut stale = f.record(&analysis, &f.first, "static", false);
        stale["artifactIdentity"]["sha256"] = json!("a".repeat(64));
        analysis.save_record(&stale).unwrap();
        let mut legacy = f.record(&analysis, &f.first, "static", false);
        legacy.as_object_mut().unwrap().remove("artifactIdentity");
        analysis.save_record(&legacy).unwrap();
        let unrelated = f.base.join("unrelated.bin");
        fs::write(&unrelated, b"unrelated").unwrap();
        let unrelated = f.record(&analysis, &path_text(&unrelated), "static", false);
        // Corrupt summary metadata cannot relabel raw evidence or pull in another target.
        fs::write(analysis.dir.join("index.json"),serde_json::to_vec(&json!({
            (failed["id"].as_str().unwrap()):{"id":failed["id"],"provider":"spoofed","target":f.first},
            (unrelated["id"].as_str().unwrap()):{"id":unrelated["id"],"target":f.first,"artifactIdentity":capture(&f.first).unwrap()}
        })).unwrap()).unwrap();
        let exported = analysis
            .handle_investigation(&f.project, "export", &json!({"id":id}))
            .unwrap();
        assert_eq!(exported["recordCount"], 2);
        assert_eq!(exported["excludedRecordCount"], 2);
        let root = Path::new(exported["path"].as_str().unwrap());
        let manifest: Value =
            serde_json::from_slice(&fs::read(root.join("manifest.json")).unwrap()).unwrap();
        assert_eq!(
            manifest["artifacts"][1]["evidenceCoverage"],
            "no-matching-saved-evidence"
        );
        assert_eq!(manifest["artifacts"][0]["failedRecordCount"], 1);
        assert_eq!(manifest["artifacts"][0]["modelSuggestionCount"], 1);
        for row in manifest["records"].as_array().unwrap() {
            assert_eq!(row["provider"], "unit-fixture");
            let bytes = fs::read(root.join(row["file"].as_str().unwrap())).unwrap();
            assert_eq!(row["sha256"], format!("{:x}", Sha256::digest(&bytes)));
            assert_eq!(
                bytes,
                fs::read(analysis.record_path(row["id"].as_str().unwrap()).unwrap()).unwrap()
            );
            if row["id"] == failed["id"] {
                assert_eq!(row["failed"], true);
            }
            if row["id"] == suggestion["id"] {
                assert_eq!(row["verified"], false);
                assert_eq!(row["interpretation"], "unverified-model-suggestion");
            }
        }
        assert_eq!(manifest["otherArtifactRecordCount"], 1);
        assert!(analysis.read_record(stale["id"].as_str().unwrap()).is_ok());
        assert!(analysis.read_record(legacy["id"].as_str().unwrap()).is_ok());
    }

    #[test]
    fn change_after_staging_removes_only_the_new_partial_bundle() {
        let f = Fixture::new();
        let analysis = AnalysisWorkspace::new(&f.data);
        let id = f.create(&analysis);
        f.record(&analysis, &f.first, "static", false);
        let root = canonical_project(&f.project).unwrap();
        let saved = analysis.load_investigation(&root, &id).unwrap();
        fs::create_dir(f.project.join("rea-investigation-existing")).unwrap();
        fs::write(
            f.project.join("rea-investigation-existing/keep.txt"),
            b"keep",
        )
        .unwrap();
        let result = analysis.export_investigation(&root, &saved, || {
            fs::write(&f.second, b"changed during staging").unwrap();
        });
        assert!(result.is_err());
        assert_eq!(fs::read_dir(&f.project).unwrap().count(), 1);
        assert_eq!(
            fs::read(f.project.join("rea-investigation-existing/keep.txt")).unwrap(),
            b"keep"
        );
    }

    #[test]
    fn corrupt_snapshots_and_oversized_or_misidentified_records_fail_without_promotion() {
        let f = Fixture::new();
        let analysis = AnalysisWorkspace::new(&f.data);
        let id = f.create(&analysis);
        let root = canonical_project(&f.project).unwrap();
        let path = analysis
            .investigation_dir(&root)
            .unwrap()
            .join(format!("{id}.json"));
        let original = fs::read(&path).unwrap();
        fs::write(&path, b"invalid json").unwrap();
        assert!(analysis
            .handle_investigation(&f.project, "inspect", &json!({"id":id}))
            .is_err());
        assert_eq!(fs::read(&path).unwrap(), b"invalid json");
        fs::write(&path, &original).unwrap();
        let mut set: Value = serde_json::from_slice(&original).unwrap();
        set["artifacts"][0]["artifactIdentity"]["size"] = json!(MAX_FILE_BYTES + 1);
        fs::write(&path, serde_json::to_vec(&set).unwrap()).unwrap();
        assert!(analysis
            .handle_investigation(&f.project, "inspect", &json!({"id":id}))
            .is_err());
        fs::write(&path, &original).unwrap();
        let large = analysis.dir.join(format!("{}.json", Uuid::new_v4()));
        fs::File::create(&large)
            .unwrap()
            .set_len(MAX_RECORD_BYTES + 1)
            .unwrap();
        assert!(analysis
            .handle_investigation(&f.project, "export", &json!({"id":id}))
            .is_err());
        fs::remove_file(large).unwrap();
        let mut record = f.record(&analysis, &f.first, "static", false);
        let record_path = analysis
            .record_path(record["id"].as_str().unwrap())
            .unwrap();
        record["id"] = json!(Uuid::new_v4().to_string());
        fs::write(&record_path, serde_json::to_vec(&record).unwrap()).unwrap();
        assert!(analysis
            .handle_investigation(&f.project, "export", &json!({"id":id}))
            .is_err());
        assert_eq!(fs::read_dir(&f.project).unwrap().count(), 0);
    }

    #[test]
    fn hash_pass_budget_and_grown_file_inspection_are_bounded() {
        let f = Fixture::new();
        let mut too_small = 4;
        assert!(capture_with_budget(&f.first, &mut too_small).is_err());
        assert_eq!(too_small, 4); // Metadata refused the read before spending its budget.
        let bytes = fs::metadata(&f.first).unwrap().len();
        let mut remaining = bytes;
        assert!(capture_with_budget(&f.first, &mut remaining).is_ok());
        assert_eq!(remaining, 0);
        assert!(capture_with_budget(&f.second, &mut remaining).is_err());
        let analysis = AnalysisWorkspace::new(&f.data);
        let id = f.create(&analysis);
        fs::write(&f.first, vec![0u8; 4096]).unwrap();
        let inspected = analysis
            .handle_investigation(&f.project, "inspect", &json!({"id":id}))
            .unwrap();
        assert_eq!(inspected["artifacts"][0]["status"], "changed");
        assert!(inspected["artifacts"][0]["currentIdentity"]["sha256"].is_null());
        assert_eq!(inspected["artifacts"][1]["status"], "current");
    }

    #[cfg(windows)]
    #[test]
    fn windows_device_stream_and_network_paths_fail_before_file_access() {
        for path in [
            r"C:\safe\CON",
            r"C:\safe\lpt1.txt",
            r"C:\safe\app.exe:payload",
            r"C:\safe\file.",
            r"\\attacker.invalid\share\module.exe",
            r"\\.\pipe\investigation",
            r"\\?\UNC\attacker.invalid\share\x",
        ] {
            assert!(validate_local_path(Path::new(path)).is_err(), "{path}");
        }
    }

    #[cfg(windows)]
    #[test]
    fn canonical_verbatim_drive_paths_check_the_root_not_the_bare_prefix() {
        let f = Fixture::new();
        let canonical = fs::canonicalize(&f.project).unwrap();
        assert!(
            matches!(canonical.components().next(),Some(Component::Prefix(prefix)) if matches!(prefix.kind(),std::path::Prefix::VerbatimDisk(_)))
        );
        reject_reparse_components(&canonical).unwrap();
        reject_reparse_components(&fs::canonicalize(&f.first).unwrap()).unwrap();
    }
}
