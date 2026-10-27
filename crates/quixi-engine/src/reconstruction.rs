//! Persisted specification/oracle loop. Expectations are explicit, never invented by the runner.
use anyhow::{bail, Context, Result};
use quixi_platform::SafeFs;
use quixi_workspace::ShellHostEngine;
use serde::Deserialize;
use serde_json::{json, Value};
use std::{collections::HashSet, fs, path::Path};
use uuid::Uuid;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OracleFile {
    version: u32,
    cases: Vec<OracleCase>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct OracleCase {
    id: String,
    requirement: String,
    command: String,
    expectation_source: String,
    expected: Expected,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Expected {
    exit_code: i64,
    stdout: Option<String>,
    stderr: Option<String>,
}

pub fn inventory(root: &Path, target: &str) -> Value {
    let mut items = Vec::new();
    if let Ok(entries) = fs::read_dir(root) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            if !name.starts_with("quixi-reconstruction-") {
                continue;
            }
            let Ok(folder) = SafeFs::resolve_beneath(root, Path::new(&name)) else {
                continue;
            };
            let Ok(bytes) = fs::read(folder.join("manifest.json")) else {
                continue;
            };
            let Ok(value) = serde_json::from_slice::<Value>(&bytes) else {
                continue;
            };
            if value["target"].as_str() != Some(target) {
                continue;
            }
            items.push(json!({"path":name,"created":value["created"],"hasBrief":!value["brief"].is_null()}));
        }
    }
    items.sort_by(|a, b| b["created"].as_str().cmp(&a["created"].as_str()));
    json!({"dossiers":items})
}

pub fn run_oracles(root: &Path, config: &str) -> Result<Value> {
    let path = SafeFs::resolve_beneath(root, Path::new(config))?;
    if fs::metadata(&path)?.len() > 1024 * 1024 {
        bail!("Oracle configuration exceeds 1 MiB");
    }
    let bytes = fs::read(path)?;
    let specification: OracleFile = serde_json::from_slice(&bytes)
        .context("Invalid oracle-cases.json; see docs/RECONSTRUCTION.md for its schema")?;
    if specification.version != 1 {
        bail!("Unsupported oracle configuration version");
    }
    if specification.cases.len() > 12 {
        bail!("Use at most 12 cases per oracle batch");
    }
    let mut ids = HashSet::new();
    // Validate every case before executing any command.
    for case in &specification.cases {
        if case.id.trim().is_empty()
            || !ids.insert(&case.id)
            || case.requirement.trim().is_empty()
            || case.command.trim().is_empty()
            || case.command.len() > 16_000
            || case.expectation_source.trim().is_empty()
            || (case.expected.stdout.is_none() && case.expected.stderr.is_none())
        {
            bail!("Each oracle needs a unique ID, SPEC requirement, command, expectationSource and at least one exact expected output stream");
        }
    }
    let mut results = Vec::new();
    for case in specification.cases {
        let observed = ShellHostEngine::run_bash_command(root, &case.command)
            .unwrap_or_else(|e| json!({"error":e.to_string()}));
        let mut differences = Vec::new();
        if !observed["error"].is_null() {
            differences.push("execution error");
        }
        if observed["timedOut"] == true {
            differences.push("command timed out");
        }
        if observed["truncated"] == true {
            differences.push("output truncated");
        }
        if observed["exitCode"].as_i64() != Some(case.expected.exit_code) {
            differences.push("exit code differs");
        }
        if let Some(stdout) = &case.expected.stdout {
            if observed["stdout"].as_str() != Some(stdout) {
                differences.push("stdout differs");
            }
        }
        if let Some(stderr) = &case.expected.stderr {
            if observed["stderr"].as_str() != Some(stderr) {
                differences.push("stderr differs");
            }
        }
        results.push(json!({"id":case.id,"requirement":case.requirement,"command":case.command,
            "expectationSource":case.expectation_source,"expected":{"exitCode":case.expected.exit_code,"stdout":case.expected.stdout,"stderr":case.expected.stderr},
            "observed":observed,"passed":differences.is_empty(),"differences":differences}));
    }
    let passed = results.iter().filter(|r| r["passed"] == true).count();
    let status = if results.is_empty() {
        "unverified"
    } else if passed == results.len() {
        "passed"
    } else {
        "failed"
    };
    let relative = format!("quixi-oracle-runs/{}.json", Uuid::new_v4());
    let report = json!({"status":status,"created":chrono::Utc::now().to_rfc3339(),"config":config,
        "total":results.len(),"passed":passed,"failed":results.len()-passed,"results":results,"reportPath":relative,
        "coverage":"Only these declared cases were checked. Passing does not establish whole-application equivalence."});
    SafeFs::write_file_beneath(
        root,
        Path::new(&relative),
        &serde_json::to_vec_pretty(&report)?,
    )?;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn oracles_record_real_output_mismatches_and_empty_coverage() {
        let root = std::env::temp_dir().join(format!("quixi-oracle-{}", Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        fs::write(root.join("oracle.json"), br#"{"version":1,"cases":[]}"#).unwrap();
        assert_eq!(
            run_oracles(&root, "oracle.json").unwrap()["status"],
            "unverified"
        );
        let command = if cfg!(windows) {
            "[Console]::Write('actual')"
        } else {
            "printf actual"
        };
        let case = json!({"id":"one","requirement":"REQ-001","command":command,"expectationSource":"test fixture","expected":{"exitCode":0,"stdout":"expected"}});
        fs::write(
            root.join("oracle.json"),
            serde_json::to_vec(&json!({"version":1,"cases":[case]})).unwrap(),
        )
        .unwrap();
        let result = run_oracles(&root, "oracle.json").unwrap();
        assert_eq!(result["status"], "failed");
        assert_eq!(result["results"][0]["observed"]["stdout"], "actual");
        assert!(root.join(result["reportPath"].as_str().unwrap()).is_file());
        assert!(run_oracles(&root, "../oracle.json").is_err());
        let command = if cfg!(windows) {
            "[Console]::Write(('0' * 131073))"
        } else {
            "printf '%0131073d' 0"
        };
        let case = json!({"id":"long","requirement":"REQ-002","command":command,"expectationSource":"bounded-output fixture","expected":{"exitCode":0,"stdout":"0".repeat(131072)}});
        fs::write(
            root.join("oracle.json"),
            serde_json::to_vec(&json!({"version":1,"cases":[case]})).unwrap(),
        )
        .unwrap();
        let truncated = run_oracles(&root, "oracle.json").unwrap();
        assert_eq!(truncated["status"], "failed");
        assert_eq!(truncated["results"][0]["observed"]["truncated"], true);
        fs::remove_dir_all(root).unwrap();
    }
}
