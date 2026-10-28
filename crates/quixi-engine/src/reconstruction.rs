//! Persisted specification/oracle loop. Expectations are explicit, never invented by the runner.
use anyhow::{bail, Context, Result};
use quixi_platform::SafeFs;
use quixi_workspace::{ShellHostEngine, COMMAND_TIMEOUT};
use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{collections::HashSet, fs, path::Path, process::Command};
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
    /// PowerShell command run in the project root (legacy form).
    #[serde(default)]
    command: Option<String>,
    /// Program (relative to the project or absolute) and its arguments, run directly.
    #[serde(default)]
    argv: Option<Vec<String>>,
    /// Standard input for an `argv` case.
    #[serde(default)]
    stdin: Option<String>,
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

/// Messages a shell prints when the program it was asked to run does not exist.
const NOT_FOUND_MARKERS: [&str; 3] = [
    "CommandNotFoundException",
    "is not recognized as the name of",
    "is not recognized as an internal or external command",
];

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

pub fn sha256_hex(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

/// Read an oracle configuration contained in the project.
pub fn read_config(root: &Path, config: &str) -> Result<Vec<u8>> {
    let path = SafeFs::resolve_beneath(root, Path::new(config))?;
    let metadata = fs::metadata(&path)
        .with_context(|| format!("Cannot read oracle configuration {config}"))?;
    if metadata.len() > 1024 * 1024 {
        bail!("Oracle configuration exceeds 1 MiB");
    }
    Ok(fs::read(path)?)
}

fn parse(bytes: &[u8]) -> Result<OracleFile> {
    let specification: OracleFile = serde_json::from_slice(bytes)
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
            || case.expectation_source.trim().is_empty()
            || (case.expected.stdout.is_none() && case.expected.stderr.is_none())
        {
            bail!("Each oracle needs a unique ID, SPEC requirement, command or argv, expectationSource and at least one exact expected output stream");
        }
        match (&case.command, &case.argv) {
            (Some(command), None) => {
                if command.trim().is_empty() || command.len() > 16_000 {
                    bail!("Oracle {}: command must be 1 to 16000 characters", case.id);
                }
                if case.stdin.is_some() {
                    bail!("Oracle {}: stdin is supported only with argv", case.id);
                }
            }
            (None, Some(argv)) => {
                if argv.is_empty()
                    || argv.len() > 64
                    || argv[0].trim().is_empty()
                    || argv.iter().any(|a| a.len() > 8192 || a.contains('\0'))
                {
                    bail!("Oracle {}: argv needs a program path followed by at most 63 arguments without NUL characters", case.id);
                }
                if case.stdin.as_ref().is_some_and(|s| s.len() > 1024 * 1024) {
                    bail!("Oracle {}: stdin exceeds 1 MiB", case.id);
                }
            }
            _ => bail!("Oracle {}: declare exactly one of command or argv", case.id),
        }
    }
    Ok(specification)
}

fn describe(case: &OracleCase) -> Value {
    let mut value = json!({"id":case.id,"name":case.id,"requirement":case.requirement,
        "expectationSource":case.expectation_source,
        "expected":{"exitCode":case.expected.exit_code,"stdout":case.expected.stdout,"stderr":case.expected.stderr}});
    if let Some(command) = &case.command {
        value["command"] = json!(command);
    }
    if let Some(argv) = &case.argv {
        value["argv"] = json!(argv);
    }
    if let Some(stdin) = &case.stdin {
        value["stdin"] = json!(stdin);
    }
    value
}

/// The exact cases a user reviews before approving a configuration's hash.
pub fn preview(root: &Path, config: &str) -> Result<Value> {
    let bytes = read_config(root, config)?;
    let specification = parse(&bytes)?;
    Ok(json!({"config":config,"sha256":sha256_hex(&bytes),
        "cases":specification.cases.iter().map(describe).collect::<Vec<_>>()}))
}

fn run_argv(root: &Path, argv: &[String], stdin: Option<&str>) -> Result<quixi_workspace::ProcessOutcome> {
    let program = Path::new(&argv[0]);
    let program = if program.is_absolute() {
        program.to_path_buf()
    } else {
        SafeFs::resolve_beneath(root, program)?
    };
    if !program.is_file() {
        bail!("Program not found: {}", argv[0]);
    }
    let mut command = Command::new(&program);
    command
        .args(&argv[1..])
        .current_dir(root)
        .envs(ShellHostEngine::resolve_user_shell_env());
    ShellHostEngine::run_process(
        command,
        stdin.map(|s| s.as_bytes().to_vec()),
        COMMAND_TIMEOUT,
        &|| false,
    )
}

/// Run an approved oracle configuration. The bytes actually executed must hash to
/// `approved_sha256`, so a configuration edited after approval is refused.
pub fn run_oracles(
    root: &Path,
    config: &str,
    approved_sha256: &str,
    cancelled: &dyn Fn() -> bool,
) -> Result<Value> {
    let bytes = read_config(root, config)?;
    let sha256 = sha256_hex(&bytes);
    if sha256 != approved_sha256 {
        bail!("Oracle configuration {config} changed since it was approved. Review and approve it again before running.");
    }
    let specification = parse(&bytes)?;
    let mut results = Vec::new();
    for case in specification.cases {
        let mut differences = Vec::new();
        let observed = if let Some(argv) = &case.argv {
            match run_argv(root, argv, case.stdin.as_deref()) {
                Ok(outcome) => {
                    if let Some(stdout) = &case.expected.stdout {
                        if outcome.stdout != stdout.as_bytes() {
                            differences.push("stdout differs");
                        }
                    }
                    if let Some(stderr) = &case.expected.stderr {
                        if outcome.stderr != stderr.as_bytes() {
                            differences.push("stderr differs");
                        }
                    }
                    outcome.to_json()
                }
                Err(e) => json!({"error":e.to_string()}),
            }
        } else {
            let command = case.command.as_deref().unwrap_or_default();
            let observed = ShellHostEngine::run_bash_command_cancellable(root, command, cancelled)
                .unwrap_or_else(|e| json!({"error":e.to_string()}));
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
            // A missing rebuilt program must not satisfy a case that expects failure.
            let stderr = observed["stderr"].as_str().unwrap_or_default();
            let expected_stderr = case.expected.stderr.as_deref().unwrap_or_default();
            if NOT_FOUND_MARKERS
                .iter()
                .any(|m| stderr.contains(m) && !expected_stderr.contains(m))
            {
                differences.push("command or program not found");
            }
            observed
        };
        if cancelled() {
            bail!("Oracle run cancelled; no report was saved");
        }
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
        let mut result = describe(&case);
        result["observed"] = observed;
        result["passed"] = json!(differences.is_empty());
        result["differences"] = json!(differences);
        results.push(result);
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
    let report = json!({"status":status,"created":chrono::Utc::now().to_rfc3339(),"config":config,"sha256":sha256,
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

    fn run(root: &Path, config: &str) -> Result<Value> {
        let sha = sha256_hex(&read_config(root, config)?);
        run_oracles(root, config, &sha, &|| false)
    }

    #[test]
    fn oracles_record_real_output_mismatches_and_empty_coverage() {
        let root = std::env::temp_dir().join(format!("quixi-oracle-{}", Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        fs::write(root.join("oracle.json"), br#"{"version":1,"cases":[]}"#).unwrap();
        assert_eq!(run(&root, "oracle.json").unwrap()["status"], "unverified");
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
        let result = run(&root, "oracle.json").unwrap();
        assert_eq!(result["status"], "failed");
        assert_eq!(result["results"][0]["observed"]["stdout"], "actual");
        assert!(root.join(result["reportPath"].as_str().unwrap()).is_file());
        assert!(run_oracles(&root, "../oracle.json", "", &|| false).is_err());
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
        let truncated = run(&root, "oracle.json").unwrap();
        assert_eq!(truncated["status"], "failed");
        assert_eq!(truncated["results"][0]["observed"]["truncated"], true);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn oracles_refuse_configurations_changed_after_approval() {
        let root = std::env::temp_dir().join(format!("quixi-oracle-pin-{}", Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        fs::write(root.join("oracle.json"), br#"{"version":1,"cases":[]}"#).unwrap();
        let approved = preview(&root, "oracle.json").unwrap()["sha256"].as_str().unwrap().to_owned();
        assert!(run_oracles(&root, "oracle.json", &approved, &|| false).is_ok());
        fs::write(root.join("oracle.json"), br#"{"version":1,"cases":[] }"#).unwrap();
        let error = run_oracles(&root, "oracle.json", &approved, &|| false).unwrap_err();
        assert!(error.to_string().contains("changed since it was approved"));
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn missing_program_fails_cases_expecting_failure_and_argv_runs_directly() {
        let root = std::env::temp_dir().join(format!("quixi-oracle-argv-{}", Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        let missing = json!({"id":"missing","requirement":"REQ-001","command":"& '.\\build\\rebuild.exe' --bad",
            "expectationSource":"reference rejects --bad","expected":{"exitCode":1,"stdout":""}});
        fs::write(root.join("oracle.json"), serde_json::to_vec(&json!({"version":1,"cases":[missing]})).unwrap()).unwrap();
        let result = run(&root, "oracle.json").unwrap();
        assert_eq!(result["status"], "failed");
        assert!(result["results"][0]["differences"]
            .as_array()
            .unwrap()
            .contains(&json!("command or program not found")));

        // argv runs the program without PowerShell: exact bytes, stdin and the real exit code.
        let system = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into());
        let findstr = format!("{system}\\System32\\findstr.exe");
        let cases = json!([
            {"id":"echo","requirement":"REQ-002","argv":[findstr,"x"],"stdin":"ax\nb\n",
             "expectationSource":"fixture","expected":{"exitCode":0,"stdout":"ax\n"}},
            {"id":"nomatch","requirement":"REQ-003","argv":[findstr,"zzz"],"stdin":"ax\n",
             "expectationSource":"fixture","expected":{"exitCode":1,"stdout":""}},
            {"id":"absent","requirement":"REQ-004","argv":["build/absent.exe"],
             "expectationSource":"fixture","expected":{"exitCode":1,"stdout":""}}
        ]);
        fs::write(root.join("oracle.json"), serde_json::to_vec(&json!({"version":1,"cases":cases})).unwrap()).unwrap();
        let result = run(&root, "oracle.json").unwrap();
        assert_eq!(result["results"][0]["passed"], true, "{}", result["results"][0]);
        assert_eq!(result["results"][1]["passed"], true, "{}", result["results"][1]);
        assert_eq!(result["results"][2]["passed"], false);
        assert!(result["results"][2]["observed"]["error"].as_str().unwrap().contains("Program not found"));
        for invalid in [
            json!({"id":"a","requirement":"R","expectationSource":"s","expected":{"exitCode":0,"stdout":""}}),
            json!({"id":"a","requirement":"R","command":"x","argv":["y"],"expectationSource":"s","expected":{"exitCode":0,"stdout":""}}),
            json!({"id":"a","requirement":"R","command":"x","stdin":"y","expectationSource":"s","expected":{"exitCode":0,"stdout":""}}),
            json!({"id":"a","requirement":"R","argv":[],"expectationSource":"s","expected":{"exitCode":0,"stdout":""}}),
        ] {
            fs::write(root.join("bad.json"), serde_json::to_vec(&json!({"version":1,"cases":[invalid]})).unwrap()).unwrap();
            assert!(preview(&root, "bad.json").is_err());
        }
        fs::remove_dir_all(root).unwrap();
    }
}
