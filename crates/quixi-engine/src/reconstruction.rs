//! Persisted specification/oracle loop. Expectations are explicit, never invented by the runner.
use anyhow::{bail, Context, Result};
use quixi_platform::SafeFs;
use quixi_workspace::{ShellHostEngine, COMMAND_TIMEOUT};
use serde::{Deserialize, Deserializer};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, HashSet},
    fs,
    io::Read,
    path::Path,
    process::Command,
    time::Duration,
};
use uuid::Uuid;

const MAX_CASES: usize = 256;
const MAX_FILES_PER_CASE: usize = 32;
const MAX_FILE_BYTES: u64 = 4 * 1024 * 1024;
const MAX_TOTAL_FILE_BYTES: u64 = 64 * 1024 * 1024;
const MAX_SUITE_SECONDS: u64 = 2 * 60 * 60;

fn default_timeout_seconds() -> u64 {
    COMMAND_TIMEOUT.as_secs()
}
fn default_exists() -> bool {
    true
}

// Unlike Option<Value>'s default deserializer, explicit JSON null is an expectation.
fn present_json<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Option<Value>, D::Error> {
    Value::deserialize(deserializer).map(Some)
}

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
    #[serde(default = "default_timeout_seconds")]
    timeout_seconds: u64,
    expectation_source: String,
    expected: Expected,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct Expected {
    exit_code: i64,
    stdout: Option<String>,
    stderr: Option<String>,
    #[serde(default)]
    files: Vec<ExpectedFile>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
struct ExpectedFile {
    path: String,
    #[serde(default = "default_exists")]
    exists: bool,
    #[serde(default)]
    sha256: Option<String>,
    #[serde(default)]
    text: Option<String>,
    #[serde(default, deserialize_with = "present_json")]
    json: Option<Value>,
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

fn parse(root: &Path, bytes: &[u8]) -> Result<OracleFile> {
    let specification: OracleFile = serde_json::from_slice(bytes)
        .context("Invalid oracle-cases.json; see docs/RECONSTRUCTION.md for its schema")?;
    if specification.version != 1 {
        bail!("Unsupported oracle configuration version");
    }
    if specification.cases.len() > MAX_CASES {
        bail!("Use at most {MAX_CASES} cases per oracle batch");
    }
    let mut ids = HashSet::new();
    let mut total_seconds = 0;
    // Validate every case before executing any command.
    for case in &specification.cases {
        if case.id.trim().is_empty()
            || !ids.insert(&case.id)
            || case.requirement.trim().is_empty()
            || case.expectation_source.trim().is_empty()
            || (case.expected.stdout.is_none()
                && case.expected.stderr.is_none()
                && case.expected.files.is_empty())
        {
            bail!("Each oracle needs a unique ID, SPEC requirement, command or argv, expectationSource and at least one expected output stream or file assertion");
        }
        if !(1..=600).contains(&case.timeout_seconds) {
            bail!("Oracle {}: timeoutSeconds must be from 1 to 600", case.id);
        }
        total_seconds += case.timeout_seconds;
        if total_seconds > MAX_SUITE_SECONDS {
            bail!("The sum of case timeoutSeconds must not exceed {MAX_SUITE_SECONDS} seconds; split the suite or reduce timeouts");
        }
        if case.expected.files.len() > MAX_FILES_PER_CASE {
            bail!(
                "Oracle {}: use at most {MAX_FILES_PER_CASE} file assertions",
                case.id
            );
        }
        let mut paths = HashSet::new();
        for file in &case.expected.files {
            if file.path.trim().is_empty() || file.path.len() > 4096 || file.path.contains('\0') {
                bail!(
                    "Oracle {}: file assertion path must be 1 to 4096 characters without NUL",
                    case.id
                );
            }
            let path = SafeFs::resolve_beneath(root, Path::new(&file.path))
                .with_context(|| format!("Oracle {}: unsafe output path {}", case.id, file.path))?;
            if path == fs::canonicalize(root)?
                || !paths.insert(path.to_string_lossy().replace('\\', "/").to_lowercase())
            {
                bail!(
                    "Oracle {}: file assertion paths must name distinct files below the project",
                    case.id
                );
            }
            if !file.exists && (file.sha256.is_some() || file.text.is_some() || file.json.is_some())
            {
                bail!(
                    "Oracle {}: exists:false cannot be combined with content expectations",
                    case.id
                );
            }
            if file.text.is_some() && file.json.is_some() {
                bail!(
                    "Oracle {}: choose text or json for a file assertion, not both",
                    case.id
                );
            }
            if file
                .sha256
                .as_ref()
                .is_some_and(|s| s.len() != 64 || !s.bytes().all(|b| b.is_ascii_hexdigit()))
            {
                bail!(
                    "Oracle {}: sha256 must contain exactly 64 hexadecimal characters",
                    case.id
                );
            }
            if file
                .text
                .as_ref()
                .is_some_and(|s| s.len() as u64 > MAX_FILE_BYTES)
            {
                bail!(
                    "Oracle {}: expected file text exceeds {MAX_FILE_BYTES} bytes",
                    case.id
                );
            }
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
        "expectationSource":case.expectation_source,"timeoutSeconds":case.timeout_seconds,
        "expected":{"exitCode":case.expected.exit_code,"stdout":case.expected.stdout,"stderr":case.expected.stderr,
            "files":case.expected.files.iter().map(describe_file).collect::<Vec<_>>()}});
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

fn describe_file(file: &ExpectedFile) -> Value {
    let mut value = json!({"path":file.path,"exists":file.exists});
    if let Some(hash) = &file.sha256 {
        value["sha256"] = json!(hash);
    }
    if let Some(text) = &file.text {
        value["text"] = json!(text);
    }
    if let Some(expected) = &file.json {
        value["json"] = expected.clone();
    }
    value
}

/// The exact cases a user reviews before approving a configuration's hash.
pub fn preview(root: &Path, config: &str) -> Result<Value> {
    let bytes = read_config(root, config)?;
    let specification = parse(root, &bytes)?;
    Ok(json!({"config":config,"sha256":sha256_hex(&bytes),
        "maximumRuntimeSeconds":specification.cases.iter().map(|c| c.timeout_seconds).sum::<u64>(),
        "cases":specification.cases.iter().map(describe).collect::<Vec<_>>()}))
}

fn run_argv(
    root: &Path,
    argv: &[String],
    stdin: Option<&str>,
    timeout: Duration,
    cancelled: &dyn Fn() -> bool,
) -> Result<quixi_workspace::ProcessOutcome> {
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
        timeout,
        cancelled,
    )
}

/// Check postconditions after the command. Files are never executed or changed here.
fn check_file(root: &Path, expected: &ExpectedFile, remaining_bytes: &mut u64) -> Value {
    let mut result = json!({"path":expected.path});
    let mut differences = Vec::<String>::new();
    let checked = (|| -> Result<()> {
        // Re-resolve after execution: a command may have replaced a directory with a link.
        let path = SafeFs::resolve_beneath(root, Path::new(&expected.path))?;
        let metadata = match fs::metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                result["exists"] = json!(false);
                if expected.exists {
                    differences.push("expected file is missing".into());
                }
                return Ok(());
            }
            Err(error) => return Err(error.into()),
        };
        result["exists"] = json!(true);
        result["bytes"] = json!(metadata.len());
        if !expected.exists {
            differences.push("expected path to be absent".into());
            return Ok(());
        }
        if !metadata.is_file() {
            bail!("Expected a regular file");
        }
        if expected.sha256.is_none() && expected.text.is_none() && expected.json.is_none() {
            return Ok(());
        }
        if metadata.len() > MAX_FILE_BYTES {
            bail!("File exceeds the {MAX_FILE_BYTES}-byte comparison limit");
        }
        if metadata.len() > *remaining_bytes {
            bail!("Suite file-comparison byte budget exhausted");
        }
        let limit = MAX_FILE_BYTES.min(*remaining_bytes);
        let mut bytes = Vec::new();
        fs::File::open(&path)?
            .take(limit + 1)
            .read_to_end(&mut bytes)?;
        *remaining_bytes = remaining_bytes.saturating_sub(bytes.len() as u64);
        if bytes.len() as u64 > limit {
            bail!("File grew past the comparison byte limit");
        }
        let hash = sha256_hex(&bytes);
        result["bytes"] = json!(bytes.len());
        result["sha256"] = json!(hash);
        if expected
            .sha256
            .as_ref()
            .is_some_and(|s| !s.eq_ignore_ascii_case(&hash))
        {
            differences.push("sha256 differs".into());
        }
        if let Some(text) = &expected.text {
            if bytes != text.as_bytes() {
                differences.push("text differs (byte-exact UTF-8)".into());
                result["textPreview"] = json!(String::from_utf8_lossy(&bytes)
                    .chars()
                    .take(4096)
                    .collect::<String>());
            }
        }
        if let Some(value) = &expected.json {
            match serde_json::from_slice::<Value>(&bytes) {
                Ok(actual) if actual == *value => {}
                Ok(_) => {
                    differences.push("JSON structure differs".into());
                    result["textPreview"] = json!(String::from_utf8_lossy(&bytes)
                        .chars()
                        .take(4096)
                        .collect::<String>());
                }
                Err(error) => differences.push(format!("Output is not valid JSON: {error}")),
            }
        }
        Ok(())
    })();
    if let Err(error) = checked {
        differences.push(error.to_string());
    }
    result["passed"] = json!(differences.is_empty());
    result["differences"] = json!(differences);
    result
}

/// Run an approved oracle configuration. The bytes actually executed must hash to
/// `approved_sha256`, so a configuration edited after approval is refused.
pub fn run_oracles(
    root: &Path,
    config: &str,
    approved_sha256: &str,
    cancelled: &dyn Fn() -> bool,
) -> Result<Value> {
    if cancelled() {
        bail!("Oracle run cancelled; no report was saved");
    }
    let bytes = read_config(root, config)?;
    let sha256 = sha256_hex(&bytes);
    if sha256 != approved_sha256 {
        bail!("Oracle configuration {config} changed since it was approved. Review and approve it again before running.");
    }
    let specification = parse(root, &bytes)?;
    let mut results = Vec::new();
    let mut remaining_file_bytes = MAX_TOTAL_FILE_BYTES;
    for case in specification.cases {
        if cancelled() {
            bail!("Oracle run cancelled; no report was saved");
        }
        let mut differences = Vec::new();
        let timeout = Duration::from_secs(case.timeout_seconds);
        let observed = if let Some(argv) = &case.argv {
            match run_argv(root, argv, case.stdin.as_deref(), timeout, cancelled) {
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
            let shell = ShellHostEngine::default_shell();
            let command = ShellHostEngine::shell_command(&shell, root, command, None);
            let observed = ShellHostEngine::run_process(command, None, timeout, cancelled)
                .map(|outcome| {
                    let mut value = outcome.to_json();
                    value["shell"] = json!(ShellHostEngine::shell_id(&shell));
                    value
                })
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
        if cancelled() || observed["cancelled"] == true {
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
        let mut files = Vec::new();
        for expected in &case.expected.files {
            if cancelled() {
                bail!("Oracle run cancelled; no report was saved");
            }
            files.push(check_file(root, expected, &mut remaining_file_bytes));
        }
        if files.iter().any(|f| f["passed"] != true) {
            differences.push("file assertions failed");
        }
        let mut result = describe(&case);
        result["observed"] = observed;
        result["observed"]["files"] = json!(files);
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
    let mut requirements = BTreeMap::<String, (usize, usize)>::new();
    for result in &results {
        let counts = requirements
            .entry(
                result["requirement"]
                    .as_str()
                    .unwrap_or_default()
                    .to_owned(),
            )
            .or_default();
        counts.0 += 1;
        counts.1 += usize::from(result["passed"] == true);
    }
    let coverage: Vec<_> = requirements.into_iter().map(|(requirement, (total, passed))|
        json!({"requirement":requirement,"declared":total,"passed":passed,"failed":total-passed})).collect();
    let report = json!({"status":status,"created":chrono::Utc::now().to_rfc3339(),"config":config,"sha256":sha256,
        "total":results.len(),"passed":passed,"failed":results.len()-passed,"results":results,"reportPath":relative,
        "requirements":coverage,"comparedFileBytes":MAX_TOTAL_FILE_BYTES-remaining_file_bytes,
        "coverage":"Only these declared cases were checked. Passing does not establish whole-application equivalence."});
    if cancelled() {
        bail!("Oracle run cancelled; no report was saved");
    }
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

    fn fixture() -> std::path::PathBuf {
        let root = std::env::temp_dir().join(format!("quixi-oracle-{}", Uuid::new_v4()));
        fs::create_dir(&root).unwrap();
        root
    }

    fn save_cases(root: &Path, cases: Value) {
        fs::write(
            root.join("oracle.json"),
            serde_json::to_vec(&json!({"version":1,"cases":cases})).unwrap(),
        )
        .unwrap();
    }

    fn file_case(files: Value) -> Value {
        json!({"id":"outputs","requirement":"REQ-001","command":if cfg!(windows) { "[Console]::Write('ok')" } else { "printf ok" },
            "expectationSource":"independently supplied test fixtures","expected":{"exitCode":0,"files":files}})
    }

    fn run(root: &Path, config: &str) -> Result<Value> {
        let sha = sha256_hex(&read_config(root, config)?);
        run_oracles(root, config, &sha, &|| false)
    }

    #[test]
    fn file_oracles_compare_exact_text_hash_json_and_absence() {
        let root = fixture();
        fs::write(root.join("text.txt"), b"Hello\r\n").unwrap();
        fs::write(
            root.join("object.json"),
            b"{ \"second\": [2, true], \"first\": 1 }\n",
        )
        .unwrap();
        fs::write(root.join("null.json"), b"null").unwrap();
        let files = json!([
            {"path":"text.txt","text":"Hello\r\n","sha256":sha256_hex(b"Hello\r\n")},
            {"path":"object.json","json":{"first":1,"second":[2,true]}},
            {"path":"null.json","json":null},
            {"path":"absent.txt","exists":false}
        ]);
        save_cases(&root, json!([file_case(files)]));
        let preview = preview(&root, "oracle.json").unwrap();
        assert!(preview["cases"][0]["expected"]["files"][2]
            .as_object()
            .unwrap()
            .contains_key("json"));
        assert_eq!(preview["cases"][0]["timeoutSeconds"], 180);
        let result = run(&root, "oracle.json").unwrap();
        assert_eq!(result["status"], "passed", "{result}");
        assert_eq!(
            result["requirements"][0],
            json!({"requirement":"REQ-001","declared":1,"passed":1,"failed":0})
        );
        assert_eq!(
            result["results"][0]["observed"]["files"][0]["sha256"],
            sha256_hex(b"Hello\r\n")
        );

        fs::write(root.join("text.txt"), b"Hello\n").unwrap();
        fs::write(
            root.join("object.json"),
            b"{\"first\":1,\"second\":[true,2]}",
        )
        .unwrap();
        fs::write(root.join("null.json"), b"\"null\"").unwrap();
        fs::write(root.join("absent.txt"), b"unexpected").unwrap();
        let result = run(&root, "oracle.json").unwrap();
        assert_eq!(result["status"], "failed");
        assert!(result["results"][0]["observed"]["files"]
            .as_array()
            .unwrap()
            .iter()
            .all(|f| f["passed"] == false));
        fs::remove_file(root.join("text.txt")).unwrap();
        let result = run(&root, "oracle.json").unwrap();
        assert_eq!(
            result["results"][0]["observed"]["files"][0]["differences"][0],
            "expected file is missing"
        );
        fs::write(root.join("object.json"), b"invalid-json").unwrap();
        let result = run(&root, "oracle.json").unwrap();
        assert!(
            result["results"][0]["observed"]["files"][1]["differences"][0]
                .as_str()
                .unwrap()
                .contains("not valid JSON")
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn file_oracles_validate_every_path_before_execution_and_bound_reads() {
        let root = fixture();
        for files in [
            json!([{"path":"../escape","text":"x"}]),
            json!([{"path":".","exists":true}]),
            json!([{"path":"same"},{"path":"./same"}]),
            json!([{"path":"output","sha256":"bad"}]),
            json!([{"path":"output","exists":false,"text":"x"}]),
            json!([{"path":"output","text":"x","json":"x"}]),
            json!([{"path":"output","unknown":true}]),
            json!([{"path":root.join("absolute.txt").to_string_lossy()}]),
        ] {
            save_cases(&root, json!([file_case(files)]));
            assert!(preview(&root, "oracle.json").is_err());
        }
        let expected: ExpectedFile =
            serde_json::from_value(json!({"path":"large.txt","sha256":"0".repeat(64)})).unwrap();
        fs::File::create(root.join("large.txt"))
            .unwrap()
            .set_len(MAX_FILE_BYTES + 1)
            .unwrap();
        let mut budget = MAX_TOTAL_FILE_BYTES;
        assert_eq!(check_file(&root, &expected, &mut budget)["passed"], false);
        assert_eq!(budget, MAX_TOTAL_FILE_BYTES);
        fs::write(root.join("large.txt"), b"content").unwrap();
        budget = 1;
        assert!(check_file(&root, &expected, &mut budget)["differences"][0]
            .as_str()
            .unwrap()
            .contains("budget exhausted"));
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(root.join("large.txt"), root.join("link.txt")).unwrap();
            let expected: ExpectedFile =
                serde_json::from_value(json!({"path":"link.txt"})).unwrap();
            assert_eq!(check_file(&root, &expected, &mut budget)["passed"], false);
        }
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn larger_suites_and_timeouts_are_validated_without_execution() {
        let root = fixture();
        let cases: Vec<_> = (0..MAX_CASES)
            .map(|n| {
                let mut case = file_case(json!([{"path":"output.txt"}]));
                case["id"] = json!(format!("case-{n}"));
                case["timeoutSeconds"] = json!(1);
                case
            })
            .collect();
        save_cases(&root, json!(cases));
        assert_eq!(
            preview(&root, "oracle.json").unwrap()["cases"]
                .as_array()
                .unwrap()
                .len(),
            MAX_CASES
        );
        let mut too_many = cases.clone();
        let mut extra = cases[0].clone();
        extra["id"] = json!("extra");
        too_many.push(extra);
        save_cases(&root, json!(too_many));
        assert!(preview(&root, "oracle.json").is_err());
        for timeout in [0, 601] {
            let mut case = cases[0].clone();
            case["timeoutSeconds"] = json!(timeout);
            save_cases(&root, json!([case]));
            assert!(preview(&root, "oracle.json").is_err());
        }
        let cases: Vec<_> = cases
            .into_iter()
            .take(13)
            .map(|mut case| {
                case["timeoutSeconds"] = json!(600);
                case
            })
            .collect();
        save_cases(&root, json!(cases));
        assert!(preview(&root, "oracle.json")
            .unwrap_err()
            .to_string()
            .contains("sum of case timeoutSeconds"));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn cancellation_before_a_case_never_executes_it_or_writes_a_report() {
        let root = fixture();
        let command = if cfg!(windows) {
            "Set-Content -Path started -Value bad"
        } else {
            "printf bad > started"
        };
        save_cases(
            &root,
            json!([{"id":"cancelled","requirement":"REQ-001","command":command,
            "expectationSource":"fixture","expected":{"exitCode":0,"stdout":""}}]),
        );
        let sha = sha256_hex(&read_config(&root, "oracle.json").unwrap());
        assert!(run_oracles(&root, "oracle.json", &sha, &|| true)
            .unwrap_err()
            .to_string()
            .contains("cancelled"));
        assert!(!root.join("started").exists());
        assert!(!root.join("quixi-oracle-runs").exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn command_cases_create_outputs_and_honour_custom_timeouts() {
        let root = fixture();
        let command = if cfg!(windows) {
            "[IO.File]::WriteAllText((Join-Path (Get-Location) 'fresh.txt'), 'fresh')"
        } else {
            "printf fresh > fresh.txt"
        };
        let mut case = file_case(json!([{"path":"fresh.txt","text":"fresh"}]));
        case["command"] = json!(command);
        save_cases(&root, json!([case]));
        assert!(!root.join("fresh.txt").exists());
        assert_eq!(run(&root, "oracle.json").unwrap()["status"], "passed");
        let command = if cfg!(windows) {
            "Start-Sleep -Seconds 5"
        } else {
            "sleep 5"
        };
        save_cases(
            &root,
            json!([{"id":"timeout","requirement":"REQ-001","command":command,
            "timeoutSeconds":1,"expectationSource":"fixture","expected":{"exitCode":0,"stdout":""}}]),
        );
        let result = run(&root, "oracle.json").unwrap();
        assert_eq!(result["status"], "failed");
        assert_eq!(result["results"][0]["observed"]["timedOut"], true);
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn argv_cancellation_kills_child_tree_and_case_timeout_is_reported() {
        let root = fixture();
        let system = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".into());
        let shell = format!("{system}\\System32\\WindowsPowerShell\\v1.0\\powershell.exe");
        let script = "$child = Start-Process -FilePath (Join-Path $PSHOME 'powershell.exe') -ArgumentList '-NoProfile','-NonInteractive','-Command','Start-Sleep -Seconds 30' -PassThru; [IO.File]::WriteAllText((Join-Path (Get-Location) 'child.pid'), [string]$child.Id); Start-Sleep -Seconds 30";
        save_cases(
            &root,
            json!([{"id":"cancel","requirement":"REQ-001","argv":[shell,"-NoProfile","-NonInteractive","-Command",script],
            "expectationSource":"fixture","expected":{"exitCode":0,"stdout":""}}]),
        );
        let sha = sha256_hex(&read_config(&root, "oracle.json").unwrap());
        let started = std::time::Instant::now();
        let error = run_oracles(&root, "oracle.json", &sha, &|| {
            fs::read_to_string(root.join("child.pid"))
                .is_ok_and(|s| s.trim().parse::<u32>().is_ok())
                || started.elapsed() > Duration::from_secs(10)
        })
        .unwrap_err();
        assert!(error.to_string().contains("cancelled"), "{error}");
        assert!(started.elapsed() < Duration::from_secs(15));
        assert!(!root.join("quixi-oracle-runs").exists());
        let pid = fs::read_to_string(root.join("child.pid"))
            .unwrap()
            .trim()
            .parse::<u32>()
            .unwrap();
        let mut check = quixi_platform::background_command(&shell);
        check.args(["-NoProfile", "-NonInteractive", "-Command", &format!("if (Get-Process -Id {pid} -ErrorAction SilentlyContinue) {{ exit 1 }} else {{ exit 0 }}")]);
        let outcome =
            ShellHostEngine::run_process(check, None, Duration::from_secs(10), &|| false).unwrap();
        assert!(
            outcome.success,
            "Cancelled oracle left child process {pid} running"
        );

        save_cases(
            &root,
            json!([{"id":"timeout","requirement":"REQ-001","argv":[shell,"-NoProfile","-NonInteractive","-Command","Start-Sleep -Seconds 5"],
            "timeoutSeconds":1,"expectationSource":"fixture","expected":{"exitCode":0,"stdout":""}}]),
        );
        let result = run(&root, "oracle.json").unwrap();
        assert_eq!(result["status"], "failed");
        assert_eq!(result["results"][0]["observed"]["timedOut"], true);
        fs::remove_dir_all(root).unwrap();
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
