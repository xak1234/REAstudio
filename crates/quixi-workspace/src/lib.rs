use anyhow::{Context, Result};
use ignore::WalkBuilder;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Shell commands and oracle cases stop after this long.
pub const COMMAND_TIMEOUT: Duration = Duration::from_secs(180);
/// Bytes retained per output stream.
pub const OUTPUT_LIMIT: usize = 131_072;
/// How long to wait for output pipes to close after the process tree is stopped.
const PIPE_DRAIN: Duration = Duration::from_secs(5);

/// Bounded result of `ShellHostEngine::run_process`; output is kept as raw bytes.
#[derive(Debug, Clone)]
pub struct ProcessOutcome {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub exit_code: Option<i32>,
    pub success: bool,
    pub timed_out: bool,
    pub cancelled: bool,
    /// Output exceeded the retained limit, or a pipe was still open at the drain deadline.
    pub truncated: bool,
    pub pipes_left_open: bool,
    pub timeout: Duration,
}

impl ProcessOutcome {
    pub fn exit_code_reported(&self) -> i32 {
        if self.timed_out {
            124
        } else if self.cancelled {
            130
        } else {
            self.exit_code.unwrap_or(-1)
        }
    }

    pub fn to_json(&self) -> Value {
        let stdout = String::from_utf8_lossy(&self.stdout).into_owned();
        let mut stderr = String::from_utf8_lossy(&self.stderr).into_owned();
        if self.timed_out {
            stderr.push_str(&format!(
                "\nCommand timed out after {} seconds.",
                self.timeout.as_secs()
            ));
        }
        if self.cancelled {
            stderr.push_str("\nCommand cancelled; its process tree was stopped.");
        }
        if self.pipes_left_open {
            stderr.push_str("\nA background process kept the output pipes open after the command finished; captured output may be incomplete.");
        }
        json!({"stdout": stdout, "stderr": stderr, "exitCode": self.exit_code_reported(),
            "ok": self.success && !self.timed_out && !self.cancelled, "timedOut": self.timed_out,
            "cancelled": self.cancelled, "truncated": self.truncated})
    }
}

/// Retains the first 60% and the last 40% of a byte stream within a fixed budget.
#[derive(Debug, Default)]
pub struct HeadTail {
    head: Vec<u8>,
    tail: std::collections::VecDeque<u8>,
    head_cap: usize,
    tail_cap: usize,
    omitted: u64,
}

impl HeadTail {
    pub fn new(limit: usize) -> Self {
        let head_cap = limit / 5 * 3;
        Self { head_cap, tail_cap: limit - head_cap, ..Self::default() }
    }

    pub fn push(&mut self, mut bytes: &[u8]) {
        let room = self.head_cap.saturating_sub(self.head.len()).min(bytes.len());
        self.head.extend_from_slice(&bytes[..room]);
        bytes = &bytes[room..];
        if bytes.len() >= self.tail_cap {
            self.omitted += (self.tail.len() + bytes.len() - self.tail_cap) as u64;
            self.tail.clear();
            self.tail.extend(&bytes[bytes.len() - self.tail_cap..]);
        } else {
            self.tail.extend(bytes);
            let excess = self.tail.len().saturating_sub(self.tail_cap);
            self.tail.drain(..excess);
            self.omitted += excess as u64;
        }
    }

    pub fn truncated(&self) -> bool {
        self.omitted > 0
    }

    /// Head, an omission marker line when bytes were dropped, then tail.
    pub fn into_bytes(self) -> Vec<u8> {
        let mut bytes = self.head;
        if self.omitted > 0 {
            bytes.extend_from_slice(
                format!("\n[... {} bytes of output omitted ...]\n", self.omitted).as_bytes(),
            );
        }
        bytes.extend(self.tail);
        bytes
    }
}

/// 1. FileIndexEngine (replaces `fileIndexWorker.js`)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IndexedFileEntry {
    pub path: String,
    pub relative_path: String,
    pub name: String,
    pub is_dir: bool,
    pub is_directory: bool,
    pub size: u64,
}

pub struct FileIndexEngine;

impl FileIndexEngine {
    /// Lists or searches files in `root` respecting `.gitignore`.
    pub fn list_files(root: &Path, query: Option<&str>, limit: usize) -> Vec<IndexedFileEntry> {
        Self::list_files_bounded(root, query, limit).0
    }

    /// Like `list_files`; `limit` counts files only (directories are listed but not counted).
    /// Returns whether the walk stopped before visiting every entry. `.gitignore` applies
    /// whether or not the folder is a Git repository; `.git`, `node_modules` and `target`
    /// are always skipped.
    pub fn list_files_bounded(
        root: &Path,
        query: Option<&str>,
        limit: usize,
    ) -> (Vec<IndexedFileEntry>, bool) {
        let q = query.unwrap_or("").to_lowercase();
        let mut results = Vec::new();
        let mut file_count = 0usize;
        // Directories do not count toward `limit`, but are still bounded.
        let entry_cap = limit.saturating_mul(4).max(limit.saturating_add(1000));
        let mut truncated = false;
        let walker = WalkBuilder::new(root)
            .hidden(false)
            .git_ignore(true)
            .require_git(false)
            .filter_entry(|entry| {
                let name = entry.file_name();
                let is_dir = entry.file_type().is_some_and(|t| t.is_dir());
                !(entry.depth() > 0
                    && (name == ".git" || (is_dir && (name == "node_modules" || name == "target"))))
            })
            .build();

        for entry in walker.flatten() {
            if entry.path() == root {
                continue;
            }
            let path = entry.path();
            let rel = path
                .strip_prefix(root)
                .unwrap_or(path)
                .to_string_lossy()
                .to_string();
            if !q.is_empty() && !rel.to_lowercase().contains(&q) {
                continue;
            }
            if file_count >= limit || results.len() >= entry_cap {
                truncated = true;
                break;
            }
            let meta = entry.metadata().ok();
            let is_dir = meta.as_ref().map(|m| m.is_dir()).unwrap_or(false);
            let size = meta.as_ref().map(|m| m.len()).unwrap_or(0);
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_default();
            if !is_dir {
                file_count += 1;
            }
            results.push(IndexedFileEntry {
                path: path.to_string_lossy().to_string(),
                relative_path: rel,
                name,
                is_dir,
                is_directory: is_dir,
                size,
            });
        }
        (results, truncated)
    }

    /// Lists immediate children of a directory (for `LocalSessions.listDirectoryAtCwd`, `CoworkSpaces.listFolderContents`).
    pub fn list_directory_children(dir: &Path) -> Vec<IndexedFileEntry> {
        let mut out = Vec::new();
        if let Ok(entries) = fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                let meta = entry.metadata().ok();
                let is_dir = meta.as_ref().map(|m| m.is_dir()).unwrap_or(false);
                let size = meta.as_ref().map(|m| m.len()).unwrap_or(0);
                let name = entry.file_name().to_string_lossy().to_string();
                out.push(IndexedFileEntry {
                    path: path.to_string_lossy().to_string(),
                    relative_path: name.clone(),
                    name,
                    is_dir,
                    is_directory: is_dir,
                    size,
                });
            }
        }
        out.sort_by(|a, b| b.is_dir.cmp(&a.is_dir).then_with(|| a.name.cmp(&b.name)));
        out
    }
}

/// 2. GitPoolEngine (replaces `heavyWorkWorker.js` git & worktree tasks)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GitRepoState {
    pub is_git_repo: bool,
    pub root_path: Option<String>,
    pub branch: Option<String>,
    pub head_sha: Option<String>,
    pub is_dirty: bool,
    pub modified_files: Vec<String>,
    pub untracked_files: Vec<String>,
    /// Set when Git integration was skipped because the repository config can run programs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disabled_reason: Option<String>,
}

pub struct GitPoolEngine;

/// One record of `git status --porcelain=v1 -z`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitStatusEntry {
    pub index: char,
    pub worktree: char,
    pub path: String,
    /// Source path of a rename or copy.
    pub orig_path: Option<String>,
}

/// Parse `git status --porcelain=v1 -z` output. Paths are verbatim (no quoting), so spaces,
/// Unicode and renames (`XY new\0old\0`) are preserved.
pub fn parse_status_z(bytes: &[u8]) -> Vec<GitStatusEntry> {
    let mut entries = Vec::new();
    let mut fields = bytes.split(|&b| b == 0);
    while let Some(field) = fields.next() {
        if field.len() < 4 || field[2] != b' ' {
            continue;
        }
        let (index, worktree) = (field[0] as char, field[1] as char);
        let orig_path = if matches!(index, 'R' | 'C') || matches!(worktree, 'R' | 'C') {
            fields.next().map(|f| String::from_utf8_lossy(f).into_owned())
        } else {
            None
        };
        entries.push(GitStatusEntry {
            index,
            worktree,
            path: String::from_utf8_lossy(&field[3..]).into_owned(),
            orig_path,
        });
    }
    entries
}

/// Parse `git diff --numstat -z` into path -> (additions, deletions); binary files count 0.
fn parse_numstat_z(bytes: &[u8]) -> HashMap<String, (u64, u64)> {
    let mut counts = HashMap::new();
    let mut fields = bytes.split(|&b| b == 0);
    while let Some(field) = fields.next() {
        let text = String::from_utf8_lossy(field);
        let mut parts = text.splitn(3, '\t');
        let (Some(added), Some(deleted), Some(path)) = (parts.next(), parts.next(), parts.next()) else {
            continue;
        };
        let path = if path.is_empty() {
            // Rename: `added\tdeleted\t\0source\0destination\0`.
            let _source = fields.next();
            match fields.next() {
                Some(destination) => String::from_utf8_lossy(destination).into_owned(),
                None => continue,
            }
        } else {
            path.to_string()
        };
        counts.insert(path, (added.parse().unwrap_or(0), deleted.parse().unwrap_or(0)));
    }
    counts
}

/// Bytes of diff text returned per stream by the Git panel routes.
pub const GIT_OUTPUT_LIMIT: usize = 2 * 1024 * 1024;
/// Untracked text files up to this size report a line count.
const UNTRACKED_COUNT_LIMIT: u64 = 1024 * 1024;

/// Config files git would read for `cwd`, located lexically without running git.
fn git_config_files(cwd: &Path) -> Vec<PathBuf> {
    let start = fs::canonicalize(cwd).unwrap_or_else(|_| cwd.to_path_buf());
    for dir in start.ancestors() {
        let dot_git = dir.join(".git");
        let git_dir = if dot_git.is_dir() {
            Some(dot_git)
        } else if dot_git.is_file() {
            fs::read_to_string(&dot_git).ok().and_then(|text| {
                text.lines()
                    .find_map(|l| l.trim().strip_prefix("gitdir:").map(|p| dir.join(p.trim())))
            })
        } else if dir.join("HEAD").is_file()
            && (dir.join("objects").is_dir() || dir.join("commondir").is_file())
        {
            // A bare repository (or a git directory opened directly) becomes GIT_DIR.
            Some(dir.to_path_buf())
        } else {
            None
        };
        let Some(git_dir) = git_dir else { continue };
        let mut files = vec![git_dir.join("config"), git_dir.join("config.worktree")];
        if let Ok(common) = fs::read_to_string(git_dir.join("commondir")) {
            files.push(git_dir.join(common.trim()).join("config"));
        }
        return files;
    }
    Vec::new()
}

/// Parse git config text lexically and return keys that make git execute external programs.
pub fn executable_git_config_keys(text: &str) -> Vec<String> {
    fn unquote(value: &str) -> String {
        let (mut out, mut quoted, mut chars) = (String::new(), false, value.chars());
        while let Some(c) = chars.next() {
            match c {
                '"' => quoted = !quoted,
                '\\' => out.extend(chars.next()),
                '#' | ';' if !quoted => break,
                _ => out.push(c),
            }
        }
        out.trim().to_ascii_lowercase()
    }
    let mut found = Vec::new();
    let (mut section, mut subsection) = (String::new(), None::<String>);
    for raw in text.lines() {
        let mut line = raw.trim();
        if line.starts_with('[') {
            // [section], [section "subsection"] or legacy [section.subsection]
            let (mut quoted, mut escaped, mut end) = (false, false, None);
            for (i, c) in line.char_indices().skip(1) {
                match c {
                    _ if escaped => escaped = false,
                    '\\' if quoted => escaped = true,
                    '"' => quoted = !quoted,
                    ']' if !quoted => {
                        end = Some(i);
                        break;
                    }
                    _ => {}
                }
            }
            let Some(end) = end else {
                found.push("malformed-section-header".to_string());
                continue;
            };
            let inner = line[1..end].trim();
            let name_end = inner
                .find(|c: char| c.is_whitespace() || c == '.' || c == '"')
                .unwrap_or(inner.len());
            section = inner[..name_end].to_ascii_lowercase();
            let rest = inner[name_end..].trim();
            subsection = if let Some(legacy) = rest.strip_prefix('.') {
                Some(legacy.to_ascii_lowercase())
            } else if let Some(quoted) = rest.strip_prefix('"') {
                let (mut sub, mut chars) = (String::new(), quoted.chars());
                while let Some(c) = chars.next() {
                    match c {
                        '\\' => sub.extend(chars.next()),
                        '"' => break,
                        _ => sub.push(c),
                    }
                }
                Some(sub)
            } else {
                None
            };
            line = line[end + 1..].trim();
        }
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        let name_end = line
            .find(|c: char| !(c.is_ascii_alphanumeric() || c == '-'))
            .unwrap_or(line.len());
        let name = line[..name_end].to_ascii_lowercase();
        if name.is_empty() {
            continue;
        }
        // Git joins a value ending in an odd number of backslashes with the next line, so the
        // following lines would not mean what this scan reads; treat that as unsafe.
        let trailing = raw.trim_end().chars().rev().take_while(|&c| c == '\\').count();
        if trailing % 2 == 1 && !found.iter().any(|k| k == "line-continuation") {
            found.push("line-continuation".to_string());
        }
        let value = line[name_end..].trim_start().strip_prefix('=').map(unquote);
        let sub = subsection.as_deref();
        if risky_git_key(&section, sub, &name, value.as_deref()) {
            let key = match sub {
                Some(sub) => format!("{section}.{sub}.{name}"),
                None => format!("{section}.{name}"),
            };
            if !found.contains(&key) {
                found.push(key);
            }
        }
    }
    found
}

/// Whether a config key (lower-case section and name) makes git execute an external program.
/// `value` is the lower-case value, or `None` for a bare key.
fn risky_git_key(section: &str, sub: Option<&str>, name: &str, value: Option<&str>) -> bool {
    match (section, sub, name) {
        ("filter", Some(_), "clean" | "smudge" | "process") => true,
        ("diff", Some(_), "textconv" | "command") | ("diff", None, "external") => true,
        ("merge", Some(_), "driver") => true,
        // A bare key means true; only an explicit false value is inert.
        ("core", None, "fsmonitor") => !matches!(value, Some("false" | "no" | "off" | "0" | "")),
        ("core", None, "sshcommand" | "pager" | "editor" | "askpass" | "gitproxy") => true,
        ("pager", _, _) | ("include", _, "path") | ("includeif", _, "path") => true,
        ("credential", _, "helper") | ("gpg", _, "program") => true,
        ("sequence", None, "editor") | ("uploadpack", None, "packobjectshook") => true,
        _ => false,
    }
}

/// Parse one config file with git's own parser (which never runs programs) and return
/// the keys that make git execute external programs. Includes are listed, not followed.
pub fn git_parsed_executable_keys(file: &Path) -> Result<Vec<String>, String> {
    // git cannot open `\\?\` paths; anything it cannot read fails closed below.
    let file = &PathBuf::from(file.to_string_lossy().trim_start_matches("\\\\?\\"));
    // GIT_DIR names a path beneath a regular file, so no repository is discovered and no
    // repository config other than `file` is read.
    let output = GitPoolEngine::command(&std::env::temp_dir())
        .args(["--no-pager", "config", "--file"])
        .arg(file)
        .args(["--no-includes", "--list", "-z"])
        .env("GIT_DIR", file.join("no-repository"))
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .output()
        .map_err(|e| format!("could not run git to validate {}: {e}", file.display()))?;
    if !output.status.success() {
        return Err(format!(
            "git could not parse {}: {}",
            file.display(),
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let mut found = Vec::new();
    for entry in output.stdout.split(|&b| b == 0).filter(|e| !e.is_empty()) {
        let entry = String::from_utf8_lossy(entry);
        let (key, value) = match entry.split_once('\n') {
            Some((key, value)) => (key, Some(value.trim().to_ascii_lowercase())),
            None => (entry.as_ref(), None),
        };
        // section[.subsection].name; the subsection may itself contain dots.
        let (Some((section, rest)), Some((_, name))) = (key.split_once('.'), key.rsplit_once('.')) else {
            return Err(format!("git reported an unexpected config key {key:?} in {}", file.display()));
        };
        let sub = rest.rsplit_once('.').map(|(sub, _)| sub);
        let (section, name) = (section.to_ascii_lowercase(), name.to_ascii_lowercase());
        if risky_git_key(&section, sub, &name, value.as_deref()) {
            let key = key.to_string();
            if !found.contains(&key) {
                found.push(key);
            }
        }
    }
    Ok(found)
}

impl GitPoolEngine {
    /// Why git must not run in `cwd`: its repository-local config can execute programs
    /// (filters, fsmonitor, textconv, ...) merely by inspecting the working tree.
    /// Each config file is checked by git's own parser and, as an additional fail-closed
    /// layer, by a lexical scan; a file git cannot parse disables git.
    pub fn disabled_reason(cwd: &Path) -> Option<String> {
        let (mut keys, mut errors) = (Vec::new(), Vec::new());
        for file in git_config_files(cwd) {
            if let Ok(bytes) = fs::read(&file) {
                let parsed = git_parsed_executable_keys(&file).unwrap_or_else(|error| {
                    errors.push(error);
                    Vec::new()
                });
                let lexical = executable_git_config_keys(&String::from_utf8_lossy(&bytes));
                for key in parsed.into_iter().chain(lexical) {
                    if !keys.contains(&key) {
                        keys.push(key);
                    }
                }
            }
        }
        let mut reasons = errors;
        if !keys.is_empty() {
            reasons.push(format!("repository config defines executable hooks {}", keys.join(", ")));
        }
        (!reasons.is_empty()).then(|| format!("Git disabled for this project: {}", reasons.join("; ")))
    }

    /// A git command hardened against repository-controlled program execution.
    /// Callers must check `disabled_reason` first.
    pub fn command(cwd: &Path) -> Command {
        let mut cmd = quixi_platform::background_command("git");
        // An empty core.hooksPath resolves hooks to the drive root ("/pre-commit"); the null
        // device cannot contain hook files.
        let hooks = if cfg!(windows) { "core.hooksPath=NUL" } else { "core.hooksPath=/dev/null" };
        cmd.args(["-c", "core.fsmonitor=false", "-c", hooks])
            .env("GIT_OPTIONAL_LOCKS", "0")
            .env("GIT_TERMINAL_PROMPT", "0")
            .current_dir(cwd);
        cmd
    }

    fn output(cwd: &Path, args: &[&str]) -> Option<std::process::Output> {
        if Self::disabled_reason(cwd).is_some() {
            return None;
        }
        Self::command(cwd).args(args).output().ok()
    }

    pub fn inspect_repo(cwd: &Path) -> GitRepoState {
        let mut state = GitRepoState {
            is_git_repo: false,
            root_path: None,
            branch: None,
            head_sha: None,
            is_dirty: false,
            modified_files: vec![],
            untracked_files: vec![],
            disabled_reason: Self::disabled_reason(cwd),
        };
        if state.disabled_reason.is_some() {
            return state;
        }
        let text = |args: &[&str]| {
            Self::command(cwd)
                .args(args)
                .output()
                .ok()
                .filter(|o| o.status.success())
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        };
        let Some(root_path) = text(&["rev-parse", "--show-toplevel"]) else {
            return state;
        };
        state.is_git_repo = true;
        state.root_path = Some(root_path);
        state.branch = text(&["rev-parse", "--abbrev-ref", "HEAD"]);
        state.head_sha = text(&["rev-parse", "HEAD"]);

        if let Ok(status_out) = Self::command(cwd)
            .args(["status", "--porcelain=v1", "-z", "--untracked-files=all"])
            .output()
        {
            if status_out.status.success() {
                for entry in parse_status_z(&status_out.stdout) {
                    match (entry.index, entry.worktree) {
                        ('?', '?') => state.untracked_files.push(entry.path),
                        ('!', '!') => {}
                        _ => state.modified_files.push(entry.path),
                    }
                }
            }
        }

        state.is_dirty = !state.modified_files.is_empty() || !state.untracked_files.is_empty();
        state
    }

    pub fn git_diff(cwd: &Path) -> String {
        Self::output(cwd, &["diff", "--no-textconv", "--no-ext-diff", "HEAD"])
            .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
            .unwrap_or_default()
    }

    pub fn get_local_branches(cwd: &Path) -> Vec<String> {
        let mut branches = Vec::new();
        if let Some(out) = Self::output(cwd, &["branch", "--format=%(refname:short)"]) {
            if out.status.success() {
                for line in String::from_utf8_lossy(&out.stdout).lines() {
                    let b = line.trim();
                    if !b.is_empty() {
                        branches.push(b.to_string());
                    }
                }
            }
        }
        if branches.is_empty() {
            branches.push("main".to_string());
        }
        branches
    }

    pub fn get_git_commits(cwd: &Path, limit: usize) -> Vec<Value> {
        let mut commits = Vec::new();
        if let Some(out) = Self::output(
            cwd,
            &[
                "log",
                &format!("-n{}", limit.max(1)),
                "--pretty=format:%H|%h|%an|%ae|%at|%s",
            ],
        ) {
            if out.status.success() {
                for line in String::from_utf8_lossy(&out.stdout).lines() {
                    let parts: Vec<&str> = line.splitn(6, '|').collect();
                    if parts.len() == 6 {
                        commits.push(json!({
                            "sha": parts[0],
                            "shortSha": parts[1],
                            "authorName": parts[2],
                            "authorEmail": parts[3],
                            "timestamp": parts[4].parse::<u64>().unwrap_or(0) * 1000,
                            "subject": parts[5],
                            "message": parts[5],
                        }));
                    }
                }
            }
        }
        commits
    }

    pub fn get_git_diff_structured(cwd: &Path) -> Value {
        let state = Self::inspect_repo(cwd);
        let branch = state.branch.unwrap_or_else(|| "main".to_string());
        let head = state.head_sha.unwrap_or_default();
        let mut files = Vec::new();
        for f in state.modified_files.iter().chain(state.untracked_files.iter()) {
            files.push(json!({
                "path": f,
                "status": "modified",
                "additions": 1,
                "deletions": 0,
            }));
        }
        json!({
            "base_ref": "main",
            "head_ref": branch,
            "merge_base": head,
            "files": files,
            "ahead_by": 0,
            "behind_by": 0,
            "total_commits": 1,
        })
    }

    pub fn get_git_diff_stats(cwd: &Path) -> Value {
        let state = Self::inspect_repo(cwd);
        let count = state.modified_files.len() + state.untracked_files.len();
        json!({
            "additions": count,
            "deletions": 0,
            "fileCount": count,
            "ahead_by": 0,
            "behind_by": 0,
        })
    }

    pub fn get_working_tree_status(cwd: &Path) -> Value {
        let state = Self::inspect_repo(cwd);
        let mut files = Vec::new();
        for f in &state.modified_files {
            files.push(json!({
                "path": f,
                "status": "modified",
                "additions": 1,
                "deletions": 0,
            }));
        }
        for f in &state.untracked_files {
            files.push(json!({
                "path": f,
                "status": "untracked",
                "additions": 1,
                "deletions": 0,
            }));
        }
        json!({
            "files": files,
            "additions": files.len(),
            "deletions": 0,
        })
    }

    pub fn get_diff_file_content(cwd: &Path, rel_path: &str) -> Value {
        let abs = cwd.join(rel_path);
        let new_text = fs::read_to_string(&abs).ok();
        let old_text = Self::output(cwd, &["show", "--no-textconv", &format!("HEAD:{}", rel_path)])
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).to_string());
        json!({
            "oldText": old_text,
            "newText": new_text,
        })
    }

    pub fn stash_working_tree(cwd: &Path) -> bool {
        Self::output(cwd, &["stash", "push", "-u", "-m", "QuixiDesk stash"])
            .map(|o| o.status.success())
            .unwrap_or(false)
    }

    /// Run hardened git with stdout bounded to `limit` bytes: (stdout, truncated, success, stderr).
    fn bounded_output(cwd: &Path, args: &[String], limit: usize) -> Result<(Vec<u8>, bool, bool, String)> {
        use std::io::Read;
        use std::process::Stdio;
        let mut child = Self::command(cwd)
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let mut stderr_pipe = child.stderr.take().context("git stderr")?;
        let stderr_reader = std::thread::spawn(move || {
            let mut bytes = Vec::new();
            let _ = (&mut stderr_pipe).take(64 * 1024).read_to_end(&mut bytes);
            // Drain the rest so git never blocks on a full pipe.
            let _ = std::io::copy(&mut stderr_pipe, &mut std::io::sink());
            String::from_utf8_lossy(&bytes).into_owned()
        });
        let mut stdout = Vec::new();
        let mut pipe = child.stdout.take().context("git stdout")?;
        (&mut pipe).take(limit as u64 + 1).read_to_end(&mut stdout)?;
        let truncated = stdout.len() > limit;
        if truncated {
            let _ = child.kill();
            // Cut at the last complete line within the limit.
            stdout.truncate(limit);
            if let Some(end) = stdout.iter().rposition(|&b| b == b'\n') {
                stdout.truncate(end + 1);
            }
        }
        drop(pipe);
        let status = child.wait()?;
        let stderr = stderr_reader.join().unwrap_or_default();
        Ok((stdout, truncated, status.success() || truncated, stderr))
    }

    fn git_text(cwd: &Path, args: &[&str]) -> Option<String> {
        Self::command(cwd)
            .args(args)
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
    }

    /// Ensure Git may run in `cwd` (repository config cannot execute programs) and `cwd` is in a repository.
    pub fn require_repo(cwd: &Path) -> Result<()> {
        if let Some(reason) = Self::disabled_reason(cwd) {
            anyhow::bail!("{reason}. Review .git/config and use your own Git client.");
        }
        if Self::git_text(cwd, &["rev-parse", "--show-toplevel"]).is_none() {
            anyhow::bail!("This project is not a Git repository");
        }
        Ok(())
    }

    /// Validate project-relative paths with SafeFs containment and return literal pathspecs.
    fn pathspecs(cwd: &Path, paths: &[String]) -> Result<Vec<(String, PathBuf)>> {
        if paths.is_empty() {
            anyhow::bail!("Choose at least one file");
        }
        let root = fs::canonicalize(cwd)?;
        let mut out = Vec::new();
        for path in paths {
            let resolved = quixi_platform::SafeFs::resolve_beneath(cwd, Path::new(path))?;
            let relative = resolved
                .strip_prefix(&root)?
                .components()
                .map(|c| c.as_os_str().to_string_lossy().into_owned())
                .collect::<Vec<_>>()
                .join("/");
            // Git metadata at any depth (also via 8.3 names, which the deepest existing
            // ancestor's canonical path expands) is never a working-tree file.
            let is_git = |p: &Path| {
                p.components().any(|c| {
                    c.as_os_str().to_string_lossy().trim_end_matches(['.', ' ']).eq_ignore_ascii_case(".git")
                })
            };
            let mut existing = resolved.as_path();
            while !existing.exists() {
                match existing.parent() {
                    Some(parent) => existing = parent,
                    None => break,
                }
            }
            let canonical = fs::canonicalize(existing).unwrap_or_else(|_| existing.to_path_buf());
            if relative.is_empty()
                || is_git(Path::new(&relative))
                || canonical.strip_prefix(&root).is_ok_and(is_git)
            {
                anyhow::bail!("Choose files inside the project: {path}");
            }
            out.push((relative, resolved));
        }
        Ok(out)
    }

    fn run_git(cwd: &Path, args: &[String]) -> Result<String> {
        let output = Self::command(cwd).args(args).output()?;
        if !output.status.success() {
            anyhow::bail!("git {}: {}", args.first().map(String::as_str).unwrap_or(""),
                String::from_utf8_lossy(&output.stderr).trim());
        }
        Ok(String::from_utf8_lossy(&output.stdout).into_owned())
    }

    fn has_head(cwd: &Path) -> bool {
        Self::git_text(cwd, &["rev-parse", "--verify", "--quiet", "HEAD"]).is_some()
    }

    /// The Git panel: `{git, files:[{path,status,staged,additions,deletions}], diff, staged, truncated}`.
    /// Paths are relative to `cwd`. Outside a repository the lists are empty; a repository whose
    /// config can execute programs is refused.
    pub fn panel(cwd: &Path) -> Result<Value> {
        if let Some(reason) = Self::disabled_reason(cwd) {
            anyhow::bail!("{reason}. Review .git/config and use your own Git client.");
        }
        let git = Self::inspect_repo(cwd);
        if !git.is_git_repo {
            return Ok(json!({"git": git, "files": [], "diff": "", "staged": "", "truncated": false}));
        }
        let prefix = Self::git_text(cwd, &["rev-parse", "--show-prefix"]).unwrap_or_default();
        let prefix = prefix.trim();
        let status = Self::command(cwd)
            .args(["status", "--porcelain=v1", "-z", "--untracked-files=all"])
            .output()?;
        if !status.status.success() {
            anyhow::bail!("git status: {}", String::from_utf8_lossy(&status.stderr).trim());
        }
        let numstat = |cached: bool| {
            let mut args = vec!["diff", "--numstat", "-z", "--relative", "--no-textconv", "--no-ext-diff"];
            if cached {
                args.push("--cached");
            }
            Self::git_text(cwd, &args).map(|s| parse_numstat_z(s.as_bytes())).unwrap_or_default()
        };
        let (worktree_counts, index_counts) = (numstat(false), numstat(true));
        let mut files = Vec::new();
        for entry in parse_status_z(&status.stdout) {
            let Some(path) = entry.path.strip_prefix(prefix).map(str::to_owned) else { continue };
            let orig = entry.orig_path.as_deref().map(|p| p.strip_prefix(prefix).unwrap_or(p).to_owned());
            let record = |status: char, staged: bool, (additions, deletions): (u64, u64)| {
                let mut file = json!({"path": path, "status": status.to_string(), "staged": staged,
                    "additions": additions, "deletions": deletions});
                if let Some(orig) = &orig {
                    file["oldPath"] = json!(orig);
                }
                file
            };
            match (entry.index, entry.worktree) {
                ('!', '!') => {}
                ('?', '?') => files.push(record('?', false, (Self::untracked_lines(&cwd.join(&path)), 0))),
                (index, worktree) => {
                    if index != ' ' {
                        files.push(record(index, true, index_counts.get(&path).copied().unwrap_or_default()));
                    }
                    if worktree != ' ' {
                        files.push(record(worktree, false, worktree_counts.get(&path).copied().unwrap_or_default()));
                    }
                }
            }
        }
        let diff_args = |cached: bool| {
            let mut args: Vec<String> = vec!["diff".into(), "--no-textconv".into(), "--no-ext-diff".into()];
            if cached {
                args.push("--cached".into());
            }
            args.extend(["--".into(), ".".into()]);
            args
        };
        let (diff, diff_cut, diff_ok, diff_err) = Self::bounded_output(cwd, &diff_args(false), GIT_OUTPUT_LIMIT)?;
        if !diff_ok {
            anyhow::bail!("git diff: {}", diff_err.trim());
        }
        let (staged, staged_cut, _, _) = Self::bounded_output(cwd, &diff_args(true), GIT_OUTPUT_LIMIT)?;
        Ok(json!({"git": git, "files": files, "diff": String::from_utf8_lossy(&diff),
            "staged": String::from_utf8_lossy(&staged), "truncated": diff_cut || staged_cut}))
    }

    /// Line count of a small untracked text file (0 for binary or large files).
    fn untracked_lines(path: &Path) -> u64 {
        match fs::metadata(path) {
            Ok(meta) if meta.is_file() && meta.len() <= UNTRACKED_COUNT_LIMIT => {}
            _ => return 0,
        }
        let Ok(bytes) = fs::read(path) else { return 0 };
        if bytes.contains(&0) {
            return 0;
        }
        let newlines = bytes.iter().filter(|&&b| b == b'\n').count() as u64;
        newlines + u64::from(!bytes.is_empty() && !bytes.ends_with(b"\n"))
    }

    /// `{diff, truncated}` for one file; an untracked file is shown as an all-added diff.
    pub fn file_diff(cwd: &Path, path: &str, staged: bool) -> Result<Value> {
        Self::require_repo(cwd)?;
        let (relative, resolved) = Self::pathspecs(cwd, &[path.to_string()])?.remove(0);
        let spec = format!(":(literal){relative}");
        let tracked = Self::git_text(cwd, &["ls-files", "-z", "--", &spec]).is_some_and(|s| !s.is_empty());
        if !staged && !tracked && resolved.is_file() {
            let bytes = fs::read(&resolved)?;
            if bytes.contains(&0) {
                return Ok(json!({"diff": format!("diff --git a/{relative} b/{relative}\nnew file (untracked)\nBinary file {relative} differs\n"), "truncated": false}));
            }
            let text = String::from_utf8_lossy(&bytes);
            let lines: Vec<&str> = text.split_inclusive('\n').collect();
            let mut diff = format!(
                "diff --git a/{relative} b/{relative}\nnew file (untracked)\n--- /dev/null\n+++ b/{relative}\n@@ -0,0 +1,{} @@\n",
                lines.len()
            );
            let mut truncated = false;
            for line in lines {
                if diff.len() + line.len() + 2 > GIT_OUTPUT_LIMIT {
                    truncated = true;
                    break;
                }
                diff.push('+');
                diff.push_str(line);
                if !line.ends_with('\n') {
                    diff.push_str("\n\\ No newline at end of file\n");
                }
            }
            return Ok(json!({"diff": diff, "truncated": truncated}));
        }
        let mut args: Vec<String> = vec!["diff".into(), "--no-textconv".into(), "--no-ext-diff".into()];
        if staged {
            args.push("--cached".into());
        }
        args.extend(["--".into(), spec]);
        let (diff, truncated, ok, stderr) = Self::bounded_output(cwd, &args, GIT_OUTPUT_LIMIT)?;
        if !ok {
            anyhow::bail!("git diff: {}", stderr.trim());
        }
        Ok(json!({"diff": String::from_utf8_lossy(&diff), "truncated": truncated}))
    }

    /// Stage the given project files (including deletions).
    pub fn stage(cwd: &Path, paths: &[String]) -> Result<Value> {
        Self::require_repo(cwd)?;
        let specs = Self::pathspecs(cwd, paths)?;
        let mut args: Vec<String> = vec!["add".into(), "--all".into(), "--".into()];
        args.extend(specs.iter().map(|(relative, _)| format!(":(literal){relative}")));
        Self::run_git(cwd, &args)?;
        Ok(json!({"ok": true, "paths": specs.iter().map(|(r, _)| r).collect::<Vec<_>>()}))
    }

    /// Remove the given files from the index, keeping the working-tree content.
    pub fn unstage(cwd: &Path, paths: &[String]) -> Result<Value> {
        Self::require_repo(cwd)?;
        let specs = Self::pathspecs(cwd, paths)?;
        let mut args: Vec<String> = if Self::has_head(cwd) {
            vec!["restore".into(), "--staged".into(), "--".into()]
        } else {
            vec!["rm".into(), "--cached".into(), "-r".into(), "-q".into(), "--".into()]
        };
        args.extend(specs.iter().map(|(relative, _)| format!(":(literal){relative}")));
        Self::run_git(cwd, &args)?;
        Ok(json!({"ok": true, "paths": specs.iter().map(|(r, _)| r).collect::<Vec<_>>()}))
    }

    /// Discard changes: files in HEAD are restored (index and working tree) from HEAD; files not
    /// in HEAD (untracked or newly added) are unstaged and deleted. Callers must confirm first.
    pub fn discard(cwd: &Path, paths: &[String]) -> Result<Value> {
        Self::require_repo(cwd)?;
        let specs = Self::pathspecs(cwd, paths)?;
        let head = Self::has_head(cwd);
        let mut restore = Vec::new();
        let mut remove = Vec::new();
        for (relative, resolved) in specs {
            let spec = format!(":(literal){relative}");
            let in_head = head
                && Self::git_text(cwd, &["ls-tree", "-z", "--name-only", "HEAD", "--", &spec])
                    .is_some_and(|s| !s.is_empty());
            if in_head {
                restore.push(spec);
            } else {
                if resolved.is_dir() {
                    anyhow::bail!("Discard untracked files individually: {relative} is a folder");
                }
                let indexed = Self::git_text(cwd, &["ls-files", "-z", "--", &spec]).is_some_and(|s| !s.is_empty());
                remove.push((relative, resolved, spec, indexed));
            }
        }
        if !restore.is_empty() {
            let mut args: Vec<String> =
                vec!["restore".into(), "--source=HEAD".into(), "--staged".into(), "--worktree".into(), "--".into()];
            args.extend(restore.iter().cloned());
            Self::run_git(cwd, &args)?;
        }
        let mut discarded: Vec<String> = restore
            .iter()
            .map(|s| s.trim_start_matches(":(literal)").to_string())
            .collect();
        for (relative, resolved, spec, indexed) in remove {
            if indexed {
                Self::run_git(cwd, &["rm".into(), "--cached".into(), "-q".into(), "--".into(), spec])?;
            }
            if resolved.is_file() {
                fs::remove_file(&resolved)?;
            }
            discarded.push(relative);
        }
        Ok(json!({"ok": true, "discarded": discarded}))
    }

    /// Commit the staged changes. Repository hooks do not run (the hardened builder points
    /// `core.hooksPath` at the null device). Returns `{ok, output}`.
    pub fn commit(cwd: &Path, message: &str) -> Result<Value> {
        Self::require_repo(cwd)?;
        if message.trim().is_empty() {
            anyhow::bail!("Enter a commit message");
        }
        let output = Self::command(cwd).args(["commit", "-m", message]).output()?;
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        Ok(json!({"ok": output.status.success(), "output": text.trim()}))
    }
}

/// 3. Shell & PTY Host (replaces `shellPathWorker.js` & `ptyHostWorker.js`)
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PtySessionEntry {
    pub key: String,
    pub cwd: String,
    pub shell: String,
    pub cols: u16,
    pub rows: u16,
    pub buffer: String,
    pub busy: bool,
}

#[derive(Clone, Default)]
pub struct ShellHostEngine {
    pub ptys: Arc<Mutex<HashMap<String, PtySessionEntry>>>,
}

impl ShellHostEngine {
    pub fn new() -> Self {
        Self {
            ptys: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn resolve_user_shell_env() -> HashMap<String, String> {
        let mut map: HashMap<String, String> = std::env::vars().collect();
        let path_key = map.keys().find(|k| k.eq_ignore_ascii_case("PATH"))
            .cloned().unwrap_or_else(|| "PATH".to_string());
        let mut paths: Vec<PathBuf> = std::env::split_paths(
            &map.get(&path_key).cloned().unwrap_or_default()).collect();
        if let Some(home) = dirs::home_dir() {
            paths.push(home.join(".cargo/bin"));
            paths.push(home.join(".local/bin"));
        }
        if cfg!(target_os = "macos") { paths.push(PathBuf::from("/opt/homebrew/bin")); }
        if let Ok(joined) = std::env::join_paths(paths) {
            map.insert(path_key, joined.to_string_lossy().into_owned());
        }
        map
    }

    /// Windows PowerShell 5.1, present on every supported Windows installation.
    pub fn windows_powershell() -> String {
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string());
        Path::new(&root)
            .join("System32/WindowsPowerShell/v1.0/powershell.exe")
            .to_string_lossy()
            .into_owned()
    }

    /// PowerShell 7+ (`pwsh.exe`) from PATH or its standard installation folder.
    pub fn find_pwsh() -> Option<String> {
        let on_path = std::env::var_os("PATH")
            .map(|path| std::env::split_paths(&path).collect::<Vec<_>>())
            .unwrap_or_default()
            .into_iter()
            .map(|dir| dir.join("pwsh.exe"));
        let installed = ["ProgramW6432", "ProgramFiles"]
            .iter()
            .filter_map(std::env::var_os)
            .map(|dir| PathBuf::from(dir).join("PowerShell").join("7").join("pwsh.exe"));
        on_path
            .chain(installed)
            .find(|candidate| candidate.is_file())
            .map(|candidate| candidate.to_string_lossy().into_owned())
    }

    /// Commands prefer PowerShell 7 when installed and fall back to Windows PowerShell 5.1.
    pub fn default_shell() -> String {
        if cfg!(windows) {
            static SHELL: std::sync::OnceLock<String> = std::sync::OnceLock::new();
            SHELL
                .get_or_init(|| Self::find_pwsh().unwrap_or_else(Self::windows_powershell))
                .clone()
        } else {
            std::env::var("SHELL").ok().filter(|s| Path::new(s).is_file())
                .unwrap_or_else(|| "/bin/sh".to_string())
        }
    }

    /// Short identifier reported with command results: `pwsh`, `powershell` or `sh`.
    pub fn shell_id(shell: &str) -> &'static str {
        let stem = Path::new(shell)
            .file_stem()
            .map(|s| s.to_string_lossy().to_ascii_lowercase())
            .unwrap_or_default();
        match stem.as_str() {
            "pwsh" => "pwsh",
            "powershell" => "powershell",
            _ => "sh",
        }
    }

    /// The shells available for commands, preferred first (used by tests and diagnostics).
    pub fn available_shells() -> Vec<String> {
        if cfg!(windows) {
            Self::find_pwsh()
                .into_iter()
                .chain(Some(Self::windows_powershell()).filter(|s| Path::new(s).is_file()))
                .collect()
        } else {
            vec![Self::default_shell()]
        }
    }

    pub fn get_terminal_shells() -> Value {
        let shell = Self::default_shell();
        let id = Self::shell_id(&shell);
        let name = match id {
            "pwsh" => "PowerShell 7",
            "powershell" => "Windows PowerShell",
            _ => "Shell",
        };
        json!({"shells": [{"id": id, "name": name, "path": shell, "isDefault": true}], "selected": shell})
    }

    /// The shell invocation for `command`. On Windows the command runs inside a script block
    /// on its own lines (a trailing `# comment` cannot swallow the wrapper), `$LASTEXITCODE` is
    /// reset so only the final statement's native exit code decides the status, and when
    /// `cwd_file` is set the final file-system location is written there, never to the output.
    pub fn shell_command(shell: &str, cwd: &Path, command: &str, cwd_file: Option<&Path>) -> Command {
        let mut cmd = Command::new(shell);
        if Self::shell_id(shell) != "sh" {
            cmd.args(["-NoLogo", "-NoProfile", "-NonInteractive", "-Command"]);
            cmd.arg(Self::powershell_wrapper(command));
        } else {
            let trap = if cwd_file.is_some() { "trap 'pwd -P > \"$QUIXI_CWD_FILE\"' EXIT\n" } else { "" };
            cmd.args(["-c", &format!("{trap}{command}")]);
        }
        cmd.current_dir(cwd).envs(Self::resolve_user_shell_env());
        if let Some(file) = cwd_file {
            cmd.env("QUIXI_CWD_FILE", file);
        } else {
            cmd.env_remove("QUIXI_CWD_FILE");
        }
        cmd
    }

    fn powershell_wrapper(command: &str) -> String {
        format!(
            concat!(
                "$ErrorActionPreference='Stop'; $PSNativeCommandUseErrorActionPreference=$false; ",
                "[Console]::OutputEncoding=[System.Text.UTF8Encoding]::new($false); ",
                // PowerShell 7 defaults to the concise error view; use 5.1's full view on both.
                "$ErrorView='NormalView'; if ($PSStyle) {{ $PSStyle.OutputRendering='PlainText' }}\n",
                "$__quixiBlock = {{\n{}\n}}\n",
                // Reset $LASTEXITCODE before the final statement so an earlier native failure
                // does not decide the status of a command whose last pipeline succeeded.
                "try {{ $__quixiAst = $__quixiBlock.Ast; $__quixiStatements = $__quixiAst.EndBlock.Statements; ",
                "if ($__quixiStatements.Count -gt 1) {{ $__quixiText = $__quixiAst.Extent.Text; ",
                "$__quixiAt = $__quixiStatements[$__quixiStatements.Count - 1].Extent.StartOffset - $__quixiAst.Extent.StartOffset; ",
                "$__quixiText = $__quixiText.Substring(0, $__quixiAt) + '$global:LASTEXITCODE = 0; ' + $__quixiText.Substring($__quixiAt); ",
                "if ($__quixiText.StartsWith('{{') -and $__quixiText.EndsWith('}}')) {{ $__quixiText = $__quixiText.Substring(1, $__quixiText.Length - 2) }}; ",
                "$__quixiBlock = [scriptblock]::Create($__quixiText) }} }} catch {{ }}\n",
                "$global:LASTEXITCODE = 0\n",
                "$__quixiOk = $false\n",
                "try {{ & $__quixiBlock; $__quixiOk = $? }} finally {{ if ($env:QUIXI_CWD_FILE) {{ try {{ ",
                "[System.IO.File]::WriteAllText($env:QUIXI_CWD_FILE, $ExecutionContext.SessionState.Path.CurrentFileSystemLocation.ProviderPath) ",
                "}} catch {{ }} }} }}\n",
                "if ($global:LASTEXITCODE) {{ exit $global:LASTEXITCODE }}\n",
                "if (-not $__quixiOk) {{ exit 1 }}\n",
                "exit 0"
            ),
            command
        )
    }

    pub fn start_pty(&self, key: &str, cwd: &Path) -> Value {
        let shell = Self::default_shell();
        let entry = PtySessionEntry {
            key: key.to_string(),
            cwd: cwd.to_string_lossy().to_string(),
            shell,
            cols: 120,
            rows: 32,
            buffer: format!("QuixiDesk Terminal ({})\r\n$ ", cwd.display()),
            busy: false,
        };
        if let Ok(mut map) = self.ptys.lock() {
            map.insert(key.to_string(), entry);
        }
        json!({ "ok": true })
    }

    pub fn write_pty(&self, key: &str, data: &str) {
        if let Ok(mut map) = self.ptys.lock() {
            if let Some(entry) = map.get_mut(key) {
                entry.buffer.push_str(data);
                if data.contains('\r') || data.contains('\n') {
                    let cmd = data.trim();
                    if !cmd.is_empty() {
                        if let Ok(res) = Self::run_bash_command(Path::new(&entry.cwd), cmd) {
                            if let Some(out) = res.get("stdout").and_then(|v| v.as_str()) {
                                entry.buffer.push_str(out);
                            }
                            if let Some(err) = res.get("stderr").and_then(|v| v.as_str()) {
                                entry.buffer.push_str(err);
                            }
                        }
                    }
                }
            }
        }
    }

    pub fn resize_pty(&self, key: &str, cols: u16, rows: u16) {
        if let Ok(mut map) = self.ptys.lock() {
            if let Some(entry) = map.get_mut(key) {
                entry.cols = cols;
                entry.rows = rows;
            }
        }
    }

    pub fn stop_pty(&self, key: &str) {
        if let Ok(mut map) = self.ptys.lock() {
            map.remove(key);
        }
    }

    pub fn get_busy_pty_keys(&self) -> Vec<String> {
        if let Ok(map) = self.ptys.lock() {
            map.values()
                .filter(|e| e.busy)
                .map(|e| e.key.clone())
                .collect()
        } else {
            vec![]
        }
    }

    /// Execute a command with the platform shell. Retains the legacy RPC name.
    /// Output and runtime are bounded; the whole Windows process tree is stopped afterwards.
    pub fn run_bash_command(cwd: &Path, command: &str) -> Result<Value> {
        Self::run_bash_command_cancellable(cwd, command, &|| false)
    }

    /// `run_bash_command` that also stops the process tree once `cancelled` returns true.
    pub fn run_bash_command_cancellable(
        cwd: &Path,
        command: &str,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<Value> {
        Self::run_shell_command(&Self::default_shell(), cwd, command, cancelled)
    }

    /// `run_bash_command_cancellable` with an explicit shell executable.
    pub fn run_shell_command(
        shell: &str,
        cwd: &Path,
        command: &str,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<Value> {
        let cmd = Self::shell_command(shell, cwd, command, None);
        let mut result = Self::run_process(cmd, None, COMMAND_TIMEOUT, cancelled)?.to_json();
        result["shell"] = json!(Self::shell_id(shell));
        Ok(result)
    }

    /// Run a prepared command with bounded output and runtime. The child is placed in a
    /// kill-on-close job; once it exits (or times out/is cancelled) the job is terminated so
    /// descendants holding the output pipes (MSBuild nodes, Start-Process) cannot hang the caller.
    pub fn run_process(
        mut cmd: Command,
        stdin: Option<Vec<u8>>,
        timeout: Duration,
        cancelled: &dyn Fn() -> bool,
    ) -> Result<ProcessOutcome> {
        use std::io::{Read, Write};
        use std::process::Stdio;
        use std::sync::mpsc;
        use std::time::Instant;
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            cmd.creation_flags(0x08000000);
        }
        cmd.env("MSBUILDDISABLENODEREUSE", "1")
            .stdin(if stdin.is_some() { Stdio::piped() } else { Stdio::null() })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = cmd.spawn()?;
        let job = match quixi_platform::ProcessJob::assign(&child) {
            Ok(job) => Some(job),
            Err(error) => {
                tracing::warn!("Process tree containment unavailable: {error}");
                None
            }
        };
        if let (Some(bytes), Some(mut pipe)) = (stdin, child.stdin.take()) {
            std::thread::spawn(move || {
                let _ = pipe.write_all(&bytes);
            });
        }
        type Shared = Arc<Mutex<HeadTail>>;
        fn collect(mut stream: impl Read + Send + 'static) -> (Shared, mpsc::Receiver<()>) {
            let shared: Shared = Arc::new(Mutex::new(HeadTail::new(OUTPUT_LIMIT)));
            let (done, finished) = mpsc::channel();
            let buffer = Arc::clone(&shared);
            std::thread::spawn(move || {
                let mut chunk = [0u8; 8192];
                while let Ok(n) = stream.read(&mut chunk) {
                    if n == 0 {
                        break;
                    }
                    if let Ok(mut retained) = buffer.lock() {
                        retained.push(&chunk[..n]);
                    }
                }
                let _ = done.send(());
            });
            (shared, finished)
        }
        let (out, out_done) = collect(child.stdout.take().expect("piped stdout"));
        let (err, err_done) = collect(child.stderr.take().expect("piped stderr"));
        let started = Instant::now();
        let (mut timed_out, mut was_cancelled) = (false, false);
        let status = loop {
            if let Some(status) = child.try_wait()? {
                break status;
            }
            timed_out = started.elapsed() > timeout;
            was_cancelled = !timed_out && cancelled();
            if timed_out || was_cancelled {
                if let Some(job) = &job {
                    job.terminate();
                } else {
                    #[cfg(windows)]
                    {
                        use std::os::windows::process::CommandExt;
                        let _ = Command::new("taskkill.exe")
                            .args(["/PID", &child.id().to_string(), "/T", "/F"])
                            .creation_flags(0x08000000)
                            .output();
                    }
                }
                let _ = child.kill();
                break child.wait()?;
            }
            std::thread::sleep(Duration::from_millis(25));
        };
        // Descendants that outlive the command would otherwise keep the pipes open forever.
        if let Some(job) = &job {
            job.terminate();
        }
        let deadline = Instant::now() + PIPE_DRAIN;
        let mut pipes_left_open = false;
        for finished in [&out_done, &err_done] {
            let remaining = deadline.saturating_duration_since(Instant::now());
            pipes_left_open |= finished.recv_timeout(remaining) == Err(mpsc::RecvTimeoutError::Timeout);
        }
        let take = |shared: &Shared| {
            shared
                .lock()
                .map(|mut retained| {
                    let retained = std::mem::replace(&mut *retained, HeadTail::new(0));
                    let truncated = retained.truncated();
                    (retained.into_bytes(), truncated)
                })
                .unwrap_or_default()
        };
        let ((stdout, out_truncated), (stderr, err_truncated)) = (take(&out), take(&err));
        Ok(ProcessOutcome {
            stdout,
            stderr,
            exit_code: status.code(),
            success: status.success(),
            timed_out,
            cancelled: was_cancelled,
            truncated: out_truncated || err_truncated || pipes_left_open,
            pipes_left_open,
            timeout,
        })
    }

}

/// Longest runtime of a streaming Terminal command.
pub const TERMINAL_JOB_TIMEOUT: Duration = Duration::from_secs(30 * 60);
/// Streaming commands that may run at once in one scope (project).
pub const TERMINAL_JOBS_PER_SCOPE: usize = 4;
/// Finished jobs stay pollable for this long.
const JOB_RETENTION: Duration = Duration::from_secs(10 * 60);
/// Output bytes always kept from the start of a job; the rest is a sliding tail window.
const JOB_HEAD_BYTES: u64 = 256 * 1024;
const JOB_TAIL_BYTES: usize = 768 * 1024;
/// Most output bytes returned by one poll.
const POLL_BYTES: usize = 512 * 1024;

/// Display form of a path without the `\\?\` prefix that `canonicalize` adds on Windows.
fn plain_path(path: &Path) -> PathBuf {
    let text = path.to_string_lossy();
    match text.strip_prefix("\\\\?\\") {
        Some(rest) if !rest.starts_with("UNC\\") => PathBuf::from(rest),
        _ => path.to_path_buf(),
    }
}

/// Decode `bytes` appended to `pending`, keeping an incomplete trailing UTF-8 sequence for
/// the next read unless `last`.
fn decode_utf8(pending: &mut Vec<u8>, bytes: &[u8], last: bool) -> String {
    pending.extend_from_slice(bytes);
    let mut text = String::new();
    loop {
        match std::str::from_utf8(pending) {
            Ok(valid) => {
                text.push_str(valid);
                pending.clear();
                break;
            }
            Err(error) => {
                let valid = error.valid_up_to();
                text.push_str(&String::from_utf8_lossy(&pending[..valid]));
                match error.error_len() {
                    Some(bad) => {
                        text.push('\u{FFFD}');
                        pending.drain(..valid + bad);
                    }
                    None => {
                        pending.drain(..valid);
                        if last {
                            text.push('\u{FFFD}');
                            pending.clear();
                        }
                        break;
                    }
                }
            }
        }
    }
    text
}

struct OutputChunk {
    start: u64,
    stream: &'static str,
    text: String,
}

/// Interleaved stdout/stderr text addressed by byte offset. The first `JOB_HEAD_BYTES` are
/// kept; later output is a sliding window of `JOB_TAIL_BYTES`.
#[derive(Default)]
struct JobOutput {
    chunks: std::collections::VecDeque<OutputChunk>,
    total: u64,
    tail_bytes: usize,
    truncated: bool,
}

impl JobOutput {
    fn push(&mut self, stream: &'static str, text: String) {
        if text.is_empty() {
            return;
        }
        let start = self.total;
        self.total += text.len() as u64;
        if start >= JOB_HEAD_BYTES {
            self.tail_bytes += text.len();
        }
        self.chunks.push_back(OutputChunk { start, stream, text });
        while self.tail_bytes > JOB_TAIL_BYTES {
            let Some(index) = self.chunks.iter().position(|c| c.start >= JOB_HEAD_BYTES) else { break };
            if index + 1 == self.chunks.len() {
                break;
            }
            if let Some(removed) = self.chunks.remove(index) {
                self.tail_bytes -= removed.text.len();
                self.truncated = true;
            }
        }
    }

    /// Chunks after `offset` (bounded per call) and the offset to poll next.
    fn read(&self, offset: u64) -> (Vec<Value>, u64) {
        let (mut chunks, mut next, mut size) = (Vec::new(), offset.min(self.total), 0usize);
        for chunk in &self.chunks {
            let end = chunk.start + chunk.text.len() as u64;
            if end <= next {
                continue;
            }
            if size >= POLL_BYTES {
                break;
            }
            if chunk.start > next {
                chunks.push(json!({"stream": "stderr",
                    "text": format!("[... {} bytes of output omitted ...]\n", chunk.start - next)}));
            }
            let mut skip = next.saturating_sub(chunk.start) as usize;
            while !chunk.text.is_char_boundary(skip) {
                skip += 1;
            }
            chunks.push(json!({"stream": chunk.stream, "text": &chunk.text[skip..]}));
            size += chunk.text.len() - skip;
            next = end;
        }
        (chunks, next)
    }
}

#[derive(Default)]
struct JobShared {
    output: JobOutput,
    done: bool,
    exit_code: Option<i32>,
    finished: Option<std::time::Instant>,
}

struct TerminalJob {
    scope: String,
    root: PathBuf,
    shell: String,
    shared: Arc<Mutex<JobShared>>,
    stop: Arc<std::sync::atomic::AtomicBool>,
}

/// Streaming Terminal commands. Each job runs in a kill-on-close Job Object with bounded
/// head+tail output. The final working directory of a job becomes the starting directory of
/// the next job in the same scope while it stays inside the scope's root.
#[derive(Clone, Default)]
pub struct TerminalJobs {
    jobs: Arc<Mutex<HashMap<String, TerminalJob>>>,
    cwds: Arc<Mutex<HashMap<String, PathBuf>>>,
}

impl TerminalJobs {
    /// A close prompt must not wait for a running job or its output lock.
    /// Contention/poisoning is conservatively reported as active work.
    pub fn has_active_jobs(&self) -> bool {
        let Ok(jobs) = self.jobs.try_lock() else { return true; };
        jobs.values().any(|job| {
            job.shared.try_lock().map(|shared| !shared.done).unwrap_or(true)
        })
    }

    pub fn new() -> Self {
        Self::default()
    }

    /// The directory the next command of `scope` starts in.
    pub fn cwd(&self, scope: &str, root: &Path) -> PathBuf {
        let root = fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf());
        self.cwds
            .lock()
            .ok()
            .and_then(|cwds| cwds.get(scope).cloned())
            .filter(|cwd| cwd.is_dir() && cwd.starts_with(&root))
            .unwrap_or(root)
    }

    fn prune(jobs: &mut HashMap<String, TerminalJob>) {
        jobs.retain(|_, job| {
            job.shared
                .lock()
                .map(|s| s.finished.is_none_or(|f| f.elapsed() < JOB_RETENTION))
                .unwrap_or(false)
        });
    }

    /// Start `command` in `scope`; returns `{job, cwd, shell}`.
    pub fn start(&self, scope: &str, root: &Path, command: &str) -> Result<Value> {
        self.start_with(&ShellHostEngine::default_shell(), scope, root, command)
    }

    pub fn start_with(&self, shell: &str, scope: &str, root: &Path, command: &str) -> Result<Value> {
        use std::io::Read;
        use std::process::Stdio;
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQUENCE: AtomicU64 = AtomicU64::new(0);
        if command.trim().is_empty() {
            anyhow::bail!("Enter a command");
        }
        let mut jobs = self.jobs.lock().map_err(|_| anyhow::anyhow!("Terminal state is unavailable"))?;
        Self::prune(&mut jobs);
        let running = jobs
            .values()
            .filter(|j| j.scope == scope && j.shared.lock().map(|s| !s.done).unwrap_or(false))
            .count();
        if running >= TERMINAL_JOBS_PER_SCOPE {
            anyhow::bail!("{TERMINAL_JOBS_PER_SCOPE} Terminal commands are already running in this project; stop one first");
        }
        let root = fs::canonicalize(root)?;
        let cwd = self.cwd(scope, &root);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or_default();
        let id = format!("job-{nanos:x}-{:x}", SEQUENCE.fetch_add(1, Ordering::Relaxed));
        let cwd_file = std::env::temp_dir().join(format!("quixi-cwd-{}-{id}.txt", std::process::id()));
        let mut cmd = ShellHostEngine::shell_command(shell, &plain_path(&cwd), command, Some(&cwd_file));
        #[cfg(windows)]
        {
            use std::os::windows::process::CommandExt;
            cmd.creation_flags(0x08000000);
        }
        cmd.env("MSBUILDDISABLENODEREUSE", "1")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        let mut child = cmd.spawn()?;
        let process_job = match quixi_platform::ProcessJob::assign(&child) {
            Ok(job) => Some(job),
            Err(error) => {
                tracing::warn!("Process tree containment unavailable: {error}");
                None
            }
        };
        let shared = Arc::new(Mutex::new(JobShared::default()));
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let readers: Vec<std::sync::mpsc::Receiver<()>> = [
            ("stdout", child.stdout.take().map(|s| Box::new(s) as Box<dyn std::io::Read + Send>)),
            ("stderr", child.stderr.take().map(|s| Box::new(s) as Box<dyn std::io::Read + Send>)),
        ]
        .into_iter()
        .filter_map(|(stream, pipe)| pipe.map(|pipe| (stream, pipe)))
        .map(|(stream, mut pipe)| {
            let (done, finished) = std::sync::mpsc::channel();
            let shared = Arc::clone(&shared);
            std::thread::spawn(move || {
                let (mut buffer, mut pending) = ([0u8; 8192], Vec::new());
                loop {
                    let n = pipe.read(&mut buffer).unwrap_or(0);
                    let text = decode_utf8(&mut pending, &buffer[..n], n == 0);
                    if let Ok(mut shared) = shared.lock() {
                        shared.output.push(stream, text);
                    }
                    if n == 0 {
                        break;
                    }
                }
                let _ = done.send(());
            });
            finished
        })
        .collect();
        let (monitor_shared, monitor_stop, monitor_cwds) =
            (Arc::clone(&shared), Arc::clone(&stop), Arc::clone(&self.cwds));
        let (scope_key, monitor_root) = (scope.to_string(), root.clone());
        std::thread::spawn(move || {
            let started = std::time::Instant::now();
            let (mut timed_out, mut stopped) = (false, false);
            let status = loop {
                match child.try_wait() {
                    Ok(Some(status)) => break Some(status),
                    Ok(None) => {}
                    Err(_) => break None,
                }
                timed_out = started.elapsed() > TERMINAL_JOB_TIMEOUT;
                stopped = !timed_out && monitor_stop.load(Ordering::Relaxed);
                if timed_out || stopped {
                    if let Some(job) = &process_job {
                        job.terminate();
                    } else {
                        #[cfg(windows)]
                        {
                            use std::os::windows::process::CommandExt;
                            let _ = Command::new("taskkill.exe")
                                .args(["/PID", &child.id().to_string(), "/T", "/F"])
                                .creation_flags(0x08000000)
                                .output();
                        }
                    }
                    let _ = child.kill();
                    break child.wait().ok();
                }
                std::thread::sleep(Duration::from_millis(40));
            };
            // Descendants that outlive the command would otherwise keep the pipes open.
            if let Some(job) = &process_job {
                job.terminate();
            }
            let deadline = std::time::Instant::now() + PIPE_DRAIN;
            for finished in &readers {
                let _ = finished.recv_timeout(deadline.saturating_duration_since(std::time::Instant::now()));
            }
            let mut notes = Vec::new();
            if timed_out {
                notes.push(format!("\nCommand timed out after {} seconds; its process tree was stopped.\n", TERMINAL_JOB_TIMEOUT.as_secs()));
            } else if stopped {
                notes.push("\nCommand stopped; its process tree was ended.\n".to_string());
            }
            if let Ok(text) = fs::read_to_string(&cwd_file) {
                let reported = PathBuf::from(text.trim());
                let final_dir = fs::canonicalize(&reported).ok().filter(|p| p.is_dir());
                if let Ok(mut cwds) = monitor_cwds.lock() {
                    match final_dir {
                        Some(dir) if dir.starts_with(&monitor_root) => {
                            cwds.insert(scope_key.clone(), dir);
                        }
                        _ => {
                            cwds.insert(scope_key.clone(), monitor_root.clone());
                            notes.push(format!(
                                "\n[REA Studio] The command ended in {}, outside the project; the next command starts in the project root.\n",
                                reported.display()
                            ));
                        }
                    }
                }
            }
            let _ = fs::remove_file(&cwd_file);
            if let Ok(mut shared) = monitor_shared.lock() {
                for note in notes {
                    shared.output.push("stderr", note);
                }
                shared.exit_code = Some(if timed_out {
                    124
                } else if stopped {
                    130
                } else {
                    status.and_then(|s| s.code()).unwrap_or(-1)
                });
                shared.done = true;
                shared.finished = Some(std::time::Instant::now());
            }
        });
        jobs.insert(
            id.clone(),
            TerminalJob { scope: scope.to_string(), root: root.clone(), shell: shell.to_string(), shared, stop },
        );
        Ok(json!({"job": id, "cwd": plain_path(&cwd), "shell": ShellHostEngine::shell_id(shell)}))
    }

    /// `{chunks:[{stream,text}], nextOffset, done, exitCode, truncated, cwd, shell}`.
    pub fn poll(&self, scope: &str, job: &str, offset: u64) -> Result<Value> {
        let (shared, root, shell) = {
            let mut jobs = self.jobs.lock().map_err(|_| anyhow::anyhow!("Terminal state is unavailable"))?;
            Self::prune(&mut jobs);
            let job = jobs
                .get(job)
                .filter(|j| j.scope == scope)
                .context("Terminal command not found; finished commands expire after 10 minutes")?;
            (Arc::clone(&job.shared), job.root.clone(), job.shell.clone())
        };
        let cwd = self.cwd(scope, &root);
        let shared = shared.lock().map_err(|_| anyhow::anyhow!("Terminal state is unavailable"))?;
        let (chunks, next) = shared.output.read(offset);
        Ok(json!({"chunks": chunks, "nextOffset": next, "done": shared.done,
            "exitCode": if shared.done { json!(shared.exit_code) } else { Value::Null },
            "truncated": shared.output.truncated, "cwd": plain_path(&cwd),
            "shell": ShellHostEngine::shell_id(&shell)}))
    }

    /// Stop a running job and its whole process tree.
    pub fn stop(&self, scope: &str, job: &str) -> Result<Value> {
        let jobs = self.jobs.lock().map_err(|_| anyhow::anyhow!("Terminal state is unavailable"))?;
        let job = jobs
            .get(job)
            .filter(|j| j.scope == scope)
            .context("Terminal command not found")?;
        job.stop.store(true, std::sync::atomic::Ordering::Relaxed);
        Ok(json!({"stopped": true}))
    }
}

/// 4. TranscriptSearchEngine & CLI Session Scanner (replaces `transcriptSearchWorker.js` & `cliImport`)
pub struct TranscriptSearchEngine;

impl TranscriptSearchEngine {
    pub fn search_transcripts(query: &str, limit: usize) -> Vec<Value> {
        let q = query.trim().to_lowercase();
        if q.is_empty() {
            return vec![];
        }
        let mut roots: Vec<PathBuf> = Vec::new();
        if let Some(home) = dirs::home_dir() {
            roots.push(home.join(".quixi/sessions"));
            roots.push(home.join(".quixi/projects"));
            roots.push(home.join(".claude/projects"));
        }

        let mut jsonl_files = Vec::new();
        for r in roots {
            if !r.exists() {
                continue;
            }
            for entry in WalkBuilder::new(&r).max_depth(Some(4)).build().flatten() {
                if entry.path().extension().and_then(|s| s.to_str()) == Some("jsonl") {
                    jsonl_files.push(entry.path().to_path_buf());
                }
            }
        }

        let matches: Vec<Value> = jsonl_files
            .par_iter()
            .filter_map(|file_path| {
                let content = fs::read_to_string(file_path).ok()?;
                if content.to_lowercase().contains(&q) {
                    let snippet = content
                        .lines()
                        .find(|l| l.to_lowercase().contains(&q))
                        .unwrap_or("")
                        .chars()
                        .take(240)
                        .collect::<String>();
                    Some(json!({
                        "filePath": file_path.to_string_lossy(),
                        "sessionId": file_path.file_stem().and_then(|s| s.to_str()).unwrap_or(""),
                        "snippet": snippet,
                    }))
                } else {
                    None
                }
            })
            .collect();

        matches.into_iter().take(limit).collect()
    }

    /// Discovers existing CLI sessions in `~/.claude/projects` and `~/.quixi/code_sessions`
    pub fn list_cli_sessions(limit: usize) -> Vec<Value> {
        use std::io::BufRead;
        let mut raw_sessions: Vec<(u64, String, Value)> = Vec::new();
        let Some(home) = dirs::home_dir() else {
            return Vec::new();
        };
        let claude_projects = home.join(".claude/projects");
        if claude_projects.exists() {
            for entry in WalkBuilder::new(&claude_projects)
                .max_depth(Some(3))
                .build()
                .flatten()
            {
                let path = entry.path();
                if path.extension().and_then(|s| s.to_str()) == Some("jsonl") {
                    let meta = match entry.metadata() {
                        Ok(m) if m.len() > 32 => m,
                        _ => continue,
                    };
                    let sid = path
                        .file_stem()
                        .and_then(|s| s.to_str())
                        .unwrap_or("")
                        .to_string();
                    if sid.is_empty() {
                        continue;
                    }
                    let mtime = meta
                        .modified()
                        .ok()
                        .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
                        .map(|d| d.as_millis() as u64)
                        .unwrap_or(0);
                    let raw_project_dir = path
                        .parent()
                        .and_then(|p| p.file_name())
                        .and_then(|s| s.to_str())
                        .unwrap_or("workspace");
                    let clean_project = raw_project_dir
                        .trim_start_matches('-')
                        .strip_prefix("Users-eric-")
                        .or_else(|| raw_project_dir.trim_start_matches('-').strip_prefix("Users-"))
                        .unwrap_or(raw_project_dir.trim_start_matches('-'));
                    let candidate_cwd = home.join(clean_project.replace('-', "/"));
                    let cwd = if candidate_cwd.is_dir() {
                        candidate_cwd.to_string_lossy().to_string()
                    } else {
                        quixi_platform::default_workspace().to_string()
                    };

                    let mut extracted_title: Option<String> = None;
                    if let Ok(file) = std::fs::File::open(path) {
                        let reader = std::io::BufReader::new(file);
                        for line in reader.lines().take(25).flatten() {
                            if let Ok(v) = serde_json::from_str::<Value>(&line) {
                                let ty = v.get("type").and_then(|t| t.as_str()).unwrap_or("");
                                if ty == "custom-title" || ty == "summary" {
                                    if let Some(s) = v
                                        .get("customTitle")
                                        .or_else(|| v.get("summary"))
                                        .or_else(|| v.get("title"))
                                        .and_then(|x| x.as_str())
                                    {
                                        let t = s.trim();
                                        if !t.is_empty() {
                                            extracted_title = Some(t.chars().take(54).collect());
                                            break;
                                        }
                                    }
                                } else if ty == "user" && extracted_title.is_none() {
                                    let msg_content = v
                                        .get("message")
                                        .and_then(|m| m.get("content"))
                                        .or_else(|| v.get("content"));
                                    let txt = if let Some(s) = msg_content.and_then(|c| c.as_str()) {
                                        s.to_string()
                                    } else if let Some(arr) = msg_content.and_then(|c| c.as_array()) {
                                        arr.iter()
                                            .filter_map(|b| b.get("text").and_then(|t| t.as_str()))
                                            .collect::<Vec<_>>()
                                            .join(" ")
                                    } else {
                                        String::new()
                                    };
                                    let first_line = txt
                                        .lines()
                                        .map(|l| l.trim())
                                        .find(|l| !l.is_empty() && !l.starts_with('<'))
                                        .unwrap_or("");
                                    if first_line.len() > 3 && !first_line.eq_ignore_ascii_case("continue") {
                                        let truncated: String = first_line.chars().take(54).collect();
                                        extracted_title = Some(truncated);
                                    }
                                }
                            }
                        }
                    }

                    let Some(title) = extracted_title else {
                        continue;
                    };
                    raw_sessions.push((
                        mtime,
                        title.clone(),
                        json!({
                            "handle": sid,
                            "sessionId": sid,
                            "id": sid,
                            "title": title,
                            "cwd": cwd,
                            "lastActivityAt": mtime,
                            "liveness": "not_running",
                            "updatedAt": mtime,
                            "createdAt": mtime,
                            "filePath": path.to_string_lossy(),
                        }),
                    ));
                }
            }
        }
        raw_sessions.sort_by(|a, b| b.0.cmp(&a.0));
        let mut seen_titles = std::collections::HashSet::new();
        let mut sessions = Vec::new();
        for (_mtime, title, val) in raw_sessions {
            if seen_titles.insert(title) {
                sessions.push(val);
                if sessions.len() >= limit {
                    break;
                }
            }
        }
        sessions
    }

    pub fn read_cli_transcript(session_id: &str) -> Value {
        let Some(home) = dirs::home_dir() else {
            return json!({ "messages": [], "totalMessages": 0 });
        };
        let claude_projects = home.join(".claude/projects");
        if claude_projects.exists() {
            for entry in WalkBuilder::new(&claude_projects)
                .max_depth(Some(3))
                .build()
                .flatten()
            {
                let path = entry.path();
                if path.extension().and_then(|s| s.to_str()) == Some("jsonl")
                    && path.file_stem().and_then(|s| s.to_str()) == Some(session_id)
                {
                    if let Ok(raw) = fs::read_to_string(path) {
                        let msgs: Vec<Value> = raw
                            .lines()
                            .filter_map(|l| serde_json::from_str::<Value>(l).ok())
                            .collect();
                        let count = msgs.len();
                        return json!({
                            "messages": msgs,
                            "totalMessages": count,
                        });
                    }
                }
            }
        }
        json!({ "messages": [], "totalMessages": 0 })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn close_work_status_is_conservative_without_waiting_for_terminal_locks() {
        fn from_another_thread(jobs: TerminalJobs) -> bool {
            let (sender, receiver) = std::sync::mpsc::channel();
            let worker = std::thread::spawn(move || {
                sender.send(jobs.has_active_jobs()).unwrap();
            });
            let value = receiver.recv_timeout(Duration::from_secs(2))
                .expect("close status blocked on a terminal lock");
            worker.join().unwrap();
            value
        }
        let jobs = TerminalJobs::new();
        assert!(!jobs.has_active_jobs());
        let shared = Arc::new(Mutex::new(JobShared::default()));
        jobs.jobs.lock().unwrap().insert("close-status".into(), TerminalJob {
            scope: "test".into(),
            root: PathBuf::new(),
            shell: "not-launched".into(),
            shared: Arc::clone(&shared),
            stop: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        });
        assert!(jobs.has_active_jobs());
        shared.lock().unwrap().done = true;
        assert!(!jobs.has_active_jobs());
        {
            let _locked_output = shared.lock().unwrap();
            assert!(from_another_thread(jobs.clone()));
        }
        {
            let _locked_jobs = jobs.jobs.lock().unwrap();
            assert!(from_another_thread(jobs.clone()));
        }
        assert!(!jobs.has_active_jobs());
    }


    #[test]
    fn test_file_index_git_and_shell_engines() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap().parent().unwrap();
        let files = FileIndexEngine::list_files(root, Some("Cargo.toml"), 20);
        assert!(!files.is_empty());

        let children = FileIndexEngine::list_directory_children(root);
        assert!(children.iter().any(|c| c.name == "Cargo.toml"));

        let _git = GitPoolEngine::inspect_repo(root);
        let _diff = GitPoolEngine::get_git_diff_structured(root);
        let _stats = GitPoolEngine::get_git_diff_stats(root);
        let res = ShellHostEngine::run_bash_command(root, "echo quixi-shell-test").unwrap();
        assert_eq!(res["ok"], true);
        assert!(res["stdout"]
            .as_str()
            .unwrap_or("")
            .contains("quixi-shell-test"));
    }
    #[cfg(windows)]
    #[test]
    fn powershell_reports_real_exit_status_and_unicode() {
        let root = std::env::temp_dir();
        let ok = ShellHostEngine::run_bash_command(&root, "Write-Output 'Quixi café'; exit 0").unwrap();
        assert_eq!(ok["exitCode"],0);
        assert!(ok["stdout"].as_str().unwrap().contains("Quixi café"));
        let failed = ShellHostEngine::run_bash_command(&root, "Write-Error 'intentional test failure'").unwrap();
        assert_ne!(failed["exitCode"],0);
        assert_eq!(failed["ok"],false);
        assert!(failed["stderr"].as_str().unwrap().contains("intentional test failure"));
    }

    /// B1 and stale `$LASTEXITCODE`, on every installed PowerShell.
    #[cfg(windows)]
    #[test]
    fn wrapper_handles_comments_and_decides_status_from_the_last_statement() {
        let root = std::env::temp_dir();
        let shells = ShellHostEngine::available_shells();
        assert!(!shells.is_empty());
        for shell in &shells {
            let run = |command: &str| ShellHostEngine::run_shell_command(shell, &root, command, &|| false).unwrap();
            let commented = run("Write-Output hi # note");
            assert_eq!(commented["exitCode"], 0, "{shell}: {commented}");
            assert!(commented["stdout"].as_str().unwrap().contains("hi"), "{shell}: {commented}");
            let stale = run("cmd /c exit 3; Write-Output next");
            assert_eq!(stale["exitCode"], 0, "{shell}: {stale}");
            assert!(stale["stdout"].as_str().unwrap().contains("next"));
            let last = run("Write-Output first\ncmd /c exit 3");
            assert_eq!(last["exitCode"], 3, "{shell}: {last}");
            assert_eq!(run("cmd /c exit 4")["exitCode"], 4, "{shell}");
            assert_eq!(run("if ($true) { cmd /c exit 5 }")["exitCode"], 5, "{shell}");
            let here = run("$x = @'\ncontent # not a comment\n'@\nWrite-Output $x # trailing");
            assert!(here["stdout"].as_str().unwrap().contains("content # not a comment"), "{shell}: {here}");
            assert_eq!(run("exit 7")["exitCode"], 7, "{shell}");
            let missing = run("& '.\\build\\absent-program.exe' --bad");
            assert_eq!(missing["exitCode"], 1, "{shell}: {missing}");
            assert!(missing["stderr"].as_str().unwrap().contains("CommandNotFoundException"), "{shell}: {missing}");
            let failed = run("Write-Error 'intentional'");
            assert_ne!(failed["exitCode"], 0, "{shell}");
            assert_eq!(failed["shell"], ShellHostEngine::shell_id(shell));
        }
        let preferred = ShellHostEngine::default_shell();
        assert_eq!(preferred, shells[0]);
    }

    #[test]
    fn head_tail_keeps_both_ends_with_a_marker() {
        let mut buffer = HeadTail::new(100);
        buffer.push(b"HEAD");
        buffer.push(&vec![b'x'; 500]);
        buffer.push(b"TAIL");
        assert!(buffer.truncated());
        let text = String::from_utf8(buffer.into_bytes()).unwrap();
        assert!(text.starts_with("HEAD"));
        assert!(text.ends_with("TAIL"));
        assert!(text.contains("bytes of output omitted"));
        let mut small = HeadTail::new(100);
        small.push(b"short");
        assert!(!small.truncated());
        assert_eq!(small.into_bytes(), b"short");
    }

    #[cfg(windows)]
    #[test]
    fn large_command_output_keeps_head_and_tail_separately_per_stream() {
        let root = std::env::temp_dir();
        let res = ShellHostEngine::run_bash_command(
            &root,
            "Write-Output FIRST-LINE; 1..40000 | ForEach-Object { 'filler line' }; Write-Output LAST-LINE; [Console]::Error.WriteLine('only-stderr')",
        )
        .unwrap();
        let stdout = res["stdout"].as_str().unwrap();
        assert_eq!(res["truncated"], true);
        assert!(stdout.contains("FIRST-LINE") && stdout.contains("LAST-LINE"));
        assert!(stdout.contains("bytes of output omitted"));
        assert!(!stdout.contains("only-stderr"));
        assert!(res["stderr"].as_str().unwrap().contains("only-stderr"));
    }

    #[test]
    fn file_listing_is_deep_bounded_and_honours_gitignore_outside_git() {
        let root = std::env::temp_dir().join(format!("quixi-list-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let deep = root.join("a/b/c/d/e/f/g/h/i/j");
        fs::create_dir_all(&deep).unwrap();
        fs::create_dir_all(root.join("node_modules/pkg")).unwrap();
        fs::create_dir_all(root.join("ignored")).unwrap();
        fs::write(deep.join("deep.txt"), "x").unwrap();
        fs::write(root.join("node_modules/pkg/index.js"), "x").unwrap();
        fs::write(root.join("ignored/secret.txt"), "x").unwrap();
        fs::write(root.join(".gitignore"), "ignored/\n").unwrap();
        for i in 0..5 {
            fs::write(root.join(format!("file{i}.txt")), "x").unwrap();
        }
        let (all, truncated) = FileIndexEngine::list_files_bounded(&root, None, 1000);
        assert!(!truncated);
        let names: Vec<_> = all.iter().map(|f| f.relative_path.replace('\\', "/")).collect();
        assert!(names.iter().any(|n| n.ends_with("a/b/c/d/e/f/g/h/i/j/deep.txt")), "{names:?}");
        assert!(!names.iter().any(|n| n.contains("node_modules") || n.contains("secret")), "{names:?}");
        // Directories are listed but only files count toward the limit.
        let (limited, truncated) = FileIndexEngine::list_files_bounded(&root, None, 3);
        assert!(truncated);
        assert_eq!(limited.iter().filter(|f| !f.is_dir).count(), 3);
        let (matched, truncated) = FileIndexEngine::list_files_bounded(&root, Some("deep"), 10);
        assert!(!truncated);
        assert_eq!(matched.len(), 1);
        fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn porcelain_z_parsing_keeps_spaces_unicode_and_renames() {
        let raw = b" M dir/with space.txt\0?? caf\xc3\xa9 \xe2\x9c\x93.md\0R  new name.txt\0old name.txt\0A  added.rs\0";
        let entries = parse_status_z(raw);
        assert_eq!(entries.len(), 4);
        assert_eq!(entries[0].path, "dir/with space.txt");
        assert_eq!((entries[0].index, entries[0].worktree), (' ', 'M'));
        assert_eq!(entries[1].path, "café ✓.md");
        assert_eq!(entries[2].path, "new name.txt");
        assert_eq!(entries[2].orig_path.as_deref(), Some("old name.txt"));
        assert_eq!(entries[3].path, "added.rs");
        let counts = parse_numstat_z(b"3\t1\ta b.txt\0-\t-\tbin.dat\x002\t0\t\0old.txt\0new.txt\0");
        assert_eq!(counts["a b.txt"], (3, 1));
        assert_eq!(counts["bin.dat"], (0, 0));
        assert_eq!(counts["new.txt"], (2, 0));
    }

    fn test_repo(name: &str) -> Option<PathBuf> {
        if Command::new("git").arg("--version").output().is_err() {
            eprintln!("skipped: git is not installed");
            return None;
        }
        let root = std::env::temp_dir().join(format!("quixi-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        Some(fs::canonicalize(&root).unwrap())
    }

    fn git_in(root: &Path, args: &[&str]) -> String {
        let output = Command::new("git")
            .args(["-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "core.autocrlf=false"])
            .args(args)
            .current_dir(root)
            .output()
            .unwrap();
        assert!(output.status.success(), "{}", String::from_utf8_lossy(&output.stderr));
        String::from_utf8_lossy(&output.stdout).into_owned()
    }

    #[test]
    fn git_panel_stages_unstages_discards_and_commits() {
        let Some(root) = test_repo("git-panel") else { return };
        // Outside a repository the panel is empty rather than an error.
        let empty = GitPoolEngine::panel(&root).unwrap();
        assert_eq!(empty["git"]["isGitRepo"], false);
        assert_eq!(empty["files"].as_array().unwrap().len(), 0);
        assert_eq!(empty["diff"], "");
        git_in(&root, &["init", "-q", "."]);
        git_in(&root, &["config", "user.name", "t"]);
        git_in(&root, &["config", "user.email", "t@example.invalid"]);
        git_in(&root, &["config", "core.autocrlf", "false"]);
        fs::write(root.join("tracked file.txt"), "one\ntwo\n").unwrap();
        fs::write(root.join("old.txt"), "rename me\n").unwrap();
        git_in(&root, &["add", "."]);
        git_in(&root, &["commit", "-q", "-m", "init"]);
        fs::write(root.join("tracked file.txt"), "one\nTWO\nthree\n").unwrap();
        fs::write(root.join("café new.txt"), "a\nb\nc").unwrap();
        git_in(&root, &["mv", "old.txt", "renamed.txt"]);
        let panel = GitPoolEngine::panel(&root).unwrap();
        let files = panel["files"].as_array().unwrap();
        let find = |path: &str, staged: bool| {
            files.iter().find(|f| f["path"] == path && f["staged"] == staged).cloned()
                .unwrap_or_else(|| panic!("{path} staged={staged} missing from {files:?}"))
        };
        let modified = find("tracked file.txt", false);
        assert_eq!((modified["status"].as_str(), modified["additions"].as_u64(), modified["deletions"].as_u64()), (Some("M"), Some(2), Some(1)));
        let untracked = find("café new.txt", false);
        assert_eq!((untracked["status"].as_str(), untracked["additions"].as_u64()), (Some("?"), Some(3)));
        let renamed = find("renamed.txt", true);
        assert_eq!((renamed["status"].as_str(), renamed["oldPath"].as_str()), (Some("R"), Some("old.txt")));
        assert!(panel["diff"].as_str().unwrap().contains("+TWO"));
        assert_eq!(panel["truncated"], false);
        assert_eq!(panel["git"]["untrackedFiles"][0], "café new.txt");

        let added = GitPoolEngine::file_diff(&root, "café new.txt", false).unwrap();
        assert!(added["diff"].as_str().unwrap().contains("+c\n\\ No newline at end of file"), "{added}");
        assert!(GitPoolEngine::file_diff(&root, "../outside.txt", false).is_err());

        GitPoolEngine::stage(&root, &["tracked file.txt".into(), "café new.txt".into()]).unwrap();
        let staged = GitPoolEngine::file_diff(&root, "tracked file.txt", true).unwrap();
        assert!(staged["diff"].as_str().unwrap().contains("+three"));
        GitPoolEngine::unstage(&root, &["café new.txt".into()]).unwrap();
        let after = GitPoolEngine::panel(&root).unwrap();
        assert!(after["files"].as_array().unwrap().iter().any(|f| f["path"] == "café new.txt" && f["status"] == "?"));
        assert!(GitPoolEngine::stage(&root, &["../escape.txt".into()]).is_err());
        assert!(GitPoolEngine::stage(&root, &[]).is_err());
        // Git metadata is refused at any depth and in any letter case.
        fs::create_dir_all(root.join("nested/.git")).unwrap();
        fs::write(root.join("nested/.git/config"), "x\n").unwrap();
        for path in [".git/config", ".GIT/config", "nested/.git/config", "nested/.Git", "nested/.git", "sub/.git/new.txt"] {
            assert!(GitPoolEngine::stage(&root, &[path.into()]).is_err(), "{path}");
            assert!(GitPoolEngine::discard(&root, &[path.into()]).is_err(), "{path}");
            assert!(GitPoolEngine::unstage(&root, &[path.into()]).is_err(), "{path}");
            assert!(GitPoolEngine::file_diff(&root, path, false).is_err(), "{path}");
        }
        fs::remove_dir_all(root.join("nested")).unwrap();
        #[cfg(windows)]
        {
            // An 8.3 alias of .git (when the volume generates them) is refused too.
            let listing = std::process::Command::new("cmd.exe").args(["/c", "dir", "/x", "/a"]).current_dir(&root).output().unwrap();
            let text = String::from_utf8_lossy(&listing.stdout).into_owned();
            if let Some(alias) = text
                .lines()
                .filter(|l| l.trim_end().ends_with(" .git"))
                .filter_map(|l| l.split_whitespace().rev().nth(1))
                .find(|a| a.contains('~'))
            {
                assert!(GitPoolEngine::stage(&root, &[format!("{alias}/config")]).is_err(), "{alias}");
            }
        }

        // A repository hook must not run when committing from REA Studio.
        fs::create_dir_all(root.join(".git/hooks")).unwrap();
        fs::write(root.join(".git/hooks/pre-commit"), "#!/bin/sh\necho ran > hook-ran.txt\nexit 1\n").unwrap();
        // Hooks resolve inside the null device, never to the drive root (as an empty value does).
        let hook_path = GitPoolEngine::run_git(&root, &["rev-parse".into(), "--git-path".into(), "hooks/pre-commit".into()]).unwrap();
        let null_device = if cfg!(windows) { "NUL/pre-commit" } else { "/dev/null/pre-commit" };
        assert_eq!(hook_path.trim(), null_device);
        assert!(GitPoolEngine::commit(&root, "  ").is_err());
        let committed = GitPoolEngine::commit(&root, "second").unwrap();
        assert_eq!(committed["ok"], true, "{committed}");
        assert!(!root.join("hook-ran.txt").exists(), "commit hook was executed");
        assert!(git_in(&root, &["log", "--oneline"]).contains("second"));

        fs::write(root.join("tracked file.txt"), "changed again\n").unwrap();
        GitPoolEngine::discard(&root, &["tracked file.txt".into(), "café new.txt".into()]).unwrap();
        assert_eq!(fs::read_to_string(root.join("tracked file.txt")).unwrap(), "one\nTWO\nthree\n");
        assert!(!root.join("café new.txt").exists());
        let clean = GitPoolEngine::panel(&root).unwrap();
        assert_eq!(clean["files"].as_array().unwrap().len(), 0, "{clean}");
        let _ = fs::remove_dir_all(&root);
    }

    fn wait_for_job(jobs: &TerminalJobs, scope: &str, job: &str) -> (String, Value) {
        let (mut offset, mut text) = (0u64, String::new());
        let started = std::time::Instant::now();
        loop {
            let poll = jobs.poll(scope, job, offset).unwrap();
            for chunk in poll["chunks"].as_array().unwrap() {
                text.push_str(chunk["text"].as_str().unwrap());
            }
            offset = poll["nextOffset"].as_u64().unwrap();
            if poll["done"] == true {
                let last = jobs.poll(scope, job, offset).unwrap();
                assert!(last["chunks"].as_array().unwrap().is_empty());
                return (text, poll);
            }
            assert!(started.elapsed() < Duration::from_secs(60), "job did not finish");
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    #[cfg(windows)]
    #[test]
    fn terminal_jobs_stream_stop_and_persist_cwd_inside_the_project() {
        let root = std::env::temp_dir().join(format!("quixi-jobs-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(root.join("sub dir")).unwrap();
        let jobs = TerminalJobs::new();
        for shell in ShellHostEngine::available_shells() {
            let scope = format!("project-{}", ShellHostEngine::shell_id(&shell));
            let start = |command: &str| {
                jobs.start_with(&shell, &scope, &root, command).unwrap()["job"].as_str().unwrap().to_string()
            };
            let job = start("Write-Output out-line; [Console]::Error.WriteLine('err-line'); cmd /c exit 2");
            let (text, done) = wait_for_job(&jobs, &scope, &job);
            assert!(text.contains("out-line") && text.contains("err-line"), "{text}");
            assert_eq!(done["exitCode"], 2);
            assert_eq!(done["shell"], ShellHostEngine::shell_id(&shell));
            let running = jobs.poll(&scope, &job, 0).unwrap();
            assert!(running["chunks"].as_array().unwrap().iter().any(|c| c["stream"] == "stderr"));

            // cwd persists inside the project.
            let (_, moved) = wait_for_job(&jobs, &scope, &start("Set-Location 'sub dir'"));
            assert!(moved["cwd"].as_str().unwrap().ends_with("sub dir"), "{moved}");
            let (text, _) = wait_for_job(&jobs, &scope, &start("Write-Output (Get-Location).Path"));
            assert!(text.trim_end().ends_with("sub dir"), "{text}");
            // Leaving the project resets the next command to the root with a note.
            let (text, outside) = wait_for_job(&jobs, &scope, &start("Set-Location $env:SystemRoot"));
            assert!(text.contains("outside the project"), "{text}");
            let root_text = plain_path(&fs::canonicalize(&root).unwrap()).to_string_lossy().into_owned();
            assert_eq!(outside["cwd"], root_text);

            // Stop ends the process tree promptly.
            let job = start("Write-Output started; Start-Sleep 60");
            let started = std::time::Instant::now();
            std::thread::sleep(Duration::from_millis(500));
            assert_eq!(jobs.stop(&scope, &job).unwrap()["stopped"], true);
            let (text, stopped) = wait_for_job(&jobs, &scope, &job);
            assert!(started.elapsed() < Duration::from_secs(20));
            assert_eq!(stopped["exitCode"], 130);
            assert!(text.contains("stopped"), "{text}");
            assert!(jobs.poll("other-project", &job, 0).is_err());
        }
        // At most TERMINAL_JOBS_PER_SCOPE commands run at once per project.
        let ids: Vec<String> = (0..TERMINAL_JOBS_PER_SCOPE)
            .map(|_| jobs.start("busy", &root, "Start-Sleep 30").unwrap()["job"].as_str().unwrap().to_string())
            .collect();
        assert!(jobs.start("busy", &root, "Write-Output x").is_err());
        for id in &ids {
            jobs.stop("busy", id).unwrap();
        }
        for id in &ids {
            wait_for_job(&jobs, "busy", id);
        }
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn job_output_is_bounded_and_resumable_by_offset() {
        let mut output = JobOutput::default();
        output.push("stdout", "a".repeat(JOB_HEAD_BYTES as usize));
        for _ in 0..200 {
            output.push("stdout", "b".repeat(8 * 1024));
        }
        output.push("stderr", "END".into());
        assert!(output.truncated);
        let (chunks, next) = output.read(0);
        assert!(chunks.len() > 1);
        assert!(chunks.iter().any(|c| c["text"].as_str().unwrap().contains("omitted")));
        let mut offset = next;
        let mut tail = String::new();
        loop {
            let (chunks, next) = output.read(offset);
            if chunks.is_empty() {
                break;
            }
            tail.extend(chunks.iter().map(|c| c["text"].as_str().unwrap().to_string()));
            offset = next;
        }
        assert!(tail.ends_with("END"));
        assert_eq!(offset, output.total);
        let mut pending = Vec::new();
        assert_eq!(decode_utf8(&mut pending, &[0xc3], false), "");
        assert_eq!(decode_utf8(&mut pending, &[0xa9, b'!'], false), "é!");
    }

    #[cfg(windows)]
    #[test]
    fn background_descendants_holding_pipes_do_not_hang_commands() {
        // The detached ping inherits the output pipes and would hold them open for ~30 s.
        let root = std::env::temp_dir();
        let started = std::time::Instant::now();
        let res = ShellHostEngine::run_bash_command(
            &root,
            "Start-Process -NoNewWindow ping -ArgumentList '-n','30','127.0.0.1'; Write-Output 'launched'",
        )
        .unwrap();
        assert!(started.elapsed() < Duration::from_secs(15), "took {:?}", started.elapsed());
        assert!(res["stdout"].as_str().unwrap().contains("launched"));
        assert_eq!(res["timedOut"], false);
    }

    #[cfg(windows)]
    #[test]
    fn cancelled_commands_stop_their_process_tree() {
        let root = std::env::temp_dir();
        let started = std::time::Instant::now();
        let res = ShellHostEngine::run_bash_command_cancellable(&root, "Start-Sleep 60", &|| {
            started.elapsed() > Duration::from_millis(500)
        })
        .unwrap();
        assert!(started.elapsed() < Duration::from_secs(15));
        assert_eq!(res["cancelled"], true);
        assert_eq!(res["ok"], false);
        assert_eq!(res["exitCode"], 130);
    }

    #[test]
    fn executable_git_config_is_detected_lexically() {
        let risky = "[core]\n\trepositoryformatversion = 0\n\tfsmonitor = \"powershell -c calc\"\n[filter \"lfs\"]\n\tclean = git-lfs clean -- %f\n[Diff \"bin\"]\n\tTextConv = hexdump\n[diff.legacy]\n\tcommand = run\n[include]\n\tpath = ../other\n";
        let keys = executable_git_config_keys(risky);
        assert_eq!(
            keys,
            ["core.fsmonitor", "filter.lfs.clean", "diff.bin.textconv", "diff.legacy.command", "include.path"]
        );
        assert_eq!(executable_git_config_keys("[core] fsmonitor\n"), ["core.fsmonitor"]);
        assert_eq!(executable_git_config_keys("[core]\n\tsshCommand = ssh -i key\n"), ["core.sshcommand"]);
        let safe = "[core]\n\tfsmonitor = false ; comment\n\tbare = false\n[remote \"origin\"]\n\turl = https://example.invalid/x.git\n[branch \"main\"]\n\tremote = origin\n# [filter \"x\"] clean = no\n";
        assert!(executable_git_config_keys(safe).is_empty());
        let continued = "[filter \"x\"]\n\ta = y\\\n[safe]\n\tclean = sh ./f.sh\n";
        assert!(executable_git_config_keys(continued).contains(&"line-continuation".to_string()));
        assert!(executable_git_config_keys("[core]\n\tpath = C:\\\\tools\\\\\n").is_empty());
    }

    /// The repository from the line-continuation bypass: the lexer and git disagree about
    /// which section `clean` belongs to. `QUIXI_TEST_GIT_BYPASS_DIR` keeps the repository
    /// at a chosen path for manual inspection.
    #[test]
    fn git_config_continuation_and_include_if_disable_git() {
        if Command::new("git").arg("--version").output().is_err() {
            eprintln!("skipped: git is not installed");
            return;
        }
        let root = std::env::var_os("QUIXI_TEST_GIT_BYPASS_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(|| std::env::temp_dir().join(format!("quixi-git-continuation-{}", std::process::id())));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let git = |args: &[&str]| {
            let status = Command::new("git")
                .args(["-c", "user.name=t", "-c", "user.email=t@example.invalid", "-c", "core.autocrlf=false"])
                .args(args)
                .current_dir(&root)
                .output()
                .unwrap();
            assert!(status.status.success(), "{}", String::from_utf8_lossy(&status.stderr));
        };
        git(&["init", "-q", "."]);
        fs::write(root.join(".gitattributes"), "a.txt filter=x\n").unwrap();
        fs::write(root.join("a.txt"), "one\n").unwrap();
        fs::write(root.join("f.sh"), "echo hit > marker.txt\ncat\n").unwrap();
        git(&["add", "."]);
        git(&["commit", "-q", "-m", "init"]);
        fs::write(root.join("a.txt"), "two\n").unwrap();
        let config = root.join(".git").join("config");
        let base = fs::read_to_string(&config).unwrap();
        assert_eq!(GitPoolEngine::disabled_reason(&root), None);

        fs::write(&config, format!("{base}[includeIf \"gitdir:/\"]\n\tpath = evil.cfg\n")).unwrap();
        let reason = GitPoolEngine::disabled_reason(&root).unwrap();
        assert!(reason.contains("includeif.gitdir:/.path"), "{reason}");
        assert!(GitPoolEngine::git_diff(&root).is_empty());

        // A file git itself rejects fails closed.
        fs::write(&config, format!("{base}[core\n")).unwrap();
        let reason = GitPoolEngine::disabled_reason(&root).unwrap();
        assert!(reason.contains("git could not parse"), "{reason}");

        fs::write(&config, format!("{base}[filter \"x\"]\n\ta = y\\\n[safe]\n\tclean = sh ./f.sh\n")).unwrap();

        // git's own parser sees filter.x.clean, not safe.clean.
        let parsed = git_parsed_executable_keys(&config).unwrap();
        assert_eq!(parsed, ["filter.x.clean"]);
        let reason = GitPoolEngine::disabled_reason(&root).unwrap();
        assert!(reason.contains("filter.x.clean") && reason.contains("line-continuation"), "{reason}");
        let state = GitPoolEngine::inspect_repo(&root);
        assert!(!state.is_git_repo && state.disabled_reason.is_some());
        assert!(GitPoolEngine::git_diff(&root).is_empty());
        assert!(GitPoolEngine::get_git_commits(&root, 5).is_empty());
        assert!(GitPoolEngine::get_diff_file_content(&root, "a.txt")["oldText"].is_null());
        let _ = GitPoolEngine::get_git_diff_structured(&root);
        assert!(!GitPoolEngine::stash_working_tree(&root));

        std::thread::sleep(Duration::from_millis(300));
        assert!(!root.join("marker.txt").exists(), "repository-configured filter was executed");
        if std::env::var_os("QUIXI_TEST_GIT_BYPASS_DIR").is_none() {
            fs::remove_dir_all(&root).unwrap();
        }
    }

    #[test]
    fn untrusted_repository_config_disables_git_without_running_it() {
        let root = std::env::temp_dir().join(format!("quixi-git-hostile-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let git_dir = root.join(".git");
        fs::create_dir_all(git_dir.join("objects")).unwrap();
        fs::create_dir_all(git_dir.join("refs/heads")).unwrap();
        fs::write(git_dir.join("HEAD"), "ref: refs/heads/main\n").unwrap();
        let sentinel = root.join("executed.txt");
        let program = if cfg!(windows) {
            format!("powershell -NoProfile -Command Set-Content '{}' x", sentinel.display())
        } else {
            format!("touch '{}'", sentinel.display())
        };
        fs::write(
            git_dir.join("config"),
            format!("[core]\n\trepositoryformatversion = 0\n\tfsmonitor = \"{program}\"\n[filter \"x\"]\n\tclean = \"{program}\"\n"),
        )
        .unwrap();
        fs::write(root.join(".gitattributes"), "* filter=x\n").unwrap();
        fs::write(root.join("file.txt"), "content\n").unwrap();
        let nested = root.join("src");
        fs::create_dir_all(&nested).unwrap();
        for cwd in [&root, &nested] {
            let state = GitPoolEngine::inspect_repo(cwd);
            assert!(!state.is_git_repo);
            let reason = state.disabled_reason.unwrap();
            assert!(reason.contains("Git disabled for this project"), "{reason}");
            assert!(reason.contains("core.fsmonitor") && reason.contains("filter.x.clean"));
            assert!(GitPoolEngine::git_diff(cwd).is_empty());
            assert!(!GitPoolEngine::stash_working_tree(cwd));
        }
        std::thread::sleep(Duration::from_millis(300));
        assert!(!sentinel.exists(), "repository-configured program was executed");
        fs::remove_dir_all(&root).unwrap();
    }
}
