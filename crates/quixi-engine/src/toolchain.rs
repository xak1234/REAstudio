//! Optional analysis tools. Presence is reported separately from provider readiness.
use crate::QuixiEngine;
use anyhow::{bail, Context, Result};
use quixi_platform::ComputerUse;
use serde_json::{json, Value};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Stdio,
};

fn config(engine: &QuixiEngine) -> Value {
    fs::read(engine.data_dir.join("toolchain-paths.json"))
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_else(|| json!({}))
}
fn catalog(engine: &QuixiEngine) -> Result<Vec<Value>> {
    let value: Value =
        serde_json::from_slice(&fs::read(engine.resources_dir.join("toolchain.json"))?)?;
    value["tools"]
        .as_array()
        .cloned()
        .context("Invalid toolchain catalog")
}
fn find_tool(root: &Path, names: &[&str], depth: u8, remaining: &mut usize) -> Option<PathBuf> {
    if depth == 0 || *remaining == 0 {
        return None;
    }
    for entry in fs::read_dir(root).ok()?.flatten() {
        if *remaining == 0 {
            break;
        }
        *remaining -= 1;
        let Ok(kind) = entry.file_type() else {
            continue;
        };
        if kind.is_symlink() {
            continue;
        }
        if kind.is_file()
            && names
                .iter()
                .any(|n| entry.file_name().to_string_lossy().eq_ignore_ascii_case(n))
        {
            return Some(entry.path());
        }
        if kind.is_dir() {
            if let Some(path) = find_tool(&entry.path(), names, depth - 1, remaining) {
                return Some(path);
            }
        }
    }
    None
}
fn locate(engine: &QuixiEngine, item: &Value, configured: &Value) -> Option<PathBuf> {
    let id = item["id"].as_str()?;
    if let Some(path) = configured[id]
        .as_str()
        .map(PathBuf::from)
        .filter(|p| p.is_file())
    {
        return Some(path);
    }
    let bundled = match id {
        "rea" => Some("plugins/rea/node_modules/rea-agents/scripts/rea.mjs"),
        "ghidra" => Some("plugins/rea/ghidra/ghidraRun.bat"),
        "workflows" => {
            Some("plugins/rea/node_modules/rea-agents/skills/reverse-engineer-anything/SKILL.md")
        }
        _ => None,
    };
    if let Some(path) = bundled
        .map(|p| engine.resources_dir.join(p))
        .filter(|p| p.is_file())
    {
        return Some(path);
    }
    let names: Vec<_> = item["candidates"]
        .as_array()?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    if let Some(path) = find_tool(
        &engine.resources_dir.join("toolchain").join(id),
        &names,
        5,
        &mut 3000,
    ) {
        return Some(path);
    }
    for directory in std::env::split_paths(&std::env::var_os("PATH").unwrap_or_default()) {
        for name in &names {
            let path = directory.join(name);
            if path.is_file() {
                return Some(path);
            }
        }
    }
    None
}
pub fn inventory(engine: &QuixiEngine) -> Result<Value> {
    let configured = config(engine);
    let tools = catalog(engine)?
        .into_iter()
        .map(|mut item| {
            let path = locate(engine, &item, &configured);
            item["path"] = json!(path);
            item["status"] = json!(if path.is_some() {
                "files found — readiness not tested"
            } else if item["kind"] == "reference" {
                "reference / separate integration"
            } else {
                "not configured"
            });
            item
        })
        .collect::<Vec<_>>();
    Ok(json!({"tools":tools}))
}
pub fn handle(engine: &QuixiEngine, operation: &str, body: &Value) -> Result<Value> {
    if operation == "inventory" {
        return inventory(engine);
    }
    let id = body["id"].as_str().context("Choose a tool")?;
    let item = catalog(engine)?
        .into_iter()
        .find(|t| t["id"] == id)
        .context("Unknown tool")?;
    if operation == "docs" {
        quixi_platform::open_external(item["source"].as_str().context("Missing source URL")?)?;
        return Ok(json!({"ok":true}));
    }
    if operation == "configure" {
        let Some(path) = ComputerUse::pick_file(Some(
            "Select this tool's executable, JAR, or MCP registration JSON",
        )) else {
            return Ok(json!({"cancelled":true}));
        };
        let path = fs::canonicalize(path)?;
        if !path.is_file() {
            bail!("Select a file");
        }
        let mut value = config(engine);
        value[id] = json!(path);
        fs::write(
            engine.data_dir.join("toolchain-paths.json"),
            serde_json::to_vec_pretty(&value)?,
        )?;
        return inventory(engine);
    }
    if operation == "install-command" {
        if item["download"].is_null() {
            bail!("This tool needs its own installation; open the official instructions");
        }
        let app = engine
            .resources_dir
            .parent()
            .context("Missing application directory")?;
        let release = app.join("Install-Toolchain.ps1");
        let script = if release.is_file() {
            release
        } else {
            app.join("scripts/install-toolchain.ps1")
        };
        if !script.is_file() {
            bail!("The optional tool installer is missing");
        }
        let path = script
            .to_string_lossy()
            .trim_start_matches("\\\\?\\")
            .replace('\'', "''");
        return Ok(json!({"command":format!("& '{path}' -Tool '{id}'")}));
    }
    let path = locate(engine, &item, &config(engine))
        .context("Install the optional tool or choose its path first")?;
    if operation == "open" {
        if item["kind"] != "gui" {
            bail!("Use the terminal for this CLI or the REA provider for this configuration");
        }
        let mut command = quixi_platform::background_command(&path);
        command
            .current_dir(path.parent().context("Tool has no parent directory")?)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let java = engine.resources_dir.join("plugins/rea/jdk");
        command.env("JAVA_HOME", java);
        let process = command
            .spawn()
            .context("Could not start the selected tool")?;
        let pid = process.id();
        std::thread::spawn(move || {
            let mut process = process;
            let _ = process.wait();
        });
        return Ok(json!({"pid":pid,"targetOpened":false}));
    }
    if operation == "command" {
        let quote = |p: &Path| {
            format!(
                "'{}'",
                p.to_string_lossy()
                    .trim_start_matches("\\\\?\\")
                    .replace('\'', "''")
            )
        };
        let command = if item["kind"] == "jar" {
            format!(
                "& {} -jar {} --version",
                quote(&engine.resources_dir.join("plugins/rea/jdk/bin/java.exe")),
                quote(&path)
            )
        } else if id == "jadx" {
            format!(
                "$env:JAVA_HOME={}; & {} --version",
                quote(&engine.resources_dir.join("plugins/rea/jdk")),
                quote(&path)
            )
        } else if item["kind"] == "python" {
            format!(
                "& {} -c 'import angr; print(angr.__version__)'",
                quote(&path)
            )
        } else if matches!(id, "radare2" | "rizin") {
            format!("& {} -v", quote(&path))
        } else {
            format!("& {} --version", quote(&path))
        };
        return Ok(json!({"command":command}));
    }
    bail!("Unknown toolchain operation")
}
