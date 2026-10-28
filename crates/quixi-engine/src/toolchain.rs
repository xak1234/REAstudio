//! Optional analysis tools. Presence is reported separately from provider readiness.
use crate::QuixiEngine;
use anyhow::{bail, Context, Result};
use quixi_platform::ComputerUse;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::io::Read;
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
    // Prefer the architecture-selecting launcher at the root over a nested x64 executable.
    for name in names {
        let path = root.join(name);
        if path.is_file() { return Some(path); }
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
        // The bridge executable lives inside the headless installer's folder.
        &engine.resources_dir.join("toolchain").join(if id == "ida-bridge" { "ida-headless" } else { id }),
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
pub fn path_for(engine: &QuixiEngine, id: &str) -> Result<Option<String>> {
    let item = catalog(engine)?.into_iter().find(|t|t["id"]==id).context("Unknown tool")?;
    Ok(locate(engine,&item,&config(engine)).map(|p|p.to_string_lossy().trim_start_matches("\\\\?\\").to_owned()))
}
pub fn sources(engine: &QuixiEngine) -> Result<Value> {
    let inventory = inventory(engine)?;
    let tools: Vec<Value> = inventory["tools"].as_array().into_iter().flatten()
        .filter(|t|t["path"].is_string() && !matches!(t["kind"].as_str(),Some("reference"|"workflow")) && t["id"]!="x64dbg-bridge" && t["id"]!="ida-bridge")
        .map(|t| {
            let id = t["id"].as_str().unwrap_or("");
            let integration = match id {
                "rea" => "REA live catalog",
                "ghidra" | "ida" => "REA native provider",
                "ida-headless" => "Live IDA bridge",
                "jadx-mcp" => "REA Android provider",
                "x64dbg" if inventory["tools"].as_array().is_some_and(|ts|ts.iter().any(|v|v["id"]=="x64dbg-bridge" && v["path"].is_string())) => "Live debugger connection",
                _ => "Import exported results",
            };
            json!({"id":id,"name":t["name"],"kind":t["kind"],"path":t["path"],"integration":integration,
                "note":t["note"],"connected":t["connected"],"connectionNote":t["connectionNote"]})
        }).collect();
    Ok(json!({"sources":tools,"note":"Files found. Connection and tool results establish actual readiness; selecting a source does not execute its target."}))
}
fn import_report(engine: &QuixiEngine, id: &str, body: &Value) -> Result<Value> {
    let source = sources(engine)?["sources"].as_array().into_iter().flatten()
        .find(|s|s["id"]==id).cloned().context("Choose an installed analysis source")?;
    let selected = engine.analysis.target.lock().clone();
    if selected.is_empty() { bail!("Select the artifact this report describes first"); }
    let report = body["path"].as_str().map(str::to_owned)
        .or_else(||ComputerUse::pick_file(Some("Select an exported UTF-8 report, log, JSON or decompiled source file")));
    let Some(report) = report else { return Ok(json!({"cancelled":true})); };
    let path = fs::canonicalize(report)?;
    let mut bytes = vec![];
    fs::File::open(&path)?.take(2 * 1024 * 1024 + 1).read_to_end(&mut bytes)?;
    if bytes.len() > 2 * 1024 * 1024 { bail!("Import a report of at most 2 MiB; split larger exports into files"); }
    let hash = format!("{:x}",Sha256::digest(&bytes));
    let text = String::from_utf8(bytes).context("Choose a UTF-8 text export")?;
    if text.contains('\0') || text.trim().is_empty() { bail!("Choose a nonempty text export, not a binary capture"); }
    engine.analysis.save_external(id,"imported-report","import_report",json!({}),&selected,
        json!({"content":[{"type":"text","text":text}]}),
        json!({"reportPath":path,"sha256":hash,"sourceExecutable":source["path"],
            "association":"User-associated with the selected artifact; origin and target are not independently verified.",
            "limitations":["Imported output is saved evidence, not a live observation by REA Studio."]}))
}
pub fn inventory(engine: &QuixiEngine) -> Result<Value> {
    let configured = config(engine);
    let tools = catalog(engine)?
        .into_iter()
        .map(|mut item| {
            let path = locate(engine, &item, &configured);
            let id=item["id"].as_str().unwrap_or("");
            let connected=match id {
                "rea"=>engine.rea.is_connected(),
                "x64dbg"|"x64dbg-bridge"=>engine.debugger.plugin.connected(),
                "ida-headless"|"ida-bridge"=>engine.ida.connected(),
                "ghidra"|"ida"|"jadx-mcp"=>engine.rea.is_connected() && engine.analysis.provider_sessions.lock().get(id)==Some(&engine.rea.process_id()),
                _=>false,
            };
            item["connected"]=json!(connected);
            item["connectionNote"]=json!(if connected {"Connected"} else if path.is_some() {"Installed · no verified live connection"} else {"Not installed / configured"});
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
    if operation == "sources" { return sources(engine); }
    let id = body["id"].as_str().context("Choose a tool")?;
    let item = catalog(engine)?
        .into_iter()
        .find(|t| t["id"] == id)
        .context("Unknown tool")?;
    if operation == "import-report" { return import_report(engine,id,body); }
    if operation == "bridge-install-command" && matches!(id, "x64dbg-bridge" | "ida-headless" | "ida-bridge") {
        let app = engine.resources_dir.parent().context("Missing application directory")?;
        let (release, source) = if id == "x64dbg-bridge" { ("Install-X64dbg-Bridge.ps1", "scripts/install-x64dbg-bridge.ps1") }
            else { ("Install-IDA-Bridge.ps1", "scripts/install-ida-bridge.ps1") };
        let release = app.join(release);
        let script = if release.is_file() { release } else { app.join(source) };
        if !script.is_file() { bail!("The bridge setup script is missing"); }
        let path = script.to_string_lossy().trim_start_matches("\\\\?\\").replace('\'', "''");
        return Ok(json!({"command":format!("& '{path}'")}));
    }
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
