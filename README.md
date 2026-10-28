<div align="center">
<img src="resources/rea-logo.svg" alt="REA Studio" width="220">

# REA Studio V1.1.1

**A native coding playground with an integrated REA reverse engineering workspace.**

[Download Windows release](https://github.com/xak1234/REAstudio/releases) · [Build from source](#build-from-source) · [REA workflow](#reverse-engineering-with-rea) · [Troubleshooting](#troubleshooting)
</div>

REA Studio combines a project explorer, text editor, Git changes, PowerShell output, model-driven coding tasks, and reverse engineering evidence in a Rust/WebView2 desktop application. Its dark playground layout keeps the project on the left, work in the centre, and model/tool settings on the right.

**V1.1.1 (package version 1.1.1).** Previously named QuixiDesk Windows. Existing `.quixi` settings, saved runs, analysis records and the `QuixiDesk\WebView` profile are reused; the `QUIXI_*` environment overrides remain compatible. Close the previous app before opening REA Studio with the same profile.

This is a Windows-focused derivative of [QuixiAI/QuixiDesk](https://github.com/QuixiAI/QuixiDesk), with a separately implemented playground UI and the upstream MIT attribution preserved. It is an independent community project. It does not include the upstream Classic renderer, extracted application assets, proprietary fonts, example account data, or local machine configuration. See [NOTICE.md](NOTICE.md) for provenance and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for bundled components.

## What works

| Area | Implemented behaviour |
| --- | --- |
| Projects | Open an existing local folder, browse/filter files, and reopen saved projects. |
| Editor | Edit UTF-8 files, save with Ctrl+S, create files, and detect conflicting external edits. |
| Changes | Inspect the real Git working tree, staged diff, and untracked file list. Git must be installed. |
| Terminal | Execute PowerShell commands in the selected project and show actual stdout, stderr, and exit status. |
| Model tasks | One coding agent with streamed responses, bounded tool steps, persisted runs, and an activity log. |
| Ask mode | Read project files and answer questions; optional static REA tools can inspect a selected artifact. |
| Code mode | Read/write files and run commands as the signed-in Windows user. |
| REA plugin | Persistent MCP connection, live tool schemas and availability, artifact selection, recovered code, and saved JSON evidence. |
| Reconstruction | Binary → REA → SPEC.md → rebuild → oracle → retry, with separate implementation runs and persisted evidence/comparison reports. |
| Analysis sources | Installed-tool selector, green live connection indicators, REA providers, x64dbg observations, and imported reports. |
| Decompilation assistant | Separate LLM4Decompile endpoint and driving agent model; source-linked suggestions with verification status. |
| Toolchain | Detection, configured paths, workflow guides, GUI launch, optional portable downloads and x64dbg bridge setup. |
| Providers | API-key providers and local/custom OpenAI-compatible endpoints; model selection and connection testing. |

This release includes an optional authenticated MCP control server. It does **not** implement multi-agent team orchestration, a full interactive terminal/PTY, a full debugger UI, Git staging/commit buttons, or upstream Classic feature parity. Subscription/OAuth sign-in is not exposed in this interface. Shared upstream engine modules remain in the source, but the public desktop shell serves only the workspace, provider and local MCP settings APIs.

## Requirements

- Windows x64; validated on Windows 11. Windows 10 x64 is a compatibility target, not a separately completed test run.
- [Microsoft Edge WebView2 Runtime](https://developer.microsoft.com/microsoft-edge/webview2/). The app uses the installed runtime; the release does not bundle a WebView2 installer.
- A local writable folder. For REA's Windows native Ghidra lane, use supported PE files on a **fixed local NTFS volume**.
- [Git for Windows](https://gitforwindows.org/) for Git state and diffs.
- A reachable model provider if you want AI tasks. Manual editing and bundled static analysis do not require an LLM subscription.
- Space for the extracted application and analysis workspace. The full JDK, Ghidra, licenses, and corresponding dependency source make the distribution much larger than the application executable.

No global Node, Java, Ghidra, npm, Rust, or administrator installation is needed to run the full release ZIP. Project-specific compilers and build tools are separate.

## Install and run

1. Open [Releases](https://github.com/xak1234/REAstudio/releases) and download `REA-Studio-1.1.1-x64.zip` and its `.sha256` file. GitHub's automatic **Source code** ZIP is for developers and does not contain the executable or bundled runtimes.
2. Verify the ZIP in PowerShell:

   ```powershell
   $archive = '.\REA-Studio-1.1.1-x64.zip'
   $expected = ((Get-Content "$archive.sha256" -Raw).Trim() -split '\s+')[0]
   $actual = (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash
   if ($actual -ne $expected) { throw 'Checksum mismatch: download the release again.' }
   'Checksum OK'
   ```

3. Extract the **whole** archive to a local folder. Keep `resources`, `licenses`, and the runtime DLLs beside `REAStudio.exe`.
4. Run `REAStudio.exe`.
5. Optionally run `Install-REA-Studio.ps1` from the extracted folder. It copies the application to `%LOCALAPPDATA%\Programs\REA Studio` and creates a desktop shortcut. Choose a different location with `-Destination 'D:\Apps\REA-Studio'`.

The application and installer are unsigned. The installer refuses to overwrite an existing installation; close the app and choose a new folder when upgrading. User data is stored separately, so replacing the application folder preserves saved settings and evidence. To uninstall, remove the application folder and shortcut. Delete the data directories below only if you also want to remove your saved work.

## First project and provider

1. Click **Open project** and choose a folder you own or are working on.
2. Click **Providers** and select the appropriate provider. For a local model server choose **Custom OpenAI-Compatible**.
3. Enter its base URL, including `/v1` when required, and its exact model ID. Supply an API key only when the endpoint requires one.
4. Click **Test connection**, then **Save provider**. Select the model in the right sidebar.
5. Start with **Ask · read files**. Switch to **Code · edit & run commands** when you want the agent to make changes.

Examples of local endpoint shapes:

| Server | Typical base URL | Model ID |
| --- | --- | --- |
| llama.cpp or another compatible server | `http://127.0.0.1:8080/v1` | The ID advertised by that server |
| LM Studio | `http://127.0.0.1:1234/v1` | The loaded model's advertised ID |
| Ollama compatibility API | `http://127.0.0.1:11434/v1` | An installed model name |

These are examples, not a requirement to use those ports. For another computer, enter its address. No private LAN address, access token, provider key, or model is preconfigured in the public release. A successful connection test confirms that the endpoint responds; it does not prove that every advertised model is loaded or supports the coding protocol.

### Environment API keys

Leave the key blank to preserve a saved credential, or look up the provider's environment key when none is saved. Examples: `OPENAI_API_KEY`, `OPENROUTER_API_KEY`, `ANTHROPIC_API_KEY`, `DEEPSEEK_API_KEY`, `GEMINI_API_KEY` (then `GOOGLE_API_KEY`). Custom endpoints check `CUSTOM_API_KEY`, then the matching known provider's variable when the endpoint hostname matches exactly. Local servers check `OLLAMA_API_KEY`, `LMSTUDIO_API_KEY`, `VLLM_API_KEY` or `LLAMACPP_API_KEY`; `*_HOST` values are never used as credentials.

Entered keys take priority, followed by the active OAuth credential or saved key, then environment lookup. Environment values are resolved for connection tests and model calls without being copied into settings or public state. Restart REA Studio after changing its inherited environment. Providers shows the source variable, without exposing its value.

### Agent control and Classic access

Open **MCP & Settings**, choose the local port and click **Enable MCP server**. **Connection config** supplies the URL and bearer-token header for a local Streamable HTTP client. The default is `http://127.0.0.1:19456/mcp`. The server starts off on every launch. **Disable MCP server** closes the listener; already accepted commands or model tasks can finish. Use Stop run to cancel a model task separately. **Reset access token** disables the listener and invalidates the previous token for future connections.

Agents can send source files directly with `studio_import_code`, inspect projects, read/write files with conflict checks, run commands, start and inspect tasks, call the static REA tools, export specifications and run oracle checks. The menu shows recent actual tool calls. Imported code appears as a new project with an **Open received code** notice; it can be opened for analysis or coding assistance without replacing unsaved editor work. Provider credentials and MCP settings are not exposed as MCP tools. See [MCP connection and tool reference](docs/MCP.md).

**Classic interface** is collapsed inside the same menu. It opens your earlier installed Classic app with `--classic` in a separate profile, copying provider settings only on the first launch. Choose the earlier executable if it is not beside the current installation. Classic assets are not part of this release.

### A minimal coding task

In an empty test project, select **Code** and submit:

> Create hello.txt containing exactly Hello from REA Studio followed by a newline. Then use PowerShell to read it back. Report the observed output. Do not change any other file.

Expected result: a real `hello.txt`, a write event, a command event with exit code 0, and a final response describing the observed text. Model behaviour varies; use the Activity panel and actual file contents as the evidence. The app does not substitute a simulated successful run.

## Working in the playground

- **Overview** contains the task and final answer. Run history is saved on the left.
- **Code** shows the selected file. Ctrl+S saves; Tab inserts indentation. Unsaved edits are checked before changing files or starting a task.
- **Changes** shows Git diffs and new files. Use the terminal or your usual Git client to stage, commit, branch, or push.
- **Terminal** accepts non-interactive PowerShell commands. It is not a persistent shell session: each command starts a new process in the project folder.
- **Activity** records model requests and actual operations. Open an entry to inspect its details.
- **Stop run** prevents the next step after the current request or tool finishes. It does not promise instant cancellation of an in-flight model request or Ghidra operation.

A run is limited to 20 model/tool iterations. Editor files are limited to 2 MiB of UTF-8 text. Agent reads can page smaller ranges. Shell commands time out after 180 seconds; captured output is bounded. Interrupted runs are recorded as interrupted on restart.

## Reverse engineering with REA

[REA — Reverse Engineer Anything](https://github.com/morluto/rea) is integrated as a packaged stdio MCP plugin. REA Studio keeps one process alive across calls so the active target and live Evidence IDs survive consecutive analysis operations.

### Bundled components

| Component | Pinned version | Purpose |
| --- | --- | --- |
| REA (`rea-agents`) | 6.8.0 | MCP tool catalog, analysis coordination, and evidence contracts |
| Node.js | 24.22.1, Windows x64 | Runs REA |
| Ghidra | 12.1.4 | Native import, function analysis, and decompilation |
| Eclipse Temurin JDK | 21.0.12.1+1 | Runs Ghidra and its Java tooling |

The plugin receives its own `JAVA_HOME`, `GHIDRA_INSTALL_DIR`, and `PATH`. It does not alter system Java, install global npm packages, or register itself in other MCP clients. Ghidra's headless heap limit is 1536 MiB; total application and analysis memory can be higher.

### Typical workflow

1. Open **Reverse engineering** and click **Connect REA**.
2. Choose an EXE/DLL or a JavaScript application folder with **File…** or **Folder…**. Use a file/folder you are authorised to analyse.
3. Use a quick action such as **Open native target**, **Imports**, **PE resources**, **.NET metadata**, or **JavaScript / Electron**. Review the real advertised JSON input schema and arguments, then click **Run analysis**. **Open native target** starts Ghidra in the background; it does not open a separate Ghidra desktop window.
4. For native work, open the binary and click **Functions**, then **Run analysis**. A paged table shows actual retained functions; click **Decompile** beside a local function to retrieve its code. External imports are labelled separately. **Strings** provides a search field and rejects empty input before calling REA. Guided fields and the advanced JSON editor stay in sync; refreshing the catalog preserves your arguments. A successful `open_binary` call alone does not prove that deeper native analysis succeeded.
5. Read **Evidence & recovered code**, including limitations. **Complete result** contains the entire retained MCP response. For large live views, use `inspect_analysis_view` with the returned reference to retrieve additional pages.
6. Use **Use in task** to supply a saved analysis record to the coding agent. **Enable analysis tools for this task** grants the agent the static-analysis subset, saved records, and the separately enabled debugger/specialist integrations. Ask mode reads debugger observations; Code mode also permits its bounded execution controls.
7. **Export JSON** writes a saved result to a selected folder. **Close target** releases the current live target.

The interactive catalog comes from the running REA version, not a fabricated tool list. It can show tools unavailable on your operating system or without optional engines. Commercial tools, Frida, Linux runtimes, and mobile toolchains are **not** included or automatically licensed. The coding agent's subset excludes runtime attachment, target execution, extraction, and patching operations; the manual catalog may expose additional tools when REA advertises them.

**Windows native Ghidra support is REA's experimental P0 lane.** The verified path is static analysis of supported PE files on fixed local NTFS storage. Decompilation is an approximation, not recovered original source. Saved JSON records remain after restart; REA's live retained references require the original MCP session.

### Rebuild a feature or application

1. Create a separate destination folder outside the original application's folder, then open it as a project. Keep the original artifact outside that destination.
2. Select the original artifact in **Reverse engineering**. Expand **Rebuild a feature or application**.
3. Choose **Selected feature** or **Whole application · staged rebuild**. Describe what must match. Add observed screens, input/output examples, data formats and edge cases when you have them.
4. Click **1 · Prepare analysis**. This prepares an **Ask** task with REA enabled. Review it and click **Start task**. The agent gathers available static evidence and produces a brief: feature inventory, behaviour contracts, dependencies, evidence references, assumptions, unknowns, milestones and tests. A full application often requires several focused analysis runs.
5. Review the completed brief in Overview. Return to Reverse engineering, select it, and click **2 · Save SPEC & prepare build**. This saves a dossier and prepares a **Code** task with REA disabled. The implementation run works from `SPEC.md` and project code. If you select an existing saved specification, it reuses your edited SPEC.
6. The new `quixi-reconstruction-<UUID>` folder contains `SPEC.md`, `oracle-cases.json`, `manifest.json` with record hashes and user observations, a coverage checklist, and original REA responses for the selected artifact. Failed records remain failed; other artifacts' evidence is excluded. **Save evidence dossier** also works before the brief is complete.
7. Add explicit oracle cases with supported expected outputs and their sources. In Code mode, click **3 · Run oracle checks**. Inspect the actual comparison report; an empty suite is **unverified**. **4 · Prepare retry** creates a repair task based on failures. Continue feature by feature, keeping uncovered requirements explicit.

Read [the reconstruction and oracle guide](docs/RECONSTRUCTION.md) for the exact case schema, output comparison rules, saved report format and implementation/analysis separation.

The static agent tools cover native functions, call paths, strings, imports/exports and resources; managed metadata, members and native boundaries; and JavaScript application graphs. Their availability depends on the artifact and running REA version. The agent uses the live schemas and cannot assume every catalog tool is usable on Windows.

This is a workflow for **functional reconstruction**, not a promise of exact original source or a one-click duplicate. Static tools cannot establish every UI interaction or recover unavailable servers, external data, dynamically generated content or bytes absent from the file. The workflow records those gaps and requests the observations needed to test them. It does not automatically run the original application or perform runtime unpacking. Rebuild only software or features you are authorised to work with, and keep applicable third-party rights and licenses intact.

### Supporting toolchain

Open **Toolchain** for the analysis core, mobile/.NET, binary, runtime/network and rebuild/verification layers. The core REA/Ghidra runtime and matching REA workflow guides are bundled. The optional installer can obtain pinned portable JADX, the headless JADX MCP engine, Apktool, ILSpy, radare2, x64dbg, ImHex, dnSpyEx, Rizin and RAD Debugger releases with verified SHA-256 checksums.

IDA Pro needs an existing licensed installation and compatible MCP registration. Frida and angr use separately configured environments. GhidraMCP is an optional separate GUI extension/server; REA already supplies the bridge used by this app. A file being found does not prove successful provider analysis. See [the complete integration table and setup guide](docs/TOOLCHAIN.md) for what is included, optional, and independently configured.

### Use an existing REA installation

Select **Existing REA wrapper** to run `%USERPROFILE%\.local\bin\rea.cmd` with the argument `mcp`. The wrapper must already work under your Windows account. Switching runtimes closes the preceding analysis session, and the app uses the selected version's own catalog and schemas. Select **Bundled REA** to return to the packaged runtime.

## Data, access, and privacy

| Location | Contents |
| --- | --- |
| `%USERPROFILE%\.quixi` | Provider configuration, local credentials, projects, runs, and analysis records |
| `%USERPROFILE%\.quixi\playground\analysis` | Saved REA responses, arguments, target paths, timestamps, and evidence |
| `%LOCALAPPDATA%\QuixiDesk\WebView` | WebView2 profile and UI preferences |
| Selected project folder | Files you or the coding agent edit |

Provider credentials use the inherited local configuration storage and are **not encrypted by this application**. Treat the data directory as sensitive. The UI masks keys and omits raw credentials from public provider state; that is not encryption of files on disk.

Code mode runs with your user permissions and is **not an operating-system sandbox**. File editor operations enforce project containment and reject unsafe Windows paths, but an authorised PowerShell command has the access of your Windows account. Model requests can contain prompts, source text, commands, and analysis results and are sent to the provider you select. An offline model endpoint is required for a wholly local AI workflow.

The optional MCP server starts disabled and listens only on 127.0.0.1 when you enable it. MCP & Settings contains connection details and an optional launcher for an earlier installed Classic app. The current shell does not serve legacy EIPC routes. Native APIs reject foreign browser origins. WebView2 remote debugging is off unless you explicitly enable it for a development/test instance.

Optional environment variables, set before launching:

| Variable | Purpose |
| --- | --- |
| `QUIXI_DATA_DIR` | Override the data directory; useful for isolated tests. |
| `QUIXI_WORKSPACE_DIR` | Override the default workspace directory. |
| `QUIXI_RESOURCES_DIR` | Override the resource directory during development. |
| `QUIXI_BENCH_URL` | Optional HTTP(S) URL opened by **Open browser playground**. No default private address is included. |
| `QUIXI_DEVTOOLS=1` | Allow development tools in a release build. |
| `WEBVIEW2_USER_DATA_FOLDER` | Separate WebView2 profile for tests. |
| `WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS` | Advanced WebView2 options, including an explicitly enabled test debugging port. |

Do not publish your data directory, API keys, token-bearing URLs, private projects, or analysis evidence with the application.

## Build from source

Install [Rust via rustup](https://rustup.rs/), [Visual Studio C++ Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/) with the MSVC x64 compiler and Windows SDK, and Git. `rust-toolchain.toml` pins Rust 1.98.0. Node is downloaded for the REA bundle; a development Node installation is needed only for the JavaScript validation scripts.

```powershell
git clone https://github.com/xak1234/REAstudio.git
cd REAstudio
cargo build --release --workspace --locked
.\scripts\prepare-rea-windows.ps1
.\target\release\REAStudio.exe
```

To produce a complete distributable:

```powershell
.\scripts\package-windows.ps1
```

The script builds the locked workspace, obtains pinned/checksummed runtimes, installs REA with the npm lockfile, copies only the public application resources, collects dependency notices and corresponding source, generates a file hash manifest, and creates the versioned ZIP and SHA-256 sidecar in `dist`.

`-SkipBuild -SkipDependencyDownload` packages an already prepared checkout. `-NoZip` leaves only the staged folder. `-BuildOutput` can point at a separate Cargo release output folder. Existing output directories are not overwritten. The prepare script restores its process PATH and does not change system environment variables.

### Validate changes

```powershell
node scripts/audit-public.mjs
node --check resources/playground/app.js
node scripts/check-analysis.cjs
node scripts/check-reconstruction.cjs
cargo check --workspace --all-targets --locked
cargo clippy --workspace --all-targets --locked
cargo test --release -p quixi-platform --locked
cargo test --release -p quixi-workspace --locked
cargo test --release -p quixi-engine playground::tests --locked
cargo test --release -p quixi-engine analysis::tests --locked
cargo test --release -p quixi-engine reconstruction::tests --locked
cargo test --release -p quixi-engine providers::tests --locked
cargo test --release -p quixi-app mcp_server::tests --locked
```

Clippy warnings inherited from shared upstream modules may remain; a successful check is not a claim that all upstream warnings were removed. The entire legacy test suite is not used as a Windows compatibility claim.

For a real WebView2/Ghidra end-to-end check, follow [docs/TESTING.md](docs/TESTING.md). It uses an isolated profile and a compiled native fixture; it does not mock MCP or pretend to run a model. Live model tests require a separately configured provider and are not run by public CI with anyone's credentials.

## Additional analysis sources and specialist models

**Reverse engineering → Analysis source** lists detected tools. REA, Ghidra, configured IDA and the JADX MCP provider use their live REA tools. x64dbg uses its optional Automate bridge. Other detected tools contribute exported UTF-8 reports, logs, JSON or decompiled source through **Import exported results**. Detection is bounded to configured paths, portable folders and PATH; use **Toolchain → Choose path** for another installation. Installed files alone do not produce a green Connected indicator.

For x64dbg, choose **Prepare bridge setup** and run the prepared command in a project terminal. Python 3.10+ is required. The installer keeps its Python environment and plugins app-local. Enable the connection, then explicitly start the selected EXE/DLL or connect an existing debugger PID. Read registers/memory/disassembly and control breakpoints/stepping through the live schema. Disabling leaves the debugger open. See [toolchain details](docs/TOOLCHAIN.md).

Open **Decompilation assistant · LLM4Decompile**, choose a specialist provider and **Discover models**. Select the served model, its Ref V2 or End V1.5 input profile, and enable specialist requests. Select a different **Driving agent model** to coordinate the investigation. **Prepare task for driving model** prepares an Ask task; **Request specialist suggestion** calls the specialist directly. The specialist uses raw `/completions` prompts and leaves the main provider/model selection unchanged. It does not download models. Ref expects Ghidra pseudo-code; End expects prepared assembly. Generated suggestions keep the source record, input hash, model, completion status and unverified label. Compile and test them separately. Windows compatibility is not established by LLM4Decompile's Linux x86-64/GCC benchmarks.

Green **Connected** labels reflect active MCP connections, successful REA provider observations, or the specialist's last successful completion. Opening a binary prepares its provider; a function listing, decompilation or other provider result must succeed before its label becomes green. Closing or reopening a target, or a failed analysis check, clears the provider labels. They are connection state, not proof of complete analysis or correct generated code. Recheck after changing or restarting an external tool.

## GitHub deployment

This is a native Windows application. **GitHub Pages cannot host or execute it.** Deploy by publishing the portable ZIP as a GitHub Release asset.

The included workflow checks source, builds on `windows-2022`, runs the focused tests, and uploads a full Windows package for pushes to `main`, version tags, and manual runs. Pull requests run checks without publishing a package or using provider credentials. Version tags create a **draft release** containing the ZIP and checksum for a maintainer to review and publish.

See [docs/RELEASING.md](docs/RELEASING.md) for the exact version/tag procedure, asset verification, and manual release commands. The source tree contains dependency manifests rather than prebuilt runtimes. Release assets include the runtimes, notices, dependency inventory, and source material needed for redistribution.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| App does not open | Install WebView2, use Windows x64, extract the complete ZIP, and verify its checksum. |
| Missing resources or bundled REA | Keep the extracted folder together; do not copy only the EXE. A source checkout needs the prepare script. |
| Git panel is unavailable | Install Git for Windows, restart the app, and open a Git repository. |
| Provider test fails | Check the base URL, `/v1` suffix, server reachability, and credentials. Check the provider's actual error. |
| Model is listed but tasks fail | Check that it can be loaded and supports chat/completion requests; choose its exact advertised ID. |
| Task reaches the iteration limit | Inspect Activity, reduce task scope, or select a model that follows structured tool instructions more reliably. |
| Ghidra or Windows containment error | Use the bundled runtime, a supported PE target on fixed local NTFS, and run as your normal desktop account. Read REA's returned remediation. |
| A catalog tool is unavailable | Inspect its reported provider/platform requirements. Inclusion in the catalog is not proof of availability. |
| PE resources: `Resource range is not entirely file-backed in one section` | Some resource entries refer to bytes absent from the file-backed section. This can occur with packed or runtime-populated resources. Changing the path will not supply those bytes. Use **Prepare native analysis**, then **Run analysis**, and inspect native functions/imports while recording resource recovery as incomplete. This message alone does not prove the entire executable is invalid. |
| Save SPEC & prepare build is disabled | Finish an Ask analysis brief for this project and artifact, or select a saved specification; failed or unrelated runs are not eligible. |
| Oracle checks are unverified | Declare cases with supported expected outputs. Zero cases never counts as success. |
| Old Evidence ID no longer resolves | Read the saved JSON record or reopen/reanalyse the target in a new live session. |
| Save reports a conflict | Reload the file and reconcile the external edit; the app preserves the other writer's changes. |
| Browser playground button reports a missing URL | Set `QUIXI_BENCH_URL` to your own playground URL and restart. |

Report reproducible bugs with the release version, Windows version, operation, and redacted error text. Do not include credentials or private binaries in a public issue. See [SECURITY.md](SECURITY.md) for vulnerability reporting.

## License and credits

QuixiDesk-derived code and this edition's changes are distributed under the [MIT License](LICENSE), with the QuixiAI copyright notice retained. REA-authored code is MIT; Node, Ghidra, Temurin, Rust crates, npm packages, and runtime DLLs retain their respective licenses and notices. The application license does not replace those third-party terms or grant rights to the software you analyse.

Thanks to [QuixiAI/QuixiDesk](https://github.com/QuixiAI/QuixiDesk), [morluto/rea](https://github.com/morluto/rea), the Ghidra project, Eclipse Adoptium, and the tao/wry community.
