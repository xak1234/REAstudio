# Toolchain and integration boundaries

Open **Reverse engineering → Toolchain** to inspect the actual files found and choose paths. Detection checks the portable tool directory, configured paths and PATH; it does not launch tools or claim their providers are ready. Use **Prepare version check** and Run in Terminal to verify a CLI. GUI launch opens the tool without passing the selected artifact or starting it under a debugger.

| Layer | Component | Integration in this edition |
| --- | --- | --- |
| Analysis core | [REA](https://github.com/morluto/rea) | Bundled stdio MCP, live catalog, persistent sessions and evidence. |
| Analysis core | [Ghidra](https://github.com/NationalSecurityAgency/ghidra) | Bundled headless REA provider; optional GUI launch. |
| Analysis core | [GhidraMCP](https://github.com/LaurieWired/GhidraMCP) | Optional separate GUI extension/MCP setup, linked from Toolchain. REA Studio uses REA's own Ghidra bridge; it does not register this second server automatically. |
| Analysis core | [ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp) | Your licensed IDA Pro. Optional app-local headless idalib bridge (pinned commit) with live schemas, a private persistent database per artifact and annotations; the same registration can serve REA's IDA provider. Attached GUI and REA's legacy attached profile remain supported. |
| Mobile & apps | [JADX](https://github.com/skylot/jadx) | Pinned portable CLI/GUI download; REA Android calls additionally require the supported headless JADX MCP JAR. |
| Mobile & apps | [Apktool](https://github.com/iBotPeaches/Apktool) | Pinned JAR download, launched with the bundled JDK from the terminal. |
| Mobile & apps | [Frida](https://github.com/frida/frida) | User-supplied frida-tools environment and explicit runtime targets; REA's manual runtime tools remain subject to their live availability. |
| Mobile & apps | [ILSpy](https://github.com/icsharpcode/ILSpy) | Pinned self-contained Windows GUI download. ILSpyCmd is a separate upstream CLI option. |
| Binary & low-level | [radare2](https://github.com/radareorg/radare2) | Pinned Windows CLI download, available through the terminal. |
| Binary & low-level | [x64dbg](https://github.com/x64dbg/x64dbg) | Optional Automate MCP connection, live schemas, explicit session selection, registers/memory/disassembly and bounded stepping/breakpoint controls. |
| Binary & low-level | [ImHex](https://github.com/WerWolv/ImHex) | Pinned portable Windows hex/pattern editor. |
| Binary & low-level | [angr](https://github.com/angr/angr) | Choose a Python interpreter from an environment where angr is installed; the panel prepares an import/version check. No generic Windows/Python compatibility claim is made. |
| Network & runtime | [mitmproxy](https://github.com/mitmproxy/mitmproxy) | User-supplied mitmweb/mitmdump for Windows. Saved captures can be analysed with advertised REA tools. No automatic interception setup. |
| Network & runtime | [dnSpyEx](https://github.com/dnSpyEx/dnSpy) | Pinned portable .NET debugger/editor download. |
| Network & runtime | [Rizin](https://github.com/rizinorg/rizin) | Pinned Windows CLI download. |
| Network & runtime | [RAD Debugger](https://github.com/EpicGames/raddebugger) | Pinned optional alpha Windows debugger download. |
| Rebuild & verify | REA workflows | Matching instructions/references ship inside rea-agents; read them in Toolchain or via the agent's `rea_workflow` action. |
| Rebuild & verify | [AI RE catalog](https://github.com/zhuyansen/awesome-ai-reverse-engineering), [RE catalog](https://github.com/morluto/awesome-reverse-engineering) | Reference links, not executable engines or a security guarantee. |
| Rebuild & verify | SPEC and oracles | Built-in specification export, real command/output comparison, saved reports and bounded retry tasks. See [RECONSTRUCTION.md](RECONSTRUCTION.md). |

## Portable optional downloads

The core release includes REA, Node, Ghidra and JDK. It includes the optional installer and pinned download catalog, **not all optional executables**. This keeps the core independent of additional tool licenses and platform environments.

From a source checkout:

```powershell
.\scripts\install-toolchain.ps1 -Tool jadx,jadx-mcp,apktool,ilspy,radare2,x64dbg,imhex,dnspy,rizin,raddebugger
```

From the extracted release use `Install-Toolchain.ps1`. The Toolchain panel can prepare a command for one component. Open a destination project before running the prepared command in Terminal.

Downloads use the exact official release URLs and SHA-256 digests recorded in `resources/toolchain.json`. They extract under `resources/toolchain/<id>` and refuse to replace an existing directory. Use `-Destination` for another root, then Choose path in the app. Preserve the upstream license and notice files. These files are ignored by Git and excluded from the core package; redistribution of an expanded tool collection requires its own component/source review.

The installer does not execute installers, add global PATH entries, register shell extensions, alter Java, install proxy certificates, or attach to processes. After installation, refresh detection and verify the tool. Windows SDKs, Python/.NET environments, device/emulator setup and project compilers remain separate prerequisites where required.

## REA runtime identity and resource settings

Use **REA runtime settings** to select the bundled or existing external REA runtime and set analysis resources. Fresh profiles use the bundled runtime. An existing explicit external-runtime selection is preserved; installing a newer application does not silently switch its engine. The connection reports the actual MCP server identity and live catalog count separately from the bundled component manifest. External Ghidra/Java versions must be checked in returned analysis provenance or the external launcher's configuration; the bundle manifest does not describe them.

Settings are persisted in the application's `rea-plugin.json`:

| Setting | Default | Accepted range |
| --- | --- | --- |
| `ghidraHeapMiB` | 4096 MiB | 512–65536 MiB |
| `ghidraStartupTimeoutSecs` | 900 seconds | 60–7200 seconds |
| `callTimeoutSecs` | 1800 seconds | 30–14400 seconds, at least the startup timeout |

Choose a heap that fits available RAM alongside the application, model server and target workload. Increasing it is a resource allowance, not a guarantee that any particular binary will complete. Ghidra startup uses the saved timeout; an analysis call may need additional time after import. The advanced `QUIXI_REA_CALL_TIMEOUT_SECS` environment override remains available for values from 30 to 14400 seconds. The status reports when it overrides the saved value, rejects invalid values in favour of the saved setting, and warns when it is shorter than startup.

Saving changed settings disconnects the current REA session and stops its owned process tree. Reconnect and reopen the artifact before continuing; ephemeral Ghidra annotations and live retained references belong to the old session. Saved evidence remains available. Settings cannot change while a new connection is starting: disconnect and retry. A failed settings write leaves the current configuration unchanged. Existing mode-only preferences receive the resource defaults. Malformed settings are kept on disk and reported; review and save settings explicitly before connecting.

The local application route `rea/settings` reads settings with `{}` and accepts a partial object containing `mode`, `ghidraHeapMiB`, `ghidraStartupTimeoutSecs` or `callTimeoutSecs`. Unknown fields and invalid values are rejected. This route is for the trusted desktop interface; it does not expand the external MCP control catalog.

## IDA Pro

IDA is used in three independent ways. All need your own licensed IDA Pro; REA Studio does not install IDA, accept its license terms, claim IDA Free is equivalent, or read license details. Select the original input binary, never an IDB/I64, as the artifact.

### Headless bridge (recommended)

Requires IDA Pro 9.x with idalib (`idalib.dll`) and Python 3.11+. From a source checkout run `scripts/install-ida-bridge.ps1 -PythonExecutable <python.exe>`, or `Install-IDA-Bridge.ps1` in a packaged release. `-IdaDirectory` defaults to the newest `C:\Program Files\IDA Professional *` containing `idalib.dll`; `-Destination` defaults to `resources\toolchain\ida-headless`. The installer creates its own virtual environment and installs IDA's bundled `idapro` wheel, `tomli-w==1.2.0` and `ida-pro-mcp` from the pinned commit `c133c3853faa111a9b00ee615c013b720d0c4acd` (the commit REA 6.8.0's headless profile is verified against). The idalib activation record is written inside the destination, not to your IDA profile. It verifies `import idapro` and `idalib-mcp --help`, then writes `rea-headless-registration.json` (`idalib-mcp --stdio --max-workers 1`, `IDADIR`) and `rea-ida-install.json` with the installed versions. It refuses non-empty destinations it did not create. No global Python package, PATH, IDA plugin, IDA install file or MCP-client registration is changed. Choose another registration JSON as **IDA headless registration** in Toolchain if you installed elsewhere.

In **Reverse engineering** the bridge starts disabled on every launch. **Enable** starts `idalib-mcp` inside a kill-on-close Job Object (its idalib workers cannot outlive REA Studio) and loads the live tool schemas. **Open** copies the selected artifact to `%USERPROFILE%\.quixi\ida\<sha256>\<file name>` (only when not already present with the same hash) and opens that copy, so the `.i64` and every rename, comment and type persist across sessions without anything being written beside the original. **Close** saves and closes the database; accepted annotations are also saved immediately. IDA handles one call at a time: **Enable**, **Disable**, **Open** and **Close** wait for an in-flight IDA call to finish or reach its timeout (up to 5 minutes for most tools, 15 minutes for opening a database) before they take effect.

Each call re-checks that the selected artifact is the bound one with unchanged content, injects the bridge's database ID, and saves the response as `ida-bridge` evidence (tool, arguments, response, target, SHA-256) for history and reconstruction dossiers. Tools are classified from the live catalog:

- **Read** (decompile, disassembly, xrefs, callees, functions, globals, imports, strings, types, survey…): UI, Ask and Code tasks, and external MCP agents.
- **Annotate** (rename, comments, bookmarks, types, stack variables, code/function/data definitions, `idb_save` in place): change only the private database. Allowed in Ask and Code mode while **Allow annotations** is on (default).
- **Blocked**: Python evaluation, byte/assembly patching, integer writes, debugger tools, `idb_open`/`idb_close`/`idb_list` (managed by the bridge) and any unreviewed tool whose description does not explicitly state it is read-only. Registrations using upstream's `--unsafe` are refused.

### Attached GUI

A current ida-pro-mcp GUI plugin serving Streamable HTTP can be attached by URL (default `http://127.0.0.1:13337/mcp`; only `127.0.0.1`, `localhost` and `[::1]` are accepted). Opening reads IDA's `ida://idb/metadata` and is refused unless its input SHA-256 matches the selected artifact; each call also checks that IDA has not switched database. The GUI database belongs to you: Close detaches without closing it. The legacy ida-pro-mcp 1.4.0 plugin does not speak MCP over HTTP and is not usable here; it remains REA's attached profile below.

### REA's IDA provider

REA's IDA adapter (14 read-only operations) uses the registration in Toolchain **IDA Pro MCP registration** (`ida`), passed as `REA_IDA_MCP_CONFIG` only to the REA child process. The headless registration above works as REA's headless profile: **Register for REA** writes it to `ida` and keeps the previous value as `ida-attached-previous`; **Restore attached** puts that value back. Disconnect and reconnect REA after either change, then select **IDA** as Native analysis provider. An existing attached profile (legacy ida-pro-mcp 1.4.0 with its IDA plugin, following [REA's IDA provider guide](https://github.com/morluto/rea/blob/main/docs/ida-provider.md)) keeps working unchanged. Readiness and analysis are established by real calls, not by the presence of a JSON file.

## Android provider

Installing the ordinary JADX CLI is useful independently but does not satisfy REA's headless provider contract. Install the pinned headless engine with `Install-Toolchain.ps1 -Tool jadx-mcp`, or choose an existing supported JAR under **JADX MCP JAR**. The standard portable location is discovered when the bundled REA starts. REA Studio passes it as `REA_JADX_MCP_JAR` to REA, with the bundled full JDK. Restart the REA connection after changing the path. Read the matching Android workflow and live tool availability before calling package/class/method analysis.

## Runtime tools

Frida, debuggers and traffic proxies serve different jobs. Configure and invoke the one needed for a defined observation. Do not interpret a tool's catalog listing as successful capture, decompilation or observation. Import retained results into your investigation, record their provenance, and turn supported observations into SPEC requirements and oracle cases.

## Analysis source selection and x64dbg

The source selector is generated from actual configured/portable/PATH tool files. Reference catalogs and workflow files are excluded. Installed standalone tools (including ILSpy, dnSpyEx, ImHex, radare2, Rizin, RAD Debugger, Frida, angr, Apktool and ordinary JADX) can supply exported text reports. This does not imply an automation API for each GUI. Imports preserve SHA-256, file path, timestamp and an explicit unverified user association with the selected artifact. Imported reports, static REA evidence and live x64dbg observations remain distinct in the shared history and reconstruction dossier.

Run `scripts/install-x64dbg-bridge.ps1 -PythonExecutable <python.exe>` from source, or `Install-X64dbg-Bridge.ps1` in a packaged release. It uses the pinned x64dbg download, Automate plugin 0.8.1-ghost_fungus (both architectures, verified hashes), and Python client `x64dbg_automate[mcp]==0.9.2` in its own environment. The installed dependency versions are recorded. Existing different plugin files are preserved. No global Python package, PATH or MCP registration is changed. Choose the generated `x64dbg-automate-mcp.exe` in Toolchain if using another destination.

The bridge starts disabled on every app launch. Enabling discovers actual MCP schemas without starting the target. **Start selected target** executes the selected EXE/DLL under x64dbg; **Connect selected session** takes the debugger PID, not an arbitrary target PID. A preexisting debugger can attach to an application through its own UI. Each data/control call checks the actual debuggee process path against the selected artifact. A debugger session with another target cannot silently contribute data to this artifact.

Ask tasks can read status, registers, bounded memory, memory maps, disassembly, symbols, annotations and breakpoints. Code tasks and external authenticated MCP agents can also pause/resume, step and manage breakpoints. Session selection, enablement, raw commands, remote connections and arbitrary patching are not exposed in this bridge's agent tools. Existing Code shell access retains its documented Windows-user permissions. Disabling or closing REA Studio leaves the debugger and debuggee open; accepted operations may finish. Timed-out operations are not automatically retried because their effects may already have occurred.

Green Connected labels show the bridge connection and identify opened native providers. A selected debugger session is a separate status; no-debuggee/error responses remain failures. Model suggestions have a separate last-success connection indicator and never count as runtime observations.
