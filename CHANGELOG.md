# Changelog

## 1.5.0 — 2026-10-30

### PE import reconstruction
- Replace the raw-memory-only unpacker with a two-stage capture and reviewed import-rebuild workflow. Keep original IAT slot RVAs; emit DLL descriptors, lookup tables and named/ordinal thunks in a new `.reaiat` section for PE32 and PE32+.
- Resolve exact exports from the paused process, retaining module/process identity, hashes, forwarders, aliases and unresolved or ambiguous slots. Keep 32-bit and 64-bit forwarder identities separate in WOW64 captures; exclude unaddressable native modules and validate read ranges before calling the 32-bit bridge.
- Use the actual loaded image base and explicit OEP VA/RVA inputs. Heuristic prologues remain candidates; unreviewed entry points/ranges and incomplete captures cannot report a completed import rebuild.
- Save hashed memory/capture evidence and a review plan for offline reconstruction. Reject mismatched hashes, incomplete slot selections, unsupported layouts and attempts to overwrite source/evidence files.
- Correct PE section/file alignment and entry-point writes. Preserve captured resources, report relocation/TLS/Load Config/delay-import limitations, and distinguish structural validation from successful execution or portability.

### Integration and verification
- Fix the packaged PowerShell launcher path and argument quoting; support offline plans and optional elevation without a CMD shim.
- Detach the owned debugger client after failed shutdown or an exited debugger so its event thread cannot keep the capture process alive.
- Package all reconstruction modules and refresh the bundled unpacking instructions even when dependency downloads are skipped. Make that guide available in the Toolchain workflow selector.
- Add format-fixture regression tests, pinned Python lint/type validation, and a real Windows x86/x64 compiler/debugger/loader test using owned fixtures. Runtime receipts establish those fixtures only, not arbitrary packed application recovery.

## 1.4.0 — 2026-10-28

### Workspace usability
- Add same-page navigation for analysis, saved evidence, investigations, reconstruction and advanced tools; collapse secondary setup and reconstruction controls by default.
- Make Files and Task settings panels collapsible at desktop sizes with remembered preferences, and use dismissible overlays on narrow windows.
- Keep the selected Agent model and Ask/Code mode visible beside task controls, with direct access to settings.
- Put raw argument/schema editors behind explicit controls while retaining individual disclosures and revealing arguments required by a selected tool or validation error. Preserve technical tools, evidence and native-close protections.

### Multi-artifact investigations
- Save named, immutable sets of local files with SHA-256 identities, scoped to the current project. Inspect each file's current, changed, missing or unavailable state and its matching, excluded, failed and model-suggestion evidence counts.
- Export staged, version-pinned evidence bundles with original saved records, raw-record hashes, exclusion reasons and explicit modules with no evidence. Recheck every artifact before publishing; refuse changed inputs, empty overall evidence or exceeded bounds without replacing earlier bundles.
- Stream artifact hashes with per-file and aggregate limits, bound history scans, and reject ambiguous or reparse-based paths. Preserve the existing single-artifact analysis and reconstruction workflow.
- Add desktop investigation controls and the project-scoped `studio_investigation` MCP tool. Deleting metadata requires explicit MCP confirmation and preserves source files, evidence and exported bundles.

### Native window close
- Negotiate native close requests with the editor: cancel, save and close, or close without saving. A failed or conflicting save leaves the editor open.
- Warn about active backend work even when it was started outside the current UI; include synchronous commands and investigation operations.
- Validate close request identities and reject stale or unsolicited replies. An unresponsive renderer falls back to a native confirmation that defaults to keeping the app open.

### Verification
- Add focused investigation integrity tests and a dedicated CI suite, plus genuine UI/MCP investigation and native-window-close smoke scripts.
- Add an optimized source-known fixture with 2,304 generated functions and no application exports, COFF symbol table or debug directory. Its optional runtime baseline and real IDA paging/string-reference discovery report separate results; it is not a production-scale or general symbol-recovery benchmark.

## 1.3.0 — 2026-10-28

### Investigation integrity
- Capture file artifact SHA-256 before and after analysis; retain changed-target failures and group history by artifact version.
- Filter reconstruction dossiers and analysis briefs by verified file identity, explicitly recording legacy/different-version exclusions without deleting evidence.
- Preserve runtime cancellation when analysis is serialized.

### Runtime and agent reliability
- Add persistent Ghidra memory, startup and call timeouts with validation, atomic writes and live server/version diagnostics.
- Qualify model selection by provider, reconcile stale defaults, budget context conservatively and save investigation checkpoints without automatically replaying commands.

### Behavioural verification
- Add bounded file existence, SHA-256, exact text and structural JSON assertions, per-case timeouts and up to 256 cases within a two-hour planned budget.
- Propagate oracle cancellation to child processes and add Stop checks for direct UI suites.
- Show the actual nested oracle expectations before approval.

### Validation
- Include IDA, debugger, decompile and MCP unit coverage in CI with explicit passed/failed/ignored receipts.
- Correct the UI oracle approval smoke sequence and add an optimized source-known C++ EXE/DLL benchmark with optional runtime baseline.
- Mark licensed live tests explicitly ignored unless requested, then require their configured backend.



The initial Windows edition includes a reconstruction workflow for selected features or staged application rebuilds, saved task handoff, evidence dossier export, and actionable guidance for PE resource ranges that are not file-backed.

## 1.2.0 — 2026-10-28

### IDA Pro
- Add `Install-IDA-Bridge.ps1`: app-local ida-pro-mcp pinned to commit c133c385 plus the licensed IDA's idalib, a headless REA registration and a version manifest. IDA's installation, plugins and other MCP clients are unchanged.
- Add the IDA bridge (headless idalib or attached loopback GUI): live IDA tool schemas, identity binding to the selected artifact, a private persistent IDB per SHA-256, evidence records for every call, read/annotate/blocked tool classes (patching, Python evaluation, debugger and database-management tools are never exposed), automatic save after annotations, and Job Object ownership of its processes.
- Expose the bridge in the Reverse engineering panel, to the coding agent (`ida_tools`/`ida` actions) and over MCP (`studio_ida_status`, `studio_ida_call`). Switch REA's own IDA provider between the headless registration and the previous attached registration.

### Guided reverse engineering
- Show workflow stages and the next required action or missing configuration from actual state and saved records, with inline prompts after each operation and prerequisite checks for quick actions.
- Inventory filter and search, row actions for decompile/callers/callees/xrefs (REA or IDA), highlighted and navigable pseudocode with history, rename/comment, filtered history, lazy rendering of large results and an oracle review dialog.

### Analysis sessions
- A timed-out REA call is cancelled with `notifications/cancelled` instead of killing the session; the call timeout is configurable (`QUIXI_REA_CALL_TIMEOUT_SECS`, default 1800 s). Disconnect, close and runtime switch interrupt in-flight calls immediately.
- Own REA, Ghidra/Java, idalib and command process trees with kill-on-close Job Objects. Skip stray non-JSON output lines instead of failing the session.
- Attribute evidence to REA's actual open binary, close the previous binary on target change and canonicalize stored targets. Clear provider indicators only for that provider's failures. Index saved records instead of reparsing every record.
- Correct the agent's REA tool set to the live 6.8.0 catalog (adds xrefs, batch_decompile, list_names, list_segments, resolve_containing_procedure, address context and session annotations) with a catalog test.
- Paging and inventory views no longer save history records or reconnect REA (`persist:false`).

### Agent and providers
- Simplify model selection into Connections and two roles: one **Agent model** that runs every task and calls tools, and an optional **Decompile helper** (LLM4Decompile) that is one of those tools. The separate driving-model picker is removed; the helper's input type is detected from the model name and it accepts IDA bridge decompile/disasm records.
- Configurable step limit (default 40, 1–100), output token limit (default 16384) and context budget; older results are compacted to references; new `edit`, `append` and `note` actions; malformed actions return to the model as errors.
- Stop aborts the in-flight model stream or command. Read errors, idle timeouts and length stops are reported as failures instead of completed answers. HTTP errors show status and a redacted excerpt; 429/5xx are retried with backoff. No silent model substitution.
- Oversized tool results are cut at JSON boundaries with retained-reference paging guidance. Atomic run/project writes; corrupt files are quarantined.
- Risky agent commands (recursive/forced deletes, destructive Git operations, disk/boot/registry/policy/power commands, writes to system folders, download-and-execute, encoded/Base64 PowerShell, `Invoke-Expression` of dynamic content, piped or splatted deletes, clustered cmd switches such as `/s/q`, `Start-Process -Verb RunAs`) wait for the user's approval (`confirmCommands`: `risky` by default, `all`, `never`; `run-approve`/`run-deny` must name the pending `command`, otherwise "The pending command changed; review it again"; status `awaiting_approval` with `pendingCommand`). Denials reach the model as a tool result. MCP runs accept `confirmCommands` but cannot approve. The classifier is a pattern check, not a sandbox.
- Per-run change sets: the first agent write/edit/append to a file snapshots its pre-image in application data; runs list `changes` with before/after hashes and a conflict flag, `run-diff` shows a unified diff and `run-revert` restores pre-images (deleting created files) unless the file changed since, or with `force`. Reverted files show a "reverted" badge, cannot be reverted again and are not offered for a forced revert. Commands' file changes are not tracked.
- Follow-up tasks (`parentRun`) receive the earlier task's prompt, a bounded answer and its change list. Runs record `provider`, `startedAt`, `finishedAt` and `steps`.
- Agent writes, edits and appends keep an existing file's CRLF line endings and UTF-8 BOM.
- Saving a provider that needs a key no longer marks it configured without a resolvable credential (local/custom endpoints are unaffected). Detect local probes the configured base URL and keeps the selected model.

### Coding workspace
- Terminal commands stream output (`command-start`/`command-poll`/`command-stop`) in a Job Object with bounded head+tail buffers, up to 4 per project, and keep the working directory between commands while it stays inside the project. Agent and one-shot commands still start in the project root.
- Prefer PowerShell 7 (`pwsh.exe`) over Windows PowerShell 5.1 and report the shell used. The command wrapper places the command on its own lines (a trailing `# comment` no longer breaks it) and takes the exit status from the last statement (a stale `$LASTEXITCODE` no longer fails a later successful statement).
- Command output keeps the first 60% and the last 40% of its budget with an omission marker instead of only the beginning.
- Git panel: changed files with status, staged flag and line counts from `git status -z`/numstat (spaces, Unicode and renames handled), per-file diffs including untracked files, stage, unstage, discard (with confirmation) and commit (repository hooks do not run: `core.hooksPath=NUL`, because an empty value resolves hooks to the drive root). Pathspecs naming `.git` at any depth, in any case or through an 8.3 alias are refused. Diffs are bounded to 2 MiB with a `truncated` flag; a folder without Git returns an empty panel instead of an error.
- The editor reports `lineEnding` and `bom` and saves them back; creating a file over an existing path reports "File already exists"; empty new files can be created. `SafeFs` writes are atomic (temporary file and rename); a save replaces the file, so hard links are not preserved and a file held open without delete sharing cannot be replaced until it is closed. Files with mixed line endings are saved as LF, and the editor status says so.
- The file explorer lists the whole tree (no depth limit; the 2000 limit counts files only, with `truncated`) and applies `.gitignore` in folders that are not Git repositories.

### Reconstruction oracles
- Oracle suites run only after the user approves their exact SHA-256 (`oracle-preview`/`oracle-approve`, `studio_oracle_preview`). Approval is a user consent step: the agent's file actions and the MCP file tools cannot record one, and the agent's write/edit/append actions refuse dossiers and oracle reports during implementation. Approvals are kept in application data, which cannot be opened as, inside or around a project. Commands that run with the user's shell permissions (Code-mode `command`, MCP `studio_command`) are not confined by this and are not a security boundary.
- `argv`/`stdin` cases run programs directly with byte-exact comparison; a missing program fails a case.

### Security
- Skip Git integration for repositories whose own config defines command hooks, and harden every Git call (`core.fsmonitor=false`, no textconv/external diff, no optional locks).
- Reject UNC and device paths from the model before any file-system access.
- Make the legacy MCP host report real connection state and stop masking external failures.

## 1.1.1 — 2026-10-28

- Give the current release an exact, distinct version in the window, HTML interface, MCP identity, README and package metadata.
- Require a version increase for every delivered update, with a version-bump helper, release consistency checks and a CI gate against the previous main/base commit.
- Verify native-provider connection status from successful analysis evidence; opening a file alone does not turn its indicator green. Failed checks and target changes clear the indicator.
- Add a live attached-IDA check covering function listings, two decompilations, assembly, saved evidence and target identity rejection.

### Analysis integrations carried forward from V1.1

- Added detected analysis-source selection and green live connection indicators.
- Integrated optional x64dbg Automate MCP with explicit sessions, bounded observations/controls and durable runtime evidence.
- Added exported-report imports with source hashes and explicit provenance.
- Added a separate LLM4Decompile specialist, served-model discovery and a driving-model selector; suggestions remain unverified and source-linked.
- Extended the app MCP catalog to 24 tools and removed the 25-model discovery truncation.

## 1.1.0 — 2026-10-27

- Add an opt-in, token-protected local MCP control server with connection config, request activity and immediate listener disable.
- Agent code imports create separate projects for analysis or coding assistance, with an in-app handoff that preserves unsaved editor work.
- Keep Classic access inside the MCP/settings menu through the earlier installed application.
- Resolve missing provider API keys from matching environment variables for both tests and model calls, without persisting discovered secrets.

- Rename the application to REA Studio V1.1, including the window, executable, installer, shortcut and portable archive. Preserve existing settings and evidence paths.
- Add guided Strings and Decompile inputs with live-schema preflight, and retain arguments across catalog refreshes.
- Browse retained native function and string results with paging; decompile local functions directly from their real addresses. Label external imports and preserve incomplete discovery coverage.
- Keep analysis controls locked while a request or agent task is running.

## 1.0.0 — 2026-10-27

- Public Windows x64 coding playground with project explorer, editor, Git diffs, PowerShell, provider setup, and saved model runs.
- Bundled REA 6.8.0, Node 24.22.1, Ghidra 12.1.4, and Temurin JDK 21.0.12.1+1 with process-scoped configuration.
- Persistent MCP sessions, canonical schemas, static agent analysis tools, recovered code, and exportable evidence.
- Native Windows path handling, conflict-aware writes, structured coding responses, and background CLI window suppression.
- Clean public shell and resource set, configurable browser playground URL, reproducible build/release scripts, dependency notices/source, and full installation/development documentation.

The Windows Ghidra lane remains experimental. This is a single-agent playground, not a multi-agent orchestration or upstream Classic parity release.
