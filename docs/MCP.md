# REA Studio MCP control

Open **MCP & Settings** in the top bar. The server always starts disabled. Choose a local port (default 19456) and enable it. **Connection config** reveals the client URL and Authorization header; keep that token private. The setting does not modify other applications' MCP registrations.

This edition implements Streamable HTTP with JSON responses, compatible with protocol versions 2025-11-25, 2025-06-18 and 2025-03-26. It negotiates 2025-11-25 when a different version is offered during initialization. It does not offer a persistent SSE subscription, OAuth discovery or remote network hosting. Clients must support a configured bearer header. Use a local client on the same computer; a hosted ChatGPT connector cannot directly reach a loopback URL.

The listener binds only to `127.0.0.1`. Host and Origin headers are checked, and every HTTP request requires the token. It is stored in the existing data directory's `mcp-server.json`, alongside the selected port and optional Classic app path. It is never included in normal workspace state or exposed as an agent tool. The connection-settings view reveals it only when requested.

**Disable MCP server** closes the listening socket and rejects work not yet accepted. An already accepted shell command or analysis call can finish. Model tasks started earlier continue independently; use **Stop run** or `studio_stop_run` to request their cancellation. Re-enabling waits for previously accepted calls to finish. **Reset access token** disables the server and replaces the credential, so existing client configs must be updated. Restarting the app preserves the token and port but leaves the server off.

## Tools

| Tool | Purpose |
| --- | --- |
| `studio_analysis_sources` | Detected analysis sources, integration type and live connection status. |
| `studio_import_analysis` | Import an installed tool’s exported text report for the selected artifact. |
| `studio_debugger_status`, `studio_debugger_catalog`, `studio_debugger_call` | Inspect the optional x64dbg connection, obtain live schemas and use the user-selected session. |
| `studio_ida_status`, `studio_ida_call` | Inspect the optional IDA Pro bridge and call its live IDA tools on the selected artifact's private IDB. Read and (when the user allows) annotation tools only; patching, Python evaluation and debugger tools are never exposed. |
| `studio_decompile_status`, `studio_decompile_assist` | Read specialist configuration and request a source-linked, unverified LLM4Decompile suggestion. |
| `studio_state` | Projects, model configuration without keys, and run summaries. |
| `studio_open_project` | Register an existing absolute project directory. |
| `studio_import_code` | Receive source files as a new project for code analysis or coding assistance. |
| `studio_files`, `studio_read_file`, `studio_diff` | Actual project files (`truncated` when the 2000-file listing stopped early), content/hash with `lineEnding` (`crlf`, `lf` or `mixed`) and `bom`, and Git changes: `files` (`path`, `status`, `staged`, `additions`, `deletions`), working-tree `diff` and `staged` diff bounded to 2 MiB each with `truncated`. Outside a Git repository the lists are empty. |
| `studio_write_file` | Write with the hash from a preceding read; empty hash only for a new file (an existing path returns "File already exists"). Optional `lineEnding: "crlf"` converts LF to CRLF and `bom: true` prefixes a UTF-8 BOM; the returned hash is of the bytes written. |
| `studio_command` | Execute a bounded noninteractive command in the project root (PowerShell 7 when installed, otherwise Windows PowerShell 5.1; `shell` reports which). Output keeps the first 60% and last 40% of 128 KiB per stream. |
| `studio_start_run`, `studio_run_status`, `studio_stop_run` | Start a model task (optional `maxSteps` 1–100, `contextBudget` 50000–2000000 characters, `maxOutputTokens` 256–128000, `confirmCommands` `risky`/`all`/`never`, `parentRun` for a follow-up of an earlier task in the same project), inspect actual results, and stop it. Commands that need approval set status `awaiting_approval` with `pendingCommand`; only the user can approve or deny them in the desktop, and no MCP tool does. Run status includes `changes` (files the agent wrote, with `beforeHash`, `afterHash` and `conflict`), `provider`, `startedAt`, `finishedAt` and `steps`. |
| `studio_rea_catalog` | Available static REA names and session state, or one full live tool schema. |
| `studio_rea_select`, `studio_rea_call`, `studio_rea_evidence` | Select an artifact, call a static tool, and inspect saved evidence. |
| `studio_export_spec` | Export a reconstruction specification and evidence dossier. |
| `studio_oracle_preview` | Read an oracle suite's cases, SHA-256 and approval state. |
| `studio_oracle_run` | Execute a user-approved oracle suite and retain real comparisons. Refused until the user approves the file's exact SHA-256 in the desktop. No MCP tool approves a suite, and the data folder holding approvals cannot be opened as a project; `studio_command` runs with the user's permissions and is not a security boundary. |

The MCP tool catalog includes each operation's input schema. Open a project first and use its returned ID. The REA catalog is discovered from the running provider. The separate x64dbg tools become usable after desktop enablement and session selection. Arbitrary debugger commands, session selection, remote debugger connections, patching and toolchain registration are not exposed by that bridge. Decompilation assistance must be configured and enabled in the desktop; its optional input contains one reviewed function, and recordId must reference successful original evidence for the selected target. Shell commands and Code tasks still run with the signed-in user's normal permissions.

Requests are limited to 3 MiB and four concurrent handlers. Recent tool activity records the tool name, completion status and duration in the settings menu; credentials and tool arguments are not logged there. Tool failures use MCP `isError`; they do not become successful analysis results.

## Minimal local client check

Enable the server and use its connection config in a Streamable HTTP client. Initialize, list tools, and call `studio_state` with `{}`. Expected: server identity `rea-studio`, version `1.2.0`, twenty-seven tools, and the actual current projects. Disable the server; new connections should fail. The development check `scripts/smoke-mcp.cjs` exercises this using the official TypeScript MCP client and real temporary project files.

## Receive code from an agent

A connected agent can call `studio_import_code` with a project name and text files:

```json
{"name":"My helper","purpose":"coding","files":[{"path":"src/helper.js","content":"export const double = n => n * 2;\n"}]}
```

Use `purpose: "analysis"` for the reverse engineering workspace. Optional `analysisPath` identifies an imported file or directory; otherwise the project root is the target. The result includes `project.id`, the stored file paths and `analysisTarget`. The agent can use that project with the read/write and model-task tools, or select `analysisTarget` with `studio_rea_select` and call a live static REA tool. Import itself does not execute source, install dependencies or start a model task.

Each import creates a separate project under the data directory's `playground/imports`, preserving earlier projects even when names match. **Open received code** appears in the explorer. Coding imports open the first file; analysis imports select the requested target. Existing unsaved editor changes are preserved until the user explicitly switches. Imported projects remain in the project list after restart.

One import accepts 1–64 UTF-8 text files, at most 2 MiB total. Paths must be relative; traversal, absolute/device paths, Git metadata and duplicate paths are rejected. Binary files and ZIP archives are not accepted by this source-code action. Continue editing through `studio_write_file` using the current file hash.

## Classic access

Expand **Classic interface** in MCP & Settings. Select an earlier QuixiDesk executable if needed, then click **Open Classic**. A sibling `QuixiDesk/QuixiDesk.exe` installation or the `REA_STUDIO_CLASSIC_EXE` environment variable is detected automatically. The earlier app must have its original `resources/ion-dist/index.html`.

Classic opens in a separate window using the earlier application's `--classic` option, with an independent `classic` data/profile folder. Existing provider settings are copied on its first launch. The current interface remains the default. The earlier renderer and its assets are not included in the REA Studio package.
