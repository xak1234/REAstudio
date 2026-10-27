# REA Studio MCP control

Open **MCP & Settings** in the top bar. The server always starts disabled. Choose a local port (default 19456) and enable it. **Connection config** reveals the client URL and Authorization header; keep that token private. The setting does not modify other applications' MCP registrations.

This edition implements Streamable HTTP with JSON responses, compatible with protocol versions 2025-11-25, 2025-06-18 and 2025-03-26. It negotiates 2025-11-25 when a different version is offered during initialization. It does not offer a persistent SSE subscription, OAuth discovery or remote network hosting. Clients must support a configured bearer header. Use a local client on the same computer; a hosted ChatGPT connector cannot directly reach a loopback URL.

The listener binds only to `127.0.0.1`. Host and Origin headers are checked, and every HTTP request requires the token. It is stored in the existing data directory's `mcp-server.json`, alongside the selected port and optional Classic app path. It is never included in normal workspace state or exposed as an agent tool. The connection-settings view reveals it only when requested.

**Disable MCP server** closes the listening socket and rejects work not yet accepted. An already accepted shell command or analysis call can finish. Model tasks started earlier continue independently; use **Stop run** or `studio_stop_run` to request their cancellation. Re-enabling waits for previously accepted calls to finish. **Reset access token** disables the server and replaces the credential, so existing client configs must be updated. Restarting the app preserves the token and port but leaves the server off.

## Tools

| Tool | Purpose |
| --- | --- |
| `studio_state` | Projects, model configuration without keys, and run summaries. |
| `studio_open_project` | Register an existing absolute project directory. |
| `studio_files`, `studio_read_file`, `studio_diff` | Actual project files, content/hash, and Git changes. |
| `studio_write_file` | Write with the hash from a preceding read; empty hash only for a new file. |
| `studio_command` | Execute a bounded noninteractive command in the project. |
| `studio_start_run`, `studio_run_status`, `studio_stop_run` | Start a model task, inspect actual results, and request cancellation. |
| `studio_rea_catalog` | Available static REA names and session state, or one full live tool schema. |
| `studio_rea_select`, `studio_rea_call`, `studio_rea_evidence` | Select an artifact, call a static tool, and inspect saved evidence. |
| `studio_export_spec` | Export a reconstruction specification and evidence dossier. |
| `studio_oracle_run` | Execute declared oracle commands and retain real comparisons. |

The MCP tool catalog includes each operation's input schema. Open a project first and use its returned ID. The REA catalog is discovered from the running provider. Runtime attachment, patching and arbitrary toolchain registration are not exposed in this static tool set. Shell commands and Code tasks still run with the signed-in user's normal permissions.

Requests are limited to 3 MiB and four concurrent handlers. Recent tool activity records the tool name, completion status and duration in the settings menu; credentials and tool arguments are not logged there. Tool failures use MCP `isError`; they do not become successful analysis results.

## Minimal local client check

Enable the server and use its connection config in a Streamable HTTP client. Initialize, list tools, and call `studio_state` with `{}`. Expected: server identity `rea-studio`, version `1.1.0`, sixteen tools, and the actual current projects. Disable the server; new connections should fail. The development check `scripts/smoke-mcp.cjs` exercises this using the official TypeScript MCP client and real temporary project files.

## Classic access

Expand **Classic interface** in MCP & Settings. Select an earlier QuixiDesk executable if needed, then click **Open Classic**. A sibling `QuixiDesk/QuixiDesk.exe` installation or the `REA_STUDIO_CLASSIC_EXE` environment variable is detected automatically. The earlier app must have its original `resources/ion-dist/index.html`.

Classic opens in a separate window using the earlier application's `--classic` option, with an independent `classic` data/profile folder. Existing provider settings are copied on its first launch. The current interface remains the default. The earlier renderer and its assets are not included in the REA Studio package.
