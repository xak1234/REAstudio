# Windows verification

Use Windows x64 with WebView2, Git, Rust 1.98.0, and Visual Studio C++ Build Tools. Do not run UI tests against a profile containing real unsaved work.

## Compiler, lint, and focused tests

Run the validation commands from the README. The focused suites cover platform/workspace behaviour and engine tests for write conflicts, interrupted runs, project-scoped task pagination, dossier isolation/preservation of failed records, implementation reads excluding raw dossier evidence, real oracle mismatches/empty coverage/truncated output, HTTP error/empty-stream handling and environment credential precedence. App tests cover MCP authentication/origin checks and tool contracts. The provider regression check uses a bounded local HTTP fixture; it is not a real model test. `node scripts/check-analysis.cjs` checks guided inputs, live-schema preflight, retained paging and function selection. `node scripts/check-reconstruction.cjs` checks target separation, eligible nonempty briefs, handoff and parser-error guidance.

The public source audit checks tracked files for excluded runtime/profile trees, private LAN addresses, credential-bearing URLs, and common credential patterns. It does not establish that arbitrary future changes are free of secrets or licensing issues.

## Native UI and Ghidra integration

From an **x64 Visual Studio Developer PowerShell**, prepare an isolated fixture and install the test driver outside the application source:

```powershell
$fixture = Join-Path $env:TEMP ('quixi-fixture-' + [guid]::NewGuid())
.\scripts\prepare-smoke-fixture.ps1 -Destination $fixture
$driver = Join-Path $env:TEMP 'quixi-ui-driver'
npm install --prefix $driver playwright-core@1.58.2 --no-audit --no-fund
$env:QUIXI_TEST_PLAYWRIGHT_MODULE = Join-Path $driver 'node_modules\playwright-core'
$env:QUIXI_SMOKE_ROOT = $fixture
$env:QUIXI_DATA_DIR = Join-Path $env:TEMP ('quixi-data-' + [guid]::NewGuid())
$env:WEBVIEW2_USER_DATA_FOLDER = Join-Path $env:TEMP ('quixi-webview-' + [guid]::NewGuid())
$env:WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS = '--remote-debugging-port=9322'
$env:QUIXI_DEVTOOLS = '1'
Start-Process .\target\release\REAStudio.exe
node scripts/smoke-windows.cjs
```

Before running this, prepare bundled dependencies with `scripts/prepare-rea-windows.ps1`. Only one test app should listen on port 9322. Run the app as the interactive Windows user; REA's Windows process containment checks can differ in a SYSTEM service session.

Expected output ends with a JSON object containing `passed: true`, real tool/catalog counts, saved native/decompile/JavaScript record IDs, and an empty `jsErrors` array. Counts can change when the pinned REA version changes. The check:

1. Edits the fixture README through the WebView and verifies the physical file.
2. Simulates an external writer and verifies that a stale-hash save is rejected.
3. Reads a real Git diff and executes PowerShell.
4. Verifies REA Studio branding and the exact current package version, prevents empty Strings/Decompile requests, preserves arguments across refresh, pages real functions and decompiles a selected row. Connects bundled REA, opens the compiled fixture, analyses `quixi_add`, and requests decompiled code in the same persistent MCP session.
5. Inspects the JavaScript fixture and reads the persisted evidence record back.
6. Captures screenshots into the fixture directory and closes the active REA target.
7. Opens Toolchain, reads the packaged workflow, prepares a SPEC task, and exports actual evidence into a separate rebuild project.
8. Checks an empty oracle suite is unverified, runs a deliberately incorrect addition fixture against 42, verifies failure/retry handoff, repairs the fixture, and verifies a passing saved comparison.

For reconstruction, use a second empty project outside the fixture directory. Prepare an analysis task and verify Ask mode, REA enablement, target path and evidence references before starting a live model task. Save a dossier and inspect its manifest and retained JSON files. Attempting to export into the original fixture project must fail. A completed model brief is necessary to test implementation handoff end to end; unit checks do not claim that a model rebuilt an application.

Close the test app afterwards. Start the normal app from a separate shell without those environment overrides. Remote debugging is intended only for controlled testing and should not remain enabled in a normal instance.

## MCP and environment credential integration

Use the isolated profile and native fixture above. Before starting the test app, set `$env:CUSTOM_API_KEY = 'rea-studio-environment-check'`. This is a non-secret test credential; never use a production key for this check. Install the official client outside the source checkout, then run:

```powershell
npm install --prefix $driver @modelcontextprotocol/sdk@1.32.2 --no-audit --no-fund
$env:REA_STUDIO_TEST_SDK = Join-Path $driver 'node_modules\@modelcontextprotocol\sdk'
$env:REA_STUDIO_TEST_DATA = $env:QUIXI_DATA_DIR
$env:REA_STUDIO_TEST_EXPECTED_ENV_KEY = $env:CUSTOM_API_KEY
node scripts/smoke-mcp.cjs
```

This connects the official MCP client to the actual app listener, checks authentication and foreign-origin rejection, lists twenty-four tools, reads/writes real fixture files, rejects stale writes/path escapes, executes PowerShell, and retrieves a live REA schema. It imports source files into distinct projects, preserves unsaved editor work, opens received code in the UI, rejects unsafe paths, and analyses imported JavaScript through real REA. A temporary local provider verifies that blank-key connection tests and model calls receive the inherited environment credential without persisting or returning it. The model response is a controlled fixture, not evidence of real model capability. The check also verifies listener shutdown, token rotation, cleared connection-config text, and collapsed Classic access. It must finish with `passed: true` and no JavaScript errors. Close the test app and remove the test environment overrides afterwards.

To verify Classic launching separately, select an earlier installed Classic executable in MCP & Settings, open it, and check its window and independent profile. Close only the test Classic window.

## Attached IDA verification

Use a licensed IDA installation with a compatible MCP bridge, and open the original `quixi-fixture.exe` in IDA. REA 6.8.0's attached legacy profile supports `ida-pro-mcp` 1.4.0; a current upstream server with renamed tools is not interchangeable. Configure the bridge's stdio registration JSON through Toolchain in a dedicated REA Studio test profile. IDA 9.3 may ask to enable its built-in PyQt5 compatibility shims when the bridge first accesses pseudocode.

With the test app on CDP port 9323, set `QUIXI_TEST_PLAYWRIGHT_MODULE` and `QUIXI_SMOKE_ROOT` as above, then run `node scripts/smoke-ida.cjs`. It requires actual IDA function listings, pseudocode for two fixture functions, assembly, matching target hashes and saved evidence. It verifies that merely opening a target stays unconnected, successful provider results turn the indicator green, and closing or testing a different binary clears it. The different input must fail IDA's identity check on the first provider operation. Expected: `passed: true` with record IDs and no JavaScript errors. The check closes the REA provider; it does not close the user's IDA window. Close the test app afterwards and launch the normal app without CDP overrides.

## Real model verification

Model-assisted tasks are a separate manual integration check because they depend on a configured server, model capability, and possibly paid credentials. Use the README's new-file task in a dedicated fixture project and verify the actual file, exit code, and Activity events. For analysis, select the native fixture, enable REA in Ask mode, and request a schema lookup plus `inspect_pe_resources`; verify a successful REA event and an Evidence ID present in the saved response. Do not turn a model assertion into a passing test without checking the underlying operation.

## Release checks

After packaging, test a copy launched from the staged release folder with `QUIXI_RESOURCES_DIR` unset. Verify the ZIP's checksum, decompress it with `tar -xOf <archive> > NUL` from Command Prompt, and exercise the bundled REA connection. Test the optional installer in a new destination; it intentionally refuses to overwrite another installation. Check that background Git refreshes do not open visible console windows and that the final normal instance is not listening on the test debugging port.

## Debugger and specialist integration

Install the optional x64dbg bridge and launch a separate test profile on CDP port 9323. Set `QUIXI_TEST_PLAYWRIGHT_MODULE`, `QUIXI_SMOKE_ROOT` and `REA_STUDIO_TEST_SDK` as above. Run `node scripts/smoke-debugger.cjs`. This opens only the compiled fixture, obtains real registers/memory/disassembly, sets a breakpoint at a returned instruction address, steps, verifies target mismatch and bounded-read rejection, imports an actual text export, and checks persistent evidence. It also verifies the green connection indicator and reads the debugger through the official MCP client. Expected: `passed: true`, record IDs and an empty `jsErrors`. The script disconnects but deliberately leaves its debugger open; close only the printed test debugger PID.

For a real specialist check, set `REA_STUDIO_PROVIDER_CONFIG` to the private provider configuration to reuse in the isolated test profile, `REA_STUDIO_SPECIALIST_MODEL` to an actually served LLM4Decompile model, and optionally `REA_STUDIO_TEST_DRIVER=1`. Run `node scripts/smoke-specialist.cjs`. It decompiles the native fixture through real Ghidra, requests a real raw text completion, verifies provenance and model separation, and optionally requires a separate real driving model to invoke the specialist. No model or endpoint is mocked. Expected: `passed: true`, the actual suggestion/source IDs and `verified: false` inside the saved suggestion. Review the emitted C before independently compiling/testing it; a successful completion alone is not a correctness test.
