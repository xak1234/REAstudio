# Windows verification

Use Windows x64 with WebView2, Git, Rust 1.98.0, and Visual Studio C++ Build Tools. Do not run UI tests against a profile containing real unsaved work.

## Compiler, lint, and focused tests

Run the validation commands from the README. The focused suites cover platform/workspace behaviour and engine tests for write conflicts, interrupted runs, project-scoped task pagination, dossier isolation/preservation of failed records, implementation reads excluding raw dossier evidence, real oracle mismatches/empty coverage/truncated output, HTTP error/empty-stream handling and environment credential precedence. App tests cover MCP authentication/origin checks and tool contracts. The provider regression check uses a bounded local HTTP fixture; it is not a real model test. Further focused tests cover: the PowerShell wrapper on every installed shell (PowerShell 7 and Windows PowerShell 5.1: trailing comments, here-strings, a stale `$LASTEXITCODE` from an earlier statement, last-statement exit codes), head+tail output bounding, deep/gitignored/truncated file listings outside Git, `git status -z` parsing, the Git panel (stage, unstage, discard, commit without running repository hooks) in a temporary repository, streaming Terminal jobs (interleaved streams, Stop, per-project limit, working directory carried over inside the project and reset outside it), atomic `SafeFs` writes, CRLF/BOM detection and preservation, run change sets (pre-image snapshots in application data, diffs, conflict detection, revert and forced revert), the risky-command classifier with positive and negative cases, approve/deny/stop while a command awaits approval, follow-up task summaries, provider saving without a resolvable credential and local detection against a configured URL. `node scripts/check-analysis.cjs` checks guided inputs, live-schema preflight, retained paging and function selection. Its oracle-preview fixture matches the backend's nested `expected` schema and verifies disclosure of exact text, SHA-256, JSON null, absent files and timeouts; it does not execute those cases. `node scripts/check-reconstruction.cjs` checks target separation, eligible nonempty briefs, handoff and parser-error guidance.

The public source audit checks tracked files for excluded runtime/profile trees, private LAN addresses, credential-bearing URLs, and common credential patterns. It does not establish that arbitrary future changes are free of secrets or licensing issues.

## Workspace usability and technical access

Use the isolated interactive app and fixture environment from the native UI instructions below. Set `QUIXI_SMOKE_ROOT` to the compiled fixture folder containing `quixi-fixture.exe`, `QUIXI_TEST_PLAYWRIGHT_MODULE` to the installed Playwright module, `REA_STUDIO_TEST_DATA` to the isolated profile and `REA_STUDIO_TEST_CDP` to that app's debugging URL. Run the additional UI check against the resources intended for packaging:

```powershell
node scripts/smoke-usability.cjs
```

The script writes a JSON receipt and responsive screenshots at 1440, 1000 and 480 pixels into a new sibling test folder. Optional `REA_STUDIO_USABILITY_REPORT` chooses the receipt path. The wrapper's `-Usability` switch writes `usability-report.json` into its output directory. It checks retained controls, panel persistence and keyboard navigation, guide/rebuild/evidence access, the complete live catalog, and a real manually edited JSON `search_strings` call with saved evidence and target identity.

Check both desktop and narrow-window layouts. Files and Task settings must collapse without leaving reserved space; desktop choices must survive reload, narrow panels must remain reachable and Escape must dismiss their overlays. The compact model/access control must open the corresponding task settings.

Exercise each same-page shortcut: Analyze, Saved evidence, Investigations, Rebuild and Advanced tools. Selecting a quick tool, following guide actions or encountering missing/invalid arguments must reveal the required controls without clearing the current target or JSON draft. With **Expert view** off, **Advanced arguments & schema** and individual raw-argument/live-schema disclosures must remain reachable. Verify full catalog access, independent IDA bridge access, debugger/source controls, reconstruction and saved evidence; this UI check does not establish new analysis-engine capability.

After changing these layouts, rerun the native UI/Ghidra, MCP, investigation and native-close suites against the final resources. Earlier receipts establish the earlier candidate only; record the new usability receipt and each rerun separately.

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

This connects the official MCP client to the actual app listener, checks authentication and foreign-origin rejection, lists twenty-eight tools, reads/writes real fixture files, rejects stale writes/path escapes, executes PowerShell, and retrieves a live REA schema. It imports source files into distinct projects, preserves unsaved editor work, opens received code in the UI, rejects unsafe paths, and analyses imported JavaScript through real REA. A temporary local provider verifies that blank-key connection tests and model calls receive the inherited environment credential without persisting or returning it. The model response is a controlled fixture, not evidence of real model capability. The check also verifies listener shutdown, token rotation, cleared connection-config text, and collapsed Classic access. It must finish with `passed: true` and no JavaScript errors. Close the test app and remove the test environment overrides afterwards.

To verify Classic launching separately, select an earlier installed Classic executable in MCP & Settings, open it, and check its window and independent profile. Close only the test Classic window.

## Attached IDA verification

Use a licensed IDA installation with a compatible MCP bridge, and open the original `quixi-fixture.exe` in IDA. REA 6.8.0's attached legacy profile supports `ida-pro-mcp` 1.4.0; a current upstream server with renamed tools is not interchangeable. Configure the bridge's stdio registration JSON through Toolchain in a dedicated REA Studio test profile. IDA 9.3 may ask to enable its built-in PyQt5 compatibility shims when the bridge first accesses pseudocode.

With the test app on CDP port 9323, set `QUIXI_TEST_PLAYWRIGHT_MODULE` and `QUIXI_SMOKE_ROOT` as above, then run `node scripts/smoke-ida.cjs`. It requires actual IDA function listings, pseudocode for two fixture functions, assembly, matching target hashes and saved evidence. It verifies that merely opening a target stays unconnected, successful provider results turn the indicator green, and closing or testing a different binary clears it. The different input must fail IDA's identity check on the first provider operation. Expected: `passed: true` with record IDs and no JavaScript errors. The check closes the REA provider; it does not close the user's IDA window. Close the test app afterwards and launch the normal app without CDP overrides.

## IDA bridge verification

Requires a licensed IDA Pro 9.x with idalib and Python 3.11+. Install the bridge into a fresh folder, for example `pwsh -File scripts\install-ida-bridge.ps1 -PythonExecutable <python.exe> -Destination <empty folder>`, and confirm it prints the registration path. Rerunning into a folder containing anything else must fail.

Focused live tests (no app UI): set `QUIXI_TEST_IDA_HEADLESS` to the generated `rea-headless-registration.json` and optionally `QUIXI_TEST_IDA_TARGET` to a small PE, then run `cargo test --release -p quixi-engine live_headless_bridge_round_trip -- --ignored --nocapture`. It enables the bridge in an isolated data directory, opens a cached copy, lists functions, decompiles, reads xrefs, renames, checks that blocked tools and a different selected artifact are refused, closes, re-enables with a new supervisor and confirms the rename persisted, and verifies that abandoning the connection terminates the detached idalib worker. For attached mode, start a current ida-pro-mcp HTTP endpoint with a binary open, set `QUIXI_TEST_IDA_ATTACHED` to its URL and `QUIXI_TEST_IDA_ATTACHED_TARGET` to that binary, and run `cargo test --release -p quixi-engine live_attached_bridge_requires_matching_input -- --ignored --nocapture`. Both live tests are #[ignore] by default. Explicitly selecting them with -- --ignored --nocapture requires these variables; missing configuration fails the test.

App smoke: in a dedicated test profile on CDP port 9323 with the bridge installed (or its registration chosen in Toolchain) and MCP disabled, set `QUIXI_TEST_PLAYWRIGHT_MODULE`, `QUIXI_SMOKE_ROOT` and `REA_STUDIO_TEST_SDK` as above and run `node scripts/smoke-ida-bridge.cjs`. It drives the real `ida/*` routes: status (installed, disabled) → enable headless → open the fixture (IDB in the private cache, nothing written beside the fixture, matching SHA-256) → list functions → decompile and xrefs for `quixi_add` → rename → blocked `py_eval`, `patch` and `idb_save` to another path → annotations toggle → target mismatch → saved `ida-bridge` evidence → `studio_ida_status`/`studio_ida_call` through the official MCP client → close, disable, re-enable, reopen and confirm the rename persisted → close. Expected: `passed: true`, record IDs and an empty `jsErrors`. The fixture's bytes are verified unchanged. The cached database stays under the test profile's `ida` folder; delete that profile afterwards.

To check REA's own IDA provider with the same registration, use **Register for REA**, reconnect REA, and run `open_binary` with `provider_id: "ida"`, `list_procedures` and `procedure_pseudo_code` on a copy of the fixture. Use **Restore attached** afterwards in profiles that had an attached registration.

## Real model verification

These optional checks call a real configured model server and may use paid credentials. Run them sequentially in the isolated data/WebView profile and source-known fixture prepared above. They save connection settings only in that test profile. Keep private configuration paths, credentials and endpoint details out of receipts committed to source control.

```powershell
$env:QUIXI_TEST_PLAYWRIGHT_MODULE = '<installed playwright-core module path>'
$env:QUIXI_SMOKE_ROOT = '<prepared source-known fixture directory>'
$env:REA_STUDIO_TEST_CDP = 'http://127.0.0.1:9323'
$env:REA_STUDIO_PROVIDER_CONFIG = '<private providers.json path>'
$env:REA_STUDIO_PROVIDER_ID = 'custom'
# Optional: otherwise use the connection's selectedModel.
$env:REA_STUDIO_AGENT_MODEL = '<exact model ID advertised by that endpoint>'
node scripts/smoke-agent.cjs
node scripts/smoke-agent.cjs --analysis
```

The default check asks the real Agent to read a fresh random file and write a byte-exact copy, then independently verifies the file and successful Activity events. The `--analysis` check opens the actual native fixture through bundled Ghidra, then requires the real Agent to discover schemas, call `analyze_function` and `procedure_pseudo_code` for `quixi_add`, and finish with a saved evidence citation and analysis limitations. The verifier checks actual tool events, target SHA-256, direct Ghidra provenance and the summary view's retained Ghidra parent evidence. Preparation and independent verification calls are separate from the required model actions.

Both modes verify exact requested connection/model routing, rejection of an unknown explicit model, and saved context/checkpoint metadata. The script uses a conservative 32,768-token configured context capacity and bounded output/step/time limits; choose a server/model that supports that capacity. Neither mode downloads or replaces models. Expected: a JSON result with `passed: true` and empty `jsErrors`. A model claim alone never passes a check. The analysis check establishes a small static-tool integration case, not whole-application recovery or behavioral equivalence. Use the separate specialist check below to verify model-to-helper routing.

## Release checks

After packaging, test a copy launched from the staged release folder with `QUIXI_RESOURCES_DIR` unset. Verify the ZIP's checksum, decompress it with `tar -xOf <archive> > NUL` from Command Prompt, and exercise the bundled REA connection. Test the optional installer in a new destination; it intentionally refuses to overwrite another installation. Check that background Git refreshes do not open visible console windows and that the final normal instance is not listening on the test debugging port.

## Debugger and specialist integration

Install the optional x64dbg bridge and launch a separate test profile on CDP port 9323. Set `QUIXI_TEST_PLAYWRIGHT_MODULE`, `QUIXI_SMOKE_ROOT` and `REA_STUDIO_TEST_SDK` as above. Run `node scripts/smoke-debugger.cjs`. This opens only the compiled fixture, obtains real registers/memory/disassembly, sets a breakpoint at a returned instruction address, steps, verifies target mismatch and bounded-read rejection, imports an actual text export, and checks persistent evidence. It also verifies the green connection indicator and reads the debugger through the official MCP client. Expected: `passed: true`, record IDs and an empty `jsErrors`. The script disconnects but deliberately leaves its debugger open; close only the printed test debugger PID.

For a real specialist check, set `REA_STUDIO_PROVIDER_CONFIG` to the private provider configuration to reuse in the isolated test profile, `REA_STUDIO_SPECIALIST_MODEL` to an actually served LLM4Decompile model, and optionally `REA_STUDIO_TEST_DRIVER=1`. Run `node scripts/smoke-specialist.cjs`. It decompiles the native fixture through real Ghidra, requests a real raw text completion, verifies provenance and model separation, and optionally (`REA_STUDIO_TEST_DRIVER=1`) requires the real Agent model to invoke the helper. No model or endpoint is mocked. Expected: `passed: true`, the actual suggestion/source IDs and `verified: false` inside the saved suggestion. Review the emitted C before independently compiling/testing it; a successful completion alone is not a correctness test.

## Validation receipts and optimized multi-module fixture

`scripts/run-integration-checks.ps1` runs source checks by default and writes a JSON receipt plus per-check logs to a fresh temporary folder. CI saves those receipts as the `rea-studio-validation` artifact. Each check has an explicit `passed`, `failed` or `skipped` status and duration; unselected live checks are skipped. A requested check with missing environment variables fails rather than becoming a pass. CI also runs the `quixi-mcp` suite and the engine IDA, debugger and decompile suites. Licensed/live Rust tests are ignored by default and are reported as ignored in Cargo's summary; their absence must not be presented as a tested backend.

The existing `quixi_add` fixture remains the quick baseline. Add the optional source-known C++ fixture from an **x64 Visual Studio Developer PowerShell**:

```powershell
$fixture = Join-Path $env:TEMP ('rea-advanced-fixture-' + [guid]::NewGuid())
.\scripts\prepare-smoke-fixture.ps1 -Destination $fixture -IncludeComplex
$env:QUIXI_SMOKE_ROOT = $fixture
$env:REA_STUDIO_COMPLEX_ROOT = Join-Path $fixture 'complex'
node scripts/smoke-complex.cjs --runtime-only
```

The additional fixture uses `/O2 /std:c++17 /W4 /WX`, emits an EXE and a separate DLL without a PDB, and retains exported names as intentional analysis anchors. Three source files cover numeric parsing, invalid-input branches, tiered pricing, string selection, imported DLL calls and invoice-file output. The source checkout's `scripts/fixtures/complex/expected.json` declares source-derived facts and exact runtime cases; `build.json` records binary/source hashes and compiler flags. The benchmark verifies that the current C++ source matches the compiled source hashes and records the expectation-file hash. File-call checks follow the same opened handle through the invoice write and cleanup/error branch, because optimized static CRT helpers may lack recovered API names. The runtime-only command executes these newly compiled fixture programs and checks five output/exit-code cases plus a byte-exact invoice file. It records static analysis as skipped.

For real static analysis, launch the built app in a fresh isolated data/WebView profile as above, with the licensed headless IDA bridge installed or configured in that test profile and IDA initially disabled. Set the following in the test-driver shell:

```powershell
$env:REA_STUDIO_TEST_DATA = $env:QUIXI_DATA_DIR
$env:REA_STUDIO_TEST_CDP = 'http://127.0.0.1:9323'
$env:REA_STUDIO_BENCHMARK_REPORT = Join-Path $fixture 'complex-static-report.json'
node scripts/smoke-complex.cjs
```

This benchmark contacts the actual app and IDA bridge. For both modules it verifies the binary SHA-256, pages the real function inventory to completion (explicit maximum 2,000 functions), finds expected exported functions, examines actual complete pseudocode for source-known constants/strings/calls, and verifies nonempty code references including two named caller-to-callee edges. It also checks the EXE's three imports from the fixture DLL and verifies that target bytes are unchanged. The report retains real evidence record IDs, import/function counts, per-operation durations and errors. It does not execute the target unless `REA_STUDIO_COMPLEX_RUNTIME=1` is explicitly set. It uses no model or simulated provider responses.

To collect a combined receipt, set the variables required by each selected suite, then run:

```powershell
.\scripts\run-integration-checks.ps1 -Windows -Mcp -Ida -Complex -ComplexRuntime
```

The wrapper does not start the app or install dependencies. It requires `REA_STUDIO_TEST_CDP`, `REA_STUDIO_TEST_DATA`, `QUIXI_SMOKE_ROOT` and `QUIXI_TEST_PLAYWRIGHT_MODULE` for UI checks; MCP/IDA checks also need `REA_STUDIO_TEST_SDK`. MCP additionally needs the non-secret environment fixture credential described earlier. Use `-Debugger` or `-Specialist` only with their dedicated prerequisites; the debugger suite executes the fixture and leaves its test debugger process open as documented above. Each UI oracle run reviews and approves the exact suite through the actual approval control before waiting for a comparison result.

These fixtures establish selected wiring, static facts and optional runtime-baseline behavior. They do **not** establish autonomous reconstruction, whole-application equivalence, stripped-symbol recovery, large-application throughput, packed/obfuscated recovery or concurrent/multi-process debugging. Record those as untested until separate representative targets and held-out behavioral cases have been evaluated.


The optional `-Controls` suite (`node scripts/smoke-controls.cjs`) exercises the 1.3 runtime settings and oracle controls through the actual app UI. It requires the isolated UI environment above, creates a separate sibling test project and uses only source-known Node programs. It checks a project-scoped settings read, invalid-limit rejection without disconnect, Save & reconnect with actual bundled REA 6.8.0 identity, approval disclosure of exact text/hash/JSON-null/absent-file expectations, a passing real file-output oracle, and prompt cancellation of a running 30-second child. Cancellation must reject wrong operation/project identities, leave no completed-child marker and save no comparison report. The script restores the original runtime settings and writes `controls-report.json` in its new test project. Run it sequentially with other UI suites.


## Multi-artifact investigation verification

Use the isolated interactive app profile, licensed headless IDA bridge, official MCP SDK and optimized EXE/DLL fixture described above. Set `REA_STUDIO_COMPLEX_ROOT` to the compiled complex fixture, `REA_STUDIO_TEST_DATA` to the dedicated app data directory, and `REA_STUDIO_TEST_CDP` to its debugging URL. IDA and the app MCP listener must start disabled. Run suites sequentially:

```powershell
node scripts/smoke-investigations.cjs
```

The script creates a new sibling test root, copies both source-known modules, saves real IDA evidence and drives the investigation panel through create, inspect and export. It also calls all five `studio_investigation` actions through the official MCP client, checks that unconfirmed deletion and irrelevant action arguments fail, and verifies each exported record's ID, artifact identity, raw byte hash and saved content. Changed and missing copies must block export without leaving staging output; restored files permit a fresh bundle. Reload preserves the set, and deleting its metadata preserves originals, evidence and every prior export. No target program or model is executed. Optional `REA_STUDIO_INVESTIGATION_ROOT` must name a new directory; `REA_STUDIO_INVESTIGATION_REPORT` overrides the default JSON receipt path.

The dedicated source suite is `cargo test --release -p quixi-engine analysis::investigations::tests --locked`. It covers project scoping, immutable identities, raw evidence validation, exclusion and failure labels, bounded hashing/history, export cleanup and Windows canonical-path handling. CI runs it separately because the older `analysis::tests` filter does not include the nested investigation module.

## Bounded scale and unnamed-function discovery

From an **x64 Visual Studio Developer PowerShell**, create a separate generated fixture:

```powershell
$scale = Join-Path $env:TEMP ('rea-scale-fixture-' + [guid]::NewGuid())
.\scripts\prepare-scale-fixture.ps1 -Destination $scale
$env:REA_STUDIO_SCALE_ROOT = $scale
node scripts/smoke-scale.cjs --runtime-only
# With the isolated app and licensed headless IDA ready:
node scripts/smoke-scale.cjs
```

The fixture compiles 2,304 generated functions with optimization and removes fixture-only linker debug metadata while verifying unchanged executable code. It has no application exports, COFF symbol table, debug directory or PDB. The receipt records generator, source, expectation and binary hashes. Runtime-only executes 12 exact output/exit-code cases and marks static analysis skipped.

The static command uses real IDA to page the full function inventory, discover an unnamed quote-calculation feature from its literal string and actual references, inspect decompiled source-known facts and imports, and verify unchanged target bytes. It performs no target execution unless `REA_STUDIO_SCALE_RUNTIME=1`. Paging is bounded by `REA_STUDIO_SCALE_MAX_FUNCTIONS` (default 10,000, permitted 100-50,000), and `REA_STUDIO_SCALE_REPORT` may select a receipt path. Record static and runtime results separately. This synthetic fixture checks bounded paging and one discovery path; it does not establish general stripped-binary recovery, production-scale throughput, packed/obfuscated recovery or application equivalence.

## Native window-close verification

This suite must run as the interactive Windows user. It launches and owns fresh app instances and profiles rather than attaching to an existing window. Choose an unused CDP port and an isolated temporary data root:

```powershell
$env:QUIXI_TEST_PLAYWRIGHT_MODULE = Join-Path $driver 'node_modules\playwright-core'
$env:REA_STUDIO_TEST_EXE = (Resolve-Path .\target\release\REAStudio.exe).Path
$env:REA_STUDIO_TEST_RESOURCES = (Resolve-Path .\resources).Path
$env:REA_STUDIO_TEST_DATA = Join-Path $env:TEMP ('rea-close-validation-' + [guid]::NewGuid())
$env:REA_STUDIO_TEST_CDP = 'http://127.0.0.1:9326'
node scripts/smoke-native-close.cjs
```

The script sends real native close requests to its own windows. It checks cancellation preserves unsaved buffers; save conflicts do not close; save/discard/clean close produce the correct disk contents; backend terminal and synchronous commands trigger warnings even without UI terminal state; and wrong, unsolicited or cancelled close identities are rejected. Suppressing the renderer acknowledgement must produce an actual native fallback with No as its default. Both No and Yes are exercised. A passing run requires normal app exits, no forced cleanup and no JavaScript errors. Its JSON receipt is saved below the fresh data root. It does not claim protection from operating-system shutdown, crashes or forced process termination.

The validation wrapper accepts `-Usability`, `-Investigations`, `-Scale`, `-ScaleRuntime` and `-NativeClose`. Each selected check requires the environment documented above; missing prerequisites fail instead of passing as skipped. `-Scale -ScaleRuntime` runs static and runtime checks together, while `-ScaleRuntime` alone executes only the fixture. It saves separate `usability-report.json`, `investigation-report.json`, `scale-benchmark.json` and `native-close-report.json` receipts in its output directory. For the wrapper's owned close-test instances, use the independent `REA_STUDIO_NATIVE_CLOSE_CDP` URL (default `http://127.0.0.1:9326`); the existing app's `REA_STUDIO_TEST_CDP` is preserved.

```powershell
.\scripts\run-integration-checks.ps1 -Usability -Investigations -Scale -ScaleRuntime -NativeClose
```

## Recorded 1.4 verification

The simplified UI passed its dedicated live usability check: all 338 original controls and the complete 229-tool advertised REA catalog were retained, exact manual JSON produced real saved evidence, full descriptions remained accessible, and keyboard/persistence/navigation checks passed. Twenty layout and interaction checks at 1440, 1000 and 480 pixels included viewport visibility and hit-testing. Target-specific tool availability remains unchanged. The native-close suite passed all seven phases again in about 40.3 seconds, including narrow-layout modal focus through eight Tab steps and Escape handling with a sidebar overlay. Neither suite reported JavaScript errors or forced cleanup.

The affected native UI/Ghidra, runtime/oracle controls, MCP, headless IDA, debugger, investigation and scale integrations also passed against the revised interface. The first aggregate run refused to reuse an existing investigation fixture directory; the investigation suite then passed all seven checks with a fresh directory. Its failed prerequisite receipt was retained. The scale rerun again completed 2,784 functions and all 12 runtime cases.

The first 1.4 CI run exposed a test-fixture path assumption when Windows TEMP used an 8.3 alias. Production already canonicalizes evidence targets; the fixture now follows that contract. The same failure was reproduced locally with an actual short TEMP/TMP path, then all eight investigation tests passed under that path after the fixture correction. Production path matching was not relaxed. The dedicated CI investigation suite includes this fixture regression.

On 2026-10-28, the coordinated Windows release-mode application, engine and workspace suites reported **100 passed, 0 failed and 2 ignored** (10 app, 74 engine and 16 workspace tests passed). The eight investigation tests and the MCP action/confirmation contract test are included. The two licensed live tests remain explicitly ignored in this run. Workspace type checking and Clippy also completed; existing upstream warnings remain.

The new investigation integration suite passed all seven checks against the actual rebuilt app: two source-known modules with six core IDA evidence records, desktop snapshot creation/inspection, all five MCP actions and negative confirmation checks, changed/missing-input export refusal, restored-input unique export and persisted reload, and metadata deletion preserving raw evidence and earlier bundles. The receipt reported no JavaScript errors.

The existing native UI/Ghidra suite also passed against the 1.4 candidate: real function inventory paging and decompilation, JavaScript analysis, saved evidence and separate dossier export, and a deliberately failing oracle followed by repair and retry handoff. Bundled REA advertised 229 live tools. The official-client MCP suite passed with 28 tools, authentication/origin checks, file and command operations, stale-write/path refusal, imports, unsaved-work preservation, non-secret environment credential handling, listener shutdown and token rotation. Both suites reported no JavaScript errors. The MCP suite's provider reply is a controlled fixture, not a real-model result.

The validation wrapper's separate source/syntax and scale-runtime receipt reported 26 passed, 0 failed and 11 skipped checks; its single runtime check contains the 12 baseline cases. Skipped integrations are not counted as executed.


The separately compiled scale fixture passed all 12 runtime baseline cases. Its distinct real-IDA static check then completed 22 pages of 128 entries, ending with a complete terminal page and 2,784 unique functions. String-to-reference discovery found the unnamed quote function, all eight source-known facts, one caller and the required WriteFile/GetStdHandle imports among 75 imports. Source/binary hashes and absence of application exports, COFF symbols and debug metadata were verified; no JavaScript errors occurred. The static run took about 5.1 seconds on this configured host. This is a bounded synthetic paging/discovery result, not a production-scale throughput or reconstruction-equivalence claim. The native-close integration also passed all seven phases in about 40 seconds: cancellation and conflicting-save preservation, successful save, explicit discard, clean close, backend terminal and synchronous-command warnings, and actual native default-No/explicit-Yes fallback. Every owned app exited normally with code zero; no forced cleanup, leftover CDP listener or JavaScript page error was reported.

## Recorded 1.3 fixture verification

On 2026-10-28, the following checks executed on Windows 11 x64 in a dedicated data/WebView profile. These are observed integration results from the 1.3 validation work, separate from the CI source checks and licensed tests that remain ignored unless explicitly requested.

| Executed check | Observed result |
| --- | --- |
| Native UI and bundled Ghidra, final candidate binary | Passed: real function inventory paging and selected-row decompilation; exact saved-record reload; toolchain/workflow display; separate evidence dossier; empty unverified oracle; deliberately failing addition followed by repaired passing output and retry handoff. Live REA catalog: 229 tools. |
| App MCP listener | Passed: 27 advertised tools, authentication/origin rejection, real file and command operations, imports, stale-write/path rejection, unsaved-work preservation, non-secret environment credential handling, listener shutdown and token rotation. The provider response in this suite is a controlled fixture. |
| Headless IDA bridge | Passed: real functions, decompilation, xrefs, cache/persisted rename and restoration, write restrictions, target identity rejection, saved evidence and app MCP access. |
| x64dbg bridge | Passed: real registers, memory, disassembly, breakpoint and step; target mismatch and bounded-read rejection; saved evidence and app MCP access. |
| Runtime settings and oracle controls | Passed: invalid limits rejected before disconnect, real bundled 6.8.0 reconnect, reviewed exact file expectations, real output comparisons, wrong operation/project stop rejection, and cancellation with child-process exit and no completed comparison report. |
| Optimized EXE + DLL static fixture | Passed: both module hashes, complete paged inventories (496 observed functions each), four expected function decompilations, two named code-reference edges, three expected DLL imports, and unchanged target bytes. |
| Optimized fixture runtime baseline | Passed separately: five output/exit-code cases and one byte-exact invoice-file case. |

The UI suites reported no JavaScript page errors. The source-known multi-module static check completed in about 4.3 seconds on this already configured host; this single small-fixture run is not a throughput claim for large applications. Most functions in these binaries come from the linked runtime, and the checked application functions retain exported names. The static and runtime receipts prove different properties and must not be substituted for each other. Attached GUI IDA, packed/obfuscated targets, symbol recovery, large workloads, and autonomous whole-application reconstruction are outside this recorded coverage. Real-model checks are separate from this fixture ledger.

## Recorded real-model verification

On 2026-10-28, `node scripts/smoke-agent.cjs --analysis` passed against the final 1.3 candidate in the isolated Windows profile with the configured local Gemma-family Agent model. In five actual model steps (about 41 seconds), it discovered schemas, successfully called native function analysis and pseudocode tools for `quixi_add`, and cited saved evidence. Independent checks verified the selected provider/model, unknown-model rejection, checkpoint/context metadata, target SHA-256, retained Ghidra parent and direct Ghidra pseudocode provenance. No JavaScript page errors occurred. No model replies were simulated. This is a small source-known function integration result; it does not establish generated-code correctness, autonomous reconstruction or whole-application equivalence. The specialist suite is a separate check and is not included in this result.
