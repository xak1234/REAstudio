QuixiDesk Windows 1.0.0 provides the native coding playground and integrated REA analysis workspace.

- Project explorer, UTF-8 editor, conflict checks, Git diffs, real PowerShell output, and persistent model runs.
- API-key and local OpenAI-compatible providers; a single coding agent with Ask and Code modes.
- Bundled REA 6.8.0, Node 24.22.1, Ghidra 12.1.4, and Temurin JDK 21.0.12.1+1 with a persistent MCP session, real schemas, saved evidence, and recovered code.
- Binary → REA → SPEC.md → rebuild → oracle → retry, with separate implementation runs, explicit expectations and saved comparison reports. Empty oracle suites remain unverified.
- Toolchain panel with 20 entries, ten pinned optional portable downloads, IDA/JADX configuration paths, and the matching REA workflow guides. Optional tools are not all bundled or validated as interchangeable REA providers.
- Clear PE resource failure guidance and a native-analysis continuation when referenced resource bytes are not file-backed.
- Public resource set with no configured private endpoint, credentials, user profile, or legacy extracted renderer assets.
- Full README, build/test/release scripts, dependency inventories, notices, corresponding source, SHA-256 file manifest and archive checksum.

Download the Windows ZIP and its `.sha256` file, verify the checksum, extract the whole folder, and run QuixiDesk.exe. GitHub's automatic source archives do not contain the executable or REA runtimes.

Requires Windows x64 and the installed WebView2 Runtime. Git is needed for diffs. The executable is unsigned. REA's native Windows Ghidra lane is experimental; optional engines and multi-agent orchestration are not included. Code mode executes commands as your user, and model requests go to the provider you configure. See README.md for details and limits.
