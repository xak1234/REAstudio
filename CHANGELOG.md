# Changelog

The initial Windows edition includes a reconstruction workflow for selected features or staged application rebuilds, saved task handoff, evidence dossier export, and actionable guidance for PE resource ranges that are not file-backed.

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
