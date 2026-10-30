---
name: unpack-packed-binary
description: Capture an explicitly authorized packed Windows x86/x64 EXE and reconstruct reviewed import tables, or rebuild offline from an existing hashed capture. Use for PECompact/UPX-like native targets with packed code, damaged imports, frozen live IAT pointers or a stale stub entry point. Do not use for managed/script targets or promise original source, complete unpacking or runtime equivalence.
---

# Capture and repair native PE imports

Use the `rea-unpack.ps1` launcher at the REA Studio installation root. In a
source checkout it is `scripts/rea-unpack/rea-unpack.ps1`. It locates its Python
modules and optional x64dbg bridge relative to the installation; pass
`-BridgePython` and `-X64dbgRoot` when using separately configured locations.
Read `docs/IMPORT-REPAIR.md` for the full input/report contract.

## Choose the operation

Check whether execution of this exact target is already authorized. Live
capture executes the EXE under a new x32dbg/x64dbg session and requires
`-Trusted`. Ask only when that authorization is missing. Offline
`-RebuildPlan` uses saved evidence and executes no target. Do not launch an
unknown binary merely to satisfy an import-table inspection request.

For a live capture, require the installed x64dbg Automate bridge. Use the
bridge's Python interpreter. Administrator-manifest targets need an elevated
terminal or `-Elevate`; ordinary captures need no elevation. Use a separate new
output file. The launcher preserves existing source and output files.

## Establish evidence before rebuilding

1. Validate the target identity. Record actual loaded base, process creation
   identity and same-capture module/export information. Never resolve a frozen
   pointer against a different process or a later boot without its matching
   module evidence.
2. Supply a reviewed `-OepRva` or `-OepVa`, never both. The driver verifies that
   the requested address is reached. Without an explicit entry point, any
   prologue-based detection is an unverified candidate. A prologue, entropy
   change or function count does not prove the true OEP or complete unpacking.
3. Identify complete IAT extents using debugger/code-reference evidence. Pass
   `-IatRange` as `RVA:SIZE`, including existing null terminators. For multiple
   ranges use a PowerShell string array. Default scans and old descriptors
   propose ranges only; they do not authorize pointer rewriting.
4. Resolve every nonzero reviewed slot to an exact captured DLL/name or ordinal.
   Use `-IatDll RUN_RVA:DLL` only to choose a matching captured alias. Preserve
   ambiguity and unresolved/interior/hooked pointers; never guess a nearest API.
5. Rebuild only after the caller-selected entry/ranges and complete capture are
   established. Keep IAT slot RVAs fixed. Unsupported mixed-DLL layouts, missing
   terminators, insufficient section-header space or incomplete bytes require
   review, not a fabricated successful file.

For exploration, run the launcher with `-Target`, `-Trusted` and
`-AnalysisOnly`. It produces capture evidence and an import-review plan. When
an explicit OEP is known, include it even for the analysis-only capture.

For a reviewed capture, set `reviewed: true` in its `.imports.json` plan after
checking the OEP, ranges and every selected import. Choose only exact
identities present in the capture. Preserve the referenced capture/memory
hashes. Run `-RebuildPlan` with that file and a new `-Output`. Do not delete an
unresolved slot to manufacture a successful result.

## Report accurately

Read stdout JSON and the durable `.report.json`. Exit 0 and
`imports_rebuilt: true` establish structural repair of the selected imports.
Exit 3 indicates review-required analysis evidence; exit 1 indicates failure.
Do not call an analysis dump a repaired executable. Keep the `.memory.bin`,
`.capture.json`, `.imports.json` and `.report.json` files together.

State that `runtime_verified` and `portable_verified` remain false until a
separate authorized behavioral check. Import reconstruction does not restore
missing relocations, original initialized data, TLS startup state, Load Config
semantics, delay-import behavior, debug symbols or original code/data
boundaries. A fixed-base repair does not establish ASLR support. A physical
host DLL match does not identify an original API-set contract.

Select the resulting file explicitly in REA Studio and open it with the chosen
native provider for subsequent analysis. Import the JSON report as evidence
when needed, preserving its original/dump hashes and limitations. Do not
equate a successful provider opening or increased function count with execution
proof or a complete clone. Keep captured application bytes and private runtime
evidence out of the public source repository.
