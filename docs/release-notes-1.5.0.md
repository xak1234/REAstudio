REA Studio V1.5.0
=================

This update adds import reconstruction to the packed-PE workflow. A memory dump
can contain decompressed code while its IAT still contains addresses from a
single process. REA Studio can now record the corresponding exact DLL exports
and build real import descriptors and named/ordinal lookup tables while
preserving the original IAT slot locations.

## Available workflow

Open **Toolchain → Bundled REA workflows → Packed PE & import repair**.
The application-root `rea-unpack.ps1` launcher supports live capture with an
explicitly authorized target and offline rebuilding from a reviewed capture.
The debugger bridge is optional and installed separately. See
[IMPORT-REPAIR.md](IMPORT-REPAIR.md) for commands, evidence and report meanings.

The capture records process creation identity, actual image base, module export
evidence and hashes. Supply an explicit OEP RVA or VA and reviewed IAT ranges to
repair in one run. Without those inputs, the result is an analysis dump and
review plan. Heuristics and unresolved pointers never become a successful
import-repair label. Source files and existing outputs are preserved.

## Scope and limitations

- PE32/x86 and PE32+/x64 named and ordinal imports are supported.
- DLL forwarders and same-address aliases are retained as evidence. Unsupported
  API-set aliases and unresolved or ambiguous pointers remain visible.
- Each reconstructed DLL run needs its existing null terminator and available
  section-header space. The writer refuses unsafe interleaved layouts or IAT
  extents spanning multiple sections.
- Missing relocations, TLS/Load Config semantics, delay imports, original data
  state and unavailable bytes are not manufactured. A prologue or function
  count does not establish the true entry point or complete decompression.
- A structurally repaired PE is not automatically a verified executable or a
  complete clone. Runtime and portability status stay unverified until tested.
- Import repair preserves captured original machine code. The separate
  SPEC → implementation → oracle workflow supports staged source rebuilding,
  but a complete working source reconstruction of a representative medium
  application has not been demonstrated.

## Validation

The following checks completed on Windows on 2026-10-30 against the 1.5.0
implementation:

- Python 3.12: **57 tests passed**, with no failures or skips; Ruff and strict
  mypy checks passed.
- Rust workspace checking, Clippy and the release build completed. The focused
  suites passed **22 MCP tests** with one ignored, and **10 application tests**.
  Existing unrelated Clippy warnings remain.
- Owned fixed-base x86 and x64 fixtures passed independent import-slot/name,
  entry-point, resource and unchanged-input checks. Original and rebuilt
  programs exited zero and printed exactly `REA_IAT_OK=42` followed by CRLF.
- The x64 capture correctly required review for equal-address export aliases.
  The harness used the fixture's original import identity to choose a recorded
  candidate, then passed the offline PowerShell launcher in the packaged layout.
- The native UI/Ghidra smoke check and import-repair guide check passed without
  JavaScript errors. Source/version checks and the public-source audit passed.

See [the recorded verification ledger](TESTING.md#recorded-15-verification) for
the implementation revision and exact scope. These results do not establish
arbitrary packed-app recovery, missing relocation/TLS/Load Config restoration,
cross-machine portability or whole-application source equivalence. A complete
portable ZIP and its extracted copy were not part of this local validation.

Source and portable downloads are published separately. Use the assets listed
on [GitHub Releases](https://github.com/xak1234/REAstudio/releases), or build the
1.5.0 source if a matching published ZIP is not yet available.

The app version is 1.5.0. Existing profiles and model/provider settings use the
same locations as 1.4.0. No external model, Java installation, or other client's
MCP registration is changed.
