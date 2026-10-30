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

## Validation

The update includes byte-format regression tests, Python lint/type checks and
a separate Windows harness that compiles owned x86/x64 fixtures, captures them
through x64dbg, independently checks imports/resources/OEP, and runs the rebuilt
programs. Execution results belong to each saved receipt; the existence of a
test script is not itself a successful test result.

The app version is 1.5.0. Existing profiles and model/provider settings use the
same locations as 1.4.0. No external model, Java installation, or other client's
MCP registration is changed.
