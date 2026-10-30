# Packed PE capture and import repair

REA Studio 1.5.0 separates three claims: bytes were captured, imports were
structurally rebuilt, and a rebuilt program was independently tested. A dump
with resolved addresses is useful evidence, but it does not have a portable
import table simply because a disassembler finds more functions.

## Requirements and entry points

Offline reconstruction uses Python 3.10+ and the standard library. Live capture
uses the optional x64dbg Automate bridge installed by `Install-X64dbg-Bridge.ps1`.
Use the bridge's Python interpreter for live work. An EXE is executed under a
dedicated x32dbg or x64dbg session, and `-Trusted`/`--trusted` is required.
Do not execute a target unless that execution is already authorized.

Installed application:

```powershell
.\rea-unpack.ps1 -Target .\analysis\target.exe -Trusted -AnalysisOnly
```

Source checkout:

```powershell
.\scripts\rea-unpack\rea-unpack.ps1 -Target .\analysis\target.exe -Trusted -AnalysisOnly
```

The launcher finds the scripts and optional toolchain relative to the
installation. `-BridgePython` and `-X64dbgRoot` select explicitly configured
locations. `REA_X64DBG_ROOT` is also recognized. The app's project Terminal and
authorized `studio_command` calls can use the same launcher. The bundled guide
is available through **Toolchain → Bundled REA workflows → Packed PE & import
repair**. This is a command-driven workflow, not a replacement debugger UI.

Targets with an administrator manifest need an elevated terminal or `-Elevate`.
The latter requests UAC. Multiple IAT ranges combined with elevation should be
passed from an already elevated PowerShell terminal. Offline rebuilding does
not need administrator access or a running debugger.

## Capture an entry point and import evidence

The driver asks x64dbg for the actual main-module base. It does not assume that
the preferred `ImageBase` was used. Supply **one** of:

| PowerShell | Python | Meaning |
| --- | --- | --- |
| `-OepRva` | `--oep-rva` | Entry point relative to the loaded main module |
| `-OepVa` | `--oep-va` | Absolute virtual address in this capture |
| `-IatRange` | repeat `--iat-range` | Reviewed `RVA:SIZE` extents, including existing zero terminators |
| `-IatDll` | repeat `--iat-dll` | Select an exact captured public DLL alias for a run: `RUN_RVA:DLL` |
| `-AnalysisOnly` | `--analysis-only` | Save capture evidence without requesting import reconstruction |

Numbers accept decimal or `0x` hexadecimal. A reviewed address at VA
`0x405252`, when the **actual** capture base is `0x400000`, corresponds to OEP
RVA `0x5252`. The executable header stores the RVA. A clean prologue alone does
not prove that this is the original startup entry.

An explicit OEP is reached using a hardware breakpoint. Without it, the driver
may collect a prologue-based candidate, but the result needs review. Likewise,
an intact original import directory or a run of exact export pointers supplies
range proposals; proposals alone do not authorize IAT mutation. Validate the
boundaries against code references and debugger evidence. Do not treat every
function pointer in initialized data as an import-table slot.

Once the OEP and full IAT extents are reviewed, add those values to the capture
command and omit `-AnalysisOnly`. The driver rebuilds only when the requested
OEP was reached, required section bytes were readable, and every nonzero slot
in the reviewed extents has an exact admissible DLL/name or DLL/ordinal mapping.
Intact original import metadata can disambiguate public DLL forwarders. Manual
DLL selections must still match the captured exports; they cannot invent an API.

## Saved evidence and offline reconstruction

For an output named `target_unpacked.exe`, the capture writes separate files:

| File | Purpose |
| --- | --- |
| `target_unpacked.exe` | Rebuilt PE or explicitly labelled analysis dump |
| `target_unpacked.exe.memory.bin` | Captured memory-layout image |
| `target_unpacked.exe.capture.json` | Process/module identity, exact pointers and export candidates, hashes and capture gaps |
| `target_unpacked.exe.imports.json` | Review plan referencing the exact capture and memory hashes |
| `target_unpacked.exe.report.json` | Operation result, import/entry status and limitations |

Existing input, output and evidence files are preserved. Choose a new output
name for every attempt. Keep these files together and outside the public source
repository: they contain application bytes, paths and runtime evidence.

Inspect the capture and edit the review plan. Confirm the entry point, choose
the complete intended IAT ranges, and resolve each nonzero slot using one of
its recorded exact export candidates. Then set `reviewed` to `true`. Do not
remove an unresolved slot just to make a table appear complete. The offline
reader checks selected ranges, slot addresses, symbol identities and hashes.
An identity absent from the capture requires better evidence, not a guessed
function name.

Same-address aliases can occur even in ordinary Windows DLLs. For an ambiguous
slot, fill the plan's `dll` and either `name` or `ordinal` from its recorded
`candidates`, based on independent evidence such as an intact original lookup
table or the caller's verified behavior. Leave the other identity field `null`.
The `status` field describes the capture; changing it does not bypass the
candidate checks. Do not select the first candidate merely to clear a warning.

```powershell
.\rea-unpack.ps1 -RebuildPlan .\analysis\target_unpacked.exe.imports.json `
  -Output .\analysis\target_repaired.exe
```

The corresponding Python entry point is `unpack.py --rebuild-plan ... --output
...`. No target is launched in offline mode. Hash checks bind the plan to its
capture; they are not signatures proving who created that capture.

## Reading the result

| Exit/status | Meaning |
| --- | --- |
| `0`, `ok: true`, `imports_rebuilt: true` | Selected import structures and the written entry point passed structural verification |
| `3`, `ok: false`, review required | Evidence/analysis output exists, but a completed import rebuild was not established |
| `1`, failure | Validation, capture, file output or another required operation failed; inspect `error` |

`runtime_verified` and `portable_verified` remain false in the reconstruction
report. Run a separate, authorized behavioral test to establish execution for
that particular output. The source-owned test harness records its independent
runtime verdict in a different receipt. Opening the file in IDA/Ghidra or
counting recovered functions is not such a runtime test.

Import metadata is written in a new `.reaiat` section. Original IAT slot RVAs
and order stay fixed, while `OriginalFirstThunk` points at new lookup data.
The original calls continue to address their existing slots. Name and ordinal
imports, forwarder aliases and 32-/64-bit thunk widths are handled explicitly.
The result is reparsed before publication. Bound-import data and invalidated
signature metadata are cleared with disclosure; preserved debug records have
their raw file pointers remapped where the payload is available.

## Reconstruction boundaries

| Area | Treatment |
| --- | --- |
| Unresolved/interior/hooked pointers | No nearest-symbol guess or fabricated API; review/failure |
| Equal-address aliases | Preserve candidates and require an unambiguous or reviewed identity |
| API-set contracts | Preserve available evidence; a physical host export does not prove the original contract or cross-version compatibility |
| IAT layout | Each DLL run needs an existing null terminator; no unsafe relocation of referenced slots |
| Header space | A new section header needs unused space; occupied padding is rejected |
| Multiple IAT sections | Unsupported for this writer; report the boundary rather than widening unrelated page protections |
| Relocations | Preserve structurally valid captured records; do not invent missing relocations or claim ASLR support |
| TLS and Load Config | Preserve captured data when available and report that initialization/security semantics were not reconstructed |
| Delay imports | Report separately; do not silently convert them into eager imports |
| Debug/certificate overlays | File-only content may be absent from memory and cannot be recovered from the snapshot |
| Data/code boundaries | Keep captured bytes; disassembler classifications and original initialized state remain uncertain |

Capturing an already running program can preserve changed globals, heap
pointers, TLS state and handles that are invalid in a fresh process. Structural
IAT repair does not undo those changes. Live mode is bounded to x86/x64 EXEs and
512 MiB images; a reviewed memory capture can be rebuilt offline independently.

## Verification commands

```powershell
python -m pip install -r scripts\rea-unpack\requirements-dev.txt
python -m ruff check scripts\rea-unpack
python -m mypy --config-file scripts\rea-unpack\pyproject.toml scripts\rea-unpack
python -m unittest discover -s scripts\rea-unpack\tests -p "test_*.py" -v
```

For the real debugger/loader test, run
`scripts/test-rea-unpack-windows.ps1` with `-BridgePython` and `-X64dbgRoot`
pointing at the installed bridge. It compiles owned fixtures with MSVC, checks
x86 and x64 separately, and expects exactly `REA_IAT_OK=42` followed by CRLF.
The receipt includes input/output hashes, import slots/names, resource equality
and actual process exit/output checks. If Windows exposes equal-address aliases,
the harness reviews them against its own compiled fixture's original imports,
then exercises the offline PowerShell launcher with that recorded selection.
See [TESTING.md](TESTING.md).

## Format references

- [Microsoft PE/COFF specification](https://learn.microsoft.com/en-us/windows/win32/debug/pe-format)
- [Microsoft API-set loader operation](https://learn.microsoft.com/en-us/windows/win32/apiindex/api-set-loader-operation)
- [x64dbg expression functions](https://help.x64dbg.com/en/latest/introduction/Expression-functions.html)
- [x64dbg Automate Python client](https://github.com/dariushoule/x64dbg-automate-pyclient)
- [Scylla upstream](https://github.com/NtQuery/Scylla), for the established distinction between a memory dump and reconstructed imports

This implementation uses its own PE writer and the installed debugger bridge;
it does not bundle or claim to invoke Scylla.
