---
name: unpack-packed-binary
description: Unpack a runtime-packed/compressed Windows PE (PECompact, UPX, ASPack, MPRESS, FSG and similar) so static analysis can see the real code. Use when a native PE opens with almost no functions, a tiny high-entropy .text, an "imports segment seems destroyed" warning, or a known packer signature, and you need the decompressed image. Produces a rebuilt, analysable PE via a live run-to-OEP dump with x64dbg. Skip for unpacked binaries, managed/.NET assemblies, scripts, and any binary the user does not trust to execute.
metadata:
  version: "1"
  requires: ["x64dbg + x64dbg-automate bridge (Studio toolchain)"]
---

# Unpack a packed Windows PE

A runtime packer compresses the real program and ships only a small loader
stub. Static tools (Ghidra, IDA) then see just the stub — typically 1-2
functions, a high-entropy `.text`, and a broken import table. The only way to
recover the real code is to let the stub decompress the image in memory and
dump it. That means **executing the target**, so this runs only on binaries the
user trusts, and it asks the user to confirm.

## When to use

Reach for this when a native PE shows ANY of:
- `list_procedures` / binary overview returns 1-2 functions on a non-trivial exe
- `.text` raw entropy ~7.8+ (compressed), or `inspect_binary_layout` flags high per-section entropy
- the loader prints "the imports segment seems to be destroyed … the file was packed"
- a packer signature in strings or at entry (e.g. `PECompact`, `UPX!`, `aPLib`, `MPRESS`)

Do NOT use it for already-unpacked binaries, .NET/managed assemblies (use the
managed tools), interpreted/script apps, or anything the user has not said is
safe to run.

## How it works

The `rea-unpack` tool drives x64dbg (via the x64dbg-automate bridge) to:
1. detect the target's architecture and pick x32dbg (x86) or x64dbg (x64),
2. launch it under the debugger with the PEB debugger flag hidden,
3. run with exceptions passed through to the target, so SEH-based decompressors
   (PECompact and friends) complete their work,
4. step past the stub until execution reaches the original entry point (OEP) in
   `.text` at a real function prologue,
5. dump the now-decompressed image and rebuild a static PE whose sections are
   realigned (raw offset = virtual address) with the import table resolved
   in-image, so a disassembler maps it 1:1.

## Prerequisites

- The x64dbg bridge must be installed (Studio: `Install-X64dbg-Bridge.ps1`).
  Confirm `E:\tools\REA-Studio\resources\toolchain\x64dbg\release` and the
  `x64dbg-bridge` venv exist.
- **The driver must run elevated** so x64dbg can launch admin-manifest targets
  (`requireAdministrator`); otherwise CreateProcess fails with error 740. The
  launcher self-elevates and surfaces one UAC prompt — tell the user to expect it.
- Confirm with the user that the target is safe to execute before running.

## Run it

From the project root (or anywhere), via `studio_command` or a shell:

```
powershell -ExecutionPolicy Bypass -File ^
  E:\git\rea\bridge\unpack\rea_unpack\rea-unpack.ps1 ^
  -Target "<path-to-packed.exe>" -Output "<path-to-unpacked.exe>" -Trusted
```

It prints one JSON object. Key fields: `ok`, `arch`, `oep`, `oep_found`,
`packed_entropy` vs `unpacked_entropy` (a large drop, e.g. 6.8 -> 3.9, confirms
decompression), `output` (the rebuilt PE), `output_sha256`.

Omit `-Output` to write `<input>_unpacked.exe` beside the source. `-Trusted` is
mandatory and records that the user accepted executing the target.

## After unpacking

Point the analysis at the **rebuilt** file, not the original:
`studio_rea_select` the `output` path, then `open_binary` (provider `ghidra` or
`ida`) and `list_procedures`. A successful unpack turns a 1-2 function result
into the real function set (for the reference target ValiDrive: 2 -> ~318).

If `oep_found` is false but `ok` is true, the dump still captured decompressed
code (check the entropy drop); the OEP just wasn't latched, so analysis may
start at the stub entry. Re-run, or set the entry to the OEP manually in the
disassembler. If the process exits before OEP (`note: "process exited"`), the
target may refuse to run under a debugger or need runtime state (a device, a
server); capture what decompressed and note the limitation.

## Safety

This executes the target. Never run it on untrusted or unknown binaries. It
does not modify the original file; it writes a separate rebuilt PE. It changes
nothing global and makes no network calls of its own.
