# Bounded unnamed-function scale fixture

This opt-in fixture generates 2,304 distinct `__declspec(noinline)` arithmetic functions retained by a dispatch table, plus a small quote feature and the linked runtime. It is compiled with optimization, without application exports, a COFF symbol table, a debug directory or a PDB. The PE header and absence of application identifier strings are checked independently. This is a **small synthetic paging/discovery fixture**, not a representative large application or an obfuscation test.

Import names, marker strings and ordinary x64 unwind metadata remain available to the analyzer. These intentional aids are part of the fixture, so this is not a test of recovering arbitrary functions without structural clues.

MSVC may emit type 13 PGO/COFF-group metadata even with `/DEBUG:NONE`. The builder explicitly clears only those records and their bounded payloads in non-executable sections of this generated fixture. It refuses other debug record types or malformed ranges, verifies unchanged executable-section hashes, and records the before/after binary hashes. The completed PE is then rechecked for absent debug/symbol/export metadata. No user-supplied application is modified.

From an x64 Visual Studio Developer PowerShell:

```powershell
$fixture = Join-Path $env:TEMP ('rea-scale-' + [guid]::NewGuid())
.\scripts\prepare-scale-fixture.ps1 -Destination $fixture
$env:REA_STUDIO_SCALE_ROOT = $fixture
node scripts/smoke-scale.cjs --runtime-only
```

The runtime-only check executes the freshly built fixture and verifies twelve declared stdout/stderr/exit-code cases, including tier boundaries, invalid inputs and first/middle/last dispatch entries. Its report explicitly skips static analysis. The fixed dispatch results are source-derived unsigned 32-bit arithmetic expectations.

For the real static check, start REA Studio in a dedicated data/WebView profile with a licensed headless IDA bridge configured and IDA initially disabled. Set `QUIXI_TEST_PLAYWRIGHT_MODULE`, `REA_STUDIO_TEST_DATA` and `REA_STUDIO_TEST_CDP` as described in `docs/TESTING.md`, then:

```powershell
$env:REA_STUDIO_SCALE_REPORT = Join-Path $fixture 'scale-static.json'
node scripts/smoke-scale.cjs
```

The check validates current source/generator/build/binary hashes; requests the live IDA catalog; pages the complete actual function inventory; rejects duplicate addresses, empty continuing pages and invalid/non-advancing cursors; and requires over 2,000 discovered functions. The default ceiling is 10,000 functions with 128 rows per page. `REA_STUDIO_SCALE_MAX_FUNCTIONS` accepts an integer from 100 to 50,000; exceeding the chosen ceiling fails explicitly instead of reporting a partial inventory as complete.

The feature is located through a live format-string search, cross-references and the containing unnamed function's address. Its pseudocode must contain all declared quote facts and have an actual code caller; `WriteFile` and `GetStdHandle` imports are also checked. The benchmark never loads a build map/PDB or looks up application source names. It records evidence IDs, addresses returned by the provider, per-call durations, response sizes, page counts and hash binding. No model or provider responses are simulated, and static mode does not execute the target. Set `REA_STUDIO_SCALE_RUNTIME=1` explicitly to run both modes.

Passing establishes this fixture's selected static facts, paging behavior and optional source-program runtime baseline. It does not prove the correctness of generated source, general symbol recovery, production throughput, complete behavioral equivalence, packed-code recovery or autonomous reconstruction. Ghidra's core path is tested separately; this scale check specifically uses the licensed IDA bridge.
