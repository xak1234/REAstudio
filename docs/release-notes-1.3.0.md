REA Studio V1.3.0

This release strengthens supervised reverse engineering with artifact identity, configurable analysis resources, richer behavioural checks and reproducible integration verification.

- Pin file evidence and analysis briefs to SHA-256. Dossiers retain excluded-record reasons instead of silently mixing builds at one path; directory identity remains explicitly unverified.
- Browse saved artifact versions and show the actual connected REA identity alongside bundled versions.
- Configure Ghidra heap, provider startup and call deadlines, with validated atomic settings and explicit reconnect behaviour.
- Route Agent models by connection and model ID, repair stale defaults, reserve model context conservatively and preserve bounded investigation notes across interruption without replaying actions.
- Compare expected files by existence, exact text, SHA-256 or structural JSON, with per-case timeouts and bounded suite sizes. Stop checks terminates owned processes.
- Repair oracle approval display and native UI smoke coverage; report live integrations as executed, failed or skipped.
- Add a source-known optimized C++ EXE/DLL fixture with branches, imports, cross-references and file output.

Existing saved evidence is preserved. File dossiers exclude legacy records that cannot establish the current binary's identity; reanalyse those inputs for a verified dossier. The default bundled stack remains REA 6.8.0, Ghidra 12.1.4, Node 24.22.1 and JDK 21.

This release supports staged, reviewed investigations. Passing declared checks does not establish complete application equivalence; GUI, distributed and nondeterministic behaviours require a suitable external harness.
