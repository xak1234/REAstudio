REA Studio V1.1.1 (1.1.1) makes the current coding and reverse engineering release identifiable throughout the application.

- The native window, interface and MCP server report the compiled package version.
- Every delivered update must increase the version; the release helper updates workspace metadata and CI checks the increase.
- IDA and Ghidra connection labels turn green after a successful provider observation. Opening a file prepares its provider without claiming a live connection.
- Attached IDA integration has been checked with IDA Professional 9.3, including real function listings, pseudocode, assembly and rejection of a different input binary.
- Existing settings, source projects, evidence, x64dbg support and separate LLM4Decompile configuration remain compatible.

Extract the complete `REA-Studio-1.1.1-x64.zip` and run `REAStudio.exe`. Keep one current installation, archive earlier copies, and point your shortcut at the current executable. Close the app before moving or replacing its files. Optional tool environments and MCP registrations may contain absolute paths and must be reconfigured if their installation moves.

The optional IDA integration requires a licensed installation and compatible bridge. Successful decompilation does not establish original source recovery or complete behavioural equivalence.
