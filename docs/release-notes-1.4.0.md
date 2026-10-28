REA Studio V1.4.0

This release simplifies access to analysis and task controls, adds persistent investigations across related modules, and protects unsaved work when the native window closes.

- Move around the same analysis page with Analyze, Saved evidence, Investigations, Rebuild and Advanced tools shortcuts. Collapse Files and Task settings to widen the work area; desktop choices persist, and narrow-window overlays dismiss with Escape.
- Keep the selected model and access mode visible by the task controls. Use Expert view or individual disclosures for exact JSON arguments and live schemas; optional bridges and runtime settings remain available under Advanced tools.

- Capture a named set of up to 32 local files with immutable SHA-256 identities. Reopen the set later and inspect changed, missing or unavailable inputs alongside matching, excluded, failed and model-suggestion evidence counts.
- Export a new version-pinned evidence bundle into a separate project. The manifest records each module's coverage, retained raw-record hashes and exclusion reasons; all artifacts are checked again before the staged bundle becomes final.
- Manage the same sets through the desktop or the new `studio_investigation` MCP tool. The MCP catalog now has 28 tools. Deleting a set requires `confirmDelete: true` through MCP and removes only its metadata.
- On native window close, cancel, save and close, or explicitly discard the editor buffer. Save conflicts keep the window open. Running backend work is disclosed, and an unresponsive interface receives a native confirmation with No as the default.
- Add reproducible investigation/native-close integration scripts, focused CI coverage and a source-known 2,304-function optimized fixture for bounded paging and unnamed-function discovery.

Existing settings, saved evidence, single-artifact dossiers and reconstruction workflows remain compatible. Investigation storage is project-scoped in application data. Exports never execute or copy the original targets, and size/count limits fail explicitly. The default bundled stack remains REA 6.8.0, Ghidra 12.1.4, Node 24.22.1 and JDK 21.

An investigation bundle establishes which saved observations belong to which file versions. It does not establish complete application coverage or behavioral equivalence. Failed observations and unverified model suggestions keep those labels. See [Investigations](INVESTIGATIONS.md) and [Windows verification](TESTING.md) for limits, test prerequisites and the distinction between executed and untested coverage.
