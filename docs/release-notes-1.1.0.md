REA Studio V1.1 (1.1.0) continues the QuixiDesk Windows coding and reverse engineering workspace.

- New REA Studio branding, REAStudio.exe, installer and portable package; existing settings, runs and evidence remain compatible.
- Optional token-protected local MCP server with enable/disable controls, connection config and actual agent activity.
- Agent code imports create separate projects for analysis or coding assistance, with an in-app handoff that preserves unsaved editor work.
- Classic launcher tucked inside MCP & Settings, using the earlier installed application.
- Missing API keys resolved from matching provider environment variables without persisting discovered secrets.
- Guided function and string inputs prevent empty requests. Advanced JSON stays available and survives catalog refreshes.
- Real retained functions and strings appear in paged tables. Local functions can be decompiled directly; external imports and discovery limits remain explicit.
- Existing binary → REA → SPEC → rebuild → oracle → retry workflow and pinned REA/Ghidra runtime retained.

Extract the complete REA-Studio-1.1.0-x64.zip and launch REAStudio.exe. Close the previous QuixiDesk instance before using the same data profile. Windows x64 and WebView2 are required. ValiDrive resource bytes outside file-backed sections remain an analysis limitation; native code analysis does not establish complete reconstruction.
