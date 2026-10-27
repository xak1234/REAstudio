# Toolchain and integration boundaries

Open **Reverse engineering → Toolchain** to inspect the actual files found and choose paths. Detection checks the portable tool directory, configured paths and PATH; it does not launch tools or claim their providers are ready. Use **Prepare version check** and Run in Terminal to verify a CLI. GUI launch opens the tool without passing the selected artifact or starting it under a debugger.

| Layer | Component | Integration in this edition |
| --- | --- | --- |
| Analysis core | [REA](https://github.com/morluto/rea) | Bundled stdio MCP, live catalog, persistent sessions and evidence. |
| Analysis core | [Ghidra](https://github.com/NationalSecurityAgency/ghidra) | Bundled headless REA provider; optional GUI launch. |
| Analysis core | [GhidraMCP](https://github.com/LaurieWired/GhidraMCP) | Optional separate GUI extension/MCP setup, linked from Toolchain. QuixiDesk uses REA's own Ghidra bridge; it does not register this second server automatically. |
| Analysis core | [ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp) | Existing licensed IDA and an existing compatible registration, consumed through REA's IDA adapter. |
| Mobile & apps | [JADX](https://github.com/skylot/jadx) | Pinned portable CLI/GUI download; REA Android calls additionally require the supported headless JADX MCP JAR. |
| Mobile & apps | [Apktool](https://github.com/iBotPeaches/Apktool) | Pinned JAR download, launched with the bundled JDK from the terminal. |
| Mobile & apps | [Frida](https://github.com/frida/frida) | User-supplied frida-tools environment and explicit runtime targets; REA's manual runtime tools remain subject to their live availability. |
| Mobile & apps | [ILSpy](https://github.com/icsharpcode/ILSpy) | Pinned self-contained Windows GUI download. ILSpyCmd is a separate upstream CLI option. |
| Binary & low-level | [radare2](https://github.com/radareorg/radare2) | Pinned Windows CLI download, available through the terminal. |
| Binary & low-level | [x64dbg](https://github.com/x64dbg/x64dbg) | Pinned portable Windows debugger; explicitly choose x32/x64 and target after opening. |
| Binary & low-level | [ImHex](https://github.com/WerWolv/ImHex) | Pinned portable Windows hex/pattern editor. |
| Binary & low-level | [angr](https://github.com/angr/angr) | Choose a Python interpreter from an environment where angr is installed; the panel prepares an import/version check. No generic Windows/Python compatibility claim is made. |
| Network & runtime | [mitmproxy](https://github.com/mitmproxy/mitmproxy) | User-supplied mitmweb/mitmdump for Windows. Saved captures can be analysed with advertised REA tools. No automatic interception setup. |
| Network & runtime | [dnSpyEx](https://github.com/dnSpyEx/dnSpy) | Pinned portable .NET debugger/editor download. |
| Network & runtime | [Rizin](https://github.com/rizinorg/rizin) | Pinned Windows CLI download. |
| Network & runtime | [RAD Debugger](https://github.com/EpicGames/raddebugger) | Pinned optional alpha Windows debugger download. |
| Rebuild & verify | REA workflows | Matching instructions/references ship inside rea-agents; read them in Toolchain or via the agent's `rea_workflow` action. |
| Rebuild & verify | [AI RE catalog](https://github.com/zhuyansen/awesome-ai-reverse-engineering), [RE catalog](https://github.com/morluto/awesome-reverse-engineering) | Reference links, not executable engines or a security guarantee. |
| Rebuild & verify | SPEC and oracles | Built-in specification export, real command/output comparison, saved reports and bounded retry tasks. See [RECONSTRUCTION.md](RECONSTRUCTION.md). |

## Portable optional downloads

The core release includes REA, Node, Ghidra and JDK. It includes the optional installer and pinned download catalog, **not all optional executables**. This keeps the core independent of additional tool licenses and platform environments.

From a source checkout:

```powershell
.\scripts\install-toolchain.ps1 -Tool jadx,jadx-mcp,apktool,ilspy,radare2,x64dbg,imhex,dnspy,rizin,raddebugger
```

From the extracted release use `Install-Toolchain.ps1`. The Toolchain panel can prepare a command for one component. Open a destination project before running the prepared command in Terminal.

Downloads use the exact official release URLs and SHA-256 digests recorded in `resources/toolchain.json`. They extract under `resources/toolchain/<id>` and refuse to replace an existing directory. Use `-Destination` for another root, then Choose path in the app. Preserve the upstream license and notice files. These files are ignored by Git and excluded from the core package; redistribution of an expanded tool collection requires its own component/source review.

The installer does not execute installers, add global PATH entries, register shell extensions, alter Java, install proxy certificates, or attach to processes. After installation, refresh detection and verify the tool. Windows SDKs, Python/.NET environments, device/emulator setup and project compilers remain separate prerequisites where required.

## IDA provider

Use upstream's installation instructions for the licensed IDA environment and `ida-pro-mcp`. Follow [REA's current IDA provider guide](https://github.com/morluto/rea/blob/main/docs/ida-provider.md) to create its compatible JSON registration. In Toolchain choose that JSON file under **IDA Pro MCP registration**, then disconnect/restart REA before selecting **IDA** as Native analysis provider and opening the original input binary. Do not select an IDB/I64 database as the original artifact.

QuixiDesk passes the configured file as `REA_IDA_MCP_CONFIG` only to its REA child process. It does not install IDA, change other clients' registrations, claim an IDA Free license is equivalent, or automatically accept upstream licensing terms. Readiness and analysis are established by real REA calls, not by the presence of the JSON file.

## Android provider

Installing the ordinary JADX CLI is useful independently but does not satisfy REA's headless provider contract. Install the pinned headless engine with `Install-Toolchain.ps1 -Tool jadx-mcp`, or choose an existing supported JAR under **JADX MCP JAR**. The standard portable location is discovered when the bundled REA starts. QuixiDesk passes it as `REA_JADX_MCP_JAR` to REA, with the bundled full JDK. Restart the REA connection after changing the path. Read the matching Android workflow and live tool availability before calling package/class/method analysis.

## Runtime tools

Frida, debuggers and traffic proxies serve different jobs. Configure and invoke the one needed for a defined observation. Do not interpret a tool's catalog listing as successful capture, decompilation or observation. Import retained results into your investigation, record their provenance, and turn supported observations into SPEC requirements and oracle cases.
