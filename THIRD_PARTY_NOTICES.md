# Third-party software and source

The MIT license in the repository covers QuixiDesk-derived code and this edition's changes. Each bundled dependency retains its own license and notices. No commercial reverse engineering engine or provider subscription license is included.

| Component | Project/source | License and location in the release |
| --- | --- | --- |
| QuixiDesk base | https://github.com/QuixiAI/QuixiDesk | MIT; root LICENSE and NOTICE.md |
| REA 6.8.0 | https://github.com/morluto/rea | MIT for REA-authored code; `resources/plugins/rea/node_modules/rea-agents/LICENSE`, THIRD_PARTY_NOTICES.md and licenses/ |
| Node 24.22.1 | https://nodejs.org/dist/v24.22.1/ | Node's LICENSE, including bundled dependency notices, in `resources/plugins/rea/node/` |
| Ghidra 12.1.4 | https://github.com/NationalSecurityAgency/ghidra/releases/tag/Ghidra_12.1.4_build | Apache 2.0 plus component-specific licenses; the complete release keeps LICENSE, licenses/, and GPL/ including its source |
| Temurin JDK 21.0.12.1+1 | https://github.com/adoptium/temurin21-binaries/releases/tag/jdk-21.0.12.1%2B1 | GPLv2 with Classpath Exception and other notices; JDK LICENSE/legal/ are retained. The matching full upstream source archive is included at `third-party-source/temurin21-21.0.12.1-sources.tar.gz`, in addition to JDK lib/src.zip. |
| Rust dependencies | Pinned Cargo.lock | `licenses/rust-dependencies.json`, copied notices in `licenses/rust/`, and exact registry source archives in `third-party-source/rust/` |
| npm dependencies | Pinned REA package-lock.json | Their files and notices remain in node_modules; `licenses/npm-dependencies.json` indexes their versions, licenses, and relative locations. |
| Microsoft VC runtime DLLs | Visual Studio Build Tools redistributable directory | Microsoft redistributable binaries, not covered by MIT. See https://learn.microsoft.com/visualstudio/releases/2022/redistribution and the terms of the Visual Studio distribution used for the build. |
| Microsoft Edge WebView2 | https://developer.microsoft.com/microsoft-edge/webview2/ | An installed system prerequisite; no Microsoft WebView2 installer or runtime is included in the ZIP. |

`collect-notices.ps1` produces the machine-independent dependency inventory and preserves the exact downloaded Rust crate source archives. The package script does not copy Cargo's cache paths or the build account's home directory into the inventory. Source archives may contain upstream examples/test data and are distributed with their own notices.

Runtime download URLs and checksums are pinned in `scripts/prepare-rea-windows.ps1`. Corresponding upstream sources for Node are available at its versioned distribution URL; the Ghidra tag identifies its source tree. If modifying or redistributing a dependency, review the license in that component, including any source, attribution, or notice requirements. Do not relabel all bundled software as MIT.
