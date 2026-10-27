# Security and data handling

The supported public surface is the Windows playground, its provider APIs, and its persistent REA plugin. Code-mode PowerShell runs as the user and is not an OS sandbox. Provider credentials use local configuration files and are not encrypted by the application. Model requests may include project or analysis content.

Report vulnerabilities using GitHub's **Security → Report a vulnerability** facility when available. If it is unavailable, open a minimal issue asking for a private reporting channel, without exploit details, credentials, private artifacts, or personal data. Ordinary reproducible bugs can be reported in Issues with redacted logs.

Do not include `%USERPROFILE%\.quixi`, WebView profiles, provider keys, token-bearing URLs, private binaries, or analysis records in public reports. Check screenshots for hostnames, paths, and credentials.

The public desktop shell has no legacy automation listener. Development remote debugging must be explicitly enabled and should be closed after testing. Download release archives from this repository's Releases page and compare their SHA-256 sidecars before installing.
