# REA Studio Windows development

- This is the public Windows playground edition. Keep changes within the requested scope.
- Read README.md and docs/TESTING.md before altering launch, packaging, or analysis behaviour.
- Do not add private endpoints, keys, user profiles, analysis evidence, extracted application assets, or downloaded runtimes to Git.
- Use `quixi_platform::background_command` for background CLI processes to avoid Windows console flashes.
- Use the running REA tool catalog and input schemas. Do not invent tool results or report a successful opening as successful deep analysis.
- Preserve the MIT attribution and bundled third-party notices/source. System Java and other clients' MCP registrations must not be changed.
- Validate the public shell with the documented Windows checks. Legacy engine modules are not a guarantee of public UI support.
