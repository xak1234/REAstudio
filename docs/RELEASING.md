# Publishing a Windows release

The source repository and portable application are separate artifacts. Keep runtimes, user profiles, private projects, credentials, and analysis records out of Git. Release assets carry the built runtime bundle.

## Maintainer procedure

1. Every delivered update needs a new version, including fixes and documentation corrections. Run `node scripts/bump-version.mjs patch`, or choose `minor`/`major` for the corresponding release. The helper updates Cargo.toml, workspace entries in Cargo.lock and current download/documentation references. Add the new CHANGELOG.md entry and matching release notes, then run `node scripts/check-version.mjs`. CI rejects a main-branch or pull-request update whose version has not increased. Window, HTML and MCP labels come from the compiled package version. Keep `rust-toolchain.toml`, REA's package.json/package-lock.json, plugin.json, and runtime checksums consistent when changing dependencies.
2. Run the public audit, JavaScript syntax checks, Rust check/Clippy, and focused tests from README.md. Run the native UI/Ghidra check from TESTING.md on an interactive Windows account.
3. Build the package with `scripts/package-windows.ps1`. Review BUILD-INFO.json, SHA256SUMS.json, the generated dependency inventories, preserved licenses, and corresponding source archives. Verify the ZIP and test its extracted copy.
4. Commit the reviewed source to `main`. Create and push a matching annotated tag:

   ```powershell
   git tag -a v1.3.0 -m 'REA Studio 1.3.0'
   git push origin main
   git push origin v1.3.0
   ```

5. The Windows workflow rebuilds and tests the tagged source, uploads its artifacts, and creates a **draft** GitHub Release with the ZIP and `.sha256` sidecar. Review its notes and assets, then publish the draft. This is not a GitHub Pages deployment.

Do not reuse a published tag or overwrite a published archive. Fixes should receive a new version so hashes and source provenance remain meaningful. A manual Actions run creates build artifacts but does not create a version tag or publish a release.

## Manual upload with GitHub CLI

If publishing a locally verified build rather than the workflow artifact, authenticate GitHub CLI normally and use:

```powershell
gh release create v1.3.0 `
  .\dist\REA-Studio-1.3.0-x64.zip `
  .\dist\REA-Studio-1.3.0-x64.zip.sha256 `
  --repo xak1234/REAstudio `
  --verify-tag --draft --title 'REA Studio 1.3.0' `
  --notes-file .\docs\release-notes-1.3.0.md
```

Use the exact source commit recorded in the package's BUILD-INFO.json. Review and publish the draft using GitHub's Releases interface. No personal access token belongs in the repository or in a command copied into the README.

The workflow pins third-party actions by commit, gives the build read-only repository permission, and grants write permission only to the tag-triggered draft-release job. Pull requests do not publish artifacts or run with model provider credentials.
