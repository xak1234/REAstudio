# Publishing a Windows release

The source repository and portable application are separate artifacts. Keep runtimes, user profiles, private projects, credentials, and analysis records out of Git. Release assets carry the built runtime bundle.

## Maintainer procedure

1. Update the workspace version in Cargo.toml and regenerate Cargo.lock. Update CHANGELOG.md and the README's versioned download name. Keep `rust-toolchain.toml`, REA's package.json/package-lock.json, plugin.json, and runtime checksums consistent when changing dependencies.
2. Run the public audit, JavaScript syntax checks, Rust check/Clippy, and focused tests from README.md. Run the native UI/Ghidra check from TESTING.md on an interactive Windows account.
3. Build the package with `scripts/package-windows.ps1`. Review BUILD-INFO.json, SHA256SUMS.json, the generated dependency inventories, preserved licenses, and corresponding source archives. Verify the ZIP and test its extracted copy.
4. Commit the reviewed source to `main`. Create and push a matching annotated tag:

   ```powershell
   git tag -a v1.1.0 -m 'REA Studio 1.1.0'
   git push origin main
   git push origin v1.1.0
   ```

5. The Windows workflow rebuilds and tests the tagged source, uploads its artifacts, and creates a **draft** GitHub Release with the ZIP and `.sha256` sidecar. Review its notes and assets, then publish the draft. This is not a GitHub Pages deployment.

Do not reuse a published tag or overwrite a published archive. Fixes should receive a new version so hashes and source provenance remain meaningful. A manual Actions run creates build artifacts but does not create a version tag or publish a release.

## Manual upload with GitHub CLI

If publishing a locally verified build rather than the workflow artifact, authenticate GitHub CLI normally and use:

```powershell
gh release create v1.1.0 `
  .\dist\REA-Studio-1.1.0-x64.zip `
  .\dist\REA-Studio-1.1.0-x64.zip.sha256 `
  --repo xak1234/QuixiDesk-Windows `
  --verify-tag --draft --title 'REA Studio 1.1.0' `
  --notes-file .\docs\release-notes-1.1.0.md
```

Use the exact source commit recorded in the package's BUILD-INFO.json. Review and publish the draft using GitHub's Releases interface. No personal access token belongs in the repository or in a command copied into the README.

The workflow pins third-party actions by commit, gives the build read-only repository permission, and grants write permission only to the tag-triggered draft-release job. Pull requests do not publish artifacts or run with model provider credentials.
