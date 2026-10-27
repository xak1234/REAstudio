[CmdletBinding()]
param(
    [switch]$SkipBuild,
    [switch]$SkipDependencyDownload,
    [switch]$NoZip,
    [string]$BuildOutput = ''
)
$ErrorActionPreference = 'Stop'
$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
if (!$BuildOutput) {
    $target = if ($env:CARGO_TARGET_DIR) { $env:CARGO_TARGET_DIR } else { Join-Path $repo 'target' }
    $BuildOutput = Join-Path $target 'release'
}
Push-Location $repo
try {
    if (!$SkipBuild) {
        & cargo build --release --workspace --locked
        if ($LASTEXITCODE -ne 0) { throw 'Windows build failed. Install Rust MSVC, Visual Studio C++ Build Tools and Windows SDK.' }
    }
    if (!$SkipDependencyDownload) { & (Join-Path $PSScriptRoot 'prepare-rea-windows.ps1') }
    $runtime = Join-Path $repo 'resources\plugins\rea'
    foreach ($path in @('node\node.exe','node_modules\rea-agents\scripts\rea.mjs','node_modules\rea-agents\native\windows\build\rea-windows-x64.node','ghidra\support\analyzeHeadless.bat','jdk\bin\javac.exe','sources\temurin21-21.0.12.1-sources.tar.gz')) {
        if (!(Test-Path -LiteralPath (Join-Path $runtime $path))) { throw "Missing bundled dependency: $path" }
    }
    $reaVersion = (Get-Content (Join-Path $runtime 'node_modules\rea-agents\package.json') -Raw | ConvertFrom-Json).version
    if ($reaVersion -ne '6.8.0') { throw 'Expected REA 6.8.0. Re-run dependency preparation in a clean checkout.' }
    $nodeVersion = & (Join-Path $runtime 'node\node.exe') --version
    if ($nodeVersion -ne 'v24.22.1') { throw 'Bundled Node version does not match the release.' }
    if (!(Select-String -LiteralPath (Join-Path $runtime 'ghidra\Ghidra\application.properties') -Pattern '^application.version=12\.1\.4$' -Quiet)) { throw 'Unexpected Ghidra version.' }
    if (!(Select-String -LiteralPath (Join-Path $runtime 'jdk\release') -Pattern '^JAVA_VERSION="21\.0\.12\.1"$' -Quiet)) { throw 'Unexpected Temurin version.' }
    $version = ((Select-String -LiteralPath Cargo.toml -Pattern '^version = "([^"]+)"$' | Select-Object -First 1).Matches[0].Groups[1].Value)
    $name = "QuixiDesk-Windows-REA-$version-x64"
    $output = Join-Path $repo "dist\$name"
    if ((Test-Path $output) -or (Test-Path "$output.zip")) { throw "Output exists: $output. Choose a new version or move the old output aside." }
    New-Item $output -ItemType Directory -Force | Out-Null
    Copy-Item -LiteralPath (Join-Path $BuildOutput 'QuixiDesk.exe') -Destination $output
    $resources = Join-Path $output 'resources'
    New-Item (Join-Path $resources 'plugins') -ItemType Directory -Force | Out-Null
    Copy-Item -LiteralPath resources\playground -Destination $resources -Recurse
    Copy-Item -LiteralPath resources\quixi-mark.svg,resources\quixi-logo.svg -Destination $resources
    Copy-Item -LiteralPath resources\toolchain.json -Destination $resources
    Copy-Item -LiteralPath $runtime -Destination (Join-Path $resources 'plugins\rea') -Recurse
    Copy-Item -LiteralPath LICENSE,NOTICE.md,THIRD_PARTY_NOTICES.md,README.md,CHANGELOG.md,SECURITY.md -Destination $output
    Copy-Item -LiteralPath docs -Destination $output -Recurse
    Copy-Item -LiteralPath scripts\install-windows.ps1 -Destination (Join-Path $output 'Install-QuixiDesk.ps1')
    Copy-Item -LiteralPath scripts\install-toolchain.ps1 -Destination (Join-Path $output 'Install-Toolchain.ps1')
    $source = Join-Path $output 'third-party-source'
    New-Item $source -ItemType Directory -Force | Out-Null
    Move-Item (Join-Path $resources 'plugins\rea\sources\*') $source
    Remove-Item (Join-Path $resources 'plugins\rea\sources')
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (!(Test-Path $vswhere)) { throw 'Visual Studio Build Tools are needed to collect the redistributable VC runtime.' }
    $vs = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    $crt = Get-Item "$vs\VC\Redist\MSVC\*\x64\Microsoft.VC143.CRT" -ErrorAction SilentlyContinue | Sort-Object FullName -Descending | Select-Object -First 1
    if (!$crt) { throw 'VC runtime redistributable DLLs are missing.' }
    Copy-Item (Join-Path $crt.FullName '*.dll') $output
    & (Join-Path $PSScriptRoot 'collect-notices.ps1') -OutputDirectory $output
    $commit = (& git rev-parse HEAD 2>$null)
    if ($LASTEXITCODE -ne 0) { $commit = 'source-archive' }
    [pscustomobject]@{application='QuixiDesk Windows';version=$version;sourceCommit=$commit;platform='windows-x86_64';rea='6.8.0';node='24.22.1';ghidra='12.1.4';jdk='21.0.12.1+1'} | ConvertTo-Json | Set-Content (Join-Path $output 'BUILD-INFO.json') -Encoding utf8
    Write-Host 'Writing the file integrity manifest...'
    $manifest = Get-ChildItem -LiteralPath $output -File -Recurse | ForEach-Object {
        [pscustomobject]@{path=$_.FullName.Substring($output.Length+1).Replace('\','/');sha256=(Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant();bytes=$_.Length}
    }
    $manifest | ConvertTo-Json -Depth 3 | Set-Content (Join-Path $output 'SHA256SUMS.json') -Encoding utf8
    if (!$NoZip) {
        Write-Host 'Compressing the portable release...'
        & tar.exe -a -c -f "$output.zip" -C (Split-Path $output) $name
        if ($LASTEXITCODE -ne 0) { throw 'Archive creation failed.' }
        $hash = (Get-FileHash -LiteralPath "$output.zip" -Algorithm SHA256).Hash.ToLowerInvariant()
        "$hash  $name.zip" | Set-Content "$output.zip.sha256" -Encoding ascii
        Write-Host "SHA256: $hash"
    }
    Write-Host "Packaged: $output"
} finally { Pop-Location }
