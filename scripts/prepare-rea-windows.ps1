[CmdletBinding()]
param([string]$Destination = (Join-Path $PSScriptRoot '..\resources\plugins\rea'))
$ErrorActionPreference = 'Stop'
$Destination = [IO.Path]::GetFullPath($Destination)
New-Item $Destination -ItemType Directory -Force | Out-Null
$cache = Join-Path ([IO.Path]::GetTempPath()) 'quixidesk-dependencies'
New-Item $cache -ItemType Directory -Force | Out-Null
function Get-VerifiedArchive([string]$Uri, [string]$Name, [string]$Sha256) {
    $path = Join-Path $cache $Name
    if (!(Test-Path $path) -or (Get-FileHash $path -Algorithm SHA256).Hash -ne $Sha256) {
        Invoke-WebRequest -Uri $Uri -OutFile $path
    }
    if ((Get-FileHash $path -Algorithm SHA256).Hash -ne $Sha256) { throw "Checksum mismatch: $Name" }
    return $path
}
function Expand-Runtime([string]$Archive, [string]$ArchiveRoot, [string]$Target) {
    if (Test-Path (Join-Path $Destination $Target)) { return }
    $temporary = Join-Path $cache ([guid]::NewGuid().ToString())
    Expand-Archive -LiteralPath $Archive -DestinationPath $temporary
    Move-Item (Join-Path $temporary $ArchiveRoot) (Join-Path $Destination $Target)
    Remove-Item $temporary -Recurse
}
# Exact upstream versions; all archives are checked before extraction.
$nodeVersion = '24.22.1'
$nodeName = "node-v$nodeVersion-win-x64.zip"
$nodeSha = 'd2046d28c2c3dcd211ac5145c0bf30e2047ef9dfb306693c8c6e2eccd8b95fa5'
$node = Get-VerifiedArchive "https://nodejs.org/dist/v$nodeVersion/$nodeName" $nodeName $nodeSha
Expand-Runtime $node "node-v$nodeVersion-win-x64" 'node'
$ghidra = Get-VerifiedArchive 'https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.1.4_build/ghidra_12.1.4_PUBLIC_20260921.zip' 'ghidra-12.1.4.zip' 'ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db'
Expand-Runtime $ghidra 'ghidra_12.1.4_PUBLIC' 'ghidra'
$jdk = Get-VerifiedArchive 'https://github.com/adoptium/temurin21-binaries/releases/download/jdk-21.0.12.1%2B1/OpenJDK21U-jdk_x64_windows_hotspot_21.0.12.1_1.zip' 'jdk-21.0.12.1.zip' 'f9d6e191ab098c0d416e7d588a24420a8621cd2f4720dab2459b8b7b2d2d8b4e'
Expand-Runtime $jdk 'jdk-21.0.12.1+1' 'jdk'
$jdkSource = Get-VerifiedArchive 'https://github.com/adoptium/temurin21-binaries/releases/download/jdk-21.0.12.1%2B1/OpenJDK21U-jdk-sources_21.0.12.1_1.tar.gz' 'temurin21-21.0.12.1-sources.tar.gz' '573057d03584ae793fb7ec9a14c76d826d9187a53efeefd99da47403a5308234'
New-Item (Join-Path $Destination 'sources') -ItemType Directory -Force | Out-Null
Copy-Item -LiteralPath $jdkSource -Destination (Join-Path $Destination 'sources\temurin21-21.0.12.1-sources.tar.gz')
$previousPath = $env:PATH
try {
    $env:PATH = (Join-Path $Destination 'node') + ';' + $env:PATH
    $npm = Join-Path $Destination 'node\npm.cmd'
    if (Test-Path (Join-Path $Destination 'package-lock.json')) {
        & $npm ci --prefix $Destination --omit=dev --omit=optional --no-audit --no-fund
    } else { throw 'The locked public build requires package-lock.json.' }
    if ($LASTEXITCODE -ne 0) { throw 'REA dependency installation failed' }
    & (Join-Path $Destination 'node\node.exe') (Join-Path $Destination 'node_modules\rea-agents\scripts\rea.mjs') --version
    if ($LASTEXITCODE -ne 0) { throw 'REA launcher check failed' }
} finally { $env:PATH = $previousPath }
# Deploy repo-local REA skills into the vendored rea-agents package (npm ci would
# otherwise not know about them). Tracked under resources\rea-skills.
$localSkills = Join-Path $PSScriptRoot '..\resources\rea-skills'
if (Test-Path $localSkills) {
    $skillsTarget = Join-Path $Destination 'node_modules\rea-agents\skills'
    New-Item $skillsTarget -ItemType Directory -Force | Out-Null
    foreach ($skill in Get-ChildItem -LiteralPath $localSkills -Directory) {
        Copy-Item -LiteralPath $skill.FullName -Destination $skillsTarget -Recurse -Force
    }
    Write-Host "Deployed local REA skills: $((Get-ChildItem -LiteralPath $localSkills -Directory).Name -join ', ')"
}
Write-Host "REA prepared at $Destination. No system Java or MCP registrations were changed."
