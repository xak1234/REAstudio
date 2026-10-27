[CmdletBinding()]
param([Parameter(Mandatory=$true)][string]$OutputDirectory)
$ErrorActionPreference = 'Stop'
$repo = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$licenses = Join-Path $OutputDirectory 'licenses\rust'
$sources = Join-Path $OutputDirectory 'third-party-source\rust'
New-Item $licenses,$sources -ItemType Directory -Force | Out-Null
Push-Location $repo
try {
    $metadataText = & cargo metadata --locked --format-version 1 --filter-platform x86_64-pc-windows-msvc
    if ($LASTEXITCODE -ne 0) { throw 'Could not resolve locked dependency metadata.' }
    $metadata = ($metadataText -join "`n") | ConvertFrom-Json
    $inventory = @()
    foreach ($package in $metadata.packages) {
        if (!$package.source) { continue }
        if (!$package.source.StartsWith('registry+')) { throw "Review non-registry dependency before redistribution: $($package.name)" }
        $id = "$($package.name)-$($package.version)"
        $directory = Split-Path $package.manifest_path -Parent
        $index = Split-Path $directory -Parent
        $registry = Split-Path (Split-Path $index -Parent) -Parent
        $archive = Join-Path $registry ("cache\" + (Split-Path $index -Leaf) + "\$id.crate")
        if (!(Test-Path -LiteralPath $archive)) { throw "Missing corresponding crate source: $id" }
        Copy-Item -LiteralPath $archive -Destination $sources
        $noticeDir = Join-Path $licenses $id
        New-Item $noticeDir -ItemType Directory -Force | Out-Null
        $notices = @(Get-ChildItem -LiteralPath $directory -File | Where-Object { $_.Name -match '^(LICENSE|LICENCE|COPYING|COPYRIGHT|NOTICE)' })
        foreach ($notice in $notices) { Copy-Item -LiteralPath $notice.FullName -Destination $noticeDir }
        $inventory += [pscustomobject]@{name=$package.name;version=$package.version;license=$package.license;repository=$package.repository;source="third-party-source/rust/$id.crate";sourceSha256=(Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash.ToLowerInvariant()}
    }
    $inventory | Sort-Object name,version | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $OutputDirectory 'licenses\rust-dependencies.json') -Encoding utf8
    $nodeRoot = Join-Path $OutputDirectory 'resources\plugins\rea\node_modules'
    $npm = @(); $seen = @{}
    foreach ($manifest in (Get-ChildItem -LiteralPath $nodeRoot -Filter package.json -File -Recurse)) {
        $entry = Get-Content -LiteralPath $manifest.FullName -Raw | ConvertFrom-Json
        if (!$entry.name -or !$entry.version) { continue }
        $key = "$($entry.name)@$($entry.version)"
        if ($seen.ContainsKey($key)) { continue }; $seen[$key] = $true
        $npm += [pscustomobject]@{name=$entry.name;version=$entry.version;license=$entry.license;path=$manifest.DirectoryName.Substring($OutputDirectory.Length+1).Replace('\','/')}
    }
    $npm | Sort-Object name,version | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $OutputDirectory 'licenses\npm-dependencies.json') -Encoding utf8
    Write-Host "Collected notices and source for $($inventory.Count) Rust packages; indexed $($npm.Count) npm packages."
} finally { Pop-Location }
