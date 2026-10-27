[CmdletBinding()]
param([Parameter(Mandatory=$true)][string[]]$Tool, [string]$Destination = '')
$ErrorActionPreference='Stop'
$base = if (Test-Path (Join-Path $PSScriptRoot 'resources\toolchain.json')) { $PSScriptRoot } else { Split-Path $PSScriptRoot -Parent }
$catalog = Get-Content -Raw (Join-Path $base 'resources\toolchain.json') | ConvertFrom-Json
if (!$Destination) { $Destination = Join-Path $base 'resources\toolchain' }
$Destination=[IO.Path]::GetFullPath($Destination)
foreach ($id in $Tool) {
    $entry=$catalog.tools | Where-Object id -EQ $id | Select-Object -First 1
    if (!$entry -or !$entry.download) { throw "No pinned portable download for '$id'. Read the tool's official setup instructions." }
    $output=Join-Path $Destination $id
    if (Test-Path -LiteralPath $output) { throw "Tool destination already exists: $output. Preserve it or choose another destination." }
    $cache=Join-Path ([IO.Path]::GetTempPath()) 'quixidesk-toolchain'
    New-Item $cache -ItemType Directory -Force | Out-Null
    $archive=Join-Path $cache $entry.download.file
    if (!(Test-Path -LiteralPath $archive) -or (Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash -ne $entry.download.sha256) {
        Write-Host "Downloading $($entry.name) $($entry.download.version) from its official release..."
        Invoke-WebRequest -Uri $entry.download.url -OutFile $archive
    }
    if ((Get-FileHash -LiteralPath $archive -Algorithm SHA256).Hash -ne $entry.download.sha256) { throw "Checksum mismatch for $id" }
    New-Item $output -ItemType Directory -Force | Out-Null
    if ($entry.download.file.EndsWith('.zip')) { Expand-Archive -LiteralPath $archive -DestinationPath $output }
    else { Copy-Item -LiteralPath $archive -Destination $output }
    $entry | ConvertTo-Json -Depth 6 | Set-Content (Join-Path $output 'quixi-tool-source.json') -Encoding utf8
    Write-Host "Installed portable files: $output. Open Toolchain and refresh detection. No system registration, proxy, or certificate changes were made."
}
