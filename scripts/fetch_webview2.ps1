param(
    [string]$Destination = "$PSScriptRoot\..\third_party\webview2"
)

$ErrorActionPreference = "Stop"
$resolvedDestination = [System.IO.Path]::GetFullPath($Destination)
$packageRoot = Split-Path -Parent $resolvedDestination
New-Item -ItemType Directory -Force $packageRoot | Out-Null

$indexUrl = "https://api.nuget.org/v3-flatcontainer/microsoft.web.webview2/index.json"
$index = Invoke-RestMethod -Uri $indexUrl
$version = $index.versions | Where-Object { $_ -notmatch "-" } | Select-Object -Last 1
if (-not $version) {
    throw "Could not resolve a stable Microsoft.Web.WebView2 package version."
}

$cacheDir = Join-Path $packageRoot "cache"
$nupkg = Join-Path $cacheDir "microsoft.web.webview2.$version.nupkg"
New-Item -ItemType Directory -Force $cacheDir | Out-Null

if (-not (Test-Path $nupkg)) {
    $url = "https://api.nuget.org/v3-flatcontainer/microsoft.web.webview2/$version/microsoft.web.webview2.$version.nupkg"
    Invoke-WebRequest -Uri $url -OutFile $nupkg
}

if (Test-Path $resolvedDestination) {
    Remove-Item -LiteralPath $resolvedDestination -Recurse -Force
}

New-Item -ItemType Directory -Force $resolvedDestination | Out-Null
$zip = Join-Path $cacheDir "microsoft.web.webview2.$version.zip"
Copy-Item -LiteralPath $nupkg -Destination $zip -Force
try {
    Expand-Archive -Path $zip -DestinationPath $resolvedDestination -Force
}
finally {
    Remove-Item -LiteralPath $zip -Force -ErrorAction SilentlyContinue
}

Write-Host "WebView2 SDK $version extracted to $resolvedDestination"
