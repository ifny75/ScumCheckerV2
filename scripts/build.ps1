$ErrorActionPreference = "Stop"
$root = [System.IO.Path]::GetFullPath("$PSScriptRoot\..")
$build = Join-Path $root "build-vs2022"

function Write-LaunchUserFile {
    param(
        [Parameter(Mandatory = $true)][string]$ProjectUserFile
    )

    $xml = @'
<?xml version="1.0" encoding="utf-8"?>
<Project ToolsVersion="Current" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <PropertyGroup Condition="'$(Configuration)|$(Platform)'=='Debug|x64'">
    <LocalDebuggerCommand>$(SolutionDir)Debug\ScumCheckerV2.exe</LocalDebuggerCommand>
    <LocalDebuggerWorkingDirectory>$(SolutionDir)Debug</LocalDebuggerWorkingDirectory>
    <DebuggerFlavor>WindowsLocalDebugger</DebuggerFlavor>
  </PropertyGroup>
  <PropertyGroup Condition="'$(Configuration)|$(Platform)'=='Release|x64'">
    <LocalDebuggerCommand>$(SolutionDir)Release\ScumCheckerV2.exe</LocalDebuggerCommand>
    <LocalDebuggerWorkingDirectory>$(SolutionDir)Release</LocalDebuggerWorkingDirectory>
    <DebuggerFlavor>WindowsLocalDebugger</DebuggerFlavor>
  </PropertyGroup>
  <PropertyGroup Condition="'$(Configuration)|$(Platform)'=='RelWithDebInfo|x64'">
    <LocalDebuggerCommand>$(SolutionDir)RelWithDebInfo\ScumCheckerV2.exe</LocalDebuggerCommand>
    <LocalDebuggerWorkingDirectory>$(SolutionDir)RelWithDebInfo</LocalDebuggerWorkingDirectory>
    <DebuggerFlavor>WindowsLocalDebugger</DebuggerFlavor>
  </PropertyGroup>
  <PropertyGroup Condition="'$(Configuration)|$(Platform)'=='MinSizeRel|x64'">
    <LocalDebuggerCommand>$(SolutionDir)MinSizeRel\ScumCheckerV2.exe</LocalDebuggerCommand>
    <LocalDebuggerWorkingDirectory>$(SolutionDir)MinSizeRel</LocalDebuggerWorkingDirectory>
    <DebuggerFlavor>WindowsLocalDebugger</DebuggerFlavor>
  </PropertyGroup>
</Project>
'@

    Set-Content -Path $ProjectUserFile -Value $xml -Encoding UTF8
}

function Patch-AllBuildProject {
    param(
        [Parameter(Mandatory = $true)][string]$ProjectFile
    )

    if (-not (Test-Path $ProjectFile)) {
        return
    }

    $xml = Get-Content -Raw -Path $ProjectFile
    if ($xml -match "ScumCheckerV2StartupTargetPath") {
        return
    }

    $startupProperties = @'
  <PropertyGroup Label="ScumCheckerV2StartupTargetPath">
    <TargetPath Condition="'$(Configuration)|$(Platform)'=='Debug|x64'">$(SolutionDir)Debug\ScumCheckerV2.exe</TargetPath>
    <TargetPath Condition="'$(Configuration)|$(Platform)'=='Release|x64'">$(SolutionDir)Release\ScumCheckerV2.exe</TargetPath>
    <TargetPath Condition="'$(Configuration)|$(Platform)'=='RelWithDebInfo|x64'">$(SolutionDir)RelWithDebInfo\ScumCheckerV2.exe</TargetPath>
    <TargetPath Condition="'$(Configuration)|$(Platform)'=='MinSizeRel|x64'">$(SolutionDir)MinSizeRel\ScumCheckerV2.exe</TargetPath>
    <LocalDebuggerCommand>$(TargetPath)</LocalDebuggerCommand>
    <LocalDebuggerWorkingDirectory>$(TargetDir)</LocalDebuggerWorkingDirectory>
    <DebuggerFlavor>WindowsLocalDebugger</DebuggerFlavor>
  </PropertyGroup>
'@

    $xml = $xml -replace '  <PropertyGroup Label="UserMacros" />', "  <PropertyGroup Label=`"UserMacros`" />`r`n$startupProperties"
    Set-Content -Path $ProjectFile -Value $xml -Encoding UTF8
}

& "$PSScriptRoot\fetch_webview2.ps1"

cmake -S $root -B $build -G "Visual Studio 17 2022" -A x64 -T v143
cmake --build $build --config Release
cmake --build $build --config Debug --target ScumCheckerV2

Write-LaunchUserFile -ProjectUserFile (Join-Path $build "ALL_BUILD.vcxproj.user")
Write-LaunchUserFile -ProjectUserFile (Join-Path $build "ScumCheckerV2.vcxproj.user")
Patch-AllBuildProject -ProjectFile (Join-Path $build "ALL_BUILD.vcxproj")

Write-Host "Built: $build\Release\ScumCheckerV2.exe"
Write-Host "Debug: $build\Debug\ScumCheckerV2.exe"
