param(
    [switch]$SkipBuild
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
Set-Location $RepoRoot

Write-Host "==> GhostLink installer build started" -ForegroundColor Cyan
Write-Host "    Root: $RepoRoot"

if (-not $SkipBuild) {
    Write-Host "==> Building application bundle first"
    & (Join-Path $PSScriptRoot "build.ps1")
}

$DistPath = Join-Path $RepoRoot "dist\GHOSTLINK"
if (-not (Test-Path $DistPath)) {
    throw "Missing '$DistPath'. Run scripts/build.ps1 before creating installer."
}

if (-not (Get-Command makensis -ErrorAction SilentlyContinue)) {
    throw "makensis was not found in PATH. Install NSIS and ensure 'makensis' is available."
}

if (-not (Test-Path "installer.nsi")) {
    throw "installer.nsi was not found in repository root."
}

Write-Host "==> Creating installer with NSIS"
makensis "installer.nsi"

$InstallerPath = Join-Path $RepoRoot "GHOSTLINK_Setup.exe"
if (-not (Test-Path $InstallerPath)) {
    throw "NSIS completed but installer file was not found at: $InstallerPath"
}

Write-Host "==> Installer created successfully" -ForegroundColor Green
Write-Host "    Setup: $InstallerPath"
