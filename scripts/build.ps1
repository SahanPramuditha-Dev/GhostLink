param(
    [switch]$Clean,
    [switch]$InstallDeps
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RepoRoot = Resolve-Path (Join-Path $PSScriptRoot "..")
Set-Location $RepoRoot

Write-Host "==> GhostLink build started" -ForegroundColor Cyan
Write-Host "    Root: $RepoRoot"

if ($Clean) {
    Write-Host "==> Cleaning previous build artifacts (build/, dist/)"
    if (Test-Path "build") { Remove-Item -LiteralPath "build" -Recurse -Force }
    if (Test-Path "dist") { Remove-Item -LiteralPath "dist" -Recurse -Force }
}

if ($InstallDeps) {
    Write-Host "==> Installing Python dependencies"
    if (Test-Path "requirements.txt" -and (Get-Item "requirements.txt").Length -gt 0) {
        python -m pip install --upgrade pip
        python -m pip install -r requirements.txt
    } else {
        Write-Warning "requirements.txt is empty or missing; skipping dependency install."
    }
}

if (-not (Get-Command pyinstaller -ErrorAction SilentlyContinue)) {
    throw "PyInstaller was not found in PATH. Install it with: python -m pip install pyinstaller"
}

if (-not (Test-Path "GHOSTLINK.spec")) {
    throw "GHOSTLINK.spec was not found in repository root."
}

Write-Host "==> Building app with PyInstaller"
pyinstaller "GHOSTLINK.spec"

$ExePath = Join-Path $RepoRoot "dist\GHOSTLINK\GHOSTLINK.exe"
if (-not (Test-Path $ExePath)) {
    throw "Build finished but executable was not found at: $ExePath"
}

Write-Host "==> Build completed successfully" -ForegroundColor Green
Write-Host "    EXE: $ExePath"
