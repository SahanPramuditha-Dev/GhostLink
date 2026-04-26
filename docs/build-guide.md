# GhostLink Build Guide

This document explains how to build:
- the packaged desktop app (`dist/GHOSTLINK/GHOSTLINK.exe`)
- the Windows installer (`GHOSTLINK_Setup.exe`)

## Prerequisites

1. Windows PowerShell
2. Python 3.9+
3. PyInstaller available in `PATH`
4. NSIS available in `PATH` for installer creation (`makensis`)

Install required tooling:

```powershell
python -m pip install --upgrade pip
python -m pip install pyinstaller
```

## Build Packaged App

From repository root:

```powershell
.\scripts\build.ps1
```

Useful options:

```powershell
# Clean build/ and dist/ before packaging
.\scripts\build.ps1 -Clean

# Attempt dependency install first (only if requirements.txt has content)
.\scripts\build.ps1 -InstallDeps
```

Expected output:
- `dist/GHOSTLINK/GHOSTLINK.exe`

## Build Windows Installer

```powershell
.\scripts\installer.ps1
```

This script:
1. builds app bundle first (unless `-SkipBuild` is used)
2. runs `makensis installer.nsi`
3. writes installer to `GHOSTLINK_Setup.exe`

If app bundle is already built:

```powershell
.\scripts\installer.ps1 -SkipBuild
```

Expected output:
- `GHOSTLINK_Setup.exe`

## Manual Commands (without scripts)

```powershell
pyinstaller GHOSTLINK.spec
makensis installer.nsi
```

## Troubleshooting

- `pyinstaller not found`
  - Install with `python -m pip install pyinstaller`
  - Reopen terminal after install

- `makensis not found`
  - Install NSIS
  - Ensure NSIS install path is in `PATH`

- `dist/GHOSTLINK/GHOSTLINK.exe missing`
  - Re-run `.\scripts\build.ps1 -Clean`
  - Confirm `GHOSTLINK.spec` exists at repo root
