# GhostLink Command Reference

## Run from Source

GUI:

```powershell
python run_gui.py
```

CLI interactive:

```powershell
python run.py
```

CLI direct mode example:

```powershell
python run.py --ssid "MyWiFi" --profile 1 --minlen 4 --maxlen 8 --threads 2
```

## Common CLI Arguments

- `--ssid` target network SSID
- `--interface` wireless interface (example: `wlan0`)
- `--profile` built-in attack profile
- `--charset` custom character set
- `--minlen` minimum password length
- `--maxlen` maximum password length
- `--wordlist` path to wordlist file
- `--threads` worker thread count
- `--timeout` per-attempt timeout in seconds
- `--use-cache` test cached password first
- `--force` skip admin privilege check
- `--debug` verbose output

## Build and Install Commands

Build app bundle:

```powershell
.\scripts\build.ps1
```

Build installer:

```powershell
.\scripts\installer.ps1
```

Manual equivalents:

```powershell
pyinstaller GHOSTLINK.spec
makensis installer.nsi
```
