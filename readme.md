# GHOSTLINK — Wi-Fi Security Assessment Framework

GHOSTLINK is a Python-based desktop and command-line project for **authorized Wi-Fi security assessment, network reconnaissance, and defensive lab workflows**. It provides both GUI and CLI interfaces and can be packaged as a Windows desktop application.

> **Authorized use only:** Use GHOSTLINK only on networks and devices you own or have explicit permission to assess.

## Project Scope

GHOSTLINK is intended for:

- personal cybersecurity labs;
- defensive Wi-Fi configuration review;
- controlled classroom / coursework environments;
- internal security assessments with explicit authorization;
- learning about network-security tooling and application architecture.

The public documentation intentionally avoids step-by-step offensive procedures or credential-attack instructions.

## Interfaces

### Desktop GUI

- Entry point: `run_gui.py`
- Main window: `ghostlink/gui/main_window.py`
- Provides visual workflows for scanning, reconnaissance, configuration, progress, and results.

Run from source:

```bash
python run_gui.py
```

### Command-Line Interface

- Entry point: `run.py`
- Core application logic: `ghostlink/main.py`

View supported commands and options:

```bash
python run.py --help
```

Interactive mode:

```bash
python run.py
```

Some operating-system network operations may require elevated privileges. Use elevated access only when necessary and only in authorized environments.

## Installation

### Prerequisites

- Python 3.9+
- pip
- Windows for the packaged desktop / installer workflow

### Run From Source

```bash
git clone https://github.com/SahanPramuditha-Dev/GhostLink.git
cd GhostLink
pip install -r requirements.txt
```

Then launch either interface:

```bash
python run_gui.py
```

or:

```bash
python run.py
```

## Windows Packaging

The repository includes packaging configuration for a distributable Windows application.

### PyInstaller

`GHOSTLINK.spec` defines the application bundle.

```bash
pyinstaller GHOSTLINK.spec
```

### NSIS Installer

`installer.nsi` defines the Windows installer.

```bash
makensis installer.nsi
```

Build outputs are expected under the repository's `dist/` / installer workflow.

For more detail, see:

- [Build Guide](docs/build-guide.md)
- [Command Reference](docs/commands.md)

## Repository Structure

```text
ghostlink/
├── core/         Core application functionality
├── engine/       Assessment / processing engine
├── network/      Network-facing modules
├── storage/      Local storage and state
├── cli/          Command-line interface
├── gui/          Desktop graphical interface
└── dashboard/    Dashboard-related components

run.py            CLI entry point
run_gui.py        GUI entry point
GHOSTLINK.spec    PyInstaller configuration
installer.nsi     NSIS installer configuration
docs/             Build and command documentation
```

## Security & Data Handling

Security tools can generate highly sensitive local data. Do not commit:

- recovered or test passwords;
- local credential vaults;
- assessment exports containing private network information;
- real SSIDs or private infrastructure details where disclosure is inappropriate;
- logs containing secrets or personal information.

Generated vault, report, log, build, and runtime artifacts should be excluded from source control where practical. If real credentials are ever committed to a public repository, rotate them and remove them from Git history rather than relying on deletion from the latest commit alone.

## Ethical Use

Appropriate use includes authorized testing, education, and defensive research. Unauthorized access, credential theft, disruption, or testing third-party networks without permission is outside the intended scope of this project.

## Newer Desktop Architecture

A newer Electron + React + FastAPI evolution of the project is available in:

[GhostLink-React](https://github.com/SahanPramuditha-Dev/GhostLink-React)

## Author

**Sahan Pramuditha**  
BICT Undergraduate — University of Colombo
