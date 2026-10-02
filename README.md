# klay — Kernel Relay

Windows kernel crash collection and analysis for developers and AI coding agents.

## The problem

When a Windows driver crashes a development VM, the evidence stays inside the guest: the Bug Check, its parameters, system events and the memory dump. A developer or coding agent working on the host must recover these files, identify the tested build and run a debugger before continuing.

**klay relays that evidence to the host after the VM reboots.** It collects the crash, verifies the dump and runs Microsoft's KD debugger, producing JSON summaries and a detailed text report that a developer or AI agent can read.

## What the first version does

- Captures WER Bug Check reports, with nonzero Kernel-Power Bug Check codes as a fallback.
- Spools dumps locally in the guest while the shared folder is unavailable.
- Publishes completed dumps with size and SHA-256 verification.
- Runs offline KD analysis and checks the result against the event's code and available parameters.
- Preserves the exact `.sys` and `.pdb` files selected for a test, with optional source path and Git revision metadata.
- Exposes `status`, `wait`, `arm` and `analyze` commands, plus files for other tools to consume.

Capture happens after Windows restarts. A missing heartbeat is reported as unknown reachability; it does not establish a BSOD. klay provides diagnostic evidence; the debugger's module attribution still needs review.

## Requirements

- Windows x64 host and guest, VMware Workstation with VMware Tools and Shared Folders enabled.
- Python 3.11 or later on the host; Windows PowerShell 5.1 in the guest.
- Microsoft WinDbg or Debugging Tools for Windows, including `kd.exe`, on the host.
- Administrator access for the one-time guest installation.
- Space for the guest's Windows dump and spool copy, host crash archives and symbol cache.

The Python host has no third-party runtime dependencies. Continuous monitoring uses the shared folder without guest credentials or an AI service key. Each VM needs its own shared root and runtime root, with one host monitor for that share.

## Setup

Clone the repository and install the host CLI in a virtual environment:

```powershell
git clone https://github.com/5forzin/klay.git
cd klay
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e .
.\.venv\Scripts\klay.exe --version
```

Create `C:\KlayShare` on the host. In VMware, share that directory under the name `Klay`, enable the share and install VMware Tools in the guest. These are example paths; select paths for your environment.

```powershell
.\.venv\Scripts\klay.exe init --shared-root 'C:\KlayShare'
New-Item -ItemType Directory -Path 'C:\KlayShare\setup' -Force
Copy-Item .\guest\*.ps1 -Destination 'C:\KlayShare\setup' -Force
```

The default configuration is `%LOCALAPPDATA%\Klay\config.json`. Runtime state, symbol cache and archived builds also live there, outside the checkout. Use global `--config` before a command for another configuration, and `init --data-root` for another data directory. `config.example.json` describes the configuration fields.

Inside the VM, open **an elevated Windows PowerShell** and run:

```powershell
& '\\vmware-host\Shared Folders\Klay\setup\Install-Guest.ps1' `
    -ShareRoot '\\vmware-host\Shared Folders\Klay'
```

The installer saves the original settings, configures Automatic Memory Dump and an automatically managed pagefile, enables automatic restart, and registers `Klay-Export` as a SYSTEM startup task. Its local code directory is writable by SYSTEM and administrators. Restart the VM to activate the dump and pagefile changes. Installation itself does not restart it.

Start the host monitor from the checkout:

```powershell
.\scripts\Start-Klay.ps1 -InstallStartup
.\.venv\Scripts\klay.exe status
```

Check that the host timestamp advances, a fresh guest heartbeat appears, the guest has an active pagefile and `currentBootDumpErrors` is empty. If Windows reports `volmgr` 46 or 161, fix dump initialization or storage before relying on capture. See [the AI guide](docs/AI_GUIDE.pt-BR.md) for diagnosis.

`Start-Klay.ps1` adds a startup shortcut only with `-InstallStartup`. The foreground alternative is `klay watch`; `klay once` scans and processes pending dumps, then exits. The installation above puts `klay.exe` in `.venv\Scripts`; use its full path or activate the virtual environment for the shorter command.

## Working with a driver

```powershell
klay arm --driver 'C:\DriverProject\x64\Debug\Example.sys' `
    --pdb 'C:\DriverProject\x64\Debug\Example.pdb' `
    --source 'C:\DriverProject' --note 'Fix for cancellation race'
klay wait --timeout 600 --require-analysis
```

Run `arm` before each test with files from the same build. Driver compilation, deployment and loading belong to the driver project. Save the previous `latest.crashId` and pass it to `wait --after` when waiting for a new crash.

Reports are written under `<shared_root>\crashes\<crashId>\`: `crash.json`, system events, `memory.dmp`, `ready.json`, `analysis.txt` and `analysis.json`. `<runtime_root>\latest.json` points to the latest observed crash; `<runtime_root>\status.json` contains monitoring and dump configuration state. Read [the AI guide](docs/AI_GUIDE.pt-BR.md) for commands, exit codes and interpretation.

## Operation and limits

- Windows must reboot and VMware shared-folder access must return before the host receives new evidence. No live kernel debugging or screen capture is provided.
- A crash that prevents Windows from writing a dump can yield event metadata without a dump. Archives and failed analyses are preserved for inspection.
- `arm` records intended build provenance. Check the loaded module and matching PDB in the debugger report; it does not prove which driver Windows loaded or snapshot source files.
- Dumps, logs and build archives can contain sensitive data. Keep them in private storage; review any evidence before sharing it. Archives have no automatic retention cleanup.
- Installation through `scripts/Deploy-Guest.ps1` is optional. VMware's `vmrun` takes credentials in transient process arguments; use the manual guest installer to avoid that exposure. Monitoring stores no passwords.

Stop a monitor launched by `Start-Klay.ps1` with `scripts/Stop-Klay.ps1`; add `-RemoveStartup` to remove its matching shortcut. Stop a foreground `klay watch` with Ctrl+C. To restore guest dump and pagefile settings, run `C:\ProgramData\Klay\Restore-Guest.ps1` in an elevated guest PowerShell, then restart the guest. Captured data is retained.

## Development

```powershell
python -m unittest discover -s tests -v
powershell -NoProfile -File .\tests\Test-GuestFunctions.ps1
powershell -NoProfile -File .\tests\Test-GuestExporter.ps1
powershell -NoProfile -File .\tests\Test-HostMonitor.ps1
```

Tests use temporary synthetic fixtures and do not generate a BSOD. CI runs them on Windows with Python 3.11 and 3.14. The original pipeline was also validated against a real controlled VM crash; see [validation evidence and limits](docs/VALIDATION.md).

See [architecture](docs/ARCHITECTURE.md), [contributing](CONTRIBUTING.md) and [agent instructions](AGENTS.md).
