# klay

When a Windows driver crashes your VM, the dump stays in the guest. If your code and tools are on the host, you have to go back into the VM to collect it before you can debug the failure.

klay (Kernel Relay) copies the Bug Check report and memory dump to the host after Windows restarts. It checks the dump's size and SHA-256, runs Microsoft's KD debugger, and saves the result as JSON and a text report. Give a coding agent the [AI guide](docs/AI_GUIDE.pt-BR.md) so it knows where to find those files and how to read them.

Before each test, `klay arm` saves the driver's `.sys` and its optional `.pdb`. That keeps the selected build available even after you compile the next one. Preserve the matching PDB whenever you have it: Windows symbols alone don't provide your driver's private types, local variables, or source lines.

klay analyzes dumps after reboot. It doesn't enable live kernel debugging, change Secure Boot or memory integrity, deploy a driver, or trigger a crash. Signed drivers can be tested with the VM's protections kept active; signature acceptance and compatibility with those protections remain part of your driver test.

## Setup

You'll need a Windows x64 host and guest, VMware Workstation, VMware Tools, and Shared Folders. Install Python 3.11 or later and Microsoft's WinDbg or Debugging Tools for Windows on the host; klay uses `kd.exe`. The guest scripts run in Windows PowerShell 5.1.

If the guest uses Unified Write Filter (UWF), check it before installation. Protected writes can be discarded after reboot, and [enabling UWF for the first time disables pagefiles](https://learn.microsoft.com/en-us/windows/configuration/unified-write-filter/uwf-filterenable). Configure the development VM so the installation and pagefile can persist. The klay installer doesn't change UWF settings.

Clone the repo and install the CLI:

```powershell
git clone https://github.com/5forzin/klay.git
cd klay
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -e .
.\.venv\Scripts\klay.exe --version
```

Create `C:\KlayShare` on the host and share it in VMware under the name `Klay`. Enable the share and check that the guest can open it. Change these example paths if you use a different directory.

```powershell
.\.venv\Scripts\klay.exe init --shared-root 'C:\KlayShare'
New-Item -ItemType Directory -Path 'C:\KlayShare\setup' -Force
Copy-Item .\guest\*.ps1 -Destination 'C:\KlayShare\setup' -Force
```

`init` writes `%LOCALAPPDATA%\Klay\config.json`. Runtime files, symbols, and build archives use that directory too. For a different location, pass `--config` before the command and use `init --data-root`. See [config.example.json](config.example.json) for the available fields. Give each VM its own shared root and runtime root, with one monitor per share.

Inside the VM, open Windows PowerShell as administrator and run:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File '\\vmware-host\Shared Folders\Klay\setup\Install-Guest.ps1' `
    -ShareRoot '\\vmware-host\Shared Folders\Klay'
```

The installer backs up the guest's dump and pagefile settings, enables Automatic Memory Dump and automatic restart, and creates the SYSTEM startup task `Klay-Export`. It copies the scripts to a local directory writable by SYSTEM and administrators. Restart the VM yourself to activate the new settings.

Start the host monitor from the checkout:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\Start-Klay.ps1 -InstallStartup
.\.venv\Scripts\klay.exe status
```

Run `status` again after a few seconds. The host timestamp should advance and the guest heartbeat should be recent. Check for an active pagefile and an empty `currentBootDumpErrors` list. The [AI guide](docs/AI_GUIDE.pt-BR.md#quando-algo-falha) covers missing heartbeats and `volmgr` errors.

Omit `-InstallStartup` if you don't want a startup shortcut. To run in a terminal, use `klay watch`. Use `klay once` to process pending dumps and exit; it returns a nonzero exit code if an analysis processed in that invocation fails. The examples below use `klay` on the PATH; activate the virtual environment or use `.\.venv\Scripts\klay.exe`.

## Driver tests

Select files from the same build before loading the driver:

```powershell
klay arm --driver 'C:\DriverProject\x64\Debug\Example.sys' `
    --pdb 'C:\DriverProject\x64\Debug\Example.pdb' `
    --source 'C:\DriverProject' --note 'Fix for cancellation race'
```

Before testing, use `klay status` to check that the guest's `observedBuild.buildId` matches the ID returned by `arm`. The exporter reads the manifest on its next poll. Keep the monitor running while you compile, deploy, and test your driver, then wait for the report:

```powershell
klay wait --timeout 600 --require-analysis
```

When repeating a test, save the previous `latest.crashId` and pass it to `wait --after` so the command waits for a new crash. The [AI guide](docs/AI_GUIDE.pt-BR.md#espere-um-crash-novo) has a complete example.

New builds publish an immutable selection record under `<shared_root>\build-selections\`. The guest heartbeat's `selectionProtocol` reports support for `immutable_v1`; `observedBuild.selectionProtocol` and `selectionRecord` identify the record it actually read. `active-run.json` remains a compatibility pointer. If that pointer is locked, `arm` can succeed with `legacyPointerUpdated=false` and a warning because the immutable record was published. Update the guest exporter and confirm its matching acknowledgment before testing; successful publication alone isn't acknowledgment. See [migration](docs/ARCHITECTURE.md#files-and-states) for legacy guests and history limits.

If you only have a signed `.sys`, omit `--pdb`. klay still archives and analyzes it, and reports the missing private symbols. With a PDB, `arm` compares the PE CodeView and PDB identities when available and rejects a mismatched GUID or age. Arming records the build selected for testing; it doesn't prove that Windows loaded that binary.

Open `analysis.txt` under `<shared_root>\crashes\<crashId>\` for the debugger report, and `analysis.json` for the extracted evidence and symbol limitations. An analysis marked `complete` passed the relay's integrity and Bug Check checks; it doesn't establish the root cause. The same directory holds `memory.dmp`, the Windows events, and JSON metadata. `<runtime_root>\latest.json` gives you the paths for the most recent crash; `<runtime_root>\status.json` holds monitor and guest status.

## When a dump doesn't arrive

The host gets the crash after Windows boots and the shared folder becomes available. The guest keeps a local spool while the share is down. If Windows couldn't write a dump, klay may have only the Bug Check event. A stale heartbeat sets reachability to `unknown`; check the VM and share before assuming a BSOD.

The exporter requires an AMD64 kernel-format dump (`PAGEDU64`); it doesn't accept a minidump in its place. It checks the header's code, parameters and crash time against the event and boot boundaries before publication. Missing boundaries or mismatched data leave the capture waiting with an explicit error.

Leave enough disk space for the Windows dump, its guest spool copy, host archives, and symbols. Archives accumulate until you remove them. Keep dumps and logs in private storage and review them before sharing.

Automatic Memory Dump contains kernel memory and uses Windows-managed pagefile sizing. It can omit user buffers and other pages needed for a particular failure. The installer preserves the previous settings for restore; use [Microsoft's dump guidance](https://learn.microsoft.com/en-us/windows-hardware/drivers/debugger/varieties-of-kernel-mode-dump-files) when a case needs a larger dump. The relay preserves the data Windows wrote rather than reconstructing missing memory.

For build matching, symbol checks, and analysis errors, read the [AI guide](docs/AI_GUIDE.pt-BR.md). [Architecture](docs/ARCHITECTURE.md) explains capture and publication in detail.

## Stopping and restoring settings

Stop a monitor launched by `Start-Klay.ps1` with `scripts/Stop-Klay.ps1`; add `-RemoveStartup` to remove its matching shortcut. Stop a foreground `klay watch` with Ctrl+C. To restore guest dump and pagefile settings, run `powershell.exe -NoProfile -ExecutionPolicy Bypass -File 'C:\ProgramData\Klay\Restore-Guest.ps1'` in an elevated guest terminal, then restart the guest. The execution-policy argument applies only to that child process; it doesn't change the machine's policy. Captured data is retained.

The manual installer above needs no saved password. The optional `scripts/Deploy-Guest.ps1` uses VMware's `vmrun`, which exposes credentials in transient process arguments during installation. The running monitor reads the shared folder without credentials.

## Development

```powershell
python -m unittest discover -s tests -v
powershell -NoProfile -File .\tests\Test-GuestFunctions.ps1
powershell -NoProfile -File .\tests\Test-GuestExporter.ps1
powershell -NoProfile -File .\tests\Test-HostMonitor.ps1
```

These tests use temporary files and leave the VM alone. CI runs them on Windows with Python 3.11 and 3.14. See [validation](docs/VALIDATION.md) for test coverage and the packaged klay's controlled VM crash test.

For changes to the project, read [contributing](CONTRIBUTING.md) and [agent instructions](AGENTS.md). The Python runtime uses only the standard library.
