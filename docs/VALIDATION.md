# Validation

## Automated checks

Python tests exercise crash discovery, partial files, size/hash verification, path validation, heartbeat interpretation, newest-boot selection, waiting for a new crash, build archiving, dump/event consistency and rejection of failed KD output. An invalid-dump test invokes an installed KD on Windows, or skips with an explicit reason when KD is unavailable.

PowerShell checks parse all scripts and test event extraction. The exporter test loads only function definitions and uses temporary synthetic files to verify offline spooling, recovery when a share becomes available, transfer integrity, repeated publication and blocking/recovery while a writer holds a dump. The host test launches a temporary monitor through a Windows venv, checks advancing status and duplicate rejection, then stops only that matching monitor. These tests do not inspect real system events, install tasks, change crash settings or generate a BSOD.

CI runs on Windows with Python 3.11 and 3.14. It installs the host CLI and runs the same tests. CI does not emulate VMware or prove capture from a real VM.

## Controlled VM validation of the original pipeline

Before this repository was created, the pipeline that klay is based on was exercised on an authorized Windows 11 x64 VMware Workstation VM on 2026-10-02. The guest had VMware Tools, Automatic Memory Dump, automatic reboot and an active system-managed pagefile. A signed Microsoft Sysinternals NotMyFault binary generated the controlled failure inside that VM.

| Observation | Result |
| --- | --- |
| Bug Check | `0x000000D1`, `DRIVER_IRQL_NOT_LESS_OR_EQUAL` |
| Dump | Kernel bitmap dump, about 467 MiB |
| Export | Completed after reboot; guest and host SHA-256 matched |
| Offline KD | Exit code zero; completion marker present |
| Consistency | Bug Check code and all four parameters matched the event |
| Debugger attribution | `myfault.sys`, process `notmyfaultc64.exe` |
| End-to-end time | About 70 seconds from trigger to completed analysis |
| Recovery | Guest returned online; no current-boot `volmgr` 46/161 errors |

The original environment needed an additional boot after enabling its previously absent pagefile before dump initialization succeeded. A reboot receipt alone was insufficient; the active pagefile and current-boot diagnostics mattered.

This evidence validates the original transport and analysis flow. The repository's renamed scripts, CLI packaging and generic configuration are checked by automated tests; they have not independently undergone another real crash test. Timing and debugger attribution above are one observed result, not a guarantee for other guests or driver bugs. Private NotMyFault symbols were unavailable; the test did not establish source-line debugging for a project driver.

The repository contains the validation description, not the original dump, credentials, machine identifiers or event artifacts. No crash-inducing binary is bundled.

## Repeating a real test

Use a disposable development VM, confirm dump initialization and monitor health, then obtain explicit authorization before deliberately crashing that environment. Follow [Microsoft's NotMyFault documentation](https://learn.microsoft.com/en-us/sysinternals/downloads/notmyfault). Keep the resulting dump and logs outside Git. Record the event, hashes, debugger completion, elapsed time and guest recovery without publishing private memory content.
