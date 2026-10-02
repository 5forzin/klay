# Validation

## Automated tests

The Python suite checks crash discovery, partial files, hashes, paths, heartbeat age, and build archives. It also tests waiting for a new crash and rejects debugger output that fails or disagrees with the Windows event. The invalid-dump test runs an installed KD; it reports a skip if KD isn't available.

The PowerShell tests parse the scripts and extract event data from fixtures. The exporter test copies temporary files through a simulated share outage, retries publication, and checks the transferred hash. It also holds a dump open for writing to check that capture waits until the writer closes. The host test starts a monitor through a Windows venv, checks that status advances, rejects a duplicate launch, and stops the monitor.

CI installs the CLI and runs these tests on Windows with Python 3.11 and 3.14. The fixtures use temporary files and don't change a VM's settings. A real crash test is a separate check.

## The original VM crash test

On 2026-10-02, the original relay was tested in a Windows 11 x64 VMware Workstation VM, with its owner's permission. The guest had VMware Tools, Automatic Memory Dump, automatic reboot, and an active system-managed pagefile. A signed Microsoft Sysinternals NotMyFault binary caused the test crash.

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

The guest initially had no pagefile. Enabling it took an additional boot before Windows initialized dump capture correctly. The active pagefile and the `volmgr` events from the current boot showed when the VM was ready for the test.

These results come from that VM and that crash. The packaged CLI and renamed guest task still need a separate real-VM crash test. The 70-second result will vary with dump size, disk speed, and symbol downloads. Private NotMyFault symbols were unavailable, so source-line debugging with a project's own PDB remains untested.

The raw dump and events are kept in local storage, outside this repository. The crash tool is available from [Microsoft Sysinternals](https://learn.microsoft.com/en-us/sysinternals/downloads/notmyfault).

## Repeating a real test

Use a disposable development VM and agree on the crash and reboot window with its owner. Check the pagefile, current-boot dump errors, and monitor status first. Follow Microsoft's NotMyFault documentation, then record the event, hashes, KD result, elapsed time, and guest recovery. Keep the dump and logs outside Git and review any excerpts before sharing them.
