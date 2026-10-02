# Validation

## Automated tests

The Python suite checks crash discovery, partial files, hashes, paths, heartbeat age, and build archives. It also tests waiting for a new crash and rejects debugger output that fails or disagrees with the Windows event. A CLI test preserves Unicode event text through a Windows ANSI output stream. The invalid-dump test runs an installed KD; it reports a skip if KD isn't available.

The PowerShell tests parse the scripts and extract event data from fixtures. The exporter test copies temporary files through a simulated share outage, retries publication, and checks the transferred hash. It also holds a dump open for writing to check that capture waits until the writer closes. The host test starts a monitor through a Windows venv, checks that status advances, rejects a duplicate launch, and stops the monitor.

CI installs the CLI and runs these tests on Windows with Python 3.11 and 3.14. The fixtures use temporary files and don't change a VM's settings. A real crash test is a separate check.

## Packaged klay: real VM crash test

On 2026-10-02, klay 0.1.0 was installed on a snapshotted Windows 11 x64 VMware Workstation VM and tested with its owner's permission. The packaged CLI watched the share, and the renamed `Klay-Export` task ran as SYSTEM after reboot. The guest had VMware Tools, Automatic Memory Dump, automatic reboot, and an active system-managed pagefile. A signed Microsoft Sysinternals NotMyFault binary caused the test crash.

| Observation | Result |
| --- | --- |
| Bug Check | `0x000000D1`, `DRIVER_IRQL_NOT_LESS_OR_EQUAL` |
| Dump | Kernel bitmap dump, 514,493,133 bytes (490.66 MiB) |
| Export | Completed after reboot; Windows dump, host dump, manifests, and analysis SHA-256 matched |
| Offline KD | Exit code zero; completion marker present |
| Consistency | Bug Check code and all four parameters matched the event |
| Debugger attribution | `myfault.sys`, process `notmyfaultc64.exe` |
| End-to-end time | 77.20 seconds from trigger to completed analysis |
| CLI wait | `wait --require-analysis` returned zero with the new crash |
| Recovery | Guest returned online; SYSTEM task running; no current-boot `volmgr` 46/161 errors |
| Host startup | Monitor running; login shortcut points to the venv and explicit configuration |

The guest initially had UWF enabled on C: and no pagefile. UWF was disabled before installation and remained off for the test. After setup, the first boot created the pagefile but still logged `volmgr` 46; a further boot cleared the initialization error. The test started with an active 1,664 MiB pagefile and no current-boot dump errors. Original UWF information and the installer backup were retained locally.

These results come from that VM and that crash. Elapsed time will vary with dump size, disk speed, and symbol downloads. Private NotMyFault symbols were unavailable, so source-line debugging with a project's own PDB remains untested. The host login shortcut was inspected; a host reboot wasn't part of this test.

The raw dump and events are kept in local storage, outside this repository. The crash tool is available from [Microsoft Sysinternals](https://learn.microsoft.com/en-us/sysinternals/downloads/notmyfault).

## Repeating a real test

Use a disposable development VM and agree on the crash and reboot window with its owner. Check the pagefile, current-boot dump errors, and monitor status first. Follow Microsoft's NotMyFault documentation, then record the event, hashes, KD result, elapsed time, and guest recovery. Keep the dump and logs outside Git and review any excerpts before sharing them.
