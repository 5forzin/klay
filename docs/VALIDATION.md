# Validation

## Automated tests

The Python suite checks crash discovery, partial files, hashes, paths, heartbeat age, and build archives. It also tests waiting for a new crash and rejects debugger output that fails or disagrees with the Windows event. A CLI test preserves Unicode event text through a Windows ANSI output stream. The invalid-dump test runs an installed KD; it reports a skip if KD isn't available.

Synthetic PE and MSF7 PDB fixtures check GUID/age matching, rejection of mismatched or excessive binary metadata, and arming without a PDB. Mocked KD output checks parameter descriptions, quoted stack/warning lines, symbol quality, and the distinction between a valid pipeline and a confirmed cause. `once` is checked for a nonzero exit code after a failed analysis. These fixtures don't load a driver or demonstrate real source-line debugging.

Parser regression cases cover empty debugger headings with LF and CRLF: an absent value stays absent instead of consuming the next field's line. Bug Check `ArgN` values accept optional `0x`/`0X` prefixes and debugger backticks while preserving normalized hexadecimal parameters.

Further cases extract `IP_IN_PAGED_CODE` as faulting-instruction evidence and retain page-outside-dump and Symbol Loading Error Summary warnings with raw line provenance. Symbol-table warnings stop before unrelated debugger output and degrade symbol quality without claiming private symbols were supplied.

Host fixtures also check immutable selection publication, identity/time fields, the 64 KiB input limit and a permanently locked legacy pointer. Publishing a new record succeeds with a compatibility warning in that lock case; a required immutable publication failure remains an error. Transient ordinary JSON replacement failures exercise the bounded retry without rerunning analysis.

The PowerShell tests parse the scripts and extract event data from fixtures. The exporter test copies temporary files through a simulated share outage, retries publication, and checks the transferred hash. It also holds a dump open for writing to check that capture waits until the writer closes. The host test starts a monitor through a Windows venv, checks that status advances, rejects a duplicate launch, and stops the monitor.

Guest fixtures also check exclusive SYSTEM/administrators ACL descriptions, full AMD64 dump-header evidence, duplicate dump refusal, a fresh filesystem timestamp on an old dump, and a legitimate long crash-to-reboot interval. Boot cases distinguish adjacent event records, tolerate a Kernel-General start preceding the CIM boot time, and reject ambiguous current-boot boundaries. Build-race fixtures ensure that an arm observed after a crash doesn't replace the earlier selection. Other cases retain unknown build context, distinguish pre-crash observations from recovery-boot context, resume a pending capture after another reboot, and reject unsupported headers or missing boot boundaries. These checks use temporary files and synthetic ACLs; they don't change real machine ACLs or cause a Bug Check.

Event fixtures detect a current-boot report before the CIM boot time and reject an older record inside the time tolerance. Late WER fixtures reject conflicting codes/parameters or missing captured-header evidence without replacing a ready fallback report. An accepted upgrade preserves the original event, updates dump/event provenance, and publishes its event sidecars.

Selection fixtures hold record A open without delete sharing, publish a different record B, and confirm that the guest observes B. They also cover corrupt latest bodies, invalid filenames/identities/timestamps, oversized records, history overflow and legacy fallback only when no immutable JSON records exist. Path fixtures restrict InstallRoot to a direct child of the real ProgramData folder without changing real ACLs. These are contract and concurrency checks, separate from a real HGFS/driver crash test.

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

## 2026-10-09: Education 25H2 and revised evidence pipeline

An authorized controlled crash tested the updated host and exporter on Windows 11 Education 25H2 build 26200.8655, VMware Workstation Pro 25, virtual hardware 22. A signed driver was demand-loaded and left idle; Microsoft Sysinternals NotMyFault deliberately caused the crash. This validates relay operation with that driver present, not an induced defect in that driver or its IOCTL behavior.

| Observation | Result |
| --- | --- |
| Bug Check | `0x000000D1`, `DRIVER_IRQL_NOT_LESS_OR_EQUAL` |
| Dump | Kernel bitmap dump, 519,527,408 bytes (495.46 MiB) |
| Integrity | Original Windows dump, host dump, publication manifests and analysis SHA-256 matched |
| Event consistency | WER SystemErrorReporting 1001; code and all four parameters matched |
| Build correlation | `observed_before_crash`, from a guest acknowledgment of `immutable_v1` |
| Deliberate crash attribution | `myfault.sys`, process `notmyfaultc64.exe` |
| Loaded test driver | Present in module evidence; timestamp/image-size metadata matched the archived selection; no private PDB |
| First offline analysis | KD exit zero, completion marker present; 22.134 seconds in KD |
| First result latency | 93.795 seconds from the dump header's system time to first completed analysis |
| Final reanalysis | Same dump, no second crash; KD exit zero and `complete`, 10.267 seconds |
| Revised structured output | Faulting instruction from `IP_IN_PAGED_CODE`; four warning entries with original lines, including dump-memory and symbol-loading categories |
| Symbol limitation | `degraded`, private symbols not supplied, loaded symbols `missing`; module metadata `matched` |
| Dump readiness | Automatic pagefile active at 1,728 MiB; no current-boot `volmgr` 46/161 errors |
| Security observations | Before/after contexts: Defender antivirus/realtime/tamper active; Secure Boot false and VBS/HVCI not running, unchanged from the found baseline |
| Recovery and cleanup | Automatic login confirmed after recovery; WinRM automatic/running; temporary crash task and test-driver service removed |

The first-result latency is derived from recorded timestamps; it is not a stopwatch measurement from the user reproduction trigger. Before/after security observations do not attest to every instant at crash time. Metadata matching does not prove the hash of the loaded image. Missing pages and private symbols remain diagnostic limitations even though the relay completed.

The final parser revision passed 40 Python tests and successfully reanalyzed this same preserved dump. Private-PDB source debugging, live KD/KDNET and functional testing of the idle driver remain unvalidated. The working revision's final commit is recorded separately when packaged and published. Raw machine identifiers, credentials, binary files, dumps and local receipts are retained privately outside Git.

## Repeating a real test

Use a disposable development VM and agree on the crash and reboot window with its owner. Check the pagefile, current-boot dump errors, disk space, and monitor status first. Follow Microsoft's NotMyFault documentation or the driver's authorized reproduction procedure. Keep the dump and logs outside Git and review any excerpts before sharing them.

Record the following evidence for the tested revision:

| Evidence | What to record |
| --- | --- |
| Environment | OS edition/version/build, VMware and Tools versions, tested klay revision, dump/pagefile settings, and separately verified security settings with their observation times and boots. |
| Driver/build | Archived `.sys` SHA-256, optional PDB identity and hash, source revision/changes, deployment path, and exact reproduction steps. |
| Crash association | Crash ID, Windows provider/event record, code and four parameters, reboot boundary and any dump/header/build correlation fields. |
| Transfer | Windows dump, spool/export sizes and SHA-256 checks; publication completion marker. |
| Analysis | KD exit, completion marker, event/dump consistency, structured stack/warnings, symbol quality and unresolved limitations. |
| Recovery | Guest heartbeat and task after reboot, current-boot dump errors, elapsed time and remaining settings or artifacts. |

A completed analysis with no private PDB validates collection and offline triage, not source-level debugging. Record that limitation explicitly. A build's observed timestamp/image size is metadata evidence; it doesn't prove that the loaded image has the archived file's hash. Keep live KD/KDNET validation separate from dump relay validation.

The 2026-10-02 result is historical validation of klay 0.1.0. The 2026-10-09 result exercises the revised relay on Education 25H2 in one controlled crash; synthetic race, rejection and path cases remain separate automated checks. Neither result establishes all possible driver failures or live-debugging compatibility.
