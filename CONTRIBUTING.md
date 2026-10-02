# Contributing

Read `README.md`, `AGENTS.md` and `docs/ARCHITECTURE.md` before changing the pipeline. Keep changes focused and update affected docs with the code.

Use Python 3.11 or later and Windows PowerShell 5.1. The Python runtime uses the standard library. From the checkout, run:

```powershell
python -m unittest discover -s tests -v
powershell -NoProfile -File .\tests\Test-GuestFunctions.ps1
powershell -NoProfile -File .\tests\Test-GuestExporter.ps1
powershell -NoProfile -File .\tests\Test-HostMonitor.ps1
python -m pip wheel --no-deps --wheel-dir "$env:TEMP\klay-wheel-check" .
```

Test publication and integrity failure paths with synthetic fixtures. Real crash, reboot, task installation and restore operations require a deliberately selected development VM and authorization; keep them out of CI.

Keep configuration, credentials, dumps, driver binaries, PDBs, logs, screenshots and generated packages outside commits. Review the staged file list as well as the diff. Preserve the `schema: 1` interface or document a migration with the change. English is used for CLI messages and the README; the Portuguese AI guide should stay accurate.
