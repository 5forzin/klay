# Working on klay

klay means Kernel Relay. It collects Windows VM Bug Check reports and dumps on the host after reboot.

Before editing, read `README.md` and `docs/ARCHITECTURE.md` in full, then inspect the affected code and tests. Keep the Portuguese AI guide accurate when commands or interpretation change.

- Keep the host standard-library-only, compatible with Python 3.11+; keep guest scripts compatible with Windows PowerShell 5.1.
- Preserve local spooling, completed-publication markers, SHA-256 checks, crash/event consistency and the separation of heartbeat reachability from Bug Check evidence.
- The SYSTEM task must run protected local scripts. Never execute code from the shared folder continuously as SYSTEM.
- Preserve original dump/pagefile settings for restore. Never automatically reboot or intentionally crash a machine.
- Use synthetic temporary fixtures for tests. Real VM modifications, deliberate crashes and restarts require explicit authorization for that environment.
- Keep local configuration, secrets, dumps, logs, builds and user data outside Git. Do not include diagnostic artifacts in CI uploads.
- Run Python tests and all three PowerShell checks before finishing. Validate package installation when changing the CLI or packaging.
- Do not add a server, dashboard, AI service dependency or driver deployment workflow without a request for that scope.

Use English for CLI output and concise, descriptive commits. Follow the writing guidance in `CONTRIBUTING.md` when editing documentation. Keep the README in English and the AI guide in Brazilian Portuguese.
