# Contributing

Read `README.md`, `AGENTS.md`, and `docs/ARCHITECTURE.md` before changing the relay. Update the affected docs in the same change as the code.

Use Python 3.11 or later and Windows PowerShell 5.1. Keep the Python runtime on the standard library. Run these checks from the checkout:

```powershell
python -m unittest discover -s tests -v
powershell -NoProfile -File .\tests\Test-GuestFunctions.ps1
powershell -NoProfile -File .\tests\Test-GuestExporter.ps1
powershell -NoProfile -File .\tests\Test-HostMonitor.ps1
python -m pip wheel --no-deps --wheel-dir "$env:TEMP\klay-wheel-check" .
```

Use temporary fixtures to test publication failures and corrupted files. Run real crash tests, restarts, task installation, and settings restoration in a development VM with its owner's permission. CI uses fixtures.

Check the staged file list before committing. Local configuration, credentials, dumps, driver binaries, PDBs, logs, screenshots, and generated packages belong outside Git. Document a migration if you change the meaning of a `schema: 1` field.

## Writing

Write for someone trying to debug a driver. Start with what happened or what they need to do next. Name the command, file, or process that does the work, and explain why a step matters when the reason isn't obvious. Keep the README in English and the AI guide in Brazilian Portuguese.

- Use ordinary verbs and consistent technical terms. Use `dump` consistently when that's what you mean.
- Give each paragraph a job. Link to the detailed guide instead of repeating the same explanation across sections.
- Use lists for steps or options and tables for fields or comparisons. Keep explanations in prose when a list adds nothing.
- Cut promotional adjectives, empty transitions, and repeated summaries. Phrases such as “seamlessly,” “it's important to note,” or “not just X, but Y” usually add words without explaining the behavior.
- Read the edited paragraph aloud. Rewrite awkward sentences without inventing personal anecdotes, test results, or claims about authorship.

For examples, see [Google's voice and tone guide](https://developers.google.com/style/tone) and [Microsoft's style and voice tips](https://learn.microsoft.com/en-us/style-guide/top-10-tips-style-voice). The [WikiProject AI Cleanup guide](https://en.wikipedia.org/wiki/Wikipedia:Signs_of_AI_writing) describes repetitive phrasing and formatting seen in AI output. Its observations are context-dependent and don't establish who wrote a text.
