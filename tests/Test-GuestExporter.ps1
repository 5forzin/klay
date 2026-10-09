$ErrorActionPreference = 'Stop'
$toolRoot = Split-Path -Parent $PSScriptRoot
. (Join-Path $toolRoot 'guest\Klay.Common.ps1')
# Load exporter functions only: do not start its monitor or inspect real crash events.
$tokens = $null; $errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile((Join-Path $toolRoot 'guest\Export-Crashes.ps1'), [ref]$tokens, [ref]$errors)
foreach ($definition in $ast.FindAll({ param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] }, $false)) {
    . ([scriptblock]::Create($definition.Extent.Text))
}
$tempParent = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
$testRoot = Join-Path $tempParent ('klay-export-test-' + [Guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $testRoot -Force | Out-Null
try {
    $localRoot = Join-Path $testRoot 'guest'
    $spoolRoot = Join-Path $localRoot 'spool'
    New-Item -ItemType Directory -Path $spoolRoot -Force | Out-Null
    $blocked = Join-Path $testRoot 'blocked'
    [IO.File]::WriteAllText($blocked, 'A regular file makes this share unavailable.')
    $ShareRoot = Join-Path $blocked 'share'
    $bootTime = (Get-Date).AddMinutes(-1)
    $previousBoot = @{timeUtc = $bootTime.AddHours(-2).ToUniversalTime().ToString('o'); eventRecordId = 10; provider = 'Microsoft-Windows-Kernel-General'; eventId = 12}
    $bootKey = 'isolated-fixture-1'
    $localCrashPath = Join-Path $spoolRoot $bootKey
    $os = [pscustomobject]@{Caption = 'Isolated fixture'; Version = '0'; BuildNumber = '0'}
    $fixtureDump = Join-Path $testRoot 'fixture.dmp'
    function Write-FixtureDump {
        param([DateTime]$CrashTime, [uint32]$Code = 0xd1, [uint64[]]$Parameters = @(1, 2, 3, 4))
        $bytes = New-Object byte[] 8192
        [Text.Encoding]::ASCII.GetBytes('PAGEDU64').CopyTo($bytes, 0)
        [BitConverter]::GetBytes([uint32]0x8664).CopyTo($bytes, 0x30)
        [BitConverter]::GetBytes($Code).CopyTo($bytes, 0x38)
        foreach ($index in 0..3) { [BitConverter]::GetBytes($Parameters[$index]).CopyTo($bytes, (0x40 + 8 * $index)) }
        [BitConverter]::GetBytes([uint32]2).CopyTo($bytes, 0xf98)
        [BitConverter]::GetBytes($CrashTime.ToUniversalTime().ToFileTimeUtc()).CopyTo($bytes, 0xfa8)
        [BitConverter]::GetBytes([long]123456789).CopyTo($bytes, 0x1030)
        [IO.File]::WriteAllBytes($fixtureDump, $bytes)
    }
    Write-FixtureDump $bootTime.AddSeconds(-10)
    $fixtureEvent = [pscustomobject]@{TimeCreated = Get-Date; RecordId = 1}
    $fixtureEvent | Add-Member -MemberType ScriptMethod -Name ToXml -Value { '<Event><EventData><Data Name="param1">0x000000d1 (0x1, 0x2, 0x3, 0x4)</Data></EventData></Event>' }
    $fixtureSource = 'isolated_fixture'
    $fixtureCode = '0x000000D1'
    $fixtureParameters = @('0x1','0x2','0x3','0x4')
    function Get-KlayCrashReport {
        param([DateTime]$BootTime, $BootEvidence)
        return @{event = $fixtureEvent; code = $fixtureCode; parameters = $fixtureParameters; dumpPath = $fixtureDump; source = $fixtureSource}
    }
    function Get-KlayRecentEvents { return @() }
    function Get-KlayPreviousBoot { param([DateTime]$BootTime); return $previousBoot }

    # The manifest snapshot permits atomic host arm, but never in-place writers.
    $manifestPath = Join-Path $testRoot 'snapshot.json'
    $replacementPath = Join-Path $testRoot 'replacement.json'
    Write-KlayJson $manifestPath @{schema = 1; buildId = 'snapshot-A'}
    Write-KlayJson $replacementPath @{schema = 1; buildId = 'snapshot-B'}
    $snapshotHash = (Get-FileHash -LiteralPath $manifestPath -Algorithm SHA256).Hash.ToLowerInvariant()
    $snapshot = Open-ArmedBuildSnapshot $manifestPath
    try {
        $writerRejected = $false
        try {
            $writer = [IO.File]::Open($manifestPath, [IO.FileMode]::Open, [IO.FileAccess]::Write, ([IO.FileShare]::Read -bor [IO.FileShare]::Write -bor [IO.FileShare]::Delete))
            $writer.Dispose()
        } catch [IO.IOException] { $writerRejected = $true }
        if (-not $writerRejected) { throw 'Manifest snapshot allowed an in-place writer.' }
        [IO.File]::Replace($replacementPath, $manifestPath, (Join-Path $testRoot 'snapshot.backup.json'))
        $algorithm = [Security.Cryptography.SHA256]::Create()
        try { $heldHash = ([BitConverter]::ToString($algorithm.ComputeHash($snapshot))).Replace('-', '').ToLowerInvariant() } finally { $algorithm.Dispose() }
        $snapshot.Position = 0
        $reader = New-Object IO.StreamReader($snapshot, [Text.Encoding]::UTF8, $true)
        try { $heldManifest = $reader.ReadToEnd() | ConvertFrom-Json } finally { $reader.Dispose() }
        $newManifest = Read-KlayJson $manifestPath
        if ($heldHash -ne $snapshotHash -or $heldManifest.buildId -ne 'snapshot-A' -or $newManifest.buildId -ne 'snapshot-B') { throw 'Atomic replacement changed the held snapshot or did not publish the new build.' }
    } finally { $snapshot.Dispose() }

    # Immutable records remain publishable when an old HGFS-style handle denies delete.
    $offlineShareRoot = $ShareRoot
    $ShareRoot = Join-Path $testRoot 'selection-share'
    New-Item -ItemType Directory -Path $ShareRoot -Force | Out-Null
    $selections = Join-Path $ShareRoot 'build-selections'
    New-Item -ItemType Directory -Path $selections -Force | Out-Null
    $armTimeA = [DateTime]::UtcNow.AddMinutes(-2)
    $armTimeA = $armTimeA.AddTicks(-($armTimeA.Ticks % 10))
    $armTimeB = $armTimeA.AddSeconds(1)
    $recordA = $armTimeA.ToString("yyyyMMdd'T'HHmmssffffff'Z'") + '_immutable-A.json'
    $recordB = $armTimeB.ToString("yyyyMMdd'T'HHmmssffffff'Z'") + '_immutable-B.json'
    $immutableA = @{schema = 1; selectionProtocol = 'immutable_v1'; selectionRecord = $recordA; buildId = 'immutable-A'; armedAtUtc = $armTimeA.ToString('o')}
    $immutableB = @{schema = 1; selectionProtocol = 'immutable_v1'; selectionRecord = $recordB; buildId = 'immutable-B'; armedAtUtc = $armTimeB.ToString('o')}
    $pathA = Join-Path $selections $recordA
    $pathB = Join-Path $selections $recordB
    Write-KlayJson $pathA $immutableA
    $oldHandle = [IO.File]::Open($pathA, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        $ackA = Observe-ArmedBuild
        Write-KlayJson $pathB $immutableB
        $ackB = Observe-ArmedBuild
        if ($ackA.buildId -ne 'immutable-A' -or $ackB.buildId -ne 'immutable-B' -or $ackB.selectionProtocol -ne 'immutable_v1' -or $ackB.selectionRecord -ne $recordB) { throw 'A locked old record prevented observing the new immutable selection.' }
        if ($ackB.manifestSha256 -ne (Get-FileHash -LiteralPath $pathB -Algorithm SHA256).Hash.ToLowerInvariant()) { throw 'Immutable selection hash does not identify the observed record.' }
        Write-KlayJson (Join-Path $ShareRoot 'active-run.json') @{schema = 1; buildId = 'legacy-must-not-win'; armedAtUtc = $armTimeA.ToString('o')}
        foreach ($badCase in @('corrupt', 'protocol', 'identity', 'timestamp', 'record', 'oversized')) {
            $bad = @{schema = 1; selectionProtocol = 'immutable_v1'; selectionRecord = $recordB; buildId = 'immutable-B'; armedAtUtc = $armTimeB.ToString('o')}
            if ($badCase -eq 'protocol') { $bad.selectionProtocol = 'future_v2' }
            if ($badCase -eq 'identity') { $bad.buildId = 'other-build' }
            if ($badCase -eq 'timestamp') { $bad.armedAtUtc = $armTimeA.ToString('o') }
            if ($badCase -eq 'record') { $bad.selectionRecord = $recordA }
            if ($badCase -eq 'corrupt') { [IO.File]::WriteAllText($pathB, '{broken') }
            elseif ($badCase -eq 'oversized') { [IO.File]::WriteAllBytes($pathB, (New-Object byte[] 65537)) }
            else { Write-KlayJson $pathB $bad }
            $rejected = $false
            try { Observe-ArmedBuild | Out-Null } catch { $rejected = $true }
            if (-not $rejected) { throw "Invalid immutable record silently used another selection: $badCase" }
        }
        Write-KlayJson $pathB $immutableB
        $extraPath = Join-Path $selections 'invalid.json'
        [IO.File]::WriteAllText($extraPath, '{}')
        $overflowRejected = $false
        try { Get-ArmedBuildRecord -MaximumEntries 2 | Out-Null } catch { $overflowRejected = $true }
        if (-not $overflowRejected) { throw 'Immutable selection enumeration ignored its explicit limit.' }
        Remove-Item -LiteralPath $extraPath -Force
    } finally { $oldHandle.Dispose() }
    Remove-Item -LiteralPath $pathA, $pathB -Force
    [IO.File]::WriteAllText((Join-Path $selections 'invalid.json'), '{}')
    $invalidNamesRejected = $false
    try { Observe-ArmedBuild | Out-Null } catch { $invalidNamesRejected = $true }
    if (-not $invalidNamesRejected) { throw 'An invalid immutable directory silently fell back to legacy active-run.' }
    Remove-Item -LiteralPath (Join-Path $selections 'invalid.json') -Force
    $legacyAck = Observe-ArmedBuild
    if ($legacyAck.buildId -ne 'legacy-must-not-win' -or $legacyAck.selectionProtocol -ne 'legacy_active_run') { throw 'An empty immutable directory did not permit the documented legacy fallback.' }
    Remove-Item -LiteralPath $selections -Force
    Remove-Item -LiteralPath (Join-Path $ShareRoot 'active-run.json') -Force
    Remove-Item -LiteralPath (Join-Path $localRoot 'build-observations.json') -Force
    $ShareRoot = $offlineShareRoot

    Capture-CurrentCrash | Out-Null
    $localDump = Join-Path $localCrashPath 'memory.dmp'
    if (-not (Test-Path -LiteralPath $localDump)) { throw 'Offline capture did not preserve a local spool dump.' }
    $metadata = Get-Content -LiteralPath (Join-Path $localCrashPath 'crash.json') -Raw | ConvertFrom-Json
    if ($metadata.status -ne 'ready') { throw 'Offline capture did not finish.' }
    if ($metadata.dumpEvidence.header.systemUpTime100ns -ne 123456789 -or $metadata.dumpEvidence.header.bugcheckParameters.Count -ne 4) { throw 'Full AMD64 header evidence was not captured.' }
    if ($null -ne $metadata.armedBuild -or $metadata.buildCorrelation.state -ne 'unknown') { throw 'Unobserved build was presented as crash-associated.' }
    $publishFailed = $false
    try { Publish-Spool } catch { $publishFailed = $true }
    if (-not $publishFailed -or -not (Test-Path -LiteralPath $localDump)) { throw 'A failed upload lost the local dump.' }

    $ShareRoot = Join-Path $testRoot 'share'
    Publish-Spool
    $capture = Join-Path (Join-Path $ShareRoot 'crashes') $bootKey
    $ready = Get-Content -LiteralPath (Join-Path $capture 'ready.json') -Raw | ConvertFrom-Json
    $actualHash = (Get-FileHash -LiteralPath (Join-Path $capture 'memory.dmp') -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($actualHash -ne $ready.sha256 -or $ready.bytes -ne 8192) { throw 'Exported dump integrity is wrong.' }
    if (Test-Path -LiteralPath $localDump) { throw 'Successful upload left the duplicate spool dump.' }
    if (-not (Test-Path -LiteralPath $fixtureDump)) { throw 'Original dump was deleted.' }
    Publish-Spool
    if (-not (Test-Path -LiteralPath (Join-Path $capture 'memory.dmp'))) { throw 'Repeated publication lost the capture.' }

    # A late WER report cannot mutate an already published dump's identity without validation.
    $originalEventXml = Get-Content -LiteralPath (Join-Path $localCrashPath 'event.xml') -Raw
    $originalFixtureEvent = $fixtureEvent
    $originalMetadata = Read-KlayJson (Join-Path $localCrashPath 'crash.json')
    $fixtureSource = 'wer_1001'
    $fixtureCode = '0x00000050'
    $fixtureEvent = [pscustomobject]@{TimeCreated = Get-Date; RecordId = 2; XmlText = '<Event>Rejected WER code fixture</Event>'}
    $fixtureEvent | Add-Member -MemberType ScriptMethod -Name ToXml -Value { $this.XmlText }
    Capture-CurrentCrash | Out-Null
    $metadata = Read-KlayJson (Join-Path $localCrashPath 'crash.json')
    if ($metadata.status -ne 'ready' -or $metadata.bugcheckCode -ne '0x000000D1' -or $metadata.eventRecordId -ne 1 -or $metadata.reportUpgrade.state -ne 'rejected' -or (Get-Content -LiteralPath (Join-Path $localCrashPath 'event.xml') -Raw) -ne $originalEventXml) { throw 'A conflicting late WER code changed the original completed capture.' }
    if (-not (Test-Path -LiteralPath (Join-Path $localCrashPath 'wer-upgrade-event.xml'))) { throw 'Rejected WER evidence was not retained.' }
    $fixtureCode = '0x000000D1'
    $fixtureParameters = @('0x9','0x2','0x3','0x4')
    $fixtureEvent.RecordId = 3
    Capture-CurrentCrash | Out-Null
    $metadata = Read-KlayJson (Join-Path $localCrashPath 'crash.json')
    if ($metadata.status -ne 'ready' -or $metadata.bugcheckParameters[0] -ne '0x1' -or $metadata.reportUpgrade.state -ne 'rejected') { throw 'Conflicting late WER parameters changed the original completed capture.' }
    $fixtureParameters = @('0x1','0x2','0x3','0x4')
    $fixtureEvent.RecordId = 4
    $fixtureEvent.XmlText = '<Event>Accepted WER fixture</Event>'
    Capture-CurrentCrash | Out-Null
    $metadata = Read-KlayJson (Join-Path $localCrashPath 'crash.json')
    if ($metadata.status -ne 'ready' -or $metadata.source -ne 'wer_1001' -or $metadata.eventRecordId -ne 4 -or $metadata.dumpEvidence.eventRecordId -ne 4 -or $metadata.dumpEvidence.eventProvider -ne 'Microsoft-Windows-WER-SystemErrorReporting' -or $metadata.reportUpgrade.state -ne 'accepted') { throw 'A matching WER upgrade was rejected or retained stale dump/event provenance.' }
    if ((Get-Content -LiteralPath (Join-Path $localCrashPath 'event-fallback.xml') -Raw) -ne $originalEventXml) { throw 'The original fallback event was lost during a WER upgrade.' }
    Publish-Spool
    if (-not (Test-Path -LiteralPath (Join-Path $capture 'event-fallback.xml')) -or -not (Test-Path -LiteralPath (Join-Path $capture 'wer-upgrade-event.xml'))) { throw 'WER upgrade evidence was not published.' }

    # Legacy ready captures without header evidence retain their original report.
    $originalBootKey = $bootKey
    $bootKey = 'isolated-fixture-legacy-ready'
    $localCrashPath = Join-Path $spoolRoot $bootKey
    New-Item -ItemType Directory -Path $localCrashPath -Force | Out-Null
    $originalMetadata.crashId = $bootKey
    $originalMetadata.PSObject.Properties.Remove('dumpEvidence')
    Write-KlayJson (Join-Path $localCrashPath 'crash.json') $originalMetadata
    [IO.File]::WriteAllText((Join-Path $localCrashPath 'event.xml'), $originalEventXml)
    Capture-CurrentCrash | Out-Null
    $metadata = Read-KlayJson (Join-Path $localCrashPath 'crash.json')
    if ($metadata.status -ne 'ready' -or $metadata.source -ne 'isolated_fixture' -or $metadata.eventRecordId -ne 1 -or $metadata.reportUpgrade.error -notlike '*header evidence is unavailable*') { throw 'A legacy ready capture was rebound without dump evidence.' }
    $bootKey = $originalBootKey
    $localCrashPath = Join-Path $spoolRoot $bootKey
    $fixtureSource = 'isolated_fixture'
    $fixtureEvent = $originalFixtureEvent

    # A Windows writer still holding the dump must prevent capture until it closes.
    $bootKey = 'isolated-fixture-2'
    $localCrashPath = Join-Path $spoolRoot $bootKey
    Write-FixtureDump $bootTime.AddSeconds(-5)
    $writer = [IO.File]::Open($fixtureDump, [IO.FileMode]::Open, [IO.FileAccess]::Write, [IO.FileShare]::ReadWrite)
    try { Capture-CurrentCrash | Out-Null } finally { $writer.Dispose() }
    $metadata = Get-Content -LiteralPath (Join-Path $localCrashPath 'crash.json') -Raw | ConvertFrom-Json
    if ($metadata.status -ne 'waiting_for_dump') { throw 'Dump with an active writer was published.' }
    Capture-CurrentCrash | Out-Null
    Publish-Spool
    if (-not (Test-Path -LiteralPath (Join-Path (Join-Path (Join-Path $ShareRoot 'crashes') $bootKey) 'ready.json'))) { throw 'Capture did not recover after the writer closed.' }

    # Same event values do not permit attaching a previously associated dump again.
    $bootKey = 'isolated-fixture-reused'
    $localCrashPath = Join-Path $spoolRoot $bootKey
    Capture-CurrentCrash | Out-Null
    $metadata = Read-KlayJson (Join-Path $localCrashPath 'crash.json')
    if ($metadata.status -ne 'waiting_for_dump' -or $metadata.error -notlike '*already associated*') { throw 'A repeated dump SHA-256 was accepted for a different crash.' }

    # Fresh LastWriteTime cannot make a dump from an older boot valid.
    $bootKey = 'isolated-fixture-old-header'
    $localCrashPath = Join-Path $spoolRoot $bootKey
    Write-FixtureDump ([DateTime]::Parse($previousBoot.timeUtc).AddSeconds(-6))
    Capture-CurrentCrash | Out-Null
    $metadata = Read-KlayJson (Join-Path $localCrashPath 'crash.json')
    if ($metadata.status -ne 'waiting_for_dump' -or $metadata.error -notlike '*outside the crashed boot*') { throw 'An older dump header was accepted despite a fresh filesystem timestamp.' }

    # A long crash-to-reboot delay is valid within the crashed boot, not an arbitrary hour.
    $bootKey = 'isolated-fixture-delayed-boot'
    $localCrashPath = Join-Path $spoolRoot $bootKey
    $previousBoot.timeUtc = $bootTime.AddHours(-6).ToUniversalTime().ToString('o')
    Write-FixtureDump $bootTime.AddHours(-3)
    (Get-Item -LiteralPath $fixtureDump).LastWriteTime = $bootTime.AddHours(-3)
    Capture-CurrentCrash | Out-Null
    $metadata = Read-KlayJson (Join-Path $localCrashPath 'crash.json')
    if ($metadata.status -ne 'ready') { throw 'A legitimate delayed reboot was rejected.' }

    # Association uses guest observations before the crash, never the host's current selection.
    $crashTime = $bootTime.AddSeconds(-20)
    $manifestA = @{schema = 1; buildId = 'build-A'; armedAtUtc = $crashTime.AddMinutes(-1).ToUniversalTime().ToString('o')}
    $manifestB = @{schema = 1; buildId = 'build-B'; armedAtUtc = $crashTime.AddSeconds(1).ToUniversalTime().ToString('o')}
    Write-KlayJson (Join-Path $localRoot 'build-observations.json') @{schema = 1; observations = @(
        @{buildId = 'build-A'; armedAtUtc = $manifestA.armedAtUtc; firstObservedAtUtc = $crashTime.AddSeconds(-30).ToUniversalTime().ToString('o'); lastObservedAtUtc = $crashTime.AddSeconds(-1).ToUniversalTime().ToString('o'); manifestSha256 = 'aaa'; manifest = $manifestA},
        @{buildId = 'build-B'; armedAtUtc = $manifestB.armedAtUtc; firstObservedAtUtc = $crashTime.AddSeconds(2).ToUniversalTime().ToString('o'); lastObservedAtUtc = $crashTime.AddSeconds(3).ToUniversalTime().ToString('o'); manifestSha256 = 'bbb'; manifest = $manifestB}
    )}
    Write-KlayJson (Join-Path $ShareRoot 'active-run.json') $manifestB
    $bootKey = 'isolated-fixture-build-race'
    $localCrashPath = Join-Path $spoolRoot $bootKey
    Write-FixtureDump $crashTime
    Capture-CurrentCrash | Out-Null
    $metadata = Read-KlayJson (Join-Path $localCrashPath 'crash.json')
    if ($metadata.status -ne 'ready' -or $metadata.armedBuild.buildId -ne 'build-A' -or $metadata.buildCorrelation.state -ne 'observed_before_crash') { throw 'Post-crash host arm changed the crash build association.' }
    $observed = Observe-ArmedBuild
    if ($observed.buildId -ne 'build-B' -or $observed.manifestSha256 -ne (Get-FileHash -LiteralPath (Join-Path $ShareRoot 'active-run.json') -Algorithm SHA256).Hash.ToLowerInvariant()) { throw 'Guest observation acknowledgement/hash is incorrect.' }

    # Optional corrupt build context cannot stop the dump capture.
    [IO.File]::WriteAllText((Join-Path $localRoot 'build-observations.json'), '{broken')
    $bootKey = 'isolated-fixture-unknown-build'
    $localCrashPath = Join-Path $spoolRoot $bootKey
    Write-FixtureDump $bootTime.AddSeconds(-25)
    Capture-CurrentCrash | Out-Null
    $metadata = Read-KlayJson (Join-Path $localCrashPath 'crash.json')
    if ($metadata.status -ne 'ready' -or $null -ne $metadata.armedBuild -or $metadata.buildCorrelation.reason -notlike '*journal unavailable*') { throw 'Invalid optional build context blocked capture or supplied a false build.' }

    # Preserve the last observed settings of the crashed boot across subsequent boot heartbeats.
    $priorBoot = [DateTime]::Parse($previousBoot.timeUtc)
    Save-HealthyObservation @{timeUtc = $bootTime.AddSeconds(-40).ToUniversalTime().ToString('o'); bootTimeUtc = $priorBoot.ToUniversalTime().ToString('o'); marker = 'pre-crash'}
    Save-HealthyObservation @{timeUtc = [DateTime]::UtcNow.ToString('o'); bootTimeUtc = $bootTime.ToUniversalTime().ToString('o'); marker = 'post-boot'}
    $bootKey = 'isolated-fixture-environment'
    $localCrashPath = Join-Path $spoolRoot $bootKey
    Write-FixtureDump $bootTime.AddSeconds(-30)
    Capture-CurrentCrash | Out-Null
    $metadata = Read-KlayJson (Join-Path $localCrashPath 'crash.json')
    if ($metadata.status -ne 'ready' -or $metadata.preCrashObservation.marker -ne 'pre-crash') { throw 'Post-boot context overwrote the pre-crash observation.' }

    # Resume a known pending crash after another boot, using its own original boot bounds.
    $spoolRoot = Join-Path $localRoot 'recovery-spool'
    New-Item -ItemType Directory -Path $spoolRoot -Force | Out-Null
    $bootKey = 'isolated-fixture-pending-original'
    $localCrashPath = Join-Path $spoolRoot $bootKey
    $pendingFolder = $localCrashPath
    $pendingBoot = $bootTime
    Remove-Item -LiteralPath $fixtureDump -Force
    Capture-CurrentCrash | Out-Null
    $bootTime = $bootTime.AddMinutes(2)
    $bootKey = 'isolated-fixture-next-boot'
    $localCrashPath = Join-Path $spoolRoot $bootKey
    Write-FixtureDump $pendingBoot.AddSeconds(-35)
    Resume-PendingCaptures
    $metadata = Read-KlayJson (Join-Path $pendingFolder 'crash.json')
    if ($metadata.status -ne 'ready' -or $metadata.captureRecovery.originalBootTimeUtc -ne $pendingBoot.ToUniversalTime().ToString('o')) { throw 'Known pending crash did not safely resume after another reboot.' }

    # Unsupported format and unavailable prior boot stay unassociated with clear errors.
    $bootKey = 'isolated-fixture-unsupported'
    $localCrashPath = Join-Path $spoolRoot $bootKey
    [IO.File]::WriteAllBytes($fixtureDump, (New-Object byte[] 8192))
    Capture-CurrentCrash | Out-Null
    $metadata = Read-KlayJson (Join-Path $localCrashPath 'crash.json')
    if ($metadata.status -ne 'waiting_for_dump' -or $metadata.error -notlike '*Unsupported dump header*' -or -not (Test-Path -LiteralPath $fixtureDump)) { throw 'Unsupported dump was accepted or its original data was lost.' }
    $bootKey = 'isolated-fixture-no-boot-boundary'
    $localCrashPath = Join-Path $spoolRoot $bootKey
    $previousBoot = $null
    Write-FixtureDump $bootTime.AddSeconds(-10)
    Capture-CurrentCrash | Out-Null
    $metadata = Read-KlayJson (Join-Path $localCrashPath 'crash.json')
    if ($metadata.status -ne 'waiting_for_dump' -or $metadata.error -notlike '*Previous boot boundary*') { throw 'Dump with an unavailable prior boot boundary was accepted.' }
    Write-Output 'Offline spool, publication integrity, manifest atomic replacement, AMD64 header/event/boot correlation, duplicate refusal, build race, pre-crash context and pending reboot recovery checks passed. No Windows bugcheck was generated.'
} finally {
    # Verify the absolute recursive-delete target is the unique test folder in TEMP.
    $resolved = [IO.Path]::GetFullPath($testRoot)
    $allowedPrefix = Join-Path $tempParent 'klay-export-test-'
    if (-not $resolved.StartsWith($allowedPrefix, [StringComparison]::OrdinalIgnoreCase)) { throw 'Unsafe test cleanup target.' }
    Remove-Item -LiteralPath $resolved -Recurse -Force
}
