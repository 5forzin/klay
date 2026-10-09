[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$ShareRoot,
    [ValidateRange(5, 300)][int]$IntervalSeconds = 15,
    [switch]$Once
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Klay.Common.ps1')
$localRoot = $PSScriptRoot
$spoolRoot = Join-Path $localRoot 'spool'
New-Item -ItemType Directory -Path $spoolRoot -Force | Out-Null
$os = Get-CimInstance Win32_OperatingSystem
$bootTime = $os.LastBootUpTime
$previousBoot = Get-KlayPreviousBoot $bootTime
$diagnosticEnvironment = $null
$environmentRefreshAt = [DateTime]::MinValue
$bootKey = $env:COMPUTERNAME.ToLowerInvariant() + '-' + $bootTime.ToUniversalTime().ToString('yyyyMMddTHHmmssfffffffZ')
$localCrashPath = Join-Path $spoolRoot $bootKey
$lastError = $null
$mutex = New-Object Threading.Mutex($false, 'Global\KlayExporter')
try { $ownsMutex = $mutex.WaitOne(0) } catch [Threading.AbandonedMutexException] { $ownsMutex = $true }
if (-not $ownsMutex) { $mutex.Dispose(); exit 0 }

function Copy-StableDump {
    param([string]$Source, [string]$Destination)
    $before = Get-Item -LiteralPath $Source
    if ($before.Length -lt 8192) { throw 'Dump is smaller than a valid Windows AMD64 dump header.' }
    # Deny writers while copying, so an unfinished WER dump cannot be published.
    $inputStream = [IO.File]::Open($Source, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        $outputStream = [IO.File]::Open($Destination, [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::None)
        try { $inputStream.CopyTo($outputStream); $outputStream.Flush($true) } finally { $outputStream.Dispose() }
    } finally { $inputStream.Dispose() }
    $after = Get-Item -LiteralPath $Source
    if ($before.Length -ne $after.Length -or $before.LastWriteTimeUtc -ne $after.LastWriteTimeUtc) {
        Remove-Item -LiteralPath $Destination -Force
        throw 'Dump changed while copying; retrying on the next poll.'
    }
    return @{bytes = $after.Length; lastWriteUtc = $after.LastWriteTimeUtc.ToString('o'); sha256 = (Get-FileHash -LiteralPath $Destination -Algorithm SHA256).Hash.ToLowerInvariant()}
}

function Open-ArmedBuildSnapshot {
    param([string]$Path)
    # Allow atomic replacement while this handle keeps the previous file's bytes.
    return [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, ([IO.FileShare]::Read -bor [IO.FileShare]::Delete))
}

function Get-ArmedBuildRecord {
    param([ValidateRange(1, 1024)][int]$MaximumEntries = 1024)
    $directory = Join-Path $ShareRoot 'build-selections'
    if (Test-Path -LiteralPath $directory) {
        $latest = $null
        $count = 0
        $iterator = [IO.Directory]::EnumerateFiles($directory, '*.json', [IO.SearchOption]::TopDirectoryOnly).GetEnumerator()
        try {
            while ($iterator.MoveNext()) {
                $count++
                if ($count -gt $MaximumEntries) { throw 'Build selection history exceeds 1024 JSON records; move old archived selections out of the share.' }
                $path = $iterator.Current
                $name = [IO.Path]::GetFileName($path)
                if ($name -cnotmatch '^([0-9]{8}T[0-9]{12}Z)_([A-Za-z0-9_-]{1,128})\.json$') { continue }
                $timestamp = $Matches[1]
                $buildId = $Matches[2]
                try { $time = [DateTime]::ParseExact($timestamp, "yyyyMMdd'T'HHmmssffffff'Z'", [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]'AssumeUniversal,AdjustToUniversal') } catch { continue }
                if ($null -eq $latest -or [StringComparer]::Ordinal.Compare($name, $latest.name) -gt 0) {
                    $latest = @{path = $path; name = $name; protocol = 'immutable_v1'; buildId = $buildId; armedTime = $time}
                }
            }
        } finally { $iterator.Dispose() }
        if ($count -gt 0) {
            if ($null -eq $latest) { throw 'Immutable build selection history contains JSON records but no valid record filename.' }
            return $latest
        }
    }
    $legacyPath = Join-Path $ShareRoot 'active-run.json'
    if (Test-Path -LiteralPath $legacyPath) { return @{path = $legacyPath; name = 'active-run.json'; protocol = 'legacy_active_run'} }
    return $null
}

function Observe-ArmedBuild {
    $journalPath = Join-Path $localRoot 'build-observations.json'
    $journal = Read-KlayJson $journalPath 8388608
    $observations = @()
    if ($null -ne $journal) { $observations = @(Get-KlayProperty $journal 'observations' @()) }
    $record = Get-ArmedBuildRecord
    if ($null -eq $record) { return $null }
    $manifestPath = $record.path
    $item = Get-Item -LiteralPath $manifestPath
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Build selection must be a regular JSON file.' }
    # Keep the exact bytes checked and parsed together; an arm may replace the file at any time.
    $stream = Open-ArmedBuildSnapshot $manifestPath
    try {
        if ($stream.Length -gt 65536) { throw 'Active build manifest exceeds 64 KiB.' }
        $algorithm = [Security.Cryptography.SHA256]::Create()
        try { $manifestHash = ([BitConverter]::ToString($algorithm.ComputeHash($stream))).Replace('-', '').ToLowerInvariant() } finally { $algorithm.Dispose() }
        $stream.Position = 0
        $reader = New-Object IO.StreamReader($stream, [Text.Encoding]::UTF8, $true)
        try { $text = $reader.ReadToEnd() } finally { $reader.Dispose() }
    } finally { $stream.Dispose() }
    $manifest = $text | ConvertFrom-Json
    $buildId = [string](Get-KlayProperty $manifest 'buildId' '')
    if ($buildId -notmatch '^[A-Za-z0-9_-]{1,128}$' -or (Get-KlayProperty $manifest 'schema') -ne 1) { throw 'Active build manifest has an invalid identity or schema.' }
    $armedAt = [DateTime]::Parse([string](Get-KlayProperty $manifest 'armedAtUtc' ''), [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime()
    if ($record.protocol -eq 'immutable_v1') {
        if ((Get-KlayProperty $manifest 'selectionProtocol') -cne 'immutable_v1' -or
            (Get-KlayProperty $manifest 'selectionRecord') -cne $record.name -or
            $buildId -cne $record.buildId -or $armedAt.Ticks -ne $record.armedTime.Ticks) {
            throw 'Immutable build selection protocol, identity or arm timestamp disagrees with its filename.'
        }
    }
    $now = [DateTime]::UtcNow
    if ($armedAt -gt $now.AddSeconds(5)) { throw 'Active build manifest is dated in the future; check host/guest clocks.' }
    $last = $null
    if ($observations.Count -gt 0) { $last = $observations[-1] }
    if ($null -eq $last -or $last.manifestSha256 -ne $manifestHash) {
        $last = [pscustomobject]@{
            buildId = $buildId; armedAtUtc = $armedAt.ToString('o'); firstObservedAtUtc = $now.ToString('o')
            lastObservedAtUtc = $now.ToString('o'); observedBootTimeUtc = $bootTime.ToUniversalTime().ToString('o')
            manifestSha256 = $manifestHash; manifest = $manifest
            selectionProtocol = $record.protocol; selectionRecord = $record.name
        }
        $observations += $last
    } else { $last.lastObservedAtUtc = $now.ToString('o') }
    $observations = @($observations | Select-Object -Last 64)
    Write-KlayJson $journalPath @{schema = 1; observations = $observations}
    return @{buildId = $last.buildId; armedAtUtc = $last.armedAtUtc; firstObservedAtUtc = $last.firstObservedAtUtc; lastObservedAtUtc = $last.lastObservedAtUtc; manifestSha256 = $last.manifestSha256; selectionProtocol = $record.protocol; selectionRecord = $record.name}
}

function Get-CrashBuildSelection {
    param([DateTime]$CrashTime)
    $result = @{build = $null; correlation = @{state = 'unknown'; reason = 'No build was observed by the guest before the crash.'; crashTimeUtc = $CrashTime.ToUniversalTime().ToString('o'); crashTimeSource = 'dump_header'}; observations = @()}
    try {
        $journal = Read-KlayJson (Join-Path $localRoot 'build-observations.json') 8388608
        if ($null -eq $journal) { return $result }
        $observations = @((Get-KlayProperty $journal 'observations' @()) | Select-Object -Last 64)
        $result.observations = @($observations | ForEach-Object { @{buildId = $_.buildId; armedAtUtc = $_.armedAtUtc; firstObservedAtUtc = $_.firstObservedAtUtc; lastObservedAtUtc = $_.lastObservedAtUtc; manifestSha256 = $_.manifestSha256; selectionProtocol = (Get-KlayProperty $_ 'selectionProtocol' 'legacy_active_run'); selectionRecord = (Get-KlayProperty $_ 'selectionRecord' 'active-run.json')} })
        $eligible = @($observations | Where-Object {
            [DateTime]::Parse($_.firstObservedAtUtc).ToUniversalTime() -le $CrashTime.ToUniversalTime() -and
            [DateTime]::Parse($_.armedAtUtc).ToUniversalTime() -le $CrashTime.ToUniversalTime()
        } | Sort-Object firstObservedAtUtc)
        if ($eligible.Count -gt 0) {
            $selected = $eligible[-1]
            $result.build = $selected.manifest
            $result.correlation = @{
                state = 'observed_before_crash'; crashTimeUtc = $CrashTime.ToUniversalTime().ToString('o'); crashTimeSource = 'dump_header'
                firstObservedAtUtc = $selected.firstObservedAtUtc; armedAtUtc = $selected.armedAtUtc; manifestSha256 = $selected.manifestSha256
                selectionProtocol = (Get-KlayProperty $selected 'selectionProtocol' 'legacy_active_run'); selectionRecord = (Get-KlayProperty $selected 'selectionRecord' 'active-run.json')
                reason = 'Guest observed the selected build before the crash; confirm the loaded module and matching PDB in the debugger.'
            }
        }
    } catch { $result.correlation.reason = 'Build observation journal unavailable: ' + $_.Exception.Message }
    return $result
}

function Set-CrashProperty {
    param($Metadata, [string]$Name, $Value)
    $Metadata | Add-Member -MemberType NoteProperty -Name $Name -Value $Value -Force
}

function Save-HealthyObservation {
    param($Observation)
    $journalPath = Join-Path $localRoot 'healthy-observations.json'
    $journal = Read-KlayJson $journalPath 1048576
    $observations = @()
    if ($null -ne $journal) { $observations = @((Get-KlayProperty $journal 'observations' @()) | Where-Object { $_.bootTimeUtc -ne $Observation.bootTimeUtc }) }
    $observations += $Observation
    Write-KlayJson $journalPath @{schema = 1; observations = @($observations | Select-Object -Last 64)}
}

function Capture-PendingDump {
    param([string]$Folder, $Metadata)
    $metadataPath = Join-Path $Folder 'crash.json'
    try {
        if ($null -eq (Get-KlayProperty $Metadata 'previousBoot')) {
            Set-CrashProperty $Metadata 'previousBoot' (Get-KlayPreviousBoot ([DateTime]::Parse($Metadata.bootTimeUtc)))
        }
        $dumpPath = $Metadata.guestDumpPath
        if (-not [IO.Path]::IsPathRooted($dumpPath) -or $dumpPath.StartsWith('\\')) { throw 'No valid local dump path was reported.' }
        $localDump = Join-Path $Folder 'memory.dmp'
        $localInfo = Join-Path $Folder 'dump-info.json'
        if (-not (Test-Path -LiteralPath $localInfo) -or -not (Test-Path -LiteralPath $localDump)) {
            $header = Get-KlayDumpHeader $dumpPath
            Test-KlayDumpCorrelation $header $Metadata
            $info = Copy-StableDump $dumpPath $localDump
            $header = Get-KlayDumpHeader $localDump
            Test-KlayDumpCorrelation $header $Metadata
            $info.header = $header
            $info.capturedAtUtc = [DateTime]::UtcNow.ToString('o')
            Write-KlayJson $localInfo $info
        }
        $info = Read-KlayJson $localInfo
        if ($null -eq (Get-KlayProperty $info 'header')) {
            $header = Get-KlayDumpHeader $localDump
            Test-KlayDumpCorrelation $header $Metadata
            $info | Add-Member -MemberType NoteProperty -Name header -Value $header -Force
            Write-KlayJson $localInfo $info
        } else { Test-KlayDumpCorrelation $info.header $Metadata }
        $associationsPath = Join-Path $localRoot 'dump-associations.json'
        $ledger = Read-KlayJson $associationsPath 131072
        $associations = @()
        if ($null -ne $ledger) { $associations = @(Get-KlayProperty $ledger 'associations' @()) }
        $other = @($associations | Where-Object { $_.sha256 -eq $info.sha256 -and $_.crashId -ne $Metadata.crashId })
        if ($other.Count -gt 0) { throw 'This dump SHA-256 is already associated with another crash; refusing to reuse it.' }
        if (@($associations | Where-Object { $_.crashId -eq $Metadata.crashId -and $_.sha256 -eq $info.sha256 }).Count -eq 0) {
            $associations += @{crashId = $Metadata.crashId; sha256 = $info.sha256; dumpSystemTimeUtc = $info.header.systemTimeUtc; associatedAtUtc = [DateTime]::UtcNow.ToString('o')}
            Write-KlayJson $associationsPath @{schema = 1; associations = @($associations | Select-Object -Last 128)}
        }
        $selection = Get-CrashBuildSelection ([DateTime]::Parse($info.header.systemTimeUtc))
        $Metadata.armedBuild = $selection.build
        Set-CrashProperty $Metadata 'buildCorrelation' $selection.correlation
        Set-CrashProperty $Metadata 'buildObservations' $selection.observations
        if ($null -eq (Get-KlayProperty $Metadata 'preCrashObservation')) {
            try {
                $history = Read-KlayJson (Join-Path $localRoot 'healthy-observations.json') 1048576
                $observations = @((Get-KlayProperty $history 'observations' @()) | Where-Object {
                    [DateTime]::Parse($_.timeUtc).ToUniversalTime() -le [DateTime]::Parse($info.header.systemTimeUtc).ToUniversalTime() -and
                    [Math]::Abs(([DateTime]::Parse((Get-KlayProperty $_ 'kernelBootTimeUtc' $_.bootTimeUtc)) - [DateTime]::Parse($Metadata.previousBoot.timeUtc)).TotalSeconds) -le 5
                } | Sort-Object timeUtc)
                if ($observations.Count -gt 0) { Set-CrashProperty $Metadata 'preCrashObservation' $observations[-1] }
            } catch { Set-CrashProperty $Metadata 'preCrashObservationError' $_.Exception.Message }
        }
        Set-CrashProperty $Metadata 'dumpEvidence' @{
            method = 'amd64_header_boot_interval_event_parameters_and_sha256'
            header = $info.header; sourcePath = $dumpPath; sourceLastWriteUtc = $info.lastWriteUtc
            capturedAtUtc = (Get-KlayProperty $info 'capturedAtUtc'); sha256 = $info.sha256; previousBoot = $Metadata.previousBoot
            eventProvider = if ($Metadata.source -eq 'wer_1001') {'Microsoft-Windows-WER-SystemErrorReporting'} else {'Microsoft-Windows-Kernel-Power'}
            eventRecordId = $Metadata.eventRecordId
        }
        if ($Metadata.crashId -ne $bootKey) {
            Set-CrashProperty $Metadata 'captureRecovery' @{resumedAtUtc = [DateTime]::UtcNow.ToString('o'); capturedOnBootTimeUtc = $bootTime.ToUniversalTime().ToString('o'); originalBootTimeUtc = $Metadata.bootTimeUtc}
        }
        $Metadata.dump = @{file = 'memory.dmp'; bytes = $info.bytes; sha256 = $info.sha256; lastWriteUtc = $info.lastWriteUtc}
        $Metadata.status = 'ready'; $Metadata.error = $null
    } catch {
        $Metadata.status = 'waiting_for_dump'; $Metadata.error = $_.Exception.Message
    }
    Write-KlayJson $metadataPath $Metadata
}

function Capture-CurrentCrash {
    $report = Get-KlayCrashReport $bootTime $previousBoot
    if ($null -eq $report) { return $null }
    New-Item -ItemType Directory -Path $localCrashPath -Force | Out-Null
    $metadataPath = Join-Path $localCrashPath 'crash.json'
    $metadata = $null
    if (Test-Path -LiteralPath $metadataPath) { $metadata = Get-Content -LiteralPath $metadataPath -Raw | ConvertFrom-Json }
    if ($null -eq $metadata) {
        $metadata = [pscustomobject]@{
            schema = 1; crashId = $bootKey; computer = $env:COMPUTERNAME
            bootTimeUtc = $bootTime.ToUniversalTime().ToString('o'); reportTimeUtc = $report.event.TimeCreated.ToUniversalTime().ToString('o')
            detectedAtUtc = [DateTime]::UtcNow.ToString('o'); source = $report.source
            bugcheckCode = $report.code; bugcheckParameters = $report.parameters
            eventRecordId = $report.event.RecordId; guestDumpPath = $report.dumpPath
            status = 'waiting_for_dump'; dump = $null; error = $null; armedBuild = $null; exportedAtUtc = $null
            previousBoot = $previousBoot; buildCorrelation = @{state = 'unknown'; reason = 'Awaiting a validated dump time.'}
            os = @{caption = $os.Caption; version = $os.Version; buildNumber = $os.BuildNumber}
        }
        Write-KlayJson $metadataPath $metadata
    }
    # Upgrade the same boot's fallback report once WER emits event 1001.
    if ($report.source -eq 'wer_1001' -and ($metadata.source -ne 'wer_1001' -or $metadata.eventRecordId -ne $report.event.RecordId)) {
        $previousSource = $metadata.source
        $previousRecord = $metadata.eventRecordId
        $dumpEvidence = Get-KlayProperty $metadata 'dumpEvidence'
        if ($metadata.status -eq 'ready') {
            try {
                $header = Get-KlayProperty $dumpEvidence 'header'
                if ($null -eq $header) { throw 'Captured dump header evidence is unavailable; preserving the original report.' }
                $candidate = [pscustomobject]@{bugcheckCode = $report.code; bugcheckParameters = $report.parameters; previousBoot = (Get-KlayProperty $metadata 'previousBoot'); bootTimeUtc = $metadata.bootTimeUtc}
                Test-KlayDumpCorrelation $header $candidate
            } catch {
                Set-CrashProperty $metadata 'reportUpgrade' @{
                    state = 'rejected'; observedAtUtc = [DateTime]::UtcNow.ToString('o'); error = $_.Exception.Message
                    candidate = @{source = $report.source; eventRecordId = $report.event.RecordId; reportTimeUtc = $report.event.TimeCreated.ToUniversalTime().ToString('o'); bugcheckCode = $report.code; bugcheckParameters = $report.parameters}
                }
                [IO.File]::WriteAllText((Join-Path $localCrashPath 'wer-upgrade-event.xml'), $report.event.ToXml(), (New-Object Text.UTF8Encoding($false)))
                Write-KlayJson $metadataPath $metadata
                return $bootKey
            }
        }
        $originalEvent = Join-Path $localCrashPath 'event.xml'
        $fallbackEvent = Join-Path $localCrashPath 'event-fallback.xml'
        if (Test-Path -LiteralPath $originalEvent) {
            if (-not (Test-Path -LiteralPath $fallbackEvent)) { Copy-Item -LiteralPath $originalEvent -Destination $fallbackEvent }
        }
        $metadata.source = $report.source; $metadata.bugcheckCode = $report.code
        $metadata.bugcheckParameters = $report.parameters; $metadata.guestDumpPath = $report.dumpPath
        $metadata.eventRecordId = $report.event.RecordId; $metadata.reportTimeUtc = $report.event.TimeCreated.ToUniversalTime().ToString('o')
        if ($null -ne $dumpEvidence) {
            Set-CrashProperty $dumpEvidence 'eventProvider' 'Microsoft-Windows-WER-SystemErrorReporting'
            Set-CrashProperty $dumpEvidence 'eventRecordId' $report.event.RecordId
        }
        Set-CrashProperty $metadata 'reportUpgrade' @{
            state = if ($metadata.status -eq 'ready') {'accepted'} else {'pending_dump_validation'}
            observedAtUtc = [DateTime]::UtcNow.ToString('o'); previousSource = $previousSource; previousEventRecordId = $previousRecord
            eventProvider = 'Microsoft-Windows-WER-SystemErrorReporting'; eventRecordId = $report.event.RecordId
        }
    }
    if ($metadata.status -eq 'ready') {
        Write-KlayJson $metadataPath $metadata
        [IO.File]::WriteAllText((Join-Path $localCrashPath 'event.xml'), $report.event.ToXml(), (New-Object Text.UTF8Encoding($false)))
        return $bootKey
    }
    Write-KlayJson $metadataPath $metadata
    [IO.File]::WriteAllText((Join-Path $localCrashPath 'event.xml'), $report.event.ToXml(), (New-Object Text.UTF8Encoding($false)))
    Write-KlayJson (Join-Path $localCrashPath 'system-events.json') @(Get-KlayRecentEvents)
    Capture-PendingDump $localCrashPath $metadata
    return $bootKey
}

function Resume-PendingCaptures {
    foreach ($folder in @(Get-ChildItem -LiteralPath $spoolRoot -Directory | Sort-Object Name -Descending | Select-Object -First 64)) {
        if ($folder.Name -eq $bootKey) { continue }
        $metadata = Read-KlayJson (Join-Path $folder.FullName 'crash.json') 8388608
        if ($null -ne $metadata -and $metadata.status -eq 'waiting_for_dump') { Capture-PendingDump $folder.FullName $metadata }
    }
}

function Publish-Spool {
    New-Item -ItemType Directory -Path (Join-Path $ShareRoot 'crashes') -Force | Out-Null
    foreach ($folder in @(Get-ChildItem -LiteralPath $spoolRoot -Directory)) {
        $metadataPath = Join-Path $folder.FullName 'crash.json'
        if (-not (Test-Path -LiteralPath $metadataPath)) { continue }
        $metadata = Get-Content -LiteralPath $metadataPath -Raw | ConvertFrom-Json
        $destination = Join-Path (Join-Path $ShareRoot 'crashes') $folder.Name
        New-Item -ItemType Directory -Path $destination -Force | Out-Null
        Write-KlayJson (Join-Path $destination 'crash.json') $metadata
        foreach ($file in @('event.xml', 'system-events.json', 'event-fallback.xml', 'wer-upgrade-event.xml')) {
            $source = Join-Path $folder.FullName $file
            if (Test-Path -LiteralPath $source) { Copy-Item -LiteralPath $source -Destination (Join-Path $destination $file) -Force }
        }
        if (Test-Path -LiteralPath (Join-Path $destination 'ready.json')) { continue }
        $localDump = Join-Path $folder.FullName 'memory.dmp'
        if ($metadata.status -ne 'ready' -or -not (Test-Path -LiteralPath $localDump)) { continue }
        $partialDump = Join-Path $destination 'memory.dmp.partial'
        Copy-Item -LiteralPath $localDump -Destination $partialDump -Force
        $exportedHash = (Get-FileHash -LiteralPath $partialDump -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($exportedHash -ne $metadata.dump.sha256 -or (Get-Item -LiteralPath $partialDump).Length -ne $metadata.dump.bytes) { throw 'Shared-folder dump integrity check failed.' }
        Move-Item -LiteralPath $partialDump -Destination (Join-Path $destination 'memory.dmp') -Force
        $metadata.exportedAtUtc = [DateTime]::UtcNow.ToString('o')
        Write-KlayJson $metadataPath $metadata
        Write-KlayJson (Join-Path $destination 'crash.json') $metadata
        Write-KlayJson (Join-Path $destination 'ready.json') @{schema = 1; crashId = $folder.Name; file = 'memory.dmp'; bytes = $metadata.dump.bytes; sha256 = $metadata.dump.sha256; exportedAtUtc = $metadata.exportedAtUtc}
        # Remove only our successful spool copy, never the Windows dump.
        Remove-Item -LiteralPath $localDump -Force
    }
}

try {
    do {
        try {
            # Capture locally before any shared-folder access, including during an outage.
            $crashId = Capture-CurrentCrash
            Resume-PendingCaptures
            if ([DateTime]::UtcNow -ge $environmentRefreshAt) {
                try { $diagnosticEnvironment = Get-KlayDiagnosticEnvironment } catch { $diagnosticEnvironment = @{observedAtUtc = [DateTime]::UtcNow.ToString('o'); error = $_.Exception.Message} }
                $environmentRefreshAt = [DateTime]::UtcNow.AddMinutes(1)
            }
            if ($null -ne $crashId) {
                $currentMetadataPath = Join-Path $localCrashPath 'crash.json'
                $currentMetadata = Read-KlayJson $currentMetadataPath 8388608
                if ($null -eq (Get-KlayProperty $currentMetadata 'postBootEnvironment')) {
                    Set-CrashProperty $currentMetadata 'postBootEnvironment' $diagnosticEnvironment
                    Write-KlayJson $currentMetadataPath $currentMetadata
                }
            }
            Publish-Spool
            $observedBuild = $null
            $buildObservationError = $null
            try { $observedBuild = Observe-ArmedBuild } catch { $buildObservationError = $_.Exception.Message }
            $crashControl = Get-ItemProperty -LiteralPath 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl'
            $heartbeat = @{
                schema = 1; timeUtc = [DateTime]::UtcNow.ToString('o'); computer = $env:COMPUTERNAME
                identity = [Security.Principal.WindowsIdentity]::GetCurrent().Name
                bootTimeUtc = $bootTime.ToUniversalTime().ToString('o'); exporter = 'running'
                crashId = $crashId; crashDumpEnabled = $crashControl.CrashDumpEnabled; autoReboot = $crashControl.AutoReboot
                pagefiles = @(Get-CimInstance Win32_PageFileUsage | Select-Object Name, AllocatedBaseSize)
                automaticManagedPagefile = (Get-CimInstance Win32_ComputerSystem).AutomaticManagedPagefile
                systemDriveFreeBytes = (Get-CimInstance Win32_LogicalDisk -Filter "DeviceID='$env:SystemDrive'").FreeSpace
                recentSystemEvents = @(Get-KlayRecentEvents); error = $null
                observedBuild = $observedBuild; buildObservationError = $buildObservationError
                selectionProtocol = 'immutable_v1'
                environment = $diagnosticEnvironment
            }
            Write-KlayJson (Join-Path $ShareRoot 'guest-status.json') $heartbeat
            Write-KlayJson (Join-Path $localRoot 'status.json') $heartbeat
            Save-HealthyObservation @{
                schema = 1; timeUtc = $heartbeat.timeUtc; bootTimeUtc = $heartbeat.bootTimeUtc
                kernelBootTimeUtc = (Get-KlayProperty $previousBoot 'currentBootTimeUtc' $heartbeat.bootTimeUtc)
                environment = $diagnosticEnvironment; observedBuild = $observedBuild
                crashDumpEnabled = $heartbeat.crashDumpEnabled; autoReboot = $heartbeat.autoReboot
                pagefiles = $heartbeat.pagefiles; automaticManagedPagefile = $heartbeat.automaticManagedPagefile
                systemDriveFreeBytes = $heartbeat.systemDriveFreeBytes
            }
            $lastError = $null
        } catch {
            $lastError = $_.Exception.Message
            Write-KlayJson (Join-Path $localRoot 'status.json') @{schema = 1; timeUtc = [DateTime]::UtcNow.ToString('o'); exporter = 'retrying'; error = $lastError}
        }
        if (-not $Once) { Start-Sleep -Seconds $IntervalSeconds }
    } while (-not $Once)
} finally {
    $mutex.ReleaseMutex(); $mutex.Dispose()
}
