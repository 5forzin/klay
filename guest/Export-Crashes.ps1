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
$bootKey = $env:COMPUTERNAME.ToLowerInvariant() + '-' + $bootTime.ToUniversalTime().ToString('yyyyMMddTHHmmssfffffffZ')
$localCrashPath = Join-Path $spoolRoot $bootKey
$lastError = $null
$mutex = New-Object Threading.Mutex($false, 'Global\KlayExporter')
try { $ownsMutex = $mutex.WaitOne(0) } catch [Threading.AbandonedMutexException] { $ownsMutex = $true }
if (-not $ownsMutex) { $mutex.Dispose(); exit 0 }

function Copy-StableDump {
    param([string]$Source, [string]$Destination)
    $before = Get-Item -LiteralPath $Source
    if ($before.Length -lt 4096) { throw 'Dump is smaller than a valid Windows dump header.' }
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

function Capture-CurrentCrash {
    $report = Get-KlayCrashReport $bootTime
    if ($null -eq $report) { return $null }
    New-Item -ItemType Directory -Path $localCrashPath -Force | Out-Null
    $metadataPath = Join-Path $localCrashPath 'crash.json'
    $metadata = $null
    if (Test-Path -LiteralPath $metadataPath) { $metadata = Get-Content -LiteralPath $metadataPath -Raw | ConvertFrom-Json }
    if ($null -eq $metadata) {
        $activeRun = $null
        $activeRunPath = Join-Path $ShareRoot 'active-run.json'
        $cachedRun = Join-Path $localRoot 'active-run.json'
        try {
            if (Test-Path -LiteralPath $activeRunPath) { Copy-Item -LiteralPath $activeRunPath -Destination $cachedRun -Force }
        } catch { }
        if (Test-Path -LiteralPath $cachedRun) { $activeRun = Get-Content -LiteralPath $cachedRun -Raw | ConvertFrom-Json }
        $metadata = [pscustomobject]@{
            schema = 1; crashId = $bootKey; computer = $env:COMPUTERNAME
            bootTimeUtc = $bootTime.ToUniversalTime().ToString('o'); reportTimeUtc = $report.event.TimeCreated.ToUniversalTime().ToString('o')
            detectedAtUtc = [DateTime]::UtcNow.ToString('o'); source = $report.source
            bugcheckCode = $report.code; bugcheckParameters = $report.parameters
            eventRecordId = $report.event.RecordId; guestDumpPath = $report.dumpPath
            status = 'waiting_for_dump'; dump = $null; error = $null; armedBuild = $activeRun; exportedAtUtc = $null
            os = @{caption = $os.Caption; version = $os.Version; buildNumber = $os.BuildNumber}
        }
        Write-KlayJson $metadataPath $metadata
    }
    # Upgrade the same boot's fallback report once WER emits event 1001.
    if ($report.source -eq 'wer_1001' -and $metadata.source -ne 'wer_1001') {
        $metadata.source = $report.source; $metadata.bugcheckCode = $report.code
        $metadata.bugcheckParameters = $report.parameters; $metadata.guestDumpPath = $report.dumpPath
        $metadata.eventRecordId = $report.event.RecordId; $metadata.reportTimeUtc = $report.event.TimeCreated.ToUniversalTime().ToString('o')
    }
    if ($metadata.status -eq 'ready') {
        Write-KlayJson $metadataPath $metadata
        [IO.File]::WriteAllText((Join-Path $localCrashPath 'event.xml'), $report.event.ToXml(), (New-Object Text.UTF8Encoding($false)))
        return $bootKey
    }
    Write-KlayJson $metadataPath $metadata
    [IO.File]::WriteAllText((Join-Path $localCrashPath 'event.xml'), $report.event.ToXml(), (New-Object Text.UTF8Encoding($false)))
    Write-KlayJson (Join-Path $localCrashPath 'system-events.json') @(Get-KlayRecentEvents)
    try {
        $dumpPath = $metadata.guestDumpPath
        if (-not [IO.Path]::IsPathRooted($dumpPath) -or $dumpPath.StartsWith('\\')) { throw 'No valid local dump path was reported.' }
        $dumpItem = Get-Item -LiteralPath $dumpPath
        # Old MEMORY.DMP must not be attached to a new bugcheck.
        if ($dumpItem.LastWriteTime -lt $bootTime.AddHours(-1) -or $dumpItem.LastWriteTime -gt $report.event.TimeCreated.AddMinutes(2)) {
            throw 'Dump timestamp does not match this boot/report; refusing to reuse an old dump.'
        }
        $localDump = Join-Path $localCrashPath 'memory.dmp'
        $localInfo = Join-Path $localCrashPath 'dump-info.json'
        if (-not (Test-Path -LiteralPath $localInfo) -or -not (Test-Path -LiteralPath $localDump)) {
            $info = Copy-StableDump $dumpPath $localDump
            Write-KlayJson $localInfo $info
        }
        $info = Get-Content -LiteralPath $localInfo -Raw | ConvertFrom-Json
        $metadata.dump = @{file = 'memory.dmp'; bytes = $info.bytes; sha256 = $info.sha256; lastWriteUtc = $info.lastWriteUtc}
        $metadata.status = 'ready'; $metadata.error = $null
        Write-KlayJson $metadataPath $metadata
    } catch {
        $metadata.status = 'waiting_for_dump'; $metadata.error = $_.Exception.Message
        Write-KlayJson $metadataPath $metadata
    }
    return $bootKey
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
        foreach ($file in @('event.xml', 'system-events.json')) {
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
            Publish-Spool
            $activeRunPath = Join-Path $ShareRoot 'active-run.json'
            if (Test-Path -LiteralPath $activeRunPath) { Copy-Item -LiteralPath $activeRunPath -Destination (Join-Path $localRoot 'active-run.json') -Force }
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
            }
            Write-KlayJson (Join-Path $ShareRoot 'guest-status.json') $heartbeat
            Write-KlayJson (Join-Path $localRoot 'status.json') $heartbeat
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
