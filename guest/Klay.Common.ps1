Set-StrictMode -Version 2.0

function Write-KlayJson {
    param([string]$Path, $Value)
    $temporary = $Path + '.' + [Guid]::NewGuid().ToString('N') + '.partial'
    $json = ConvertTo-Json -InputObject $Value -Depth 15
    [IO.File]::WriteAllText($temporary, $json, (New-Object Text.UTF8Encoding($false)))
    Move-Item -LiteralPath $temporary -Destination $Path -Force
}

function Read-KlayJson {
    param([string]$Path, [long]$MaximumBytes = 65536)
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    if ((Get-Item -LiteralPath $Path).Length -gt $MaximumBytes) { throw "JSON exceeds the size limit: $Path" }
    return Get-Content -LiteralPath $Path -Raw | ConvertFrom-Json
}

function Get-KlayProperty {
    param($Value, [string]$Name, $Default = $null)
    if ($null -eq $Value) { return $Default }
    if ($Value -is [Collections.IDictionary]) {
        if ($Value.Contains($Name)) { return $Value[$Name] }
    } elseif ($null -ne $Value.PSObject.Properties[$Name]) { return $Value.$Name }
    return $Default
}

function Resolve-KlayInstallRoot {
    param([string]$Path, [string]$ProgramDataRoot = [Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData))
    if ($Path -notmatch '^[A-Za-z]:[\\/]' -or $ProgramDataRoot -notmatch '^[A-Za-z]:[\\/]') {
        throw 'InstallRoot must be an absolute local path directly below the system ProgramData directory.'
    }
    $requestedLeaf = [IO.Path]::GetFileName($Path.TrimEnd([char[]]'\/'))
    if ($requestedLeaf.EndsWith('.') -or $requestedLeaf.EndsWith(' ')) { throw 'InstallRoot cannot use a trailing-dot or trailing-space path alias.' }
    $systemRoot = [IO.Path]::GetFullPath($ProgramDataRoot).TrimEnd([char[]]'\/')
    $candidate = [IO.Path]::GetFullPath($Path).TrimEnd([char[]]'\/')
    $parent = [IO.Path]::GetDirectoryName($candidate)
    $leaf = [IO.Path]::GetFileName($candidate)
    if (-not [string]::Equals($parent, $systemRoot, [StringComparison]::OrdinalIgnoreCase) -or
        [string]::IsNullOrWhiteSpace($leaf) -or $leaf.EndsWith('.') -or $leaf.EndsWith(' ') -or
        $leaf.IndexOfAny([IO.Path]::GetInvalidFileNameChars()) -ge 0 -or
        $leaf -match '^(?i:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])(?:\.|$)') {
        throw 'InstallRoot must name one directory directly below the system ProgramData directory.'
    }
    return $candidate
}

function New-KlayProtectedSecurity {
    param([switch]$Directory)
    $system = New-Object Security.Principal.SecurityIdentifier('S-1-5-18')
    $administrators = New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')
    if ($Directory) {
        $security = New-Object Security.AccessControl.DirectorySecurity
        $inheritance = [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit'
    } else {
        $security = New-Object Security.AccessControl.FileSecurity
        $inheritance = [Security.AccessControl.InheritanceFlags]::None
    }
    $security.SetOwner($administrators)
    $security.SetAccessRuleProtection($true, $false)
    foreach ($identity in @($system, $administrators)) {
        $rule = New-Object Security.AccessControl.FileSystemAccessRule($identity, [Security.AccessControl.FileSystemRights]::FullControl, $inheritance, [Security.AccessControl.PropagationFlags]::None, [Security.AccessControl.AccessControlType]::Allow)
        $security.AddAccessRule($rule)
    }
    return $security
}

function Test-KlayProtectedSecurity {
    param($Security, [switch]$Directory)
    if (-not $Security.AreAccessRulesProtected) { return $false }
    if ($Security.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin @('S-1-5-18', 'S-1-5-32-544')) { return $false }
    $rules = @($Security.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
    if ($rules.Count -ne 2) { return $false }
    $expectedInheritance = [Security.AccessControl.InheritanceFlags]::None
    if ($Directory) { $expectedInheritance = [Security.AccessControl.InheritanceFlags]'ContainerInherit, ObjectInherit' }
    foreach ($sid in @('S-1-5-18', 'S-1-5-32-544')) {
        $matches = @($rules | Where-Object { $_.IdentityReference.Value -eq $sid })
        if ($matches.Count -ne 1) { return $false }
        $rule = $matches[0]
        if ($rule.AccessControlType -ne [Security.AccessControl.AccessControlType]::Allow -or
            $rule.FileSystemRights -ne [Security.AccessControl.FileSystemRights]::FullControl -or
            $rule.IsInherited -or $rule.InheritanceFlags -ne $expectedInheritance -or
            $rule.PropagationFlags -ne [Security.AccessControl.PropagationFlags]::None) { return $false }
    }
    return $true
}

function Protect-KlayInstallation {
    param([string]$Path)
    $root = Get-Item -LiteralPath $Path
    if (-not $root.PSIsContainer -or $root.FullName.StartsWith('\\') -or ($root.Attributes -band [IO.FileAttributes]::ReparsePoint)) { throw 'Guest installation must be a local directory without a reparse point.' }
    $ancestor = $root.Parent
    while ($null -ne $ancestor) {
        if ($ancestor.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Guest installation must not be reached through a reparse point.' }
        $ancestor = $ancestor.Parent
    }
    # Replace the DACL rather than retaining explicit grants from an earlier directory.
    Set-Acl -LiteralPath $root.FullName -AclObject (New-KlayProtectedSecurity -Directory)
    $directories = New-Object Collections.Generic.Queue[string]
    $directories.Enqueue($root.FullName)
    while ($directories.Count -gt 0) {
        $directory = $directories.Dequeue()
        if (-not (Test-KlayProtectedSecurity (Get-Acl -LiteralPath $directory) -Directory)) { throw "Guest installation permissions could not be verified: $directory" }
        foreach ($entry in @(Get-ChildItem -LiteralPath $directory -Force)) {
            if ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'Guest installation contains a reparse point; refusing to execute its scripts.' }
            Set-Acl -LiteralPath $entry.FullName -AclObject (New-KlayProtectedSecurity -Directory:$entry.PSIsContainer)
            if (-not (Test-KlayProtectedSecurity (Get-Acl -LiteralPath $entry.FullName) -Directory:$entry.PSIsContainer)) { throw "Guest installation permissions could not be verified: $($entry.FullName)" }
            if ($entry.PSIsContainer) { $directories.Enqueue($entry.FullName) }
        }
    }
}

function Get-KlayPreviousBoot {
    param([DateTime]$BootTime)
    # CIM's boot time may be several seconds after Kernel-General's StartTime.
    # Select the preceding boot by event record order, not a time-based exclusion.
    $events = @(Get-WinEvent -FilterHashtable @{LogName = 'System'; ProviderName = 'Microsoft-Windows-Kernel-General'; Id = 12} -MaxEvents 8 -ErrorAction SilentlyContinue | Sort-Object RecordId -Descending)
    if ($events.Count -lt 2) { return $null }
    $starts = @($events | ForEach-Object {
        $data = Get-KlayEventData $_
        $start = $_.TimeCreated.ToUniversalTime()
        if ($data.ContainsKey('StartTime')) {
            $start = [DateTime]::Parse($data['StartTime'], [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind).ToUniversalTime()
        }
        @{event = $_; start = $start}
    })
    # Missing/current-boot events and large clock changes are ambiguous; fail closed.
    if ([Math]::Abs(($starts[0].start - $BootTime.ToUniversalTime()).TotalSeconds) -gt 120) { return $null }
    $current = $starts[0]
    $previous = $starts[1]
    if ($previous.start -ge $current.start) { return $null }
    return @{
        timeUtc = $previous.start.ToString('o'); eventRecordId = $previous.event.RecordId; provider = $previous.event.ProviderName; eventId = 12
        currentBootTimeUtc = $current.start.ToString('o'); currentBootEventRecordId = $current.event.RecordId
    }
}

function Get-KlayDumpHeader {
    param([string]$Path)
    # Windows SDK mindumpdef.h DUMP_HEADER64. Read only its fixed 8 KiB header.
    $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
    try {
        $header = New-Object byte[] 8192
        $offset = 0
        while ($offset -lt $header.Length) {
            $count = $stream.Read($header, $offset, $header.Length - $offset)
            if ($count -eq 0) { throw 'Dump header is incomplete.' }
            $offset += $count
        }
    } finally { $stream.Dispose() }
    if ([Text.Encoding]::ASCII.GetString($header, 0, 8) -ne 'PAGEDU64' -or [BitConverter]::ToUInt32($header, 0x30) -ne 0x8664) {
        throw 'Unsupported dump header; expected a Windows AMD64 kernel dump (PAGEDU64).'
    }
    $systemTime = [DateTime]::FromFileTimeUtc([BitConverter]::ToInt64($header, 0xfa8))
    return @{
        format = 'windows_amd64_kernel'; systemTimeUtc = $systemTime.ToString('o')
        bugcheckCode = ('0x{0:X8}' -f [BitConverter]::ToUInt32($header, 0x38))
        bugcheckParameters = @((0..3) | ForEach-Object { '0x{0:x16}' -f [BitConverter]::ToUInt64($header, (0x40 + 8 * $_)) })
        dumpType = [BitConverter]::ToUInt32($header, 0xf98)
        systemUpTime100ns = [BitConverter]::ToInt64($header, 0x1030)
    }
}

function Get-KlayDiagnosticEnvironment {
    $version = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
    $result = @{
        observedAtUtc = [DateTime]::UtcNow.ToString('o'); provenance = 'observed_after_boot; not proof of settings at crash time'
        os = @{buildNumber = $version.CurrentBuildNumber; ubr = $version.UBR; displayVersion = (Get-KlayProperty $version 'DisplayVersion'); editionId = $version.EditionID; architecture = $env:PROCESSOR_ARCHITECTURE}
        secureBoot = @{enabled = $null; error = $null}; deviceGuard = $null; deviceGuardError = $null; defender = $null; defenderError = $null
    }
    try { $result.secureBoot.enabled = [bool](Confirm-SecureBootUEFI -ErrorAction Stop) } catch { $result.secureBoot.error = $_.Exception.Message.Substring(0, [Math]::Min(1024, $_.Exception.Message.Length)) }
    try {
        $guard = Get-CimInstance -Namespace 'root\Microsoft\Windows\DeviceGuard' -ClassName Win32_DeviceGuard -OperationTimeoutSec 5
        $result.deviceGuard = @{
            virtualizationBasedSecurityStatus = $guard.VirtualizationBasedSecurityStatus
            securityServicesConfigured = @($guard.SecurityServicesConfigured | Select-Object -First 16)
            securityServicesRunning = @($guard.SecurityServicesRunning | Select-Object -First 16)
        }
    } catch { $result.deviceGuardError = $_.Exception.Message.Substring(0, [Math]::Min(1024, $_.Exception.Message.Length)) }
    try {
        $defender = Get-CimInstance -Namespace 'root\Microsoft\Windows\Defender' -ClassName MSFT_MpComputerStatus -OperationTimeoutSec 5
        $result.defender = @{
            antivirusEnabled = (Get-KlayProperty $defender 'AntivirusEnabled')
            realTimeProtectionEnabled = (Get-KlayProperty $defender 'RealTimeProtectionEnabled')
            isTamperProtected = (Get-KlayProperty $defender 'IsTamperProtected')
        }
    } catch { $result.defenderError = $_.Exception.Message.Substring(0, [Math]::Min(1024, $_.Exception.Message.Length)) }
    return $result
}

function Test-KlayDumpCorrelation {
    param($Header, $Metadata)
    if ($Header.bugcheckCode -ne $Metadata.bugcheckCode) { throw 'Dump header Bug Check code disagrees with the Windows event.' }
    if (@($Metadata.bugcheckParameters).Count -ne 4) { throw 'Windows event does not provide four Bug Check parameters.' }
    foreach ($index in 0..3) {
        $eventValue = [string]$Metadata.bugcheckParameters[$index]
        if ($eventValue -notmatch '^0x[0-9a-fA-F]{1,16}$' -or [Convert]::ToUInt64($eventValue.Substring(2), 16) -ne [Convert]::ToUInt64($Header.bugcheckParameters[$index].Substring(2), 16)) {
            throw 'Dump header Bug Check parameters disagree with the Windows event.'
        }
    }
    $previousBoot = Get-KlayProperty $Metadata 'previousBoot'
    if ($null -eq $previousBoot) { throw 'Previous boot boundary is unavailable; cannot safely associate this dump with the crash.' }
    $dumpTime = [DateTime]::Parse($Header.systemTimeUtc).ToUniversalTime()
    $previousBootTime = [DateTime]::Parse($previousBoot.timeUtc).ToUniversalTime()
    $nextBootTime = [DateTime]::Parse((Get-KlayProperty $previousBoot 'currentBootTimeUtc' $Metadata.bootTimeUtc)).ToUniversalTime()
    if ($dumpTime -lt $previousBootTime.AddSeconds(-5) -or $dumpTime -gt $nextBootTime.AddSeconds(5)) {
        throw "Dump header time is outside the crashed boot; refusing to reuse another boot's dump."
    }
}

function Get-KlayEventData {
    param($Event)
    [xml]$xml = $Event.ToXml()
    $data = @{}
    foreach ($item in @($xml.SelectNodes("//*[local-name()='EventData']/*[local-name()='Data']"))) {
        if ($null -ne $item -and $item.HasAttribute('Name')) {
            $data[$item.GetAttribute('Name')] = $item.InnerText
        }
    }
    return $data
}

function Get-KlayBugCheck {
    param([string]$Text)
    $match = [regex]::Match($Text, '(?i)(0x[0-9a-f]+)\s*\(\s*(0x[0-9a-f]+)\s*,\s*(0x[0-9a-f]+)\s*,\s*(0x[0-9a-f]+)\s*,\s*(0x[0-9a-f]+)\s*\)')
    if (-not $match.Success) { return $null }
    return @{
        code = ('0x{0:X8}' -f [Convert]::ToUInt32($match.Groups[1].Value.Substring(2), 16))
        parameters = @((2..5) | ForEach-Object { $match.Groups[$_].Value.ToLowerInvariant() })
    }
}

function Get-KlayRecentEvents {
    $events = @(Get-WinEvent -FilterHashtable @{LogName = 'System'; Id = @(41, 46, 161, 1001, 6008)} -MaxEvents 32 -ErrorAction SilentlyContinue)
    return @($events | Where-Object {
        ($_.Id -eq 1001 -and $_.ProviderName -eq 'Microsoft-Windows-WER-SystemErrorReporting') -or
        ($_.Id -eq 41 -and $_.ProviderName -eq 'Microsoft-Windows-Kernel-Power') -or
        ($_.Id -in @(46, 161) -and $_.ProviderName -eq 'volmgr') -or
        ($_.Id -eq 6008 -and $_.ProviderName -eq 'EventLog')
    } | ForEach-Object {
        @{
            id = $_.Id; provider = $_.ProviderName; recordId = $_.RecordId
            timeUtc = $_.TimeCreated.ToUniversalTime().ToString('o')
            data = Get-KlayEventData $_; message = $_.Message
        }
    })
}

function Get-KlayCrashReport {
    param([DateTime]$BootTime, $BootEvidence = $null)
    $kernelBootTime = [DateTime]::Parse((Get-KlayProperty $BootEvidence 'currentBootTimeUtc' $BootTime.ToUniversalTime().ToString('o'))).ToUniversalTime()
    $currentBootRecordId = Get-KlayProperty $BootEvidence 'currentBootEventRecordId' 0
    $wer = Get-WinEvent -FilterHashtable @{LogName = 'System'; ProviderName = 'Microsoft-Windows-WER-SystemErrorReporting'; Id = 1001} -MaxEvents 1 -ErrorAction SilentlyContinue
    if ($null -ne $wer -and $wer.TimeCreated.ToUniversalTime() -ge $kernelBootTime.AddSeconds(-5) -and $wer.RecordId -gt $currentBootRecordId) {
        $data = Get-KlayEventData $wer
        $bugcheck = Get-KlayBugCheck ([string]$data['param1'])
        if ($null -ne $bugcheck) {
            return @{event = $wer; code = $bugcheck.code; parameters = $bugcheck.parameters; dumpPath = [string]$data['param2']; source = 'wer_1001'}
        }
    }
    # A nonzero code in Kernel-Power 41 is evidence of a bugcheck. Code 0 is not.
    $power = Get-WinEvent -FilterHashtable @{LogName = 'System'; ProviderName = 'Microsoft-Windows-Kernel-Power'; Id = 41} -MaxEvents 1 -ErrorAction SilentlyContinue
    if ($null -ne $power -and $power.TimeCreated.ToUniversalTime() -ge $kernelBootTime.AddSeconds(-5) -and $power.RecordId -gt $currentBootRecordId) {
        $data = Get-KlayEventData $power
        $decimalCode = 0L
        if ([long]::TryParse([string]$data['BugcheckCode'], [ref]$decimalCode) -and $decimalCode -gt 0) {
            return @{
                event = $power; code = ('0x{0:X8}' -f $decimalCode)
                parameters = @((1..4) | ForEach-Object { [string]$data['BugcheckParameter' + $_] })
                dumpPath = (Join-Path $env:SystemRoot 'MEMORY.DMP'); source = 'kernel_power_41_nonzero'
            }
        }
    }
    return $null
}
