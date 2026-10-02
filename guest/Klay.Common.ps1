Set-StrictMode -Version 2.0

function Write-KlayJson {
    param([string]$Path, $Value)
    $temporary = $Path + '.' + [Guid]::NewGuid().ToString('N') + '.partial'
    $json = ConvertTo-Json -InputObject $Value -Depth 15
    [IO.File]::WriteAllText($temporary, $json, (New-Object Text.UTF8Encoding($false)))
    Move-Item -LiteralPath $temporary -Destination $Path -Force
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
    param([DateTime]$BootTime)
    $wer = Get-WinEvent -FilterHashtable @{LogName = 'System'; ProviderName = 'Microsoft-Windows-WER-SystemErrorReporting'; Id = 1001} -MaxEvents 1 -ErrorAction SilentlyContinue
    if ($null -ne $wer -and $wer.TimeCreated -ge $BootTime.AddSeconds(-5)) {
        $data = Get-KlayEventData $wer
        $bugcheck = Get-KlayBugCheck ([string]$data['param1'])
        if ($null -ne $bugcheck) {
            return @{event = $wer; code = $bugcheck.code; parameters = $bugcheck.parameters; dumpPath = [string]$data['param2']; source = 'wer_1001'}
        }
    }
    # A nonzero code in Kernel-Power 41 is evidence of a bugcheck. Code 0 is not.
    $power = Get-WinEvent -FilterHashtable @{LogName = 'System'; ProviderName = 'Microsoft-Windows-Kernel-Power'; Id = 41} -MaxEvents 1 -ErrorAction SilentlyContinue
    if ($null -ne $power -and $power.TimeCreated -ge $BootTime.AddSeconds(-5)) {
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
