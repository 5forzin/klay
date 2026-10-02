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
    $bootKey = 'isolated-fixture-1'
    $localCrashPath = Join-Path $spoolRoot $bootKey
    $os = [pscustomobject]@{Caption = 'Isolated fixture'; Version = '0'; BuildNumber = '0'}
    $fixtureDump = Join-Path $testRoot 'fixture.dmp'
    [IO.File]::WriteAllBytes($fixtureDump, (New-Object byte[] 8192))
    $fixtureEvent = [pscustomobject]@{TimeCreated = Get-Date; RecordId = 1}
    $fixtureEvent | Add-Member -MemberType ScriptMethod -Name ToXml -Value { '<Event><EventData><Data Name="param1">0x000000d1 (0x1, 0x2, 0x3, 0x4)</Data></EventData></Event>' }
    function Get-KlayCrashReport {
        param([DateTime]$BootTime)
        return @{event = $fixtureEvent; code = '0x000000D1'; parameters = @('0x1','0x2','0x3','0x4'); dumpPath = $fixtureDump; source = 'isolated_fixture'}
    }
    function Get-KlayRecentEvents { return @() }

    Capture-CurrentCrash | Out-Null
    $localDump = Join-Path $localCrashPath 'memory.dmp'
    if (-not (Test-Path -LiteralPath $localDump)) { throw 'Offline capture did not preserve a local spool dump.' }
    $metadata = Get-Content -LiteralPath (Join-Path $localCrashPath 'crash.json') -Raw | ConvertFrom-Json
    if ($metadata.status -ne 'ready') { throw 'Offline capture did not finish.' }
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

    # A Windows writer still holding the dump must prevent capture until it closes.
    $bootKey = 'isolated-fixture-2'
    $localCrashPath = Join-Path $spoolRoot $bootKey
    $writer = [IO.File]::Open($fixtureDump, [IO.FileMode]::Open, [IO.FileAccess]::Write, [IO.FileShare]::ReadWrite)
    try { Capture-CurrentCrash | Out-Null } finally { $writer.Dispose() }
    $metadata = Get-Content -LiteralPath (Join-Path $localCrashPath 'crash.json') -Raw | ConvertFrom-Json
    if ($metadata.status -ne 'waiting_for_dump') { throw 'Dump with an active writer was published.' }
    Capture-CurrentCrash | Out-Null
    Publish-Spool
    if (-not (Test-Path -LiteralPath (Join-Path (Join-Path (Join-Path $ShareRoot 'crashes') $bootKey) 'ready.json'))) { throw 'Capture did not recover after the writer closed.' }
    Write-Output 'Offline spool, upload integrity, repeat publication and active-writer checks passed. No Windows bugcheck was generated.'
} finally {
    # Verify the absolute recursive-delete target is the unique test folder in TEMP.
    $resolved = [IO.Path]::GetFullPath($testRoot)
    $allowedPrefix = Join-Path $tempParent 'klay-export-test-'
    if (-not $resolved.StartsWith($allowedPrefix, [StringComparison]::OrdinalIgnoreCase)) { throw 'Unsafe test cleanup target.' }
    Remove-Item -LiteralPath $resolved -Recurse -Force
}
