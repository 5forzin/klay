$ErrorActionPreference = 'Stop'
$toolRoot = Split-Path -Parent $PSScriptRoot
$python = (Get-Command python.exe -ErrorAction Stop).Source
$tempParent = [IO.Path]::GetFullPath([IO.Path]::GetTempPath())
$testRoot = Join-Path $tempParent ('klay-host-test-' + [Guid]::NewGuid().ToString('N'))
$configPath = Join-Path $testRoot 'config.json'
$share = Join-Path $testRoot 'share'
New-Item -ItemType Directory -Path $share -Force | Out-Null
$monitorPid = $null
try {
    & $python -m venv --without-pip (Join-Path $testRoot 'venv')
    if ($LASTEXITCODE -ne 0) { throw 'Test venv creation failed.' }
    $venvPython = Join-Path $testRoot 'venv\Scripts\python.exe'
    & $venvPython (Join-Path $toolRoot 'klay.py') --config $configPath init --shared-root $share --data-root $testRoot | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'Test configuration failed.' }
    & (Join-Path $toolRoot 'scripts\Start-Klay.ps1') -Config $configPath -PythonPath $venvPython | Out-Null
    $statusPath = Join-Path $testRoot 'runtime\status.json'
    $before = Get-Content -LiteralPath $statusPath -Raw | ConvertFrom-Json
    $monitorPid = [int]$before.hostPid
    if ($before.latestCrashId -or $before.guestReachability -ne 'unknown') { throw 'An empty synthetic share was incorrectly reported as a crash or online guest.' }
    Start-Sleep -Seconds 6
    $after = Get-Content -LiteralPath $statusPath -Raw | ConvertFrom-Json
    if ($after.hostTimeUtc -le $before.hostTimeUtc -or $after.hostPid -ne $monitorPid) { throw 'Host status did not advance from the same monitor.' }
    $duplicateRejected = $false
    try { & (Join-Path $toolRoot 'scripts\Start-Klay.ps1') -Config $configPath -PythonPath $venvPython | Out-Null } catch { $duplicateRejected = $true }
    if (-not $duplicateRejected) { throw 'A second monitor was accepted for the same runtime.' }
    if ((Get-Content -LiteralPath $statusPath -Raw | ConvertFrom-Json).hostPid -ne $monitorPid) { throw 'The duplicate launch replaced the original monitor.' }
} finally {
    if (Test-Path -LiteralPath $configPath) { & (Join-Path $toolRoot 'scripts\Stop-Klay.ps1') -Config $configPath }
    if ($null -ne $monitorPid) {
        Start-Sleep -Milliseconds 500
        if (Get-Process -Id $monitorPid -ErrorAction SilentlyContinue) { throw 'The test monitor was not stopped; temporary evidence was preserved.' }
    }
    $resolved = [IO.Path]::GetFullPath($testRoot)
    $allowedPrefix = Join-Path $tempParent 'klay-host-test-'
    if (-not $resolved.StartsWith($allowedPrefix, [StringComparison]::OrdinalIgnoreCase)) { throw 'Unsafe test cleanup target.' }
    Remove-Item -LiteralPath $resolved -Recurse -Force
}
Write-Output 'Venv startup, advancing status, duplicate rejection and matching monitor shutdown passed.'
