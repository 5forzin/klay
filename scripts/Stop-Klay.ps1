[CmdletBinding()]
param(
    [switch]$RemoveStartup,
    [string]$Config = (Join-Path $env:LOCALAPPDATA 'Klay\config.json')
)
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$settings = Get-Content -LiteralPath $Config -Raw | ConvertFrom-Json
$pidFile = Join-Path $settings.runtime_root 'monitor.json'
$expectedScript = Join-Path $projectRoot 'klay.py'
if (Test-Path -LiteralPath $pidFile) {
    $state = Get-Content -LiteralPath $pidFile -Raw | ConvertFrom-Json
    $process = Get-CimInstance Win32_Process -Filter ("ProcessId=" + [int]$state.pid)
    if ($null -ne $process -and $process.CommandLine -and $process.CommandLine.Contains($expectedScript) -and $process.CommandLine -match '\bwatch\b') {
        # End only the matching monitor and its direct KD children.
        Get-CimInstance Win32_Process -Filter ("ParentProcessId=" + [int]$state.pid) | Where-Object { $_.Name -eq 'kd.exe' } | ForEach-Object { Stop-Process -Id $_.ProcessId -ErrorAction SilentlyContinue }
        Stop-Process -Id ([int]$state.pid) -ErrorAction SilentlyContinue
        Write-Output 'klay host monitor stopped.'
    }
}
if ($RemoveStartup) {
    $shortcutPath = Join-Path ([Environment]::GetFolderPath('Startup')) 'klay.lnk'
    if (Test-Path -LiteralPath $shortcutPath) {
        $shell = New-Object -ComObject WScript.Shell
        $shortcut = $shell.CreateShortcut($shortcutPath)
        if ($shortcut.Arguments.Contains($expectedScript)) { Remove-Item -LiteralPath $shortcutPath -Force }
    }
}
