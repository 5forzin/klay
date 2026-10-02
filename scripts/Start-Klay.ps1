[CmdletBinding()]
param(
    [switch]$InstallStartup,
    [string]$Config = (Join-Path $env:LOCALAPPDATA 'Klay\config.json'),
    [string]$PythonPath
)
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
if (-not (Test-Path -LiteralPath $Config)) { throw 'Run klay init first, or pass -Config with your configuration path.' }
$Config = (Resolve-Path -LiteralPath $Config).Path
if (-not $PythonPath) {
    $PythonPath = Join-Path $projectRoot '.venv\Scripts\python.exe'
    if (-not (Test-Path -LiteralPath $PythonPath)) { $PythonPath = (Get-Command python.exe -ErrorAction Stop).Source }
}
$PythonPath = (Resolve-Path -LiteralPath $PythonPath).Path
$pythonw = Join-Path (Split-Path -Parent $PythonPath) 'pythonw.exe'
if (-not (Test-Path -LiteralPath $pythonw)) { throw 'pythonw.exe was not found next to the selected Python.' }
$script = Join-Path $projectRoot 'klay.py'
$arguments = '"' + $script + '" --config "' + $Config + '" watch'
if ($InstallStartup) {
    $startup = [Environment]::GetFolderPath('Startup')
    $shell = New-Object -ComObject WScript.Shell
    $shortcut = $shell.CreateShortcut((Join-Path $startup 'klay.lnk'))
    $shortcut.TargetPath = $pythonw
    $shortcut.Arguments = $arguments
    $shortcut.WorkingDirectory = $projectRoot
    $shortcut.WindowStyle = 7
    $shortcut.Description = 'Kernel Relay: local VMware kernel crash collection and analysis.'
    $shortcut.Save()
}
$started = [DateTime]::UtcNow
$process = Start-Process -FilePath $pythonw -ArgumentList $arguments -WorkingDirectory $projectRoot -WindowStyle Hidden -PassThru
$settings = Get-Content -LiteralPath $Config -Raw | ConvertFrom-Json
$statusPath = Join-Path $settings.runtime_root 'status.json'
for ($attempt = 0; $attempt -lt 10; $attempt++) {
    Start-Sleep -Milliseconds 500
    if (Test-Path -LiteralPath $statusPath) {
        $state = Get-Content -LiteralPath $statusPath -Raw | ConvertFrom-Json
        # A Windows venv redirector can launch the actual monitor as a child.
        $launchedMonitor = $state.hostPid -eq $process.Id
        if (-not $launchedMonitor) {
            $candidate = Get-CimInstance Win32_Process -Filter ("ProcessId=" + [int]$state.hostPid)
            $launchedMonitor = $null -ne $candidate -and $candidate.ParentProcessId -eq $process.Id -and $candidate.CommandLine -and $candidate.CommandLine.Contains($script) -and $candidate.CommandLine.Contains($Config)
        }
        if ($launchedMonitor -and [DateTime]::Parse($state.hostTimeUtc).ToUniversalTime() -ge $started.AddSeconds(-1)) {
            $state | ConvertTo-Json -Depth 15
            return
        }
    }
    if ($process.HasExited) { break }
}
throw ('No fresh status from the launched monitor. Check ' + (Join-Path $settings.runtime_root 'host.log') + ' and whether a monitor is already running.')
