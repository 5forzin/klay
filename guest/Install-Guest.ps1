[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$ShareRoot,
    [string]$InstallRoot = (Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::CommonApplicationData)) 'Klay')
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Klay.Common.ps1')
$InstallRoot = Resolve-KlayInstallRoot $InstallRoot
$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Run this installer in an elevated PowerShell inside the VM.' }
if (-not (Test-Path -LiteralPath $ShareRoot)) { throw 'VMware shared folder is unavailable. Enable VMware Tools / Shared Folders first.' }
New-Item -ItemType Directory -Path $InstallRoot -Force | Out-Null
$existingTask = Get-ScheduledTask -TaskName 'Klay-Export' -ErrorAction SilentlyContinue
if ($null -ne $existingTask) {
    Disable-ScheduledTask -TaskName 'Klay-Export' | Out-Null
    Stop-ScheduledTask -TaskName 'Klay-Export'; Start-Sleep -Seconds 2
}
Protect-KlayInstallation $InstallRoot
$crashKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl'
$memoryKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management'
$backupFile = Join-Path $InstallRoot 'settings-before.json'
if (-not (Test-Path -LiteralPath $backupFile)) {
    $key = Get-Item -LiteralPath $crashKey
    $backup = @{schema = 1; savedAtUtc = [DateTime]::UtcNow.ToString('o'); crashControl = @{}; automaticManagedPagefile = (Get-CimInstance Win32_ComputerSystem).AutomaticManagedPagefile; pagingFiles = @((Get-ItemProperty -LiteralPath $memoryKey).PagingFiles)}
    foreach ($name in @('CrashDumpEnabled', 'AutoReboot', 'LogEvent', 'Overwrite', 'AlwaysKeepMemoryDump', 'DumpFile', 'MinidumpDir')) {
        if ($key.GetValueNames() -contains $name) {
            $backup.crashControl[$name] = @{exists = $true; kind = $key.GetValueKind($name).ToString(); value = $key.GetValue($name, $null, [Microsoft.Win32.RegistryValueOptions]::DoNotExpandEnvironmentNames)}
        } else { $backup.crashControl[$name] = @{exists = $false} }
    }
    Write-KlayJson $backupFile $backup
}
foreach ($file in @('Klay.Common.ps1', 'Export-Crashes.ps1', 'Restore-Guest.ps1')) {
    $source = Join-Path $PSScriptRoot $file
    $target = Join-Path $InstallRoot $file
    if ([IO.Path]::GetFullPath($source) -ne [IO.Path]::GetFullPath($target)) { Copy-Item -LiteralPath $source -Destination $target -Force }
}
# Verify the copied code too, including explicit permissions on pre-existing files.
Protect-KlayInstallation $InstallRoot
foreach ($entry in @(@('CrashDumpEnabled', 7), @('AutoReboot', 1), @('LogEvent', 1), @('Overwrite', 1), @('AlwaysKeepMemoryDump', 1))) {
    New-ItemProperty -LiteralPath $crashKey -Name $entry[0] -Value $entry[1] -PropertyType DWord -Force | Out-Null
}
New-ItemProperty -LiteralPath $crashKey -Name 'DumpFile' -Value '%SystemRoot%\MEMORY.DMP' -PropertyType ExpandString -Force | Out-Null
New-ItemProperty -LiteralPath $crashKey -Name 'MinidumpDir' -Value '%SystemRoot%\Minidump' -PropertyType ExpandString -Force | Out-Null
Get-CimInstance Win32_ComputerSystem | Set-CimInstance -Property @{AutomaticManagedPagefile = $true}
$pagingFiles = @((Get-ItemProperty -LiteralPath $memoryKey).PagingFiles)
if ($pagingFiles.Count -eq 0 -or [string]::IsNullOrWhiteSpace(($pagingFiles -join ''))) {
    New-ItemProperty -LiteralPath $memoryKey -Name 'PagingFiles' -Value @($env:SystemDrive + '\pagefile.sys 0 0') -PropertyType MultiString -Force | Out-Null
}
$powershell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$exportScript = Join-Path $InstallRoot 'Export-Crashes.ps1'
$arguments = '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $exportScript + '" -ShareRoot "' + $ShareRoot + '"'
$action = New-ScheduledTaskAction -Execute $powershell -Argument $arguments
$trigger = New-ScheduledTaskTrigger -AtStartup
$taskPrincipal = New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest
$settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -MultipleInstances IgnoreNew -ExecutionTimeLimit ([TimeSpan]::Zero) -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1)
Register-ScheduledTask -TaskName 'Klay-Export' -Action $action -Trigger $trigger -Principal $taskPrincipal -Settings $settings -Description 'Exports local Windows kernel crash reports to the VMware host after reboot; no credentials stored.' -Force | Out-Null
Start-ScheduledTask -TaskName 'Klay-Export'
Write-KlayJson (Join-Path $ShareRoot 'installation.json') @{
    schema = 1; installedAtUtc = [DateTime]::UtcNow.ToString('o'); computer = $env:COMPUTERNAME
    installRoot = $InstallRoot; shareRoot = $ShareRoot; task = 'Klay-Export'
    rebootRequired = $true; reason = 'Crash dump and pagefile settings require a Windows restart.'
    configuration = @{CrashDumpEnabled = 7; AutoReboot = 1; AutomaticManagedPagefile = $true}
    backup = $backupFile
}
Write-Output 'Installed Klay-Export. Restart the VM once to activate pagefile/dump changes. No restart was requested by this installer.'
