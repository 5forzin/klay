[CmdletBinding()]
param([string]$InstallRoot = $PSScriptRoot)
$ErrorActionPreference = 'Stop'
$backup = Get-Content -LiteralPath (Join-Path $InstallRoot 'settings-before.json') -Raw | ConvertFrom-Json
$crashKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\CrashControl'
$memoryKey = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management'
Stop-ScheduledTask -TaskName 'Klay-Export' -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName 'Klay-Export' -Confirm:$false -ErrorAction SilentlyContinue
foreach ($property in $backup.crashControl.PSObject.Properties) {
    if ($property.Value.exists) {
        New-ItemProperty -LiteralPath $crashKey -Name $property.Name -Value $property.Value.value -PropertyType $property.Value.kind -Force | Out-Null
    } else { Remove-ItemProperty -LiteralPath $crashKey -Name $property.Name -ErrorAction SilentlyContinue }
}
Get-CimInstance Win32_ComputerSystem | Set-CimInstance -Property @{AutomaticManagedPagefile = [bool]$backup.automaticManagedPagefile}
New-ItemProperty -LiteralPath $memoryKey -Name 'PagingFiles' -Value @($backup.pagingFiles) -PropertyType MultiString -Force | Out-Null
Write-Output 'Previous crash/pagefile settings restored. Restart the VM once. Captured dumps and installation files were preserved.'
