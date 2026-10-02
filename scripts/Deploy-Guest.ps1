[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Vmx,
    [Parameter(Mandatory = $true)][PSCredential]$Credential,
    [Parameter(Mandatory = $true)][string]$GuestShareRoot,
    [Security.SecureString]$VmPassword,
    [string]$Config = (Join-Path $env:LOCALAPPDATA 'Klay\config.json'),
    [string]$Vmrun = 'C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe'
)
$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$settings = Get-Content -LiteralPath $Config -Raw | ConvertFrom-Json
if (-not (Test-Path -LiteralPath $Vmx -PathType Leaf)) { throw 'The VMX file does not exist.' }
if (-not (Test-Path -LiteralPath $Vmrun -PathType Leaf)) { throw 'vmrun.exe does not exist.' }
if (-not (Test-Path -LiteralPath $settings.shared_root -PathType Container)) { throw 'Create the host shared directory and enable it in VMware first.' }
if (-not $GuestShareRoot.StartsWith('\\') -or $GuestShareRoot.Contains('"')) { throw 'GuestShareRoot must be a VMware shared-folder UNC path.' }
$setup = Join-Path $settings.shared_root 'setup'
New-Item -ItemType Directory -Path $setup -Force | Out-Null
foreach ($file in @('Klay.Common.ps1', 'Export-Crashes.ps1', 'Install-Guest.ps1', 'Restore-Guest.ps1')) {
    Copy-Item -LiteralPath (Join-Path (Join-Path $projectRoot 'guest') $file) -Destination (Join-Path $setup $file) -Force
}
$vmArguments = @('-T', 'ws')
if ($null -ne $VmPassword) {
    $pointer = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($VmPassword)
    try { $vmArguments += @('-vp', [Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)) } finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer) }
}
# vmrun requires transient command-line credentials; never persist or print them.
$vmArguments += @('-gu', $Credential.UserName, '-gp', $Credential.GetNetworkCredential().Password)
$guestInstaller = $GuestShareRoot + '\setup\Install-Guest.ps1'
$vmArguments += @('runProgramInGuest', $Vmx, 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe', '-NoLogo', '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $guestInstaller, '-ShareRoot', $GuestShareRoot)
$started = [DateTime]::UtcNow
try {
    & $Vmrun @vmArguments
    if ($LASTEXITCODE -ne 0) { throw 'vmrun could not execute the guest installer.' }
    $installation = Get-Content -LiteralPath (Join-Path $settings.shared_root 'installation.json') -Raw | ConvertFrom-Json
    if ([DateTime]::Parse($installation.installedAtUtc).ToUniversalTime() -lt $started.AddSeconds(-5)) { throw 'No fresh installation receipt. Check guest elevation and shared-folder access.' }
    $installation | ConvertTo-Json -Depth 8
} finally { $vmArguments = $null }
