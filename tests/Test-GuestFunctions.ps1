$ErrorActionPreference = 'Stop'
. (Join-Path (Split-Path -Parent $PSScriptRoot) 'guest\Klay.Common.ps1')
$result = Get-KlayBugCheck '0x000000d1 (0xfffff80200112233, 0x0000000000000002, 0x0000000000000000, 0xfffff80244556677)'
if ($result.code -ne '0x000000D1' -or $result.parameters.Count -ne 4) { throw 'Bugcheck parsing failed.' }
if ($null -ne (Get-KlayBugCheck 'The system rebooted without cleanly shutting down.')) { throw 'Unexpected reboot was incorrectly treated as a bugcheck.' }
$event = New-Object PSObject
$event | Add-Member -MemberType ScriptMethod -Name ToXml -Value { '<Event><EventData><Binary>00</Binary></EventData></Event>' }
if ((Get-KlayEventData $event).Count -ne 0) { throw 'Binary-only event parsing failed.' }
foreach ($path in @('C:\ProgramData\Klay', 'c:\programdata\Klay-VM2', 'C:/ProgramData/Klay-VM2/', 'C:\ProgramData\Unused\..\Klay-VM2')) {
    $resolved = Resolve-KlayInstallRoot $path 'C:\ProgramData'
    if (-not [string]::Equals([IO.Path]::GetDirectoryName($resolved), 'C:\ProgramData', [StringComparison]::OrdinalIgnoreCase)) { throw 'Canonical direct-child installation path was rejected or resolved incorrectly.' }
}
foreach ($path in @('Klay', 'C:Klay', '\ProgramData\Klay', '\\server\ProgramData\Klay', '\\?\C:\ProgramData\Klay', 'C:\ProgramData', 'C:\ProgramData\', 'C:\ProgramData\.', 'C:\ProgramData\..', 'C:\Users\someone\Temp\Klay', 'C:\ProgramData\Other\Klay', 'C:\ProgramData\Klay\Child', 'C:\ProgramData\Klay.', 'C:\ProgramData\.. ', 'C:\ProgramData\Klay:stream', 'C:\ProgramData\NUL')) {
    $rejected = $false
    try { Resolve-KlayInstallRoot $path 'C:\ProgramData' | Out-Null } catch { $rejected = $true }
    if (-not $rejected) { throw "Unsafe guest installation path was accepted: $path" }
}
$fixtureBoot = [DateTime]::UtcNow
$bootEvents = @()
foreach ($definition in @(@{recordId = 102; seconds = -6}, @{recordId = 101; seconds = -7}, @{recordId = 90; seconds = -3600})) {
    $bootEvent = [pscustomobject]@{RecordId = $definition.recordId; TimeCreated = $fixtureBoot.AddSeconds($definition.seconds + 1); ProviderName = 'Microsoft-Windows-Kernel-General'; Start = $fixtureBoot.AddSeconds($definition.seconds).ToString('o')}
    $bootEvent | Add-Member -MemberType ScriptMethod -Name ToXml -Value { '<Event><EventData><Data Name="StartTime">' + $this.Start + '</Data></EventData></Event>' }
    $bootEvents += $bootEvent
}
function Get-WinEvent { param($FilterHashtable, $MaxEvents, $ErrorAction); return $bootEvents }
$previous = Get-KlayPreviousBoot $fixtureBoot
if ($null -eq $previous -or $previous.eventRecordId -ne 101 -or $previous.currentBootEventRecordId -ne 102 -or $previous.timeUtc -ne $fixtureBoot.AddSeconds(-7).ToString('o')) { throw 'A short preceding boot was skipped or the current boot was mistaken for the previous one.' }
if ($null -ne (Get-KlayPreviousBoot $fixtureBoot.AddMinutes(3))) { throw 'An ambiguous current boot was accepted.' }
$powerEvent = [pscustomobject]@{RecordId = 103; TimeCreated = $fixtureBoot.AddSeconds(-6); ProviderName = 'Microsoft-Windows-Kernel-Power'}
$powerEvent | Add-Member -MemberType ScriptMethod -Name ToXml -Value { '<Event><EventData><Data Name="BugcheckCode">209</Data><Data Name="BugcheckParameter1">0x1</Data><Data Name="BugcheckParameter2">0x2</Data><Data Name="BugcheckParameter3">0x3</Data><Data Name="BugcheckParameter4">0x4</Data></EventData></Event>' }
function Get-WinEvent { param($FilterHashtable, $MaxEvents, $ErrorAction); if ($FilterHashtable.ProviderName -eq 'Microsoft-Windows-Kernel-Power') { return $powerEvent }; return $null }
$report = Get-KlayCrashReport $fixtureBoot $previous
if ($null -eq $report -or $report.code -ne '0x000000D1') { throw 'A current-boot Kernel-Power report earlier than CIM minus five seconds was missed.' }
$powerEvent.RecordId = 100
if ($null -ne (Get-KlayCrashReport $fixtureBoot $previous)) { throw 'A preceding boot report inside the time tolerance was treated as a new crash.' }
Remove-Item -LiteralPath Function:\Get-WinEvent
$original = New-Object Security.AccessControl.DirectorySecurity
$original.SetOwner((New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544')))
$original.SetAccessRuleProtection($true, $false)
$original.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier('S-1-1-0')), [Security.AccessControl.FileSystemRights]::Modify, [Security.AccessControl.InheritanceFlags]'ObjectInherit,ContainerInherit', [Security.AccessControl.PropagationFlags]::None, [Security.AccessControl.AccessControlType]::Allow)))
if (Test-KlayProtectedSecurity $original -Directory) { throw 'Unprivileged explicit modify ACL was accepted.' }
$protectedDirectory = New-KlayProtectedSecurity -Directory
$protectedFile = New-KlayProtectedSecurity
if (-not (Test-KlayProtectedSecurity $protectedDirectory -Directory) -or -not (Test-KlayProtectedSecurity $protectedFile)) { throw 'Exclusive SYSTEM/administrators ACL validation failed.' }
$protectedFile.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule((New-Object Security.Principal.SecurityIdentifier('S-1-1-0')), [Security.AccessControl.FileSystemRights]::Modify, [Security.AccessControl.AccessControlType]::Allow)))
if (Test-KlayProtectedSecurity $protectedFile) { throw 'Extra explicit script permissions were accepted.' }
$parseErrors = @()
foreach ($file in Get-ChildItem -LiteralPath (Split-Path -Parent $PSScriptRoot) -Filter '*.ps1' -Recurse) {
    $tokens = $null; $errors = $null
    [Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tokens, [ref]$errors) | Out-Null
    $parseErrors += @($errors)
}
if ($parseErrors.Count -gt 0) { $parseErrors | Format-List; throw 'PowerShell source parse failed.' }
Write-Output 'Guest event parsing, exclusive installation ACLs and PowerShell syntax checks passed. No machine ACL was changed.'
