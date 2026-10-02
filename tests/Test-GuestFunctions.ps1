$ErrorActionPreference = 'Stop'
. (Join-Path (Split-Path -Parent $PSScriptRoot) 'guest\Klay.Common.ps1')
$result = Get-KlayBugCheck '0x000000d1 (0xfffff80200112233, 0x0000000000000002, 0x0000000000000000, 0xfffff80244556677)'
if ($result.code -ne '0x000000D1' -or $result.parameters.Count -ne 4) { throw 'Bugcheck parsing failed.' }
if ($null -ne (Get-KlayBugCheck 'The system rebooted without cleanly shutting down.')) { throw 'Unexpected reboot was incorrectly treated as a bugcheck.' }
$event = New-Object PSObject
$event | Add-Member -MemberType ScriptMethod -Name ToXml -Value { '<Event><EventData><Binary>00</Binary></EventData></Event>' }
if ((Get-KlayEventData $event).Count -ne 0) { throw 'Binary-only event parsing failed.' }
$parseErrors = @()
foreach ($file in Get-ChildItem -LiteralPath (Split-Path -Parent $PSScriptRoot) -Filter '*.ps1' -Recurse) {
    $tokens = $null; $errors = $null
    [Management.Automation.Language.Parser]::ParseFile($file.FullName, [ref]$tokens, [ref]$errors) | Out-Null
    $parseErrors += @($errors)
}
if ($parseErrors.Count -gt 0) { $parseErrors | Format-List; throw 'PowerShell source parse failed.' }
Write-Output 'Guest event parsing and PowerShell syntax checks passed.'
