#Requires -RunAsAdministrator
<#
  goodix-fresh-session.ps1 — force a fresh Goodix driver session UNDER Windhawk.

  Why this exists: the 521D host runs ProcessPsk -> PskSet -> PskGet ONCE per
  host lifetime (~200ms after start, pre-login). Windhawk starts at user login,
  so it always misses the boot session. Restarting WbioSrvc while Windhawk is
  already up spawns a fresh observed host instead.

  Usage (admin PowerShell):
    .\goodix-fresh-session.ps1            # wait for Windhawk, restart stack
    .\goodix-fresh-session.ps1 -NoWait    # skip the Windhawk check

  After it reports a NEW host pid:
    1. Confirm Windhawk log shows BOTH hooked-internal lines for that pid.
    2. Exercise Hello once.
    3. Expect C:\goodix-capture\psk32.bin at exactly 32 bytes.
#>
param([switch]$NoWait)

$ErrorActionPreference = 'Stop'

function Get-WudfPids {
  (Get-CimInstance Win32_Process -Filter "Name='WUDFHost.exe'" |
    Select-Object -ExpandProperty ProcessId)
}

if (-not $NoWait) {
  $deadline = (Get-Date).AddSeconds(120)
  while (-not (Get-Process -Name Windhawk -ErrorAction SilentlyContinue)) {
    if ((Get-Date) -gt $deadline) {
      Write-Error 'Windhawk not running after 120s; start it first, then re-run.'
    }
    Start-Sleep -Seconds 2
  }
  Write-Output 'Windhawk running.'
}

$before = @(Get-WudfPids)
Write-Output ("Existing WUDFHost pids: {0}" -f ($before -join ', '))

Write-Output 'Restarting WbioSrvc...'
Restart-Service -Name WbioSrvc -Force
Start-Sleep -Seconds 5

$after = @(Get-WudfPids)
$new = @($after | Where-Object { $before -notcontains $_ })
if (-not $new) {
  Write-Output 'Service restart did not cycle the UMDF host; cycling the Goodix device instead...'
  $dev = Get-PnpDevice -Class Biometric -ErrorAction SilentlyContinue |
    Where-Object { $_.InstanceId -match 'VID_27C6' } |
    Select-Object -First 1
  if (-not $dev) {
    Write-Error 'No VID_27C6 biometric device found. Use Device Manager manually: Disable, wait 5s, Enable.'
  }
  Write-Output ("Cycling device: {0} [{1}]" -f $dev.FriendlyName, $dev.InstanceId)
  Disable-PnpDevice -InstanceId $dev.InstanceId -Confirm:$false
  Start-Sleep -Seconds 5
  Enable-PnpDevice -InstanceId $dev.InstanceId -Confirm:$false
  Start-Sleep -Seconds 8
  $after = @(Get-WudfPids)
  $new = @($after | Where-Object { $before -notcontains $_ })
}
Write-Output ("Current WUDFHost pids: {0}" -f ($after -join ', '))
if ($new) {
  Write-Output ("NEW host pid(s): {0}" -f ($new -join ', '))
  Write-Output 'Next: confirm BOTH hooked-internal lines for the new pid in the Windhawk log, Hello once, then check C:\goodix-capture\psk32.bin (32 bytes).'
} else {
  Write-Output 'WARNING: no new WUDFHost spawned; the old session persists and PskGet will NOT refire.'
}
