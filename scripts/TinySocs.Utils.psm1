# scripts/TinySocs.Utils.psm1
Set-StrictMode -Version Latest

function New-TinySocsHmacHeaders {
  [CmdletBinding()]
  param([Parameter(Mandatory)][string]$Secret)

  $ts  = [int][DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
  $h   = [System.Security.Cryptography.HMACSHA256]::new([Text.Encoding]::UTF8.GetBytes($Secret))
  $sig = -join ($h.ComputeHash([Text.Encoding]::UTF8.GetBytes("$ts")) | ForEach-Object { $_.ToString('x2') })
  @{ 'X-TinySOCS-Timestamp' = "$ts"; 'X-TinySOCS-Signature' = $sig }
}

Export-ModuleMember -Function New-TinySocsHmacHeaders