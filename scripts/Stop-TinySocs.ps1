Set-StrictMode -Version Latest
$ErrorActionPreference = 'SilentlyContinue'

$RepoRoot = (Resolve-Path "$PSScriptRoot\..").Path
$RunDir  = Join-Path $RepoRoot ".run"

Get-ChildItem $RunDir -Filter *.pid | ForEach-Object {
  $pid = Get-Content $_.FullName | Select-Object -First 1
  if ($pid) {
    try {
      $p = Get-Process -Id $pid -ErrorAction Stop
      Stop-Process -Id $pid -Force -ErrorAction SilentlyContinue
      Write-Host "[stop] killed PID $pid ($($_.BaseName))"
    } catch {}
  }
  Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue
}