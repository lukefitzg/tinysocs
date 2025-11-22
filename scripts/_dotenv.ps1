function Import-DotEnv {
  param([string]$Path)
  if (-not (Test-Path $Path)) { return }
  Get-Content $Path | ForEach-Object {
    $line = $_.Trim()
    if ($line -and -not $line.StartsWith('#') -and $line.Contains('=')) {
      $k,$v = $line.Split('=',2)
      $k = $k.Trim(); $v = $v.Trim().Trim("'`"").Trim()
      if ($k) { $env:$k = $v }
    }
  }
}