# scripts/Nightly-VerifyLedger.ps1
param(
  [string]$RepoRoot = (Resolve-Path "$PSScriptRoot\..").Path,
  [string]$OutDir   = (Join-Path $PSScriptRoot "..\logs")
)

$ErrorActionPreference = 'Stop'
Set-Location $RepoRoot
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

function Get-PythonExe {
  param([string]$Root)
  $venvPy = Join-Path $Root ".venv\Scripts\python.exe"
  if (Test-Path $venvPy) { return $venvPy } else { return "python" }
}

$py      = Get-PythonExe -Root $RepoRoot
$stamp   = Get-Date -Format "yyyyMMdd-HHmmss"
$rawFile = Join-Path $OutDir "verify_ledger-$stamp.raw.txt"
$jsonFile= Join-Path $OutDir "verify_ledger-$stamp.json"

$env:PYTHONUNBUFFERED = "1"
$raw = & $py -m tinysocs.orchestrator.check_ledger --verify 2>&1 | Out-String
$raw | Out-File -Encoding UTF8 -FilePath $rawFile
Write-Host "[verify] wrote $rawFile"

function Get-BalancedJson([string]$text){
  $bestStart = -1; $bestEnd = -1
  $stack = New-Object System.Collections.Stack
  $inStr = $false; $esc = $false; $startIdx = -1
  for($i=0;$i -lt $text.Length;$i++){
    $c = $text[$i]
    if($inStr){
      if($esc){ $esc=$false; continue }
      if($c -eq '\'){ $esc=$true; continue }
      if($c -eq '"'){ $inStr=$false; continue }
      continue
    }
    switch($c){
      '"' { $inStr=$true }
      '{' { if($stack.Count -eq 0){ $startIdx = $i }; $stack.Push('}') }
      '[' { if($stack.Count -eq 0){ $startIdx = $i }; $stack.Push(']') }
      '}' { if($stack.Count -gt 0 -and $stack.Peek() -eq '}'){ [void]$stack.Pop(); if($stack.Count -eq 0){ $bestStart=$startIdx; $bestEnd=$i } } }
      ']' { if($stack.Count -gt 0 -and $stack.Peek() -eq ']'){ [void]$stack.Pop(); if($stack.Count -eq 0){ $bestStart=$startIdx; $bestEnd=$i } } }
    }
  }
  if($bestStart -ge 0 -and $bestEnd -gt $bestStart){ return $text.Substring($bestStart, $bestEnd-$bestStart+1) }
  return $null
}

try {
  $block = Get-BalancedJson $raw
  if (-not $block) { throw "No JSON block found in output." }
  $block | Out-File -Encoding UTF8 -FilePath $jsonFile
  Write-Host "[verify] wrote $jsonFile"

  $data = $block | ConvertFrom-Json -ErrorAction Stop
  if ($data -isnot [System.Collections.IEnumerable]) { $data = @($data) }

  $bad = @($data | Where-Object { -not $_.ok })
  if ($bad.Count -gt 0) {
    $list = ($bad | ForEach-Object { "$($_.node_id):$($_.reason)" }) -join ', '
    Write-Warning ("Ledger check found issues: " + $list)
    exit 1
  } else {
    Write-Host "Ledger OK for all nodes."
  }
} catch {
  Write-Warning ("Could not parse JSON output; see $rawFile :: " + $_.Exception.Message)
  exit 2
}