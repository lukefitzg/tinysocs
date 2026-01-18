param(
  [Parameter(Mandatory)][string]$Path
)

$ErrorActionPreference = "Stop"

if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
  throw "File not found: $Path"
}

# Read lines for context/snippets
$lines = Get-Content -LiteralPath $Path -ErrorAction Stop

function Show-Context {
  param(
    [int]$Line,
    [int]$Radius = 3
  )
  if ($Line -le 0) { return }
  $start = [Math]::Max(1, $Line - $Radius)
  $end   = [Math]::Min($lines.Count, $Line + $Radius)

  for ($i = $start; $i -le $end; $i++) {
    $prefix = if ($i -eq $Line) { ">>" } else { "  " }
    $text = $lines[$i-1]
    Write-Host ("{0} {1,6}: {2}" -f $prefix, $i, $text)
  }
}

function Show-SelectStringMatches {
  param(
    [string[]]$Patterns
  )
  foreach ($p in $Patterns) {
    try {
      $m = Select-String -LiteralPath $Path -Pattern $p -SimpleMatch -ErrorAction SilentlyContinue
      if ($m) {
        Write-Host ""
        Write-Host ("--- Matches for pattern: {0} ---" -f $p)
        $m | ForEach-Object {
          Write-Host ("  {0}:{1}" -f $_.LineNumber, $_.Line.TrimEnd())
        }
      }
    } catch { }
  }
}

$tokens = $null
$errors = $null

$ast = [System.Management.Automation.Language.Parser]::ParseFile($Path, [ref]$tokens, [ref]$errors)

if ($errors -and $errors.Count) {

  Write-Host ""
  Write-Host ("PARSE ERRORS in: {0}" -f $Path)
  Write-Host ("PowerShell version: {0}" -f $PSVersionTable.PSVersion)
  Write-Host ""

  foreach ($e in $errors) {
    $msg = $e.Message
    $extentText = $null
    try { $extentText = $e.Extent.Text } catch { }

    $sl = 0; $sc = 0; $el = 0; $ec = 0
    try {
      $sl = [int]$e.Extent.StartLineNumber
      $sc = [int]$e.Extent.StartColumnNumber
      $el = [int]$e.Extent.EndLineNumber
      $ec = [int]$e.Extent.EndColumnNumber
    } catch { }

    Write-Host ("ERROR: {0}" -f $msg)

    if ($sl -gt 0) {
      Write-Host ("  at line {0}, col {1} (to line {2}, col {3})" -f $sl, $sc, $el, $ec)
      if ($extentText) { Write-Host ("  near: {0}" -f ($extentText -replace '\r?\n',' ')) }
      Show-Context -Line $sl -Radius 4
    } else {
      # When extents aren't usable, we still try to give you something actionable.
      if ($extentText) { Write-Host ("  near: {0}" -f ($extentText -replace '\r?\n',' ')) }
      Write-Host "  (No line/col info from parser for this error.)"
    }

    Write-Host ""
  }

  # Heuristic hints: common PS7-only operators that will explode under Windows PowerShell 5.1
  Write-Host "Heuristic scan for common PS7-only tokens (these will break under powershell.exe 5.1):"
  Show-SelectStringMatches -Patterns @("??","?.","?:")
  Write-Host ""

  throw "Parse errors in $Path (fix syntax / remove PS7-only constructs)."
}

# If we got here, we parsed successfully. Now check for duplicate function names.
$funcs = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true) |
  Select-Object Name,
    @{n="StartLine";e={$_.Extent.StartLineNumber}},
    @{n="EndLine";e={$_.Extent.EndLineNumber}}

$dupes = $funcs | Group-Object Name | Where-Object Count -gt 1
if ($dupes) {
  foreach ($d in $dupes) {
    Write-Error ("DUPLICATE FUNCTION: {0} (count={1})" -f $d.Name, $d.Count)
    $d.Group | Sort-Object StartLine | Format-Table -AutoSize | Out-String | Write-Error
  }
  throw "Duplicate functions found. Fix before building installer."
}

Write-Host "OK: parsed cleanly and no duplicate function names in $Path"