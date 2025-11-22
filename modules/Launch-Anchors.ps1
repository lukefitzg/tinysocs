param([switch]$Ensure,[switch]$Prune,[int]$RetentionDays=45)
$exe="C:\Program Files\TinySocs\bin\TinySocsAnchors.exe"
if($Ensure){ & $exe --ensure; exit } 
if($Prune){  & $exe --prune --retention-days $RetentionDays; exit }
& $exe --help
