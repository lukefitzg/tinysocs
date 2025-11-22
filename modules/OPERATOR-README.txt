TinySocs Quickstart
Install: Run TinySocs-Setup.exe (admin). Files -> C:\Program Files\TinySocs; data -> %ProgramData%\TinySocs.
Pair:
  Import-Module "C:\Program Files\TinySocs\modules\TinySocs.Installer.psm1"
  Pair-TinySocs -Role Node   -SharedSecret "<secret>" -NodePort 8081 -SiemUrl "https://localhost:9201"
  Pair-TinySocs -Role Master -Nodes "http://NODE:8081" -SharedSecret "<secret>" -AnchorsRetentionDays 45 -HeartbeatMinutes 15
Tasks: Heartbeat (15m), Verify (03:10), Prune (03:15), Rotate (hourly)