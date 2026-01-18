
  [CmdletBinding()]
  param(
    [string]$OpenSearchPort = "9201"
  )

  $caPem = Join-Path (Join-Path $env:ProgramData "TinySocs\OpenSearch\config\certs") "ca.pem"

  # Canonical defaults: localhost avoids hostname/IP mismatch with certs lacking 127.0.0.1 SAN.
  return [ordered]@{
    url            = "https://localhost:$OpenSearchPort"
    user           = "admin"
    pass           = "secret"
    sslVerify      = $true
    ssl_verify     = $true
    caBundlePath   = $caPem
    ca_bundle_path = $caPem
  }

