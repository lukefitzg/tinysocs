# os_license_shim.ps1 — listens HTTP on 127.0.0.1:9202
# If request is GET /_license -> returns harmless ES-style JSON
# Otherwise proxies to https://127.0.0.1:9201 (OpenSearch), skipping TLS verify

Add-Type -AssemblyName System.Net.Http
$listener = New-Object System.Net.HttpListener
$prefix = "http://127.0.0.1:9202/"
$listener.Prefixes.Add($prefix)
$listener.Start()
Write-Host "[shim] listening on $prefix, proxying to https://127.0.0.1:9201" -ForegroundColor Cyan

$handler = New-Object System.Net.Http.HttpClientHandler
$handler.ServerCertificateCustomValidationCallback = { param($s,$c,$ch,$e) $true }  # ignore self-signed
$client = [System.Net.Http.HttpClient]::new($handler)
$client.Timeout = [TimeSpan]::FromSeconds(30)

while ($true) {
  $ctx = $listener.GetContext()
  $req = $ctx.Request
  $res = $ctx.Response

  try {
    if ($req.HttpMethod -eq 'GET' -and $req.RawUrl -match '^/_license(\?.*)?$') {
      $json = '{"license":{"status":"active","uid":"shim","type":"basic","issue_date":"2020-01-01","expiry_date":"2099-01-01"}}'
      $bytes = [Text.Encoding]::UTF8.GetBytes($json)
      $res.StatusCode = 200
      $res.ContentType = "application/json"
      $res.OutputStream.Write($bytes,0,$bytes.Length)
      $res.Close()
      continue
    }

    # Build upstream request
    $uri = "https://127.0.0.1:9201" + $req.RawUrl
    $method = New-Object System.Net.Http.HttpMethod($req.HttpMethod)
    $up = New-Object System.Net.Http.HttpRequestMessage($method, $uri)

    # Copy headers (skip Host/Content-Length/Transfer-Encoding)
    foreach ($hName in $req.Headers.AllKeys) {
      if ($hName -in @('Host','Content-Length','Transfer-Encoding')) { continue }
      $null = $up.Headers.TryAddWithoutValidation($hName, $req.Headers[$hName])
    }

    # Copy body if present
    if ($req.HasEntityBody) {
      $ms = New-Object System.IO.MemoryStream
      $req.InputStream.CopyTo($ms)
      $ms.Position = 0
      $content = New-Object System.Net.Http.ByteArrayContent($ms.ToArray())
      if ($req.ContentType) { $content.Headers.ContentType = $req.ContentType }
      $up.Content = $content
    }

    $resp = $client.Send($up)
    $res.StatusCode = [int]$resp.StatusCode
    foreach ($h in $resp.Headers) {
      foreach ($v in $h.Value) { $res.Headers.Add($h.Key, $v) }
    }
    if ($resp.Content) {
      $res.ContentType = $resp.Content.Headers.ContentType.ToString()
      $bytes = $resp.Content.ReadAsByteArrayAsync().Result
      $res.OutputStream.Write($bytes,0,$bytes.Length)
    }
  }
  catch {
    $msg = ('{"error":"shim failure","detail":"{0}"}' -f ($_.Exception.Message -replace '"','\"'))
    $b = [Text.Encoding]::UTF8.GetBytes($msg)
    $res.StatusCode = 502
    $res.ContentType = "application/json"
    $res.OutputStream.Write($b,0,$b.Length)
  }
  finally {
    try { $res.Close() } catch {}
  }
}