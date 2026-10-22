# Import-PuttySessions.ps1
# Reads PuTTY sessions straight from the registry and writes a ssloth vault
# file you can import via Settings -> Vault -> Import in the ssloth UI.
#
#   powershell -ExecutionPolicy Bypass -File tools\Import-PuttySessions.ps1 -Out ssloth-import.json
#
# Passwords/private keys are NOT in the registry (PuTTY stores keys as .ppk
# paths) — imported hosts default to "ask" auth. Convert .ppk files with:
#   puttygen key.ppk -O private-openssh -o key
# then paste the key into the host or a credential in ssloth.

param(
  [string]$Out = "ssloth-import.json",
  [string]$BaseKey = "HKCU:\Software\SimonTatham\PuTTY\Sessions"
)

$hosts = @()
$skipped = 0

if (-not (Test-Path $BaseKey)) {
  Write-Error "No PuTTY sessions found at $BaseKey"
  exit 1
}

foreach ($key in Get-ChildItem $BaseKey) {
  $p = Get-ItemProperty $key.PSPath
  $proto = if ($p.Protocol) { $p.Protocol.ToLower() } else { "ssh" }
  if ($proto -ne "ssh") {
    Write-Warning "skipping '$($key.PSChildName)' — protocol '$proto' isn't SSH"
    $skipped++
    continue
  }

  $name = [uri]::UnescapeDataString($key.PSChildName)
  $folder = ""
  if ($name.Contains("/")) {
    $idx = $name.LastIndexOf("/")
    $folder = $name.Substring(0, $idx)
    $name = $name.Substring($idx + 1)
  }

  $notes = @()
  if ($p.PublicKeyFile) { $notes += "PuTTY key file: $($p.PublicKeyFile) (convert: puttygen x.ppk -O private-openssh -o key)" }
  if ($p.ProxyMethod -and [int]$p.ProxyMethod -gt 0 -and $p.ProxyHost) {
    $notes += "PuTTY proxy: method $($p.ProxyMethod) host $($p.ProxyHost) — recreate as a jump host/tunnel in ssloth"
  }

  $hosts += [ordered]@{
    name             = $name
    hostname         = "$($p.HostName)"
    port             = if ($p.PortNumber) { [int]$p.PortNumber } else { 22 }
    username         = "$($p.UserName)"
    auth_type        = "ask"
    folder           = $folder
    region           = ""
    tags             = ""
    pinned           = 0
    record           = 0
    shared           = 0
    color            = ""
    notes            = ($notes -join "`n")
    keepalive        = 15
    credential_name  = $null
    jump_host_name   = $null
    password_ref     = $null
  }
}

$vault = [ordered]@{
  ssloth_export = [ordered]@{
    version     = 2
    exported_at = (Get-Date).ToUniversalTime().ToString("o")
    user        = "Import-PuttySessions.ps1"
    hosts       = $hosts
    credentials = @()
    sealed      = $null
  }
}

$vault | ConvertTo-Json -Depth 10 | Set-Content -Path $Out -Encoding utf8
Write-Host "imported $($hosts.Count) hosts$(if ($skipped) { ", $skipped skipped" }) -> $Out"
Write-Host "import it in ssloth: Settings -> Vault -> Import"
