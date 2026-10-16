# Télécharge la liste Red Flag Domains avec PowerShell, qui utilise le proxy et les certificats
# de Windows (indispensable sur un réseau d'entreprise qui inspecte le HTTPS).

$ErrorActionPreference = 'Stop'
$dir = Join-Path $PSScriptRoot '..\blocklists'
New-Item -ItemType Directory -Force -Path $dir | Out-Null
$out = Join-Path $dir 'redflagdomains.txt'
$tmp = "$out.tmp"

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
# Proxy d'entreprise avec authentification Windows
[System.Net.WebRequest]::DefaultWebProxy.Credentials = [System.Net.CredentialCache]::DefaultNetworkCredentials

try {
  Invoke-WebRequest -Uri 'https://dl.red.flag.domains/red.flag.domains.txt' -OutFile $tmp -UseBasicParsing -TimeoutSec 60
  Move-Item -Force $tmp $out
  Write-Host '      Liste Red Flag Domains telechargee.'
} catch {
  if (Test-Path $tmp) { Remove-Item $tmp -Force }
  Write-Host "      Echec du telechargement : $($_.Exception.Message)"
  if (Test-Path $out) { Write-Host '      La liste precedente sera utilisee.' }
}
