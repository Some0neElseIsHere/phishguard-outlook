# Crée un certificat HTTPS pour "localhost" et l'ajoute aux certificats de confiance de l'utilisateur.
# Aucun droit administrateur ni npm nécessaire. Windows affiche un avertissement : répondre "Oui".

$ErrorActionPreference = 'Stop'
$dir = Join-Path $PSScriptRoot '..\certs'
New-Item -ItemType Directory -Force -Path $dir | Out-Null
$pfx = Join-Path $dir 'localhost.pfx'
$cer = Join-Path $dir 'localhost.cer'

if (Test-Path $pfx) {
  Write-Host '      Certificat deja present.'
  exit 0
}

$cert = New-SelfSignedCertificate `
  -DnsName 'localhost', '127.0.0.1' `
  -CertStoreLocation 'Cert:\CurrentUser\My' `
  -FriendlyName 'PhishGuard (developpement local)' `
  -NotAfter (Get-Date).AddYears(2) `
  -KeyAlgorithm RSA -KeyLength 2048 `
  -KeyExportPolicy Exportable `
  -KeyUsage DigitalSignature, KeyEncipherment `
  -TextExtension @('2.5.29.37={text}1.3.6.1.5.5.7.3.1')

$password = ConvertTo-SecureString -String 'phishguard' -Force -AsPlainText
Export-PfxCertificate -Cert $cert -FilePath $pfx -Password $password | Out-Null
Export-Certificate -Cert $cert -FilePath $cer | Out-Null

# Ajout aux autorités de confiance de l'utilisateur (déclenche la fenêtre de confirmation Windows)
Import-Certificate -FilePath $cer -CertStoreLocation 'Cert:\CurrentUser\Root' | Out-Null
Write-Host '      Certificat cree et approuve.'
