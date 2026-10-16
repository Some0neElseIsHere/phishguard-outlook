# Fabrique PhishGuard-Outlook.exe avec IExpress (outil fourni avec Windows).
param([Parameter(Mandatory = $true)][string]$PackageDir, [Parameter(Mandatory = $true)][string]$Target)

$ErrorActionPreference = 'Stop'
$PackageDir = (Resolve-Path $PackageDir).Path.TrimEnd('\') + '\'
$files = Get-ChildItem -File $PackageDir | Select-Object -ExpandProperty Name
$sed = Join-Path (Split-Path $Target) 'phishguard.sed'

$lines = @(
  '[Version]', 'Class=IEXPRESS', 'SEDVersion=3',
  '[Options]', 'PackagePurpose=InstallApp', 'ShowInstallProgramWindow=0', 'HideExtractAnimation=1',
  'UseLongFileName=1', 'InsideCompressed=0', 'CAB_FixedSize=0', 'CAB_ResvCodeSigning=0', 'RebootMode=N',
  'InstallPrompt=%InstallPrompt%', 'DisplayLicense=%DisplayLicense%', 'FinishMessage=%FinishMessage%',
  'TargetName=%TargetName%', 'FriendlyName=%FriendlyName%', 'AppLaunched=%AppLaunched%',
  'PostInstallCmd=%PostInstallCmd%', 'AdminQuietInstCmd=%AdminQuietInstCmd%', 'UserQuietInstCmd=%UserQuietInstCmd%',
  'SourceFiles=SourceFiles',
  '[Strings]', 'InstallPrompt=', 'DisplayLicense=', 'FinishMessage=',
  "TargetName=$Target", 'FriendlyName=PhishGuard pour Outlook', 'AppLaunched=cmd.exe /c installer.cmd',
  'PostInstallCmd=<None>', 'AdminQuietInstCmd=', 'UserQuietInstCmd='
)
for ($i = 0; $i -lt $files.Count; $i++) { $lines += "FILE$i=`"$($files[$i])`"" }
$lines += '[SourceFiles]'
$lines += "SourceFiles0=$PackageDir"
$lines += '[SourceFiles0]'
for ($i = 0; $i -lt $files.Count; $i++) { $lines += "%FILE$i%=" }

[System.IO.File]::WriteAllLines($sed, $lines, [System.Text.Encoding]::Default)
if (Test-Path $Target) { Remove-Item -Force $Target }
$iexpress = Join-Path $env:WINDIR 'System32\iexpress.exe'
$p = Start-Process -FilePath $iexpress -ArgumentList '/N', '/Q', "`"$sed`"" -Wait -PassThru
if (-not (Test-Path $Target)) { throw "IExpress n'a pas produit $Target (code $($p.ExitCode))" }
