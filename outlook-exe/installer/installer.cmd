@echo off
rem PhishGuard pour Outlook - installation pour l'utilisateur courant.
rem N'utilise que des outils Windows de base (copy, reg) : aucun droit administrateur requis.
rem   installer.cmd          installation interactive
rem   installer.cmd /quiet   installation silencieuse (deploiement automatise)
setlocal
chcp 65001 >nul
set "SRC=%~dp0"
set "DEST=%LOCALAPPDATA%\PhishGuard"
set "PROGID=PhishGuard.Connect"
set "CLSID={6C3F2A1E-8B5D-4E7A-9F21-3D4B8C6E2A71}"
set "QUIET="
if /i "%~1"=="/quiet" set "QUIET=1"
if /i "%~1"=="-quiet" set "QUIET=1"

echo PhishGuard pour Outlook - installation
echo.
if not exist "%SRC%PhishGuard.dll" (
  echo [!] PhishGuard.dll introuvable a cote de ce fichier.
  goto fail
)

:checkoutlook
tasklist /FI "IMAGENAME eq OUTLOOK.EXE" 2>nul | find /I "OUTLOOK.EXE" >nul
if errorlevel 1 goto copyfiles
if defined QUIET (timeout /t 5 >nul & goto checkoutlook)
echo Outlook est ouvert. Fermez Outlook, puis appuyez sur une touche.
pause >nul
goto checkoutlook

:copyfiles
echo [1/3] Copie des fichiers dans %DEST%
if not exist "%DEST%" mkdir "%DEST%"
for %%F in (PhishGuard.dll config.ini custom.txt phishguard.ico installer.cmd desinstaller.cmd) do (
  if exist "%SRC%%%F" copy /y "%SRC%%%F" "%DEST%\" >nul
)
if not exist "%DEST%\PhishGuard.dll" (
  echo [!] Copie impossible dans %DEST%
  goto fail
)

echo [2/3] Enregistrement du complement
set "DLL=%DEST%\PhishGuard.dll"
set "CODEBASE=file:///%DLL:\=/%"
set "ASM=PhishGuard, Version=1.0.0.0, Culture=neutral, PublicKeyToken=null"
set "CK=HKCU\Software\Classes\CLSID\%CLSID%"
for %%V in (64 32) do (
  reg add "HKCU\Software\Classes\%PROGID%" /ve /d "%PROGID%" /f /reg:%%V >nul
  reg add "HKCU\Software\Classes\%PROGID%\CLSID" /ve /d "%CLSID%" /f /reg:%%V >nul
  reg add "%CK%" /ve /d "%PROGID%" /f /reg:%%V >nul
  reg add "%CK%\ProgId" /ve /d "%PROGID%" /f /reg:%%V >nul
  reg add "%CK%\Implemented Categories\{62C8FE65-4EBB-45e7-B440-6E39B2CDBF29}" /f /reg:%%V >nul
  reg add "%CK%\InprocServer32" /ve /d "mscoree.dll" /f /reg:%%V >nul
  reg add "%CK%\InprocServer32" /v ThreadingModel /d "Both" /f /reg:%%V >nul
  for %%K in ("%CK%\InprocServer32" "%CK%\InprocServer32\1.0.0.0") do (
    reg add %%K /v Class /d "PhishGuard.AddIn.Connect" /f /reg:%%V >nul
    reg add %%K /v Assembly /d "%ASM%" /f /reg:%%V >nul
    reg add %%K /v RuntimeVersion /d "v4.0.30319" /f /reg:%%V >nul
    reg add %%K /v CodeBase /d "%CODEBASE%" /f /reg:%%V >nul
  )
)
set "AK=HKCU\Software\Microsoft\Office\Outlook\Addins\%PROGID%"
reg add "%AK%" /v FriendlyName /d "PhishGuard" /f >nul
reg add "%AK%" /v Description /d "Analyse anti-phishing des emails recus" /f >nul
reg add "%AK%" /v LoadBehavior /t REG_DWORD /d 3 /f >nul
if errorlevel 1 (
  echo [!] Ecriture dans le registre refusee.
  goto fail
)
rem Evite qu'Outlook desactive le complement s'il juge son demarrage trop lent
reg add "HKCU\Software\Microsoft\Office\16.0\Outlook\Resiliency\DoNotDisableAddinList" /v %PROGID% /t REG_DWORD /d 1 /f >nul 2>&1

echo [3/3] Ajout dans "Applications et fonctionnalites"
set "UK=HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\PhishGuard"
reg add "%UK%" /v DisplayName /d "PhishGuard pour Outlook" /f >nul
reg add "%UK%" /v DisplayVersion /d "1.0.0" /f >nul
reg add "%UK%" /v Publisher /d "PhishGuard" /f >nul
reg add "%UK%" /v InstallLocation /d "%DEST%" /f >nul
reg add "%UK%" /v DisplayIcon /d "%DEST%\phishguard.ico" /f >nul
reg add "%UK%" /v UninstallString /d "\"%DEST%\desinstaller.cmd\"" /f >nul
reg add "%UK%" /v NoModify /t REG_DWORD /d 1 /f >nul
reg add "%UK%" /v NoRepair /t REG_DWORD /d 1 /f >nul

echo.
echo PhishGuard est installe.
echo Ouvrez Outlook : les boutons "Analyser" et "Signaler" sont dans l'onglet Accueil.
if not defined QUIET pause
exit /b 0

:fail
echo.
echo L'installation a echoue.
if not defined QUIET pause
exit /b 1
