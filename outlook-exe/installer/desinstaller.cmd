@echo off
rem PhishGuard pour Outlook - desinstallation pour l'utilisateur courant.
setlocal
set "PROGID=PhishGuard.Connect"
set "CLSID={6C3F2A1E-8B5D-4E7A-9F21-3D4B8C6E2A71}"

:checkoutlook
tasklist /FI "IMAGENAME eq OUTLOOK.EXE" 2>nul | find /I "OUTLOOK.EXE" >nul
if errorlevel 1 goto remove
echo Outlook est ouvert. Fermez Outlook, puis appuyez sur une touche.
pause >nul
goto checkoutlook

:remove
for %%V in (64 32) do (
  reg delete "HKCU\Software\Classes\%PROGID%" /f /reg:%%V >nul 2>&1
  reg delete "HKCU\Software\Classes\CLSID\%CLSID%" /f /reg:%%V >nul 2>&1
  reg delete "HKCU\Software\Classes\PhishGuard.Banner" /f /reg:%%V >nul 2>&1
  reg delete "HKCU\Software\Classes\CLSID\{8B1E4F52-3C7A-4D9E-A1F6-2E5B7C9D0A43}" /f /reg:%%V >nul 2>&1
)
reg delete "HKCU\Software\Microsoft\Office\Outlook\Addins\%PROGID%" /f >nul 2>&1
reg delete "HKCU\Software\Microsoft\Office\Outlook\FormRegions\IPM.Note" /v PhishGuardZone /f >nul 2>&1
reg delete "HKCU\Software\Microsoft\Office\16.0\Outlook\Resiliency\DoNotDisableAddinList" /v %PROGID% /f >nul 2>&1
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\PhishGuard" /f >nul 2>&1
rem Les reglages de l'utilisateur sont gardes de cote : une reinstallation les retrouve
if not exist "%LOCALAPPDATA%\PhishGuard-reglages" mkdir "%LOCALAPPDATA%\PhishGuard-reglages"
for %%F in (config.user.ini custom.user.txt) do (
  if exist "%LOCALAPPDATA%\PhishGuard\%%F" copy /y "%LOCALAPPDATA%\PhishGuard\%%F" "%LOCALAPPDATA%\PhishGuard-reglages\" >nul
)
echo Vos reglages sont conserves dans %LOCALAPPDATA%\PhishGuard-reglages
echo PhishGuard a ete desinstalle. Cette fenetre se ferme toute seule.
timeout /t 4 >nul
rem Supprime le dossier d'installation (ce script compris)
cd /d "%TEMP%"
start "" /b cmd /c "timeout /t 1 >nul & rmdir /s /q "%LOCALAPPDATA%\PhishGuard""
