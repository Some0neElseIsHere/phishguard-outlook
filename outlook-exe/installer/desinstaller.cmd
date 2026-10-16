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
)
reg delete "HKCU\Software\Microsoft\Office\Outlook\Addins\%PROGID%" /f >nul 2>&1
reg delete "HKCU\Software\Microsoft\Office\16.0\Outlook\Resiliency\DoNotDisableAddinList" /v %PROGID% /f >nul 2>&1
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall\PhishGuard" /f >nul 2>&1
echo PhishGuard a ete desinstalle.
pause
rem Supprime le dossier d'installation (ce script compris)
cd /d "%TEMP%"
start "" /b cmd /c "timeout /t 1 >nul & rmdir /s /q "%LOCALAPPDATA%\PhishGuard""
