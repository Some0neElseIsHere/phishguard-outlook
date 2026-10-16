@echo off
chcp 65001 >nul
setlocal
title PhishGuard - construction
cd /d "%~dp0"

rem Compilateur C# fourni avec Windows (.NET Framework 4.x) : rien a installer.
set "CSC=%WINDIR%\Microsoft.NET\Framework64\v4.0.30319\csc.exe"
if not exist "%CSC%" set "CSC=%WINDIR%\Microsoft.NET\Framework\v4.0.30319\csc.exe"
if not exist "%CSC%" goto nocsc

echo Dossier : %CD%
echo Compilateur : %CSC%
echo.

rem Le compilateur peut-il se lancer ?
"%CSC%" /nologo /help >nul 2>&1
if errorlevel 1 goto cscblocked

if exist build rmdir /s /q build
mkdir build\package
if errorlevel 1 goto nowrite

echo [1/4] Compilation des tests du moteur...
"%CSC%" /nologo /codepage:65001 /target:exe /out:build\PhishGuard-Tests.exe /r:System.Core.dll /r:Microsoft.CSharp.dll src\Engine\*.cs tests\Tests.cs
if errorlevel 1 goto compilefail

echo       Lancement des tests...
build\PhishGuard-Tests.exe
if exist build\tests-result.txt goto testsran
echo.
echo       [!] Le programme de tests n'a pas pu s'executer : Windows bloque les programmes
echo           situes dans ce dossier (strategie de securite ou antivirus).
echo           Les tests sont ignores, la construction continue.
goto build
:testsran
set /p TESTFAIL=<build\tests-result.txt
if not "%TESTFAIL%"=="0" (
  echo.
  echo Des tests ont echoue : envoyez ce qui est affiche ci-dessus.
  goto fail
)

:build
echo.
echo [2/4] Compilation du complement Outlook...
"%CSC%" /nologo /codepage:65001 /target:library /platform:anycpu /out:build\package\PhishGuard.dll ^
  /r:System.dll /r:System.Core.dll /r:Microsoft.CSharp.dll /r:System.Windows.Forms.dll /r:System.Drawing.dll ^
  /resource:assets\icon-32.png,PhishGuard.icon-32.png /resource:assets\report-32.png,PhishGuard.report-32.png /resource:assets\settings-32.png,PhishGuard.settings-32.png ^
  src\Engine\*.cs src\AddIn\*.cs
if errorlevel 1 goto compilefail

echo [3/4] Preparation de l'installation...
for %%F in (config.ini custom.txt assets\phishguard.ico installer\installer.cmd installer\desinstaller.cmd) do copy /y "%%F" build\package\ >nul

echo [4/4] Creation de l'installeur PhishGuard-Outlook.exe...
rem Programme d'installation en C# : les fichiers du complement sont integres a l'exe.
if not defined PG_VERSION set "PG_VERSION=1.0.0"
>build\version.txt echo %PG_VERSION%
"%CSC%" /nologo /codepage:65001 /target:winexe /out:build\PhishGuard-Outlook.exe ^
  /win32icon:assets\phishguard.ico /win32manifest:installer\app.manifest ^
  /r:System.dll /r:System.Windows.Forms.dll /r:System.Drawing.dll ^
  /resource:build\package\PhishGuard.dll,Setup.PhishGuard.dll /resource:build\package\config.ini,Setup.config.ini ^
  /resource:build\package\custom.txt,Setup.custom.txt /resource:build\package\phishguard.ico,Setup.phishguard.ico ^
  /resource:build\version.txt,Setup.version.txt /resource:build\package\installer.cmd,Setup.installer.cmd /resource:build\package\desinstaller.cmd,Setup.desinstaller.cmd ^
  installer\Setup.cs
if errorlevel 1 (
  echo       L'exe n'a pas pu etre cree. L'installation reste possible avec build\package\installer.cmd
  if defined CI goto fail
)

echo.
echo ============================================================
echo  Termine.
echo  Pour installer : fermez Outlook, puis lancez
echo    build\PhishGuard-Outlook.exe
echo  ou, si l'exe est bloque :
echo    build\package\installer.cmd
echo ============================================================
goto end

:nocsc
echo Le compilateur .NET Framework 4 est introuvable sur ce poste.
goto fail

:cscblocked
echo [!] Windows refuse de lancer le compilateur C# :
echo     %CSC%
echo     Votre strategie de securite (AppLocker, antivirus) bloque cet outil.
echo     Solution : lancer construire.bat sur un poste ou il est autorise
echo     (par exemple celui du service informatique), puis copier le dossier build.
goto fail

:nowrite
echo [!] Impossible d'ecrire dans %CD%\build.
echo     Deplacez le dossier PhishGuard ailleurs (par exemple C:\PhishGuard-exe) et relancez.
goto fail

:compilefail
echo.
echo [!] La compilation a echoue. Si le message est "Acces refuse", Windows bloque le compilateur
echo     ou l'ecriture du fichier. Sinon, envoyez le texte ci-dessus pour correction.
goto fail

:fail
echo.
echo La construction a echoue. Envoyez tout le texte ci-dessus pour correction.
if not defined CI pause
exit /b 1

:end
echo.
if not defined CI pause
exit /b 0
