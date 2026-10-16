@echo off
chcp 65001 >nul
title PhishGuard
cd /d "%~dp0"

where node >nul 2>nul
if errorlevel 1 goto nonode

echo [1/3] Certificat de securite local...
echo       Si Windows affiche un avertissement de securite, cliquez sur "Oui".
powershell -NoProfile -ExecutionPolicy Bypass -File "tools\creer-certificat.ps1"
if errorlevel 1 goto certfail

echo [2/3] Listes de domaines malveillants...
powershell -NoProfile -ExecutionPolicy Bypass -File "tools\telecharger-listes.ps1"
set "REDFLAG_FILE=%~dp0blocklists\redflagdomains.txt"
node tools\update-blocklists.mjs

echo [3/3] Demarrage de PhishGuard. Laissez cette fenetre ouverte pendant vos tests.
echo.
node server.js
pause
exit /b

:nonode
echo Node.js n'est pas installe sur ce poste.
echo Telechargez la version LTS sur https://nodejs.org, installez-la, puis relancez ce fichier.
pause
exit /b 1

:certfail
echo.
echo La creation du certificat a echoue (voir le message ci-dessus).
echo Votre entreprise bloque peut-etre l'ajout de certificats : contactez votre service informatique.
pause
exit /b 1
