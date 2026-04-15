@echo off
echo Parando servidor antigo...
taskkill /F /IM node.exe /T 2>nul
timeout /t 2 /nobreak >nul
echo Iniciando Marina One...
start "" "C:\Program Files\nodejs\node.exe" "%~dp0server.js"
timeout /t 3 /nobreak >nul
echo Pronto!
start "" "http://localhost:3000/frontend.html"
