@echo off
REM ============================================================
REM  Marina One — Script de Publicacao (Windows)
REM  Uso: publicar.bat "descricao" [patch|minor|major]
REM  Ex:  publicar.bat "corrige calculo de contratos"
REM       publicar.bat "novo modulo de reservas" minor
REM ============================================================

setlocal enabledelayedexpansion

set "MENSAGEM=%~1"
set "TIPO=%~2"
if "%MENSAGEM%"=="" set "MENSAGEM=atualizacao do sistema"
if "%TIPO%"=="" set "TIPO=patch"

echo.
echo  ==================================================
echo   Marinah One - Publicacao
echo  ==================================================

REM Verificar se ha alteracoes
git diff --quiet 2>nul
git diff --staged --quiet 2>nul
if errorlevel 1 goto :tem_alteracoes

REM Checar arquivos nao rastreados
for /f %%i in ('git status --porcelain') do goto :tem_alteracoes

echo  [AVISO] Nenhuma alteracao detectada.
echo  Adicione suas mudancas com: git add .
goto :fim

:tem_alteracoes

REM Obter versao atual
for /f "delims=" %%v in ('node -p "require('./package.json').version"') do set "VERSAO_ATUAL=%%v"
echo  Versao atual: %VERSAO_ATUAL%

REM Calcular nova versao
for /f "tokens=1,2,3 delims=." %%a in ("%VERSAO_ATUAL%") do (
  set /a MAJOR=%%a
  set /a MINOR=%%b
  set /a PATCH=%%c
)

if /i "%TIPO%"=="major" (
  set /a MAJOR=MAJOR+1
  set MINOR=0
  set PATCH=0
) else if /i "%TIPO%"=="minor" (
  set /a MINOR=MINOR+1
  set PATCH=0
) else (
  set /a PATCH=PATCH+1
)

set "NOVA_VERSAO=%MAJOR%.%MINOR%.%PATCH%"
echo  Nova versao: %NOVA_VERSAO%

REM Atualizar package.json
node -e "const fs=require('fs');const pkg=JSON.parse(fs.readFileSync('package.json','utf8'));pkg.version='%NOVA_VERSAO%';fs.writeFileSync('package.json',JSON.stringify(pkg,null,2)+'\n');"
echo  package.json atualizado

REM Atualizar CHANGELOG
for /f "tokens=1-3 delims=/" %%a in ("%date%") do set "DATA=%%c-%%a-%%b"
REM Tenta obter data no formato ISO
for /f %%d in ('powershell -NoProfile -Command "Get-Date -Format yyyy-MM-dd"') do set "DATA=%%d"

if exist CHANGELOG.md (
  powershell -NoProfile -Command "$c=Get-Content 'CHANGELOG.md' -Raw; $entry=\"## [%NOVA_VERSAO%] — %DATA%`n- %MENSAGEM%`n\"; $lines=$c -split \"`n\"; $first=$lines[0]; $rest=($lines | Select-Object -Skip 1) -join \"`n\"; Set-Content 'CHANGELOG.md' ($first + \"`n`n\" + $entry + $rest)"
) else (
  echo # Changelog - Marina One > CHANGELOG.md
  echo. >> CHANGELOG.md
  echo ## [%NOVA_VERSAO%] - %DATA% >> CHANGELOG.md
  echo - %MENSAGEM% >> CHANGELOG.md
)
echo  CHANGELOG.md atualizado

REM Commit + Tag + Push
git add -A
git commit -m "v%NOVA_VERSAO%: %MENSAGEM%"
git tag "v%NOVA_VERSAO%" -m "v%NOVA_VERSAO%: %MENSAGEM%"
git push origin main
git push origin "v%NOVA_VERSAO%"

echo.
echo  ==================================================
echo   Publicado! v%NOVA_VERSAO% - GitHub - Railway
echo   https://marina-one-app-production.up.railway.app
echo  ==================================================

:fim
endlocal
