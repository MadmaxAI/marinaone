@echo off
REM ============================================================
REM  Marina One — Aplicar alteracoes no ambiente LOCAL
REM  Uso: testar.bat [patch|minor|major]
REM  Ex:  testar.bat          (bump patch: 2.3.2 -> 2.3.3)
REM       testar.bat minor    (bump minor: 2.3.x -> 2.4.0)
REM       testar.bat major    (bump major: 2.x.x -> 3.0.0)
REM ============================================================

setlocal enabledelayedexpansion

set "TIPO=%~1"
if "%TIPO%"=="" set "TIPO=patch"

echo.
echo  ==================================================
echo    Marina One - Ambiente LOCAL
echo  ==================================================

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

echo.
echo  [1/2] Buildando imagem Docker...
docker compose build app --no-cache
IF %ERRORLEVEL% NEQ 0 (
  echo.
  echo  !! ERRO: docker compose build falhou.
  echo  !! A imagem NAO foi atualizada. Corrija o erro acima antes de testar.
  echo.
  exit /b 1
)

echo.
echo  [2/2] Recriando container com a nova imagem...
docker compose up -d --force-recreate app
IF %ERRORLEVEL% NEQ 0 (
  echo.
  echo  !! ERRO: docker compose up falhou. Verifique os logs com: docker logs marinaone_app
  echo.
  exit /b 1
)

echo.
echo  ==================================================
echo   Ambiente local atualizado para v%NOVA_VERSAO%!
echo   Acesse: http://localhost:3000
echo.
echo   Aguarde ~5s para o servidor iniciar completamente.
echo   Verifique os logs: docker logs marinaone_app --tail=30
echo.
echo   Quando aprovar, diga ao Claude: "aprovado"
echo   e ele publicara em producao com publicar.bat
echo  ==================================================
echo.

endlocal
