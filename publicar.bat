@echo off
REM ============================================================
REM  Marina One — Script de Publicacao (Windows)
REM  Uso: publicar.bat "descricao"
REM  Ex:  publicar.bat "corrige calculo de contratos"
REM
REM  IMPORTANTE: rode testar.bat antes para bumpar a versao
REM  e testar localmente. publicar.bat apenas commita e pusha.
REM ============================================================

setlocal enabledelayedexpansion

set "MENSAGEM=%~1"
if "%MENSAGEM%"=="" set "MENSAGEM=atualizacao do sistema"

echo.
echo  ==================================================
echo    Marina One - Publicacao
echo  ==================================================

REM Verificar se ha alteracoes
git diff --quiet 2>nul
git diff --staged --quiet 2>nul
if errorlevel 1 goto :tem_alteracoes

for /f %%i in ('git status --porcelain') do goto :tem_alteracoes

echo  [AVISO] Nenhuma alteracao detectada.
goto :fim

:tem_alteracoes

REM Ler versao atual do package.json (ja bumpad pelo testar.bat)
for /f "delims=" %%v in ('node -p "require('./package.json').version"') do set "VERSAO=%%v"
echo  Publicando versao: %VERSAO%

REM Atualizar CHANGELOG
for /f %%d in ('powershell -NoProfile -Command "Get-Date -Format yyyy-MM-dd"') do set "DATA=%%d"

if exist CHANGELOG.md (
  powershell -NoProfile -Command "$c=Get-Content 'CHANGELOG.md' -Raw; $entry='## [%VERSAO%] -- %DATA%' + [char]10 + '- %MENSAGEM%' + [char]10; $lines=$c -split [char]10; $first=$lines[0]; $rest=($lines | Select-Object -Skip 1) -join [char]10; Set-Content 'CHANGELOG.md' ($first + [char]10 + [char]10 + $entry + $rest) -Encoding utf8"
) else (
  echo # Changelog - Marina One > CHANGELOG.md
  echo. >> CHANGELOG.md
  echo ## [%VERSAO%] - %DATA% >> CHANGELOG.md
  echo - %MENSAGEM% >> CHANGELOG.md
)
echo  CHANGELOG.md atualizado

REM Commit + Tag + Push
git add -A
git commit -m "v%VERSAO%: %MENSAGEM%"
git tag "v%VERSAO%" -m "v%VERSAO%: %MENSAGEM%"
git push origin main
git push origin "v%VERSAO%"

echo.
echo  ==================================================
echo    Publicado v%VERSAO% enviado ao GitHub
echo    Railway fara o deploy automaticamente.
echo    https://marina-one-app.up.railway.app
echo  ==================================================

:fim
endlocal
