@echo off
:: ============================================================
::  Marina One — Script de Atualização (Windows)
::  Uso: duplo clique ou executar como Administrador
:: ============================================================
setlocal enabledelayedexpansion
title Marina One — Atualizacao

echo.
echo ===========================================
echo   Marina One ^— Atualizacao do Sistema
echo ===========================================
echo.

set APP_DIR=%~dp0
set BACKUP_DIR=%APP_DIR%..\marina-backups
set DB_FILE=%APP_DIR%marina.db
for /f "tokens=2 delims==" %%I in ('wmic os get localdatetime /value') do set dt=%%I
set DATE=%dt:~0,8%_%dt:~8,6%

cd /d "%APP_DIR%"

:: ── 1. Backup do banco ───────────────────────────────────
echo [1/5] Criando backup do banco...
if not exist "%BACKUP_DIR%" mkdir "%BACKUP_DIR%"
copy /Y "%DB_FILE%" "%BACKUP_DIR%\marina-pre-update-%DATE%.db" > nul
echo      Salvo em: marina-pre-update-%DATE%.db

:: ── 2. Versao atual ──────────────────────────────────────
echo.
echo [2/5] Versao atual:
node -e "const p=require('./package.json');console.log('  v'+p.version);"
git rev-parse --short HEAD 2>nul && echo. || echo   (sem git hash)

:: ── 3. Git pull ──────────────────────────────────────────
echo.
echo [3/5] Buscando atualizacoes...
git pull origin main
if %errorlevel% neq 0 (
  echo ERRO no git pull. Verifique a conexao e tente novamente.
  pause & exit /b 1
)

:: ── 4. Instalar dependencias npm ─────────────────────────
echo.
echo [4/6] Instalando dependencias npm...
npm install --omit=dev
if %errorlevel% neq 0 (
  echo AVISO: npm install retornou erro. Verifique manualmente.
)

:: ── 5. Validar server.js ─────────────────────────────────
echo.
echo [5/6] Validando arquivos...
node --check server.js
if %errorlevel% neq 0 (
  echo ERRO de sintaxe em server.js! Revertendo...
  git checkout HEAD~1 -- server.js
  pause & exit /b 1
)
echo      server.js OK

:: ── 6. Reiniciar via PM2 ─────────────────────────────────
echo.
echo [6/6] Reiniciando aplicacao...
pm2 describe marina-one > nul 2>&1
if %errorlevel% equ 0 (
  pm2 restart marina-one --update-env
) else (
  pm2 start server.js --name marina-one
)

timeout /t 3 /nobreak > nul

:: ── Health check ─────────────────────────────────────────
echo.
echo Verificando saude da aplicacao...
set /a TRIES=0
:CHECK
  curl -sf http://localhost:3000/api/version > nul 2>&1
  if %errorlevel% equ 0 goto OK
  set /a TRIES+=1
  if %TRIES% geq 10 (
    echo ERRO: aplicacao nao respondeu apos 10 tentativas.
    echo Verifique: pm2 logs marina-one
    pause & exit /b 1
  )
  timeout /t 1 /nobreak > nul
  goto CHECK

:OK
echo.
echo ===========================================
echo   Atualizacao Concluida com Sucesso!
echo ===========================================
echo.
node -e "const p=require('./package.json');console.log('  Versao: v'+p.version);"
echo.
pause
