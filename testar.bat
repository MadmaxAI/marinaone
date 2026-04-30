@echo off
REM ============================================================
REM  Marina One — Aplicar alteracoes no ambiente LOCAL
REM  Uso: testar.bat
REM  Rodado pelo Claude apos cada alteracao de codigo.
REM  Voce testa em http://localhost:3000 e aprova antes
REM  de publicar em producao.
REM ============================================================

echo.
echo  ==================================================
echo   Marina One - Aplicando no ambiente LOCAL
echo  ==================================================

REM Rebuildar imagem e reiniciar container
docker compose build app --no-cache 2>nul || docker-compose build app --no-cache 2>nul
docker compose restart app 2>nul || docker-compose restart app 2>nul

echo.
echo  ==================================================
echo   Ambiente local atualizado!
echo   Acesse: http://localhost:3000
echo.
echo   Quando aprovar, diga ao Claude: "aprovado"
echo   e ele publicara em producao com publicar.bat
echo  ==================================================
echo.
