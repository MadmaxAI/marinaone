@echo off
REM ============================================================
REM  Marina One — Aplicar alteracoes no ambiente LOCAL
REM  Uso: testar.bat
REM ============================================================

echo.
echo  ==================================================
echo   Marina One - Aplicando no ambiente LOCAL
echo  ==================================================
echo.

REM --- Build da imagem (erros sao exibidos — nao silenciados) ---
echo  [1/2] Buildando imagem Docker...
docker compose build app --no-cache
IF %ERRORLEVEL% NEQ 0 (
  echo.
  echo  !! ERRO: docker compose build falhou.
  echo  !! A imagem NAO foi atualizada. Corrija o erro acima antes de testar.
  echo.
  exit /b 1
)

REM --- Recriar container com a imagem nova ---
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
echo   Ambiente local atualizado!
echo   Acesse: http://localhost:3000
echo.
echo   Aguarde ~5s para o servidor iniciar completamente.
echo   Verifique os logs: docker logs marinaone_app --tail=30
echo.
echo   Quando aprovar, diga ao Claude: "aprovado"
echo   e ele publicara em producao com publicar.bat
echo  ==================================================
echo.
