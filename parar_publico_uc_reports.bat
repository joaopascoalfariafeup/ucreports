@echo off
setlocal

REM Para processos locais da app pública (Waitress + Cloudflared)

echo [INFO] A terminar Cloudflare Tunnel (cloudflared)...
taskkill /F /IM cloudflared.exe >nul 2>nul
if errorlevel 1 (
  echo [INFO] cloudflared.exe nao estava em execucao.
) else (
  echo [OK] cloudflared.exe terminado.
)

echo [INFO] A terminar servidor web (waitress/python)...
taskkill /F /IM waitress-serve.exe >nul 2>nul
if errorlevel 1 (
  echo [INFO] waitress-serve.exe nao estava em execucao.
) else (
  echo [OK] waitress-serve.exe terminado.
)

REM fallback para casos em que waitress corre via python.exe
for /f "tokens=5" %%P in ('netstat -ano ^| findstr ":5000" ^| findstr "LISTENING"') do (
  taskkill /F /PID %%P >nul 2>nul
)

echo.
echo [OK] Pedido de paragem concluido.
echo     Se tiveres outros servicos na porta 5000, confirma antes de reutilizar este script.
echo.
pause
