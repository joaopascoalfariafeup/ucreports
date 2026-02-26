@echo off
setlocal

REM Arranque local da app (Waitress) + Cloudflare Tunnel
REM Projeto: c:\Dados\Python\AuditoriaRelatoriosUC

set "ROOT=c:\Dados\Python\AuditoriaRelatoriosUC"
set "CF_CONFIG=C:\Users\jpf\.cloudflared\config.yml"
set "TUNNEL_NAME=auditoria-uc"

if not exist "%ROOT%\app_web.py" (
  echo [ERRO] Nao foi encontrado app_web.py em "%ROOT%".
  pause
  exit /b 1
)

if not exist "%CF_CONFIG%" (
  echo [ERRO] Nao foi encontrado config do cloudflared em "%CF_CONFIG%".
  pause
  exit /b 1
)

where cloudflared >nul 2>nul
if errorlevel 1 (
  echo [ERRO] cloudflared nao encontrado no PATH.
  pause
  exit /b 1
)

where waitress-serve >nul 2>nul
if errorlevel 1 (
  echo [ERRO] waitress-serve nao encontrado no PATH.
  echo Instala com: pip install waitress
  pause
  exit /b 1
)

echo [INFO] A iniciar servidor web local em http://127.0.0.1:5000 ...
start "UC Reports - Web (waitress)" cmd /k "cd /d "%ROOT%" && waitress-serve --listen=127.0.0.1:5000 app_web:app"

echo [INFO] A iniciar Cloudflare Tunnel (%TUNNEL_NAME%) ...
start "UC Reports - Tunnel (cloudflared)" cmd /k "cloudflared tunnel --config "%CF_CONFIG%" run %TUNNEL_NAME%"

echo.
echo [OK] Foram abertas duas janelas: Web + Tunnel.
echo      URL publica esperada: https://app.uc-reports.com
echo.
pause
