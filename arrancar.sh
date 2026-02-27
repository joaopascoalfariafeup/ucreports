#!/usr/bin/env bash
# Arranque da app (Waitress) + Cloudflare Tunnel
# Uso: ./arrancar.sh [--sem-tunnel] [--native]
#
#   --sem-tunnel  arranca so o servidor web (sem Cloudflare Tunnel)
#   --native      em WSL, forcar uso de binarios Linux em vez dos binarios Windows

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PIDFILE="$ROOT/.pids"
TUNNEL_NAME="auditoria-uc"
LISTEN="127.0.0.1:5000"

# --- processar flags ---
SEM_TUNNEL=0
FORCE_NATIVE=0
for arg in "$@"; do
  [[ "$arg" == "--sem-tunnel" ]] && SEM_TUNNEL=1
  [[ "$arg" == "--native"     ]] && FORCE_NATIVE=1
done

# --- detetar WSL ---
IS_WSL=0
if [[ $FORCE_NATIVE -eq 0 ]] && grep -qi microsoft /proc/version 2>/dev/null; then
  IS_WSL=1
  echo "[INFO] WSL detetado - a usar binarios Windows (usa --native para forcar Linux)."
fi

# --- selecionar comandos para o servidor web ---
if [[ $IS_WSL -eq 1 ]]; then
  # py.exe (Python Launcher) e mais fiavel que python.exe em WSL
  PYTHON_CMD="py.exe"
  WAITRESS_BIN=""  # nao usado no ramo WSL
else
  # Procurar venv: primeiro em ~/ucreports-venv (filesystem Linux, evita
  # problemas de permissoes em /mnt/c/), depois em $ROOT/.venv
  _VENV=""
  for _v in "$HOME/ucreports-venv" "$ROOT/.venv"; do
    [[ -f "$_v/bin/waitress-serve" ]] && { _VENV="$_v"; break; }
  done
  if [[ -n "$_VENV" ]]; then
    PYTHON_CMD="$_VENV/bin/python3"
    WAITRESS_BIN="$_VENV/bin/waitress-serve"
  else
    PYTHON_CMD="python3"
    WAITRESS_BIN="waitress-serve"
  fi
fi

# --- selecionar comandos para o tunnel ---
# Em WSL sem --native usa cloudflared.exe (nao requer instalacao Linux)
# Com --native (ou fora de WSL) usa cloudflared Linux
IN_WSL_ENV=0
grep -qi microsoft /proc/version 2>/dev/null && IN_WSL_ENV=1
if [[ $IN_WSL_ENV -eq 1 && $FORCE_NATIVE -eq 0 ]]; then
  WIN_PROFILE="$(cmd.exe /c 'echo %USERPROFILE%' 2>/dev/null | tr -d '\r')"
  CF_CONFIG_LINUX="$(wslpath "$WIN_PROFILE")/.cloudflared/config.yml"
  CF_CONFIG_WIN="${WIN_PROFILE}\\.cloudflared\\config.yml"
else
  echo "cloudflare Linux"
  CF_CMD="cloudflared"
  CF_CONFIG_LINUX="${HOME}/.cloudflared/config.yml"
  CF_CONFIG_WIN="${HOME}/.cloudflared/config.yml"
fi

# --- verificacoes ---
if [[ ! -f "$ROOT/app_web.py" ]]; then
  echo "[ERRO] app_web.py nao encontrado em $ROOT" >&2
  exit 1
fi

if [[ -f "$PIDFILE" ]]; then
  echo "[AVISO] Parece ja existir uma instancia em execucao (ficheiro $PIDFILE existe)."
  echo "        Execute ./parar.sh primeiro, ou apague $PIDFILE manualmente."
  exit 1
fi

if ! command -v "$PYTHON_CMD" &>/dev/null; then
  echo "[ERRO] $PYTHON_CMD nao encontrado." >&2
  [[ $IS_WSL -eq 1 ]] && echo "       Certifica-te que Python esta instalado no Windows, que py.exe esta no PATH," >&2
  [[ $IS_WSL -eq 1 ]] && echo "       e que desativaste o alias da Microsoft Store em:" >&2
  [[ $IS_WSL -eq 1 ]] && echo "       Definicoes > Aplicacoes > Aliases de execucao de aplicacoes" >&2
  exit 1
fi

if [[ $SEM_TUNNEL -eq 0 ]]; then
  if ! command -v "$CF_CMD" &>/dev/null; then
    echo "[ERRO] $CF_CMD nao encontrado." >&2
    [[ $IN_WSL_ENV -eq 1 ]] && echo "       Certifica-te que cloudflared esta instalado no Windows e no PATH." >&2
    exit 1
  fi
  if [[ ! -f "$CF_CONFIG_LINUX" ]]; then
    echo "[ERRO] Config do cloudflared nao encontrado em $CF_CONFIG_LINUX" >&2
    exit 1
  fi
fi

# --- ler configuracao do .env ---
WEB_THREADS=$(grep -m1 '^WEB_THREADS=' "$ROOT/.env" 2>/dev/null | cut -d= -f2 | tr -d '[:space:]')
WEB_THREADS=${WEB_THREADS:-8}

# --- arrancar servidor web ---
echo "[INFO] A iniciar servidor web em http://$LISTEN (threads=$WEB_THREADS) ..."
cd "$ROOT"
if [[ $IS_WSL -eq 1 ]]; then
  py.exe -m waitress --listen="$LISTEN" --threads="$WEB_THREADS" app_web:app &> "$ROOT/waitress.log" &
else
  "$WAITRESS_BIN" --listen="$LISTEN" --threads="$WEB_THREADS" app_web:app &> "$ROOT/waitress.log" &
fi
WEB_PID=$!
echo "[INFO] waitress PID=$WEB_PID (log: waitress.log)"

# --- arrancar tunnel ---
CF_PID=""
if [[ $SEM_TUNNEL -eq 0 ]]; then
  echo "[INFO] A iniciar Cloudflare Tunnel ($TUNNEL_NAME) ..."
  "$CF_CMD" tunnel --config "$CF_CONFIG_WIN" run "$TUNNEL_NAME" &> "$ROOT/cloudflared.log" &
  CF_PID=$!
  echo "[INFO] cloudflared PID=$CF_PID (log: cloudflared.log)"
fi

# --- guardar PIDs ---
echo "WEB_PID=$WEB_PID" > "$PIDFILE"
echo "CF_PID=${CF_PID}" >> "$PIDFILE"

echo ""
echo "[OK] Servicos iniciados em background."
[[ $SEM_TUNNEL -eq 0 ]] && echo "     URL publica esperada: https://app.uc-reports.com"
echo "     Para parar: ./parar.sh"
echo "     Logs: waitress.log  cloudflared.log"
