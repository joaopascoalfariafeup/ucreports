#!/usr/bin/env bash
# Para os servicos iniciados por arrancar.sh

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PIDFILE="$ROOT/.pids"

if [[ ! -f "$PIDFILE" ]]; then
  echo "[AVISO] Ficheiro $PIDFILE nao encontrado. Nada a parar."
  exit 0
fi

source "$PIDFILE"

kill_pid() {
  local name="$1" pid="$2"
  if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
    kill "$pid" && echo "[OK] $name (PID=$pid) terminado."
  else
    echo "[INFO] $name (PID=${pid:-?}) ja nao estava em execucao."
  fi
}

kill_pid "waitress"    "${WEB_PID:-}"
kill_pid "cloudflared" "${CF_PID:-}"

rm -f "$PIDFILE"
echo "[OK] Concluido."
