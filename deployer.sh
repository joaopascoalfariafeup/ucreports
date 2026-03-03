#!/usr/bin/env bash
# deployer.sh — Monitoriza o GitHub e faz deploy automático quando há novos commits.
#
# Alternativa ao GitHub Actions quando não é possível/desejável expor SSH.
# Pode correr como serviço systemd (ver deployer.service) ou manualmente.
#
# Uso: ./deployer.sh [intervalo_segundos]
#   intervalo_segundos: segundos entre verificações (default: 60)

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INTERVALO="${1:-60}"
MAX_DRAIN_S=600  # máx. 10 min a aguardar jobs em curso

log() { echo "[$(date '+%H:%M:%S')] [deployer] $*"; }

log "A monitorizar $ROOT (intervalo: ${INTERVALO}s)"

while true; do
    sleep "$INTERVALO"

    # Verificar novos commits no remoto
    if ! git -C "$ROOT" fetch origin main --quiet 2>/dev/null; then
        log "AVISO: fetch falhou (sem rede?). A tentar novamente..."
        continue
    fi

    LOCAL=$(git -C "$ROOT" rev-parse HEAD 2>/dev/null || echo "")
    REMOTE=$(git -C "$ROOT" rev-parse origin/main 2>/dev/null || echo "")

    [[ -z "$REMOTE" || "$LOCAL" == "$REMOTE" ]] && continue

    log "Novo commit detetado: ${REMOTE:0:8} (local: ${LOCAL:0:8}). A iniciar deploy..."

    # 1. Activar drain
    touch "$ROOT/.draining"
    log "Drain activado. A aguardar jobs em curso (máx. ${MAX_DRAIN_S}s)..."

    # 2. Aguardar jobs em curso
    WAITED=0
    while [ "$WAITED" -lt "$MAX_DRAIN_S" ]; do
        ACTIVE=$(find "$ROOT/output" -maxdepth 3 -name "*.log" -newer "$ROOT/.draining" 2>/dev/null | wc -l)
        [ "$ACTIVE" -eq 0 ] && break
        log "  $ACTIVE log(s) ativo(s), a aguardar... (${WAITED}s)"
        sleep 30
        WAITED=$((WAITED + 30))
    done

    if [ "$WAITED" -ge "$MAX_DRAIN_S" ]; then
        log "AVISO: timeout de drain atingido. A reiniciar na mesma."
    fi

    # 3. Pull, atualização de dependências e reinício
    git -C "$ROOT" pull --quiet
    VENV_PIP="$(find /home /root -maxdepth 4 -name pip -path "*/ucreports-venv/*" 2>/dev/null | head -1)"
    if [ -n "$VENV_PIP" ]; then
        log "A atualizar dependências Python..."
        "$VENV_PIP" install -q -r "$ROOT/requirements.txt" && log "Dependências OK." || log "AVISO: pip falhou."
    fi
    sudo systemctl restart ucreports
    log "Deploy concluído: ${REMOTE:0:8}"
done
