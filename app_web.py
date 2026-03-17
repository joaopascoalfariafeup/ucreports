"""
Ponto de entrada Web (localhost) para Assistente de Apoio à Elaboração de Relatórios de Unidades Curriculares.

- Login/password via formulário (SIGARRA)
- Lista UCs do serviço docente
- Seleciona UC e corre a análise em background
- Mostra progresso (stream do log tipo terminal) via SSE
"""

from __future__ import annotations

import base64
import html
import io
import json
import os
import random
import re
import secrets
import shutil
import threading
import time
import zipfile
from dataclasses import dataclass
from datetime import datetime, timedelta
from html.parser import HTMLParser
from pathlib import Path
from typing import Optional
import urllib.request as _urllib_req
import urllib.parse
from urllib.parse import urlparse

from flask import Flask, request, session as flask_session, redirect, url_for, Response, abort, send_file

from sigarra import SigarraSession, load_env
from logger import AuditoriaLogger
from auditoria_core import analisar_uc, submeter_preview_uc, _SCRIPT_DIR
from sigarra import extrair_ocorrencias_servico_docente
from sigarra import extrair_ficha_uc


# Carregar .env antes de ler variáveis WEB_* no arranque do módulo
load_env()

app = Flask(__name__)
app.secret_key = os.environ.get("WEB_SECRET_KEY") or secrets.token_hex(32)

app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("WEB_COOKIE_SECURE", "0").strip() == "1",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
)

_output_dir_env = os.environ.get("AUDITORIA_OUTPUT_DIR", "").strip()
OUTPUT_DIR = (
    Path(_output_dir_env).resolve()
    if _output_dir_env
    else (_SCRIPT_DIR / "output").resolve()
)

# armazenamento in-memory (local/single-user)
_SESSOES: dict[str, SigarraSession] = {}
_SESSOES_LOCK = threading.Lock()

# Sessão SIGARRA do servidor (partilhada; usada na autenticação OIDC como fallback)
_SERVER_SESS: Optional[SigarraSession] = None
_SERVER_SESS_LOCK = threading.Lock()

# Estados OAuth OIDC em curso: state → expires_at
_OIDC_STATES: dict[str, float] = {}
_OIDC_STATES_LOCK = threading.Lock()


def _oidc_config() -> dict:
    return {
        "client_id":     os.environ.get("OIDC_CLIENT_ID",     ""),
        "client_secret": os.environ.get("OIDC_CLIENT_SECRET", ""),
        "redirect_uri":  os.environ.get("OIDC_REDIRECT_URI",  ""),
        "auth_endpoint":    "https://open-id.up.pt/realms/sigarra/protocol/openid-connect/auth",
        "token_endpoint":   "https://open-id.up.pt/realms/sigarra/protocol/openid-connect/token",
        "userinfo_endpoint":"https://open-id.up.pt/realms/sigarra/protocol/openid-connect/userinfo",
    }


def _get_server_session() -> SigarraSession:
    """Devolve sessão SIGARRA do servidor, autenticando na primeira chamada."""
    global _SERVER_SESS
    with _SERVER_SESS_LOCK:
        if _SERVER_SESS is not None and _SERVER_SESS.autenticado:
            return _SERVER_SESS
        login    = os.environ.get("SIGARRA_SERVER_LOGIN",    "")
        password = os.environ.get("SIGARRA_SERVER_PASSWORD", "")
        if not login or not password:
            raise RuntimeError("SIGARRA_SERVER_LOGIN/PASSWORD não configurados no .env")
        sess = SigarraSession()
        sess.autenticar(login, password)
        _SERVER_SESS = sess
        return _SERVER_SESS


# Cache de dados de serviço docente (muito estáveis, mudam 1-2x/ano)
# chave: (doc_codigo, ano_letivo); valor: (timestamp, anos_disponiveis, ucs_list, meta)
_UCS_CACHE: dict[tuple[str, str], tuple[float, list, list, dict]] = {}
_UCS_CACHE_LOCK = threading.Lock()
_UCS_CACHE_TTL_S = float(os.environ.get("WEB_UCS_CACHE_TTL_H", "4")) * 3600
# Intervalo de anos letivos hardcoded (evita consulta lenta ao SIGARRA).
# Ex: WEB_ANOS_LETIVOS_INICIO=2016  WEB_ANOS_LETIVOS_FIM=2025
# Se não definidos, a lista é obtida dinamicamente do SIGARRA.
_ANOS_LETIVOS_INICIO = int(os.environ.get("WEB_ANOS_LETIVOS_INICIO", "0") or "0")
_ANOS_LETIVOS_FIM    = int(os.environ.get("WEB_ANOS_LETIVOS_FIM",    "0") or "0")


def _gera_lista_anos_letivos() -> list[dict]:
    """Gera lista de anos letivos.

    Se WEB_ANOS_LETIVOS_INICIO/FIM estiver configurado, usa esse intervalo.
    Caso contrário, devolve o ano corrente e o anterior (SIGARRA só aceita
    relatórios para esses dois anos).  Lógica de 'ano corrente':
      mês >= setembro → ano_inicio = ano_civil atual  (ex: set 2026 → 2026/27)
      mês < setembro  → ano_inicio = ano_civil - 1    (ex: jun 2026 → 2025/26)
    """
    if _ANOS_LETIVOS_INICIO and _ANOS_LETIVOS_FIM:
        return [
            {"ano_inicio": str(y), "ano_letivo": f"{y}/{y + 1}"}
            for y in range(_ANOS_LETIVOS_FIM, _ANOS_LETIVOS_INICIO - 1, -1)
        ]
    hoje = datetime.now()
    ano_corrente = hoje.year if hoje.month >= 9 else hoje.year - 1
    return [
        {"ano_inicio": str(y), "ano_letivo": f"{y}/{y + 1}"}
        for y in [ano_corrente, ano_corrente - 1]
    ]


@dataclass
class Tarefa:
    job_id: str
    oc_id: str
    log_path: Path
    started_at: float
    uc_nome: str = ""
    uc_sigla: str = ""
    ano_letivo: str = ""
    user_code: str = ""
    llm_provider: str = ""
    llm_modelo: str = ""
    llm_modelo_condensacao: str = ""
    run_dir: Path | None = None
    action: str = "preview"  # preview | submit
    done: bool = False
    ok: bool = False
    error: str = ""


_JOBS: dict[str, Tarefa] = {}
_JOBS_LOCK = threading.Lock()

MAX_JOBS = int(os.environ.get("WEB_MAX_JOBS", "20"))
MAX_RUNNING_JOBS = int(os.environ.get("WEB_MAX_RUNNING_JOBS", "2"))
_SESSION_TIMEOUT_S = 8 * 3600  # 8h — alinhado com PERMANENT_SESSION_LIFETIME
_JOB_TIMEOUT_S = int(os.environ.get("WEB_JOB_TIMEOUT_S", "1800"))  # 30 min
WEB_VERBOSIDADE = int(os.environ.get("WEB_VERBOSIDADE", "0"))
WEB_OUTPUT_RETENTION_HOURS = float(os.environ.get("WEB_OUTPUT_RETENTION_HOURS",
    str(int(os.environ.get("WEB_OUTPUT_RETENTION_DAYS", "2")) * 24)  # compat
))
WEB_OUTPUT_MAX_GB = float(os.environ.get("WEB_OUTPUT_MAX_GB", "5"))
_REVIEW_ERROR_INJECTION = int(os.environ.get("REVIEW_ERROR_INJECTION", "0").strip() or "0")
# Se 1 (default), lista de UCs restringe-se a UCs em que o docente é regente.
# Se 0, todos os docentes da UC podem gerar relatório (útil para testes).
_ACESSO_APENAS_REGENTE = os.environ.get("WEB_ACESSO_APENAS_REGENTE", "1").strip() != "0"
_REVIEW_ERROR_COUNT = int(os.environ.get("REVIEW_ERROR_COUNT", "3"))
_REVIEW_ERROR_TOLERANCE = int(os.environ.get("REVIEW_ERROR_TOLERANCE", "1"))
WEB_MAX_USD_PER_USER_PER_MONTH = float(
    os.environ.get(
        "WEB_MAX_USD_PER_USER_PER_MONTH",
        os.environ.get("WEB_MAX_USD_PER_USER_PER_DAY", "0"),  # compat
    )
)
WEB_COST_BYPASS_USERS = {
    u.strip().lower()
    for u in os.environ.get("WEB_COST_BYPASS_USERS", "").split(",")
    if u.strip()
}
WEB_FREE_LLM_PROVIDERS_LIST = []
for _p in os.environ.get("WEB_FREE_LLM_PROVIDERS", "iaedu").split(","):
    _v = _p.strip().lower()
    if _v and _v not in WEB_FREE_LLM_PROVIDERS_LIST:
        WEB_FREE_LLM_PROVIDERS_LIST.append(_v)
WEB_FREE_LLM_PROVIDERS_SET = set(WEB_FREE_LLM_PROVIDERS_LIST)


def _evict_old_jobs_locked() -> None:
    """Remove jobs mais antigos que já terminaram quando o limite é excedido.

    DEVE ser chamado com _JOBS_LOCK já adquirido.
    Nunca remove jobs em execução (not done) para evitar corromper
    operações em curso.
    """
    while len(_JOBS) > MAX_JOBS:
        candidatos = [j for j in _JOBS.values() if j.done]
        if not candidatos:
            break  # todos em execução — não podemos remover nenhum
        antigo = min(candidatos, key=lambda j: j.started_at)
        _JOBS.pop(antigo.job_id, None)


def _reap_stuck_jobs() -> None:
    """Marca como falhados jobs que ultrapassaram o timeout sem terminar."""
    now = time.time()
    with _JOBS_LOCK:
        for job in list(_JOBS.values()):
            if not job.done and (now - job.started_at) > _JOB_TIMEOUT_S:
                job.ok = False
                job.error = f"Timeout ({_JOB_TIMEOUT_S}s) — a tarefa foi cancelada."
                job.done = True


def _reap_expired_sessions() -> None:
    """Remove sessões SIGARRA com mais de _SESSION_TIMEOUT_S."""
    # Flask sessions têm expiração própria, mas _SESSOES in-memory não.
    # Guardamos o timestamp de criação junto com a sessão.
    now = time.time()
    with _SESSOES_LOCK:
        expired = [
            sid for sid, s in _SESSOES.items()
            if (now - getattr(s, "_created_at", now)) > _SESSION_TIMEOUT_S
        ]
        for sid in expired:
            _SESSOES.pop(sid, None)
    # Limpar entradas expiradas do cache de UCs
    with _UCS_CACHE_LOCK:
        expired_keys = [k for k, (ts, *_) in _UCS_CACHE.items()
                        if now - ts > _UCS_CACHE_TTL_S]
        for k in expired_keys:
            _UCS_CACHE.pop(k, None)


def _periodic_cleanup() -> None:
    """Thread de background que periodicamente limpa sessões, jobs e pastas de output."""
    prune_interval = max(1, int(WEB_OUTPUT_RETENTION_HOURS * 3600 / 4))  # 4x por período de retenção
    last_prune = 0.0
    while True:
        time.sleep(120)  # a cada 2 minutos
        try:
            _reap_expired_sessions()
            _reap_stuck_jobs()
        except Exception:
            pass
        now = time.time()
        if now - last_prune >= prune_interval:
            try:
                _prune_output_dir()
            except Exception:
                pass
            last_prune = now


_cleanup_thread = threading.Thread(target=_periodic_cleanup, daemon=True)
_cleanup_thread.start()


def _llm_provider_options() -> list[str]:
    # 1) Se WEB_LLM_PROVIDER_OPTIONS estiver definido, respeitar essa ordem.
    raw = os.environ.get("WEB_LLM_PROVIDER_OPTIONS", "").strip()
    if raw:
        opts = [p.strip().lower() for p in raw.split(",") if p.strip()]
        if opts:
            return opts

    # 2) Caso contrário, usar a ordem das chaves em WEB_LLM_MODEL_OPTIONS_JSON.
    #    (json.loads preserva ordem de inserção em Python 3.7+)
    raw_models = os.environ.get("WEB_LLM_MODEL_OPTIONS_JSON", "").strip()
    if raw_models:
        try:
            data = json.loads(raw_models)
            if isinstance(data, dict):
                opts = [str(k).strip().lower() for k in data.keys() if str(k).strip()]
                if opts:
                    return opts
        except json.JSONDecodeError:
            pass

    # 3) Fallback de compatibilidade.
    return ["anthropic", "openai", "iaedu"]


def _llm_model_options_map() -> dict[str, list[str]]:
    """Lê mapa provider->modelos de WEB_LLM_MODEL_OPTIONS_JSON.

    Formatos suportados (JSON):
      {"anthropic": ["claude-sonnet-4-5", "claude-opus-4-6"]}
      {"anthropic": "claude-sonnet-4-5, claude-opus-4-6"}
    """
    raw = os.environ.get("WEB_LLM_MODEL_OPTIONS_JSON", "").strip()
    if not raw:
        return {}
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return {}
    if not isinstance(data, dict):
        return {}
    out: dict[str, list[str]] = {}
    for prov, models in data.items():
        limpos: list[str] = []
        if isinstance(models, list):
            limpos = [str(m).strip() for m in models if str(m).strip()]
        elif isinstance(models, str):
            limpos = [m.strip() for m in models.split(",") if m.strip()]
        if limpos:
            out[str(prov).strip().lower()] = limpos
    return out


def _format_model_cost(provider: str) -> str:
    """Devolve indicação de gratuitidade para mostrar na UI (apenas iaedu)."""
    if (provider or "").strip().lower() == "iaedu":
        return " — gratuito"
    return ""


def _default_modelo_por_provider(provider: str) -> str:
    p = (provider or "").strip().lower()
    if p == "openai":
        return os.environ.get("OPENAI_MODELO_ANALISE", "").strip() or "gpt-4o"
    if p == "iaedu":
        return os.environ.get("IAEDU_MODELO_ANALISE", "").strip() or "gpt-4o"
    return os.environ.get("ANTHROPIC_MODELO_ANALISE", "").strip() or "claude-opus-4-6"


def _default_modelo_cond_por_provider(provider: str) -> str:
    p = (provider or "").strip().lower()
    if p == "openai":
        return os.environ.get("OPENAI_MODELO_CONDENSACAO", "").strip() or "gpt-4o-mini"
    if p == "iaedu":
        return os.environ.get("IAEDU_MODELO_CONDENSACAO", "").strip() or _default_modelo_por_provider(p)
    return os.environ.get("ANTHROPIC_MODELO_CONDENSACAO", "").strip() or "claude-sonnet-4-5"

_COSTS_FILE = OUTPUT_DIR / "_web_costs_monthly.json"
_USAGE_LOG_FILE = OUTPUT_DIR / "_web_usage_log.jsonl"
_COSTS_LOCK = threading.Lock()


class _SafeHtmlWhitelistParser(HTMLParser):
    """Sanitizador HTML simples por whitelist para conteúdos de preview."""

    _ALLOWED_TAGS = {
        "p", "br", "ul", "ol", "li", "strong", "em", "b", "i", "u", "s", "code", "pre", "a"
    }
    _BLOCKED_TAGS = {"script", "style", "iframe", "object", "embed"}
    _ALLOWED_ATTRS = {
        "a": {"href", "title", "target", "rel"},
    }

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self._out: list[str] = []
        self._open_allowed: list[str] = []
        self._blocked_depth = 0

    @staticmethod
    def _safe_href(href: str) -> str:
        href_clean = (href or "").strip()
        if not href_clean:
            return ""
        parsed = urlparse(href_clean)
        if parsed.scheme and parsed.scheme.lower() not in {"http", "https", "mailto"}:
            return ""
        return href_clean

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        t = (tag or "").lower()
        if t in self._BLOCKED_TAGS:
            self._blocked_depth += 1
            return
        if self._blocked_depth > 0:
            return
        if t not in self._ALLOWED_TAGS:
            return

        allowed_attrs = self._ALLOWED_ATTRS.get(t, set())
        clean_attrs: list[str] = []
        for k, v in attrs:
            key = (k or "").lower()
            if key not in allowed_attrs:
                continue
            val = (v or "").strip()
            if t == "a" and key == "href":
                val = self._safe_href(val)
                if not val:
                    continue
            if t == "a" and key == "target":
                # reduzir superfície para apenas nova aba
                if val not in {"_blank"}:
                    continue
            clean_attrs.append(f' {key}="{html.escape(val, quote=True)}"')

        if t == "a" and any(a.startswith(" target=") for a in clean_attrs):
            # proteger links com target _blank
            if not any(a.startswith(" rel=") for a in clean_attrs):
                clean_attrs.append(' rel="noopener noreferrer"')

        self._out.append(f"<{t}{''.join(clean_attrs)}>")
        if t not in {"br"}:
            self._open_allowed.append(t)

    def handle_endtag(self, tag: str) -> None:
        t = (tag or "").lower()
        if t in self._BLOCKED_TAGS:
            if self._blocked_depth > 0:
                self._blocked_depth -= 1
            return
        if self._blocked_depth > 0:
            return
        if t not in self._ALLOWED_TAGS or t in {"br"}:
            return

        for i in range(len(self._open_allowed) - 1, -1, -1):
            if self._open_allowed[i] == t:
                self._open_allowed.pop(i)
                self._out.append(f"</{t}>")
                break

    def handle_data(self, data: str) -> None:
        if self._blocked_depth > 0:
            return
        self._out.append(html.escape(data, quote=False))

    def get_html(self) -> str:
        while self._open_allowed:
            t = self._open_allowed.pop()
            self._out.append(f"</{t}>")
        return "".join(self._out)


def _sanitize_preview_html(raw_html: object) -> str:
    raw = str(raw_html or "")
    parser = _SafeHtmlWhitelistParser()
    try:
        parser.feed(raw)
        parser.close()
        return parser.get_html()
    except Exception:
        return html.escape(raw, quote=False)


# ---------------------------------------------------------------------------
# Injeção de erros de revisão (substituição semântica)
# ---------------------------------------------------------------------------
# Pares (original, substituição) — a substituição produz palavras portuguesas
# válidas que invertem o sentido; não são detetadas pelo corretor ortográfico
# mas são óbvias numa leitura atenta.
_REVIEW_SUBST_PAIRS: list[tuple[str, str]] = [
    ('estudantes',      'docentes'),
    ('estudante',       'docente'),
    ('aprovadas',       'reprovadas'),
    ('aprovados',       'reprovados'),
    ('aprovada',        'reprovada'),
    ('aprovado',        'reprovado'),
    ('irrelevantes',    'relevantes'),   # sentido inverso também
    ('relevantes',      'irrelevantes'),
    ('irrelevante',     'relevante'),
    ('relevante',       'irrelevante'),
    ('incumprimento',   'cumprimento'),
    ('cumprimento',     'incumprimento'),
    ('satisfatórias',   'insatisfatórias'),
    ('satisfatórios',   'insatisfatórios'),
    ('satisfatória',    'insatisfatória'),
    ('satisfatório',    'insatisfatório'),
    ('inadequadas',     'adequadas'),
    ('inadequados',     'adequados'),
    ('inadequada',      'adequada'),
    ('inadequado',      'adequado'),
    ('adequadas',       'inadequadas'),
    ('adequados',       'inadequados'),
    ('adequada',        'inadequada'),
    ('adequado',        'inadequado'),
    ('atingidas',       'omitidas'),
    ('atingidos',       'omitidos'),
    ('atingida',        'omitida'),
    ('atingido',        'omitido'),
    ('obrigatórias',    'facultativas'),
    ('obrigatórios',    'facultativos'),
    ('obrigatória',     'facultativa'),
    ('obrigatório',     'facultativo'),
    ('médias',          'invariâncias'),
    ('média',           'invariância'),
]
# Ordenar por comprimento decrescente: palavras mais longas têm prioridade no regex
_REVIEW_SUBST_PAIRS.sort(key=lambda p: len(p[0]), reverse=True)
_REVIEW_SUBST_MAP: dict[str, str] = {w.lower(): s for w, s in _REVIEW_SUBST_PAIRS}
# Regex combinada — evita matches dentro de tags HTML
_REVIEW_SUBST_RE = re.compile(
    r'(?<![<&/\w])\b(' + '|'.join(re.escape(p[0]) for p in _REVIEW_SUBST_PAIRS) + r')\b(?![^<]*>)',
    re.IGNORECASE,
)
# Nível 1: palavras correntes cuja duplicação é fácil de ignorar na leitura
_REVIEW_DUP_WORDS: list[str] = [
    "de", "da", "do", "das", "dos", "a", "o", "as", "os",
    "e", "em", "no", "na", "nos", "nas", "ao", "à",
    "que", "com", "para", "por", "se", "ou", "mais",
]
_REVIEW_DUP_RE = re.compile(
    r'(?<![<&/\w])\b(' + '|'.join(re.escape(w) for w in _REVIEW_DUP_WORDS) + r')\b(?![^<]*>)',
    re.IGNORECASE,
)


def _inject_review_errors_multi(
    fields: dict[str, str], total_count: int, seed: str, level: int = 2
) -> tuple[dict[str, str], dict[str, list[dict]]]:
    """Injeta *total_count* erros distribuídos entre vários campos.

    fields: {"programa": html, "resultados": html, "funcionamento": html}
    Retorna (campos_modificados, erros_por_campo).
    level=1: duplicação de palavras correntes ("de de", "a a", …).
             Cada erro: {"word": "de", "duplicate": "de de"}.
    level=2: substituições semânticas ("aprovados" → "reprovados", …).
             Cada erro: {"original": "aprovados", "replacement": "reprovados"}.
    Usa seed determinístico para que reloads não alterem os erros.
    """
    if total_count <= 0:
        return dict(fields), {k: [] for k in fields}

    pattern_re = _REVIEW_DUP_RE if level == 1 else _REVIEW_SUBST_RE

    candidates: list[tuple[str, re.Match]] = []
    for field_name, html_text in fields.items():
        for m in pattern_re.finditer(html_text):
            candidates.append((field_name, m))

    if not candidates:
        return dict(fields), {k: [] for k in fields}

    rng = random.Random(seed)
    chosen = rng.sample(candidates, min(total_count, len(candidates)))

    by_field: dict[str, list[re.Match]] = {k: [] for k in fields}
    for field_name, m in chosen:
        by_field[field_name].append(m)

    result_fields: dict[str, str] = {}
    result_errors: dict[str, list[dict]] = {}
    for field_name, html_text in fields.items():
        matches = by_field[field_name]
        matches.sort(key=lambda m: m.start(), reverse=True)
        errors: list[dict] = []
        text = html_text
        for m in matches:
            original = m.group(0)
            if level == 1:
                replacement = original + " " + original
                errors.append({"word": original, "duplicate": replacement})
            else:
                replacement = _REVIEW_SUBST_MAP.get(original.lower(), original)
                # Preservar maiúscula inicial
                if original and original[0].isupper() and replacement:
                    replacement = replacement[0].upper() + replacement[1:]
                errors.append({"original": original, "replacement": replacement})
            text = text[: m.start()] + replacement + text[m.end() :]
        errors.reverse()
        result_fields[field_name] = text
        result_errors[field_name] = errors

    return result_fields, result_errors


def _count_persisting_errors(html_text: str, errors: list[dict]) -> int:
    """Conta quantas substituições injetadas ainda persistem no texto."""
    count = 0
    for err in errors:
        repl = err.get("replacement") or err.get("duplicate", "")
        if repl and re.search(r'\b' + re.escape(repl) + r'\b', html_text, re.IGNORECASE):
            count += 1
    return count


def _remove_injected_errors(html_text: str, errors: list[dict]) -> str:
    """Reverte substituições semânticas injetadas que ainda persistam no texto."""
    for err in errors:
        repl = err.get("replacement") or err.get("duplicate", "")
        orig = err.get("original") or err.get("word", "")
        if repl and orig:
            html_text = re.sub(
                r'\b' + re.escape(repl) + r'\b',
                orig,
                html_text,
                count=1,
                flags=re.IGNORECASE,
            )
    return html_text


def _esc(v: object) -> str:
    return html.escape(str(v), quote=True)


def _format_ano_servico(ano: object) -> str:
    """Formata ano curricular de serviço docente para mostrar sufixo 'A'.

    Exemplos:
      '1'  -> '1ºA'
      '1º' -> '1ºA'
      '2'  -> '2ºA'
    """
    s = str(ano or "").strip()
    m = re.match(r"^(\d+)\s*º?$", s)
    if m:
        return f"{m.group(1)}ºA"
    return s


def _format_ano_letivo_display(ano: object) -> str:
    """Formata ano letivo para display curto (ex: 2025 -> 2025/26)."""
    s = str(ano or "").strip()
    if not s:
        return "-"
    if re.match(r"^\d{4}/\d{2,4}$", s):
        return s
    if re.match(r"^\d{4}$", s):
        y = int(s)
        return f"{y}/{(y + 1) % 100:02d}"
    return s


def _format_periodo_display(periodo: object) -> str:
    """Formata período SIGARRA para leitura humana na UI.

    Exemplos:
      1S -> 1ºS
      2S -> 2ºS
      1T -> 1ºT
      2T -> 2ºT
      3T -> 3ºT
      A  -> Anual
    """
    s = str(periodo or "").strip().upper()
    mapa = {
        "1S": "1ºS",
        "2S": "2ºS",
        "1T": "1ºT",
        "2T": "2ºT",
        "3T": "3ºT",
        "A": "Anual",
    }
    return mapa.get(s, str(periodo or "").strip())


def _format_epoca_display(epoca: object) -> str:
    """Formata época de avaliação para leitura humana na UI."""
    raw = str(epoca or "").strip()
    if not raw:
        return "Não definida"

    s = raw.upper()
    mapa = {
        "N": "Normal",
        "NORMAL": "Normal",
        "R": "Recurso",
        "RECURSO": "Recurso",
        "AD": "Avaliação Distribuída",
        "AVALIACAO DISTRIBUIDA": "Avaliação Distribuída",
        "AVALIAÇÃO DISTRIBUÍDA": "Avaliação Distribuída",
    }
    return mapa.get(s, raw)


def _extract_horas_preview(campos: dict, chave: str) -> str:
    """Obtém horas do payload (lista/str) e devolve string legível."""
    v = campos.get(chave, "")
    if isinstance(v, list):
        return ", ".join(str(x) for x in v if str(x).strip()) or "-"
    return str(v or "-")


def _uc_titulo_html(nome: str, sigla: str, ano: str = "") -> str:
    """Título da UC: sigla em negrito + nome truncado com ellipsis + ano letivo.

    Usa flex para garantir que sigla e ano nunca são cortados,
    enquanto o nome longo encolhe com text-overflow: ellipsis.
    """
    nome_esc = _esc(nome or "(sem nome)")
    ano_html = f'<span class="uc-ano-tag"> — {_esc(ano)}</span>' if ano else ""
    if sigla:
        sigla_esc = _esc(sigla)
        return (
            f'<p class="uc-card-title">'
            f'<span class="uc-sigla-tag">{sigla_esc}</span>'
            f'<span class="uc-nome-tag"> — {nome_esc}</span>'
            f'{ano_html}'
            f'</p>'
        )
    return (
        f'<p class="uc-card-title">'
        f'<span class="uc-sigla-tag">{nome_esc}</span>'
        f'{ano_html}'
        f'</p>'
    )


def _slug(texto: str) -> str:
    s = re.sub(r"\s+", "-", str(texto or "").strip().lower())
    s = re.sub(r"[^a-z0-9\-_]+", "", s)
    return s.strip("-_")


def _extrair_custo_estimado_valor(log_path: Path) -> float:
    try:
        txt = log_path.read_text(encoding="utf-8", errors="replace")
    except Exception:
        return 0.0
    
    matches = re.findall(r"Custo estimado:\s*\$([0-9]+(?:\.[0-9]+)?)", txt)
    if not matches:
        return 0.0

    total = 0.0
    for m in matches:
        try:
            total += float(m)
        except ValueError:
            continue

    return total


def _dir_size_bytes(path: Path) -> int:
    total = 0
    for p in path.rglob("*"):
        if p.is_file():
            try:
                total += p.stat().st_size
            except OSError:
                pass
    return total


_PRUNE_LOCK = threading.Lock()


def _active_run_dirs() -> set[str]:
    """Devolve os caminhos absolutos de run_dir de jobs activos (não terminados)."""
    with _JOBS_LOCK:
        return {
            str(j.run_dir.resolve())
            for j in _JOBS.values()
            if j.run_dir and not j.done
        }


def _prune_output_dir() -> None:
    if not OUTPUT_DIR.exists():
        return

    # Serializar limpezas concorrentes
    if not _PRUNE_LOCK.acquire(blocking=False):
        return  # outra limpeza já em curso — saltar

    try:
        active = _active_run_dirs()

        def _is_safe(d: Path) -> bool:
            return str(d.resolve()) not in active

        # 1) Retenção por idade
        if WEB_OUTPUT_RETENTION_HOURS > 0:
            cutoff = time.time() - WEB_OUTPUT_RETENTION_HOURS * 3600
            for d in OUTPUT_DIR.iterdir():
                if not d.is_dir() or not _is_safe(d):
                    continue
                try:
                    if d.stat().st_mtime < cutoff:
                        shutil.rmtree(d, ignore_errors=True)
                except OSError:
                    continue

        # 2) Limite de espaço total
        if WEB_OUTPUT_MAX_GB > 0:
            max_bytes = int(WEB_OUTPUT_MAX_GB * 1024 * 1024 * 1024)
            try:
                dirs = [d for d in OUTPUT_DIR.iterdir() if d.is_dir() and _is_safe(d)]
                dirs.sort(key=lambda p: p.stat().st_mtime if p.exists() else 0)
            except OSError:
                dirs = []
            total = sum(_dir_size_bytes(d) for d in dirs)
            while total > max_bytes and dirs:
                oldest = dirs.pop(0)
                size_old = _dir_size_bytes(oldest)
                shutil.rmtree(oldest, ignore_errors=True)
                total = max(0, total - size_old)
    finally:
        _PRUNE_LOCK.release()


def _month_key_utc() -> str:
    return datetime.utcnow().strftime("%Y-%m")


def _load_costs_store() -> dict:
    if not _COSTS_FILE.exists():
        return {"month": _month_key_utc(), "users": {}}
    try:
        data = json.loads(_COSTS_FILE.read_text(encoding="utf-8"))
        if not isinstance(data, dict):
            raise ValueError("invalid store")
        month = str(data.get("month", "")).strip() or _month_key_utc()
        users = data.get("users", {})
        if not isinstance(users, dict):
            users = {}
        return {"month": month, "users": users}
    except Exception:
        return {"month": _month_key_utc(), "users": {}}


def _save_costs_store(data: dict) -> None:
    _COSTS_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = _COSTS_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(_COSTS_FILE)


def _append_usage_event(
    user_code: str,
    oc_id: str,
    custo_usd: float,
    job_id: str,
    duracao_total_s: float,
    llm_provider: str = "",
    llm_modelo: str = "",
) -> None:
    """Regista evento de utilização persistente (append-only)."""
    evento = {
        "timestamp_utc": datetime.utcnow().isoformat(timespec="seconds") + "Z",
        "user_code": user_code,
        "ocorrencia_id": oc_id,
        "job_id": job_id,
        "custo_usd": round(float(custo_usd), 6),
        "duracao_total_s": round(float(duracao_total_s), 3),
        "llm_provider": (llm_provider or "").strip().lower(),
        "llm_modelo": (llm_modelo or "").strip(),
    }
    with _COSTS_LOCK:
        _USAGE_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        with _USAGE_LOG_FILE.open("a", encoding="utf-8") as f:
            f.write(json.dumps(evento, ensure_ascii=False) + "\n")


def _user_cost_month(user_code: str) -> float:
    if not user_code:
        return 0.0
    month = _month_key_utc()
    with _COSTS_LOCK:
        data = _load_costs_store()
        if data.get("month") != month:
            data = {"month": month, "users": {}}
            _save_costs_store(data)
        try:
            return float(data.get("users", {}).get(user_code, 0.0))
        except (TypeError, ValueError):
            return 0.0


def _add_user_cost_month(user_code: str, usd: float) -> None:
    if not user_code or usd <= 0:
        return
    month = _month_key_utc()
    with _COSTS_LOCK:
        data = _load_costs_store()
        if data.get("month") != month:
            data = {"month": month, "users": {}}
        users = data.setdefault("users", {})
        atual = users.get(user_code, 0.0)
        try:
            atual = float(atual)
        except (TypeError, ValueError):
            atual = 0.0
        users[user_code] = round(atual + usd, 6)
        _save_costs_store(data)


def _user_has_cost_bypass(user_code: str, user_login: str = "") -> bool:
    """Valida bypass de custos por código pessoal ou login SIGARRA.

    Aceita entradas em WEB_COST_BYPASS_USERS como, por exemplo:
      - jpf
      - up202012345
      - 202012345
    """
    candidatos: set[str] = set()

    code = str(user_code or "").strip().lower()
    if code:
        candidatos.add(code)
        candidatos.add(f"up{code}")

    login = str(user_login or "").strip().lower()
    if login:
        candidatos.add(login)
        # Se for email (ex: jpf@fe.up.pt), também verificar a parte local ("jpf")
        if "@" in login:
            candidatos.add(login.split("@")[0])

    if not candidatos:
        return False

    return any(c in WEB_COST_BYPASS_USERS for c in candidatos)


def _max_usd_per_user_per_month() -> float:
    """Lê limite mensal atual do ambiente (permite override por env)."""
    try:
        return float(
            os.environ.get(
                "WEB_MAX_USD_PER_USER_PER_MONTH",
                os.environ.get("WEB_MAX_USD_PER_USER_PER_DAY", "0"),
            )
        )
    except ValueError:
        return 0.0


def _new_csrf_token() -> str:
    token = secrets.token_urlsafe(24)
    flask_session["csrf_token"] = token
    return token


def _get_csrf_token() -> str:
    token = flask_session.get("csrf_token")
    if not token:
        token = _new_csrf_token()
    return token


def _require_csrf() -> None:
    sent = request.form.get("csrf_token", "")
    expected = flask_session.get("csrf_token", "")
    if not expected or not sent or sent != expected:
        abort(400, "CSRF token inválido")


def _get_sigarra_session() -> Optional[SigarraSession]:
    sid = flask_session.get("sigarra_sid")
    if not sid:
        return None
    with _SESSOES_LOCK:
        return _SESSOES.get(sid)


def _set_sigarra_session(sess: SigarraSession) -> None:
    sid = secrets.token_urlsafe(16)
    sess._created_at = time.time()  # para expiração automática em _reap_expired_sessions
    with _SESSOES_LOCK:
        _SESSOES[sid] = sess
    flask_session["sigarra_sid"] = sid


def _clear_sigarra_session() -> None:
    sid = flask_session.pop("sigarra_sid", None)
    if sid:
        with _SESSOES_LOCK:
            _SESSOES.pop(sid, None)


def _is_job_owner(job: Tarefa, sess: SigarraSession) -> bool:
    """Valida se o job pertence ao utilizador autenticado."""
    owner = (job.user_code or "").strip()
    current = (sess.codigo_pessoal or "").strip()
    return bool(owner and current and owner == current)


@app.before_request
def _before_request():
    flask_session.permanent = True


@app.after_request
def _secure_headers(resp: Response):
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    resp.headers["Cache-Control"] = "no-store"
    resp.headers["Pragma"] = "no-cache"
    # CSP conservadora para esta app (com script inline existente)
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "base-uri 'none'; "
        "object-src 'none'; "
        "form-action 'self'; "
        "img-src 'self' data:; "
        "style-src 'self' 'unsafe-inline'; "
        "script-src 'self'; "
        "connect-src 'self'; "
        "frame-ancestors 'none';"
    )
    return resp


_STEPPER_LABELS = ["Seleção", "Geração", "Revisão", "Submissão"]


def _stepper_html(step: int, logout_url: str = "") -> str:
    """Gera HTML do stepper-bar. step: 0=nenhum, 1=Seleção, 2=Geração, 3=Revisão, 4=Submissão."""
    if step < 1:
        return ""
    parts: list[str] = []
    for i, label in enumerate(_STEPPER_LABELS, 1):
        if i < step:
            cls = "stepper-step done"
            num = "&#10003;"  # checkmark
        elif i == step:
            cls = "stepper-step active"
            num = str(i)
        else:
            cls = "stepper-step"
            num = str(i)
        if i > 1:
            parts.append('<span class="stepper-arrow">&#8250;</span>')
        # Seleção (i==1) clicável quando já foi completado
        if i == 1 and i < step:
            ucs_url = url_for('ucs')
            parts.append(
                f'<a class="stepper-step done stepper-link" href="{ucs_url}" data-slow-ucs-nav="1" data-slow-ucs-loading-text="A carregar...">'
                f'<span class="stepper-num">{num}</span>'
                f'<span class="stepper-label">{label}</span>'
                f'</a>'
            )
        else:
            parts.append(
                f'<span class="{cls}">'
                f'<span class="stepper-num">{num}</span>'
                f'<span class="stepper-label">{label}</span>'
                f'</span>'
            )
    sair_html = ""
    if logout_url:
        sair_html = f'<a class="stepper-sair" href="{_esc(logout_url)}">Sair</a>'
    return (
        '<div class="stepper-bar">'
        '<div class="stepper">' + "".join(parts) + '</div>'
        + sair_html +
        '</div>'
    )


def _page(title: str, body: str, step: int = 0) -> str:
    logout_url = url_for('logout') if step >= 1 else ""
    stepper = _stepper_html(step, logout_url=logout_url)
    return f"""<!doctype html>
<html lang="pt">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Geração de Relatórios de UCs</title>
  <link rel="icon" type="image/svg+xml" href="{url_for('favicon_svg')}">
  <style>
    :root {{
      --bg: #f3f4f6;
      --panel: #ffffff;
      --fg: #111827;
      --muted: #6b7280;
      --line: #d1d5db;
      --ok: #16a34a;
      --warn: #d97706;
      --err: #dc2626;
      --accent: #2563eb;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      font-family: Inter, Segoe UI, Arial, sans-serif;
      margin: 0;
      color: var(--fg);
      background: var(--bg);
      line-height: 1.45;
    }}
    .container {{ max-width: 980px; margin: 24px auto 44px; padding: 0 18px; }}
    .app-header {{ margin: 0 0 14px; }}
    .app-brandrow {{ display:flex; align-items:center; gap:10px; flex-wrap:wrap; }}
    .app-brand {{ font-size: 18px; font-weight: 800; letter-spacing: .2px; }}
    .app-subtitle {{ margin-top: 2px; color: var(--muted); font-size: 13px; }}
    .page-title {{ margin: 0 0 16px; font-size: 20px; font-weight: 750; letter-spacing: .1px; }}
    h3 {{ margin: 0 0 10px; font-size: 16px; }}
    .card {{
      background: var(--panel);
      border: 1px solid var(--line);
      border-radius: 12px;
      padding: 14px 15px;
      margin: 10px 0;
    }}
    .row {{ display: flex; gap: 10px; flex-wrap: wrap; align-items: center; }}
    .form-row-inline {{ display:flex; align-items:center; gap:10px; margin-top:10px; min-width:0; }}
    .form-row-inline label {{ flex-shrink:0; min-width:150px; margin:0; }}
    .form-row-inline select {{ flex:1; min-width:0; max-width:600px; padding-left:7px; padding-right:7px; }}
.form-grid {{
      display: grid;
      grid-template-columns: minmax(0, 1fr) 380px;
      gap: 12px;
      align-items: end;
    }}
    @media (max-width: 900px) {{
      .form-grid {{ grid-template-columns: 1fr; }}
    }}
    .select-wide {{ width: 100%; min-width: 0; }}
    .statusbar {{ display:flex; flex-wrap:wrap; gap:8px; align-items:center; }}
    .preview-html {{
      background: #f9fafb;
      border: 1px solid var(--line);
      border-radius: 12px;
      padding: 14px;
      font-size: 13px; 
    }}
    .preview-html[contenteditable="true"] {{
      background: #fff;
      border-color: var(--accent);
      box-shadow: 0 0 0 2px rgba(59,130,246,.15);
      outline: none;
      min-height: 80px;
    }}
    .preview-html p {{ margin: 0 0 10px; }}
    .preview-html p:last-child {{ margin-bottom: 0; }}
    .editable-header {{
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 8px;
    }}
    .upload-list {{
      font-size: 13px;
    }}
    .editable-header h3 {{ margin: 0; }}
    .btn-edit {{
      background: transparent;
      color: var(--muted);
      border: 1px solid var(--line);
      padding: 3px 10px;
      font-size: 12px;
      font-weight: 500;
      border-radius: 6px;
      cursor: pointer;
    }}
    .btn-edit:hover {{ background: #f3f4f6; color: var(--fg); }}
    .btn-edit.editing {{
      background: var(--accent);
      color: #fff;
      border-color: var(--accent);
    }}
    .edit-controls {{
      display: inline-flex;
      align-items: center;
      gap: 8px;
      flex-wrap: wrap;
    }}
    .edit-counter {{
      display: none;
      font-size: 12px;
      color: var(--muted);
      padding: 2px 6px;
      border: 1px solid var(--line);
      border-radius: 6px;
      background: #fff;
    }}
    .edit-counter.over-limit {{
      color: var(--err);
      border-color: var(--err);
      background: #fef2f2;
    }}
    .btn-cancel-edit {{
      display: none;
      background: transparent;
      color: var(--muted);
      border: 1px solid var(--line);
      padding: 3px 10px;
      font-size: 12px;
      font-weight: 500;
      border-radius: 6px;
      cursor: pointer;
    }}
    .btn-cancel-edit:hover {{
      background: #f3f4f6;
      color: var(--fg);
    }}
    .edit-toolbar {{
      display: none;
      flex-wrap: wrap;
      gap: 2px;
      padding: 6px 8px;
      background: #f9fafb;
      border: 1px solid var(--accent);
      border-bottom: none;
      border-radius: 12px 12px 0 0;
    }}
    .edit-toolbar.visible {{
      display: flex;
    }}
    .edit-toolbar + .preview-html[contenteditable="true"] {{
      border-radius: 0 0 12px 12px;
    }}
    .edit-toolbar button {{
      background: transparent;
      border: 1px solid transparent;
      border-radius: 4px;
      padding: 3px 7px;
      font-size: 13px;
      cursor: pointer;
      color: var(--fg);
      line-height: 1;
      min-width: 28px;
    }}
    .edit-toolbar button:hover {{
      background: #e5e7eb;
    }}
    .edit-toolbar .sep {{
      width: 1px;
      background: var(--line);
      margin: 2px 4px;
      align-self: stretch;
    }}
    .muted {{ color: var(--muted); font-size: 13px; }}
    .mutedsmall {{ color: var(--muted); font-size: 12px; }}
    .uc-card-title {{
      margin: 0;
      display: flex;
      align-items: baseline;
      min-width: 0;
      overflow: hidden;
      gap: 0;
    }}
    .uc-sigla-tag {{ font-weight: normal; flex-shrink: 0; white-space: nowrap; }}
    .uc-nome-tag {{
      font-weight: normal;
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
      min-width: 0;
      flex: 0 1 auto;
    }}
    .uc-ano-tag {{ font-weight: normal; flex-shrink: 0; white-space: nowrap; }}
    .card {{ overflow: hidden; }}
    label {{ color: var(--muted); }}
    input, select {{
      padding: 9px 11px;
      font-size: 14px;
      color: var(--fg);
      background: #ffffff;
      border: 1px solid var(--line);
      border-radius: 9px;
      outline: none;
    }}
    input:focus, select:focus {{ border-color: var(--accent); box-shadow: 0 0 0 2px rgba(59,130,246,.25); }}
    button, .btn {{
      padding: 9px 13px;
      font-size: 14px;
      cursor: pointer;
      background: var(--accent);
      color: #fff;
      border: 0;
      border-radius: 9px;
      font-weight: 650;
      text-decoration: none;
      display: inline-flex;
      align-items: center;
      gap: 8px;
      line-height: 1.1;
    }}
    button:hover, .btn:hover {{ filter: brightness(1.05); text-decoration: none; }}
    .btn-secondary {{
      background: #fff;
      color: var(--accent);
      border: 1px solid var(--line);
    }}
    .btn-secondary:hover {{ filter: none; background: #f9fafb; }}
    pre {{
      white-space: pre-wrap;
      background: #f9fafb;
      color: #1f2937;
      font-size: 0.875rem;
      line-height: 1.5;
      padding: 12px;
      border-radius: 10px;
      overflow-x: auto;
      height: 26em;
      overflow-y: auto;
      border: 1px solid var(--line);
    }}
    a {{ color: #1d4ed8; text-decoration: none; }}
    a:hover {{ text-decoration: underline; }}
    code {{ background: #f3f4f6; border: 1px solid var(--line); padding: 2px 6px; border-radius: 6px; }}
    .pill {{ display:inline-block; padding: 3px 10px; border-radius: 999px; background:#f3f4f6; border:1px solid var(--line); color: var(--muted); }}
    .status-ok {{ color: #15803d; }}
    .status-err {{ color: #b91c1c; }}
    .status-run {{ color: #1d4ed8; }}
    ul {{ margin: 8px 0 0 18px; padding: 0; }}
    li {{ margin: 4px 0; }}
    .input-with-suffix {{ display:flex; align-items:center; gap:8px; width:320px; max-width:100%; }}
    .input-with-suffix input {{ width:100%; }}
    .input-suffix {{ color: var(--muted); font-size: 13px; white-space: nowrap; }}
    .stepper-bar {{
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin: 0 0 18px;
      gap: 12px;
    }}
    .stepper-sair {{
      font-size: 13px;
      color: var(--muted);
      text-decoration: none;
      white-space: nowrap;
      padding: 4px 10px;
      border: 1px solid var(--line);
      border-radius: 7px;
      background: var(--panel);
      transition: background .15s;
    }}
    .stepper-sair:hover {{ background: #f3f4f6; text-decoration: none; }}
    .stepper {{
      display: flex;
      align-items: center;
      gap: 0;
      font-size: 13px;
      color: var(--muted);
    }}
    .stepper-step {{
      display: flex;
      align-items: center;
      gap: 6px;
    }}
    .stepper-num {{
      display: inline-flex;
      align-items: center;
      justify-content: center;
      width: 22px; height: 22px;
      border-radius: 50%;
      border: 1.5px solid var(--line);
      font-size: 11px;
      font-weight: 600;
      color: var(--muted);
      background: var(--bg);
      flex-shrink: 0;
    }}
    .stepper-step.active .stepper-num {{
      background: var(--accent);
      border-color: var(--accent);
      color: #fff;
    }}
    .stepper-step.active .stepper-label {{
      color: var(--fg);
      font-weight: 600;
    }}
    .stepper-step.done .stepper-num {{
      background: var(--ok);
      border-color: var(--ok);
      color: #fff;
    }}
    .stepper-arrow {{
      margin: 0 10px;
      color: var(--line);
      font-size: 14px;
    }}
    a.stepper-link {{
      text-decoration: none;
      cursor: pointer;
    }}
    a.stepper-link:hover .stepper-label {{
      text-decoration: underline;
    }}
    @keyframes spin {{ to {{ transform: rotate(360deg); }} }}
    .is-loading {{
      pointer-events: none;
      opacity: .7;
    }}
    .is-loading::after {{
      content: "";
      display: inline-block;
      width: 14px; height: 14px;
      margin-left: 6px;
      border: 2px solid currentColor;
      border-top-color: transparent;
      border-radius: 50%;
      animation: spin .6s linear infinite;
      vertical-align: middle;
    }}
    .navbar {{
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 10px;
    }}
    .navbar-left {{ display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }}
    .navbar-right {{ display: flex; gap: 8px; align-items: center; flex-wrap: wrap; }}
  </style>
</head>
<body>
  <div class="container">
    <div class="app-header">
      <div class="app-brandrow">
        <div class="app-brand">Assistente de Apoio à Elaboração de Relatórios de Unidades Curriculares</div>
        <span class="pill">Piloto</span>
      </div>
      <div class="app-subtitle">FEUP · Melhoria Contínua</div>
    </div>
    {stepper}
    {f'<h1 class="page-title">{_esc(title)}</h1>' if not step else ''}
    {body}
  </div>
  <script src="{url_for('static_app_js')}" defer></script>
</body>
</html>"""

@app.get("/favicon.svg")
def favicon_svg():
    """Ícone da aplicação para separador do browser."""
    svg = """<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'>
  <defs>
    <linearGradient id='g' x1='0' y1='0' x2='1' y2='1'>
      <stop offset='0%' stop-color='#2563eb'/>
      <stop offset='100%' stop-color='#1d4ed8'/>
    </linearGradient>
  </defs>
  <rect x='4' y='4' width='56' height='56' rx='12' fill='url(#g)'/>
  <text x='32' y='39' text-anchor='middle' font-size='22' font-family='Arial, sans-serif' fill='white' font-weight='700'>UC</text>
</svg>"""
    return Response(svg, mimetype="image/svg+xml")


@app.get("/static/app.js")
def static_app_js():
    """JS único (sem inline) para cumprir CSP: script-src 'self'."""
    js = r"""
// app.js — UI helper (CSP-friendly: sem inline)

function _byId(id) { return document.getElementById(id); }

function setupLogin() {
  const form = _byId('login-form');
  if (!form) return;
  form.addEventListener('submit', () => {
    const btn = _byId('btn-login');
    if (btn) {
      btn.disabled = true;
      btn.classList.add('is-loading');
      btn.textContent = 'A autenticar e carregar serviço docente...';
    }
  });
}

function setupUCSelection() {
  const sel = _byId('ocorrencia_select');
  const hiddenNome = _byId('uc_nome_hidden');
  const hiddenSigla = _byId('uc_sigla_hidden');
  const llmChoiceSel = _byId('llm_choice_select');
  const llmProviderHidden = _byId('llm_provider_hidden');
  const llmModeloHidden = _byId('llm_modelo_hidden');

  if (sel && hiddenNome) {
    const update = () => {
      const opt = sel.options[sel.selectedIndex];
      const txt = (opt && opt.text) ? opt.text : '';
      hiddenNome.value = ((opt && opt.dataset && opt.dataset.nome) ? opt.dataset.nome : (txt.split(' — ')[0] || '')).trim();
      if (hiddenSigla) hiddenSigla.value = ((opt && opt.dataset && opt.dataset.sigla) ? opt.dataset.sigla : '').trim();
    };
    sel.addEventListener('change', update);
    update();
  }

  if (llmChoiceSel && llmProviderHidden && llmModeloHidden) {
    const updateLLMChoice = () => {
      const opt = llmChoiceSel.options[llmChoiceSel.selectedIndex];
      llmProviderHidden.value = ((opt && opt.dataset && opt.dataset.provider) ? opt.dataset.provider : '').trim().toLowerCase();
      llmModeloHidden.value = ((opt && opt.dataset && opt.dataset.modelo) ? opt.dataset.modelo : '').trim();
    };
    llmChoiceSel.addEventListener('change', updateLLMChoice);
    updateLLMChoice();
  }
}

function setupProgressSSE() {
  const pre = _byId('console');
  if (!pre) return;

  const eventsUrl = pre.dataset.eventsUrl;
  if (!eventsUrl) return;

  const shouldReloadOnDone = (pre.dataset.shouldReloadOnDone || 'false') === 'true';
  let doneHandled = false;

  const es = new EventSource(eventsUrl);
  es.onmessage = (ev) => {
    if (!ev.data) return;
    if (ev.data === '__DONE__') {
      es.close();
      if (shouldReloadOnDone && !doneHandled) {
        doneHandled = true;
        const savedLog = pre.textContent;
        fetch(window.location.href)
          .then(r => r.text())
          .then(html => {
            const doc = new DOMParser().parseFromString(html, 'text/html');
            // Atualizar stepper (pode passar a verde)
            const newStepper = doc.querySelector('.stepper-bar');
            const curStepper = document.querySelector('.stepper-bar');
            if (newStepper && curStepper) curStepper.outerHTML = newStepper.outerHTML;
            // Substituir corpo da página de progresso sem flash
            const newPB = doc.getElementById('progress-body');
            const curPB = document.getElementById('progress-body');
            if (newPB && curPB) {
              curPB.outerHTML = newPB.outerHTML;
              // Restaurar log do console (o novo <pre> está vazio)
              const newPre = document.getElementById('console');
              if (newPre && savedLog) newPre.textContent = savedLog;
            }
          })
          .catch(() => window.location.reload());
      }
      return;
    }
    pre.textContent += ev.data;
    pre.scrollTop = pre.scrollHeight;
  };
  es.onerror = () => {
    // tolerar interrupções (reinício do processo / perda temporária de ligação)
  };
}

function setupSlowUCSNavigationHint() {
  const links = document.querySelectorAll('a[data-slow-ucs-nav="1"]');
  if (!links || links.length === 0) return;

  links.forEach((lnk) => {
    lnk.addEventListener('click', () => {
      lnk.classList.add('is-loading');
      const loadingText = (lnk.dataset && lnk.dataset.slowUcsLoadingText)
        ? lnk.dataset.slowUcsLoadingText
        : 'A carregar UCs...';
      lnk.textContent = loadingText;
    });
  });
}

function setupListarUCsWaitHint() {
  const form = _byId('ucs-filter-form');
  if (!form) return;

  const UC_CONTROLS = ['ocorrencia_select', 'llm_choice_select', 'btn-gerar'];

  function setUCControlsDisabled(disabled) {
    UC_CONTROLS.forEach(id => {
      const el = _byId(id);
      if (el) el.disabled = disabled;
    });
  }

  // Restaurar controlos quando página vem do bfcache (eram desabilitados antes de navegar)
  window.addEventListener('pageshow', (ev) => {
    if (!ev.persisted) return;
    setUCControlsDisabled(false);
    const hint = document.getElementById('year-loading-hint');
    if (hint) hint.remove();
  });

  // Auto-submeter quando o ano letivo muda — garante lista sempre sincronizada
  const sel = form.querySelector('select[name="ano_letivo"]');
  if (sel) {
    sel.addEventListener('change', () => {
      setUCControlsDisabled(true);
      const hint = document.createElement('span');
      hint.id = 'year-loading-hint';
      hint.className = 'muted';
      hint.style.cssText = 'margin-left:8px; font-size:13px;';
      hint.textContent = 'A carregar...';
      sel.insertAdjacentElement('afterend', hint);
      form.submit();
    });
  }
}

function setupPreviewEdit() {
  const MAX_CHARS = 4000;
  const btns = document.querySelectorAll('.btn-edit[data-target]');
  if (!btns || btns.length === 0) return;

  const edited = {};    // campos que foram editados
  const origHtml = {};  // HTML original para cancelar

  const form = _byId('confirm-form');
  const submitBtn = form ? form.querySelector('button[type="submit"]') : null;

  function hasPendingEdits() {
    return Array.from(btns).some((btn) => {
      const target = _byId(btn.dataset.target);
      return target && target.contentEditable === 'true';
    });
  }

  function hasOverLimit() {
    const targets = ['edit-programa', 'edit-resultados', 'edit-funcionamento'];
    return targets.some((id) => {
      const el = _byId(id);
      return el && (el.textContent || '').length > MAX_CHARS;
    });
  }

  function updateSubmitState() {
    if (!submitBtn) return;
    const pending = hasPendingEdits();
    const overLimit = hasOverLimit();
    submitBtn.disabled = pending || overLimit;
    if (pending) {
      submitBtn.title = 'Conclua ou cancele as edições pendentes antes de submeter.';
    } else if (overLimit) {
      submitBtn.title = 'Um ou mais campos excedem o limite de 4000 caracteres.';
    } else {
      submitBtn.title = '';
    }
  }

  function updateCounter(targetId) {
    const target = _byId(targetId);
    const counter = _byId('counter-' + targetId);
    if (!target || !counter) return;
    const len = (target.textContent || '').length;
    counter.textContent = len + ' / ' + MAX_CHARS;
    if (len > MAX_CHARS) {
      counter.classList.add('over-limit');
    } else {
      counter.classList.remove('over-limit');
    }
    updateSubmitState();
  }

  function startEdit(btn, targetId) {
    const target = _byId(targetId);
    const toolbar = _byId('toolbar-' + targetId);
    const counter = _byId('counter-' + targetId);
    const cancelBtn = _byId('cancel-' + targetId);
    if (!target) return;
    origHtml[targetId] = target.innerHTML;
    target.contentEditable = 'true';
    document.execCommand('defaultParagraphSeparator', false, 'p');
    target.focus();
    btn.textContent = 'Concluir';
    btn.classList.add('editing');
    if (toolbar) toolbar.classList.add('visible');
    if (counter) counter.style.display = 'inline-flex';
    if (cancelBtn) cancelBtn.style.display = 'inline-flex';
    updateCounter(targetId);
    target.addEventListener('input', function onInput() { updateCounter(targetId); });
    target._onInput = function() { updateCounter(targetId); };
    updateSubmitState();
  }

  function finishEdit(btn, targetId) {
    const target = _byId(targetId);
    const toolbar = _byId('toolbar-' + targetId);
    const counter = _byId('counter-' + targetId);
    const cancelBtn = _byId('cancel-' + targetId);
    if (!target) return;
    target.contentEditable = 'false';
    btn.textContent = 'Editar';
    btn.classList.remove('editing');
    if (toolbar) toolbar.classList.remove('visible');
    if (counter) counter.style.display = 'none';
    if (cancelBtn) cancelBtn.style.display = 'none';
    edited[targetId] = true;
    updateSubmitState();
  }

  function cancelEdit(btn, targetId) {
    const target = _byId(targetId);
    const editBtn = document.querySelector('.btn-edit[data-target="' + targetId + '"]');
    if (!target) return;
    target.innerHTML = origHtml[targetId] || target.innerHTML;
    if (editBtn) finishEdit(editBtn, targetId);
    delete edited[targetId];  // não foi realmente editado
    updateCounter(targetId);
    updateSubmitState();
  }

  btns.forEach((btn) => {
    btn.addEventListener('click', () => {
      const targetId = btn.dataset.target;
      const target = _byId(targetId);
      if (!target) return;
      if (target.contentEditable === 'true') {
        finishEdit(btn, targetId);
      } else {
        startEdit(btn, targetId);
      }
    });
  });

  // Botões de cancelar
  document.querySelectorAll('.btn-cancel-edit').forEach((cb) => {
    cb.addEventListener('click', () => {
      cancelEdit(cb, cb.dataset.target);
    });
  });

  // Botões de formatação da toolbar
  document.querySelectorAll('.edit-toolbar button[data-cmd]').forEach((tbBtn) => {
    tbBtn.addEventListener('click', (e) => {
      e.preventDefault();
      document.execCommand(tbBtn.dataset.cmd, false, null);
    });
  });

  // Inicialização dos contadores e estado do submit
  ['edit-programa', 'edit-resultados', 'edit-funcionamento'].forEach((id) => updateCounter(id));
  updateSubmitState();

  // Sincronizar conteúdo editado para hidden fields antes do submit
  if (!form) return;
  form.addEventListener('submit', (e) => {
    const mapping = [
      ['edit-programa', 'field-programa'],
      ['edit-resultados', 'field-resultados'],
      ['edit-funcionamento', 'field-funcionamento'],
    ];
    // Impedir submissão com edição pendente
    if (hasPendingEdits()) {
      e.preventDefault();
      alert('Existem campos em edição. Clique em "Concluir" ou "Cancelar" antes de submeter.');
      updateSubmitState();
      return;
    }
    // Verificar limite de caracteres
    let overLimit = false;
    mapping.forEach(([editId]) => {
      const el = _byId(editId);
      if (el && (el.textContent || '').length > MAX_CHARS) {
        overLimit = true;
      }
    });
    if (overLimit) {
      e.preventDefault();
      alert('Um ou mais campos excedem o limite de ' + MAX_CHARS + ' caracteres. Reduza o texto antes de submeter.');
      return;
    }
    mapping.forEach(([editId, fieldId]) => {
      const el = _byId(editId);
      const field = _byId(fieldId);
      if (el && field && edited[editId]) {
        field.value = el.innerHTML;
      }
    });
  });
}

document.addEventListener('DOMContentLoaded', () => {
  setupLogin();
  setupUCSelection();
  setupProgressSSE();
  setupSlowUCSNavigationHint();
  setupListarUCsWaitHint();
  setupPreviewEdit();
});
"""
    resp = Response(js, mimetype="application/javascript; charset=utf-8")
    # No-store por consistência com o resto da app.
    resp.headers["Cache-Control"] = "no-store"
    return resp


@app.get("/")
def home():
    sess = _get_sigarra_session()
    if not sess:
        return redirect(url_for("login"))
    return redirect(url_for("ucs"))


@app.get("/login")
def login():
    body = f"""
    <div class="card">
      <p style="margin-top:14px;">
        <a href="{url_for('login_oidc')}" style="font-size:1.1em;">Autenticação Federada U.Porto</a>
      </p>
      <p class="muted"><a href="{url_for('privacidade')}">Política de privacidade e proteção de dados</a></p>
    </div>
    """
    return _page("Login", body)


@app.get("/privacidade")
def privacidade():
    body = f"""
    <div class="card">
      <h3>Política de privacidade e proteção de dados</h3>

      <p class="muted">
        Esta aplicação encontra-se em fase piloto de teste e validação institucional. Os conteúdos gerados com apoio
        de modelos de inteligência artificial podem conter imprecisões e devem ser sempre revistos e confirmados
        pelo utilizador antes da sua utilização ou submissão oficial.
      </p>

      <h4>Enquadramento institucional</h4>
      <p>
        A aplicação é disponibilizada no âmbito das atividades de melhoria contínua do ensino da FEUP,
        sob responsabilidade institucional da Direção da FEUP, através do pelouro responsável pela área da
        Melhoria Contínua. A aplicação apenas permite a análise e geração de relatórios relativos a unidades
        curriculares (UCs) para as quais o utilizador autenticado possui permissões institucionais de regência.
      </p>

      <h4>Autenticação e comunicação segura</h4>
      <p>
        A autenticação é efetuada exclusivamente através de <b>Autenticação Federada (OpenID Connect)</b>:
        as credenciais são submetidas diretamente ao Fornecedor de Identidade da Universidade do Porto
        (via Keycloak/open-id.up.pt), através de um formulário servido por essa infraestrutura.
        A aplicação nunca recebe nem processa as credenciais do utilizador — apenas recebe um token
        de autenticação emitido pelo IdP após autenticação bem-sucedida.
      </p>
      <p>
        Toda a comunicação entre o utilizador e a aplicação é protegida através de ligações cifradas (HTTPS/TLS),
        assegurando a confidencialidade e integridade dos dados em trânsito.
      </p>

      <h4>Dados acedidos pela aplicação</h4>
      <p>
        A sessão autenticada é usada para aceder a informação restrita necessária à análise da UC,
        consistindo exclusivamente em dados institucionais e estatísticas agregadas (não sendo efetuado tratamento
        de dados individuais de estudantes), incluindo, quando disponível:
      </p>
      <ul>
        <li>sumários da UC;</li>
        <li>conteúdos e enunciados no Moodle;</li>
        <li>enunciados no SIGARRA (no relatório da UC);</li>
        <li>estatísticas agregadas de resultados de avaliação da UC, da ocorrência anterior e de outras UCs do mesmo ano do curso;</li>
        <li>resultados agregados dos inquéritos pedagógicos da UC e da ocorrência anterior.</li>
      </ul>

      <h4>Utilização de modelos de linguagem (LLM)</h4>
      <p>
        A aplicação utiliza modelos de linguagem de grande escala (LLM) que, com base nos dados recolhidos,
        apoiam a geração do relatório da UC. O relatório gerado é apresentado ao utilizador para revisão,
        sendo a sua submissão ao SIGARRA efetuada apenas após confirmação explícita do utilizador.
        As garantias de privacidade e proteção de dados aplicáveis dependem do fornecedor selecionado:
      </p>
      <ul>
        <li>
        <b>Via IAedu:</b> o processamento é efetuado através da infraestrutura Microsoft Azure AI Foundry disponibilizada
        pelo serviço IAedu da FCT/FCCN (sem custos diretos para a unidade orgânica utilizadora), limitado aos modelos aí
        disponibilizados. De acordo com a respetiva <a href="https://iaedu.pt/pt/politica-de-privacidade-e-protecao-de-dados" target="_blank" rel="noopener noreferrer">política de privacidade</a>, 
        os dados não são armazenados, registados, transmitidos a terceiros, utilizados para treino de modelos ou conservados sob qualquer forma.
        </li>
<li>
  <b>Via Anthropic API:</b> o processamento é efetuado através da API comercial da Anthropic.
  De acordo com a <a href="https://privacy.claude.com/en/collections/10672411-data-handling-retention">informação pública atualmente disponibilizada</a>, os dados enviados não são utilizados para treino de modelos,  podendo ser objeto de retenção temporária 
  (limitada por defeito a 30 dias) para fins de monitorização de segurança e prevenção de abuso.
          Quando aplicável, os custos de utilização são suportados institucionalmente pela FEUP,
        podendo ser definidos limites de utilização por utilizador no âmbito de políticas de utilização responsável.

</li>
<li>
  <b>Via OpenAI API:</b> o processamento é efetuado através da API comercial da OpenAI.
  De acordo com a <a href="https://developers.openai.com/api/docs/guides/your-data">informação pública atualmente disponibilizada</a>, os dados enviados não são utilizados para treino de modelos, podendo ser objeto de retenção temporária
  (limitada por defeito a 30 dias) para fins de monitorização de segurança e prevenção de abuso.
        Quando aplicável, os custos de utilização são suportados institucionalmente pela FEUP,
        podendo ser definidos limites de utilização por utilizador no âmbito de políticas de utilização responsável.
</li>
      </ul>

      <h4>Registos técnicos e auditoria</h4>
      <p>
        Para fins de auditoria técnica, monitorização operacional e controlo de custos de utilização dos serviços LLM,
        são mantidos registos técnicos persistentes contendo apenas metadados de execução, incluindo o código do
        utilizador, o código da ocorrência da UC, data e hora da execução, identificador técnico da
        operação, modelo utilizado e custo estimado. Não são armazenados conteúdos processados nem credenciais de autenticação.
        Estes registos são utilizados exclusivamente para fins operacionais, de auditoria e gestão de custos.
      </p>

      <h4>Retenção e exportação de dados</h4>
      <p>
        Os dados gerados durante a execução podem ser exportados pelo utilizador em formato <code>.zip</code>.
        Estes dados são removidos automaticamente do disco após um período máximo de
        {WEB_OUTPUT_RETENTION_HOURS:.3g} hora(s) de retenção configurado no servidor.
      </p>

      <p class="muted">
        O código-fonte desta ferramenta é público e auditável em
        <a href="https://github.com/joaopascoalfariafeup/ucreports" target="_blank" rel="noopener">github.com/joaopascoalfariafeup/ucreports</a>.
      </p>

      <p class="muted"><a href="{url_for('login')}">Voltar ao login</a></p>
    </div>
    """
    return _page("Política de privacidade e proteção de dados", body)



@app.get("/login/oidc")
def login_oidc():
    """Inicia o fluxo OIDC redirecionando para Keycloak UP."""
    cfg = _oidc_config()
    if not cfg["client_id"]:
        return _page("Erro", """<div class="card"><p>Autenticação federada OIDC não configurada.</p></div>""")

    # Gerar estado CSRF com expiração de 5 minutos
    with _OIDC_STATES_LOCK:
        now = time.time()
        for k in [k for k, v in _OIDC_STATES.items() if v < now]:
            del _OIDC_STATES[k]
        state = secrets.token_urlsafe(24)
        _OIDC_STATES[state] = now + 300

    params = urllib.parse.urlencode({
        "client_id":     cfg["client_id"],
        "response_type": "code",
        "redirect_uri":  cfg["redirect_uri"],
        "scope":         "openid email profile",
        "state":         state,
        "response_mode": "query",
        "kc_idp_hint":   "saml",
    })
    resp = Response("", status=302)
    resp.headers["Location"] = f"{cfg['auth_endpoint']}?{params}"
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
    resp.headers["Pragma"] = "no-cache"
    return resp


@app.get("/login/oidc/callback")
def login_oidc_callback():
    """Callback OIDC: troca code por tokens, obtém sessão SIGARRA."""
    cfg = _oidc_config()

    error = request.args.get("error")
    if error:
        desc = request.args.get("error_description", "")
        return _page("Autenticação Federada", f"""
        <div class="card">
          <p><b>Erro na autenticação:</b> {_esc(desc or error)}</p>
          <p><a href="{url_for('login')}">Voltar ao login</a></p>
        </div>""")

    code  = request.args.get("code",  "").strip()
    state = request.args.get("state", "").strip()

    with _OIDC_STATES_LOCK:
        if not state or _OIDC_STATES.pop(state, 0) < time.time():
            return _page("Autenticação Federada", f"""
            <div class="card">
              <p><b>Sessão expirada ou inválida.</b></p>
              <p><a href="{url_for('login_oidc')}">Tentar novamente</a></p>
            </div>""")

    # Trocar authorization_code por tokens
    try:
        payload = urllib.parse.urlencode({
            "grant_type":   "authorization_code",
            "code":          code,
            "redirect_uri":  cfg["redirect_uri"],
            "client_id":     cfg["client_id"],
            "client_secret": cfg["client_secret"],
        }).encode()
        req = _urllib_req.Request(
            cfg["token_endpoint"],
            data=payload,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        with _urllib_req.urlopen(req, timeout=15) as resp:
            token_data = json.loads(resp.read().decode())
    except Exception as e:
        app.logger.warning("login_oidc_callback: erro ao trocar token: %s", e)
        return _page("Autenticação Federada", f"""
        <div class="card">
          <p><b>Erro ao contactar servidor de autenticação:</b> {_esc(str(e))}</p>
          <p><a href="{url_for('login_oidc')}">Tentar novamente</a></p>
        </div>""")

    # Extrair preferred_username do id_token (JWT)
    username = ""
    id_token = token_data.get("id_token", "")
    if id_token:
        try:
            parts = id_token.split(".")
            if len(parts) >= 2:
                padded = parts[1] + "=" * (4 - len(parts[1]) % 4)
                claims = json.loads(base64.urlsafe_b64decode(padded))
                username = claims.get("preferred_username") or claims.get("sub") or ""
        except Exception:
            pass

    # Normalizar: "up210006@up.pt" → "210006"
    if "@" in username:
        username = username.split("@")[0]
    if username.lower().startswith("up"):
        codigo = username[2:]
    else:
        codigo = username

    if not codigo:
        return _page("Autenticação Federada", f"""
        <div class="card">
          <p><b>Não foi possível identificar o utilizador UP.</b></p>
          <p><a href="{url_for('login')}">Usar login SIGARRA</a></p>
        </div>""")

    # Tentar obter sessão SIGARRA via access_token Bearer
    user_sess = None
    flask_session.pop("oidc_sess_debug", None)
    _at = token_data.get("access_token", "")
    try:
        user_sess = SigarraSession.from_oidc_token(_at, codigo)
        flask_session["oidc_sess_debug"] = "ok"
        app.logger.info("login_oidc_callback: sessão SIGARRA obtida para %s", codigo)
    except Exception as e:
        app.logger.warning("login_oidc_callback: %s", e)
        flask_session["oidc_sess_debug"] = str(e)

    # Fallback: clonar sessão do servidor
    if user_sess is None:
        try:
            server_sess = _get_server_session()
        except Exception as e:
            app.logger.warning("login_oidc_callback: sessão servidor indisponível: %s", e)
            return _page("Autenticação Federada", f"""
            <div class="card">
              <p><b>Serviço temporariamente indisponível.</b> Tente mais tarde.</p>
              <p><a href="{url_for('login')}">Usar login SIGARRA</a></p>
            </div>""")
        user_sess = server_sess.clone_para_utilizador(codigo)
        flask_session["oidc_sess_type"] = "clone"
    else:
        flask_session["oidc_sess_type"] = "direct"

    _set_sigarra_session(user_sess)
    flask_session["sigarra_login"] = username + "@up.pt" if "@" not in username else username
    flask_session["login_method"] = "oidc"
    return redirect(url_for("ucs"))


@app.get("/logout")
def logout():
    _clear_sigarra_session()
    flask_session.pop("sigarra_login", None)
    return redirect(url_for("login"))


@app.get("/ucs")
def ucs():
    sess = _get_sigarra_session()
    if not sess:
        return _page("Sessão expirada", f"""
        <div class="card">
          <p>A sua sessão local expirou (ou o processo reiniciou). Faça login novamente.</p>
          <p><a href="{url_for('login')}">Ir para login</a></p>
        </div>
        """)

    # usa sempre o utilizador autenticado no SIGARRA
    doc_codigo = (sess.codigo_pessoal or "").strip()
    ano_letivo = request.args.get("ano_letivo", "").strip()  # ex: 2025
    force_refresh = request.args.get("refresh", "").strip() == "1"

    ucs_list = None
    anos_disponiveis: list[dict] = []
    ano_letivo_resolvido = ""
    docente_nome = ""
    erro = ""
    from_cache = False

    if doc_codigo:
        # Tentar cache para o ano pedido (ou "" se ainda não há ano resolvido)
        cache_key = (doc_codigo, ano_letivo)
        if not force_refresh:
            with _UCS_CACHE_LOCK:
                entry = _UCS_CACHE.get(cache_key)
            if entry:
                ts, anos_disponiveis, ucs_list, meta = entry
                if time.time() - ts < _UCS_CACHE_TTL_S:
                    ano_letivo_resolvido = (meta.get("ano_letivo_resolvido") or "").strip()
                    docente_nome = (meta.get("docente_nome") or "").strip()
                    from_cache = True
                    # Sincronizar dropdown: se não veio ano na URL, recuperar do meta
                    if not ano_letivo:
                        m_ano = re.search(r"(\d{4})/", ano_letivo_resolvido)
                        if m_ano:
                            ano_letivo = m_ano.group(1)
                        elif anos_disponiveis:
                            ano_letivo = (anos_disponiveis[0].get("ano_inicio") or "").strip()
                else:
                    with _UCS_CACHE_LOCK:
                        _UCS_CACHE.pop(cache_key, None)

        if not from_cache:
            try:
                anos_disponiveis = _gera_lista_anos_letivos()

                ucs_list, meta = extrair_ocorrencias_servico_docente(
                    sessao=sess,
                    doc_codigo=doc_codigo,
                    ano_letivo=ano_letivo or None,
                    incluir_meta=True,
                    apenas_regente_docente=_ACESSO_APENAS_REGENTE,
                )
                ano_letivo_resolvido = (meta.get("ano_letivo_resolvido") or "").strip()
                docente_nome = (meta.get("docente_nome") or "").strip()

                # Se o utilizador não indicou ano:
                # 1) tentar o ano inicial resolvido no cabeçalho SIGARRA
                # 2) fallback para o primeiro ano da lista SIGARRA
                if not ano_letivo and ano_letivo_resolvido:
                    m_ano = re.search(r"(\d{4})/\d{4}", ano_letivo_resolvido)
                    if m_ano:
                        ano_letivo = m_ano.group(1)
                if not ano_letivo and anos_disponiveis:
                    ano_letivo = (anos_disponiveis[0].get("ano_inicio") or "").strip()

                # Se o ano mudou por default, recarregar lista de UCs com esse ano explícito.
                if ano_letivo:
                    ucs_list, meta = extrair_ocorrencias_servico_docente(
                        sessao=sess,
                        doc_codigo=doc_codigo,
                        ano_letivo=ano_letivo,
                        incluir_meta=True,
                        apenas_regente_docente=_ACESSO_APENAS_REGENTE,
                    )
                    ano_letivo_resolvido = (meta.get("ano_letivo_resolvido") or "").strip()
                    docente_nome = (meta.get("docente_nome") or "").strip()

                # Guardar no cache — incluir chave vazia para hits sem ano explícito
                entry = (time.time(), anos_disponiveis, ucs_list, meta)
                with _UCS_CACHE_LOCK:
                    _UCS_CACHE[(doc_codigo, ano_letivo)] = entry
                    if ano_letivo:
                        _UCS_CACHE[(doc_codigo, "")] = entry
            except Exception as e:
                erro = str(e)
    else:
        erro = "Não foi possível determinar o código pessoal do utilizador autenticado no SIGARRA."

    if anos_disponiveis:
        options_anos = "\n".join(
            f'<option value="{_esc(a.get("ano_inicio", ""))}"'
            f'{" selected" if (a.get("ano_inicio", "") == ano_letivo) else ""}>'
            f'{_esc(a.get("ano_letivo", a.get("ano_inicio", "")))}'
            f"</option>"
            for a in anos_disponiveis
        )
    else:
        options_anos = (
            '<option value="" selected>(anos não disponíveis)</option>'
        )

    docente_label = "-"
    if docente_nome and doc_codigo:
        docente_label = f"{docente_nome} ({doc_codigo})"
    elif docente_nome:
        docente_label = docente_nome

    body = f"""
    <div class="card">
      <div class="muted" style="margin-bottom:14px;">Regente: {_esc(docente_label)}</div>
      <form id="ucs-filter-form" method="get" action="{url_for('ucs')}">
        <div class="form-row-inline">
          <label>Ano letivo:</label>
          <select name="ano_letivo" style="max-width:130px;flex:0 1 auto;">
            {options_anos}
          </select>
        </div>
      </form>
    """

    if erro:
        body += f'<p class="status-err" style="margin-top:12px;"><b>Erro ao listar UCs:</b> {_esc(erro)}</p>'

    if ucs_list:
        csrf = _get_csrf_token()
        provider_opts = _llm_provider_options()
        model_map = _llm_model_options_map()
        provider_default = (os.environ.get("LLM_PROVIDER", "anthropic") or "anthropic").strip().lower()
        if provider_default not in provider_opts and provider_opts:
            provider_default = provider_opts[0]

        llm_choices: list[dict[str, str]] = []
        for p in provider_opts:
            modelos = model_map.get(p) or [_default_modelo_por_provider(p)]
            for m in modelos:
                val = f"{p}::{m}"
                label = f"{p} / {m}{_format_model_cost(p)}"
                llm_choices.append({"provider": p, "modelo": m, "value": val, "label": label})

        # Default da combobox:
        # 1) última seleção do utilizador (flask_session)
        # 2) WEB_LLM_DEFAULT_CHOICE (ex.: "iaedu::gpt-4o")
        # 3) fallback para a 1ª opção da lista (respeitando a ordem configurada)
        default_choice = (os.environ.get("WEB_LLM_DEFAULT_CHOICE", "") or "").strip()
        valid_choices = {c["value"] for c in llm_choices}
        if default_choice not in valid_choices:
            default_choice = llm_choices[0]["value"] if llm_choices else ""
        last_llm_choice = flask_session.get("last_llm_choice", "")
        if last_llm_choice in valid_choices:
            default_choice = last_llm_choice
        last_oc_id = flask_session.get("last_oc_id", "")

        default_provider = provider_default
        default_model = _default_modelo_por_provider(default_provider)
        if "::" in default_choice:
            dp, dm = default_choice.split("::", 1)
            default_provider = dp.strip().lower() or default_provider
            default_model = dm.strip() or default_model

        llm_choice_option_tags = "\n".join(
            f'<option value="{_esc(c["value"])}"'
            + (" selected" if c["value"] == default_choice else "")
            + f' data-provider="{_esc(c["provider"])}" data-modelo="{_esc(c["modelo"])}">{_esc(c["label"])}</option>'
            for c in llm_choices
        )
        model_options_json = json.dumps(model_map, ensure_ascii=False).replace("</", "<\\/")
        default_analise_json = json.dumps(
            {p: _default_modelo_por_provider(p) for p in provider_opts},
            ensure_ascii=False,
        ).replace("</", "<\\/")
        default_cond_json = json.dumps(
            {p: _default_modelo_cond_por_provider(p) for p in provider_opts},
            ensure_ascii=False,
        ).replace("</", "<\\/")
        # UC pré-selecionada: última usada (se existir na lista atual), senão a primeira
        uc_presel = next((u for u in ucs_list if u["ocorrencia_id"] == last_oc_id), None) or (ucs_list[0] if ucs_list else None)
        option_parts = []
        for u in ucs_list:
            sigla = u.get("sigla_uc", u.get("sigla", ""))
            sigla_prefix = f'{_esc(sigla)} — ' if sigla else ""
            option_parts.append(
                f'<option value="{u["ocorrencia_id"]}" data-sigla="{_esc(sigla)}" data-nome="{_esc(u["nome_uc"])}"'
                f'{" selected" if u is uc_presel else ""}>'
                f'{sigla_prefix}{_esc(u["nome_uc"])} — {_esc(u["curso"])} — {_esc(_format_ano_servico(u["ano"]))} — {_esc(_format_periodo_display(u["periodo"]))} '
                f"</option>"
            )
        options = "\n".join(option_parts)
        primeira_uc = uc_presel.get("nome_uc", "") if uc_presel else ""
        primeira_sigla = uc_presel.get("sigla_uc", uc_presel.get("sigla", "")) if uc_presel else ""

        body += f"""
          <form method="post" action="{url_for('start_job')}" style="margin-top:14px;">
            <input type="hidden" name="csrf_token" value="{_esc(csrf)}">
            <input type="hidden" name="ano_letivo" value="{ano_letivo}">
            <input type="hidden" name="uc_nome" id="uc_nome_hidden" value="{_esc(primeira_uc)}">
            <input type="hidden" name="uc_sigla" id="uc_sigla_hidden" value="{_esc(primeira_sigla)}">
            <input type="hidden" name="llm_provider" id="llm_provider_hidden" value="{_esc(provider_default)}">
            <input type="hidden" name="llm_modelo" id="llm_modelo_hidden" value="{_esc(default_model)}">

            <div class="form-row-inline">
              <label for="ocorrencia_select">Unidade curricular:</label>
              <select name="ocorrencia_id" id="ocorrencia_select" required>
                {options}
              </select>
            </div>

            <div class="form-row-inline">
              <label for="llm_choice_select">Modelo:</label>
              <select name="llm_choice" id="llm_choice_select" required style="max-width:220px;">
                {llm_choice_option_tags}
              </select>
            </div>
            <p class="muted" style="margin:6px 0 0 160px;font-size:0.88em;">Sugestão: use o modelo gratuito para testes e o claude-opus-4-6 para o relatório final.</p>
            <div class="row" style="justify-content:flex-start; margin-top:12px;">
              <button class="btn" id="btn-gerar" type="submit">Gerar relatório</button>
            </div>
          </form>
        """

    body += """
    </div>
    """
#      <p class="muted" style="margin-top:14px;">(*) Restrito às UCs em que o docente autenticado é regente.</p>
#      <p class="mutedsmall">Devido a limitações atuais da ligação SIGARRA-Moodle, o Moodle só é acedido para o ano corrente.</p>

    return _page("Seleção da Unidade Curricular", body, step=1)


def _run_job(job: Tarefa, sess: SigarraSession, verbosidade: int) -> None:
    """Executa a análise e marca o job como concluído."""
    try:
        with AuditoriaLogger(job.log_path, verbosidade=verbosidade) as log:
            if job.action == "submit":
                submeter_preview_uc(
                    job.oc_id,
                    sess,
                    log,
                    output_dir=OUTPUT_DIR,
                    run_dir=job.run_dir,
                )
            else:
                analisar_uc(
                    job.oc_id,
                    sess,
                    log,
                    output_dir=OUTPUT_DIR,
                    submeter=False,
                    run_dir=job.run_dir,
                    llm_provider=job.llm_provider,
                    llm_modelo=job.llm_modelo,
                    llm_modelo_condensacao=job.llm_modelo_condensacao,
                )
        job.ok = True
    except Exception as e:
        job.ok = False
        job.error = str(e)
        # tentar escrever o erro no log também
        try:
            job.log_path.parent.mkdir(parents=True, exist_ok=True)
            with job.log_path.open("a", encoding="utf-8", errors="replace") as f:
                f.write(f"\n# erro-sistema: {job.error}\n")
        except Exception:
            pass
    finally:
        # Atualizar custo mensal por utilizador (apenas análise/preview)
        if job.action == "preview" and job.log_path.exists() and job.user_code:
            custo_job = _extrair_custo_estimado_valor(job.log_path)
            duracao_total_s = max(0.0, time.time() - float(job.started_at or 0.0))
            _add_user_cost_month(job.user_code, custo_job)
            _append_usage_event(
                job.user_code,
                job.oc_id,
                custo_job,
                job.job_id,
                duracao_total_s,
                job.llm_provider,
                job.llm_modelo,
            )
        job.done = True


_DRAINING_FILE = _SCRIPT_DIR / ".draining"


@app.post("/start")
def start_job():
    _require_csrf()
    sess = _get_sigarra_session()
    if not sess:
        return redirect(url_for("login"))

    if _DRAINING_FILE.exists():
        return _page("Manutenção", f"""
        <div class="card">
          <p class="status-err"><b>Servidor em manutenção.</b>
          Não é possível iniciar novas análises neste momento.</p>
          <p class="muted">O servidor será reiniciado em breve. Tente novamente dentro de alguns minutos.</p>
          <p><a class="btn btn-secondary" href="{url_for('ucs')}">Voltar à seleção</a></p>
        </div>"""), 503

    oc_id = request.form.get("ocorrencia_id", "").strip()
    uc_nome = request.form.get("uc_nome", "").strip()
    ano_letivo = request.form.get("ano_letivo", "").strip()
    uc_sigla = request.form.get("uc_sigla", "").strip()
    llm_provider = request.form.get("llm_provider", "").strip().lower()
    llm_modelo = request.form.get("llm_modelo", "").strip()
    llm_choice = request.form.get("llm_choice", "").strip()
    llm_modelo_cond = request.form.get("llm_modelo_condensacao", "").strip()
    verb = WEB_VERBOSIDADE
    if not oc_id or not re.fullmatch(r'\d{1,10}', oc_id):
        return redirect(url_for("ucs"))

    # Novo formato simplificado: "provider::modelo"
    if llm_choice and "::" in llm_choice:
        p, m = llm_choice.split("::", 1)
        llm_provider = p.strip().lower()
        llm_modelo = m.strip()

    # Guardar última seleção para pré-selecionar ao voltar à página
    flask_session["last_oc_id"] = oc_id
    flask_session["last_llm_choice"] = llm_choice or f"{llm_provider}::{llm_modelo}"

    providers_validos = _llm_provider_options()
    if llm_provider not in providers_validos:
        llm_provider = (os.environ.get("LLM_PROVIDER", "anthropic") or "anthropic").strip().lower()
        if llm_provider not in providers_validos and providers_validos:
            llm_provider = providers_validos[0]
    if not llm_modelo:
        llm_modelo = _default_modelo_por_provider(llm_provider)
    if not llm_modelo_cond:
        llm_modelo_cond = _default_modelo_cond_por_provider(llm_provider)

    # housekeeping de privacidade/espaço
    _prune_output_dir()

    user_code = (sess.codigo_pessoal or "").strip()
    user_login = str(flask_session.get("sigarra_login", "")).strip()
    max_usd_mes = _max_usd_per_user_per_month()
    if max_usd_mes >= 0 and user_code and not _user_has_cost_bypass(user_code, user_login):
        usado = _user_cost_month(user_code)
        if usado >= max_usd_mes:
            if llm_provider not in WEB_FREE_LLM_PROVIDERS_SET:
                free_list = ", ".join(WEB_FREE_LLM_PROVIDERS_LIST) or "(nenhum)"
                return _page("Limite mensal", f"""
                <div class="card">
                  <p class="status-err"><b>Limite mensal atingido:</b> ${usado:.2f} / ${max_usd_mes:.2f}</p>
                  <p class="muted">Com limite atingido, apenas são permitidos providers gratuitos: <code>{_esc(free_list)}</code>.</p>
                  <p><a class="btn btn-secondary" data-slow-ucs-nav="1" href="{url_for('ucs')}">Voltar à seleção</a></p>
                </div>
                """), 429

    if not uc_sigla:
        try:
            ficha = extrair_ficha_uc(oc_id, sess)
            uc_sigla = str(ficha.get("sigla_uc", "")).strip()
        except Exception:
            uc_sigla = ""

    job_id = secrets.token_urlsafe(12)
    ts = time.strftime("%Y%m%d-%H%M%S")
    sigla_slug = _slug(uc_sigla).replace(".", "").replace(":", "") if uc_sigla else ""
    base_slug = sigla_slug or _slug(uc_nome) or f"oc-{oc_id}"
    # job_id garante unicidade mesmo que dois pedidos caiam no mesmo segundo
    run_dir = OUTPUT_DIR / f"{base_slug}__{oc_id}__{ts}__{job_id}"
    log_path = run_dir / "auditoria_web.log"
    log_path.parent.mkdir(parents=True, exist_ok=True)

    # (re)iniciar log
    try:
        log_path.write_text("", encoding="utf-8")
    except Exception:
        pass

    job = Tarefa(
        job_id=job_id,
        oc_id=oc_id,
        uc_nome=uc_nome,
        uc_sigla=uc_sigla,
        ano_letivo=ano_letivo,
        user_code=user_code,
        llm_provider=llm_provider,
        llm_modelo=llm_modelo,
        llm_modelo_condensacao=llm_modelo_cond,
        log_path=log_path,
        started_at=time.time(),
        run_dir=run_dir,
        action="preview",
    )
    with _JOBS_LOCK:
        em_execucao = sum(1 for j in _JOBS.values() if not j.done)
        if em_execucao >= MAX_RUNNING_JOBS:
            return _page("Capacidade temporariamente atingida", f"""
            <div class="card">
              <p class="status-err"><b>Capacidade atingida:</b> já existem {em_execucao} tarefa(s) em execução.</p>
              <p class="muted">Tenta novamente dentro de instantes.</p>
              <p><a class="btn btn-secondary" data-slow-ucs-nav="1" href="{url_for('ucs')}">Voltar à seleção</a></p>
            </div>
            """), 429

        _JOBS[job_id] = job
        _evict_old_jobs_locked()

    t = threading.Thread(target=_run_job, args=(job, sess, verb), daemon=True)
    t.start()

    return redirect(url_for("progress", job_id=job_id))


@app.post("/confirm/<job_id>")
def confirm_submit(job_id: str):
    _require_csrf()
    sess = _get_sigarra_session()
    if not sess:
        return redirect(url_for("login"))

    with _JOBS_LOCK:
        prev_job = _JOBS.get(job_id)
        if not prev_job or not prev_job.done or not prev_job.ok or prev_job.action != "preview":
            return _page("Confirmação", f"""
            <div class="card">
              <p class="status-err">Preview ainda não está pronto para submissão.</p>
              <p><a class="btn btn-secondary" data-slow-ucs-nav="1" href="{url_for('ucs')}">Voltar à seleção</a></p>
            </div>
            """), 400
        if not _is_job_owner(prev_job, sess):
            return _page("Acesso negado", """
            <div class="card">
              <p class="status-err">Não tens permissões para este job.</p>
              <p><a href="/ucs">Voltar</a></p>
            </div>
            """), 403

    # Aplicar edições do utilizador ao preview_payload.json (se alteradas)
    edit_programa = request.form.get("edit_programa", "").strip()
    edit_resultados = request.form.get("edit_resultados", "").strip()
    edit_funcionamento = request.form.get("edit_funcionamento", "").strip()
    preview_path = (prev_job.run_dir or (OUTPUT_DIR / prev_job.oc_id)) / "preview_payload.json"
    try:
        payload = json.loads(preview_path.read_text(encoding="utf-8"))
    except Exception:
        payload = {}
    campos = payload.get("campos", {})

    if edit_programa or edit_resultados or edit_funcionamento:
        if edit_programa:
            payload["programa_efetivo"] = edit_programa
            campos["pv_rel_programa"] = edit_programa
        if edit_resultados:
            payload["comentarios_resultados"] = edit_resultados
            campos["pv_rel_coment_res"] = edit_resultados
        if edit_funcionamento:
            payload["comentarios_funcionamento"] = edit_funcionamento
            campos["pv_rel_coment_func"] = edit_funcionamento
        payload["campos"] = campos

    # Aplicar edições de horas
    horas_prev_list = campos.get("parr_horas_prev", [])
    if not isinstance(horas_prev_list, list):
        horas_prev_list = [horas_prev_list]
    horas_efec_list = campos.get("parr_horas_efec", [])
    if not isinstance(horas_efec_list, list):
        horas_efec_list = [horas_efec_list]
    n_horas = max(len(horas_prev_list), len(horas_efec_list))
    novas_prev = list(horas_prev_list)
    novas_efec = list(horas_efec_list)
    for i in range(n_horas):
        vp = request.form.get(f"horas_prev_{i}")
        ve = request.form.get(f"horas_efec_{i}")
        if vp is not None and i < len(novas_prev):
            novas_prev[i] = vp.strip()
        if ve is not None and i < len(novas_efec):
            novas_efec[i] = ve.strip()
    if novas_prev != horas_prev_list or novas_efec != horas_efec_list:
        campos["parr_horas_prev"] = novas_prev
        campos["parr_horas_efec"] = novas_efec
        payload["campos"] = campos

    # Filtrar enunciados desmarcados pelo utilizador
    enunciados_upload = payload.get("enunciados_para_upload", [])
    if enunciados_upload and any(f"enun_check_{i}" in request.form for i in range(len(enunciados_upload))):
        payload["enunciados_para_upload"] = [
            e for i, e in enumerate(enunciados_upload)
            if request.form.get(f"enun_check_{i}")
        ]

    # Verificar erros de revisão injetados
    review_errors = payload.get("_review_errors")
    if _REVIEW_ERROR_INJECTION and review_errors:
        # Textos actuais (editados pelo utilizador ou originais do payload)
        txt_p = edit_programa or payload.get("_programa_com_erros", payload.get("programa_efetivo", ""))
        txt_r = edit_resultados or payload.get("_resultados_com_erros", payload.get("comentarios_resultados", ""))
        txt_f = edit_funcionamento or payload.get("_funcionamento_com_erros", payload.get("comentarios_funcionamento", ""))
        persisting = (
            _count_persisting_errors(txt_p, review_errors.get("programa", []))
            + _count_persisting_errors(txt_r, review_errors.get("resultados", []))
            + _count_persisting_errors(txt_f, review_errors.get("funcionamento", []))
        )
        if persisting > _REVIEW_ERROR_TOLERANCE:
            return _page("Revisão insuficiente", f"""
            <div class="card">
              <p class="status-err"><b>Os textos não parecem ter sido revistos com atenção.</b></p>
              <p>Há <b>{persisting}</b> gralhas(s) nos campos de texto
                 que deveriam ter sido corrigidas durante a revisão.</p>
              <p class="muted">Volte à pré-visualização e reveja cuidadosamente os 3 campos de texto.</p>
              <p style="margin-top:12px;">
                <a class="btn" href="{url_for('preview', job_id=job_id)}">Voltar à pré-visualização</a>
              </p>
            </div>
            """, step=3)

        # Passou a verificação: limpar erros residuais do texto
        prog = edit_programa or payload.get("programa_efetivo", "")
        resu = edit_resultados or payload.get("comentarios_resultados", "")
        func = edit_funcionamento or payload.get("comentarios_funcionamento", "")
        prog = _remove_injected_errors(prog, review_errors.get("programa", []))
        resu = _remove_injected_errors(resu, review_errors.get("resultados", []))
        func = _remove_injected_errors(func, review_errors.get("funcionamento", []))
        payload["programa_efetivo"] = prog
        payload["comentarios_resultados"] = resu
        payload["comentarios_funcionamento"] = func
        campos["pv_rel_programa"] = prog
        campos["pv_rel_coment_res"] = resu
        campos["pv_rel_coment_func"] = func
        payload["campos"] = campos
        # Remover metadados de injeção
        payload.pop("_review_errors", None)
        payload.pop("_programa_com_erros", None)
        payload.pop("_resultados_com_erros", None)
        payload.pop("_funcionamento_com_erros", None)

    # Registar sumários selecionados para submissão no job de streaming
    sumarios_a_submeter = []
    for s in payload.get("sumarios_sugeridos", []):
        std_id = s.get("std_id", "")
        if not std_id:
            continue
        if request.form.get(f"sum_check_{std_id}"):
            texto = request.form.get(f"sum_texto_{std_id}", "").strip()
            if texto:
                sumarios_a_submeter.append({
                    "std_id": std_id,
                    "texto": texto,
                    "data_iso": s.get("data_iso", ""),
                    "turma": s.get("turma", ""),
                    "numero": s.get("numero", ""),
                })
    if sumarios_a_submeter:
        payload["sumarios_a_submeter"] = sumarios_a_submeter

    # Guardar payload atualizado
    try:
        tmp = preview_path.with_suffix(".tmp")
        tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp.replace(preview_path)
    except Exception:
        pass

    sub_job_id = secrets.token_urlsafe(12)
    sub_run_dir = prev_job.run_dir or (OUTPUT_DIR / prev_job.oc_id)
    sub_log_path = sub_run_dir / "auditoria_submit_web.log"
    sub_log_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        sub_log_path.write_text("", encoding="utf-8")
    except Exception:
        pass

    sub_job = Tarefa(
        job_id=sub_job_id,
        oc_id=prev_job.oc_id,
        uc_nome=prev_job.uc_nome,
        uc_sigla=prev_job.uc_sigla,
        ano_letivo=prev_job.ano_letivo,
        user_code=prev_job.user_code,
        llm_provider=prev_job.llm_provider,
        llm_modelo=prev_job.llm_modelo,
        llm_modelo_condensacao=prev_job.llm_modelo_condensacao,
        log_path=sub_log_path,
        started_at=time.time(),
        run_dir=sub_run_dir,
        action="submit",
    )

    with _JOBS_LOCK:
        em_execucao = sum(1 for j in _JOBS.values() if not j.done)
        if em_execucao >= MAX_RUNNING_JOBS:
            return _page("Capacidade temporariamente atingida", f"""
            <div class="card">
              <p class="status-err"><b>Capacidade atingida:</b> já existem {em_execucao} tarefa(s) em execução.</p>
              <p class="muted">Tenta novamente dentro de instantes.</p>
              <p><a href="{url_for('progress', job_id=job_id)}">Voltar ao preview</a></p>
            </div>
            """), 429

        _JOBS[sub_job_id] = sub_job
        _evict_old_jobs_locked()

    t = threading.Thread(target=_run_job, args=(sub_job, sess, WEB_VERBOSIDADE), daemon=True)
    t.start()

    return redirect(url_for("progress", job_id=sub_job_id))


@app.get("/preview/<job_id>")
def preview(job_id: str):
    sess = _get_sigarra_session()
    if not sess:
        return redirect(url_for("login"))

    with _JOBS_LOCK:
        job = _JOBS.get(job_id)
        if not job:
            return _page("Preview", "<div class='card'><p>Tarefa não encontrada.</p></div>"), 404
        if not _is_job_owner(job, sess):
            return _page("Preview", "<div class='card'><p class='status-err'>Acesso negado.</p></div>"), 403

    preview_path = (job.run_dir or (OUTPUT_DIR / job.oc_id)) / "preview_payload.json"
    try:
        payload = json.loads(preview_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return _page("Preview", f"""
        <div class="card">
          <p>Preview ainda não disponível.</p>
          <p><a href="{url_for('progress', job_id=job_id)}">Voltar à geração do relatório</a></p>
        </div>
        """), 404

    programa = _sanitize_preview_html(payload.get("programa_efetivo", ""))
    res = _sanitize_preview_html(payload.get("comentarios_resultados", ""))
    func = _sanitize_preview_html(payload.get("comentarios_funcionamento", ""))

    # Injeção de erros de revisão (se ativa)
    if _REVIEW_ERROR_INJECTION and _REVIEW_ERROR_COUNT > 0:
        existing_errors = payload.get("_review_errors")
        if existing_errors is None:
            # Primeira visualização: injetar e persistir
            fields_in = {"programa": programa, "resultados": res, "funcionamento": func}
            fields_out, review_errors = _inject_review_errors_multi(fields_in, _REVIEW_ERROR_COUNT, job_id, level=_REVIEW_ERROR_INJECTION)
            programa = fields_out["programa"]
            res = fields_out["resultados"]
            func = fields_out["funcionamento"]
            payload["_review_errors"] = review_errors
            # Guardar textos com erros no payload para consistência em reloads
            payload["_programa_com_erros"] = programa
            payload["_resultados_com_erros"] = res
            payload["_funcionamento_com_erros"] = func
            try:
                tmp = preview_path.with_suffix(".tmp")
                tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
                tmp.replace(preview_path)
            except Exception:
                pass
        else:
            # Reload: usar textos com erros já guardados
            programa = payload.get("_programa_com_erros", programa)
            res = payload.get("_resultados_com_erros", res)
            func = payload.get("_funcionamento_com_erros", func)

    campos = payload.get("campos", {})
    tipos_aula = campos.get("_tipos_aula") or []
    horas_prev_list = campos.get("parr_horas_prev", [])
    horas_efec_list = campos.get("parr_horas_efec", [])
    if not isinstance(horas_prev_list, list):
        horas_prev_list = [horas_prev_list]
    if not isinstance(horas_efec_list, list):
        horas_efec_list = [horas_efec_list]
    n_horas = max(len(horas_prev_list), len(horas_efec_list), len(tipos_aula), 1)
    _input_style = "width:5em;padding:2px 4px;border:1px solid #d1d5db;border-radius:4px;font-size:0.95em;"
    _horas_rows = ""
    for i in range(n_horas):
        tipo_label = _esc(tipos_aula[i]) if i < len(tipos_aula) else ""
        vp = _esc(horas_prev_list[i] if i < len(horas_prev_list) else "0")
        ve = _esc(horas_efec_list[i] if i < len(horas_efec_list) else "0")
        tipo_html = f"<span style='min-width:3em;display:inline-block;color:#6b7280;'>{tipo_label}</span> " if tipo_label else ""
        _horas_rows += (
            f"<div style='display:flex;align-items:center;gap:16px;margin:4px 0;'>"
            f"{tipo_html}"
            f"<label style='display:flex;align-items:center;gap:6px;'>"
            f"Previstas <input type='number' step='0.5' min='0' name='horas_prev_{i}' value='{vp}' form='confirm-form' style='{_input_style}'></label>"
            f"<label style='display:flex;align-items:center;gap:6px;'>"
            f"Efetivas <input type='number' step='0.5' min='0' name='horas_efec_{i}' value='{ve}' form='confirm-form' style='{_input_style}'></label>"
            f"</div>"
        )

    enunciados_upload = payload.get("enunciados_para_upload", [])
    if enunciados_upload:
        itens_upload = "".join(
            f"<li style='margin:4px 0;'>"
            f"<label style='display:flex;align-items:baseline;gap:8px;'>"
            f"<input type='checkbox' name='enun_check_{i}' checked form='confirm-form' style='flex-shrink:0;margin-top:2px;'>"
            f"<span>{_esc(e.get('nome', ''))}"
            f"{' — ' + _esc(e.get('descricao', '')) if e.get('descricao') else ''}"
            f" — <strong>Época:</strong> {_esc(_format_epoca_display(e.get('epoca') or e.get('epoca_cod') or e.get('epoca_codigo')))}"
            f"</span></label></li>"
            for i, e in enumerate(enunciados_upload)
        )
        html_upload = f"<ul style='padding-left:4px;list-style:none;margin:0;'>{itens_upload}</ul>"
    else:
        html_upload = "<p class='muted'>Nenhum enunciado novo para upload.</p>"

    ano_letivo_label = _format_ano_letivo_display(job.ano_letivo)
    uc_titulo = _uc_titulo_html(
        payload.get("nome_uc", "") or job.uc_nome,
        payload.get("sigla_uc", "") or job.uc_sigla,
        ano_letivo_label,
    )
    can_submit = job.done and job.ok and job.action == "preview" and not payload.get("sem_acesso_formulario")

    # Aviso se campos de comentários já têm conteúdo no SIGARRA
    _sig_res = payload.get("sigarra_resultados_existente", "").strip()
    _sig_func = payload.get("sigarra_funcionamento_existente", "").strip()
    _campos_com_conteudo = []
    if _sig_res:
        _campos_com_conteudo.append("Comentários aos resultados")
    if _sig_func:
        _campos_com_conteudo.append("Comentários ao funcionamento")
    if _campos_com_conteudo and can_submit:
        _lista_campos = " e ".join(f"<strong>{_esc(c)}</strong>" for c in _campos_com_conteudo)
        aviso_conteudo_existente = f"""
    <div class="card" style="border-color:#f59e0b;background:#fffbeb;">
      <p style="margin:0;">⚠ {_lista_campos} já {'têm' if len(_campos_com_conteudo) > 1 else 'tem'} conteúdo no SIGARRA. Ao confirmar, esse conteúdo será substituído pela análise gerada acima. Por favor reveja antes de submeter.</p>
    </div>"""
    else:
        aviso_conteudo_existente = ""

    excluidos_rgpd = payload.get("enunciados_excluidos_rgpd", [])
    if excluidos_rgpd:
        itens_rgpd = "".join(
            f"<li>{_esc(e['nome'])} — <span class='muted'>{_esc('; '.join(e['motivos']))}</span></li>"
            for e in excluidos_rgpd
        )
        aviso_rgpd = f"""
    <div class="card" style="border-color:#f59e0b;background:#fffbeb;">
      <b>⚠ Enunciados excluídos por precaução RGPD</b>
      <p class="muted" style="margin:6px 0 8px;">Os seguintes ficheiros não foram enviados para o LLM para análise de enunciados por poderem conter dados pessoais de estudantes (nomes, números de matrícula).</p>
      <ul style="margin:0 0 8px;padding-left:18px;">{itens_rgpd}</ul>
      <p class="muted">Sugestão: separe o enunciado de avaliação das listas de estudantes/grupos antes de o carregar no SIGARRA ou Moodle.</p>
    </div>"""
    else:
        aviso_rgpd = ""

    aulas_sem_sumario = payload.get("aulas_sem_sumario", [])
    sumarios_sugeridos = payload.get("sumarios_sugeridos", [])
    if aulas_sem_sumario:
        # Contagem por turma
        turmas_map: dict[str, int] = {}
        for a in aulas_sem_sumario:
            chave = f"{a['turma']} ({a['tipo_aula']})" if a.get("tipo_aula") else a["turma"]
            turmas_map[chave] = turmas_map.get(chave, 0) + 1
        itens_sums = "".join(
            f"<li>{_esc(turma)}: <span class='muted'>{n} aula(s) sem sumário</span></li>"
            for turma, n in turmas_map.items()
        )
        # Sugestões editáveis: apenas aulas com sugestão inferida E std_id para submissão
        sugestoes_html = ""
        sugs_com_std = [s for s in sumarios_sugeridos if s.get("std_id") and s.get("sugestao")]
        if sugs_com_std:
            linhas = []
            for s in sugs_com_std:
                std_id = _esc(s["std_id"])
                turma_label = f"{s.get('turma', '')} ({s.get('tipo_aula', '')})" if s.get("tipo_aula") else s.get("turma", "")
                label = f"Aula {s['numero']} · {s.get('data_iso', s.get('data', ''))} · {_esc(turma_label)}"
                sugestao = _esc(s.get("sugestao", ""))
                checked = "checked" if s.get("sugestao") else ""
                linhas.append(f"""
      <div style="margin:8px 0 4px;">
        <label style="display:flex;align-items:baseline;gap:8px;font-size:0.92em;">
          <input type="checkbox" name="sum_check_{std_id}" {checked} form="confirm-form" style="margin-top:2px;flex-shrink:0;">
          <span>{label}</span>
        </label>
        <textarea name="sum_texto_{std_id}" rows="2" form="confirm-form"
          style="width:100%;margin-top:4px;font-size:0.9em;padding:4px 6px;border:1px solid #d1d5db;border-radius:4px;resize:vertical;"
          >{sugestao}</textarea>
      </div>""")
            sugestoes_html = f"""
      <p class="muted" style="margin:10px 0 4px;">Sugestões do Moodle para aulas por si lecionadas — selecione as que pretende submeter ao SIGARRA:</p>
      {"".join(linhas)}"""
        aviso_sumarios = f"""
    <div class="card" style="border-color:#f59e0b;background:#fffbeb;">
      <b>⚠ Sumários por lançar</b>
      <ul style="margin:6px 0 0;padding-left:18px;">{itens_sums}</ul>{sugestoes_html}
    </div>"""
    else:
        sumarios_sugeridos = []
        aviso_sumarios = ""

    pautas_pendentes = payload.get("pautas_classificacoes_pendentes", [])
    if pautas_pendentes:
        itens_pautas = "".join(
            f"<li>{_esc(p['epoca'])}: <span class='muted'>{p['sem_classificacao']} estudante(s) ainda sem classificação final"
            + (f" (de {p['n_estudantes']})" if p.get("n_estudantes") else "")
            + "</span></li>"
            for p in pautas_pendentes
        )
        aviso_pautas = f"""
    <div class="card" style="border-color:#f59e0b;background:#fffbeb;">
      <b>⚠ Classificações por lançar</b>
      <ul style="margin:6px 0 0;padding-left:18px;">{itens_pautas}</ul>
    </div>"""
    else:
        aviso_pautas = ""

    body = f"""
    <div class="card">
      {uc_titulo}
      <p class="muted">Reveja o conteúdo abaixo antes de submeter ao SIGARRA. Pode editar os campos de texto clicando em «Editar».</p>
      <p class="muted">Depois de submeter, pode ainda editar no SIGARRA.</p>
      <p class="muted" style="margin-top:10px;">
        Legenda: &nbsp;
        🟢 Adequado &nbsp;·&nbsp;
        🟡 Parcialmente adequado &nbsp;·&nbsp;
        🔴 Não adequado &nbsp;·&nbsp;
        ⚫ Sem dados
      </p>
    </div>
    {aviso_rgpd}
    {aviso_sumarios}
    {aviso_pautas}

    <div class="card">
      <p><b>Nº de Horas</b></p>
      {_horas_rows}
      <h3>Enunciados a carregar no SIGARRA</h3>
        <div class="upload-list">
            {html_upload}
        </div>
    </div>

    <div class="card">
      <div class="editable-header">
        <h3>Programa efetivamente lecionado</h3>
        <div class="edit-controls">
          <span id="counter-edit-programa" class="edit-counter">0 / 4000</span>
          <button type="button" id="cancel-edit-programa" class="btn-cancel-edit" data-target="edit-programa">Cancelar</button>
          <button type="button" class="btn-edit" data-target="edit-programa">Editar</button>
        </div>
      </div>
      <div class="edit-toolbar" id="toolbar-edit-programa">
        <button type="button" data-cmd="bold" title="Negrito"><b>B</b></button>
        <button type="button" data-cmd="italic" title="Itálico"><i>I</i></button>
        <button type="button" data-cmd="underline" title="Sublinhado"><u>U</u></button>
        <button type="button" data-cmd="strikeThrough" title="Riscado"><s>S</s></button>
        <span class="sep"></span>
        <button type="button" data-cmd="insertUnorderedList" title="Lista">&#8226; Lista</button>
        <button type="button" data-cmd="insertOrderedList" title="Lista numerada">1. Lista</button>
        <span class="sep"></span>
        <button type="button" data-cmd="removeFormat" title="Limpar formatação">&#10005; Limpar</button>
      </div>
      <div class="preview-html" id="edit-programa">{programa}</div>
    </div>

    <div class="card">
      <div class="editable-header">
        <h3>Comentários — Resultados</h3>
        <div class="edit-controls">
          <span id="counter-edit-resultados" class="edit-counter">0 / 4000</span>
          <button type="button" id="cancel-edit-resultados" class="btn-cancel-edit" data-target="edit-resultados">Cancelar</button>
          <button type="button" class="btn-edit" data-target="edit-resultados">Editar</button>
        </div>
      </div>
      <div class="edit-toolbar" id="toolbar-edit-resultados">
        <button type="button" data-cmd="bold" title="Negrito"><b>B</b></button>
        <button type="button" data-cmd="italic" title="Itálico"><i>I</i></button>
        <button type="button" data-cmd="underline" title="Sublinhado"><u>U</u></button>
        <button type="button" data-cmd="strikeThrough" title="Riscado"><s>S</s></button>
        <span class="sep"></span>
        <button type="button" data-cmd="insertUnorderedList" title="Lista">&#8226; Lista</button>
        <button type="button" data-cmd="insertOrderedList" title="Lista numerada">1. Lista</button>
        <span class="sep"></span>
        <button type="button" data-cmd="removeFormat" title="Limpar formatação">&#10005; Limpar</button>
      </div>
      <div class="preview-html" id="edit-resultados">{res}</div>
    </div>

    <div class="card">
      <div class="editable-header">
        <h3>Comentários — Funcionamento</h3>
        <div class="edit-controls">
          <span id="counter-edit-funcionamento" class="edit-counter">0 / 4000</span>
          <button type="button" id="cancel-edit-funcionamento" class="btn-cancel-edit" data-target="edit-funcionamento">Cancelar</button>
          <button type="button" class="btn-edit" data-target="edit-funcionamento">Editar</button>
        </div>
      </div>
      <div class="edit-toolbar" id="toolbar-edit-funcionamento">
        <button type="button" data-cmd="bold" title="Negrito"><b>B</b></button>
        <button type="button" data-cmd="italic" title="Itálico"><i>I</i></button>
        <button type="button" data-cmd="underline" title="Sublinhado"><u>U</u></button>
        <button type="button" data-cmd="strikeThrough" title="Riscado"><s>S</s></button>
        <span class="sep"></span>
        <button type="button" data-cmd="insertUnorderedList" title="Lista">&#8226; Lista</button>
        <button type="button" data-cmd="insertOrderedList" title="Lista numerada">1. Lista</button>
        <span class="sep"></span>
        <button type="button" data-cmd="removeFormat" title="Limpar formatação">&#10005; Limpar</button>
      </div>
      <div class="preview-html" id="edit-funcionamento">{func}</div>
    </div>

    """

    if can_submit:
        csrf = _get_csrf_token()
        body += aviso_conteudo_existente
        body += f"""
    <div class="card">
      <div class="navbar">
        <div class="navbar-left">
          <form id="confirm-form" method="post" action="{url_for('confirm_submit', job_id=job_id)}">
            <input type="hidden" name="csrf_token" value="{_esc(csrf)}">
            <input type="hidden" name="edit_programa" id="field-programa" value="">
            <input type="hidden" name="edit_resultados" id="field-resultados" value="">
            <input type="hidden" name="edit_funcionamento" id="field-funcionamento" value="">
            <button type="submit">Confirmar e submeter no SIGARRA</button>
          </form>
        """
    else:
        body += """
    <div class="card">
      <div class="navbar">
        <div class="navbar-left">
        """

    body += f"""
        </div>
        <div class="navbar-right">
          <a class="muted" href="https://docs.google.com/forms/d/e/1FAIpQLSfA3s2k-Ir7w5BIvADHW6VmU3mr2jMQzJtATjhuq4w5OJrV-g/viewform?usp=dialog" target="_blank" rel="noopener">Dar feedback</a>
          <a class="muted" href="{url_for('download_run_zip', job_id=job_id)}">Exportar dados (.zip)</a>
        </div>
      </div>
    </div>
    """
    return _page("Pré-visualização do Relatório", body, step=3)


@app.get("/progress/<job_id>")
def progress(job_id: str):
    sess = _get_sigarra_session()
    if not sess:
        return redirect(url_for("login"))

    with _JOBS_LOCK:
        job = _JOBS.get(job_id)
        if not job:
            return _page("Tarefa não encontrada", f"""
            <div class="card">
              <p>Tarefa não encontrada (talvez o processo tenha reiniciado).</p>
              <p><a class="btn btn-secondary" data-slow-ucs-nav="1" href="{url_for('ucs')}">Voltar à seleção</a></p>
            </div>
            """)
        if not _is_job_owner(job, sess):
            return _page("Acesso negado", """
            <div class="card"><p class="status-err">Não tens permissões para este job.</p></div>
            """), 403

    is_submit = job.action == "submit"

    if job.done and job.ok and is_submit:
        estado = '<span class="status-ok">Relatório submetido com sucesso no SIGARRA</span>'
    elif job.done and job.ok:
        estado = '<span class="status-ok">Relatório gerado com sucesso</span>'
    elif job.done and not job.ok:
        acao_label = "Submissão falhou" if is_submit else "Geração falhou"
        estado = f'<span class="status-err">{acao_label}: {_esc(job.error or "erro desconhecido")}</span>'
    else:
        if is_submit:
            estado = '<span class="status-run">A submeter no SIGARRA... pode demorar alguns segundos</span>'
        else:
            estado = '<span class="status-run">A extrair dados e gerar relatório... pode demorar alguns minutos</span>'

    should_reload_on_done = "true" if not job.done else "false"
    ano_letivo_label = _format_ano_letivo_display(job.ano_letivo)

    body = f"""
    <div class="card">
      {_uc_titulo_html(job.uc_nome, job.uc_sigla, ano_letivo_label)}
      <div class="muted">{estado}</div>
    </div>
    """

    console_style = ' style="height:9em"' if is_submit else ""
    body += f"""
    <pre id="console"{console_style} data-events-url="{_esc(url_for('events', job_id=job_id))}" data-should-reload-on-done="{should_reload_on_done}"></pre>
    """

    if job.done and job.ok and not is_submit:
        body += f"""
        <div class="card">
          <div class="navbar">
            <div class="navbar-left">
              <a class="btn" href="{url_for('preview', job_id=job_id)}">Rever e submeter relatório</a>
            </div>
            <div class="navbar-right">
              <a class="muted" href="{url_for('download_run_zip', job_id=job_id)}">Exportar dados (.zip)</a>
            </div>
          </div>
        </div>
        """
    elif job.done and job.ok and is_submit:
        sigarra_url = f"https://sigarra.up.pt/feup/pt/ucurr_geral.rel_uc_view?pv_ocorrencia_id={_esc(job.oc_id)}"
        body += f"""
        <div class="card">
          <p><a href="{sigarra_url}" target="_blank" rel="noopener">Ver relatório no SIGARRA &#8599;</a></p>
          <p><a href="https://docs.google.com/forms/d/e/1FAIpQLSfA3s2k-Ir7w5BIvADHW6VmU3mr2jMQzJtATjhuq4w5OJrV-g/viewform?usp=dialog" target="_blank" rel="noopener">Dar feedback sobre esta ferramenta &#8599;</a></p>
          <p><a class="muted" href="{url_for('download_run_zip', job_id=job_id)}">Exportar dados (.zip)</a></p>
          <p class="muted">Para gerar outro relatório, clique em «Seleção» no topo da página.</p>
        </div>
        """
    elif job.done:
        body += f"""
        <div class="card">
          <p><a class="muted" href="{url_for('download_run_zip', job_id=job_id)}">Exportar dados (.zip)</a></p>
        </div>
        """

    if is_submit and job.done and job.ok:
        progress_step = 5  # todos os passos concluídos (verde)
    elif is_submit:
        progress_step = 4
    else:
        progress_step = 2
    page_title = "Submissão do Relatório" if is_submit else "Geração do Relatório"
    return _page(page_title, f'<div id="progress-body">{body}</div>', step=progress_step)


@app.get("/download/<job_id>.zip")
def download_run_zip(job_id: str):
    sess = _get_sigarra_session()
    if not sess:
        return redirect(url_for("login"))

    with _JOBS_LOCK:
        job = _JOBS.get(job_id)
        if not job:
            return _page("Download", "<div class='card'><p>Tarefa não encontrada.</p></div>"), 404
        if not _is_job_owner(job, sess):
            return _page("Download", "<div class='card'><p class='status-err'>Acesso negado.</p></div>"), 403

    run_dir = (job.run_dir or (OUTPUT_DIR / job.oc_id)).resolve()

    try:
        if not run_dir.is_dir():
            raise FileNotFoundError("run_dir não existe")
        mem = io.BytesIO()
        with zipfile.ZipFile(mem, mode="w", compression=zipfile.ZIP_DEFLATED) as zf:
            for p in run_dir.rglob("*"):
                try:
                    if p.is_file():
                        zf.write(p, arcname=p.relative_to(run_dir))
                except OSError:
                    pass  # ficheiro removido entre rglob e write — ignorar
        mem.seek(0)
    except (OSError, FileNotFoundError):
        return _page("Download", "<div class='card'><p>Pasta da execução não encontrada ou foi removida.</p></div>"), 404

    nome = f"{run_dir.name}.zip"
    return send_file(mem, as_attachment=True, download_name=nome, mimetype="application/zip")


@app.get("/events/<job_id>")
def events(job_id: str):
    sess = _get_sigarra_session()
    if not sess:
        return Response("unauthorized", status=401)

    with _JOBS_LOCK:
        job = _JOBS.get(job_id)
        if not job:
            return Response("job not found", status=404)
        if not _is_job_owner(job, sess):
            return Response("forbidden", status=403)

    # Suporte a reconexão SSE: ler posição do último evento recebido pelo browser
    _last_event_id = request.headers.get("Last-Event-ID", "") or ""

    def generate():
        try:
            last_pos = int(_last_event_id)
        except (ValueError, TypeError):
            last_pos = 0

        def _filtrar_fases(txt: str) -> str:
            """Mantém apenas linhas de fase/aviso/erro para a UI web."""
            linhas = txt.splitlines(keepends=True)
            keep = []
            for ln in linhas:
                if any(tag in ln for tag in (
                    "--- Sumário ---",
                    "Chamadas LLM:",
                    "Modelo(s):",
                    "Tokens:",
                    "Tempo LLM:",
                    "Custo estimado:",
                    "Tempo total:",
                    "Campo 'Funcionamento' excedia",
                )):
                    continue
                if "[FASE]" in ln or "[ERRO]" in ln or "[AVIS]" in ln:
                    # remover timestamp do logger: [HH:MM:SS.mmm]
                    ln = re.sub(r"^\[\d{2}:\d{2}:\d{2}\.\d{3}\]\s*", "", ln)
                    keep.append(
                        ln.replace("[FASE] ", "")
                        .replace("[AVIS] ", "")
                        .replace("[ERRO] ", "")
                    )
            return "".join(keep)

        # aguardar até o ficheiro existir
        for _ in range(50):
            if job.log_path.exists():
                break
            time.sleep(0.1)

        while True:
            # ler incrementos
            try:
                with job.log_path.open("r", encoding="utf-8", errors="replace") as f:
                    f.seek(last_pos)
                    chunk_raw = f.read()
                    last_pos = f.tell()
            except Exception:
                chunk_raw = ""

            chunk = _filtrar_fases(chunk_raw)

            if chunk:
                # SSE: id com posição no ficheiro para suporte a reconexão
                yield (
                    f"id: {last_pos}\n"
                    "data: " + chunk.replace("\n", "\ndata: ") + "\n\n"
                )

            # terminou?
            if job.done:
                # garantir que não ficou nada por enviar
                if not chunk:
                    yield f"id: {last_pos}\ndata: __DONE__\n\n"
                    break

            time.sleep(0.35)

    return Response(generate(), mimetype="text/event-stream")


if __name__ == "__main__":
    # Localhost. Não uses debug=True com credenciais.
    app.run(host="127.0.0.1", port=5000, debug=False, threaded=True)
