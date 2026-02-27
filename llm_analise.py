"""
Módulo de análise integrada de UCs por LLM (Claude).

Contém a função principal `analisar_uc_integrado` que produz a análise
completa da UC numa única chamada ao LLM, e funções auxiliares de
construção de prompts.

Os system prompts estão em ficheiros na pasta prompts/ para edição
independente do código.
"""

import base64
import getpass
import io
import json
import os
import random
import re
import secrets
import time
import urllib.request
from pathlib import Path
import anthropic
from pypdf import PdfReader
from openai import OpenAI

from sigarra import load_env
from logger import AuditoriaLogger

_SCRIPT_DIR = Path(__file__).resolve().parent
_PROMPTS_DIR = _SCRIPT_DIR / "prompts"


def _carregar_prompt(nome_ficheiro: str) -> str:
    """Carrega um system prompt da pasta prompts/."""
    caminho = _PROMPTS_DIR / nome_ficheiro
    return caminho.read_text(encoding="utf-8").strip()


SYSTEM_PROMPT_INTEGRADO = _carregar_prompt("system_prompt.txt")

# Modelos — configuráveis via .env, com defaults no código
_MODELO_ANALISE_DEFAULT = "claude-opus-4-6"
_MODELO_CONDENSACAO_DEFAULT = "claude-sonnet-4-5-20250929"


def _obter_provider() -> str:
    """Provider LLM: anthropic (default), openai ou iaedu."""
    return os.environ.get("LLM_PROVIDER", "anthropic").strip().lower()


def _default_modelo_analise_por_provider(provider: str) -> str:
    """Modelo de análise por provider, com fallback compatível."""
    p = (provider or "").strip().lower()
    if p == "openai":
        return os.environ.get("OPENAI_MODELO_ANALISE", "").strip() or "gpt-4o"
    if p == "iaedu":
        return os.environ.get("IAEDU_MODELO_ANALISE", "").strip() or "gpt-4o"
    return os.environ.get("ANTHROPIC_MODELO_ANALISE", "").strip() or _MODELO_ANALISE_DEFAULT


def _default_modelo_condensacao_por_provider(provider: str) -> str:
    """Modelo de condensação por provider, com fallback compatível."""
    p = (provider or "").strip().lower()
    if p == "openai":
        return os.environ.get("OPENAI_MODELO_CONDENSACAO", "").strip() or "gpt-4o-mini"
    if p == "iaedu":
        return os.environ.get("IAEDU_MODELO_CONDENSACAO", "").strip() or _default_modelo_analise_por_provider(p)
    return os.environ.get("ANTHROPIC_MODELO_CONDENSACAO", "").strip() or _MODELO_CONDENSACAO_DEFAULT


def _garantir_api_key(provider: str):
    """Garante API key do provider; pede no terminal se necessário."""
    if provider == "openai":
        env_key = "OPENAI_API_KEY"
    elif provider == "iaedu":
        env_key = "IAEDU_API_KEY"
    else:
        env_key = "ANTHROPIC_API_KEY"

    key = os.environ.get(env_key, "").strip()
    if not key:
        key = getpass.getpass(f"{env_key}: ")
        os.environ[env_key] = key


def _is_retryable_llm_error(exc: Exception) -> bool:
    """Heurística para erros transitórios (429/5xx/timeouts/conectividade)."""
    code = (
        getattr(exc, "status_code", None)
        or getattr(exc, "status", None)
        or getattr(exc, "code", None)
    )
    if isinstance(code, int) and (code == 429 or 500 <= code < 600):
        return True

    response = getattr(exc, "response", None)
    status_code = getattr(response, "status_code", None)
    if isinstance(status_code, int) and (status_code == 429 or 500 <= status_code < 600):
        return True

    msg = str(exc).lower()
    retry_hints = (
        "rate limit",
        "429",
        "too many requests",
        "temporarily unavailable",
        "service unavailable",
        "overloaded",
        "timeout",
        "timed out",
        "connection reset",
        "connection aborted",
        "connection refused",
        "try again",
    )
    return any(h in msg for h in retry_hints)


def _call_text_only_llm_once(
    *,
    provider: str,
    model: str,
    system: str,
    user_text: str,
    max_tokens: int,
) -> dict:
    """Chamada LLM texto->texto unificada (Anthropic/OpenAI/IAedu)."""
    if provider == "iaedu":
        endpoint = os.environ.get("IAEDU_ENDPOINT", "").strip()
        api_key = os.environ.get("IAEDU_API_KEY", "").strip()
        channel_id = os.environ.get("IAEDU_ID_CANAL", "").strip()
        if not endpoint:
            raise ValueError("IAEDU_ENDPOINT não definido")
        if not api_key:
            raise ValueError("IAEDU_API_KEY não definido")
        if not channel_id:
            raise ValueError("IAEDU_ID_CANAL não definido")

        thread_id = os.environ.get("IAEDU_THREAD_ID", "").strip() or secrets.token_urlsafe(16)
        user_info = os.environ.get("IAEDU_USER_INFO", "{}").strip() or "{}"
        user_id = os.environ.get("IAEDU_USER_ID", "").strip()
        user_context = os.environ.get("IAEDU_USER_CONTEXT", "").strip()

        boundary = f"----auditoria-{secrets.token_hex(8)}"

        def _part(name: str, value: str) -> bytes:
            return (
                f"--{boundary}\r\n"
                f'Content-Disposition: form-data; name="{name}"\r\n\r\n'
                f"{value}\r\n"
            ).encode("utf-8")

        # IAedu recebe apenas um campo de mensagem; para manter paridade
        # com OpenAI/Anthropic, incluímos o system prompt no início.
        full_message = (
            f"{system.strip()}\n\n{user_text}"
            if (system or "").strip()
            else user_text
        )

        body_chunks = [
            _part("channel_id", channel_id),
            _part("thread_id", thread_id),
            _part("user_info", user_info),
            _part("message", full_message),
        ]
        if model:
            body_chunks.append(_part("model", model))
        if user_id:
            body_chunks.append(_part("user_id", user_id))
        if user_context:
            body_chunks.append(_part("user_context", user_context))
        body_chunks.append(f"--{boundary}--\r\n".encode("utf-8"))
        body = b"".join(body_chunks)

        req = urllib.request.Request(
            endpoint,
            data=body,
            headers={
                "x-api-key": api_key,
                "Content-Type": f"multipart/form-data; boundary={boundary}",
                "Accept": "text/event-stream, application/json, text/plain, */*",
            },
            method="POST",
        )
        try:
            resp_raw = urllib.request.urlopen(req, timeout=180)
        except urllib.error.HTTPError as exc:
            body = ""
            try:
                body = exc.read().decode("utf-8", errors="replace")[:800]
            except Exception:
                pass
            # Re-raise preservando .code (necessário para _is_retryable_llm_error)
            # mas enriquecendo o reason com o corpo da resposta para diagnóstico.
            raise urllib.error.HTTPError(
                exc.url, exc.code,
                f"{exc.reason}. Corpo: {body or '(vazio)'}",
                exc.headers, None,
            ) from exc
        with resp_raw:
            raw_text = resp_raw.read().decode("utf-8", errors="replace")
            content_type = (resp_raw.headers.get("Content-Type", "") or "").lower()

        def _extrair_texto_json(v) -> str:
            if isinstance(v, str):
                return v
            if isinstance(v, dict):
                for k in (
                    "text",
                    "content",
                    "delta",
                    "message",
                    "response",
                    "output",
                    "answer",
                    "final_answer",
                    "output_text",
                    "result",
                ):
                    if k in v:
                        t = _extrair_texto_json(v[k])
                        if t:
                            return t
                return ""
            if isinstance(v, list):
                return "".join(_extrair_texto_json(i) for i in v)
            return ""

        def _parse_sse_payloads(txt: str) -> list[str]:
            payloads: list[str] = []
            data_lines: list[str] = []
            for raw_line in txt.splitlines():
                line = raw_line.rstrip("\r")
                if not line.strip():
                    if data_lines:
                        payloads.append("\n".join(data_lines).strip())
                        data_lines = []
                    continue
                s = line.strip()
                if s.startswith(":"):
                    continue
                if s.startswith("data:"):
                    data_lines.append(s[5:].strip())
            if data_lines:
                payloads.append("\n".join(data_lines).strip())
            return [p for p in payloads if p and p not in ("[DONE]", "__DONE__")]

        chunks: list[str] = []
        full_message_text = ""

        def _extract_from_event_obj(obj: dict) -> tuple[str, str]:
            """Extrai (token_text, full_message_text) de eventos IAEDU em JSON."""
            if not isinstance(obj, dict):
                return "", ""

            tipo = str(obj.get("type", "")).strip().lower()
            conteudo = obj.get("content")

            # Fluxo por tokens
            if tipo == "token" and isinstance(conteudo, str):
                return conteudo, ""

            # Mensagem final estruturada
            if tipo == "message":
                if isinstance(conteudo, str):
                    return "", conteudo
                if isinstance(conteudo, dict):
                    txt = _extrair_texto_json(conteudo)
                    if txt:
                        return "", txt

            # Alguns endpoints podem devolver diretamente texto em "content"
            if isinstance(conteudo, str) and tipo not in ("start", "done"):
                return conteudo, ""

            return "", ""
        for payload in _parse_sse_payloads(raw_text):
            try:
                obj = json.loads(payload)
                tok, full = _extract_from_event_obj(obj)
                if tok:
                    chunks.append(tok)
                if full:
                    full_message_text = full
            except json.JSONDecodeError:
                # por vezes o payload vem em texto puro
                chunks.append(payload)

        # Fallback adicional: stream newline-delimited JSON (sem prefixo "data:")
        if not chunks and not full_message_text:
            for line in raw_text.splitlines():
                s = line.strip()
                if not s or not s.startswith("{"):
                    continue
                try:
                    obj = json.loads(s)
                except json.JSONDecodeError:
                    continue
                tok, full = _extract_from_event_obj(obj)
                if tok:
                    chunks.append(tok)
                if full:
                    full_message_text = full

        if full_message_text:
            texto = full_message_text.strip()
        elif chunks:
            texto = "".join(chunks).strip()
        else:
            # fallback para respostas não-SSE
            try:
                obj = json.loads(raw_text)
                texto = _extrair_texto_json(obj).strip()
            except json.JSONDecodeError:
                texto = raw_text.strip()

        if not texto:
            snippet = re.sub(r"\s+", " ", raw_text).strip()[:700]
            raise ValueError(
                "IAEDU devolveu resposta sem texto útil. "
                f"Content-Type={content_type or '(desconhecido)'} | "
                f"Snippet: {snippet or '(vazio)'}"
            )

        return {
            "text": texto,
            "model": model or os.environ.get("IAEDU_MODELO_ANALISE", "iaedu-agent") or "iaedu-agent",
            "input_tokens": 0,
            "output_tokens": 0,
        }

    if provider == "openai":
        base_url = os.environ.get("OPENAI_BASE_URL", "").strip() or None
        client = OpenAI(base_url=base_url)
        # max_completion_tokens é o parâmetro universal da API OpenAI (substitui
        # max_tokens, que foi descontinuado nos modelos mais recentes como o1/o3/GPT-5).
        resp = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user_text},
            ],
            max_completion_tokens=max_tokens,
        )
        text = (resp.choices[0].message.content or "").strip()
        usage = resp.usage
        return {
            "text": text,
            "model": resp.model,
            "input_tokens": int(getattr(usage, "prompt_tokens", 0) or 0),
            "output_tokens": int(getattr(usage, "completion_tokens", 0) or 0),
        }

    client = anthropic.Anthropic()
    message = client.messages.create(
        model=model,
        max_tokens=max_tokens,
        system=system,
        messages=[{"role": "user", "content": user_text}],
    )
    return {
        "text": message.content[0].text.strip(),
        "model": message.model,
        "input_tokens": int(message.usage.input_tokens),
        "output_tokens": int(message.usage.output_tokens),
    }


def _call_text_only_llm(
    *,
    provider: str,
    model: str,
    system: str,
    user_text: str,
    max_tokens: int,
) -> dict:
    """Chamada LLM texto->texto com retries para erros transitórios."""
    max_retries = int(os.environ.get("LLM_MAX_RETRIES", "3") or "3")
    base_wait = float(os.environ.get("LLM_RETRY_BASE_SECONDS", "2") or "2")
    max_wait = float(os.environ.get("LLM_RETRY_MAX_SECONDS", "20") or "20")

    tentativa = 0
    while True:
        try:
            return _call_text_only_llm_once(
                provider=provider,
                model=model,
                system=system,
                user_text=user_text,
                max_tokens=max_tokens,
            )
        except Exception as e:
            if tentativa >= max_retries or not _is_retryable_llm_error(e):
                raise

            espera = min(max_wait, base_wait * (2 ** tentativa)) + random.uniform(0, 0.4)
            time.sleep(espera)
            tentativa += 1


def _enunciados_para_texto(enunciados: list[dict]) -> str:
    """Extrai texto dos PDFs para providers sem suporte nativo a docs anexos."""
    blocos = []
    for e in enunciados:
        nome = e.get("nome", "(sem nome)")
        try:
            reader = PdfReader(io.BytesIO(e["pdf_bytes"]))
            txt = []
            for p in reader.pages[:30]:
                t = (p.extract_text() or "").strip()
                if t:
                    txt.append(t)
            joined = "\n".join(txt).strip()
            if not joined:
                joined = "[sem texto extraível do PDF]"
        except Exception:
            joined = "[falha na extração de texto do PDF]"
        blocos.append(f"### {nome}\n{joined[:12000]}")
    return "\n\n".join(blocos)


def _condensar_html(
    texto: str,
    max_chars: int,
    campo: str,
    logger: "AuditoriaLogger | None" = None,
    provider: str = "",
    modelo_condensacao: str = "",
) -> tuple[str, float]:
    """Condensa texto HTML para caber no limite, usando um LLM rápido.

    Só é chamada se len(texto) > max_chars. Pede ao LLM para manter toda
    a informação relevante (incluindo sugestões de melhoria) mas de forma
    mais concisa.
    """
    prompt = f"""\
O texto HTML abaixo destina-se ao campo "{campo}" de um relatório de UC no SIGARRA.
O limite é {max_chars} caracteres (incluindo tags HTML e espaços), mas o texto atual tem {len(texto)} caracteres.

Condensa o texto para caber no limite, mantendo:
- Toda a informação factual e dados quantitativos
- Todas as sugestões de melhoria
- O formato HTML (<p>, <strong>, <em>) e o estilo institucional
- Português de Portugal

Devolve APENAS o HTML condensado, sem delimitadores nem explicações.

Texto a condensar:
{texto}"""

    provider = provider or _obter_provider()
    modelo_cond = modelo_condensacao or _default_modelo_condensacao_por_provider(provider)
    _garantir_api_key(provider)
    t0 = time.monotonic()
    resp = _call_text_only_llm(
        provider=provider,
        model=modelo_cond,
        system="",
        user_text=prompt,
        max_tokens=4096,
    )
    duracao = time.monotonic() - t0
    resultado = resp["text"].strip()

    modelo_resp = resp.get("model")
    input_tokens = resp.get("input_tokens", 0)
    output_tokens = resp.get("output_tokens", 0)
    custo = _estimar_custo(modelo_resp, input_tokens, output_tokens)
    
    if logger:
        logger.aviso(
            f"  Campo '{campo}' excedia {max_chars} chars ({len(texto)})"
            f" — condensado para {len(resultado)} chars"
        )
        logger.registar_llm(
            modelo=modelo_resp,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            duracao=duracao,
            custo=custo,
        )

    # Se a condensação ainda excede (improvável), truncar como último recurso
    if len(resultado) > max_chars:
        resultado = resultado[:max_chars - 4] + "</p>"

    return resultado, custo


# ---------------------------------------------------------------------------
# Compactação de PDFs para reduzir tokens
# ---------------------------------------------------------------------------

def _compactar_pdf(
    pdf_bytes: bytes,
    nome: str = "",
    logger=None,
) -> bytes:
    try:
        from pypdf import PdfReader, PdfWriter
        from PIL import Image, ImageOps
    except ImportError:
        if logger:
            logger.debug(f"  PDF '{nome}': pypdf/Pillow não disponíveis, manter original")
        return pdf_bytes

    # ===== Ajustes agressivos (enunciados para LLM) =====
    MAX_DIM = 600            # mais agressivo (450–700 costuma funcionar bem)
    JPEG_QUALITY = 12        # 8–15 normalmente ok
    FORCE_GRAYSCALE = True   # costuma ser ok para enunciados
    SKIP_TINY = True
    TINY_MAX_PIXELS = 300 * 300

    # “Scan/texto”: binarizar para 1-bit e guardar como PNG (muito pequeno)
    ENABLE_1BIT_FOR_SCANS = True
    SCAN_COLORS_THRESHOLD = 8   # <= isto -> considera scan/texto
    BW_THRESHOLD = 200          # threshold (0-255). 180–215 é um intervalo típico.

    def downsample(pil: Image.Image) -> Image.Image:
        w, h = pil.size
        m = max(w, h)
        if m <= MAX_DIM:
            return pil
        r = MAX_DIM / m
        nw, nh = max(1, int(w * r)), max(1, int(h * r))
        # para enunciados/diagramas, BILINEAR chega e é rápido
        return pil.resize((nw, nh), Image.BILINEAR)

    def looks_like_scan(pil: Image.Image) -> bool:
        # Heurística barata: poucos tons -> “scan/texto/diagrama simples”
        g = pil.convert("L")
        small = g.resize((200, 200), Image.BILINEAR)
        q = small.quantize(colors=16)
        colors = len(q.getcolors() or [])
        return colors <= SCAN_COLORS_THRESHOLD

    try:
        reader = PdfReader(io.BytesIO(pdf_bytes))
        writer = PdfWriter()
        for p in reader.pages:
            writer.add_page(p)

        n_imgs = 0
        n_changed = 0

        for page in writer.pages:
            for img in page.images:
                n_imgs += 1
                try:
                    pil = Image.open(io.BytesIO(img.data))
                    pil.load()

                    w, h = pil.size
                    if SKIP_TINY and (w * h) <= TINY_MAX_PIXELS:
                        continue

                    # 1) downsample (uma vez só)
                    pil = downsample(pil)

                    # 2) escolher estratégia
                    is_scan = looks_like_scan(pil)

                    if ENABLE_1BIT_FOR_SCANS and is_scan:
                        # Binarização 1-bit + PNG
                        g = pil.convert("L")
                        g = ImageOps.autocontrast(g, cutoff=1)
                        bw = g.point(lambda x: 255 if x > BW_THRESHOLD else 0, mode="1")

                        buf = io.BytesIO()
                        bw.save(buf, format="PNG", optimize=True)
                        buf.seek(0)

                        new_img = Image.open(buf)
                        new_img.load()
                        img.replace(new_img)
                        n_changed += 1

                    else:
                        # JPEG agressivo (ainda mais leve com chroma subsampling)
                        if FORCE_GRAYSCALE:
                            pil = pil.convert("L")
                        else:
                            pil = pil.convert("RGB")

                        buf = io.BytesIO()
                        pil.save(
                            buf,
                            format="JPEG",
                            quality=JPEG_QUALITY,
                            optimize=True,
                            progressive=True,
                            subsampling=2,   # 4:2:0
                        )
                        buf.seek(0)

                        new_img = Image.open(buf)
                        new_img.load()
                        img.replace(new_img)
                        n_changed += 1

                except Exception as e:
                    if logger:
                        logger.debug(
                            f"  PDF '{nome}': erro ao compactar imagem ({e}), manter original"
                        )

        if n_changed == 0:
            if logger:
                logger.debug(f"  PDF '{nome}': sem imagens compactadas, manter original")
            return pdf_bytes

        out = io.BytesIO()
        writer.write(out)
        resultado = out.getvalue()

        ganho = 1 - len(resultado) / len(pdf_bytes)
        if logger:
            logger.info(
                f"  PDF '{nome}': {len(pdf_bytes)/1024:.0f}KB → {len(resultado)/1024:.0f}KB "
                f"({ganho:.0%} redução, {n_changed}/{n_imgs} imgs)"
            )

        return resultado if ganho > 0 else pdf_bytes

    except Exception as e:
        if logger:
            logger.debug(f"  PDF '{nome}': erro na compactação ({e}), mantido original")
        return pdf_bytes


# ---------------------------------------------------------------------------
# Funções auxiliares de construção de prompts
# ---------------------------------------------------------------------------

def _formatar_distribuicao(distribuicao: list[dict]) -> str:
    """Formata a distribuição de notas como texto tabular."""
    if not distribuicao:
        return "(sem dados)"
    linhas = []
    for item in distribuicao:
        linhas.append(
            f"  {item['codigo']:>3s}  {item['descricao']:<50s}  {item['contagem']}"
        )
    return "\n".join(linhas)


def _construir_prompt_resultados(
    resultados_atual: dict,
    resultados_anterior: dict | None = None,
    pares_curso: list[dict] | None = None,
) -> str:
    """Constrói o bloco de prompt para resultados / sucesso escolar."""
    ident = resultados_atual.get("identificacao", {})
    resumo = resultados_atual.get("resumo", {})
    estat = resultados_atual.get("estatisticas", {})
    dist = resultados_atual.get("distribuicao_notas", [])

    prompt = f"""\
## Resultados da UC — Ano Atual

### Identificação
- UC: {ident.get('nome_uc', 'N/A')}
- Código: {ident.get('codigo', 'N/A')}
- Ano letivo: {ident.get('ano_letivo', 'N/A')}
- Período: {ident.get('periodo', 'N/A')}

### Resumo de Resultados
- Inscritos: {resumo.get('inscritos', 'N/A')}
- Avaliados: {resumo.get('avaliados', 'N/A')}
- Aprovados: {resumo.get('aprovados_total', resumo.get('aprovados', 'N/A'))}
- Reprovados: {resumo.get('reprovados', 'N/A')}
- Não Avaliados: {resumo.get('nao_avaliados', 'N/A')}
- Avaliados/Inscritos: {resumo.get('racio_avaliados_inscritos', 'N/A')}%
- Aprovados/Inscritos: {resumo.get('racio_aprovados_inscritos', 'N/A')}%
- Aprovados/Avaliados: {resumo.get('racio_aprovados_avaliados', 'N/A')}%

### Estatísticas dos Aprovados
- Média: {estat.get('media', 'N/A')}
- Mediana: {estat.get('mediana', 'N/A')}
- Desvio Padrão: {estat.get('desvio_padrao', 'N/A')}
- N (aprovados com nota): {estat.get('n_aprovados_com_nota', 'N/A')}

### Distribuição Detalhada de Resultados
Código  Descrição                                            Contagem
{_formatar_distribuicao(dist)}
"""

    if resultados_anterior:
        ident_ant = resultados_anterior.get("identificacao", {})
        resumo_ant = resultados_anterior.get("resumo", {})
        estat_ant = resultados_anterior.get("estatisticas", {})
        dist_ant = resultados_anterior.get("distribuicao_notas", [])

        prompt += f"""
## Resultados da UC — Ano Anterior (para comparação)

### Identificação
- UC: {ident_ant.get('nome_uc', 'N/A')}
- Ano letivo: {ident_ant.get('ano_letivo', 'N/A')}

### Resumo de Resultados
- Inscritos: {resumo_ant.get('inscritos', 'N/A')}
- Avaliados: {resumo_ant.get('avaliados', 'N/A')}
- Aprovados: {resumo_ant.get('aprovados_total', resumo_ant.get('aprovados', 'N/A'))}
- Reprovados: {resumo_ant.get('reprovados', 'N/A')}
- Não Avaliados: {resumo_ant.get('nao_avaliados', 'N/A')}
- Avaliados/Inscritos: {resumo_ant.get('racio_avaliados_inscritos', 'N/A')}%
- Aprovados/Inscritos: {resumo_ant.get('racio_aprovados_inscritos', 'N/A')}%
- Aprovados/Avaliados: {resumo_ant.get('racio_aprovados_avaliados', 'N/A')}%

### Estatísticas dos Aprovados (Ano Anterior)
- Média: {estat_ant.get('media', 'N/A')}
- Mediana: {estat_ant.get('mediana', 'N/A')}
- Desvio Padrão: {estat_ant.get('desvio_padrao', 'N/A')}

### Distribuição Detalhada de Resultados (Ano Anterior)
Código  Descrição                                            Contagem
{_formatar_distribuicao(dist_ant)}
"""

    if pares_curso:
        pares_com_dados = [p for p in pares_curso if p.get("media_aprovados") is not None]
        if pares_com_dados:
            linhas_pares = []
            codigo_uc = ident.get("codigo", "")
            for p in pares_com_dados:
                marca = " <<<" if p["codigo"] == codigo_uc else ""
                r_aprov = p.get("racio_aprovados_inscritos")
                media = p.get("media_aprovados")
                r_str = f"{r_aprov:5.1f}%" if r_aprov is not None else "  N/A"
                m_str = f"{media:.2f}" if media is not None else "N/A"
                linhas_pares.append(
                    f"  {p['codigo']:10s}  {p['nome_uc'][:50]:<50s}"
                    f"  Aprov/Insc: {r_str}  Média aprov: {m_str}{marca}"
                )
            prompt += f"""
## Resultados das Outras UCs do Mesmo Ano do Curso (para contexto)

A UC em análise está assinalada com <<<.

Código      UC                                                  Aprov/Insc    Média aprov
{chr(10).join(linhas_pares)}
"""

    return prompt


def _construir_prompt_inquerito(
    dados: dict,
    dados_anterior: dict | None = None,
    tem_comentarios: bool = False,
) -> str:
    """Constrói o bloco de prompt para inquérito pedagógico."""
    ident = dados.get("identificacao", {})

    prompt = f"""\
## Inquérito Pedagógico — Resultados (Ano Atual)

### Identificação
- UC: {ident.get('nome_uc', 'N/A')}
- Código: {ident.get('codigo', 'N/A')}
- Ano letivo: {ident.get('ano_letivo', 'N/A')}
- Período: {ident.get('periodo', 'N/A')}

### Taxa de Resposta
- Questionários distribuídos: {dados.get('n_questionarios', 'N/A')}
- Questionários respondidos: {dados.get('n_respondidos', 'N/A')}
- Taxa de resposta: {dados.get('taxa_resposta', 'N/A')}%

### Resultados por Pergunta (escala 1-7)

{"Pergunta":<100s}  {"Dimensão":<30s}  {"Alvo":<20s}  {"μ":>5s}  {"Md":>5s}  {"σ":>5s}
{"-" * 175}
"""

    for p in dados.get("perguntas", []):
        pergunta = p["pergunta"].replace("unidade curricular", "UC")
        prompt += (
            f"{pergunta:<100s}  {p['dimensao']:<30s}  {p['alvo']:<20s}"
            f"  {p['media']:5.2f}  {p['mediana']:5.1f}  {p['dp']:5.2f}\n"
        )

    if dados_anterior:
        ident_ant = dados_anterior.get("identificacao", {})
        prompt += f"""
## Inquérito Pedagógico — Ano Anterior (para comparação)

### Identificação
- Ano letivo: {ident_ant.get('ano_letivo', 'N/A')}

### Taxa de Resposta (Ano Anterior)
- Questionários distribuídos: {dados_anterior.get('n_questionarios', 'N/A')}
- Questionários respondidos: {dados_anterior.get('n_respondidos', 'N/A')}
- Taxa de resposta: {dados_anterior.get('taxa_resposta', 'N/A')}%

### Resultados por Pergunta — Ano Anterior (escala 1-7)

{"Pergunta":<100s}  {"Dimensão":<30s}  {"Alvo":<20s}  {"μ":>5s}  {"Md":>5s}  {"σ":>5s}
{"-" * 175}
"""
        for p in dados_anterior.get("perguntas", []):
            pergunta = p["pergunta"].replace("unidade curricular", "UC")
            prompt += (
                f"{pergunta:<100s}  {p['dimensao']:<30s}  {p['alvo']:<20s}"
                f"  {p['media']:5.2f}  {p['mediana']:5.1f}  {p['dp']:5.2f}\n"
            )

    if tem_comentarios:
        prompt += """
## Comentários dos Estudantes
(ver abaixo)
"""

    return prompt


def _extrair_texto_comentarios(xls_bytes: bytes) -> str | None:
    """Extrai texto dos comentários do ficheiro XLS do SIGARRA.

    O SIGARRA exporta ficheiros .xls que são na realidade tabelas HTML.
    Extrai o texto das células, um comentário por linha.
    """
    for enc in ("utf-8", "iso-8859-15", "cp1252"):
        try:
            html = xls_bytes.decode(enc)
            break
        except (UnicodeDecodeError, ValueError):
            continue
    else:
        return None

    comentarios = []
    for m in re.finditer(r"<td[^>]*>(.*?)</td>", html, re.DOTALL | re.IGNORECASE):
        texto = re.sub(r"<[^>]+>", "", m.group(1)).strip()
        if texto and len(texto) > 5:
            comentarios.append(f"- {texto}")

    if not comentarios:
        return None
    return "\n".join(comentarios)


# ---------------------------------------------------------------------------
# Análise integrada (chamada única ao LLM)
# ---------------------------------------------------------------------------

def analisar_uc_integrado(
    ficha: dict,
    sumarios: list[dict],
    conteudos_moodle: dict | None = None,
    enunciados: list[dict] | None = None,
    resultados_atual: dict | None = None,
    resultados_anterior: dict | None = None,
    pares_curso: list[dict] | None = None,
    inq: dict | None = None,
    inq_anterior: dict | None = None,
    comentarios_bytes: bytes | None = None,
    ocorrencia_id: str = "",
    output_dir: Path | None = None,
    logger: AuditoriaLogger | None = None,
    modelo: str = "",
    provider: str = "",
    modelo_condensacao: str = "",
) -> dict:
    """Análise integrada da UC numa única chamada ao LLM.

    Combina cumprimento, avaliação, resultados, inquérito e síntese.

    Args:
        ficha: Dict retornado por extrair_ficha_uc().
        sumarios: Lista de sumários.
        conteudos_moodle: Conteúdos do Moodle (opcional).
        enunciados: Lista de enunciados com pdf_bytes (opcional).
        resultados_atual: Resultados do ano atual (opcional).
        resultados_anterior: Resultados do ano anterior (opcional).
        pares_curso: UCs pares do curso (opcional).
        inq: Inquérito pedagógico atual (opcional).
        inq_anterior: Inquérito do ano anterior (opcional).
        comentarios_bytes: Bytes do ficheiro de comentários (opcional).
        ocorrencia_id: Código da ocorrência.
        output_dir: Pasta de output para ficheiros intermédios.
        logger: Logger para mensagens e metadata.
        modelo: Modelo Claude a utilizar.

    Returns:
        Dict com:
        - 'resultados': texto para pv_rel_coment_res
        - 'funcionamento': texto para pv_rel_coment_func
        - 'programa_efetivo': HTML do programa efetivo
        - 'enunciados_moodle_bloco': bloco de classificação de enunciados
        - 'custo_estimado': custo estimado da(s) chamada(s) a LLM
    """
    load_env()
    provider = provider or _obter_provider()
    if not modelo:
        modelo = _default_modelo_analise_por_provider(provider)
    if not modelo_condensacao:
        modelo_condensacao = _default_modelo_condensacao_por_provider(provider)
    _garantir_api_key(provider)

    _debug = logger.debug if logger else lambda _msg: None

    programa_html = ficha.get("programa_html", "")

    # --- Construir prompt unificado ---
    partes = []

    # 1. Ficha da UC — todos os campos, programa só em HTML
    componentes = ficha.get("componentes_avaliacao", [])
    if componentes:
        texto_comp = "\n".join(
            f"  - {c['designacao']}: {c['peso']:.1f}%" for c in componentes
        )
    else:
        texto_comp = "(sem dados)"

    partes.append(f"""\
## Ficha da UC

### Objetivos da UC
{ficha.get('objetivos', 'N/A')}

## Resultados de Aprendizagem e Competências
{ficha.get('resultados_aprendizagem', 'N/A')}

### Programa da UC (HTML)
{programa_html or ficha.get('programa', 'N/A')}

### Métodos de Ensino e Atividades de Aprendizagem
{ficha.get('metodos_ensino', 'N/A')}

### Tipo de Avaliação
{ficha.get('tipo_avaliacao', 'N/A')}

### Componentes de Avaliação
{texto_comp}

### Fórmula de Cálculo da Classificação Final
{ficha.get('formula_classificacao', 'N/A')}

### Obtenção de Frequência
{ficha.get('obtencao_frequencia', 'N/A')}

### Língua de Trabalho
{ficha.get('lingua_trabalho', 'N/A')}""")

    # 2. Sumários das aulas
    linhas_sum = []
    turma_atual = ""
    for s in sumarios:
        if s["turma"] != turma_atual:
            turma_atual = s["turma"]
            linhas_sum.append(f"\n### Turma {turma_atual} ({s['tipo_aula']})")
        linhas_sum.append(f"- Aula {s['numero']} [{s['data']}]: {s['sumario']}")

    partes.append(f"""\


## Sumários das Aulas Lecionadas
{chr(10).join(linhas_sum).strip()}""")

    # 3. Conteúdos do Moodle (complemento)
    if conteudos_moodle and conteudos_moodle.get("seccoes"):
        linhas_m = []
        for sec in conteudos_moodle["seccoes"]:
            if sec.get("nome"):
                linhas_m.append(f"\n### {sec['nome']}")
            if sec.get("descricao"):
                linhas_m.append(sec["descricao"])
            for act in sec.get("atividades", []):
                linhas_m.append(f"- [{act['tipo']}] {act['nome']}")
        partes.append(f"## Conteúdos do Moodle\n{chr(10).join(linhas_m).strip()}")

    # 4. Enunciados de avaliação (só listagem; PDFs vão como documentos anexos)
    if enunciados:
        linhas_enun = []
        for e in enunciados:
            origem = e.get("origem", "?")
            linhas_enun.append(
                f"  - {e['nome']} — {e['descricao']} (Época: {e['epoca']}) [Origem: {origem}]"
            )
        partes.append(f"""\
## Enunciados de Avaliação Disponíveis (PDFs anexos)
{chr(10).join(linhas_enun)}

Os PDFs dos enunciados estão anexos a esta mensagem para análise detalhada.
Os enunciados com origem "Moodle/*" foram extraídos automaticamente do Moodle. \
Confirma se cada um corresponde efetivamente a um elemento de avaliação \
(enunciado de exame, teste, trabalho, projeto, etc.) e não a material de apoio \
(slides, tutoriais, etc.).""")
    else:
        partes.append("""\
## Enunciados de Avaliação
Não foram encontrados enunciados de avaliação para esta UC.""")

    # 5. Resultados / Sucesso Escolar (reutiliza construtor sem instrução final)
    if resultados_atual:
        partes.append(
            _construir_prompt_resultados(
                resultados_atual, resultados_anterior, pares_curso
            )
        )
    else:
        partes.append("## Resultados / Sucesso Escolar\n(sem dados disponíveis)")

    # 6. Inquérito Pedagógico (reutiliza construtor sem instrução final)
    if inq:
        texto_comentarios = None
        if comentarios_bytes:
            texto_comentarios = _extrair_texto_comentarios(comentarios_bytes)
        prompt_inq = _construir_prompt_inquerito(
            inq, inq_anterior, texto_comentarios is not None
        )
        if texto_comentarios:
            prompt_inq += f"\n### Comentários dos Estudantes\n\n{texto_comentarios}\n"
        partes.append(prompt_inq)
    else:
        partes.append("## Inquérito Pedagógico\n(sem dados disponíveis)")

    user_prompt = "\n\n".join(partes)
    user_prompt += """

---
Com base em toda a informação acima, produz a análise integrada da UC \
com todas as secções delimitadas indicadas no system prompt.\
"""

    # Guardar prompt e system prompt no output
    if output_dir and ocorrencia_id:
        pasta = output_dir / ocorrencia_id
        pasta.mkdir(parents=True, exist_ok=True)

        prompt_path = pasta / "user_prompt_integrado.txt"
        prompt_path.write_text(user_prompt, encoding="utf-8")
        _debug(f"  User prompt guardado em: {prompt_path}")

        sys_prompt_path = pasta / "system_prompt_integrado.txt"
        sys_prompt_path.write_text(SYSTEM_PROMPT_INTEGRADO, encoding="utf-8")
        _debug(f"  System prompt guardado em: {sys_prompt_path}")

    # Chamar API conforme provider
    t0 = time.monotonic()
    if provider in ("openai", "iaedu"):
        # fallback: extrair texto dos PDFs e anexar ao prompt
        if enunciados:
            user_prompt = (
                user_prompt
                + "\n\n## Texto extraído dos PDFs de enunciados\n"
                + _enunciados_para_texto(enunciados)
            )
        resp = _call_text_only_llm(
            provider=provider,
            model=modelo,
            system=SYSTEM_PROMPT_INTEGRADO,
            user_text=user_prompt,
            max_tokens=16384,
        )
        resultado_raw = resp["text"]
    else:
        content: list[dict] = []
        _so_texto = os.environ.get("LLM_ENUNCIADOS_APENAS_TEXTO", "0").strip() == "1"
        if enunciados:
            if _so_texto:
                content.append({
                    "type": "text",
                    "text": "\n\n## Texto extraído dos PDFs de enunciados\n" + _enunciados_para_texto(enunciados),
                })
            else:
                texto_fallback: list[str] = []
                for e in enunciados:
                    raw = e["pdf_bytes"]
                    nome = e["nome"]
                    # Validar magic bytes antes de compactar/enviar
                    if not raw or not raw.lstrip()[:4].startswith(b"%PDF"):
                        if logger:
                            logger.aviso(f"  PDF '{nome}' inválido (não começa com %PDF) — extraindo texto como fallback")
                        try:
                            txt = _enunciados_para_texto([e])
                            if txt.strip():
                                texto_fallback.append(f"## {nome}\n{txt}")
                        except Exception:
                            pass
                        continue
                    pdf = _compactar_pdf(raw, nome, logger)
                    if output_dir and ocorrencia_id and pdf is not raw:
                        nome_base = Path(nome).stem
                        llm_path = output_dir / ocorrencia_id / f"{nome_base}_llm.pdf"
                        llm_path.write_bytes(pdf)
                    content.append({
                        "type": "document",
                        "source": {
                            "type": "base64",
                            "media_type": "application/pdf",
                            "data": base64.b64encode(pdf).decode(),
                        },
                        "title": nome,
                    })
                if texto_fallback:
                    content.append({
                        "type": "text",
                        "text": "\n\n## Texto extraído de PDFs inválidos\n" + "\n\n".join(texto_fallback),
                    })
        content.append({"type": "text", "text": user_prompt})

        client = anthropic.Anthropic()
        message = client.messages.create(
            model=modelo,
            max_tokens=16384,
            system=SYSTEM_PROMPT_INTEGRADO,
            messages=[{"role": "user", "content": content}],
        )
        resp = {
            "text": message.content[0].text,
            "model": message.model,
            "input_tokens": int(message.usage.input_tokens),
            "output_tokens": int(message.usage.output_tokens),
        }
        resultado_raw = resp["text"]

    duracao = time.monotonic() - t0

    modelo_resp = resp.get("model")
    input_tokens = resp.get("input_tokens", 0)
    output_tokens = resp.get("output_tokens", 0)
    custo = _estimar_custo(modelo_resp, input_tokens, output_tokens)

    # Registar metadata LLM
    if logger:
        logger.registar_llm(
            modelo=modelo_resp,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            duracao=duracao,
            custo=custo,
        )

    # Guardar resultado
    if output_dir and ocorrencia_id:
        resultado_path = output_dir / ocorrencia_id / "resultado_integrado.txt"
        resultado_path.write_text(resultado_raw, encoding="utf-8")
        _debug(f"  Resultado guardado em: {resultado_path}")

    # --- Extrair secções da resposta ---

    def _extrair_bloco(marcador_ini: str, marcador_fim: str) -> str:
        m = re.search(
            rf"\*{{0,2}}{re.escape(marcador_ini)}\*{{0,2}}\s*(.*?)"
            rf"\*{{0,2}}{re.escape(marcador_fim)}\*{{0,2}}",
            resultado_raw, re.DOTALL,
        )
        return m.group(1).strip() if m else ""

    resultados = _extrair_bloco("===RESULTADOS===", "===FIM_RESULTADOS===")
    funcionamento = _extrair_bloco("===FUNCIONAMENTO===", "===FIM_FUNCIONAMENTO===")
    programa_efetivo = _extrair_bloco("===PROGRAMA_EFETIVO===", "===FIM_PROGRAMA_EFETIVO===")
    enunciados_moodle_bloco = _extrair_bloco("===ENUNCIADOS_MOODLE===", "===FIM_ENUNCIADOS_MOODLE===")
    lingua_enunciados_bloco = _extrair_bloco("===LINGUA_ENUNCIADOS===", "===FIM_LINGUA_ENUNCIADOS===")

    # Fallback: delimitadores sem FIM_ (formato antigo)
    if not resultados:
        m = re.search(
            r"\*{0,2}===RESULTADOS===\*{0,2}\s*(.*?)(?:\*{0,2}===FUNCIONAMENTO===\*{0,2}|$)",
            resultado_raw, re.DOTALL,
        )
        if m:
            resultados = m.group(1).strip()
    if not funcionamento:
        m = re.search(
            r"\*{0,2}===FUNCIONAMENTO===\*{0,2}\s*(.*?)(?:\*{0,2}===PROGRAMA|$)",
            resultado_raw, re.DOTALL,
        )
        if m:
            funcionamento = m.group(1).strip()

    # Fallback adicional: se o LLM ignorar delimitadores, pedir "reformatação"
    if not resultados and not funcionamento:
        if logger:
            logger.aviso(
                "  Resposta do LLM sem delimitadores esperados; "
                "a tentar normalização para formato canónico."
            )
        normalizar_prompt = (
            "Recebeste uma análise de UC em texto livre. "
            "Reorganiza EXATAMENTE no formato abaixo, sem introdução extra:\n\n"
            "===RESULTADOS===\n"
            "(HTML para o campo de resultados)\n"
            "===FIM_RESULTADOS===\n\n"
            "===FUNCIONAMENTO===\n"
            "(HTML para o campo de funcionamento)\n"
            "===FIM_FUNCIONAMENTO===\n\n"
            "===PROGRAMA_EFETIVO===\n"
            "(HTML curto com o programa efetivo, se disponível)\n"
            "===FIM_PROGRAMA_EFETIVO===\n\n"
            "===ENUNCIADOS_MOODLE===\n"
            "(lista/classificação dos enunciados Moodle, se aplicável)\n"
            "===FIM_ENUNCIADOS_MOODLE===\n\n"
            "Regras obrigatórias:\n"
            "- Não inventar dados; usar apenas o texto fornecido.\n"
            "- Se faltar informação numa secção, devolver secção vazia mas manter delimitadores.\n"
            "- Em RESULTADOS e FUNCIONAMENTO devolver HTML simples (<p>, <strong>, <em>, <ul>, <li>).\n\n"
            "Texto a normalizar:\n"
            f"{resultado_raw}"
        )
        try:
            resp_norm = _call_text_only_llm(
                provider=provider,
                model=modelo,
                system="",
                user_text=normalizar_prompt,
                max_tokens=8192,
            )
            resultado_norm = (resp_norm.get("text") or "").strip()
            if resultado_norm:
                resultado_raw = resultado_norm
                resultados = _extrair_bloco("===RESULTADOS===", "===FIM_RESULTADOS===")
                funcionamento = _extrair_bloco("===FUNCIONAMENTO===", "===FIM_FUNCIONAMENTO===")
                programa_efetivo = _extrair_bloco("===PROGRAMA_EFETIVO===", "===FIM_PROGRAMA_EFETIVO===")
                enunciados_moodle_bloco = _extrair_bloco("===ENUNCIADOS_MOODLE===", "===FIM_ENUNCIADOS_MOODLE===")
                lingua_enunciados_bloco = _extrair_bloco("===LINGUA_ENUNCIADOS===", "===FIM_LINGUA_ENUNCIADOS===")
        except Exception as e:
            if logger:
                logger.aviso(f"  Falha ao normalizar resposta sem delimitadores: {e}")

    if not resultados and not funcionamento:
        snippet = re.sub(r"\s+", " ", resultado_raw).strip()[:600]
        raise ValueError(
            "LLM não devolveu resposta no formato esperado (sem blocos RESULTADOS/FUNCIONAMENTO). "
            f"Snippet: {snippet or '(vazio)'}"
        )

    # Condensar se excede limite do SIGARRA (4000 chars)
    max_res = 4000
    if len(resultados) > max_res:
        resultados, custo_res = _condensar_html(
            resultados,
            max_res - 100,
            "Resultados",
            logger,
            provider=provider,
            modelo_condensacao=modelo_condensacao,
        )
        custo += custo_res
    max_func = 4000
    if len(funcionamento) > max_func:
        funcionamento, custo_func = _condensar_html(
            funcionamento,
            max_func - 100,
            "Funcionamento",
            logger,
            provider=provider,
            modelo_condensacao=modelo_condensacao,
        )
        custo += custo_func
    return {
        "resultados": resultados,
        "funcionamento": funcionamento,
        "programa_efetivo": programa_efetivo,
        "enunciados_moodle_bloco": enunciados_moodle_bloco,
        "lingua_enunciados_bloco": lingua_enunciados_bloco,
        "custo_estimado": custo,
    }



def _carregar_precos_config() -> dict[str, tuple[float, float]]:
    """Carrega tabela de preços de LLM a partir de configuração.

    Formato suportados:
      - LLM_PRICING_JSON='{"modelo": [in, out], "modelo2": {"input": x, "output": y}}'
      - LLM_PRICING_FILE='caminho/ficheiro.json' com o mesmo formato
    """
    precos = dict()  # modelo → (in_cost, out_cost) em USD por 1M tokens

    payload = os.environ.get("LLM_PRICING_JSON", "").strip()
    pricing_file = os.environ.get("LLM_PRICING_FILE", "").strip()

    if not payload and pricing_file:
        try:
            payload = Path(pricing_file).read_text(encoding="utf-8")
        except OSError:
            payload = ""

    if not payload:
        return precos

    try:
        data = json.loads(payload)
    except json.JSONDecodeError:
        return precos

    if not isinstance(data, dict):
        return precos

    for modelo, val in data.items():
        try:
            if isinstance(val, (list, tuple)) and len(val) == 2:
                in_cost = float(val[0])
                out_cost = float(val[1])
            elif isinstance(val, dict):
                in_cost = float(val.get("input", 0))
                out_cost = float(val.get("output", 0))
            else:
                continue
            precos[str(modelo)] = (in_cost, out_cost)
        except (TypeError, ValueError):
            continue

    # ordena por comprimento descendente de modelo para facilitar correspondência por prefixo
    precos = dict(sorted(precos.items(), key=lambda x: len(x[0]), reverse=True))
    return precos


_PRECOS = None
'''Tabela de preços carregada (modelo → (input_cost, output_cost) em USD por 1M tokens).'''

def _estimar_custo(modelo: str, input_tokens: int, output_tokens: int) -> float | None:
    """Estima custo em USD a partir do modelo e tokens usados."""
    # Carrega tabela de preços na primeira chamada (lazy loading).
    global _PRECOS
    if _PRECOS is None:
        _PRECOS = _carregar_precos_config()
    print(f"Estimando custo para modelo '{modelo}' com {input_tokens} input + {output_tokens} output tokens...")
    precos = _PRECOS.get(modelo)
    if precos is None:
        # Correspondência por prefixo (ex: "claude-opus-4-6-20250101" → "claude-opus-4-6").
        # Itera pelo prefixo mais longo primeiro para evitar que "gpt-4o" capture "gpt-4o-mini".
        for chave, custos in _PRECOS.items():  # já está por comprimento desc
            if modelo.startswith(chave):
                precos = custos
                break
    if not precos:
        return None
    return input_tokens * precos[0] / 1_000_000 + output_tokens * precos[1] / 1_000_000
