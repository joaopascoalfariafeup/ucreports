"""
Módulo de interação com o Moodle da Universidade do Porto.

Acesso SSO, extração de conteúdos de cursos, download de enunciados
(assignments, resources, URLs, Google Docs/Drive) e extração de quizzes
para PDF.
"""

from __future__ import annotations
import base64
import html as html_mod

import random
import re
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import TYPE_CHECKING
from dataclasses import dataclass
from typing import Optional
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlsplit, urlunsplit, quote


def _safe_url(url: str) -> str:
    """Percent-encode caracteres não-ASCII numa URL (http.client só aceita ASCII)."""
    try:
        url.encode("ascii")
        return url
    except UnicodeEncodeError:
        parts = urlsplit(url)
        return urlunsplit((
            parts.scheme,
            parts.netloc,
            quote(parts.path, safe="/:@!$&'()*+,;="),
            quote(parts.query, safe="=&+%[]"),
            quote(parts.fragment, safe=""),
        ))
import unicodedata
from typing import Set

from logger import AuditoriaLogger


if TYPE_CHECKING:
    from sigarra import SigarraSession

_SCRIPT_DIR = Path(__file__).resolve().parent



def _urlopen_retry(req: urllib.request.Request, timeout: int = 60, retries: int = 2):
    """Abre URL externa com retries e backoff para falhas transitórias."""
    total = max(0, retries) + 1
    last_exc: Exception | None = None
    for i in range(1, total + 1):
        try:
            timeout_i = int(timeout * (1 + 0.4 * (i - 1)))
            return urllib.request.urlopen(req, timeout=timeout_i)
        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, socket.timeout) as e:
            last_exc = e
            if i < total:
                atraso = 0.7 * (2 ** (i - 1)) + random.uniform(0, 0.2)
                time.sleep(atraso)
                continue
            raise
    if last_exc:
        raise last_exc
    raise RuntimeError("Falha inesperada em _urlopen_retry")


# ---------------------------------------------------------------------------
# Acesso SSO e extração de conteúdos do Moodle
# ---------------------------------------------------------------------------

def aceder_moodle(moodle_portal_url: str, sessao: SigarraSession, verbosidade: int, log: AuditoriaLogger) -> tuple[str, str] | None:
    """Acede ao Moodle seguindo o link do portal SIGARRA (SSO).

    O opener autenticado segue a cadeia de redirects HTTP e acumula
    cookies, resolvendo a autenticação SSO automaticamente.

    Args:
        moodle_portal_url: URL completa do portal Moodle no SIGARRA
            (``moodle_portal.go_moodle_portal_up?p_codigo=...``).
        sessao: Sessão autenticada no SIGARRA.
        verbosidade: Nível de detalhe na saída (0=quieto, 1=normal, 2=debug).
        log: Instância de AuditoriaLogger para registar mensagens.
    Returns:
        Tuplo (url_final, html) se o acesso ao Moodle teve sucesso,
        ou None se falhar.
    """
    if not sessao.autenticado:
        raise PermissionError("É necessário autenticar antes de aceder ao Moodle.")

    try:
        req = urllib.request.Request(
            moodle_portal_url, headers={"User-Agent": "Mozilla/5.0"}
        )
        resp = sessao.http_open(req, timeout=30, context="aceder_moodle")
        url_final = resp.url
        charset = resp.headers.get_content_charset() or "utf-8"
        html = resp.read().decode(charset, errors="replace")

        # Tratar meta-refresh caso o SSO use redirect HTML
        meta_match = re.search(
            r'<meta[^>]+http-equiv=["\']refresh["\'][^>]+content=["\']\d+;\s*url=([^"\']+)["\']',
            html, re.IGNORECASE,
        )
        if meta_match:
            # Substituir apenas &amp; → & sem html.unescape() completo:
            # unescape() converteria &times; (de "&timestamp=") em ×, corrompendo o URL
            redirect_url = _safe_url(meta_match.group(1).replace("&amp;", "&"))
            req2 = urllib.request.Request(
                redirect_url, headers={"User-Agent": "Mozilla/5.0"}
            )
            resp2 = sessao.http_open(req2, timeout=30, context="aceder_moodle meta-refresh")
            url_final = resp2.url
            charset = resp2.headers.get_content_charset() or "utf-8"
            html = resp2.read().decode(charset, errors="replace")

        # Verificar se chegámos ao Moodle
        if "moodle" in url_final.lower() and ".up.pt" in url_final.lower():
            return url_final, html
        else:
            log.aviso(f"  Aviso: redirect do Moodle terminou em URL inesperada: {url_final}")
            return None

    except (urllib.error.URLError, urllib.error.HTTPError) as e:
        log.aviso(f"  Aviso: falha ao aceder ao Moodle: {e}")
        return None


def _obter_pdf_de_resource_view(
    resource_view_url: str,
    sessao,
    verbosidade: int,
    log: AuditoriaLogger,
):
    """
    Resolve /mod/resource/view.php?id=... para um PDF real.

    Estratégia:
      - tenta primeiro redirect=1 (normalmente redireciona para pluginfile.php)
      - tenta o URL original
      - se vier HTML, procura links pluginfile.php no HTML e tenta-os
    Retorna (nome_fich, pdf_bytes) ou None.
    """
    def _is_pdf(data: bytes) -> bool:
        return bool(data) and data[:4] == b"%PDF"

    def _add_redirect_1(url: str) -> str:
        if "redirect=1" in url:
            return url
        sep = "&" if "?" in url else "?"
        return url + sep + "redirect=1"

    # 1) URLs candidatas (sem repetir)
    candidatos = []
    for u in (_add_redirect_1(resource_view_url), resource_view_url):
        if u not in candidatos:
            candidatos.append(u)

    # 2) tentar descarregar cada candidato
    for u in candidatos:
        r = _descarregar_ficheiro_moodle(u, sessao, log=log)
        if not r:
            continue

        nome, data = r
        if _is_pdf(data):
            return nome, data

        # Se não é PDF, pode ser HTML intermédio: procurar pluginfile.php
        # (só faz sentido se parecer HTML)
        try:
            html_txt = data.decode("utf-8", errors="replace")
        except Exception:
            html_txt = ""

        if "<html" not in html_txt.lower() and "pluginfile.php" not in html_txt:
            continue

        links = re.findall(
            r'(?:href|src)="(https?://[^"]*pluginfile\.php/[^"]+)"',
            html_txt
        )
        links = [html_mod.unescape(x) for x in links]

        # remover duplicados preservando ordem
        vistos = set()
        links = [x for x in links if not (x in vistos or vistos.add(x))]

        log.debug(f"      resource/view: HTML recebido; {len(links)} links pluginfile encontrados")

        # priorizar os que parecem pdf (mas sem exigir)
        links.sort(key=lambda x: (".pdf" not in x.lower(), len(x)))

        for link in links:
            rr = _descarregar_ficheiro_moodle(link, sessao, log=log)
            if not rr:
                continue
            n2, d2 = rr
            if _is_pdf(d2):
                return n2, d2

    return None


def extrair_conteudos_moodle(course_url: str, sessao: SigarraSession, 
                             verbosidade: int, log: AuditoriaLogger) -> dict | None:
    """Extrai os conteúdos de uma página de curso do Moodle.

    Faz fetch da página do curso e extrai secções, atividades e recursos
    usando as classes CSS standard do Moodle.

    Args:
        course_url: URL da página do curso Moodle.
        sessao: Sessão autenticada (com cookies do Moodle).
        verbosidade: Nível de detalhe na saída (0=quieto, 1=normal, 2=debug).

    Returns:
        Dict com 'url' e 'seccoes', ou None se falhar.
    """
    try:
        req = urllib.request.Request(
            course_url, headers={"User-Agent": "Mozilla/5.0"}
        )
        resp = sessao.http_open(req, timeout=30, context="extrair_conteudos_moodle")
        charset = resp.headers.get_content_charset() or "utf-8"
        html = resp.read().decode(charset, errors="replace")
    except (urllib.error.URLError, urllib.error.HTTPError) as e:
        log.aviso(f"  Aviso: falha ao aceder à página do curso Moodle: {e}")
        return None

    seccoes = []

    # Dividir o HTML pelas fronteiras das secções em vez de usar (.*?) com
    # tags aninhadas (que truncava no primeiro </li> interior).
    sec_starts = [
        m.start()
        for m in re.finditer(
            r'<li[^>]+class="[^"]*\bsection\b[^"]*"', html,
        )
    ]

    for i, start in enumerate(sec_starts):
        # Conteúdo entre esta secção e a próxima (ou fim do HTML)
        end = sec_starts[i + 1] if i + 1 < len(sec_starts) else len(html)
        sec_html = html[start:end]

        # Nome da secção — extrair todo o conteúdo do elemento sectionname
        nome = ""
        nome_match = re.search(
            r'class="[^"]*\bsectionname\b[^"]*"[^>]*>(.+)',
            sec_html, re.DOTALL,
        )
        if nome_match:
            # Extrair texto até ao fecho do elemento contentor (h3, span, div)
            fragmento = nome_match.group(1)
            # Cortar no primeiro tag de fecho de bloco relevante
            corte = re.search(r"</(?:h[23456]|span|div)>", fragmento)
            if corte:
                fragmento = fragmento[:corte.start()]
            nome = re.sub(r"<[^>]+>", "", fragmento).strip()

        # Descrição da secção
        descricao = ""
        desc_match = re.search(
            r'class="[^"]*\bsummary\b[^"]*"[^>]*>(.+)',
            sec_html, re.DOTALL,
        )
        if desc_match:
            fragmento = desc_match.group(1)
            corte = re.search(r"</div>", fragmento)
            if corte:
                fragmento = fragmento[:corte.start()]
            descricao = re.sub(r"<[^>]+>", "", fragmento).strip()

        # Atividades — dividir pelas fronteiras de cada <li class="activity ...">
        atividades = []
        act_starts = list(re.finditer(
            r'<li[^>]+class="[^"]*\bactivity\b[^"]*"[^>]*>',
            sec_html,
        ))
        for j, act_m in enumerate(act_starts):
            li_tag = act_m.group(0)  # todo o <li ...>
            a_start = act_m.end()
            a_end = act_starts[j + 1].start() if j + 1 < len(act_starts) else len(sec_html)
            act_html = sec_html[a_start:a_end]

            # Extrair tipo da atividade (várias estratégias por ordem de fiabilidade)
            tipo = ""

            # 1. Classe "modtype_XXX" (presente em muitas versões)
            mt = re.search(r'\bmodtype_(\w+)', li_tag)
            if mt:
                tipo = mt.group(1)

            # 2. Classe com tipo direto: "activity assign ..." (Moodle < 4.x)
            if not tipo:
                ct = re.search(r'\bactivity\b\s+(?!activity\b)(\w+)', li_tag)
                if ct:
                    tipo = ct.group(1)

            # 3. Atributo data-modname="assign" (Moodle 4.x)
            if not tipo:
                dm = re.search(r'data-modname="(\w+)"', li_tag)
                if dm:
                    tipo = dm.group(1)

            # 4. Extrair do URL: mod/assign/view.php → assign (fallback fiável)
            if not tipo:
                url_tipo = re.search(r'/mod/(\w+)/view\.php', act_html)
                if url_tipo:
                    tipo = url_tipo.group(1)

            if not tipo:
                tipo = "outro"

            # Nome da atividade — todo o texto dentro do instancename
            act_nome = ""
            inst_match = re.search(
                r'class="[^"]*\binstancename\b[^"]*"[^>]*>(.+)',
                act_html, re.DOTALL,
            )
            if inst_match:
                fragmento = inst_match.group(1)
                # Cortar quando o nível de <span> volta a zero (fim do instancename)
                nivel = 1
                pos = 0
                for tag in re.finditer(r"<(/?)span\b[^>]*>", fragmento):
                    if tag.group(1) == "/":
                        nivel -= 1
                    else:
                        nivel += 1
                    if nivel <= 0:
                        pos = tag.start()
                        break
                if pos > 0:
                    fragmento = fragmento[:pos]
                # Remover spans accesshide (contêm tipo: " Teste", " Ficheiro", etc.)
                fragmento = re.sub(
                    r'<span[^>]+class="[^"]*\baccesshide\b[^"]*"[^>]*>.*?</span>',
                    '', fragmento, flags=re.DOTALL | re.IGNORECASE,
                )
                act_nome = re.sub(r"<[^>]+>", "", fragmento).strip()

            if not act_nome:
                # Alternativa: texto do link principal
                link_match = re.search(r'<a[^>]+>(.+?)</a>', act_html, re.DOTALL)
                if link_match:
                    act_nome = re.sub(r"<[^>]+>", "", link_match.group(1)).strip()

            # Moodle 4.x: nome no atributo data-activityname
            if not act_nome:
                dan = re.search(r'data-activityname="([^"]+)"', li_tag)
                if dan:
                    act_nome = html_mod.unescape(dan.group(1))

            if not act_nome:
                continue

            # URL da atividade
            url_match = re.search(r'href="([^"]+/mod/\w+/view\.php[^"]*)"', act_html)
            if not url_match:
                url_match = re.search(r'href="([^"]+)"', act_html)
            act_url = url_match.group(1) if url_match else ""

            atividades.append({
                "tipo": tipo,
                "nome": act_nome,
                "url": act_url,
            })

        if nome or atividades:
            seccoes.append({
                "nome": nome,
                "descricao": descricao,
                "atividades": atividades,
            })

    if not seccoes:
        return None

    return {
        "url": course_url,
        "seccoes": seccoes,
    }


# ---------------------------------------------------------------------------
# Download de ficheiros e Google Docs/Drive
# ---------------------------------------------------------------------------

def _url_para_pdf_google(url: str) -> str | None:
    """Converte URL do Google Docs/Drive/Slides/Sheets para URL de export PDF.

    Args:
        url: URL original (ex: https://docs.google.com/document/d/ABC123/edit).

    Returns:
        URL de download/export direto como PDF, ou None se não reconhecido.
    """
    # Google Docs
    m = re.match(r'https?://docs\.google\.com/document/d/([^/?#]+)', url)
    if m:
        return f"https://docs.google.com/document/d/{m.group(1)}/export?format=pdf"

    # Google Slides
    m = re.match(r'https?://docs\.google\.com/presentation/d/([^/?#]+)', url)
    if m:
        return f"https://docs.google.com/presentation/d/{m.group(1)}/export/pdf"

    # Google Sheets
    m = re.match(r'https?://docs\.google\.com/spreadsheets/d/([^/?#]+)', url)
    if m:
        return f"https://docs.google.com/spreadsheets/d/{m.group(1)}/export?format=pdf"

    # Google Drive file view (drive.google.com/file/d/FILE_ID/view)
    m = re.match(r'https?://drive\.google\.com/file/d/([^/?#]+)', url)
    if m:
        return f"https://drive.google.com/uc?export=download&id={m.group(1)}"

    # Google Drive open (drive.google.com/open?id=FILE_ID)
    if "drive.google.com" in url:
        m = re.search(r'[?&]id=([^&]+)', url)
        if m:
            return f"https://drive.google.com/uc?export=download&id={m.group(1)}"

    return None


def _descarregar_url_externo(url: str, nome_default: str, log: AuditoriaLogger) -> tuple[str, bytes] | None:
    """Descarrega ficheiro de URL externo (sem cookies de sessão).

    Utiliza urllib.request.urlopen diretamente (sem o opener da sessão)
    para aceder a URLs de terceiros (Google Drive, etc.).

    Args:
        url: URL de download direto.
        nome_default: Nome a usar se não for possível extrair do response.
        log: Instância de AuditoriaLogger para registar mensagens.

    Returns:
        Tuplo (nome_ficheiro, bytes_conteudo) ou None se falhar.
    """
    try:
        req = urllib.request.Request(_safe_url(url), headers={"User-Agent": "Mozilla/5.0"})
        resp = _urlopen_retry(req, timeout=60)
        data = resp.read()

        # Nome do ficheiro: Content-Disposition ou URL final
        cd = resp.headers.get("Content-Disposition", "")
        nome = ""
        if "filename=" in cd:
            m = re.search(r'filename[*]?="?([^";\n]+)"?', cd)
            if m:
                nome = m.group(1).strip()
        if not nome:
            url_path = urllib.parse.urlparse(resp.url).path
            segmento = urllib.parse.unquote(url_path.rsplit("/", 1)[-1])
            if segmento and segmento not in ("export", "pdf", "download"):
                nome = segmento
        if not nome:
            nome = nome_default or "documento.pdf"
        if not nome.lower().endswith(".pdf"):
            nome += ".pdf"

        return nome, data

    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, socket.timeout) as e:
        log.aviso(f"    Aviso: falha ao descarregar URL externo: {e}")
        return None


def _descarregar_ficheiro_moodle(
    url: str, sessao: SigarraSession, log: AuditoriaLogger
) -> tuple[str, bytes] | None:
    """Descarrega um ficheiro do Moodle, seguindo redirects.

    Args:
        url: URL do ficheiro (tipicamente pluginfile.php/...).
        sessao: Sessão autenticada (com cookies do Moodle).
        log: Instância de AuditoriaLogger para registar mensagens.

    Returns:
        Tuplo (nome_ficheiro, bytes_conteudo) ou None se falhar.
    """
    try:
        req = urllib.request.Request(_safe_url(url), headers={"User-Agent": "Mozilla/5.0"})
        resp = sessao.http_open(req, timeout=60, context=f"download moodle {url}")
        data = resp.read()

        # Determinar nome do ficheiro: Content-Disposition ou URL final
        cd = resp.headers.get("Content-Disposition", "")
        nome = ""
        if "filename=" in cd:
            m = re.search(r'filename[*]?="?([^";\n]+)"?', cd)
            if m:
                nome = m.group(1).strip()
        if not nome:
            url_path = urllib.parse.urlparse(resp.url).path
            nome = urllib.parse.unquote(url_path.rsplit("/", 1)[-1])

        return nome, data

    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, socket.timeout) as e:
        log.aviso(f"    Aviso: falha ao descarregar {url}: {e}")
        return None



def _extrair_ficheiros_atividade_moodle(
    url_atividade: str,
    nome_atividade: str,
    sessao: "SigarraSession",
    verbosidade: int,
    log: AuditoriaLogger,
) -> list[dict]:
    """Extrai PDFs de uma página de atividade Moodle.

    - Apanha ficheiros internos (pluginfile.php), mesmo sem .pdf no URL
    - Apanha recursos Moodle (mod/resource/view.php?id=...) que redirecionam para o ficheiro
    - Apanha links Google Docs/Drive (exporta para PDF)
    """
    try:
        req = urllib.request.Request(
            url_atividade, headers={"User-Agent": "Mozilla/5.0"}
        )
        resp = sessao.http_open(req, timeout=30, context=f"atividade moodle {url_atividade}")
        charset = resp.headers.get_content_charset() or "utf-8"
        html = resp.read().decode(charset, errors="replace")
    except (urllib.error.URLError, urllib.error.HTTPError) as e:
        log.aviso(f"    Aviso: falha ao aceder à atividade Moodle: {e}")
        return []

    enunciados = []
    urls_vistos = set()

    # --- Diagnóstico: links encontrados ---
    links_pluginfile = re.findall(r'href="(https?://[^"]*pluginfile\.php/[^"]*)"', html)
    links_google = re.findall(r'href="(https?://(?:docs|drive)\.google\.com/[^"]*)"', html)
    # NOVO: recursos Moodle (tipicamente PDFs de "Resource")
    links_resource_view = re.findall(r'href="(https?://[^"]*/mod/resource/view\.php\?[^"]*)"', html)

    log.info(
            f"      Página carregada ({len(html)} chars). "
            f"Links: {len(links_pluginfile)} pluginfile, {len(links_resource_view)} resource/view, {len(links_google)} Google"
        )

    def _tentar_adicionar_pdf(url: str, descricao: str):
        """Tenta descarregar URL e, se for PDF real, adiciona a enunciados."""
        if url in urls_vistos:
            return
        urls_vistos.add(url)

        resultado = _descarregar_ficheiro_moodle(url, sessao, log=log)
        if not resultado:
            log.debug(f"      Falha a descarregar: {url[:120]}")
            return

        nome_fich, data = resultado
        if data[:4] != b"%PDF":
            # Alguns servidores devolvem HTML (login, erro, etc.)
            base = url.split("?", 1)[0].rsplit("/", 1)[-1]
            log.debug(f"      (não é PDF real, ignorado): {nome_fich or base} ({len(data)} bytes)")
            return

        enunciados.append({
            "nome": nome_fich or (nome_atividade + ".pdf"),
            "descricao": descricao,
            "epoca": "",
            "data": "",
            "url": url,
            "pdf_bytes": data,
        })

    # Pass 1: pluginfile.php (ficheiros internos) — NÃO filtrar por .pdf
    for href_raw in links_pluginfile:
        pdf_url = html_mod.unescape(href_raw)

        # opcional: ignorar duplicados por "versão limpa"
        # (muita gente tem forcedownload=1 etc.)
        # mas não forces filtro por extensão!
        _tentar_adicionar_pdf(
            pdf_url,
            descricao=f"Moodle (pluginfile): {nome_atividade}",
        )

    # Pass 1b (NOVO): mod/resource/view.php?id=... — frequentemente redireciona para o ficheiro
    for href_raw in links_resource_view:
        res_url = html_mod.unescape(href_raw)
        _tentar_adicionar_pdf(
            res_url,
            descricao=f"Moodle (resource): {nome_atividade}",
        )

    # Pass 2: Google Docs/Drive (exportar como PDF)
    for href_raw in links_google:
        google_url = html_mod.unescape(href_raw)
        if google_url in urls_vistos:
            continue
        urls_vistos.add(google_url)

        pdf_export_url = _url_para_pdf_google(google_url)
        if not pdf_export_url:
            log.debug(f"      Google (tipo não reconhecido): {google_url[:80]}")
            continue

        log.info(f"      Google Docs/Drive: a exportar como PDF...")

        resultado = _descarregar_url_externo(pdf_export_url, nome_default=nome_atividade, log=log)
        if resultado:
            nome_fich, data = resultado
            if data[:4] == b"%PDF":
                enunciados.append({
                    "nome": nome_fich,
                    "descricao": f"Moodle/Google: {nome_atividade}",
                    "epoca": "",
                    "data": "",
                    "url": google_url,
                    "pdf_bytes": data,
                })
            else:
                log.debug(f"      Google: resposta não é PDF ({len(data)} bytes)")
        else:
            log.debug(f"      Google: falha ao descarregar")

    return enunciados



def _extrair_pdf_de_url_externo(
    moodle_url: str,
    nome_atividade: str,
    sessao: SigarraSession,
    verbosidade: int,
    log: AuditoriaLogger,
) -> dict | None:
    """Tenta extrair um PDF de um link externo do Moodle (tipo 'url').

    Segue o redirect do Moodle (mod/url/view.php?id=...) para o URL real
    e verifica se é um Google Docs/Drive (exportando como PDF) ou um PDF direto.

    Args:
        moodle_url: URL da atividade Moodle (mod/url/view.php?id=...).
        nome_atividade: Nome da atividade (para descrição).
        sessao: Sessão autenticada (com cookies do Moodle).
        verbosidade: Nível de detalhe na saída (0=quieto, 1=normal, 2=debug).
        log: Instância de AuditoriaLogger para registar mensagens.

    Returns:
        Dict com 'nome', 'descricao', 'url', 'pdf_bytes', etc., ou None.
    """
    # Seguir o redirect do Moodle para obter o URL externo real
    try:
        req = urllib.request.Request(
            moodle_url, headers={"User-Agent": "Mozilla/5.0"}
        )
        resp = sessao.http_open(req, timeout=30, context=f"url externa moodle {moodle_url}")
        url_final = resp.url
        content_type = resp.headers.get("Content-Type", "")
        data = resp.read()
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, socket.timeout) as e:
        log.aviso(f"    Aviso: falha ao seguir URL externo: {e}")
        return None

    # Caso 1: o URL final é diretamente um PDF
    if "application/pdf" in content_type and data[:4] == b"%PDF":
        url_path = urllib.parse.urlparse(url_final).path
        nome_fich = urllib.parse.unquote(url_path.rsplit("/", 1)[-1])
        if not nome_fich.lower().endswith(".pdf"):
            nome_fich = f"{nome_atividade}.pdf"
        log.info(f"    URL externo (PDF direto): {nome_fich}")
        return {
            "nome": nome_fich,
            "descricao": f"Moodle/URL: {nome_atividade}",
            "epoca": "",
            "data": "",
            "url": url_final,
            "pdf_bytes": data,
        }

    # Caso 2: Google Docs/Drive — exportar como PDF
    pdf_export_url = _url_para_pdf_google(url_final)
    if pdf_export_url:
        log.info(f"    URL externo (Google): {nome_atividade}...")
        resultado = _descarregar_url_externo(pdf_export_url, nome_default=nome_atividade, log=log)
        if resultado:
            nome_fich, pdf_data = resultado
            if pdf_data[:4] == b"%PDF":
                return {
                    "nome": nome_fich,
                    "descricao": f"Moodle/Google: {nome_atividade}",
                    "epoca": "",
                    "data": "",
                    "url": url_final,
                    "pdf_bytes": pdf_data,
                }

    # Caso 3: página HTML — procurar links Google dentro da página
    if "text/html" in content_type:
        html = data.decode("utf-8", errors="replace")
        for m in re.finditer(
            r'href="(https?://(?:docs|drive)\.google\.com/[^"]*)"', html,
        ):
            google_url = html_mod.unescape(m.group(1))
            export_url = _url_para_pdf_google(google_url)
            if export_url:
                log.info(f"    URL externo (Google via página): {nome_atividade}...")
                resultado = _descarregar_url_externo(export_url, nome_default=nome_atividade, log=log)
                if resultado:
                    nome_fich, pdf_data = resultado
                    if pdf_data[:4] == b"%PDF":
                        return {
                            "nome": nome_fich,
                            "descricao": f"Moodle/Google: {nome_atividade}",
                            "epoca": "",
                            "data": "",
                            "url": google_url,
                            "pdf_bytes": pdf_data,
                        }

    return None


# ---------------------------------------------------------------------------
# Extração de quizzes do Moodle
# ---------------------------------------------------------------------------

def _moodle_base_url(url: str) -> str:
    """Extrai o URL base do Moodle (ex: ``https://moodle2526.up.pt``)."""
    parsed = urllib.parse.urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}"


def _extrair_ano_instancia_moodle(url: str) -> str:
    """Extrai ano letivo (YYYY/YYYY) a partir do host Moodle (moodle2526...)."""
    host = (urllib.parse.urlparse(url).netloc or "").lower()
    m = re.search(r"moodle(\d{2})(\d{2})", host)
    if not m:
        return ""
    return f"20{m.group(1)}/20{m.group(2)}"


def _extrair_sesskey_moodle(html: str) -> str | None:
    """Extrai o sesskey do Moodle a partir do HTML de qualquer página.

    O sesskey é um token anti-CSRF presente em campos hidden, na config
    JavaScript ou no link de logout.
    """
    # hidden input
    m = re.search(r'name="sesskey"\s+value="([^"]+)"', html)
    if m:
        return m.group(1)
    m = re.search(r'value="([^"]+)"\s+name="sesskey"', html)
    if m:
        return m.group(1)
    # JS config
    m = re.search(r'"sesskey"\s*:\s*"([^"]+)"', html)
    if m:
        return m.group(1)
    # logout link
    m = re.search(r'logout\.php\?sesskey=([a-zA-Z0-9]+)', html)
    if m:
        return m.group(1)
    return None


def _extrair_cmid_de_url(url: str) -> str | None:
    """Extrai o CMID (course module ID) do URL ``mod/quiz/view.php?id=X``."""
    m = re.search(r'[?&]id=(\d+)', url)
    return m.group(1) if m else None


def _quiz_requer_password(html: str) -> bool:
    """Verifica se a página do quiz requer password para iniciar."""
    return bool(re.search(
        r'<input[^>]+name="quizpassword"', html, re.IGNORECASE
    ))


def _extrair_attempt_existente(html: str) -> str | None:
    """Procura um attempt ID existente (review ou em curso) na view page."""
    m = re.search(r'review\.php\?attempt=(\d+)', html)
    if m:
        return m.group(1)
    m = re.search(r'attempt\.php\?attempt=(\d+)', html)
    if m:
        return m.group(1)
    return None


def _post_moodle_form(
    url: str,
    params: dict,
    sessao: SigarraSession,
) -> tuple[str, str]:
    """POST form data para o Moodle e devolve ``(url_final, html)``."""
    dados = urllib.parse.urlencode(params).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=dados,
        headers={
            "User-Agent": "Mozilla/5.0",
            "Content-Type": "application/x-www-form-urlencoded",
        },
        method="POST",
    )
    resp = sessao.http_open(req, timeout=30, context=f"POST moodle {url}")
    url_final = resp.url
    charset = resp.headers.get_content_charset() or "utf-8"
    html = resp.read().decode(charset, errors="replace")
    return url_final, html


def _submeter_password_quiz(
    quiz_url: str,
    password: str,
    sesskey: str,
    sessao: SigarraSession,
    html_view: str,
    log: AuditoriaLogger,
) -> str:
    """Submete a password de acesso ao quiz. Devolve HTML resultante.

    Extrai o formulário de password do HTML da view page para obter
    o action URL correto e todos os campos hidden necessários
    (cmid, _qf__*, submitbutton, etc.).
    """
    # Extrair o formulário que contém o campo quizpassword
    soup = BeautifulSoup(html_view or "", "html.parser")
    form = None
    pw_input = soup.find("input", {"name": "quizpassword"})
    if pw_input:
        form = pw_input.find_parent("form")

    if form:
        # Construir URL de action
        action = form.get("action", quiz_url)
        if action and not action.startswith("http"):
            action = urllib.parse.urljoin(quiz_url, action)

        # Recolher campos hidden + submit (excluir cancel — senão o Moodle cancela)
        params = {}
        for inp in form.find_all("input"):
            name = inp.get("name")
            if not name or name == "cancel":
                continue
            tipo = (inp.get("type") or "text").lower()
            if tipo == "submit":
                params[name] = inp.get("value", "")
            elif tipo == "hidden":
                params[name] = inp.get("value", "")

        # Inserir a password
        params["quizpassword"] = password
        params.setdefault("sesskey", sesskey)

        log.debug(f"      [pw] POST {action}")
        log.debug(f"      [pw] campos: {sorted(params.keys())}")
        _, html = _post_moodle_form(action, params, sessao)
    else:
        # Fallback: POST simples como antes
        log.debug(f"      [pw] Formulário não encontrado, fallback simples")
        _, html = _post_moodle_form(quiz_url, {
            "quizpassword": password,
            "sesskey": sesskey,
        }, sessao)

    if _quiz_requer_password(html):
        raise PermissionError(f"Password do quiz rejeitada: {quiz_url}")
    return html


def _iniciar_preview_quiz(
    cmid: str,
    sesskey: str,
    moodle_base: str,
    sessao: SigarraSession,
) -> str | None:
    """Inicia uma tentativa de preview do quiz (como docente).

    POST para ``startattempt.php`` — o Moodle cria a tentativa e redireciona
    para ``attempt.php?attempt=X&cmid=Y``.

    Returns:
        Attempt ID (string numérica) ou None.
    """
    start_url = f"{moodle_base}/mod/quiz/startattempt.php"
    url_final, html = _post_moodle_form(start_url, {
        "cmid": cmid,
        "sesskey": sesskey,
    }, sessao)

    m = re.search(r'[?&]attempt=(\d+)', url_final)
    if m:
        return m.group(1)
    # fallback: procurar no HTML
    m = re.search(r'attempt=(\d+)', html)
    return m.group(1) if m else None

def _extrair_blocos_que(html: str) -> list[str]:
    """Extrai blocos de perguntas (div.que) de uma página HTML do Moodle."""
    starts = [m.start() for m in re.finditer(
        r'<div[^>]+class="[^"]*\bque\b', html)]
    if not starts:
        return []
    blocos = []
    for i, s in enumerate(starts):
        fim = starts[i + 1] if i + 1 < len(starts) else len(html)
        blocos.append(html[s:fim])
    # Truncar último bloco em marcadores estruturais (sidebar, form, etc.)
    if blocos:
        corte = re.search(
            r'</form>|<aside\b|<div[^>]+data-region="blocks-column"',
            blocos[-1], re.IGNORECASE)
        if corte:
            blocos[-1] = blocos[-1][:corte.start()]
    return blocos


def _obter_html_attempt_preview_paginado(
    moodle_base: str,
    attempt_id: str,
    cmid: str,
    sessao: SigarraSession,
    log: AuditoriaLogger,
) -> str:
    """Busca todas as páginas de um attempt e devolve HTML unificado.

    Extrai apenas os blocos de perguntas (div.que) de cada página,
    evitando duplicar <html>/<head>/<style>/<body> na concatenação.
    Usa a página 0 como template (mantém head/styles) e insere
    os blocos de todas as páginas no body.
    """
    base = f"{moodle_base}/mod/quiz/attempt.php?attempt={attempt_id}&cmid={cmid}"

    # Página 0 — usamos para descobrir quantas páginas existem
    html0 = sessao.fetch_html(f"{base}&page=0")

    # Extrair números de página dos botões de navegação do quiz
    # Moodle usa data-quiz-page="N" nos botões (não links href)
    page_nums = {int(m) for m in re.findall(
        r'data-quiz-page="(\d+)"', html0)}
    # Fallback: tentar links href tradicionais
    if not page_nums:
        page_nums = {int(m) for m in re.findall(
            r'href="[^"]*attempt\.php[^"]*page=(\d+)', html0)}
    max_page = max(page_nums) if page_nums else 0

    log.info(f"      Paginação: {max_page + 1} páginas detetadas")

    # Recolher blocos de perguntas de todas as páginas
    todos_blocos = _extrair_blocos_que(html0)
    for page in range(1, max_page + 1):
        html = sessao.fetch_html(f"{base}&page={page}")
        todos_blocos.extend(_extrair_blocos_que(html))

    log.info(f"      Total: {len(todos_blocos)} blocos de perguntas extraídos")

    if not todos_blocos:
        return html0  # fallback: devolver página 0 inteira

    # Construir HTML unificado usando head/styles da página 0
    head_match = re.search(r'<head[^>]*>.*?</head>', html0,
                           re.DOTALL | re.IGNORECASE)
    head = head_match.group(0) if head_match else "<head><meta charset='utf-8'></head>"

    conteudo = "\n".join(todos_blocos)
    return f"<!DOCTYPE html><html>{head}<body>\n{conteudo}\n</body></html>"


def _finalizar_preview_quiz(
    attempt_id: str,
    cmid: str,
    sesskey: str,
    moodle_base: str,
    sessao: SigarraSession,
    log: AuditoriaLogger,
) -> bool:
    """Finaliza a tentativa de preview (torna a review page disponível)."""
    url = f"{moodle_base}/mod/quiz/processattempt.php"
    params = {
        "attempt": attempt_id,
        "finishattempt": "1",
        "sesskey": sesskey,
        "cmid": cmid,
        "timeup": "0",
        "slots": "",
    }
    try:
        _, html = _post_moodle_form(url, params, sessao)
        # Se o Moodle pedir confirmação, re-submeter
        if "finishattempt" in html and 'type="submit"' in html:
            _post_moodle_form(url, params, sessao)
        return True
    except (urllib.error.URLError, urllib.error.HTTPError) as e:
        log.aviso(f"    Aviso: falha ao finalizar preview do quiz: {e}")
        return False


def _inline_images_moodle(html: str, sessao: SigarraSession) -> str:
    """Substitui URLs de imagens por data URIs base64 (HTML auto-contido)."""

    _MIME = {
        "png": "image/png", "jpg": "image/jpeg", "jpeg": "image/jpeg",
        "gif": "image/gif", "svg": "image/svg+xml", "webp": "image/webp",
    }

    def _substituir(match):
        tag = match.group(0)
        src = match.group(1)
        if src.startswith("data:"):
            return tag
        ext = src.split("?")[0].rsplit(".", 1)[-1].lower() if "." in src else ""
        mime = _MIME.get(ext, "image/png")
        try:
            req = urllib.request.Request(_safe_url(src), headers={"User-Agent": "Mozilla/5.0"})
            resp = sessao.http_open(req, timeout=15, context=f"inline image {src}")
            img_data = resp.read()
            ct = resp.headers.get("Content-Type", "")
            if ct and "/" in ct:
                mime = ct.split(";")[0].strip()
            encoded = base64.b64encode(img_data).decode("ascii")
            return tag.replace(src, f"data:{mime};base64,{encoded}")
        except Exception:
            return tag

    return re.sub(r'<img\s[^>]*src="([^"]+)"[^>]*>', _substituir, html)



@dataclass
class QuizMeta:
    summative_value: Optional[int]   # 0,1,2 ou None
    is_summative: Optional[bool]     # True/False/None
    quizpassword: Optional[str]      # pode vir None/''

def parse_modedit_quiz_meta(html: str) -> QuizMeta:
    soup = BeautifulSoup(html, "html.parser")

    # 1) Tipo (formativo/sumativo): input name="summative" com checked
    checked = soup.select_one('input[name="summative"][checked]')
    summative_value = None
    if checked and checked.has_attr("value"):
        try:
            summative_value = int(checked["value"])
        except ValueError:
            summative_value = None

    is_summative = None if summative_value is None else (summative_value != 0)

    # 2) Senha: input name="quizpassword"
    pw = soup.select_one('input[name="quizpassword"]')
    quizpassword = None
    if pw is not None:
        quizpassword = pw.get("value")  # pode ser '' ou pode nem existir
        # Se value vazio/None, tentar defaultValue ou data attributes
        if not quizpassword:
            quizpassword = pw.get("data-initial-value") or pw.get("defaultvalue") or None
    # Fallback: regex no HTML raw (BS4 pode perder atributos em inputs complexos)
    if not quizpassword:
        m = re.search(r'name="quizpassword"[^>]*\bvalue="([^"]+)"', html)
        if not m:
            m = re.search(r'\bvalue="([^"]+)"[^>]*name="quizpassword"', html)
        if m:
            quizpassword = m.group(1)

    return QuizMeta(
        summative_value=summative_value,
        is_summative=is_summative,
        quizpassword=quizpassword
    )

def obter_quiz_meta(
    session,
    base_url: str,
    cmid,
    output_dir: "Path | None",
    verbosidade: int,
    log: AuditoriaLogger,
) -> QuizMeta:
    url = urljoin(base_url, f"/course/modedit.php?update={cmid}")
    html = session.fetch_html(url)

    # Debug: guardar HTML para inspeção (apenas V>=2)
    if verbosidade >= 2:
        _dbg = output_dir if output_dir else _SCRIPT_DIR / "output"
        _dbg.mkdir(parents=True, exist_ok=True)
        (_dbg / f"quiz_modedit_{cmid}.html").write_text(html, encoding="utf-8")

    meta = parse_modedit_quiz_meta(html)

    # Debug: mostrar o que realmente foi extraído (apenas V>=2)
    if verbosidade >= 2:
        if meta.quizpassword is not None:
            pw_repr = repr(meta.quizpassword)
            log.debug(f"      [modedit] quizpassword extraída: {pw_repr} (len={len(meta.quizpassword)})")
        else:
            # Tentar encontrar via regex como diagnóstico
            m = re.search(r'name="quizpassword"[^>]*value="([^"]*)"', html)
            if not m:
                m = re.search(r'value="([^"]*)"[^>]*name="quizpassword"', html)
            if m:
                log.debug(f"      [modedit] BS4 não encontrou, regex encontrou: {m.group(1)!r}")
            else:
                log.debug(f"      [modedit] quizpassword não encontrada no HTML")

    return meta

def _remover_feedback_bs4(html: str) -> str:
    soup = BeautifulSoup(html, "html.parser")

    # Remove blocos de feedback/resultados
    for sel in [
        "div.outcome",
        "div.feedback",
        "div.rightanswer",
        "div.specificfeedback",
        "div.correct",
        "div.incorrect",
    ]:
        for tag in soup.select(sel):
            tag.decompose()

    return str(soup)

def _limpar_html_quiz(html: str, nome_quiz: str, nome_uc: str = "") -> str:
    """Extrai conteúdo das perguntas e devolve HTML limpo para conversão PDF.

    Remove chrome do Moodle (flag icons, botões de edição, estado de resposta,
    badges de versão, sidebar, inputs, áreas de resposta vazia, etc.)
    e mantém cotações de forma compacta.  Suporta PT e EN.
    """

    # --- 1. Remoções globais (antes de extrair conteúdo) ---

    # Scripts, styles, noscript
    html = re.sub(r'<script[^>]*>.*?</script>', '', html,
                  flags=re.DOTALL | re.IGNORECASE)
    html = re.sub(r'<noscript[^>]*>.*?</noscript>', '', html,
                  flags=re.DOTALL | re.IGNORECASE)
    html = re.sub(r'<style[^>]*>.*?</style>', '', html,
                  flags=re.DOTALL | re.IGNORECASE)

    # Event handlers inline
    html = re.sub(r'\s+on\w+="[^"]*"', '', html)

    # Remover estilos específicos do MS Word (mso-*)
    html = re.sub(
        r'\sstyle="[^"]*mso-[^"]*"',
        '',
        html,
        flags=re.IGNORECASE
    )

    # Limpeza adicional comum de HTML colado do Word
    html = re.sub(r'\sclass="Mso[^"]*"', '', html, flags=re.IGNORECASE)
    html = re.sub(r'</?o:p[^>]*>', '', html, flags=re.IGNORECASE)

    # Escalar imagens para caber nas margens do PDF
    # A4 (210mm) - 2×2cm margens = 170mm ≈ 640px a 96dpi
    # xhtml2pdf não suporta max-width CSS; usar width hardcoded em pixels
    _IMG_MAX_PX = 640

    def _escalar_img(m):
        tag = m.group(0)
        # Extrair largura original (atributo width ou style)
        w_attr = re.search(r'\bwidth\s*=\s*"(\d+)', tag)
        w_style = re.search(r'width\s*:\s*(\d+)', tag)
        w = int(w_attr.group(1)) if w_attr else (int(w_style.group(1)) if w_style else 0)
        if w > _IMG_MAX_PX or w == 0:
            # Remover width/height antigos
            tag = re.sub(r'\s*(?:width|height)\s*=\s*"[^"]*"', '', tag)
            tag = re.sub(r'\s*style="[^"]*"', '', tag)
            # Inserir largura máxima
            tag = tag.replace('<img', f'<img width="{_IMG_MAX_PX}"', 1)
        return tag

    html = re.sub(r'<img\b[^>]*/?>', _escalar_img, html, flags=re.IGNORECASE)

    # Corrigir tipos de listas incompatíveis com xhtml2pdf
    html = re.sub(
        r'(<ul\b[^>]*\btype=["\'])disc(["\'])',
        r'\1disk\2',
        html,
        flags=re.IGNORECASE
    )
    html = re.sub(
        r'<(ul|ol)\b([^>]*?)\btype=["\'](?!circle|disk|square)[^"\']*["\']([^>]*)>',
        r'<\1\2\3>',
        html,
        flags=re.IGNORECASE
    )


    # --- 2. Remover UI chrome do Moodle ---

    # Flag icons ("Destacar pergunta" / "Flag question") — contêm SVG grandes
    html = re.sub(
        r'<(?:span|div|label)[^>]+class="[^"]*\bquestionflag\b[^"]*"[^>]*>'
        r'.*?</(?:span|div|label)>',
        '', html, flags=re.DOTALL | re.IGNORECASE,
    )
    html = re.sub(r'<img[^>]+flagged[^>]*/?\s*>', '', html,
                  flags=re.IGNORECASE)

    # "Editar pergunta" / "Edit question" links
    html = re.sub(
        r'<(?:div|a|span)[^>]+class="[^"]*\beditquestion\b[^"]*"[^>]*>'
        r'.*?</(?:div|a|span)>',
        '', html, flags=re.DOTALL | re.IGNORECASE,
    )

    # Remover o cabeçalho "Informação"/"Information" dentro de blocos informativos
    html = re.sub(
        r'<h3\b[^>]*class=["\'][^"\']*\bno\b[^"\']*["\'][^>]*>\s*(Informação|Informacao|Information)\s*</h3>',
        '',
        html,
        flags=re.IGNORECASE
    )

    # Badge de versão: "v3 (última)" / "v2 (latest)"
    html = re.sub(
        r'<span[^>]+class="[^"]*\bbadge\b[^"]*"[^>]*>.*?</span>',
        '', html, flags=re.DOTALL | re.IGNORECASE,
    )

    # Estado da resposta ("Não respondida", "Not yet answered", etc.)
    html = re.sub(
        r'<div[^>]+class="[^"]*\bstate\b[^"]*"[^>]*>.*?</div>',
        '', html, flags=re.DOTALL | re.IGNORECASE,
    )

    # Remover feedback/resultados da tentativa (inclui "A sua resposta...", "Resposta correta", etc.)
    html = _remover_feedback_bs4(html)

    def _compactar_cotacao_texto(inner_html: str) -> str:
        texto = re.sub(r'<[^>]+>', '', inner_html)
        nums = re.findall(r'[\d]+[,.][\d]+|[\d]+', texto)
        return f' <span class="cotacao">[{" / ".join(nums)} pt]</span>' if nums else ''

    html = re.sub(
        r'<div[^>]+class=(["\'])[^"\']*\bgrade\b[^"\']*\1[^>]*>(.*?)</div>',
        lambda m: _compactar_cotacao_texto(m.group(2)),
        html,
        flags=re.DOTALL | re.IGNORECASE
    )

    # Colar cotação no mesmo heading da pergunta (apenas dentro do bloco .info)
    html = re.sub(
        r'(<div\b[^>]*class=["\'][^"\']*\binfo\b[^"\']*["\'][^>]*>\s*)'
        r'(<h3\b[^>]*class=["\'][^"\']*\bno\b[^"\']*["\'][^>]*>.*?</h3>)\s*'
        r'(<span\b[^>]*class=["\'][^"\']*\bcotacao\b[^"\']*["\'][^>]*>.*?</span>)',
        r'\1\2&nbsp;\3',
        html,
        flags=re.IGNORECASE | re.DOTALL
    )


    # Elementos acessibilidade (screen-reader only) — não visíveis mas poluem PDF
    # "Enunciado da pergunta", "Texto informativo", "Question text", etc.
    html = re.sub(
        r'<[^>]+class="[^"]*\baccesshide\b[^"]*"[^>]*>.*?</[^>]+>',
        '', html, flags=re.DOTALL,
    )

    # Remover legends "prompt/sr-only" (é aí que costuma vir "... Resposta")
    html = re.sub(
        r'<legend\b[^>]*class\s*=\s*(["\'])[^"\']*\b(sr-only|accesshide)\b[^"\']*\1[^>]*>.*?</legend>',
        '',
        html,
        flags=re.DOTALL | re.IGNORECASE
    )

    # E remover spans sr-only restantes (ex.: <span class="sr-only">Pergunta N</span>)
    html = re.sub(
        r'<span\b[^>]*class\s*=\s*(["\'])[^"\']*\bsr-only\b[^"\']*\1[^>]*>.*?</span>',
        '',
        html,
        flags=re.DOTALL | re.IGNORECASE
    )

    # Inputs hidden
    html = re.sub(r'<input[^>]+type=["\']hidden["\'][^>]*/?\s*>', '', html,
                  flags=re.IGNORECASE)

    # Radio buttons → ( ), checkboxes → [ ] (ASCII para renderizar bem no PDF)
    html = re.sub(r'<input[^>]+type=["\']radio["\'][^>]*/?\s*>', '( ) ', html,
                  flags=re.IGNORECASE)
    html = re.sub(r'<input[^>]+type=["\']checkbox["\'][^>]*/?\s*>', '[ ] ', html,
                  flags=re.IGNORECASE)

    # "Apagar a minha resposta" / "Clear my choice" (opção extra em multichoice)
    html = re.sub(
        r'<div[^>]+class="[^"]*\bqtype_multichoice_clearchoice\b[^"]*"[^>]*>.*?</div>',
        '', html, flags=re.DOTALL | re.IGNORECASE,
    )
    # Fallback: link/texto solto "Apagar a minha resposta" / "Clear my choice"
    html = re.sub(
        r'<a\b[^>]*>\s*\(?\s*\)?\s*(?:Apagar a minha resposta|Clear my choice)\s*</a>',
        '', html, flags=re.IGNORECASE,
    )
    html = re.sub(
        r'\(\s*\)\s*(?:Apagar a minha resposta|Clear my choice)',
        '', html, flags=re.IGNORECASE,
    )

    # Espaço de respostas para questões de resposta aberta
    html = re.sub(
        r'(?:<[^>]+>\s*)*'
        r'(Texto\s+da\s+resposta(?:\s+Pergunta\s+\d+)?|Response\s+text(?:\s+Question\s+\d+)?)'
        r'(?:\s*</[^>]+>)*',
        '',
        html,
        flags=re.IGNORECASE
    )

    # Outros inputs que sobraram
    html = re.sub(r'<input[^>]*/?\s*>', '', html, flags=re.IGNORECASE)

    # Áreas de resposta vazias (essay/textbox) — caixas em branco grandes
    # "Texto da resposta Pergunta N" / "Response text Question N"
    html = re.sub(
        r'<div[^>]+class="[^"]*\bqtype_essay_response\b[^"]*"[^>]*>.*?</div>',
        '', html, flags=re.DOTALL | re.IGNORECASE,
    )
    html = re.sub(
        r'<div[^>]+class="[^"]*\battachments\b[^"]*"[^>]*>\s*</div>',
        '', html, flags=re.DOTALL,
    )

    # Tags <label> e </label> órfãos (restantes após remoção de questionflag)
    html = re.sub(r'</label>', '', html)
    # Fechos órfãos comuns (por vezes ficam depois de remover chrome do Moodle)
    html = re.sub(r'</legend>', '', html, flags=re.IGNORECASE)

    # Remover parágrafos vazios e quebras repetidas (reduz "linhas em branco" no PDF)
    html = re.sub(r'<p[^>]*>\s*</p>', '', html, flags=re.DOTALL | re.IGNORECASE)
    html = re.sub(r'(<br\s*/?>\s*){3,}', '<br><br>', html, flags=re.IGNORECASE)
    # Compactar whitespace entre tags (evita nós de texto só com \n/espacos)
    html = re.sub(r'>\s+<', '><', html)

    # Fieldset wrappers (remover tags, manter conteúdo)
    html = re.sub(r'</?fieldset[^>]*>', '', html, flags=re.IGNORECASE)

    # Tentar extrair nome da UC do cabeçalho (se não fornecido via parâmetro)
    if not nome_uc:
        _m_uc = re.search(
            r'<div[^>]*class="[^"]*page-header-headings[^"]*"[^>]*>\s*<h1[^>]*>(.*?)</h1>',
            html, re.DOTALL | re.IGNORECASE,
        )
        if _m_uc:
            nome_uc = _m_uc.group(1).strip()

    # Navegação, header, footer
    html = re.sub(r'<nav[^>]*>.*?</nav>', '', html,
                  flags=re.DOTALL | re.IGNORECASE)
    html = re.sub(r'<header[^>]*>.*?</header>', '', html,
                  flags=re.DOTALL | re.IGNORECASE)
    html = re.sub(r'<footer[^>]*>.*?</footer>', '', html,
                  flags=re.DOTALL | re.IGNORECASE)
    # Sidebar inteira (Blocos, navegação quiz, foto autor, botões)
    html = re.sub(r'<aside\b[^>]*>.*?</aside>', '', html,
                  flags=re.DOTALL | re.IGNORECASE)

    # Botões finais (Terminar revisão / Finish review, Guardar respostas assinaladas, etc.)
    html = re.sub(
        r'<div\b[^>]*class=["\'][^"\']*\bsubmitbtns\b[^"\']*["\'][^>]*>.*?</div>',
        '',
        html,
        flags=re.IGNORECASE | re.DOTALL
)

    # --- 3. Compactar opções de escolha múltipla ---
    # Transformar cada div.r0/r1 com divs nested em <p> inline:
    #   <div class="r0">○ <div class="d-flex ..."><span class="answernumber">
    #   a. </span><div class="flex-fill ms-1">texto</div></div> </div>
    # → <p class="opcao">○ a. texto</p>

    def _flatten_opcao(m):
        bloco = m.group(0)
        marcador = ''
        if '( )' in bloco:
            marcador = '( ) '
        elif '[ ]' in bloco:
            marcador = '[ ] '
        num_m = re.search(r'class="answernumber">(.*?)</span>', bloco)
        num = num_m.group(1) if num_m else ''
        # Texto da resposta: dentro de flex-fill, pode conter <p>, <code>, etc.
        text_m = re.search(
            r'class="flex-fill[^"]*"[^>]*>(.*?)</div>', bloco, re.DOTALL)
        texto = text_m.group(1).strip() if text_m else ''
        # Se vier embrulhado em <p>...</p>, remover wrapper para evitar espaçamento extra no PDF
        texto = re.sub(r'^\s*<p[^>]*>', '', texto, flags=re.IGNORECASE)
        texto = re.sub(r'</p>\s*$', '', texto, flags=re.IGNORECASE)
        if not texto:
            texto = re.sub(r'<[^>]+>', '', bloco).strip()
        return f'<p class="opcao">{marcador}{num}{texto}</p>\n'

    # Padrão: <div class="r0/r1"> ... 3 </div> nested (r0 > d-flex > flex-fill)
    html = re.sub(
        r'<div\s+class="r[01]">.*?</div>\s*</div>\s*</div>',
        _flatten_opcao, html, flags=re.DOTALL,
    )

    # --- 4. Extrair blocos de perguntas ---

    # Localizar inícios de blocos "que" (cada pergunta é <div class="que ...">)
    starts = [m.start() for m in re.finditer(
        r'<div[^>]+class="[^"]*\bque\b', html)]

    if starts:
        blocos = []
        for i, s in enumerate(starts):
            fim = starts[i + 1] if i + 1 < len(starts) else None
            blocos.append(html[s:fim] if fim else html[s:])
        # Truncar último bloco: remover sidebar/rodapé que sobrou
        if blocos:
            corte = re.search(
                r'</form>|<aside\b|<div[^>]+data-region="blocks-column"',
                blocos[-1], re.IGNORECASE)
            if corte:
                blocos[-1] = blocos[-1][:corte.start()]
        conteudo = "\n<hr>\n".join(blocos)
    else:
        # Fallback: conteúdo principal
        m = re.search(
            r'<div[^>]+(?:id="page-content"|role="main")[^>]*>(.*)',
            html, re.DOTALL,
        )
        if m:
            conteudo = m.group(1)
            footer = re.search(
                r'<footer\b|<div[^>]+id="page-footer"|<aside\b', conteudo)
            if footer:
                conteudo = conteudo[:footer.start()]
        else:
            m = re.search(r'<body[^>]*>(.*)</body>', html,
                          re.DOTALL | re.IGNORECASE)
            conteudo = m.group(1) if m else html

    # Limpar linhas vazias excessivas
    conteudo = re.sub(r'(\s*\n){3,}', '\n\n', conteudo)

    return f"""<!DOCTYPE html>
<html lang="pt">
<head>
<meta charset="utf-8">
<title>{html_mod.escape(nome_quiz)}</title>
<style>
body {{ font-family: Arial, Helvetica, sans-serif; font-size: 11pt;
       margin: 2cm; line-height: 1.15; }}

/* xhtml2pdf tende a exagerar margens default */
p {{ margin: 0; padding: 0; }}
.qtext p {{ margin: 0; padding: 0; }}

/* headings do Moodle (Pergunta X) — tirar margens e manter inline para colar com cotação */
h1 {{ font-size: 16pt; margin: 0 0 0.6em 0; }}
h3 {{ margin: 0; padding: 0; display: inline; }}

.que {{ margin-bottom: 0.6em; page-break-inside: avoid; }}

/* bloco de topo (Pergunta X + cotação) */
.info {{ margin: 0 0 0.15em 0; padding: 0; }}
.info .qno {{ font-weight: bold; font-size: 12pt; }}
.cotacao {{ display: inline-block; font-size: 9pt; color: #555; font-style: italic; margin-left: 0.6em; }}
/* reduzir espaçamento antes do enunciado */
.formulation {{ margin: 0.15em 0; }}
.qtext {{ display: block; margin: 0 0 0.15em 0; padding: 0; }}

/* opções */
.opcao {{ margin: 0.03em 0 0.03em 1.5em; line-height: 1.15; }}

/* separadores e restantes */
hr {{ border: none; border-top: 1px solid #ccc; margin: 0.35em 0; }}
img {{ width: auto; height: auto; }}
.qtext, .formulation, .que {{ overflow: hidden; }}

table {{ border-collapse: collapse; margin: 0.4em 0; }}
td, th {{ border: 1px solid #999; padding: 4px 8px; }}

pre, code {{ font-size: 10pt; background: #f5f5f5; padding: 2px 4px; }}
</style>

</head>
<body>
{f'<p style="font-size:13pt;margin:0 0 0.2em 0">{html_mod.escape(nome_uc)}</p>' if nome_uc else ''}
<h1>{html_mod.escape(nome_quiz)}</h1>
{conteudo}
</body>
</html>"""


def _html_para_pdf(html: str, nome_ficheiro: str, log: AuditoriaLogger) -> bytes | None:
    """Converte HTML para PDF via xhtml2pdf (se instalado).

    Returns:
        Bytes do PDF, ou None se xhtml2pdf não disponível ou falhar.
    """
    try:
        from xhtml2pdf import pisa
        import io
        resultado = io.BytesIO()
        status = pisa.CreatePDF(html, dest=resultado, encoding="utf-8")
        if status.err:
            log.aviso(f"    Aviso: xhtml2pdf reportou {status.err} erro(s) "
                  f"ao converter {nome_ficheiro}")
        pdf_bytes = resultado.getvalue()
        if pdf_bytes and pdf_bytes[:4] == b"%PDF":
            return pdf_bytes
        return None
    except ImportError:
        return None
    except Exception as e:
        log.aviso(f"    Aviso: erro na conversão HTML→PDF: {e}")
        return None


def _obter_html_attempt_preview(moodle_base: str, attempt_id: str, cmid: str, 
                                sessao: SigarraSession, log: AuditoriaLogger) -> str:
    # Usar sempre abordagem paginada — funciona para quizzes de 1 ou N páginas.
    # (attempt.php não suporta showall=1 de forma fiável; pode remover
    #  navegação sem mostrar todas as perguntas, induzindo em erro.)
    return _obter_html_attempt_preview_paginado(moodle_base, attempt_id, cmid, sessao, log)


def extrair_quiz_moodle(
    quiz_url: str,
    nome_quiz: str,
    sessao: SigarraSession,
    ignorar_formativo: bool = True,
    verbosidade: int = 1,
    output_dir: "Path | None" = None,
    log: AuditoriaLogger = None,
) -> dict | None:
    """Extrai um quiz do Moodle como PDF usando preview de docente.

    Fluxo: view page → password (auto via modedit) → start preview →
    attempt pages → finish preview → fallback review page →
    inline images → clean HTML → PDF.

    Returns:
        Dict standard de enunciado (com ``pdf_bytes``) ou None.
    """

    log.info(f"    [quiz] {nome_quiz}")
    log.info(f"      URL: {quiz_url}")

    # 1. Fetch quiz view page
    try:
        req = urllib.request.Request(quiz_url, headers={"User-Agent": "Mozilla/5.0"})
        resp = sessao.http_open(req, timeout=30, context=f"quiz view {quiz_url}")
        charset = resp.headers.get_content_charset() or "utf-8"
        html_view = resp.read().decode(charset, errors="replace")
    except (urllib.error.URLError, urllib.error.HTTPError) as e:
        log.error(f"      Erro ao aceder ao quiz: {e}")
        return None

    # 2. Extrair sesskey
    sesskey = _extrair_sesskey_moodle(html_view)
    if not sesskey:
        log.error(f"      Erro: sesskey não encontrado")
        return None

    # 3. Base URL e CMID
    moodle_base = _moodle_base_url(quiz_url)
    cmid = _extrair_cmid_de_url(quiz_url)
    if not cmid:
        log.error(f"      Erro: CMID não encontrado no URL")
        return None

    # 4. Verificar se o quiz é sumativo e/ou protegido por password
    try:
        meta = obter_quiz_meta(
            sessao,
            moodle_base,
            cmid,
            output_dir=output_dir,
            verbosidade=verbosidade,
            log=log,
        )
        log.debug(f"      Quiz meta: summative={meta.summative_value}, "
                f"is_summative={meta.is_summative}, "
                f"password={'set' if meta.quizpassword else 'not set'}")
        if meta.is_summative is False and ignorar_formativo:
            log.debug(f"      Quiz formativo ignorado {cmid}")
            return None
    except Exception as e:
        log.aviso(f"      Aviso: não foi possível obter meta do quiz: {e}")
        meta = QuizMeta(summative_value=None, is_summative=None, quizpassword=None)

    # 5. Password — usar password das definições do quiz (modedit) se disponível
    if _quiz_requer_password(html_view):
        pw = meta.quizpassword or None
        if pw:
            log.debug(f"      Password obtida das definições do quiz.")
        else:
            try:
                pw = input(f"      Password para '{nome_quiz}': ")
            except EOFError:
                log.debug(f"      Sem password disponível.")
                return None
        try:
            html_view = _submeter_password_quiz(quiz_url, pw, sesskey, sessao, html_view, log=log)
            # Sesskey pode mudar após submissão
            sesskey = _extrair_sesskey_moodle(html_view) or sesskey
        except PermissionError as e:
            log.error(f"      {e}")
            return None

    # 6. Tentativa existente?
    attempt_id = _extrair_attempt_existente(html_view)
    novo_preview = False
    if attempt_id:
        log.debug(f"      Tentativa existente: attempt={attempt_id}")
    else:
        # 7. Iniciar preview
        log.info(f"      A iniciar preview...")
        try:
            attempt_id = _iniciar_preview_quiz(cmid, sesskey, moodle_base, sessao)
        except (urllib.error.URLError, urllib.error.HTTPError) as e:
            log.error(f"      Erro ao iniciar preview: {e}")
            return None
        if not attempt_id:
            log.error(f"      Erro: não foi possível iniciar preview")
            return None
        log.debug(f"      Preview iniciado: attempt={attempt_id}")
        novo_preview = True

    # 8. Extrair perguntas via attempt.php (funciona durante preview ativo)
    log.debug(f"      A extrair attempt pages...")
    try:
        html_review = _obter_html_attempt_preview(
            moodle_base, attempt_id, cmid, sessao, log
        )
    except Exception:
        html_review = ""

    n_perguntas = html_review.count('class="que ')
    log.debug(f"      Attempt page: {len(html_review)} chars, {n_perguntas} perguntas")

    # 9. Finalizar preview novo (cleanup — APÓS extrair perguntas)
    if novo_preview:
        log.info(f"      A finalizar preview...")
        _finalizar_preview_quiz(attempt_id, cmid, sesskey, moodle_base, sessao, log)

    # Fallback: review.php (para tentativas já finalizadas ou se attempt não tinha perguntas)
    if n_perguntas < 1:
        review_url = (
            f"{moodle_base}/mod/quiz/review.php"
            f"?attempt={attempt_id}&cmid={cmid}&showall=1"
        )
        log.debug(f"      A extrair review page (fallback)...")
        try:
            req = urllib.request.Request(review_url, headers={"User-Agent": "Mozilla/5.0"})
            resp = sessao.http_open(req, timeout=60, context=f"quiz review {review_url}")
            charset = resp.headers.get_content_charset() or "utf-8"
            html_review = resp.read().decode(charset, errors="replace")
        except (urllib.error.URLError, urllib.error.HTTPError) as e:
            log.error(f"      Erro ao aceder à review page: {e}")
            return None
        n_perguntas = html_review.count('class="que ')
        log.debug(f"      Review page: {len(html_review)} chars, {n_perguntas} perguntas")

    if len(html_review) < 500:
        log.debug(f"      Review page vazia ou muito curta ({len(html_review)} chars)")
        return None

    # Debug: guardar view e review pages com CMID distinto (apenas V>=2)
    _dbg = output_dir if output_dir else _SCRIPT_DIR / "output"
    if verbosidade >= 2:
        _dbg.mkdir(parents=True, exist_ok=True)
        (_dbg / f"quiz_view_{cmid}.html").write_text(
            html_view, encoding="utf-8")
        (_dbg / f"quiz_review_{cmid}.html").write_text(
            html_review, encoding="utf-8")
        log.info(f"      Debug: quiz_view_{cmid}.html, quiz_review_{cmid}.html")

    # 9. Inline images
    log.debug(f"      A processar imagens...")
    html_review = _inline_images_moodle(html_review, sessao)

    # Extrair nome da UC do cabeçalho da view page
    _m_uc = re.search(
        r'<div[^>]*class="[^"]*page-header-headings[^"]*"[^>]*>\s*<h1[^>]*>(.*?)</h1>',
        html_view, re.DOTALL | re.IGNORECASE,
    )
    nome_uc_view = _m_uc.group(1).strip() if _m_uc else ""

    # 10. Limpar HTML
    html_limpo = _limpar_html_quiz(html_review, nome_quiz, nome_uc=nome_uc_view)

    # Debug: guardar HTML limpo para inspeção (apenas V>=2)
    if verbosidade >= 2:
        (_dbg / f"quiz_limpo_{cmid}.html").write_text(
            html_limpo, encoding="utf-8")

    # 11. Converter para PDF
    pdf_bytes = _html_para_pdf(html_limpo, nome_quiz, log)

    if pdf_bytes:
        log.info(f"      -> PDF gerado: {len(pdf_bytes) / 1024:.0f} KB")
    else:
        # Fallback: guardar HTML na pasta output (não incluir nos enunciados)
        pasta = output_dir if output_dir else _SCRIPT_DIR / "output"
        pasta.mkdir(parents=True, exist_ok=True)
        nome_limpo = re.sub(r'[<>:"/\\|?*]', '_', nome_quiz)
        caminho = pasta / f"{nome_limpo}.html"
        caminho.write_text(html_limpo, encoding="utf-8")
        log.aviso(f"      -> PDF não disponível (xhtml2pdf não instalado)")
        log.info(f"      -> HTML guardado: {caminho}")
        log.info(f"        (pip install xhtml2pdf para conversão automática)")
        return None

    # 12. Construir dict de enunciado
    nome_ficheiro = re.sub(r'[<>:"/\\|?*]', '_', nome_quiz) + ".pdf"
    return {
        "nome": nome_ficheiro,
        "descricao": f"Moodle: {nome_quiz}",
        "epoca": "",
        "data": "",
        "url": quiz_url,
        "pdf_bytes": pdf_bytes,
        "origem": "Moodle/quiz",
    }


# ---------------------------------------------------------------------------
# Extração de enunciados e orquestração
# ---------------------------------------------------------------------------



# --- Normalização & tokenização ---

_TOKEN_RE = re.compile(r"[a-z0-9]+", re.IGNORECASE)

def _normalize(text: str) -> str:
    """
    Lowercase + remove acentos + normaliza separadores.
    """
    text = text.lower()
    text = unicodedata.normalize("NFKD", text)
    text = "".join(ch for ch in text if not unicodedata.combining(ch))
    return text

def _tokens(text: str) -> Set[str]:
    """
    Extrai tokens alfanuméricos (palavra-a-palavra), já normalizados.
    """
    text = _normalize(text)
    return set(_TOKEN_RE.findall(text))


# --- Listas de palavras (tokens) ---

# Palavras que indicam avaliação (como tokens isolados)
_AVALIACAO_TOKENS = {
    # PT
    "exame", "teste", "questionário", "trabalho", "projeto", "prova", "avaliacao", 
    "frequencia", "exercicio", "exercicios", "laboratorio",

    # EN
    "exam", "test", "quiz", "assignment", "project", "assessment",
    "midterm", "homework", "exercise", "exercises", "lab",
}

# Palavras que normalmente significam "não é avaliação" (materiais, correções, exemplos, etc.)
# Nota: NÃO incluímos "form" nem "grade/marks" por serem muito ambíguas em substring/semântica.
_EXCLUIR_TOKENS = {
    # PT
    "solucao", "solucoes", "correcao", "resposta", "respostas",
    "classificacao", "classificacoes", "notas",
    "apresentacao", "apresentacoes", "aula", "palestra", 
    "slide", "slides", "leitura", "material", "pratica",
    "submissao", "submissoes", "entrega", "entregas",
    "exemplo", "exemplos", 

    # EN
    "solution", "solutions", "correction", "corrections", "answer", "answers",
    "grading", "grade", "grades", "marks",
    "presentation", "presentations", "lecture", 
    "handout", "handouts", "reading", "material", "materials",
    "submissions", "deliverables",
    "sample", "samples", "example", "examples",
}


def _e_atividade_avaliacao(nome: str, tipo: str) -> bool:
    """
    Determina se uma atividade Moodle é provavelmente de avaliação.

    Regras (mantém a tua filosofia original, mas mais robusta):
    - assign / quiz: sempre True
    - resource / url / page / folder / ...: só se tiver indícios de avaliação e não tiver indícios fortes de exclusão
    - em geral: tokens + frases, evitando falsos positivos por substring
    """
    nome_norm = _normalize(nome)
    toks = _tokens(nome_norm)

    if not (toks & _AVALIACAO_TOKENS):
        return False

    if toks & _EXCLUIR_TOKENS:
        return False

    return True


def extrair_enunciados_moodle(
    conteudos_moodle: dict,
    sessao: SigarraSession,
    verbosidade: int ,
    output_dir: "Path | None",
    log: AuditoriaLogger
) -> list[dict]:
    """Extrai enunciados de avaliação do Moodle (trabalhos, recursos e links).

    Descarrega ficheiros PDF de atividades tipo 'assign' (trabalhos/projetos),
    'resource' (ficheiros) e 'url' (links externos, incluindo Google Drive/Docs).
    Para 'resource' e 'url', aplica filtro por palavras-chave no nome da
    atividade para evitar descarregar slides de aulas ou material de leitura.
    Quizzes são reportados mas não extraídos (requerem acesso especial).

    Args:
        conteudos_moodle: Dict retornado por extrair_moodle_uc().
        sessao: Sessão autenticada (com cookies do Moodle).
        verbosidade: Nível de detalhe na saída (0=quieto, 1=normal, 2=debug).
    Returns:
        Lista de dicts com 'nome', 'descricao', 'epoca', 'data',
        'url', 'pdf_bytes' e 'origem'.
    """
    if not conteudos_moodle:
        return []

    # Inventariar atividades por tipo
    contagem = {}
    todas_atividades = []
    for sec in conteudos_moodle.get("seccoes", []):
        for act in sec.get("atividades", []):
            tipo = act.get("tipo", "outro")
            contagem[tipo] = contagem.get(tipo, 0) + 1
            todas_atividades.append(act)

    resumo = ", ".join(f"{n} {t}" for t, n in sorted(contagem.items())) 
    log.info(f"  Atividades Moodle: {resumo}")

    enunciados = []
    quizzes_encontrados = []
    ignorados = []

    for act in todas_atividades:
        tipo = act.get("tipo", "")
        nome = act.get("nome", "")
        url = act.get("url", "")

        if not url:
            continue

        # Para resource e url, filtrar por keywords de avaliação
        #if tipo in ("resource", "url") and not _e_atividade_avaliacao(nome, tipo):
        if not _e_atividade_avaliacao(nome, tipo):
            ignorados.append((tipo, nome))
            continue

        if tipo == "quiz":
            try:
                resultado_quiz = extrair_quiz_moodle(url, nome, sessao, verbosidade=verbosidade, output_dir=output_dir, log=log)
                if resultado_quiz:
                    enunciados.append(resultado_quiz)
                else:
                    quizzes_encontrados.append(nome)
            except Exception as e:
                log.aviso(f"      Aviso: erro ao extrair quiz '{nome}': {e}")
                quizzes_encontrados.append(nome)
            continue

        elif tipo == "assign":
            # Aceder à página do assignment e extrair PDFs anexados
            log.info(f"    [assign] {nome}")
            log.info(f"      URL: {url}")
            ficheiros = _extrair_ficheiros_atividade_moodle(url, nome, sessao, verbosidade=verbosidade, log=log)
            if ficheiros:
                for f in ficheiros:
                    f["origem"] = "Moodle/assign"
                enunciados.extend(ficheiros)
                for f in ficheiros:
                    tamanho = len(f["pdf_bytes"]) / 1024
                    log.info(f"      -> PDF encontrado: {f['nome']} [{tamanho:.0f} KB]")
            else:
                log.info(f"      -> Nenhum PDF encontrado na página do assignment")

        elif tipo == "resource":
            log.info(f"    [resource] {nome} -> view.php (a tentar resolver para PDF)")

            resultado = _obter_pdf_de_resource_view(url, sessao, verbosidade=verbosidade, log=log)
            if resultado:
                nome_fich, data = resultado
                tamanho = len(data) / 1024
                log.info(f"    [resource] {nome} -> {nome_fich} [{tamanho:.0f} KB]")
                enunciados.append({
                    "nome": nome_fich,
                    "descricao": f"Moodle: {nome}",
                    "epoca": "",
                    "data": "",
                    "url": url,
                    "pdf_bytes": data,
                    "origem": "Moodle/resource",
                })
            else:
                log.info(f"    [resource] {nome} -> (não é PDF, ignorado)")

        elif tipo == "url":
            log.info(f"    [url] {nome}")
            log.info(f"      URL: {url}")
            enunciado = _extrair_pdf_de_url_externo(url, nome, sessao, verbosidade=verbosidade, log=log)
            if enunciado:
                enunciado["origem"] = "Moodle/url"
                tamanho = len(enunciado["pdf_bytes"]) / 1024
                
                log.info(f"      -> PDF obtido: {enunciado['nome']} [{tamanho:.0f} KB]")
                enunciados.append(enunciado)
            else:
                log.info(f"      -> Nenhum PDF obtido")

    if ignorados:
        log.info(f"  Atividades ignoradas (sem keywords de avaliação): {len(ignorados)}")
        for tipo_ign, nome_ign in ignorados:
            log.info(f"    [{tipo_ign}] {nome_ign}")

    if quizzes_encontrados:
        log.info(f"  Quizzes Moodle (não extraídos automaticamente):")
        for q in quizzes_encontrados:
            log.info(f"    [quiz] {q}")
        log.info("  Nota: quizzes sem PDF exportável não são incluídos automaticamente.")

    return enunciados


def extrair_moodle_uc(
    moodle_portal_url: str,
    sessao: SigarraSession,
    sigla_uc: str = "",
    nome_uc: str = "",
    ano_letivo_ocorrencia: str = "",
    codigo_docente: str = "",
    verbosidade: int = 1,
    log: AuditoriaLogger = None,
) -> dict | None:
    """Orquestra o acesso ao Moodle: SSO + extração de conteúdos.

    Quando o SSO redireciona para o dashboard (lista de cursos), procura
    o curso correto fazendo match pela sigla ou nome da UC.

    Args:
        moodle_portal_url: URL do portal Moodle no SIGARRA.
        sessao: Sessão autenticada no SIGARRA.
        sigla_uc: Sigla da UC (ex: "M.EIC044") para match no dashboard.
        nome_uc: Nome da UC para match por nome (fallback).
        codigo_docente: Código SIGARRA do docente para aceder ao Moodle
            em nome desse docente (impersonation). Se vazio, usa o
            utilizador autenticado.
        verbosidade: Nível de detalhe na saída (0=quieto, 1=normal, 2=debug).

    Returns:
        Dict com conteúdos do curso Moodle, ou None se indisponível.
    """
    if codigo_docente:
        # Substituir p_codigo no URL do portal para aceder como outro docente
        moodle_portal_url = re.sub(
            r'p_codigo=[^&]+', f'p_codigo={codigo_docente}', moodle_portal_url)
        log.info(f"  Impersonation: acesso Moodle como docente {codigo_docente}")

    resultado = aceder_moodle(moodle_portal_url, sessao, verbosidade=verbosidade, log=log)
    if not resultado:
        return None

    url_final, html_moodle = resultado

    # Salvaguarda: não ler conteúdos se a instância Moodle for de outro ano letivo
    ano_moodle = _extrair_ano_instancia_moodle(url_final)
    if ano_letivo_ocorrencia and ano_moodle and ano_letivo_ocorrencia != ano_moodle:
        log.info(
                "  Moodle ignorado: instância de ano diferente "
                f"({ano_moodle}) da ocorrência ({ano_letivo_ocorrencia})."
            )
        return None

    # Se a URL final já é uma página de curso, extrair diretamente
    if "course/view.php" in url_final:
        return extrair_conteudos_moodle(url_final, sessao, verbosidade=verbosidade, log=log)

    # Estamos no dashboard — extrair links de cursos com texto e atributo title
    # (versão atual: sigla no texto; versão anterior: sigla no atributo title=FEUP-M.EIC044-1S)
    cursos = []
    for m in re.finditer(
        r'<a[^>]+href="(https?://[^"]*moodle[^"]*\.up\.pt/course/view\.php\?id=\d+)"[^>]*>(.*?)</a>',
        html_moodle,
        re.DOTALL,
    ):
        url = m.group(1)
        texto = re.sub(r'<[^>]+>', '', m.group(2)).strip()
        title_m = re.search(r'\btitle=(["\']?)([^"\'>\s]+)\1', m.group(0))
        title = title_m.group(2) if title_m else ""
        cursos.append((url, texto, title))

    if not cursos:
        log.aviso(f"nenhum curso encontrado no dashboard Moodle (URL: {url_final})")
        return None

    # Match pela sigla — verificar texto E atributo title (formatos diferem entre anos)
    if sigla_uc:
        for url, texto, title in cursos:
            if sigla_uc in texto or sigla_uc in title:
                log.info(f"  Curso encontrado por sigla ({sigla_uc}): {texto or title}")
                return extrair_conteudos_moodle(url, sessao, verbosidade=verbosidade, log=log)

    # Fallback: match pelo nome da UC
    if nome_uc:
        nome_lower = nome_uc.lower()
        for url, texto, title in cursos:
            if nome_lower in texto.lower() or nome_lower in title.lower():
                log.info(f"  Curso encontrado por nome: {texto or title}")
                return extrair_conteudos_moodle(url, sessao, verbosidade=verbosidade, log=log)

    # Sem match — mostrar cursos disponíveis para diagnóstico
    log.aviso(f"UC não encontrada no Moodle (sigla={sigla_uc!r}, nome={nome_uc!r}).")
    log.info(f"  Cursos disponíveis ({len(cursos)}):")
    for url, texto, title in cursos[:10]:
        log.info(f"    - {title or texto}")
    return None
