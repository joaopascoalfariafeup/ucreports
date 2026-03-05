"""
Extracção de conteúdo de páginas web públicas de UCs (Página Web na ficha SIGARRA).

Fluxo:
1. Fetch da página principal
2. Conversão HTML→Markdown + extracção de links
3. LLM selecciona até MAX_SUBPAGES links relevantes (programa, avaliação, materiais)
4. Fetch das subpáginas seleccionadas
5. Devolve texto agregado para incluir no contexto de análise
"""

import json
import re
import urllib.request
from urllib.parse import urljoin, urlparse, urlunparse, quote

from bs4 import BeautifulSoup, NavigableString, Tag

# Máximo de subpáginas a buscar após selecção LLM
MAX_SUBPAGES = 5
# Máximo de links a passar ao LLM para selecção
MAX_LINKS_LLM = 60
# Limite de texto por página (chars) para não encher contexto LLM
MAX_TEXT_PER_PAGE = 32000

# Tags que não contêm conteúdo útil
_SKIP_TAGS = frozenset([
    "script", "style", "noscript", "nav", "header", "footer", "aside",
    "meta", "link", "svg", "path", "symbol", "button", "input", "select",
    "option", "form", "img", "figure", "iframe",
])


def _fetch_html(url: str, timeout: int = 20) -> str:
    # Percent-encode caracteres não-ASCII no path (ex: "época" → "%C3%A9poca")
    p = urlparse(url)
    encoded_url = urlunparse(p._replace(path=quote(p.path, safe="/:@!$&'()*+,;=")))
    req = urllib.request.Request(encoded_url, headers={"User-Agent": "Mozilla/5.0"})
    resp = urllib.request.urlopen(req, timeout=timeout)
    charset = resp.headers.get_content_charset() or "utf-8"
    return resp.read().decode(charset, errors="replace")


def _elem_para_md(elem: Tag, out: list[str], list_depth: int = 0) -> None:
    """Converte recursivamente um elemento BeautifulSoup em Markdown."""
    if isinstance(elem, NavigableString):
        return  # texto tratado via get_text() nos ramos específicos

    name = getattr(elem, "name", None)
    if not name or name in _SKIP_TAGS:
        return

    if name in ("h1", "h2", "h3", "h4", "h5", "h6"):
        text = elem.get_text(" ", strip=True)
        if text:
            level = int(name[1])
            out.append(f"\n\n{'#' * level} {text}\n\n")

    elif name == "li":
        # Texto directo do li, excluindo listas aninhadas
        parts = []
        for child in elem.children:
            if getattr(child, "name", None) in ("ul", "ol"):
                continue
            t = child.get_text(" ", strip=True) if isinstance(child, Tag) else str(child).strip()
            if t:
                parts.append(t)
        li_text = " ".join(parts).strip()
        if li_text:
            out.append(f"{'  ' * list_depth}- {li_text}\n")
        # Listas aninhadas
        for child in elem.children:
            if getattr(child, "name", None) in ("ul", "ol"):
                _elem_para_md(child, out, list_depth + 1)

    elif name in ("ul", "ol"):
        for child in elem.children:
            _elem_para_md(child, out, list_depth)
        out.append("\n")

    elif name == "p":
        text = elem.get_text(" ", strip=True)
        if text:
            out.append(f"{text}\n\n")

    elif name == "br":
        out.append("\n")

    elif name == "table":
        for row in elem.find_all("tr"):
            cells = [td.get_text(" ", strip=True) for td in row.find_all(("td", "th"))]
            if any(cells):
                out.append(" | ".join(cells) + "\n")
        out.append("\n")

    else:
        # Contentor genérico (div, section, article, span, …): recursão
        for child in elem.children:
            _elem_para_md(child, out, list_depth)


def _extrair_conteudo_e_links(html: str, base_url: str) -> tuple[str, list[dict]]:
    """Converte HTML em Markdown estruturado e extrai lista de links {url, texto}."""
    soup = BeautifulSoup(html, "html.parser")

    # Extrair links ANTES de remover elementos de navegação (nav, header, …)
    # — assim os menus laterais/superiores do Google Sites também são capturados
    links: list[dict] = []
    visto: set[str] = set()

    for a in soup.find_all("a", href=True):
        href = a["href"].strip()
        if not href or href.startswith(("#", "mailto:", "javascript:")):
            continue
        full_url = urljoin(base_url, href)
        parsed = urlparse(full_url)
        if parsed.scheme not in ("http", "https"):
            continue
        if full_url in visto:
            continue
        visto.add(full_url)
        anchor = a.get_text(strip=True)
        if len(anchor) < 2:
            continue
        links.append({"url": full_url, "texto": anchor})

    # Remover blocos não-conteúdo para a conversão Markdown
    for tag in soup(_SKIP_TAGS):
        tag.decompose()

    # Converter para Markdown
    corpo = soup.find("main") or soup.find("article") or soup.find("body") or soup
    partes: list[str] = []
    _elem_para_md(corpo, partes)
    texto = "".join(partes)
    texto = re.sub(r"\n{3,}", "\n\n", texto).strip()

    return texto, links


def _selecionar_links_llm(
    url_principal: str,
    texto_principal: str,
    links: list[dict],
    provider: str,
    modelo: str,
) -> list[str]:
    """Usa LLM para seleccionar links com conteúdo relevante para análise da UC."""
    from llm_analise import _call_text_only_llm  # noqa: PLC0415

    links_fmt = "\n".join(
        f"{i+1}. [{l['texto']}]({l['url']})"
        for i, l in enumerate(links[:MAX_LINKS_LLM])
    )

    user_text = f"""Site da UC: {url_principal}

Excerto da página principal:
{texto_principal[:2000]}

Links disponíveis:
{links_fmt}

Selecciona até {MAX_SUBPAGES} links que provavelmente contêm informação útil sobre:
- Programa ou conteúdos leccionados
- Métodos e critérios de avaliação, trabalhos, projectos
- Calendário, horário ou planeamento
- Materiais de ensino (slides, apontamentos, guiões)

Responde APENAS com JSON (sem mais texto): {{"urls": ["url1", "url2", ...]}}
Se nenhum link parecer relevante, responde com {{"urls": []}}"""

    resultado = _call_text_only_llm(
        provider=provider,
        model=modelo,
        system="És um assistente que analisa sites de unidades curriculares universitárias.",
        user_text=user_text,
        max_tokens=300,
    )
    texto_resposta = resultado.get("text", "")
    m = re.search(r"\{.*\}", texto_resposta, re.DOTALL)
    if not m:
        return []
    try:
        return json.loads(m.group()).get("urls", [])
    except json.JSONDecodeError:
        return []


def extrair_pagina_web_uc(
    url: str,
    provider: str = "iaedu",
    modelo: str = "gpt-4o",
    verbosidade: int = 1,
) -> str:
    """
    Extrai conteúdo relevante de um site público de UC.

    Devolve string com Markdown agregado (página principal + subpáginas seleccionadas pelo LLM).
    Lança exceção em caso de falha de rede na página principal.
    """
    if verbosidade >= 1:
        print(f"  [PáginaWeb] {url}")

    html_principal = _fetch_html(url)
    texto_principal, links = _extrair_conteudo_e_links(html_principal, url)

    if verbosidade >= 2:
        print(f"    Página principal: {len(texto_principal)} chars, {len(links)} links")

    blocos = [f"=== Página principal ({url}) ===\n{texto_principal[:MAX_TEXT_PER_PAGE]}"]

    if links:
        urls_relevantes = _selecionar_links_llm(
            url, texto_principal, links, provider, modelo
        )
        if verbosidade >= 1:
            print(f"    LLM seleccionou {len(urls_relevantes)} subpágina(s)")

        for sub_url in urls_relevantes[:MAX_SUBPAGES]:
            try:
                sub_html = _fetch_html(sub_url)
                sub_texto, _ = _extrair_conteudo_e_links(sub_html, sub_url)
                blocos.append(
                    f"=== Subpágina ({sub_url}) ===\n{sub_texto[:MAX_TEXT_PER_PAGE]}"
                )
                if verbosidade >= 1:
                    print(f"    ✓ {sub_url} ({len(sub_texto)} chars)")
            except Exception as e:
                if verbosidade >= 1:
                    print(f"    ✗ {sub_url}: {e}")

    return "\n\n".join(blocos)
