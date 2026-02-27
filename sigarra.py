"""
Módulo de acesso ao SIGARRA da Universidade do Porto.

Gere a autenticação, sessão com cookies e extração de dados de fichas de UC,
sumários e resultados estatísticos.
1) Aceder a URL de autenticação do SIGARRA - responde com redirect para o IdP - seguir cabeçalho "location" do redirect;
2) Aceder à pagina de autenticação (com os dados do redirect);
3) Fazer web scrap à página de autenticação e submeter o formulário;
4) A resposta é um redirect para o SIGARRA - fazer o pedido ao sigarra com os dados do redirect;
5) O SIGARRA responde com um cookie de sessão, entre outras coisas;
6) O cookie de sessão pode ser usado nos pedidos seguintes.

https://www.up.pt/pdados/
https://www.up.pt/pdados/new-request 

"""



import getpass
import http.cookiejar
import io
import json
import math
import os
import random
from pathlib import Path
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from html.parser import HTMLParser
import html as html_mod
from bs4 import BeautifulSoup

from logger import AuditoriaLogger


# Diretório do script (para localizar .env)
_SCRIPT_DIR = Path(__file__).resolve().parent

# URLs do SIGARRA
SIGARRA_BASE = "https://sigarra.up.pt/feup/pt"
SIGARRA_AUTH_URL = f"{SIGARRA_BASE}/mob_val_geral.autentica"
SIGARRA_UC_URL = f"{SIGARRA_BASE}/UCURR_GERAL.FICHA_UC_VIEW?pv_ocorrencia_id={{}}"
SIGARRA_SUMARIOS_URL = f"{SIGARRA_BASE}/sumarios_geral.ver?pv_ocorrencia_id={{}}"
SIGARRA_SUMARIOS_LISTA_URL = f"{SIGARRA_BASE}/sumarios_geral.lista"
SIGARRA_RELATORIO_UC_URL = f"{SIGARRA_BASE}/ucurr_geral.rel_uc_view?pv_ocorrencia_id={{}}"
SIGARRA_IPUP_URL = f"{SIGARRA_BASE}/ipup2016_est_geral.show_estatistica_uc?pv_ocorrencia_id={{}}"
SIGARRA_IPUP_COMENTARIOS_URL = f"{SIGARRA_BASE}/ipup2016_geral.stats_comentarios_uc_xls?pi_ocorr_id={{}}&pi_instancia_id=&pi_ano_letivo={{}}"
SIGARRA_REL_UC_EDIT_URL = f"{SIGARRA_BASE}/ucurr_adm.rel_uc_edit?pv_ocorrencia_id={{}}"
SIGARRA_REL_UC_VIEW_URL = f"{SIGARRA_BASE}/ucurr_adm.rel_uc_view?pv_ocorrencia_id={{}}"
SIGARRA_REL_UC_SUB_URL = f"{SIGARRA_BASE}/ucurr_adm.rel_uc_sub"
SIGARRA_UPLOAD_SANDBOX_URL = f"{SIGARRA_BASE}/gdoc_geral.upload_to_sandbox"


# ---------------------------------------------------------------------------
# Utilitários
# ---------------------------------------------------------------------------

_ENV_LOADED = False

def load_env():
    """Carrega variáveis do ficheiro .env local (se existir) para os.environ.

    Só carrega variáveis que ainda não estejam definidas no ambiente,
    para que variáveis de ambiente reais tenham sempre prioridade.
    """

    global _ENV_LOADED
    if _ENV_LOADED:
        return

    env_path = _SCRIPT_DIR / ".env"
    if not env_path.is_file():
        return
    for line in env_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
            value = value[1:-1]
        os.environ.setdefault(key, value)

    _ENV_LOADED = True

class _HTMLToText(HTMLParser):
    """Conversor de HTML para texto, preservando hierarquia de listas."""

    def __init__(self):
        super().__init__()
        self._parts: list[str] = []
        self._list_depth = 0

    def handle_data(self, data: str):
        self._parts.append(data)

    def handle_starttag(self, tag: str, attrs):
        if tag in ("ul", "ol"):
            self._list_depth += 1
        elif tag == "li":
            indent = "  " * max(0, self._list_depth - 1)
            self._parts.append(f"\n{indent}- ")
        elif tag == "br":
            if self._list_depth == 0:
                self._parts.append("\n")
        elif tag in ("p", "div"):
            self._parts.append("\n")

    def handle_endtag(self, tag: str):
        if tag in ("ul", "ol"):
            self._list_depth = max(0, self._list_depth - 1)
            if self._list_depth == 0:
                self._parts.append("\n")
        elif tag in ("p", "div"):
            self._parts.append("\n")

    def get_text(self) -> str:
        raw = "".join(self._parts)
        raw = re.sub(r"\n{3,}", "\n\n", raw)
        return raw.strip()


def html_to_text(html_fragment: str) -> str:
    """Converte um fragmento HTML em texto plano."""
    parser = _HTMLToText()
    parser.feed(html_fragment)
    return parser.get_text()


def _extrair_seccao(html: str, nome_seccao: str) -> str | None:
    """Extrai o conteúdo de uma secção <h3> da ficha de UC.

    Returns:
        Texto plano da secção, ou None se não encontrada.
    """
    match = re.search(
        rf"<h3[^>]*>\s*{re.escape(nome_seccao)}[^<]*</h3>(.*?)<h3[^>]*>",
        html,
        re.DOTALL | re.IGNORECASE,
    )
    if not match:
        return None
    return html_to_text(match.group(1))


def _extrair_seccao_html(html: str, nome_seccao: str) -> str | None:
    """Extrai o conteúdo HTML de uma secção <h3> da ficha de UC.

    Semelhante a _extrair_seccao mas preserva o HTML original.

    Returns:
        HTML da secção, ou None se não encontrada.
    """
    match = re.search(
        rf"<h3[^>]*>\s*{re.escape(nome_seccao)}[^<]*</h3>(.*?)<h3[^>]*>",
        html,
        re.DOTALL | re.IGNORECASE,
    )
    if not match:
        return None
    return match.group(1).strip()


# ---------------------------------------------------------------------------
# Sessão autenticada
# ---------------------------------------------------------------------------

class SigarraSession:
    """Sessão autenticada no SIGARRA com gestão automática de cookies."""

    def __init__(self):
        load_env()
        self._cookie_jar = http.cookiejar.CookieJar()
        self._opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self._cookie_jar)
        )
        self._lock = threading.Lock()  # serializa acessos ao _opener / _cookie_jar
        self._autenticado = False
        self._codigo_pessoal: str | None = None  # nº mecanográfico (p/ Moodle)
        self._http_retries = int(os.environ.get("SIGARRA_HTTP_RETRIES", "2"))
        self._http_backoff_base = float(os.environ.get("SIGARRA_HTTP_BACKOFF_BASE", "0.7"))

    @property
    def autenticado(self) -> bool:
        return self._autenticado

    @property
    def codigo_pessoal(self) -> str | None:
        """Número mecanográfico do utilizador (capturado na autenticação)."""
        return self._codigo_pessoal

    def autenticar(self, login: str | None = None, password: str | None = None):
        """Autentica no SIGARRA.

        Ordem de prioridade para credenciais:
        1. Argumentos diretos (login, password)
        2. Ficheiro .env local (SIGARRA_LOGIN / SIGARRA_PASSWORD)
        3. Variáveis de ambiente do sistema
        4. Prompt interativo
        """
        login = login or os.environ.get("SIGARRA_LOGIN") or input("Login SIGARRA: ")
        password = (
            password
            or os.environ.get("SIGARRA_PASSWORD")
            or getpass.getpass("Password SIGARRA: ")
        )

        params = urllib.parse.urlencode({"pv_login": login, "pv_password": password})
        url = f"{SIGARRA_AUTH_URL}?{params}"
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})

        try:
            resp = self.http_open(req, timeout=30, context="autenticação SIGARRA")
            charset = resp.headers.get_content_charset() or "utf-8"
            body = resp.read().decode(charset)
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace")
            try:
                dados = json.loads(body)
                msg = dados.get("erro_msg", body)
            except json.JSONDecodeError:
                msg = f"HTTP {e.code}: {body[:200]}"
            raise PermissionError(f"Autenticação SIGARRA falhou: {msg}") from e

        dados = json.loads(body)
        if dados.get("erro") or not dados.get("authenticated"):
            raise PermissionError(
                f"Autenticação SIGARRA falhou: {dados.get('erro_msg', body)}"
            )

        self._autenticado = True

        # Guardar nº mecanográfico (código pessoal) para construir URL do Moodle.
        # O JSON de autenticação pode incluí-lo em "codigo"; como fallback,
        # extraímos do login (formato "upXXXXXX").
        self._codigo_pessoal = str(dados["codigo"]) if "codigo" in dados else None
        if not self._codigo_pessoal and login:
            m = re.match(r"[Uu][Pp](\d+)", login)
            if m:
                self._codigo_pessoal = m.group(1)

        return dados

    @staticmethod
    def _saml_input_val(html: str, name: str) -> str:
        """Extrai value de um campo de formulário pelo name."""
        m = re.search(
            rf'name=["\']?{re.escape(name)}["\']?[^>]+value=["\']([^"\']*)["\']',
            html, re.IGNORECASE,
        ) or re.search(
            rf'value=["\']([^"\']*)["\'][^>]+name=["\']?{re.escape(name)}["\']?',
            html, re.IGNORECASE,
        )
        return html_mod.unescape(m.group(1)) if m else ""

    @staticmethod
    def _saml_form_action(html: str, base_url: str) -> str:
        m = re.search(r'<form[^>]+action=["\']([^"\']+)["\']', html, re.IGNORECASE)
        if m:
            return urllib.parse.urljoin(base_url, html_mod.unescape(m.group(1)))
        return base_url

    def _saml_request(self, url: str, post_data=None, referer: str | None = None) -> tuple[str, str]:
        """Executa um pedido HTTP no fluxo SAML, usando o opener com cookies da sessão."""
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "pt-PT,pt;q=0.9,en;q=0.8",
            "Upgrade-Insecure-Requests": "1",
        }
        if referer:
            headers["Referer"] = referer
        if post_data:
            encoded = urllib.parse.urlencode(post_data).encode("ascii")
            headers["Content-Type"] = "application/x-www-form-urlencoded"
            req = urllib.request.Request(url, data=encoded, headers=headers)
        else:
            req = urllib.request.Request(url, headers=headers)
        resp = self._opener.open(req, timeout=30)
        charset = resp.headers.get_content_charset() or "utf-8"
        return resp.read().decode(charset, errors="replace"), resp.geturl()

    def autenticar_federado_iniciar(self) -> tuple[str, str]:
        """Inicia o fluxo SAML até ao formulário de login do IdP (e1s2).

        Executa os passos:
        1. GET federate_login → SIGARRA redireciona para wayf.up.pt (IdP)
        2. GET IdP → redireciona para e1s1 (sonda localStorage)
        3. POST e1s1 com localStorage vazio → e1s2 (formulário de login)

        Returns:
            tuple (html_e1s2, url_e1s2) — HTML do formulário de login e URL base.
        """
        _FED_START = f"{SIGARRA_BASE}/vld_validacao.federate_login?p_redirect=web_page.Inicial"

        try:
            html_e1s1, url_e1s1 = self._saml_request(_FED_START)
        except Exception as e:
            raise ConnectionError(f"Autenticação federada: falha ao contactar SIGARRA/IdP: {e}") from e

        if "wayf.up.pt" not in url_e1s1:
            raise PermissionError(f"Autenticação federada: redirecionamento inesperado para {url_e1s1}")

        csrf_e1s1 = self._saml_input_val(html_e1s1, "csrf_token")
        if not csrf_e1s1:
            raise PermissionError("Autenticação federada: csrf_token não encontrado em e1s1")

        probe = {
            "csrf_token": csrf_e1s1,
            "shib_idp_ls_exception.shib_idp_session_ss": "",
            "shib_idp_ls_success.shib_idp_session_ss": "true",
            "shib_idp_ls_value.shib_idp_session_ss": "",
            "shib_idp_ls_exception.shib_idp_persistent_ss": "",
            "shib_idp_ls_success.shib_idp_persistent_ss": "true",
            "shib_idp_ls_value.shib_idp_persistent_ss": "",
            "shib_idp_ls_supported": "true",
            "_eventId_proceed": "",
        }
        try:
            html_e1s2, url_e1s2 = self._saml_request(url_e1s1, post_data=probe, referer=url_e1s1)
        except Exception as e:
            raise ConnectionError(f"Autenticação federada: falha na sonda localStorage (e1s1): {e}") from e

        return html_e1s2, url_e1s2

    def autenticar_federado_completar(self, html_saml: str, url_saml: str, username: str = "") -> None:
        """Completa o fluxo SAML extraindo a asserção e submetendo ao SIGARRA.

        Deve ser chamado quando o relay recebe o formulário com SAMLResponse
        vindo do browser (após o utilizador se autenticar no IdP).

        Args:
            html_saml: HTML com o formulário auto-submit contendo SAMLResponse.
            url_saml:  URL de onde veio esse HTML (para referer).
            username:  Username UP (para extrair código pessoal); pode estar vazio.

        Raises:
            PermissionError se SAMLResponse ausente ou SIGARRA rejeitar.
            ConnectionError em falhas de rede.
        """
        saml_response = self._saml_input_val(html_saml, "SAMLResponse")
        relay_state = self._saml_input_val(html_saml, "RelayState")
        saml_action = self._saml_form_action(html_saml, "https://sigarra.up.pt/Shibboleth.sso/SAML2/POST")

        if not saml_response:
            raise PermissionError("Autenticação federada: asserção SAML não encontrada")

        try:
            _html_final, url_final = self._saml_request(
                saml_action,
                post_data={"SAMLResponse": saml_response, "RelayState": relay_state},
                referer=url_saml,
            )
        except Exception as e:
            raise ConnectionError(f"Autenticação federada: falha ao submeter asserção SAML: {e}") from e

        if "sigarra.up.pt" not in url_final:
            raise PermissionError(f"Autenticação federada: SIGARRA não reconheceu a sessão ({url_final})")

        self._autenticado = True

        # Tentar extrair código pessoal do username (ex: up210006 ou up210006@up.pt)
        m = re.match(r"[Uu][Pp](\d+)", username)
        if m:
            self._codigo_pessoal = m.group(1)
        else:
            # Fallback: ler da página home do SIGARRA após autenticação.
            # A foto do perfil tem o padrão: fotografias_service.foto_thumb?pct_cod=XXXXXX
            try:
                html_home, _ = self._saml_request(f"{SIGARRA_BASE}/web_page.inicial", referer=url_final)
                mc = re.search(r'foto_thumb\?pct_cod=(\d+)', html_home)
                self._codigo_pessoal = mc.group(1) if mc else None
            except Exception:
                self._codigo_pessoal = None

    def fetch_html(self, url: str, timeout: int = 30) -> str:
        """Descarrega uma página do SIGARRA (com cookies de sessão)."""
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})

        try:
            resp = self.http_open(req, timeout=timeout, context=f"GET {url}")
            charset = resp.headers.get_content_charset() or "iso-8859-15"
            return resp.read().decode(charset, errors="replace")

        except urllib.error.HTTPError as e:
            # tentar obter corpo para diagnosticar
            try:
                charset = e.headers.get_content_charset() or "iso-8859-15"
                body = e.read().decode(charset, errors="replace")
            except Exception:
                body = ""

            if e.code in (401, 403):
                raise PermissionError(f"Sem permissões / sessão inválida") from e
            if e.code == 404:
                raise ValueError(f"Página não encontrada (404) ao aceder ao URL") from e

            # outros HTTP (500, 503, etc.)
            raise RuntimeError(f"Erro HTTP {e.code} ao aceder a {url}. {body[:200]}") from e

        except urllib.error.URLError as e:
            raise ConnectionError(f"Erro de rede/timeout ao aceder a {url}: {e}") from e

    @staticmethod
    def _is_retryable_http(code: int) -> bool:
        return code in {408, 429, 500, 502, 503, 504}

    def http_open(
        self,
        req: urllib.request.Request,
        timeout: int = 30,
        retries: int | None = None,
        context: str = "",
    ):
        """Abre request HTTP com retries e backoff para falhas transitórias.

        Serializa o acesso ao _opener/_cookie_jar via self._lock para
        garantir thread-safety quando a mesma sessão é usada concorrentemente.
        """
        tentativas = (self._http_retries if retries is None else max(0, retries)) + 1
        last_exc: Exception | None = None

        for i in range(1, tentativas + 1):
            try:
                with self._lock:
                    return self._opener.open(req, timeout=timeout)
            except urllib.error.HTTPError as e:
                last_exc = e
                if self._is_retryable_http(e.code) and i < tentativas:
                    atraso = self._http_backoff_base * (2 ** (i - 1)) + random.uniform(0, 0.2)
                    print(f"  [retry {i}/{tentativas-1}] HTTP {e.code} em {context or req.full_url}; novo intento em {atraso:.1f}s")
                    time.sleep(atraso)
                    continue
                raise
            except urllib.error.URLError as e:
                last_exc = e
                if i < tentativas:
                    atraso = self._http_backoff_base * (2 ** (i - 1)) + random.uniform(0, 0.2)
                    print(f"  [retry {i}/{tentativas-1}] erro de rede em {context or req.full_url}: {e}; novo intento em {atraso:.1f}s")
                    time.sleep(atraso)
                    continue
                raise

        if last_exc:
            raise last_exc
        raise RuntimeError("Falha inesperada em http_open")

# ---------------------------------------------------------------------------
# Extração de dados da ficha de UC
# ---------------------------------------------------------------------------

def _extrair_componentes_avaliacao(html: str) -> list[dict]:
    """Extrai a tabela de componentes de avaliação da ficha de UC.

    Returns:
        Lista de dicts com 'designacao' e 'peso' (float).
    """
    match = re.search(
        r"<h3[^>]*>\s*Componentes de Avalia[^<]*</h3>\s*<table[^>]*>(.*?)</table>",
        html,
        re.DOTALL | re.IGNORECASE,
    )
    if not match:
        return []

    componentes = []
    for row in re.finditer(
        r'<tr class="d">\s*'
        r'<td class="t">([^<]*)</td>\s*'
        r'<td class="n">([^<]*)</td>\s*'
        r"</tr>",
        match.group(1),
        re.DOTALL,
    ):
        designacao = row.group(1).strip()
        peso_str = row.group(2).strip().replace(",", ".")
        try:
            peso = float(peso_str)
        except ValueError:
            peso = 0.0
        componentes.append({"designacao": designacao, "peso": peso})

    return componentes


def extrair_ficha_uc(ocorrencia_id: str, sessao: SigarraSession | None = None) -> dict:
    """Extrai secções da ficha de UC relevantes para auditoria.

    Faz uma única chamada HTTP à ficha e extrai as secções de conteúdo
    e de avaliação.

    Args:
        ocorrencia_id: Código da ocorrência da UC (ex: "559654").
        sessao: Sessão autenticada (opcional; a ficha de UC é pública).

    Returns:
        Dict com chaves 'programa', 'objetivos', 'resultados_aprendizagem',
        'metodos_ensino', 'tipo_avaliacao', 'componentes_avaliacao',
        'formula_classificacao' e 'obtencao_frequencia'.

    Raises:
        ValueError: Se a secção 'Programa' não for encontrada.
    """
    url = SIGARRA_UC_URL.format(ocorrencia_id)
    if sessao:
        html = sessao.fetch_html(url)
    else:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        resp = urllib.request.urlopen(req, timeout=30)
        charset = resp.headers.get_content_charset() or "iso-8859-15"
        html = resp.read().decode(charset)

    # Nome da UC (do <h1>)
    nome_uc = ""
    h1_match = re.search(r'<h1[^>]*>([^<]+)</h1>', html)
    if h1_match:
        nome_uc = html_mod.unescape(h1_match.group(1)).strip()

    # Sigla da UC (ex: M.EIC044)
    sigla_uc = _extrair_sigla_uc(html)

    # Ano letivo da ocorrência (ex: 2025/2026), quando disponível na página
    ano_letivo = ""
    m_ano = re.search(r"(\d{4}/\d{4})", html)
    if m_ano:
        ano_letivo = m_ano.group(1)

    programa = _extrair_seccao(html, "Programa")
    programa_html = _extrair_seccao_html(html, "Programa")
    if not programa:
        raise ValueError(
            f"Secção 'Programa' não encontrada para a ocorrência {ocorrencia_id}"
        )

    objetivos = _extrair_seccao(html, "Objetivos") or ""
    resultados = _extrair_seccao(html, "Resultados de aprendizagem e compet") or ""

    metodos = _extrair_seccao(html, "Métodos de ensino e atividades de aprendizagem") or ""
    tipo_aval = _extrair_seccao(html, "Tipo de avaliação") or ""
    componentes = _extrair_componentes_avaliacao(html)
    formula = _extrair_seccao(html, "Fórmula de cálculo da classificação final") or ""
    frequencia = _extrair_seccao(html, "Obtenção de frequência") or ""

    # Horas de contacto da acreditação (tabela "Ciclos de Estudo/Cursos")
    horas_contacto = 0
    m_hc = re.search(
        r'<th[^>]*>Horas de Contacto</th>.*?</tr>\s*<tr[^>]*>.*?'
        r'<td[^>]*>.*?</td>\s*'   # Sigla
        r'<td[^>]*>.*?</td>\s*'   # Nº de Estudantes
        r'<td[^>]*>.*?</td>\s*'   # Plano de Estudos
        r'<td[^>]*>.*?</td>\s*'   # Anos Curriculares
        r'<td[^>]*>.*?</td>\s*'   # Créditos UCN
        r'<td[^>]*>.*?</td>\s*'   # Créditos ECTS
        r'<td[^>]*>\s*(\d+)\s*</td>',  # Horas de Contacto
        html, re.DOTALL | re.IGNORECASE,
    )
    if m_hc:
        horas_contacto = int(m_hc.group(1))

    # ID da UC (ucurr_id) — extraído do link "Outras ocorrências"
    ucurr_id = ""
    ucurr_match = re.search(
        r'ucurr_geral\.ficha_uc_list\?pv_ucurr_id=(\d+)', html,
    )
    if ucurr_match:
        ucurr_id = ucurr_match.group(1)

    # Link para o Moodle (se integrado).
    # O link só aparece na ficha quando acedida com autenticação.
    # Redireciona sempre para a instância corrente (limitação do moodle_portal);
    # o mismatch de ano é detectado em extrair_moodle_uc via
    # _extrair_ano_instancia_moodle, que descarta o resultado se necessário.
    moodle_url = _extrair_moodle_url(html)

    return {
        "nome_uc": nome_uc,
        "sigla_uc": sigla_uc,
        "ano_letivo": ano_letivo,
        "ucurr_id": ucurr_id,
        "programa": programa,
        "programa_html": programa_html or "",
        "objetivos": objetivos,
        "resultados_aprendizagem": resultados,
        "metodos_ensino": metodos,
        "tipo_avaliacao": tipo_aval,
        "componentes_avaliacao": componentes,
        "formula_classificacao": formula,
        "obtencao_frequencia": frequencia,
        "horas_contacto": horas_contacto,
        "moodle_url": moodle_url,
    }


def _extrair_sigla_uc(html: str) -> str:
    """Extrai a sigla da UC (ex: M.EIC044, MESW001) da ficha de UC.

    Prioriza a tabela de identificação logo após o ``<h1>`` (campo
    "Sigla:"), depois tenta URLs com ``pv_sigla=`` e, por fim,
    padrões de sigla no cabeçalho ``<h2>`` da página.

    Returns:
        Sigla da UC, ou string vazia se não encontrada.
    """
    # Pattern 1: campo "Sigla:" na tabela de identificação da ficha
    m = re.search(
        r'<h1[^>]*>.*?</h1>\s*'
        r'<table[^>]*class=["\"][^"\>]*formulario[^"\>]*["\"][^>]*>.*?'
        r'<td[^>]*class=["\"][^"\>]*formulario-legenda[^"\>]*["\"][^>]*>\s*Sigla:\s*</td>\s*'
        r'<td[^>]*>\s*([^<\s]+)\s*</td>',
        html,
        re.DOTALL | re.IGNORECASE,
    )
    if m:
        return html_mod.unescape(m.group(1)).strip()

    # Pattern 2: parâmetro pv_sigla= em qualquer URL da página
    m = re.search(r'[?&]pv_sigla=([A-Za-z][A-Za-z0-9.]+\d{3,4})', html)
    if m:
        return m.group(1)

    # Pattern 3: sigla em texto do <h2> (zona de ocorrência)
    for m in re.finditer(r'<h2[^>]*>(.*?)</h2>', html, re.DOTALL):
        h2_text = re.sub(r'<[^>]+>', ' ', m.group(1))
        sigla_m = re.search(r'\b([A-Z]+\.?[A-Z]+\d{3,4})\b', h2_text)
        if sigla_m:
            return sigla_m.group(1)

    return ""


def _extrair_moodle_url(html: str) -> str | None:
    """Extrai o URL do portal Moodle da ficha de UC.

    Procura o link ``moodle_portal.go_moodle_portal_up?p_codigo=...``
    presente no cabeçalho ``<h2>`` da ocorrência.

    Nota: este link redireciona sempre para a instância Moodle corrente,
    independentemente do ano da UC.  O mismatch de ano é detectado em
    ``extrair_moodle_uc`` via ``_extrair_ano_instancia_moodle``.

    Returns:
        URL completa para o portal Moodle, ou None se não encontrado.
    """
    m = re.search(
        r'href="(moodle_portal\.go_moodle_portal_up\?p_codigo=[^"]+)"',
        html,
    )
    if not m:
        return None
    href = m.group(1)
    # p_codigo=-1 significa que a integração não está ativa
    if "p_codigo=-1" in href:
        return None
    return f"{SIGARRA_BASE}/{href}"


# ---------------------------------------------------------------------------
# Ocorrências da UC (para encontrar o ano anterior automaticamente)
# ---------------------------------------------------------------------------

SIGARRA_UC_LIST_URL = f"{SIGARRA_BASE}/ucurr_geral.ficha_uc_list?pv_ucurr_id={{}}"


def _ocorrencia_ativa(oc_id: str, sessao: SigarraSession | None) -> bool:
    """Verifica se uma ocorrência está ativa consultando a sua ficha."""
    url = SIGARRA_UC_URL.format(oc_id)
    try:
        if sessao:
            html = sessao.fetch_html(url)
        else:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            resp = urllib.request.urlopen(req, timeout=30)
            charset = resp.headers.get_content_charset() or "iso-8859-15"
            html = resp.read().decode(charset)
    except Exception:
        return True  # assume ativa se não conseguir verificar
    m = re.search(r'Ativa\?\s*</td>\s*<td>([^<]+)</td>', html)
    if m:
        return m.group(1).strip().lower() == "sim"
    return True  # se o campo não existir, assume ativa


def extrair_ocorrencia_anterior(
    ocorrencia_id: str,
    ucurr_id: str,
    sessao: SigarraSession | None = None,
) -> tuple[str, str] | None:
    """Encontra o ID e período da ocorrência anterior ativa a partir da lista de ocorrências.

    Acede à página de ocorrências da UC e devolve o ID e período da primeira
    ocorrência anterior ativa à ocorrência indicada (ocorrências inativas são
    ignoradas e é pesquisada a seguinte).

    Args:
        ocorrencia_id: Código da ocorrência atual (ex: "559654").
        ucurr_id: ID da UC (ex: "252608"), extraído da ficha.
        sessao: Sessão autenticada (opcional; a lista é pública).

    Returns:
        Tuplo (oc_id, periodo) da ocorrência anterior ativa, ou None se não encontrada.
    """
    if not ucurr_id:
        return None

    url = SIGARRA_UC_LIST_URL.format(ucurr_id)
    if sessao:
        html = sessao.fetch_html(url)
    else:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        resp = urllib.request.urlopen(req, timeout=30)
        charset = resp.headers.get_content_charset() or "iso-8859-15"
        html = resp.read().decode(charset)

    # Extrair pares (ocorrencia_id, periodo) da tabela de ocorrências
    ocorrencias = re.findall(
        r'UCURR_GERAL\.FICHA_UC_VIEW\?pv_ocorrencia_id=(\d+)"[^>]*>([^<]+)<',
        html,
    )
    if not ocorrencias:
        return None

    # Encontrar a ocorrência atual e devolver a primeira anterior ativa
    # (a lista está ordenada por ano decrescente, logo as seguintes são anos anteriores)
    for i, (oc_id, _periodo) in enumerate(ocorrencias):
        if oc_id == ocorrencia_id:
            for oc_ant_id, oc_ant_periodo in ocorrencias[i + 1:]:
                if _ocorrencia_ativa(oc_ant_id, sessao):
                    return oc_ant_id, oc_ant_periodo.strip()
            break

    return None


# ---------------------------------------------------------------------------
# Extração de sumários
# ---------------------------------------------------------------------------

def _extrair_turmas(html: str) -> list[dict]:
    """Extrai as turmas e respetivos parâmetros a partir da página de sumários."""
    turmas = []
    for m in re.finditer(
        r'<a\s+href="sumarios_geral\.\w+\?([^"]+)"[^>]*>([^<]+)</a>', html
    ):
        params_str = m.group(1)
        nome_turma = m.group(2).strip()
        params = dict(urllib.parse.parse_qsl(params_str))
        turmas.append({
            "turma": nome_turma,
            "tipo_aula": params.get("pv_tipo_aula", ""),
            "turma_id": params.get("pv_turma_id", ""),
            "per_aula": params.get("pv_per_aula", ""),
        })
    return turmas


def _extrair_sumarios_lista(html: str) -> list[dict]:
    """Extrai sumários da página sumarios_geral.lista de uma turma."""
    sumarios = []
    blocos = re.split(r'<h3 class="sumario">', html)
    for bloco in blocos[1:]:
        header_match = re.match(
            r"Aula\s+n[ºo]\.\s*(\d+)\s*-\s*(\d{2}/\d{2}/\d{4})\s*</h3>",
            bloco,
        )
        if not header_match:
            continue

        numero = int(header_match.group(1))
        data = header_match.group(2)

        resto = bloco[header_match.end():]
        p_match = re.search(
            r'<p class="sumario">((?:(?!<span class="nota">).)*?)</p>',
            resto,
            re.DOTALL,
        )
        texto = html_to_text(p_match.group(1)).strip() if p_match else ""

        sumarios.append({
            "numero": numero,
            "data": data,
            "sumario": texto,
        })

    return sumarios


def extrair_sumarios(ocorrencia_id: str, sessao: SigarraSession, verbosidade: int = 1) -> list[dict]:
    """Extrai os sumários de todas as turmas de uma UC.

    Requer sessão autenticada. Para cada turma, acede à página
    sumarios_geral.lista (1 pedido HTTP por turma).

    Args:
        ocorrencia_id: Código da ocorrência da UC.
        sessao: Sessão autenticada no SIGARRA.
        verbosidade: Nível de detalhe na saída (0=quieto, 1=normal, 2=debug).

    Returns:
        Lista de dicionários com chaves 'turma', 'tipo_aula', 'numero',
        'data' e 'sumario'.
    """
    if not sessao.autenticado:
        raise PermissionError("É necessário autenticar antes de aceder aos sumários.")

    url = SIGARRA_SUMARIOS_URL.format(ocorrencia_id)
    html = sessao.fetch_html(url)
    turmas = _extrair_turmas(html)

    if not turmas:
        return []

    todos_sumarios = []

    for turma in turmas:
        if verbosidade >= 1:
            print(f"  A extrair sumários da turma {turma['turma']} ({turma['tipo_aula']})...")
        params = urllib.parse.urlencode({
            "pv_ocorrencia_id": ocorrencia_id,
            "pv_tipo_aula": turma["tipo_aula"],
            "pv_turma_id": turma["turma_id"],
        })
        lista_url = f"{SIGARRA_SUMARIOS_LISTA_URL}?{params}"
        html_lista = sessao.fetch_html(lista_url)
        sums = _extrair_sumarios_lista(html_lista)
        for s in sums:
            s["turma"] = turma["turma"]
            s["tipo_aula"] = turma["tipo_aula"]
        todos_sumarios.extend(sums)

    return todos_sumarios


# ---------------------------------------------------------------------------
# Extração de resultados / estatísticas de sucesso escolar
# ---------------------------------------------------------------------------

def _extrair_identificacao_relatorio(html: str) -> dict:
    """Extrai dados de identificação da UC a partir da página de relatório."""
    info = {}
    m = re.search(r'Unidade Curricular:\s*</td>\s*<td>([^<]+)</td>', html)
    if m:
        info["nome_uc"] = m.group(1).strip()
    m = re.search(r'Código:\s*</td>\s*<td>([^<]+)</td>', html, re.DOTALL)
    if m:
        info["codigo"] = m.group(1).strip()
    m = re.search(
        r'Relat.rio de Unidade Curricular\s*-\s*(\d{4}/\d{4})', html
    )
    if m:
        info["ano_letivo"] = m.group(1)
    m = re.search(
        r'Per.odo de Aulas:\s*</td>\s*<td>([^<]+)</td>', html, re.DOTALL
    )
    if m:
        info["periodo"] = m.group(1).strip()
    # Ano curricular (ex: "1º")
    m = re.search(r'Ano:\s*</td>\s*<td>([^<]+)</td>', html, re.DOTALL)
    if m:
        info["ano_curricular"] = m.group(1).strip()
    # Curso (primeiro link cur_geral.cur_view com pv_curso_id)
    m = re.search(
        r'cur_geral\.cur_view\?pv_curso_id=(\d+)&pv_ano_lectivo=(\d+)',
        html,
    )
    if m:
        info["curso_id"] = m.group(1)
        info["ano_letivo_num"] = m.group(2)
    return info


def _extrair_distribuicao_notas(html: str, oc_id: str) -> list[dict]:
    """Extrai a distribuição detalhada de resultados/notas."""
    pattern = (
        rf'id="tbl_estat_table_dist_result_ocorr_detail_{re.escape(oc_id)}__N"'
        r".*?</table>"
    )
    match = re.search(pattern, html, re.DOTALL)
    if not match:
        return []

    table_html = match.group(0)
    distribuicao = []
    for row_match in re.finditer(
        r'<tr class="d">\s*'
        r"<td[^>]*>([^<]*)</td>\s*"
        r"<td[^>]*>([^<]*)</td>\s*"
        r"<td[^>]*>(\d+)</td>\s*"
        r"</tr>",
        table_html,
        re.DOTALL,
    ):
        distribuicao.append({
            "codigo": row_match.group(1).strip(),
            "descricao": row_match.group(2).strip(),
            "contagem": int(row_match.group(3)),
        })
    return distribuicao


def _extrair_resumo_resultados(html: str, oc_id: str) -> dict:
    """Extrai os resumos e rácios de resultados."""
    resumo = {}

    # Há duas tabelas com o mesmo ID: 1.ª hidden (contagens), 2.ª visível (rácios)
    tables = list(re.finditer(
        rf'<table[^>]*id="tbl_estat_table_dist_result_ocorr_{re.escape(oc_id)}__N"'
        r"[^>]*>.*?</table>",
        html,
        re.DOTALL,
    ))

    if len(tables) >= 1:
        hidden_table = tables[0].group(0)
        for row in re.finditer(
            r'<td class="k t">([^<]+)</td>\s*<td class="n">(\d+)</td>',
            hidden_table,
        ):
            label = row.group(1).strip().lower()
            count = int(row.group(2))
            if "reprovado" in label:
                resumo["reprovados"] = count
            elif "avaliado" in label:
                resumo["nao_avaliados"] = count
            elif "aprovado" in label:
                resumo["aprovados"] = count

    if len(tables) >= 2:
        ratios_table = tables[1].group(0)
        values = re.findall(r'<td class="k n">([^<]+)</td>', ratios_table)
        if len(values) >= 6:
            resumo["inscritos"] = int(values[0])
            resumo["avaliados"] = int(values[1])
            resumo["aprovados_total"] = int(values[2])
            resumo["racio_avaliados_inscritos"] = float(values[3])
            resumo["racio_aprovados_inscritos"] = float(values[4])
            resumo["racio_aprovados_avaliados"] = float(values[5])

    return resumo


def _calcular_estatisticas(distribuicao: list[dict]) -> dict:
    """Calcula média, mediana e desvio padrão das notas dos aprovados."""
    notas = []
    for item in distribuicao:
        try:
            nota = int(item["codigo"])
            if nota >= 10:
                notas.extend([nota] * item["contagem"])
        except ValueError:
            continue

    if not notas:
        return {
            "media": None, "mediana": None,
            "desvio_padrao": None, "n_aprovados_com_nota": 0,
        }

    n = len(notas)
    media = sum(notas) / n

    notas_sorted = sorted(notas)
    if n % 2 == 0:
        mediana = (notas_sorted[n // 2 - 1] + notas_sorted[n // 2]) / 2
    else:
        mediana = notas_sorted[n // 2]

    variancia = sum((x - media) ** 2 for x in notas) / n
    desvio_padrao = math.sqrt(variancia)

    return {
        "media": round(media, 2),
        "mediana": mediana,
        "desvio_padrao": round(desvio_padrao, 2),
        "n_aprovados_com_nota": n,
    }


def extrair_resultados_uc(ocorrencia_id: str, sessao: SigarraSession) -> dict:
    """Extrai estatísticas de resultados da UC a partir da página de relatório.

    Requer sessão autenticada. Faz uma única chamada HTTP.

    Args:
        ocorrencia_id: Código da ocorrência da UC.
        sessao: Sessão autenticada no SIGARRA.

    Returns:
        Dict com chaves 'identificacao', 'distribuicao_notas', 'resumo',
        'estatisticas'.
    """
    if not sessao.autenticado:
        raise PermissionError(
            "É necessário autenticar antes de aceder ao relatório."
        )

    url = SIGARRA_RELATORIO_UC_URL.format(ocorrencia_id)
    html = sessao.fetch_html(url)

    identificacao = _extrair_identificacao_relatorio(html)
    distribuicao = _extrair_distribuicao_notas(html, ocorrencia_id)
    resumo = _extrair_resumo_resultados(html, ocorrencia_id)
    estatisticas = _calcular_estatisticas(distribuicao)

    if not distribuicao and not resumo:
        raise ValueError(
            f"Dados de resultados não encontrados para a ocorrência {ocorrencia_id}"
        )

    return {
        "identificacao": identificacao,
        "distribuicao_notas": distribuicao,
        "resumo": resumo,
        "estatisticas": estatisticas,
    }


# ---------------------------------------------------------------------------
# Verificação de pautas e classificações pendentes
# ---------------------------------------------------------------------------

def extrair_pautas_uc(ocorrencia_id: str, sessao: SigarraSession) -> list[dict]:
    """Extrai lista de pautas de época da UC (show_pautas).

    Returns:
        Lista de dicts com 'pauta_id', 'epoca', 'ano_letivo', 'estado',
        'data_estado', 'n_estudantes'.
    """
    url = f"{SIGARRA_BASE}/lres_geral.show_pautas?pv_ocorr_id={ocorrencia_id}"
    html = sessao.fetch_html(url)
    soup = BeautifulSoup(html, "html.parser")
    pautas = []
    tabela = soup.find("table", class_="dadossz")
    if not tabela:
        return pautas
    for tr in tabela.find_all("tr")[1:]:
        tds = tr.find_all("td")
        if len(tds) < 5:
            continue
        link = tr.find("a", href=lambda h: h and "pv_pauta_id=" in h)
        if not link:
            continue
        m = re.search(r'pv_pauta_id=(\d+)', link["href"])
        if not m:
            continue
        pauta_id = m.group(1)
        try:
            n_estudantes = int(tds[4].get_text(strip=True))
        except ValueError:
            n_estudantes = None
        pautas.append({
            "pauta_id": pauta_id,
            "epoca": tds[0].get_text(strip=True),
            "ano_letivo": tds[1].get_text(strip=True),
            "estado": tds[2].get_text(strip=True),
            "data_estado": tds[3].get_text(strip=True),
            "n_estudantes": n_estudantes,
        })
    return pautas


def verificar_estudantes_sem_classificacao(pauta_id: str, sessao: SigarraSession) -> int | None:
    """Verifica se há estudantes sem classificação final numa pauta.

    Returns:
        Número de estudantes sem classificação, 0 se todos têm classificação,
        ou None se não foi possível determinar.
    """
    url = f"{SIGARRA_BASE}/lres_geral.show_pauta?pv_pauta_id={pauta_id}&pv_modo=LST"
    html = sessao.fetch_html(url)
    soup = BeautifulSoup(html, "html.parser")
    h3 = soup.find("h3", string=lambda s: s and "sem classificação final" in s.lower())
    if not h3:
        return None
    div_info = h3.find_next_sibling("div", class_="informa")
    if div_info and "todos os estudantes já estão incluidos em termos" in div_info.get_text().lower():
        return 0
    # Contar estudantes na tabela seguinte
    tabela = h3.find_next_sibling("table")
    if tabela:
        linhas = [tr for tr in tabela.find_all("tr") if tr.find("td")]
        return len(linhas)
    return None  # secção existe mas estrutura inesperada


# ---------------------------------------------------------------------------
# Extração de resultados por curso (tabela resumo, via AJAX)
# ---------------------------------------------------------------------------

SIGARRA_AJAX_RESULT_RESUMO_URL = f"{SIGARRA_BASE}/EST_AJAX.CUR_RESULT_RESUMO_TBL"


def extrair_resultados_curso(
    curso_id: str,
    ano_letivo: str,
    sessao: SigarraSession,
) -> list[dict]:
    """Extrai a tabela resumo de resultados de todas as UCs de um curso/ano.

    Faz um pedido AJAX POST (como a página dinâmica do SIGARRA).

    Args:
        curso_id: Código do curso (ex: "10861" para MESW).
        ano_letivo: Ano letivo numérico (ex: "2025" para 2025/26).
        sessao: Sessão autenticada no SIGARRA.

    Returns:
        Lista de dicts, cada um com: 'codigo', 'nome_uc', 'ano_curricular',
        'periodo', 'inscritos', 'avaliados', 'aprovados',
        'racio_avaliados_inscritos', 'racio_aprovados_inscritos',
        'racio_aprovados_avaliados', 'media_aprovados', 'dp_aprovados'.
    """
    if not sessao.autenticado:
        raise PermissionError(
            "É necessário autenticar antes de aceder às estatísticas do curso."
        )

    params = urllib.parse.urlencode({
        "PV_CURSO_ID": curso_id,
        "PV_ANO_LETIVO": ano_letivo,
        "PV_SYNC_TT_HC": "SYNC",
        "PV_SHOW_TITLE": "S",
    })
    req = urllib.request.Request(
        SIGARRA_AJAX_RESULT_RESUMO_URL,
        data=params.encode("utf-8"),
        headers={
            "User-Agent": "Mozilla/5.0",
            "X-Requested-With": "XMLHttpRequest",
        },
        method="POST",
    )
    resp = sessao.http_open(req, timeout=30, context="POST EST_AJAX.CUR_RESULT_RESUMO_TBL")
    charset = resp.headers.get_content_charset() or "iso-8859-15"
    html = resp.read().decode(charset)

    return _parse_resultado_curso_html(html)


def _parse_resultado_curso_html(html: str) -> list[dict]:
    """Extrai linhas de UCs individuais da tabela AJAX de resultados do curso."""
    import html as html_mod  # para unescape de entidades

    resultados = []

    # Linhas individuais de UCs (class="i filho-de-acurrminX")
    for tr_match in re.finditer(
        r'<tr\s+id="[^"]*"\s+class="i\s+filho-de-[^"]*"\s*>'
        r"(.*?)</tr>",
        html,
        re.DOTALL,
    ):
        cells = re.findall(r"<td[^>]*>(.*?)</td>", tr_match.group(1), re.DOTALL)
        if len(cells) < 12:
            continue

        # Primeira célula: "(MESW0001) Nome UC → 1º ano → 1º Semestre"
        label_html = cells[0]
        label_text = html_mod.unescape(re.sub(r"<[^>]+>", "", label_html)).strip()

        # Extrair código e nome
        code_match = re.match(r"\(([^)]+)\)\s*(.+?)(?:\s*→|$)", label_text)
        if not code_match:
            continue
        codigo = code_match.group(1).strip()
        resto = label_text[code_match.end():]

        nome_uc = code_match.group(2).strip()

        # Extrair ano curricular e período (se presentes)
        ano_curr = ""
        periodo = ""
        partes = [p.strip() for p in resto.split("→") if p.strip()]
        if partes:
            ano_curr = partes[0]
        if len(partes) > 1:
            periodo = partes[1]

        # Valores numéricos (posições 1-11)
        def _parse_num(val):
            val = val.strip()
            if val in ("N/A", ""):
                return None
            try:
                return float(val)
            except ValueError:
                return None

        inscritos = _parse_num(cells[1])
        avaliados = _parse_num(cells[2])
        aprovados = _parse_num(cells[3])
        r_aval_insc = _parse_num(cells[4])
        # cells[5] = Não Avaliados/Inscritos (skip)
        r_aprov_insc = _parse_num(cells[6])
        r_aprov_aval = _parse_num(cells[7])
        # cells[8] = média avaliados, cells[9] = DP avaliados
        media_aprov = _parse_num(cells[10])
        dp_aprov = _parse_num(cells[11])

        resultados.append({
            "codigo": codigo,
            "nome_uc": nome_uc,
            "ano_curricular": ano_curr,
            "periodo": periodo,
            "inscritos": int(inscritos) if inscritos is not None else None,
            "avaliados": int(avaliados) if avaliados is not None else None,
            "aprovados": int(aprovados) if aprovados is not None else None,
            "racio_avaliados_inscritos": r_aval_insc,
            "racio_aprovados_inscritos": r_aprov_insc,
            "racio_aprovados_avaliados": r_aprov_aval,
            "media_aprovados": media_aprov,
            "dp_aprovados": dp_aprov,
        })

    return resultados


# ---------------------------------------------------------------------------
# Extração de enunciados de avaliação (PDFs) da página de relatório
# ---------------------------------------------------------------------------

def extrair_enunciados_avaliacao(
    ocorrencia_id: str,
    sessao: SigarraSession,
    verbosidade: int = 1,
    logger: AuditoriaLogger | None = None,
) -> list[dict]:
    """Extrai os enunciados de avaliação (PDFs) da página de relatório da UC.

    Faz fetch da página de relatório, localiza a secção
    'Enunciados das Avaliações' e descarrega cada PDF.

    Args:
        ocorrencia_id: Código da ocorrência da UC.
        sessao: Sessão autenticada no SIGARRA.
        verbosidade: Nível de verbosidade (0 = silencioso, 1 = normal, 2 = detalhado).
        logger: Logger opcional; se presente, usado em vez de print.

    Returns:
        Lista de dicts com 'nome', 'descricao', 'epoca', 'data',
        'url' e 'pdf_bytes'.  Lista vazia se a secção não existir.
    """

    def _info(msg: str) -> None:
        if logger:
            logger.info(msg)
        elif verbosidade >= 1:
            print(msg)

    def _aviso(msg: str) -> None:
        if logger:
            logger.aviso(msg)
        elif verbosidade >= 1:
            print(msg)
    if not sessao.autenticado:
        raise PermissionError(
            "É necessário autenticar antes de aceder aos enunciados."
        )

    url = SIGARRA_RELATORIO_UC_URL.format(ocorrencia_id)
    html = sessao.fetch_html(url)

    # Localizar secção "Enunciados das Avaliações" + tabela
    match = re.search(
        r"<h2[^>]*>Enunciados das Avalia[^<]*</h2>\s*<table[^>]*>(.*?)</table>",
        html,
        re.DOTALL | re.IGNORECASE,
    )
    if not match:
        return []

    enunciados = []
    for row in re.finditer(
        r'<tr class="d">(.*?)</tr>', match.group(1), re.DOTALL,
    ):
        cells = re.findall(r"<td[^>]*>(.*?)</td>", row.group(1), re.DOTALL)
        if len(cells) < 4:
            continue

        # Célula 0: link com nome do ficheiro
        link_match = re.search(r'href="([^"]+)"[^>]*>([^<]+)</a>', cells[0])
        if not link_match:
            continue

        href = link_match.group(1).strip()
        nome = link_match.group(2).strip()
        descricao = re.sub(r"<[^>]+>", "", cells[1]).strip()
        epoca = re.sub(r"<[^>]+>", "", cells[2]).strip()
        data = re.sub(r"<[^>]+>", "", cells[3]).strip()

        # URL completa para download
        if href.startswith("http"):
            pdf_url = href
        else:
            pdf_url = f"{SIGARRA_BASE}/{href}"

        # Descarregar PDF
        _info(f"  A descarregar: {nome}...")
        try:
            req = urllib.request.Request(
                pdf_url, headers={"User-Agent": "Mozilla/5.0"}
            )
            resp = sessao.http_open(req, timeout=60, context=f"download enunciado {nome}")
            pdf_bytes = resp.read()
        except (urllib.error.URLError, urllib.error.HTTPError) as e:
            _aviso(f"    Aviso: falha ao descarregar {nome}: {e}")
            continue

        # Se for ZIP, expandir os PDFs contidos
        if pdf_bytes[:4] == b"PK\x03\x04":
            _info(f"    É um ZIP — a extrair PDFs...")
            try:
                with zipfile.ZipFile(io.BytesIO(pdf_bytes)) as zf:
                    pdf_names = [n for n in zf.namelist() if n.lower().endswith(".pdf")]
                    for pdf_name in pdf_names:
                        extracted = zf.read(pdf_name)
                        base = Path(pdf_name).name
                        enunciados.append({
                            "nome": f"{nome} — {base}",
                            "descricao": descricao,
                            "epoca": epoca,
                            "data": data,
                            "url": pdf_url,
                            "pdf_bytes": extracted,
                            "origem": "SIGARRA",
                        })
            except zipfile.BadZipFile as e:
                _aviso(f"    Aviso: ZIP inválido em {nome}: {e}")
            continue

        enunciados.append({
            "nome": nome,
            "descricao": descricao,
            "epoca": epoca,
            "data": data,
            "url": pdf_url,
            "pdf_bytes": pdf_bytes,
            "origem": "SIGARRA",
        })

    return enunciados


def carregar_enunciados_locais(ocorrencia_id: str) -> list[dict]:
    """Carrega enunciados de avaliação a partir de ficheiros PDF locais.

    Procura PDFs na pasta ``enunciados/<ocorrencia_id>/`` relativa ao
    diretório do script.  Cada ficheiro é devolvido no mesmo formato que
    ``extrair_enunciados_avaliacao`` para poder ser combinado.

    Args:
        ocorrencia_id: Código da ocorrência da UC.

    Returns:
        Lista de dicts com 'nome', 'descricao', 'epoca', 'data',
        'url' e 'pdf_bytes' (os campos descritivos ficam genéricos).
    """
    pasta = _SCRIPT_DIR / "enunciados" / ocorrencia_id
    if not pasta.is_dir():
        return []

    enunciados = []
    for pdf_path in sorted(pasta.glob("*.pdf")):
        pdf_bytes = pdf_path.read_bytes()
        tamanho_kb = len(pdf_bytes) / 1024
        print(f"  Ficheiro local: {pdf_path.name} [{tamanho_kb:.0f} KB]")
        enunciados.append({
            "nome": pdf_path.name,
            "descricao": "ficheiro local",
            "epoca": "",
            "data": "",
            "url": str(pdf_path),
            "pdf_bytes": pdf_bytes,
            "origem": "local",
        })

    return enunciados


# ---------------------------------------------------------------------------
# Extração de resultados de inquéritos pedagógicos
# ---------------------------------------------------------------------------

def extrair_inquerito_pedagogico(
    ocorrencia_id: str, sessao: SigarraSession,
) -> dict:
    """Extrai os resultados dos inquéritos pedagógicos de uma UC.

    Faz fetch da página IPUP, extrai a identificação, taxa de resposta
    e as 12 perguntas com estatísticas (média, mediana, DP na escala 1-7).

    Args:
        ocorrencia_id: Código da ocorrência da UC.
        sessao: Sessão autenticada no SIGARRA.

    Returns:
        Dict com 'identificacao', 'n_questionarios', 'n_respondidos',
        'taxa_resposta' e 'perguntas'.
    """
    if not sessao.autenticado:
        raise PermissionError(
            "É necessário autenticar antes de aceder aos inquéritos pedagógicos."
        )

    url = SIGARRA_IPUP_URL.format(ocorrencia_id)

    try:
        html = sessao.fetch_html(url, timeout=90)

    except urllib.error.HTTPError as e:
        if e.code == 403:
            raise PermissionError(
                "Sem permissões para aceder aos inquéritos pedagógicos desta UC."
            ) from e
        elif e.code == 404:
            raise ValueError(
                f"Páginas de inquéritos pedagógicos não encontradas para ocorrência {ocorrencia_id}."
            ) from e
        else:
            raise RuntimeError(f"Erro HTTP {e.code} ao aceder aos inquéritos pedagógicos.") from e

    except urllib.error.URLError as e:
        raise ConnectionError(
            f"Erro de ligação ao SIGARRA: {e.reason}"
        ) from e



    # Identificação: <h3>Nome UC (CÓDIGO) - ANO/ANO - PERÍODO</h3>
    ident = {}
    h3_match = re.search(
        r"<h3>(.+?)\(([^)]+)\)\s*-\s*(\d{4}/\d{4})\s*-\s*(\w+)</h3>",
        html,
    )
    if h3_match:
        ident["nome_uc"] = html_mod.unescape(h3_match.group(1).strip())
        ident["codigo"] = h3_match.group(2).strip()
        ident["ano_letivo"] = h3_match.group(3).strip()
        ident["periodo"] = h3_match.group(4).strip()

    # Extrair perguntas da tabela (apenas linhas visíveis)
    perguntas = []
    n_questionarios = 0
    n_respondidos = 0

    for tr_match in re.finditer(
        r'<tr[^>]*class="d"[^>]*>(.*?)</tr>', html, re.DOTALL,
    ):
        # Saltar linhas ocultas (detalhe por docente)
        if "display:none" in tr_match.group(0):
            continue

        cells = re.findall(r"<td[^>]*>(.*?)</td>", tr_match.group(1), re.DOTALL)
        if len(cells) < 10:
            continue

        # Pergunta: remover tags HTML (img expand/collapse) e entidades
        pergunta = html_mod.unescape(re.sub(r"<[^>]+>", "", cells[0])).strip()
        dimensao = html_mod.unescape(re.sub(r"<[^>]+>", "", cells[1])).strip()
        alvo = html_mod.unescape(re.sub(r"<[^>]+>", "", cells[2])).strip()

        def _parse_int(val):
            val = val.strip()
            try:
                return int(val)
            except ValueError:
                return 0

        def _parse_float(val):
            val = val.strip().replace(",", ".")
            try:
                return float(val)
            except ValueError:
                return 0.0

        nq = _parse_int(cells[3])
        nqr = _parse_int(cells[4])
        minimo = _parse_int(cells[5])
        maximo = _parse_int(cells[6])
        media = _parse_float(cells[7])
        mediana = _parse_float(cells[8])
        dp = _parse_float(cells[9])

        if not n_questionarios and nq:
            n_questionarios = nq
            n_respondidos = nqr

        perguntas.append({
            "pergunta": pergunta,
            "dimensao": dimensao,
            "alvo": alvo,
            "n_quest": nq,
            "n_resp": nqr,
            "min": minimo,
            "max": maximo,
            "media": media,
            "mediana": mediana,
            "dp": dp,
        })

    if not perguntas:
        raise ValueError(
            f"Dados de inquéritos pedagógicos não encontrados para a ocorrência {ocorrencia_id}"
        )

    taxa_resposta = (n_respondidos / n_questionarios * 100) if n_questionarios else 0.0

    return {
        "identificacao": ident,
        "n_questionarios": n_questionarios,
        "n_respondidos": n_respondidos,
        "taxa_resposta": round(taxa_resposta, 1),
        "perguntas": perguntas,
    }


def extrair_comentarios_inquerito(
    ocorrencia_id: str, ano_letivo: str, sessao: SigarraSession,
) -> bytes | None:
    """Descarrega o ficheiro Excel de comentários do inquérito pedagógico.

    Args:
        ocorrencia_id: Código da ocorrência da UC.
        ano_letivo: Ano civil de início do ano letivo (ex: "2024" para 2024/2025).
        sessao: Sessão autenticada no SIGARRA.

    Returns:
        Bytes do ficheiro Excel, ou None se falhar.
    """
    if not sessao.autenticado:
        raise PermissionError(
            "É necessário autenticar antes de aceder aos comentários."
        )

    url = SIGARRA_IPUP_COMENTARIOS_URL.format(ocorrencia_id, ano_letivo)
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        resp = sessao.http_open(req, timeout=90, context="download comentários inquérito")
        return resp.read()
    except (urllib.error.URLError, urllib.error.HTTPError) as e:
        print(f"  Aviso: falha ao descarregar comentários do inquérito: {e}")
        return None


# ---------------------------------------------------------------------------
# Cálculo de horas previstas / efetivas
# ---------------------------------------------------------------------------

# Mapeamento de códigos SIGARRA para nomes no formulário
_TIPO_AULA_NOMES = {
    "T": "Teóricas",
    "TP": "Teórico-Práticas",
    "P": "Práticas",
    "PL": "Práticas Laboratoriais",
    "S": "Seminários",
    "OT": "Orientação Tutorial",
    "TC": "Trabalho de Campo",
    "E": "Estágio",
}
_TIPO_AULA_CODIGOS: dict[str, str] = {}
for _cod, _nome in _TIPO_AULA_NOMES.items():
    _TIPO_AULA_CODIGOS[_nome.lower()] = _cod
# Formas singulares comuns
_TIPO_AULA_CODIGOS.update({
    "teórica": "T", "teórico-prática": "TP",
    "prática": "P", "prática laboratorial": "PL",
    "seminário": "S",
})


def _normalizar_tipo_aula(nome: str) -> str:
    """Normaliza nome/código de tipo de aula para código curto (T, TP, etc.)."""
    s = nome.strip()
    if s.upper() in _TIPO_AULA_NOMES:
        return s.upper()
    s_lower = s.lower()
    if s_lower in _TIPO_AULA_CODIGOS:
        return _TIPO_AULA_CODIGOS[s_lower]
    for chave, cod in _TIPO_AULA_CODIGOS.items():
        if chave in s_lower or s_lower in chave:
            return cod
    return s


_RE_AULA_NAO_REALIZADA = re.compile(
    r"(?:aula\s+n[ãa]o\s+(?:se\s+)?realiz|n[ãa]o\s+houve\s+aula"
    r"|feriado|toler[âa]ncia\s+de\s+ponto"
    r"|docente\s+ausente|professor\s+ausente"
    r"|sem\s+aula|aula\s+cancel|aula\s+suspensa|greve"
    r"|no\s+(?:\S+\s+){0,4}class(?:es)?"
    r"|class(?:es)?\s+cancel"
    r"|did\s+not\s+take\s+place"
    r"|holiday|bank\s+holiday)",
    re.IGNORECASE,
)


def _extrair_escolaridade_form(html: str) -> dict[str, float]:
    """Extrai horas/semana por tipo de aula da secção Escolaridade do formulário.

    Suporta formato com vários tipos na mesma célula, ex:
      <b>Teóricas:</b> 2 - <b>Teórico-Práticas:</b> 2 (horas/semana)
    """
    # Localizar a célula da Escolaridade
    m_celula = re.search(
        r'Escolaridade:\s*</td>\s*<td>(.*?)</td>',
        html, re.DOTALL | re.IGNORECASE,
    )
    if not m_celula:
        return {}
    celula = m_celula.group(1)
    result = {}
    for m in re.finditer(r'<b>([^<:]+):</b>\s*([\d,\.]+)', celula):
        tipo_nome = m.group(1).strip()
        horas = float(m.group(2).replace(",", "."))
        result[tipo_nome] = horas
    return result


def _extrair_tipos_aula_tabela_horas(html: str) -> list[str]:
    """Extrai nomes dos tipos de aula da tabela de horas do formulário, por ordem."""
    m_sec = re.search(
        r'N[úu]mero de horas de aula.*?</table>',
        html, re.DOTALL | re.IGNORECASE,
    )
    if not m_sec:
        return []
    tabela = m_sec.group(0)
    nomes = []
    for m in re.finditer(r'<td[^>]*>\s*<b>([^<]+)</b>\s*</td>', tabela):
        nomes.append(m.group(1).strip())
    return nomes


def calcular_horas_relatorio(
    campos: dict,
    sumarios: list[dict],
) -> None:
    """Calcula e preenche horas previstas e efetivas no dict de campos.

    Utiliza _escolaridade e _tipos_aula extraídos por extrair_form_relatorio()
    e os sumários das aulas para determinar semanas de calendário e semanas
    sem aula efetiva.

    Modifica campos in-place (parr_horas_prev e parr_horas_efec).
    """
    from datetime import datetime

    escolaridade = campos.get("_escolaridade", {})
    # _tipos_aula vem da tabela de horas (pode não existir no HTML do SIGARRA);
    # fallback para as chaves de _escolaridade, que têm a mesma ordem do formulário.
    tipos_aula = campos.get("_tipos_aula") or list(escolaridade.keys())
    horas_prev_orig = campos.get("parr_horas_prev", [])
    if not isinstance(horas_prev_orig, list):
        horas_prev_orig = [horas_prev_orig]

    if not escolaridade:
        print("  Aviso: sem dados de escolaridade — horas não calculadas.")
        return

    novas_prev = []
    novas_efec = []

    for i, tipo_nome in enumerate(tipos_aula):
        h_semana = escolaridade.get(tipo_nome)
        h_total_str = horas_prev_orig[i] if i < len(horas_prev_orig) else "0"
        try:
            h_total = float(h_total_str)
        except (ValueError, TypeError):
            h_total = 0.0

        if not h_semana or h_total == 0:
            novas_prev.append(h_total_str)
            novas_efec.append(h_total_str)
            print(f"  {tipo_nome}: sem horas/semana — mantido {h_total_str}h")
            continue

        semanas_acred = round(h_total / h_semana)
        codigo = _normalizar_tipo_aula(tipo_nome)

        # Filtrar sumários deste tipo de aula
        sums_tipo = [
            s for s in sumarios
            if _normalizar_tipo_aula(s.get("tipo_aula", "")) == codigo
        ]

        if not sums_tipo:
            novas_prev.append(h_total_str)
            novas_efec.append(h_total_str)
            print(f"  {tipo_nome} ({codigo}): sem sumários — mantido {h_total_str}h")
            continue

        # Usar turma representativa (a com mais sumários)
        turmas: dict[str, list] = {}
        for s in sums_tipo:
            turmas.setdefault(s["turma"], []).append(s)
        turma_rep = max(turmas.values(), key=len)

        # Contar semanas distintas (por nº de semana ISO)
        semanas_info: dict[tuple, list] = {}
        for s in turma_rep:
            try:
                dt = datetime.strptime(s["data"], "%d/%m/%Y")
                chave = dt.isocalendar()[:2]  # (year, week)
            except ValueError:
                continue
            semanas_info.setdefault(chave, []).append(s)

        semanas_calendario = len(semanas_info)

        # Detetar semanas sem aula efetiva
        semanas_nao_realizadas = 0
        for _chave, sums_semana in semanas_info.items():
            if all(
                _RE_AULA_NAO_REALIZADA.search(s["sumario"])
                for s in sums_semana
            ):
                semanas_nao_realizadas += 1

        h_previstas = round(semanas_calendario * h_semana)
        h_efetivas = round(
            (semanas_calendario - semanas_nao_realizadas) * h_semana
        )

        print(
            f"  {tipo_nome} ({codigo}): {h_semana}h/sem × {semanas_acred} sem (acred.)"
            f" → {semanas_calendario} sem calendário"
            f" ({semanas_nao_realizadas} não realizadas)"
            f" → previstas={h_previstas}h, efetivas={h_efetivas}h"
        )

        novas_prev.append(str(h_previstas))
        novas_efec.append(str(h_efetivas))

    campos["parr_horas_prev"] = novas_prev
    campos["parr_horas_efec"] = novas_efec


# ---------------------------------------------------------------------------
# Extração e submissão do formulário de relatório da UC
# ---------------------------------------------------------------------------

def extrair_form_relatorio(
    ocorrencia_id: str,
    sessao: SigarraSession,
    output_dir: Path | None = None,
    verbosidade: int = 1,
) -> dict:
    """Extrai os campos do formulário de edição do relatório da UC.

    Faz fetch da página de edição e extrai todos os campos do formulário
    (hidden, text, textarea) com os seus valores atuais.

    Args:
        ocorrencia_id: Código da ocorrência da UC.
        sessao: Sessão autenticada no SIGARRA.

    Returns:
        Dict com os nomes e valores dos campos do formulário.
        Campos com múltiplas ocorrências (parr_*) são listas.
    """
    if not sessao.autenticado:
        raise PermissionError(
            "É necessário autenticar antes de aceder ao relatório."
        )

    url = SIGARRA_REL_UC_EDIT_URL.format(ocorrencia_id)
    html = sessao.fetch_html(url)

    # Guardar HTML do formulário para diagnóstico apenas em debug (V>=2)
    if verbosidade >= 2:
        dbg_dir = output_dir or (Path(__file__).resolve().parent / "output" / ocorrencia_id)
        dbg_dir.mkdir(parents=True, exist_ok=True)
        (dbg_dir / "form_edit.html").write_text(html, encoding="utf-8")

    import html as html_mod

    # Remover blocos <script> para não capturar inputs/selects de código JavaScript
    html_limpo = re.sub(r'<script\b[^>]*>.*?</script>', '', html,
                        flags=re.DOTALL | re.IGNORECASE)

    campos = {}

    # Extrair todos os <input> (hidden, text) independentemente da ordem dos atributos
    for m in re.finditer(r'<input\b([^>]*)/?>', html_limpo, re.DOTALL | re.IGNORECASE):
        attrs = m.group(1)
        # Extrair atributos individuais
        tipo_m = re.search(r'type=["\']([^"\']+)["\']', attrs, re.IGNORECASE)
        nome_m = re.search(r'name=["\']([^"\']+)["\']', attrs, re.IGNORECASE)
        valor_m = re.search(r'value=["\']([^"\']*)["\']', attrs, re.IGNORECASE)
        if not nome_m:
            continue
        tipo = (tipo_m.group(1) if tipo_m else "text").lower()
        if tipo not in ("hidden", "text"):
            continue
        nome = nome_m.group(1)
        valor = valor_m.group(1) if valor_m else ""
        if nome.startswith("parr_"):
            campos.setdefault(nome, []).append(valor)
        else:
            campos[nome] = valor

    # Extrair textareas: <textarea name="...">conteúdo</textarea>
    for m in re.finditer(
        r'<textarea\s+name=["\']([^"\']+)["\'][^>]*>(.*?)</textarea>',
        html_limpo,
        re.DOTALL | re.IGNORECASE,
    ):
        nome = m.group(1)
        valor = m.group(2)
        campos[nome] = valor

    # Extrair selects: <select name="...">...<option selected value="...">...</select>
    for m in re.finditer(
        r'<select\s+[^>]*name=["\']([^"\']+)["\'][^>]*>(.*?)</select>',
        html_limpo,
        re.DOTALL | re.IGNORECASE,
    ):
        nome = m.group(1)
        options_html = m.group(2)
        # Procurar a opção selecionada
        sel = re.search(
            r'<option[^>]+selected[^>]*value=["\']([^"\']*)["\']',
            options_html, re.IGNORECASE,
        )
        if not sel:
            sel = re.search(
                r'<option[^>]*value=["\']([^"\']*)["\'][^>]*selected',
                options_html, re.IGNORECASE,
            )
        valor = sel.group(1) if sel else ""
        if nome.startswith("parr_"):
            campos.setdefault(nome, []).append(valor)
        else:
            campos[nome] = valor

    # Metadata adicional para cálculo de horas (não enviada no POST)
    campos["_escolaridade"] = _extrair_escolaridade_form(html)
    campos["_tipos_aula"] = _extrair_tipos_aula_tabela_horas(html)

    return campos



def texto_para_html_paragrafos(s: str) -> str:
    s = (s or "").strip()
    if not s:
        return ""
    # normalizar quebras
    s = s.replace("\r\n", "\n").replace("\r", "\n")
    # escapar para não partir com <, &, etc.
    s = html_mod.escape(s)

    # separar por linhas em branco => parágrafos
    blocos = re.split(r"\n\s*\n+", s)
    ps = []
    for b in blocos:
        b = b.strip()
        if not b:
            continue
        # quebras dentro do parágrafo
        b = b.replace("\n", "<br>\n")
        ps.append(f"<p>{b}</p>")
    return "\n".join(ps)


def submeter_relatorio(
    sessao: SigarraSession,
    campos: dict,
    ocorrencia_id: str,
    output_dir: Path | None = None,
) -> bool:
    """Submete o formulário de relatório da UC.

    Faz POST para ucurr_adm.rel_uc_sub com todos os campos fornecidos.

    Args:
        sessao: Sessão autenticada no SIGARRA.
        campos: Dict com os campos do formulário (nome → valor).
                Campos parr_* podem ser listas (múltiplos valores).
        ocorrencia_id: Código da ocorrência da UC (ex: "559654").

    Returns:
        True se a submissão foi bem-sucedida.
    """
    if not sessao.autenticado:
        raise PermissionError(
            "É necessário autenticar antes de submeter o relatório."
        )

    # Substituir caracteres Unicode não suportados por ISO-8859-15
    _unicode_to_latin = str.maketrans({
        "\u2192": "->",   # →
        "\u2190": "<-",   # ←
        "\u2013": "-",    # –
        "\u2014": "-",    # —
        "\u2018": "'",    # '
        "\u2019": "'",    # '
        "\u201c": '"',    # "
        "\u201d": '"',    # "
        "\u2026": "...",  # …
        "\u2022": "-",    # •
        "\u2265": ">=",   # ≥
        "\u2264": "<=",   # ≤
        "\u2248": "~",    # ≈
    })

    # Remover emoji de semáforo dos cabeçalhos quando configurado
    _remover_emoji = os.environ.get("SIGARRA_REMOVER_EMOJI", "").strip().lower() in ("1", "true", "yes")
    _EMOJI_SEMAFORO = re.compile(r'(<strong>)\s*[🟢🟡🟠🔴⚫]\s*')

    # Construir pares chave-valor para o POST (preservando ordem e múltiplos)
    # Enviamos TODOS os campos extraídos do formulário — o SIGARRA precisa
    # de campos hidden (tokens, action, etc.) para processar a submissão.
    pares = []
    to_html = {"pv_rel_coment_res", "pv_rel_coment_func"}
    _campos_texto = {"pv_rel_coment_res", "pv_rel_coment_func", "pv_rel_programa"}
    for nome, valor in campos.items():
        if nome.startswith("_"):
            continue  # metadata interna, não enviar
        valores = valor if isinstance(valor, list) else [valor]
        for v in valores:
            v = "" if v is None else str(v)
            if nome in to_html and "<p>" not in v:
                # Só converter texto plano → HTML; se já contém <p>, é HTML
                v = texto_para_html_paragrafos(v)
            if _remover_emoji and nome in _campos_texto:
                v = _EMOJI_SEMAFORO.sub(r'\1', v)
            pares.append((nome, v))

    # Codificar em iso-8859-15 (encoding do SIGARRA)
    dados_codificados = urllib.parse.urlencode(pares, 
                                               encoding="iso-8859-15", 
                                               errors="xmlcharrefreplace")


    referer_url = SIGARRA_REL_UC_EDIT_URL.format(ocorrencia_id)
    
    req = urllib.request.Request(
        SIGARRA_REL_UC_SUB_URL,
        data=dados_codificados.encode("iso-8859-15"),
        headers={
            "User-Agent": "Mozilla/5.0",
            "Content-Type": "application/x-www-form-urlencoded",
            "Referer": referer_url,
        },
        method="POST",
    )

    # Diagnóstico: listar campos enviados
    nomes_campos = {}
    for nome, v in pares:
        nomes_campos[nome] = nomes_campos.get(nome, 0) + 1
    print(f"  Campos no POST ({len(pares)} pares): "
          + ", ".join(f"{n}(x{c})" if c > 1 else n for n, c in nomes_campos.items()))

    try:
        resp = sessao.http_open(req, timeout=30, context="submeter relatório UC")
        charset = resp.headers.get_content_charset() or "iso-8859-15"
        body = resp.read().decode(charset)

        # Guardar sempre a resposta para diagnóstico
        dbg_dir = output_dir or (Path(__file__).resolve().parent / "output" / ocorrencia_id)
        dbg_dir.mkdir(parents=True, exist_ok=True)
        (dbg_dir / "submissao_resposta.html").write_text(body, encoding="utf-8")

        # Verificar indicadores de erro no corpo da resposta
        _padroes_erro = [
            r'class="erro"[^>]*>(.*?)</',
            r'class="error"[^>]*>(.*?)</',
            r'<div[^>]+id="erros"[^>]*>(.*?)</div>',
        ]
        for padrao in _padroes_erro:
            m = re.search(padrao, body, re.DOTALL | re.IGNORECASE)
            if m:
                msg = html_to_text(m.group(1)).strip()
                if msg:
                    raise ValueError(f"SIGARRA: {msg}")

        # Verificar padrões textuais de rejeição
        _rejeicoes = [
            "não tem permissão",
            "sem permissão",
            "operação não permitida",
            "não é possível submeter",
            "fora do prazo",
            "período de entrega",
        ]
        body_lower = body.lower()
        for r in _rejeicoes:
            if r in body_lower:
                raise ValueError(
                    f"SIGARRA não permitiu a submissão: '{r}'. "
                    "Verifique se o ano letivo está em período de entrega de relatórios."
                )

        return True
    except urllib.error.HTTPError as e:
        try:
            err_body = e.read().decode("iso-8859-15", errors="replace")
        except Exception:
            err_body = ""
        # Mensagem dependente do nível de verbosidade
        raise ConnectionError(
            f"Erro HTTP {e.code} na submissão ao SIGARRA. "
            #+ (f"Detalhe: {err_body[:300]}" if err_body else "")
        ) from e


# ---------------------------------------------------------------------------
# Upload de enunciados de avaliação para o SIGARRA
# ---------------------------------------------------------------------------

def _gerar_sandbox_hash() -> str:
    """Gera um identificador para o sandbox de upload do SIGARRA.

    O pv_hash é gerado pelo JavaScript do cliente (não pelo servidor —
    o campo ``<input name="pv_hash">`` vem com value vazio).
    O servidor aceita qualquer valor único. Usamos um formato semelhante
    ao original (17 dígitos baseados em timestamp + aleatório).
    """
    import time
    import random
    # Formato semelhante ao observado: "01152145113592562"
    ts = str(int(time.time() * 1000))       # 13 dígitos (milissegundos)
    rnd = str(random.randint(1000, 9999))    # 4 dígitos aleatórios
    return ts + rnd


def upload_enunciado_sigarra(
    sessao: SigarraSession,
    pv_hash: str,
    nome_ficheiro: str,
    pdf_bytes: bytes,
    ocorrencia_id: str = "",
) -> dict | None:
    """Faz upload de um PDF para o sandbox de enunciados do SIGARRA.

    Envia o ficheiro via multipart/form-data para gdoc_geral.upload_to_sandbox.
    O ficheiro fica na sandbox até o formulário principal ser submetido.

    Args:
        sessao: Sessão autenticada no SIGARRA.
        pv_hash: Hash do sandbox (gerado por _gerar_sandbox_hash).
        nome_ficheiro: Nome do ficheiro PDF.
        pdf_bytes: Conteúdo binário do PDF.
        ocorrencia_id: Código da ocorrência (para Referer).

    Returns:
        Dict com info do ficheiro {'id', 'nome', 'extensao', 'tamanho'}
        ou None se falhar.
    """
    if not sessao.autenticado:
        raise PermissionError("É necessário autenticar antes de fazer upload.")

    # Construir corpo multipart manualmente (stdlib, sem dependências)
    boundary = f"----PythonUpload{id(pdf_bytes):016x}"

    parts = []

    # Campo pv_hash
    parts.append(
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="pv_hash"\r\n\r\n'
        f"{pv_hash}\r\n"
    )

    # Campo parr_ficheiro (o PDF)
    parts.append(
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="parr_ficheiro"; '
        f'filename="{nome_ficheiro}"\r\n'
        f"Content-Type: application/pdf\r\n\r\n"
    )

    # Montar o corpo: partes texto + binário do PDF + fecho
    body = b""
    for p in parts[:-1]:
        body += p.encode("utf-8")

    # Última parte (header do ficheiro) + conteúdo binário + boundary final
    body += parts[-1].encode("utf-8")
    body += pdf_bytes
    body += f"\r\n--{boundary}--\r\n".encode("utf-8")

    referer_url = SIGARRA_REL_UC_EDIT_URL.format(ocorrencia_id) if ocorrencia_id else ""

    req = urllib.request.Request(
        SIGARRA_UPLOAD_SANDBOX_URL,
        data=body,
        headers={
            "User-Agent": "Mozilla/5.0",
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "Referer": referer_url,
        },
        method="POST",
    )

    try:
        resp = sessao.http_open(req, timeout=120, context=f"upload sandbox {nome_ficheiro}")
        charset = resp.headers.get_content_charset() or "iso-8859-15"
        html = resp.read().decode(charset, errors="replace")

        # Extrair resposta JSON do JavaScript:
        # pedidos["hash"].onComplete({ "hash": "...", "erro": null, "ficheiros": [...] })
        m = re.search(r'onComplete\(\s*(\{.*?\})\s*\)', html, re.DOTALL)
        if not m:
            print(f"    Upload: resposta inesperada (sem onComplete)")
            return None

        import json
        # O JSON pode ter trailing commas ou formatação SIGARRA — tentar parse
        json_str = m.group(1)
        # Limpar possíveis vírgulas antes de } ou ]
        json_str = re.sub(r',\s*([}\]])', r'\1', json_str)
        data = json.loads(json_str)

        if data.get("erro"):
            print(f"    Upload erro: {data['erro']}")
            return None

        ficheiros = data.get("ficheiros", [])
        if ficheiros:
            return ficheiros[0]  # {id, nome, extensao, tamanho, ...}

        return None

    except urllib.error.HTTPError as e:
        print(f"    Upload erro HTTP: {e.code}")
        return None
    except (json.JSONDecodeError, ValueError) as e:
        print(f"    Upload: erro ao parsear resposta: {e}")
        return None


_RE_EPOCA_NORMAL = re.compile(
    r"(?:exame|exam|frequencia|frequência|midterm|final\b|teste|test\b)",
    re.IGNORECASE,
)
_RE_EPOCA_RECURSO = re.compile(
    r"(?:recurso|retake|appeal|repescagem|2\.?\s*[eé]poca|segunda\s*[eé]poca"
    r"|resit|supplementary|makeup|make-up)",
    re.IGNORECASE,
)


def _inferir_epoca(nome: str) -> str:
    """Infere o código de época a partir do nome do enunciado.

    Returns:
        "R" (Recurso), "N" (Normal) ou "AD" (Avaliação Distribuída).
    """
    if _RE_EPOCA_RECURSO.search(nome):
        return "R"
    if _RE_EPOCA_NORMAL.search(nome):
        return "N"
    return "AD"


def inferir_epoca_enunciado(nome: str) -> str:
    """Versão pública da inferência de época para um enunciado.

    Args:
        nome: Nome do ficheiro/enunciado.

    Returns:
        Código de época: "N", "R" ou "AD".
    """
    return _inferir_epoca(nome or "")


def submeter_enunciados_sigarra(
    sessao: SigarraSession,
    ocorrencia_id: str,
    enunciados: list[dict],
) -> list[dict]:
    """Faz upload de enunciados para o SIGARRA e devolve info para o formulário.

    Obtém o pv_hash da página de sandbox (popup de upload de enunciados),
    faz upload de cada PDF e devolve os dados necessários para incluir
    no formulário principal (parr_aval_gdoc_id, parr_aval_descricao,
    parr_aval_epoca).

    A época é inferida automaticamente a partir do nome do enunciado:
    - "R" (Recurso) se contiver: recurso, appeal, repescagem, 2.ª época
    - "N" (Normal) se contiver: exame, teste, frequência, midterm, final
    - "AD" (Avaliação Distribuída) para tudo o resto (projetos, trabalhos)

    Args:
        sessao: Sessão autenticada no SIGARRA.
        ocorrencia_id: Código da ocorrência da UC.
        enunciados: Lista de dicts com 'nome', 'descricao' e 'pdf_bytes'.

    Returns:
        Lista de dicts com 'gdoc_id', 'descricao' e 'epoca' para cada
        ficheiro carregado com sucesso.
    """
    if not enunciados:
        return []

    pv_hash = _gerar_sandbox_hash()
    print(f"  pv_hash (gerado): {pv_hash}")

    carregados = []
    for e in enunciados:
        nome = e["nome"]
        if not nome.lower().endswith(".pdf"):
            nome += ".pdf"
        descricao = e.get("descricao", nome)
        epoca = _inferir_epoca(nome)
        print(f"  A carregar: {nome} (época: {epoca})...")
        resultado = upload_enunciado_sigarra(
            sessao, pv_hash, nome, e["pdf_bytes"],
            ocorrencia_id=ocorrencia_id,
        )
        if resultado:
            gdoc_id = resultado.get("id")
            print(f"    OK: id={gdoc_id}, "
                  f"tamanho={resultado.get('tamanho')} KB")
            carregados.append({
                "gdoc_id": str(gdoc_id),
                "descricao": descricao,
                "epoca": epoca,
            })
        else:
            print(f"    FALHA: {nome}")

    return carregados


# ---------------------------------------------------------------------------
# Extração de UCs do serviço docente (Distribuição de Serviço) — ocorrências únicas
# (dedup por (ocorrencia_id, curso, ano, periodo))
# ---------------------------------------------------------------------------

SIGARRA_SERVICO_DOCENTE_QUERYLIST_URL = f"{SIGARRA_BASE}/ds_func_relatorios.querylist"
SIGARRA_SERVICO_DOCENTE_LISTA_ANOS_URL = f"{SIGARRA_BASE}/ds_func_relatorios.lista_anos"


def extrair_anos_servico_docente(
    sessao: SigarraSession,
    doc_codigo: str,
) -> list[dict]:
    """Extrai os anos letivos disponíveis no serviço docente.

    Args:
        sessao: Sessão autenticada.
        doc_codigo: Código do docente.

    Returns:
        Lista de dicts no formato:
          {
            "ano_inicio": "2025",
            "ano_letivo": "2025/2026",
          }
        ordenada conforme apresentada no SIGARRA (tipicamente decrescente).
    """
    if not sessao.autenticado:
        raise PermissionError("É necessário autenticar antes de aceder ao serviço docente.")

    params = {
        "pv_doc_codigo": str(doc_codigo).strip(),
        "pv_outras_inst": "S",
    }
    url = f"{SIGARRA_SERVICO_DOCENTE_LISTA_ANOS_URL}?{urllib.parse.urlencode(params)}"
    html = sessao.fetch_html(url)

    soup = BeautifulSoup(html, "html.parser")
    anos: list[dict] = []
    vistos: set[str] = set()

    for a in soup.find_all("a", href=True):
        href = a.get("href", "")
        m_inicio = re.search(r"pv_ano_lectivo=(\d{4})", href, re.IGNORECASE)
        if not m_inicio:
            continue

        texto = html_mod.unescape(a.get_text(" ", strip=True))
        title = html_mod.unescape(a.get("title", "") or "")
        ano_letivo = ""

        m_ano = re.search(r"(\d{4}/\d{4})", title) or re.search(r"(\d{4}/\d{4})", texto)
        if m_ano:
            ano_letivo = m_ano.group(1)

        ano_inicio = m_inicio.group(1)
        if not ano_letivo:
            try:
                ano_letivo = f"{ano_inicio}/{int(ano_inicio) + 1}"
            except ValueError:
                ano_letivo = ano_inicio

        if ano_inicio in vistos:
            continue
        vistos.add(ano_inicio)
        anos.append({
            "ano_inicio": ano_inicio,
            "ano_letivo": ano_letivo,
        })

    return anos


def docente_eh_regente_na_ocorrencia(
    sessao: SigarraSession,
    ocorrencia_id: str,
    doc_codigo: str,
) -> bool:
    """Indica se o docente é Regente na ocorrência da UC.

    A informação é extraída da secção "Docência - Responsabilidades"
    da ficha da UC.
    """
    if not sessao.autenticado:
        raise PermissionError("É necessário autenticar antes de verificar responsabilidades.")

    html = sessao.fetch_html(SIGARRA_UC_URL.format(ocorrencia_id))
    soup = BeautifulSoup(html, "html.parser")

    alvo = str(doc_codigo).strip()

    for tabela in soup.find_all("table", class_="dados"):
        header = tabela.find("th")
        if not header:
            continue
        tabela_txt = html_mod.unescape(tabela.get_text(" ", strip=True)).lower()
        if "responsabilidade" not in tabela_txt:
            continue

        for tr in tabela.find_all("tr"):
            tds = tr.find_all("td")
            if len(tds) < 2:
                continue

            docente_td, resp_td = tds[0], tds[1]
            a = docente_td.find("a", href=True)
            if not a:
                continue

            href = a.get("href", "")
            m_doc = re.search(r"p_codigo=(\d+)", href, re.IGNORECASE)
            if not m_doc:
                continue

            codigo_linha = m_doc.group(1).strip()
            if codigo_linha != alvo:
                continue

            resp = html_mod.unescape(resp_td.get_text(" ", strip=True)).lower()
            if "regente" in resp:
                return True

    return False


def _info_docencia_ocorrencia(
    sessao: SigarraSession,
    ocorrencia_id: str,
    doc_codigo: str,
) -> tuple[bool, str]:
    """Devolve (eh_regente, sigla_uc) para uma ocorrência.

    Reutiliza a mesma página da ficha para verificar regência e extrair sigla.
    """
    if not sessao.autenticado:
        raise PermissionError("É necessário autenticar antes de verificar responsabilidades.")

    html = sessao.fetch_html(SIGARRA_UC_URL.format(ocorrencia_id))
    soup = BeautifulSoup(html, "html.parser")
    sigla_uc = _extrair_sigla_uc(html)

    alvo = str(doc_codigo).strip()
    eh_regente = False

    for tabela in soup.find_all("table", class_="dados"):
        header = tabela.find("th")
        if not header:
            continue
        tabela_txt = html_mod.unescape(tabela.get_text(" ", strip=True)).lower()
        if "responsabilidade" not in tabela_txt:
            continue

        for tr in tabela.find_all("tr"):
            tds = tr.find_all("td")
            if len(tds) < 2:
                continue

            docente_td, resp_td = tds[0], tds[1]
            a = docente_td.find("a", href=True)
            if not a:
                continue

            href = a.get("href", "")
            m_doc = re.search(r"p_codigo=(\d+)", href, re.IGNORECASE)
            if not m_doc:
                continue

            codigo_linha = m_doc.group(1).strip()
            if codigo_linha != alvo:
                continue

            resp = html_mod.unescape(resp_td.get_text(" ", strip=True)).lower()
            if "regente" in resp:
                eh_regente = True
                break

        if eh_regente:
            break

    return eh_regente, sigla_uc

def extrair_ocorrencias_servico_docente(
    sessao: SigarraSession,
    doc_codigo: str,
    ano_letivo: str | int | None = None,   # ex: 2022 => 2022/23
    incluir_meta: bool = False,
    apenas_regente_docente: bool = False,
) -> list[dict] | tuple[list[dict], dict]:
    """Extrai ocorrências de UCs do serviço docente, mantendo curso/ano/período.

    Requer sessão autenticada (cookies). Dedup por chave composta:
        (ocorrencia_id, curso, ano, periodo)

    Returns:
        Por omissão, lista de dicts:
          {
            'ocorrencia_id': '559654',
            'nome_uc': '...',
            'curso': 'MESW',
            'periodo': '1S',
            'ano': '1',
            'chave': ('559654','MESW','1','1S'),
            'url_ficha_uc': '...'
          }

        Se incluir_meta=True, devolve (lista, meta), onde meta pode incluir:
          {
            'ano_letivo_resolvido': '2025/2026',
            'docente_nome': 'Nome Apresentado na Página'
          }
    """
    if not sessao.autenticado:
        raise PermissionError("É necessário autenticar antes de aceder ao serviço docente.")

    params = {"pv_doc_codigo": str(doc_codigo).strip()}
    if ano_letivo is not None and str(ano_letivo).strip():
        params["pv_ano_lectivo"] = str(ano_letivo).strip()

    url = f"{SIGARRA_SERVICO_DOCENTE_QUERYLIST_URL}?{urllib.parse.urlencode(params)}"
    html = sessao.fetch_html(url)

    resultados: list[dict] = []
    vistos: set[tuple[str, str, str, str]] = set()

    def _norm(s: str) -> str:
        s = html_mod.unescape(s or "")
        s = re.sub(r"\s+", " ", s).strip()
        return s

    soup = BeautifulSoup(html, "html.parser")

    # Metadata da página (ano letivo efetivo e nome do docente)
    ano_letivo_resolvido = ""
    docente_nome = ""

    for h1 in soup.find_all("h1"):
        h1_txt = _norm(h1.get_text(" ", strip=True))
        if h1_txt:
            docente_nome = h1_txt
            break

    for h2 in soup.find_all("h2"):
        h2_txt = _norm(h2.get_text(" ", strip=True))
        if "distrib" in h2_txt.lower() and "servi" in h2_txt.lower():
            m_ano = re.search(r"(\d{4}/\d{4})", h2_txt)
            if m_ano:
                ano_letivo_resolvido = m_ano.group(1)
                break

    # Encontrar a tabela que contém o cabeçalho "Unidade Curricular"
    tabela_alvo = None
    for t in soup.find_all("table"):
        header_txt = " ".join(_norm(t.get_text(" ", strip=True)).split())
        if "Unidade Curricular" in header_txt or "Course Unit" in header_txt:
            # Heurística: a tabela tem de ter links com pv_ocorrencia_id
            if t.find("a", href=re.compile(r"pv_ocorrencia_id=\d+", re.I)):
                tabela_alvo = t
                break

    if tabela_alvo is None:
        raise ValueError("Tabela de distribuição de serviço não encontrada na página.")

    for tr in tabela_alvo.find_all("tr"):
        tds = tr.find_all("td")
        if len(tds) < 4:
            continue

        a = tr.find("a", href=re.compile(r"pv_ocorrencia_id=\d+", re.I))
        if not a:
            continue

        m = re.search(r"pv_ocorrencia_id=(\d+)", a.get("href", ""), re.I)
        if not m:
            continue
        ocorrencia_id = m.group(1)

        nome_uc = _norm(a.get_text(" ", strip=True))
        curso = _norm(tds[1].get_text(" ", strip=True)) if len(tds) > 1 else ""
        periodo = _norm(tds[2].get_text(" ", strip=True)) if len(tds) > 2 else ""
        ano = _norm(tds[3].get_text(" ", strip=True)) if len(tds) > 3 else ""

        chave = (ocorrencia_id, curso, ano, periodo)
        if chave in vistos:
            continue
        vistos.add(chave)

        resultados.append({
            "ocorrencia_id": ocorrencia_id,
            "nome_uc": nome_uc,
            "curso": curso,
            "periodo": periodo,
            "ano": ano,
            "chave": chave,
            "url_ficha_uc": SIGARRA_UC_URL.format(ocorrencia_id),
        })

    if apenas_regente_docente:
        filtradas: list[dict] = []
        for item in resultados:
            oc_id = item.get("ocorrencia_id", "")
            try:
                eh_regente, sigla_uc = _info_docencia_ocorrencia(sessao, oc_id, doc_codigo)
                if sigla_uc:
                    item["sigla_uc"] = sigla_uc
                if eh_regente:
                    filtradas.append(item)
            except Exception as e:
                print(f"  Aviso: falha ao verificar regência na ocorrência {oc_id}: {e}")
        resultados = filtradas

    if incluir_meta:
        return resultados, {
            "ano_letivo_resolvido": ano_letivo_resolvido,
            "docente_nome": docente_nome,
        }
    return resultados