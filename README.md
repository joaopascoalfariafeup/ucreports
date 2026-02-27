# UC Reports — Ferramenta de Revisão de Relatórios de Unidades Curriculares

Aplicação web para apoio à revisão e auditoria de relatórios de Unidades Curriculares (UCs) da FEUP/U.Porto, com análise assistida por LLM (modelos de linguagem de grande escala).

## Funcionalidades

- **Integração com SIGARRA** — carregamento automático dos relatórios de UC via API SIGARRA
- **Integração com Moodle** — recolha complementar de dados (enunciados, avaliações)
- **Análise por LLM** — revisão assistida por IA (Anthropic Claude, OpenAI GPT, IAEDU)
- **Revisão humana guiada** — pré-visualização, edição e submissão do relatório revisto ao SIGARRA
- **Autenticação federada** — suporte a login via credenciais SIGARRA ou SSO Shibboleth/SAML2 da U.Porto
- **Controlo de custos** — limite mensal de gastos por utilizador com suporte a providers gratuitos

## Arquitetura

```
Flask (app_web.py)
  ├── auditoria_core.py   — orquestração da análise e revisão
  ├── llm_analise.py      — clientes LLM (Anthropic, OpenAI, IAEDU)
  ├── sigarra.py          — cliente API SIGARRA
  ├── moodle.py           — cliente Moodle
  └── logger.py           — logging estruturado

Servidor WSGI: Waitress (produção)
Acesso público: Cloudflare Tunnel
```

## Pré-requisitos

- Python 3.10+
- [Waitress](https://docs.pylonsproject.org/projects/waitress/) (`pip install waitress`)
- [Cloudflare Tunnel](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/) (`cloudflared`) — apenas para acesso público

## Instalação

```bash
# Clonar repositório
git clone https://github.com/joaopascoalfariafeup/ucreports.git
cd ucreports

# Criar e ativar ambiente virtual
python3 -m venv .venv
source .venv/bin/activate        # Linux/macOS
# ou: .venv\Scripts\activate     # Windows

# Instalar dependências
pip install -r requirements.txt
```

## Configuração

Copiar o ficheiro de exemplo e preencher as variáveis:

```bash
cp .env.example .env   # (se disponível) ou criar .env manualmente
```

Variáveis obrigatórias no `.env`:

| Variável | Descrição |
|---|---|
| `WEB_SECRET_KEY` | Chave secreta Flask (gerar com `python -c "import secrets; print(secrets.token_urlsafe(64))"`) |
| `ANTHROPIC_API_KEY` | Chave API Anthropic (opcional, se usar Claude) |
| `OPENAI_API_KEY` | Chave API OpenAI (opcional, se usar GPT) |
| `IAEDU_API_KEY` | Chave API IAEDU (opcional, se usar provider gratuito institucional) |
| `WEB_THREADS` | Número de threads Waitress (default: `8`) |
| `WEB_MAX_USD_PER_USER_PER_MONTH` | Limite de custo mensal por utilizador em USD (default: `5`) |

Consultar [`.env`](.env) (não incluído no repositório) para a lista completa de variáveis.

## Arranque

### Linux / macOS / WSL

```bash
chmod +x arrancar.sh parar.sh

# Arrancar servidor + Cloudflare Tunnel
./arrancar.sh

# Arrancar só o servidor (sem tunnel)
./arrancar.sh --sem-tunnel

# Em WSL, forçar binários Linux em vez dos binários Windows
./arrancar.sh --native
```

### Windows (direto)

```bat
arrancar_publico_uc_reports.bat
```

### Parar os serviços

```bash
./parar.sh
```

Os logs ficam em `waitress.log` e `cloudflared.log`.

## Estrutura de ficheiros

```
ucreports/
├── app_web.py                        — aplicação Flask principal
├── auditoria_core.py                 — núcleo de análise
├── llm_analise.py                    — integração LLM
├── sigarra.py                        — integração SIGARRA
├── moodle.py                         — integração Moodle
├── logger.py                         — logging
├── prompts/
│   └── system_prompt.txt             — prompt de sistema para análise LLM
├── doc/                              — documentação de referência (não incluída no repo)
├── arrancar.sh                       — script de arranque (Linux/WSL)
├── parar.sh                          — script de paragem (Linux/WSL)
├── arrancar_publico_uc_reports.bat   — script de arranque (Windows)
├── requirements.txt                  — dependências Python
└── .env                              — configuração (não incluída no repo)
```

## Deployment em servidor Linux

Recomenda-se usar SSH + rsync ou git para transferir ficheiros para o servidor de produção:

```bash
# Transferir ficheiros (excluindo .env, output/, .venv/)
rsync -avz --exclude='.env' --exclude='output/' --exclude='.venv/' \
  ./ utilizador@servidor:/caminho/para/app/

# Ou clonar via git e configurar .env manualmente no servidor
git clone https://github.com/joaopascoalfariafeup/ucreports.git
```

No servidor, instalar cloudflared Linux seguindo as [instruções oficiais](https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/) e configurar `~/.cloudflared/config.yml` com o tunnel existente.

## Privacidade e RGPD

Os dados dos relatórios de UC enviados para análise são processados pelos fornecedores de LLM como subprocessadores:

- **Anthropic** — [Terms of Service](https://www.anthropic.com/legal/commercial-terms) · [DPA](https://privacy.anthropic.com/pt) · Retenção: 30 dias · Dados não usados para treino
- **OpenAI** — [API Data Usage](https://openai.com/policies/api-data-usage-policies) · [DPA](https://openai.com/policies/data-processing-addendum) · Retenção: 30 dias · Dados não usados para treino
- **IAEDU** — Serviço institucional da FCT/FCCN

A aplicação nunca armazena credenciais SIGARRA nem tokens de sessão em base de dados. No caso de autenticação federada (Shibboleth/SAML2), as credenciais transitam pelo servidor da aplicação (proxy HTTPS) antes de serem reencaminhadas para o Identity Provider da U.Porto (wayf.up.pt); não são guardadas em disco nem registadas em logs.

## Licença

Uso interno FEUP/U.Porto. Contactar os autores para outros usos.
