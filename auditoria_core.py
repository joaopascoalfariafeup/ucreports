"""
Auditoria de Relatórios de Unidades Curriculares (UCs) - SIGARRA, Universidade do Porto.

Extrai informação das fichas de UC do SIGARRA e do Moodle, analisa com LLM (Claude)
e preenche automaticamente o relatório da UC.
"""

import hashlib
import json
import os
import re
from pathlib import Path

from sigarra import (
    SigarraSession, SIGARRA_BASE, extrair_ficha_uc, extrair_sumarios,
    extrair_resultados_uc, extrair_resultados_curso,
    extrair_enunciados_avaliacao,
    submeter_enunciados_sigarra,
    inferir_epoca_enunciado,
    extrair_ocorrencia_anterior,
    extrair_inquerito_pedagogico, extrair_comentarios_inquerito,
    extrair_form_relatorio, submeter_relatorio,
    calcular_horas_relatorio,
)
from moodle import extrair_enunciados_moodle, extrair_moodle_uc
from llm_analise import analisar_uc_integrado
from logger import AuditoriaLogger

_SCRIPT_DIR = Path(__file__).resolve().parent


def _normalizar_nome_enunciado(nome: str) -> str:
    """Normaliza nome de ficheiro para comparação fuzzy de duplicados."""
    nome = os.path.splitext(nome)[0]          # remove extensão
    nome = nome.lower()
    nome = re.sub(r'\s*\(\d+\)\s*$', '', nome)   # remove (1), (2), …
    nome = re.sub(r'[-_\s]v\d+\s*$', '', nome)   # remove -v2, _v2, v2
    nome = re.sub(r'[^a-z0-9]', '', nome)         # só alfanuméricos
    return nome


def _processar_enunciados_moodle_bloco(
    bloco_texto: str,
    enunciados: list[dict],
    log: AuditoriaLogger,
) -> list[dict]:
    """Processa o bloco de classificação de enunciados Moodle do LLM."""
    if not bloco_texto or not enunciados:
        return []

    nomes_sigarra = {
        e["nome"].lower() for e in enunciados if e.get("origem") == "SIGARRA"
    }

    log.info("\n--- Classificação LLM dos enunciados Moodle ---")
    novos_avaliacao = []
    for linha in bloco_texto.strip().splitlines():
        linha = linha.strip().lstrip("- ")
        if not linha:
            continue
        if "AVALIAÇÃO" in linha.upper() and "NÃO_AVALIAÇÃO" not in linha.upper():
            nome_fich = linha.split(":")[0].strip()
            if nome_fich.lower() in nomes_sigarra:
                log.info(f"  [JÁ NO SIGARRA] {linha}")
            else:
                novos_avaliacao.append(nome_fich)
                log.info(f"  [AVALIAÇÃO]      {linha}")
        elif "NÃO_AVALIAÇÃO" in linha.upper():
            log.info(f"  [NÃO AVALIAÇÃO]  {linha}")
        else:
            log.info(f"  [?]              {linha}")

    enunciados_para_upload = []
    if novos_avaliacao:
        log.info(f"  {len(novos_avaliacao)} enunciado(s) novo(s) do Moodle para upload")
        nomes_novos = {n.lower() for n in novos_avaliacao}
        enunciados_para_upload = [
            e for e in enunciados
            if e.get("origem", "").startswith("Moodle")
            and e["nome"].lower() in nomes_novos
        ]

    return enunciados_para_upload


def _anexar_enunciados_ao_form(campos: dict, enunciados_carregados: list[dict]) -> None:
    """Anexa enunciados carregados no sandbox aos campos do formulário."""
    if not enunciados_carregados:
        return

    ids_existentes = campos.get("parr_aval_gdoc_id", [])
    desc_existentes = campos.get("parr_aval_descricao", [])
    epoca_existentes = campos.get("parr_aval_epoca", [])
    if not isinstance(ids_existentes, list):
        ids_existentes = [ids_existentes] if ids_existentes else []
    if not isinstance(desc_existentes, list):
        desc_existentes = [desc_existentes] if desc_existentes else []
    if not isinstance(epoca_existentes, list):
        epoca_existentes = [epoca_existentes] if epoca_existentes else []

    for ec in enunciados_carregados:
        ids_existentes.append(ec["gdoc_id"])
        desc_existentes.append(ec["descricao"])
        epoca_existentes.append(ec["epoca"])

    campos["parr_aval_gdoc_id"] = ids_existentes
    campos["parr_aval_descricao"] = desc_existentes
    campos["parr_aval_epoca"] = epoca_existentes


def _submeter_campos_relatorio(
    sessao: SigarraSession,
    oc_id: str,
    pasta_uc: Path,
    log: AuditoriaLogger,
    campos: dict,
    enunciados_para_upload: list[dict],
) -> bool:
    """Executa upload de enunciados (se existir) e submete o relatório."""
    enunciados_carregados = []
    if enunciados_para_upload:
        n = len(enunciados_para_upload)
        log.iniciar_fase("enunciados", f"A carregar {n} enunciado(s) no SIGARRA...")
        try:
            enunciados_carregados = submeter_enunciados_sigarra(
                sessao, oc_id, enunciados_para_upload,
            )
            log.concluir_fase("enunciados", f"{len(enunciados_carregados)}/{n} enunciado(s) carregado(s)")
        except (PermissionError, ConnectionError) as e:
            log.concluir_fase("enunciados", f"Erro no upload: {e}", ok=False)

    if enunciados_carregados:
        _anexar_enunciados_ao_form(campos, enunciados_carregados)

    log.iniciar_fase("relatorio", "A submeter relatório no SIGARRA...")
    try:
        result = submeter_relatorio(
            sessao,
            campos,
            ocorrencia_id=oc_id,
            output_dir=pasta_uc,
        )
        log.concluir_fase("relatorio", "Relatório submetido com sucesso!")
        return result
    except (ValueError, ConnectionError) as e:
        log.concluir_fase("relatorio", f"Submissão rejeitada: {e}", ok=False)
        raise


def submeter_preview_uc(
    oc_id: str,
    sessao: SigarraSession,
    log: AuditoriaLogger,
    output_dir: Path = _SCRIPT_DIR / "output",
    run_dir: Path | None = None,
) -> bool:
    """Submete no SIGARRA um preview previamente preparado para a UC."""
    pasta_uc = run_dir if run_dir is not None else (output_dir / oc_id)
    preview_path = pasta_uc / "preview_payload.json"
    if not preview_path.is_file():
        raise ValueError(f"Preview não encontrado: {preview_path}")

    payload = json.loads(preview_path.read_text(encoding="utf-8"))
    campos = payload.get("campos", {})
    enunciados_refs = payload.get("enunciados_para_upload", [])

    enunciados_para_upload = []
    for ref in enunciados_refs:
        nome = str(ref.get("nome", "")).strip()
        if not nome:
            continue
        caminho = pasta_uc / nome
        if not caminho.is_file():
            log.aviso(f"  Enunciado para upload não encontrado em disco: {nome}")
            continue
        enunciados_para_upload.append({
            "nome": nome,
            "descricao": ref.get("descricao", nome),
            "pdf_bytes": caminho.read_bytes(),
        })

    _submeter_campos_relatorio(
        sessao=sessao,
        oc_id=oc_id,
        pasta_uc=pasta_uc,
        log=log,
        campos=campos,
        enunciados_para_upload=enunciados_para_upload,
    )
    return True


def analisar_uc(
    oc_id: str,
    sessao: SigarraSession,
    log: AuditoriaLogger,
    output_dir: Path = _SCRIPT_DIR / "output",
    submeter: bool = True,
    run_dir: Path | None = None,
    llm_provider: str = "",
    llm_modelo: str = "",
    llm_modelo_condensacao: str = "",
) -> Path:
    """Executa a auditoria completa de uma UC.

    Args:
        oc_id: Código da ocorrência da UC.
        sessao: Sessão SIGARRA autenticada.
        log: Logger para mensagens e metadata.
        output_dir: Pasta base de output.
    """
    pasta_uc = run_dir if run_dir is not None else (output_dir / oc_id)
    pasta_uc.mkdir(parents=True, exist_ok=True)

    log.cabecalho(oc_id, usuario=sessao.codigo_pessoal)

    # ================================================================
    # FASE 1: Extração de dados
    # ================================================================

    # --- Ficha da UC ---
    log.iniciar_fase("ficha", "Extrair ficha da UC...")
    ficha = extrair_ficha_uc(oc_id, sessao)

    # extrair ano letivo da ficha
    ano_letivo_corrente = ficha.get("ano_letivo", "")
    prev_oc_id = None
    prev_ano_letivo = None
    if ficha.get("ucurr_id"):
        prev = extrair_ocorrencia_anterior(oc_id, ficha["ucurr_id"], sessao)
        if prev:
            prev_oc_id, prev_ano_letivo = prev
    if prev_oc_id:
        ficha_msg = f"2 fichas extraídas: ocorrências {ano_letivo_corrente} e {prev_ano_letivo}"
    else:
        ficha_msg = f"1 ficha extraída: ocorrência {ano_letivo_corrente}, sem ocorrência anterior identificada"
    log.concluir_fase("ficha", ficha_msg)

    log.info(f"\n--- Programa ---\n")
    log.info(ficha["programa"])
    log.info(f"\n--- Objetivos ---\n")
    log.info(ficha["objetivos"])
    log.info(f"\n--- Resultados de Aprendizagem e Competências ---\n")
    log.info(ficha["resultados_aprendizagem"])

    # --- Sumários ---
    log.iniciar_fase("sumarios", "Extrair sumários...")
    sums = extrair_sumarios(oc_id, sessao, log._verbosidade)
    turmas = {s["turma"] for s in sums}
    log.concluir_fase("sumarios", f"{len(sums)} sumários extraídos" + (f" de {len(turmas)} turma(s)" if turmas else ""))

    if not sums:
        log.aviso("  Nenhum sumário encontrado.")
    else:
        turma_atual = ""
        for s in sums:
            if s["turma"] != turma_atual:
                turma_atual = s["turma"]
                log.info(f"\n--- Turma {turma_atual} ({s['tipo_aula']}) ---\n")
            log.info(f"  Aula {s['numero']:2d} [{s['data']}]: {s['sumario']}")

    # --- Conteúdos do Moodle ---
    conteudos_moodle = None
    moodle_url = ficha.get("moodle_url")
    _urls_moodle = ([moodle_url] if moodle_url else [])
    if sessao.codigo_pessoal:
        # Portais como fallback: ano corrente e depois ano anterior
        _urls_moodle += [
            f"{SIGARRA_BASE}/moodle_portal.go_moodle_portal_up?p_codigo={sessao.codigo_pessoal}",
            f"{SIGARRA_BASE}/moodle_portal.go_moodle_portal?p_codigo={sessao.codigo_pessoal}",
        ]
    if _urls_moodle:
        log.iniciar_fase("moodle", "Extrair conteúdos do Moodle...")
        _moodle_erro = None
        for _url in _urls_moodle:
            log.info(f"  Link Moodle: {_url}")
            try:
                conteudos_moodle = extrair_moodle_uc(
                    _url, sessao,
                    sigla_uc=ficha.get("sigla_uc", ""),
                    nome_uc=ficha.get("nome_uc", ""),
                    ano_letivo_ocorrencia=ficha.get("ano_letivo", ""),
                    verbosidade=log._verbosidade,
                    log=log,
                )
                if conteudos_moodle:
                    break
                if len(_urls_moodle) > 1 and _url is not _urls_moodle[-1]:
                    log.info("  UC não encontrada, a tentar portal do ano anterior...")
            except PermissionError as e:
                _moodle_erro = e
                if _url is not _urls_moodle[-1]:
                    log.info(f"  Sem acesso ({e}), a tentar portal do ano anterior...")
            except ConnectionError as e:
                _moodle_erro = e
                break  # erro de rede — não adianta tentar o próximo
        if conteudos_moodle:
            n_atividades = sum(
                len(sec.get("atividades", []))
                for sec in conteudos_moodle["seccoes"]
            )
            log.concluir_fase("moodle", f"Moodle: {n_atividades} atividades em {len(conteudos_moodle['seccoes'])} secções")
            for sec in conteudos_moodle["seccoes"]:
                log.info(f"\n  --- {sec['nome'] or '(sem nome)'} ---")
                for act in sec.get("atividades", []):
                    log.info(f"    [{act['tipo']}] {act['nome']}")
        elif _moodle_erro:
            log.concluir_fase("moodle", f"Moodle: erro ({_moodle_erro})", ok=False)
        else:
            log.concluir_fase("moodle", "Moodle: sem acesso", ok=False)

    # --- Enunciados de avaliação ---
    log.iniciar_fase("enunciados", "Extrair enunciados de elementos de avaliação...")
    log.info(f"  Tipo de avaliação: {ficha.get('tipo_avaliacao', '?')}")
    componentes = ficha.get("componentes_avaliacao", [])
    if componentes:
        log.info("  Componentes de avaliação:")
        for c in componentes:
            log.info(f"    - {c['designacao']}: {c['peso']:.1f}%")

    try:
        enunciados = extrair_enunciados_avaliacao(oc_id, sessao, log._verbosidade, logger=log)
    except (ValueError, PermissionError) as e:
        log.aviso(f"  Aviso: {e}")
        enunciados = []

    n_sigarra = len(enunciados)
    n_moodle = 0
    if conteudos_moodle:
        log.info(f"  A extrair enunciados do Moodle...")
        try:
            enunciados_moodle = extrair_enunciados_moodle(conteudos_moodle, sessao, log._verbosidade, output_dir=pasta_uc, log=log)
            if enunciados_moodle:
                n_moodle = len(enunciados_moodle)
                enunciados.extend(enunciados_moodle)
        except (PermissionError, ConnectionError) as e:
            log.aviso(f"  Aviso Moodle: {e}")

    # Deduplicar por hash de conteúdo e nome
    n_dups = 0
    if len(enunciados) > 1:
        vistos_hash: set[str] = set()
        vistos_nome: set[str] = set()
        unicos = []
        for e in enunciados:
            h = hashlib.md5(e["pdf_bytes"]).hexdigest()
            nome_norm = _normalizar_nome_enunciado(e["nome"])
            if h in vistos_hash:
                log.info(f"  [DUP conteúdo] {e['nome']} ({e.get('origem','?')}) — ignorado")
                continue
            if nome_norm in vistos_nome:
                log.info(f"  [DUP nome] {e['nome']} ({e.get('origem','?')}) — nome similar, provável variação de metadados PDF, ignorado")
                continue
            vistos_hash.add(h)
            vistos_nome.add(nome_norm)
            unicos.append(e)
        n_dups = len(enunciados) - len(unicos)
        enunciados = unicos

    # Resumo
    partes_orig = []
    if n_sigarra:
        partes_orig.append(f"{n_sigarra} SIGARRA")
    if n_moodle:
        partes_orig.append(f"{n_moodle} Moodle")
    resumo_orig = f" ({', '.join(partes_orig)})" if partes_orig else ""
    dups_info = f", {n_dups} duplicado(s)" if n_dups else ""
    log.concluir_fase("enunciados", f"{len(enunciados)} enunciado(s) extraído(s){resumo_orig}{dups_info}")

    if enunciados:
        for e in enunciados:
            tamanho_kb = len(e["pdf_bytes"]) / 1024
            origem = e.get("origem", "?")
            log.info(f"    - {e['nome']} ({e['descricao']}) [{tamanho_kb:.0f} KB] [{origem}]")
            caminho = pasta_uc / e["nome"]
            caminho.write_bytes(e["pdf_bytes"])
        log.debug(f"  Enunciados guardados em: {pasta_uc}")

    # --- Resultados de Avaliação ---
    resultados_atual = None
    resultados_anterior = None
    pares_curso = None
    log.iniciar_fase("resultados", "Extrair resultados de avaliação...")
    resumo_resultados = "Resultados indisponíveis"
    resultados_ok = False
    try:
        resultados_atual = extrair_resultados_uc(oc_id, sessao)

        resumo = resultados_atual.get("resumo", {})
        estat = resultados_atual.get("estatisticas", {})
        taxa = resumo.get("racio_aprovados_inscritos", "?")
        media = estat.get("media", "?")
        resumo_resultados = (
            f"Resultados: {resumo.get('inscritos', '?')} inscritos, {taxa}% aprovados, média {media}"
        )
        resultados_ok = True

        log.info(f"  Avaliados: {resumo.get('avaliados', '?')}")
        log.info(f"  Aprovados: {resumo.get('aprovados_total', '?')}")
        log.info(f"  Mediana aprovados: {estat.get('mediana', '?')}")

        if prev_oc_id:
            log.info(f"\n  A extrair resultados do ano anterior ({prev_ano_letivo})...")
            try:
                resultados_anterior = extrair_resultados_uc(prev_oc_id, sessao)
                res_ant = resultados_anterior.get("resumo", {})
                log.info(f"  Ano anterior: {res_ant.get('racio_aprovados_inscritos', '?')}% aprovados")
            except (ValueError, PermissionError) as e:
                log.aviso(f"Aviso: Resultados da ocorrência anterior indisponíveis")

        ident = resultados_atual.get("identificacao", {})
        curso_id = ident.get("curso_id")
        ano_letivo_num = ident.get("ano_letivo_num")
        ano_curr = ident.get("ano_curricular", "")
        if curso_id and ano_letivo_num:
            log.info(f"\n  A extrair resultados das UCs do curso...")
            try:
                todas_ucs = extrair_resultados_curso(curso_id, ano_letivo_num, sessao)
                pares_curso = [
                    uc for uc in todas_ucs
                    if uc.get("media_aprovados") is not None
                    and ano_curr in uc.get("ano_curricular", "")
                ]
                log.info(f"  {len(pares_curso)} UCs do {ano_curr} ano com resultados")
            except (ValueError, PermissionError) as e:
                log.aviso(f"Aviso: Resultados do curso indisponíveis")

    except ValueError as e:
        log.aviso(f"Resultados: indisponíveis ({e})")
    except PermissionError as e:
        log.erro(f"Resultados: erro de autenticação ({e})")

    log.concluir_fase("resultados", resumo_resultados, ok=resultados_ok)

    # --- Inquéritos Pedagógicos ---
    inq = None
    inq_anterior = None
    comentarios = None
    log.iniciar_fase("inquerito", "Extrair resultados de inquéritos pedagógicos...")
    resumo_inqueritos = "Inquéritos: indisponíveis"
    inqueritos_ok = False
    try:
        inq = extrair_inquerito_pedagogico(oc_id, sessao)

        medias_perguntas = [p["media"] for p in inq["perguntas"] if p["media"] > 0]
        media_global = sum(medias_perguntas) / len(medias_perguntas) if medias_perguntas else 0.0
        resumo_inqueritos = (
            f"Inquéritos: {inq['taxa_resposta']}% respostas "
            f"({inq['n_respondidos']}/{inq['n_questionarios']}), "
            f"média {media_global:.1f}/7"
        )
        inqueritos_ok = True

        log.info(f"\n  {'Pergunta':<70s}  {'Dimensão':<25s}  {'μ':>5s}  {'Md':>5s}  {'σ':>5s}")
        log.info(f"  {'-' * 135}")
        for p in inq["perguntas"]:
            pergunta = p["pergunta"][:70]
            log.info(
                f"  {pergunta:<70s}  {p['dimensao']:<25s}"
                f"  {p['media']:5.2f}  {p['mediana']:5.1f}  {p['dp']:5.2f}"
            )

        ano_letivo_str = inq.get("identificacao", {}).get("ano_letivo", "")
        if ano_letivo_str:
            ano_civil = ano_letivo_str.split("/")[0]
            log.info(f"\n  A descarregar comentários do inquérito (ano {ano_civil})...")
            comentarios = extrair_comentarios_inquerito(oc_id, ano_civil, sessao)
            if comentarios:
                log.info(f"  Comentários descarregados ({len(comentarios) / 1024:.0f} KB)")
            else:
                log.info("  Nenhum comentário disponível.")

        if prev_oc_id:
            log.info(f"\n  A extrair inquérito do ano anterior ({prev_ano_letivo})...")
            try:
                inq_anterior = extrair_inquerito_pedagogico(prev_oc_id, sessao)
                log.info(f"  Ano anterior: {inq_anterior['taxa_resposta']}% taxa de resposta")
            except (ValueError, PermissionError) as e:
                log.aviso(f"Aviso: Inquéritos da ocorrência anterior indisponíveis")

    except ValueError as e:
        resumo_inqueritos = f"Inquéritos: indisponíveis"
    except PermissionError as e:
        resumo_inqueritos = f"Inquéritos: erro de autenticação ({e})"

    log.concluir_fase("inquerito", resumo_inqueritos, ok=inqueritos_ok)

    # ================================================================
    # FASE 2: Análise LLM
    # ================================================================

    enunciados_para_upload = []
    provider_llm = (llm_provider or os.environ.get("LLM_PROVIDER", "anthropic")).strip().lower()
    modelo_llm = (llm_modelo or os.environ.get("LLM_MODELO_ANALISE", "").strip() or "claude-opus-4-6")
    log.iniciar_fase("llm", f"Analisar UC com {provider_llm}/{modelo_llm}...")

    resultado_int = analisar_uc_integrado(
        ficha=ficha,
        sumarios=sums,
        conteudos_moodle=conteudos_moodle,
        enunciados=enunciados or None,
        resultados_atual=resultados_atual,
        resultados_anterior=resultados_anterior,
        pares_curso=pares_curso,
        inq=inq,
        inq_anterior=inq_anterior,
        comentarios_bytes=comentarios,
        ocorrencia_id=pasta_uc.name,
        output_dir=pasta_uc.parent,
        logger=log,
        provider=provider_llm,
        modelo=modelo_llm,
        modelo_condensacao=llm_modelo_condensacao,
    )

    resultados_texto = resultado_int["resultados"]
    funcionamento_texto = resultado_int["funcionamento"]
    programa_efetivo = resultado_int["programa_efetivo"]
    custo_estimado = resultado_int["custo_estimado"]

    resumo_llm = (
        f"Análise concluída (programa: {len(programa_efetivo)} chars, "
        f"resultados: {len(resultados_texto)} chars, "
        f"funcionamento: {len(funcionamento_texto)} chars)"
    )
    if custo_estimado is not None:
        resumo_llm += f" [~${custo_estimado:.3f}]"
    log.concluir_fase("llm", resumo_llm)

    log.info(f"\n--- Resultados da UC ---\n")
    log.info(resultados_texto)
    log.info(f"\n--- Funcionamento da UC ---\n")
    log.info(funcionamento_texto)

    # Processar classificação de enunciados Moodle
    enunciados_moodle_bloco = resultado_int.get("enunciados_moodle_bloco", "")
    if enunciados_moodle_bloco:
        enunciados_para_upload = _processar_enunciados_moodle_bloco(
            enunciados_moodle_bloco, enunciados, log,
        )

    
    # ================================================================
    # FASE 3: Preparação do Relatório (preview + submissão opcional)
    # ================================================================

    log.iniciar_fase("relatorio", "Preparar relatório...")

    # Extrair formulário e preencher campos
    log.info("  A extrair formulário do relatório...")
    try:
        campos = extrair_form_relatorio(
            oc_id,
            sessao,
            output_dir=pasta_uc,
            verbosidade=log._verbosidade,
        )

        # Calcular horas previstas e efetivas
        log.info("  A calcular horas previstas e efetivas...")
        calcular_horas_relatorio(campos, sums)

        # Programa efetivamente lecionado
        if programa_efetivo:
            campos["pv_rel_programa"] = programa_efetivo
            log.info(f"  Programa efetivo preenchido ({len(programa_efetivo)} chars)")

        # Comentários - resultados
        campos["pv_rel_coment_res"] = resultados_texto 

        # Comentários - funcionamento 
        campos["pv_rel_coment_func"] = funcionamento_texto 

        preview_payload = {
            "ocorrencia_id": oc_id,
            "nome_uc": ficha.get("nome_uc", ""),
            "programa_efetivo": programa_efetivo or "",
            "comentarios_resultados": campos.get("pv_rel_coment_res", ""),
            "comentarios_funcionamento": campos.get("pv_rel_coment_func", ""),
            "campos": campos,
            "enunciados_para_upload": [
                {
                    "nome": e.get("nome", ""),
                    "descricao": e.get("descricao", e.get("nome", "")),
                    "epoca": (
                        str(e.get("epoca", "")).strip()
                        or inferir_epoca_enunciado(str(e.get("nome", "")))
                    ),
                }
                for e in enunciados_para_upload
            ],
        }
        preview_path = pasta_uc / "preview_payload.json"
        # Escrita atómica: write+rename para evitar leituras parciais
        preview_tmp = preview_path.with_suffix(".tmp")
        preview_tmp.write_text(
            json.dumps(preview_payload, ensure_ascii=False, indent=2),
            encoding="utf-8",
        )
        preview_tmp.replace(preview_path)
        log.info(f"  Preview guardado em: {preview_path}")

        if not submeter:
            log.concluir_fase("relatorio", "Relatório pronto (sem submissão)")
            return pasta_uc

        ok = _submeter_campos_relatorio(
            sessao=sessao,
            oc_id=oc_id,
            pasta_uc=pasta_uc,
            log=log,
            campos=campos,
            enunciados_para_upload=enunciados_para_upload,
        )
        if ok:
            log.concluir_fase("relatorio", "Relatório submetido com sucesso!")
        else:
            log.concluir_fase("relatorio", "AVISO: A submissão pode não ter sido bem-sucedida.", ok=False)

    except (ValueError, PermissionError) as e:
        log.erro(f"  Erro ao preencher relatório: {e}")
        log.concluir_fase("relatorio", "Preenchimento do relatório falhou.", ok=False)

    return pasta_uc


















