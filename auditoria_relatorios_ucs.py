"""CLI para auditoria de relatórios de UCs (SIGARRA)."""

import argparse
import sys
from pathlib import Path

from auditoria_core import analisar_uc, _SCRIPT_DIR
from logger import AuditoriaLogger
from sigarra import SigarraSession


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")

    parser = argparse.ArgumentParser(
        description="Auditoria de Relatórios de UCs (SIGARRA)")
    parser.add_argument(
        "ocorrencias", nargs="*",
        help="Códigos de ocorrência da UC")
    parser.add_argument(
        "-o", "--output", type=Path, default=None,
        help="Pasta de output (default: output/)")
    grupo_verb = parser.add_mutually_exclusive_group()
    grupo_verb.add_argument(
        "-q", "--quiet", action="store_true",
        help="Modo silencioso: apenas fases e avisos")
    grupo_verb.add_argument(
        "-v", "--verbose", action="store_true",
        help="Modo debug: inclui detalhes de prompts e resultados LLM")
    args = parser.parse_args()

    if not args.ocorrencias:
        parser.print_help()
        print("\nExemplo: python auditoria_relatorios_ucs.py 559654")
        print("         python auditoria_relatorios_ucs.py 559654 560305")
        print("         python auditoria_relatorios_ucs.py -q 559654")
        print("         python auditoria_relatorios_ucs.py -o resultados/ 559654")
        sys.exit(1)

    verbosidade = 1
    if args.quiet:
        verbosidade = 0
    elif args.verbose:
        verbosidade = 2

    output_dir = args.output or (_SCRIPT_DIR / "output")
    output_dir = output_dir.resolve()

    sessao = SigarraSession()
    sessao.autenticar()

    for oc_id in args.ocorrencias:
        log_path = output_dir / oc_id / "auditoria.log"
        with AuditoriaLogger(log_path, verbosidade=verbosidade) as log:
            analisar_uc(oc_id, sessao, log, output_dir=output_dir)
