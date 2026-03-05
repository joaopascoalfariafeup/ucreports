"""
Script de teste local para extracção de páginas web de UCs.
Corre independentemente da app web.

Uso:
    python test_pagina_web.py
    python test_pagina_web.py --provider anthropic --modelo claude-sonnet-4-6
"""

import argparse
import os
import sys
from pathlib import Path

# Carregar variáveis de ambiente (.env e .env.public)
from sigarra import load_env
load_env()

from pagina_web_uc import extrair_pagina_web_uc

URLS_TESTE = [
    "https://sites.google.com/gcloud.fe.up.pt/io-legi",
    "https://sites.google.com/g.uporto.pt/projeto-integrador-leic/",
]

def main():
    parser = argparse.ArgumentParser(description="Teste de extracção de página web de UC")
    parser.add_argument("--provider", default="iaedu", help="Provider LLM (iaedu/openai/anthropic)")
    parser.add_argument("--modelo", default="gpt-4o", help="Modelo LLM")
    parser.add_argument("--url", help="URL específica a testar (omite as URLs padrão)")
    parser.add_argument("-v", "--verbosidade", type=int, default=2)
    args = parser.parse_args()

    urls = [args.url] if args.url else URLS_TESTE

    for url in urls:
        print(f"\n{'='*70}")
        print(f"URL: {url}")
        print(f"Provider: {args.provider} / Modelo: {args.modelo}")
        print('='*70)
        try:
            texto = extrair_pagina_web_uc(
                url,
                provider=args.provider,
                modelo=args.modelo,
                verbosidade=args.verbosidade,
            )
            print("\n--- Conteúdo extraído ---")
            # Mostrar até 4000 chars por bloco
            for bloco in texto.split("\n\n==="):
                print(f"\n==={bloco[:2000]}" if bloco else "")
                if len(bloco) > 2000:
                    print(f"  [... +{len(bloco)-2000} chars omitidos]")
        except Exception as e:
            print(f"ERRO: {e}")

if __name__ == "__main__":
    main()
