"""Módulo de logging para auditoria de UCs.

Fornece um logger dual (terminal + ficheiro) com controlo de verbosidade
e registo de metadata para controlo de custos LLM.
"""

import time
from datetime import datetime
from pathlib import Path



class AuditoriaLogger:
    """Logger com escrita dual (terminal + ficheiro) e controlo de verbosidade.

    Níveis de importância (do mais ao menos importante):
        PHASE   (0) - início/conclusão de fase (sempre visível)
        ERROR   (1) - erros (sempre visível)
        WARNING (2) - avisos (visível com V>=1))
        INFO    (3) - detalhes (visível com V>=1)
        DEBUG   (4) - debug (visível com V>=2)

    Tudo é sempre escrito no ficheiro de log, independentemente da verbosidade.
    """

    PHASE = 0
    ERROR = 1
    WARNING = 2
    INFO = 3
    DEBUG = 4

    _PREFIXOS = {0: "FASE", 1: "ERRO", 2: "AVIS", 3: "INFO", 4: "DEBG"}

    def __init__(self, log_path: Path, verbosidade: int = 1):
        self._log_path = log_path
        log_path.parent.mkdir(parents=True, exist_ok=True)
        self._log_file = open(log_path, "w", encoding="utf-8")
        self._verbosidade = verbosidade

        # Nível máximo mostrado no terminal:
        #   V=0 → PHASE + ERROR + WARNING
        #   V=1 → + INFO
        #   V=2 → + DEBUG
        self._terminal_max = {0: self.ERROR, 1: self.INFO, 2: self.DEBUG}.get(
            verbosidade, self.INFO
        )

        self._fase_inicio: dict[str, float] = {}
        self._llm_calls: list[dict] = []
        self._t0_global = time.monotonic()

    # --- Logging base ---

    def log(self, msg: str, nivel: int = INFO) -> None:
        """Regista uma mensagem com o nível de importância indicado."""
        ts = datetime.now().strftime("%H:%M:%S.%f")[:-3]
        prefixo = self._PREFIXOS.get(nivel, "????")
        linha_log = f"[{ts}] [{prefixo}] {msg}"

        self._log_file.write(linha_log + "\n")
        self._log_file.flush()

        if nivel <= self._terminal_max:
            try:
                print(msg)
            except UnicodeEncodeError:
                print(msg.encode("ascii", errors="replace").decode("ascii"))

    def fase(self, msg: str) -> None:
        """Mensagem de início/conclusão de fase (sempre visível)."""
        self.log(msg, self.PHASE)

    def erro(self, msg: str) -> None:
        """Mensagem de erro (sempre visível)."""
        self.log(msg, self.ERROR)

    def aviso(self, msg: str) -> None:
        """Mensagem de aviso (visível com V>=1)."""
        txt = msg.removeprefix("Aviso: ")
        self.log(f"  ⚠ {txt}", self.WARNING)

    def info(self, msg: str) -> None:
        """Mensagem informativa (visível com V>=1)."""
        self.log(msg, self.INFO)

    def debug(self, msg: str) -> None:
        """Mensagem de debug (visível com V>=2)."""
        self.log(msg, self.DEBUG)

    # --- Controlo de fases (timing) ---

    def iniciar_fase(self, nome: str, msg: str = "") -> None:
        """Regista o início de uma fase e guarda o timestamp."""
        self._fase_inicio[nome] = time.monotonic()
        self.fase(f"▸ {msg or f'Início: {nome}'}")

    def concluir_fase(self, nome: str, msg: str = "", ok: bool = True) -> float:
        """Regista a conclusão de uma fase e devolve a duração em segundos."""
        t0 = self._fase_inicio.pop(nome, None)
        duracao = time.monotonic() - t0 if t0 is not None else 0.0
        texto = msg or f"Concluído: {nome}"
        icone = "✓" if ok else "✗"
        self.fase(f"  {icone} {texto}  [{duracao:.1f}s]")
        return duracao

    # --- Metadata LLM ---

    def registar_llm(
        self,
        modelo: str,
        input_tokens: int,
        output_tokens: int,
        duracao: float,
        custo: float | None = None,
    ) -> None:
        """Regista metadata de uma chamada LLM (tokens, tempo, custo estimado)."""
        
        entry = {
            "timestamp": datetime.now().isoformat(),
            "modelo": modelo,
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "duracao_s": round(duracao, 2),
            "custo_usd": round(custo, 6) if custo is not None else None,
        }
        self._llm_calls.append(entry)

        total = input_tokens + output_tokens
        custo_str = f", ~${custo:.4f}" if custo is not None else ""
        self.info(
            f"  LLM: {modelo} | {input_tokens}+{output_tokens}={total} tokens"
            f" | {duracao:.1f}s{custo_str}"
        )

    # --- Cabeçalho e sumário ---

    def cabecalho(self, oc_id: str, usuario: str = "") -> None:
        """Escreve cabeçalho no log com metadata da execução."""
        self._log_file.write(f"# Auditoria UC — ocorrência {oc_id}\n")
        self._log_file.write(f"# Data: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        if usuario:
            self._log_file.write(f"# Utilizador: {usuario}\n")
        self._log_file.write(f"# Verbosidade: {self._verbosidade}\n")
        self._log_file.write(f"# Log: {self._log_path}\n")
        self._log_file.write("\n")
        self._log_file.flush()

    def sumario(self) -> str:
        """Produz um sumário das chamadas LLM (tokens, tempo, custo)."""
        if not self._llm_calls:
            return ""

        total_input = sum(c["input_tokens"] for c in self._llm_calls)
        total_output = sum(c["output_tokens"] for c in self._llm_calls)
        total_duracao = sum(c["duracao_s"] for c in self._llm_calls)
        custos = [c["custo_usd"] for c in self._llm_calls if c["custo_usd"] is not None]
        total_custo = sum(custos) if custos else None
        modelos = {c["modelo"] for c in self._llm_calls}

        duracao_total = time.monotonic() - self._t0_global

        linhas = [
            "\n--- Sumário ---",
            f"Chamadas LLM: {len(self._llm_calls)}",
            f"Modelo(s): {', '.join(sorted(modelos))}",
            f"Tokens: {total_input} input + {total_output} output"
            f" = {total_input + total_output} total",
            f"Tempo LLM: {total_duracao:.1f}s",
        ]
        if total_custo is not None:
            linhas.append(f"Custo estimado: ${total_custo:.4f}")
        linhas.append(f"Tempo total: {duracao_total:.1f}s")

        return "\n".join(linhas) + "\n"

    def total_custo_estimado(self) -> float | None:
        """Devolve o custo total estimado (USD) das chamadas LLM desta execução."""
        if not self._llm_calls:
            return None
        custos = [c["custo_usd"] for c in self._llm_calls if c.get("custo_usd") is not None]
        if not custos:
            return None
        return float(sum(custos))

    # --- Ciclo de vida ---

    def fechar(self) -> None:
        """Escreve o sumário final e fecha o ficheiro de log."""
        texto_sumario = self.sumario()
        if texto_sumario:
            self._log_file.write(texto_sumario)
            # Também mostrar sumário no terminal (nível PHASE)
            for linha in texto_sumario.strip().splitlines():
                self.fase(linha)
        self._log_file.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.fechar()
