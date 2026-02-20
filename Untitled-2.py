from __future__ import annotations

import argparse
import datetime as dt
from pathlib import Path
from typing import Optional


# =======================
#   LOGGER DE EVENTOS
# =======================

class EventLogger:
    """
    Logger simples de eventos em arquivo texto.

    Serve para simular o comportamento de um keylogger,
    MAS aqui os "eventos" são digitados explicitamente no programa.
    """

    def __init__(self, log_path: Path) -> None:
        self.log_path = log_path.resolve()
        self.log_path.parent.mkdir(parents=True, exist_ok=True)

    def log(self, event: str) -> None:
        """Registra uma linha no arquivo de log com timestamp UTC."""
        timestamp = dt.datetime.utcnow().isoformat()
        line = f"[{timestamp} UTC] {event}\n"
        try:
            with self.log_path.open("a", encoding="utf-8") as f:
                f.write(line)
        except OSError as exc:
            print(f"[ERRO] Falha ao gravar log em {self.log_path}: {exc}")

    def rotate(self, max_bytes: int = 1024 * 1024) -> Optional[Path]:
        """
        Faz rotação do arquivo se ele passar de max_bytes.
        Retorna o caminho do arquivo antigo, se houver rotação.
        """
        if not self.log_path.exists():
            return None

        try:
            size = self.log_path.stat().st_size
        except OSError:
            return None

        if size <= max_bytes:
            return None

        rotated = self.log_path.with_name(self.log_path.stem + ".old" + self.log_path.suffix)
        try:
            if rotated.exists():
                rotated.unlink()
            self.log_path.rename(rotated)
            return rotated
        except OSError as exc:
            print(f"[ERRO] Falha ao rotacionar log: {exc}")
            return None


# =======================
#   SIMULADOR DE KEYLOGGER
# =======================

DEFAULT_LOG_PATH = Path("./lab_keylogger/typed_events.log").resolve()


class KeyloggerSimulator:
    """
    Simulador de keylogger baseado em entrada explícita via terminal.

    Não captura teclas do sistema, apenas o que é digitado aqui.
    """

    def __init__(self, log_path: Path = DEFAULT_LOG_PATH) -> None:
        self.log_path = log_path.resolve()
        self.logger = EventLogger(self.log_path)

    def run(self) -> None:
        """Inicia o loop de captura de 'eventos'."""
        print("=== Simulador de Keylogger (modo seguro) ===")
        print("Tudo que você digitar abaixo será registrado no arquivo de log.")
        print("Comandos especiais:")
        print("  /sair  -> encerra o simulador")
        print("  /rotar -> força rotação do arquivo de log")
        print(f"Arquivo de log: {self.log_path}\n")

        while True:
            try:
                user_input = input("> ")
            except (EOFError, KeyboardInterrupt):
                print("\nEncerrando simulador...")
                break

            cmd = user_input.strip()

            if cmd == "/sair":
                print("Encerrando simulador...")
                break
            elif cmd == "/rotar":
                rotated = self.logger.rotate()
                if rotated:
                    print(f"Log rotacionado para: {rotated}")
                else:
                    print("Nenhuma rotação necessária (arquivo ainda pequeno).")
                continue
            else:
                # Simulando "teclas" sendo registradas
                self.logger.log(f"INPUT: {user_input!r}")
                print("(Evento registrado no log.)")


# =======================
#   CLI
# =======================

def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Simulador educacional de keylogger (modo seguro).\n"
            "Registra apenas aquilo que é digitado neste próprio terminal."
        )
    )
    parser.add_argument(
        "--log-path",
        type=Path,
        default=DEFAULT_LOG_PATH,
        help="Caminho do arquivo de log (padrão: ./lab_keylogger/typed_events.log)",
    )
    return parser


def main() -> None:
    parser = build_arg_parser()
    args = parser.parse_args()

    simulator = KeyloggerSimulator(log_path=args.log_path)
    simulator.run()


if __name__ == "__main__":
    main()