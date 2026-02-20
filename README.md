# Simulador-de-Ransomware-e-Keylogger-em-Python
Projeto desenvolvido para o desafio da formação DIO — Cybersecurity

Sobre o Projeto

Este repositório contém simulações educacionais de duas classes comuns de malware:

Ransomware → criptografa arquivos de teste em um diretório controlado.

Keylogger → registra entradas fornecidas explicitamente no terminal.

Exfiltração via E-mail → opcionalmente envia o arquivo de logs por SMTP.

Importante:

Este projeto é 100% seguro, executado apenas em ambiente controlado e sem nenhum comportamento malicioso real.

Ele serve para fins educacionais: entender como ameaças funcionam e como se defender.

Scripts Disponíveis

Script	Função	Tipo

| Script            | Função                             | Tipo                           |
| ----------------- | ---------------------------------- | ------------------------------ |
| **Untitled-1.py** | Simulador de Ransomware            | Criptografia/Descriptografia   |
| **Untitled-2.py** | Simulador de Keylogger             | Registro de eventos do usuário |
| **Untitled-3.py** | Envio automático de log por E-mail | Exfiltração simulada           |

1. Simulador de Ransomware (Untitled-1.py)

Este script:

✔ Cria um ambiente de laboratório com arquivos fictícios

✔ Gera e salva uma chave criptográfica

✔ Criptografa arquivos .txt e .md

✔ Cria uma ransom note simulada

✔ Descriptografa arquivos usando a chave correta

✔ Remove a ransom note automaticamente (após restore)

Comandos de Uso

Criar pasta e arquivos de teste:

& python "Untitled-1.py" --init-lab

Criptografar:

& python "Untitled-1.py" --encrypt

Descriptografar:

& python "Untitled-1.py" --decrypt

Os arquivos ficam dentro da pasta:

lab_ransomware/

2. Simulador de Keylogger (Untitled-2.py)

Este keylogger não captura teclas reais.
Ele só registra o que você digita dentro do próprio programa.

Executar:
& python "Untitled-2.py"

Comandos internos:

Digite qualquer coisa → será registrado no log

/rotar → força rotação de arquivo

/sair → encerra

Log salvo em:

lab_keylogger/typed_events.log

3. Envio de Log por E-mail (Untitled-3.py)

Simula exfiltração de dados via SMTP, anexando o arquivo typed_events.log.

Segurança Importante:

Não coloque senhas no código!

Use variável de ambiente: SMTP_PASSWORD

Antes de rodar:

$env:SMTP_PASSWORD = "SUA_SENHA_DE_APP"
Exemplo de execução:

& python "Untitled-3.py" `

  --log-path "lab_keylogger/typed_events.log" `
  
  --smtp-host smtp.seuprovedor.com `
  
  --smtp-port 587 `
  
  --username seu_email@provedor.com `
  
  --from-addr seu_email@provedor.com `
  
  --to-addr destino@provedor.com
  
Reflexão sobre Defesa e Prevenção

Este projeto simula comportamentos comuns usados por malwares reais. A seguir, medidas de defesa essenciais contra ransomware, keyloggers e exfiltração de dados:

1. Contra Ransomware
2. 
✔ Backups regulares

3-2-1 backup rule: 3 cópias, 2 mídias diferentes, 1 off-site.

✔ Atualização e correções

Corrigir vulnerabilidades exploradas por ransomware modernos.

✔ Antivírus + Antimalware atualizado

Com heurística e detecção comportamental.

✔ Princípio do menor privilégio

Usuários comuns não devem ter direitos administrativos.

✔ Isolamento / Sandboxing

Testes em ambientes seguros (como este laboratório educacional).

2. Contra Keyloggers

✔ Antivírus com detecção heurística

✔ Bloquear instalação de software não autorizado

✔ Hardening do sistema

✔ Evitar abrir anexos suspeitos

✔ Usar Autenticação Multi-Fator (MFA)

3. Contra Exfiltração / Vazamento de Dados

✔ Monitoramento de tráfego de rede (IDS/IPS)

✔ DLP — Data Loss Prevention

✔ Filtragem de SMTP, bloqueio de portas inseguras

✔ Criptografia fim-a-fim

✔ Treinamento de conscientização de usuários
