# Network Vulnerability Scanner

A comprehensive network reconnaissance tool written in Python. This project offers two modes of operation: a graphical user interface (GUI) for desktop usage and a high-performance command-line interface (CLI) for servers and quick auditing.

The tool performs multi-threaded port scanning, DNS resolution, service banner grabbing, and automated risk assessment based on common vulnerability signatures.

## Features

### Core Capabilities
- **Multi-threaded Architecture:** High-speed scanning using `concurrent.futures`.
- **Risk Assessment:** Automatic detection of potential vulnerabilities (e.g., cleartext protocols like Telnet/FTP, known ransomware vectors like SMB).
- **Service Enumeration:** Captures service banners (HEAD requests) to identify running applications.
- **Reporting:** Exports results to structured JSON files (`scan_<IP>.json`).

### Interface Modes
- **GUI Version:** Modern interface built with `customtkinter`. Features dark mode, real-time logging, thread control slider, and non-blocking execution.
- **CLI Version:** Lightweight interactive command-line interface, ideal for headless servers (VPS) or quick diagnostics.

## Prerequisites

- **OS:** Windows, Linux, or macOS.
- **Python:** Version 3.10, 3.11, or 3.12.
- **Network:** Active internet connection to the target host.

## Installation

1. Clone the repository:
   ```bash
   git clone [https://github.com/SEU_USUARIO/port-scanner-python.git](https://github.com/SEU_USUARIO/port-scanner-python.git)
   cd port-scanner-python
   ```

2. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

### Option 1: GUI Version (Recommended)
For a visual experience with interactive controls and real-time feedback:

```bash
python portscan_gui.py
```
* Enter the Target IP/Hostname.
* Adjust the "Threads" slider to set scan speed.
* Click **INICIAR SCAN**.

### Option 2: CLI Version (Terminal)
For server environments or script integration:

```bash
python portscan.py
```
Follow the interactive prompts for Target, Port Range, Threads, and Timeout.

## Output
Regardless of the version used, if open ports are detected, a report file will be generated in the root directory:
`scan_<TARGET_IP>.json`

## Disclaimer

This tool is intended for **educational purposes and authorized security auditing only**. The author is not responsible for any misuse or damage caused by this program. Scanning networks without permission is illegal in many jurisdictions. Always obtain explicit authorization before scanning any target.

---

# Scanner de Vulnerabilidades de Rede (PT-BR)

Ferramenta completa de reconhecimento de rede desenvolvida em Python. Este projeto oferece dois modos de operação: uma Interface Gráfica (GUI) para desktop e uma Linha de Comando (CLI) de alta performance para servidores e auditorias rápidas.

A ferramenta executa varredura de portas multi-thread, resolução de DNS, captura de banners de serviço e avaliação automatizada de riscos baseada em assinaturas de vulnerabilidades comuns.

## Funcionalidades

### Capacidades Principais
- **Arquitetura Multi-thread:** Varredura de alta velocidade utilizando `concurrent.futures`.
- **Avaliação de Risco:** Detecção automática de vulnerabilidades potenciais (ex: protocolos de texto claro como Telnet/FTP, vetores de ransomware como SMB).
- **Enumeração de Serviços:** Captura banners de serviço (requisições HEAD) para identificar aplicações.
- **Relatórios:** Exporta resultados para arquivos JSON estruturados (`scan_<IP>.json`).

### Modos de Interface
- **Versão GUI:** Interface moderna construída com `customtkinter`. Possui modo escuro nativo, logs em tempo real, controle deslizante de threads e execução assíncrona.
- **Versão CLI:** Interface de linha de comando interativa e leve, ideal para servidores sem monitor (VPS) ou diagnósticos rápidos.

## Pré-requisitos

- **SO:** Windows, Linux ou macOS.
- **Python:** Versão 3.10, 3.11 ou 3.12.
- **Rede:** Conexão ativa com o host alvo.

## Instalação

1. Clone o repositório:
   ```bash
   git clone [https://github.com/SEU_USUARIO/port-scanner-python.git](https://github.com/SEU_USUARIO/port-scanner-python.git)
   cd port-scanner-python
   ```

2. Instale as dependências necessárias:
   ```bash
   pip install -r requirements.txt
   ```

## Utilização

### Opção 1: Versão GUI (Recomendada)
Para uma experiência visual com controles interativos e feedback em tempo real:

```bash
python portscan_gui.py
```
* Insira o IP/Hostname Alvo.
* Ajuste o slider de "Threads" para definir a velocidade.
* Clique em **INICIAR SCAN**.

### Opção 2: Versão CLI (Terminal)
Para ambientes de servidor ou integração com scripts:

```bash
python portscan.py
```
Siga as instruções interativas para definir Alvo, Portas, Threads e Timeout.

## Resultados
Independentemente da versão utilizada, se portas abertas forem detectadas, um arquivo de relatório será gerado no diretório raiz:
`scan_<IP_DO_ALVO>.json`

## Aviso Legal

Esta ferramenta destina-se apenas a **fins educacionais e auditorias de segurança autorizadas**. O autor não se responsabiliza por qualquer uso indevido ou danos causados por este programa. A varredura de redes sem permissão é ilegal em muitas jurisdições. Obtenha sempre autorização explícita antes de escanear qualquer alvo.