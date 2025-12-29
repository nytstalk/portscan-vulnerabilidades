import concurrent.futures
import colorama
from colorama import Fore, Style
import dns.resolver
import logging
import socket
import sys
import os
import json

# Configuração de Logs
logging.basicConfig(level=logging.INFO, format='%(message)s')

class PortScanner:
    def __init__(self):
        colorama.init(autoreset=True)
        self.logger = logging.getLogger(__name__)
        
        # --- BANCO DE DADOS DE VULNERABILIDADES COMUNS ---
        self.vuln_db = {
            21: "FTP: Transmite dados/senhas em texto claro. Risco de Sniffing.",
            22: "SSH: Sujeito a ataques de Brute-Force. Verifique chaves fracas.",
            23: "TELNET: ALTÍSSIMO RISCO. Comunicação não criptografada. Substitua por SSH.",
            25: "SMTP: Pode permitir enumeração de usuários ou ser Open Relay (SPAM).",
            53: "DNS: Risco de ataques de Amplificação DDoS ou Transferência de Zona.",
            80: "HTTP: Site sem criptografia. Vulnerável a Sniffing e ataques Web (XSS, SQLi).",
            110: "POP3: E-mail antigo. Transmite senhas em texto claro.",
            135: "RPC: Vetor comum para enumeração de rede interna.",
            139: "NetBIOS: Risco de vazamento de informações da rede interna.",
            143: "IMAP: Transmite senhas em texto claro se não usar SSL/TLS.",
            443: "HTTPS: Seguro, mas verifique certificados expirados ou Heartbleed.",
            445: "SMB: CRÍTICO. Vetor principal de Ransomware (WannaCry) e exploits (EternalBlue).",
            3306: "MySQL: Banco de dados exposto. Risco de Brute-force ou vazamento de dados.",
            3389: "RDP: Acesso Remoto Windows. Alvo frequente de Brute-force e exploits (BlueKeep).",
            5432: "PostgreSQL: Banco de dados exposto. Verifique permissões de acesso.",
            5900: "VNC: Acesso remoto. Frequentemente configurado sem senha ou senha fraca.",
            8080: "HTTP-Alt: Geralmente servidores de aplicação/proxy mal configurados.",
            27017: "MongoDB: Frequentemente encontrado sem autenticação (Vazamento de Dados)."
        }

    def limpar_tela(self):
        os.system('cls' if os.name == 'nt' else 'clear')

    def exibir_logo(self):
        print(Fore.CYAN + Style.BRIGHT + "="*60)
        print(f"{Fore.CYAN}       PYTHON VULNERABILITY SCANNER PRO       ")
        print(Fore.CYAN + "="*60 + Fore.RESET)
        print(f"{Style.DIM}Análise de Portas + Detecção de Riscos Comuns.\n{Style.RESET_ALL}")

    def resolve_dns(self, hostname):
        print(f"\n{Fore.BLUE}[*] Resolvendo DNS para {hostname}...{Fore.RESET}")
        try:
            socket.inet_aton(hostname)
            return hostname
        except socket.error:
            try:
                ip_address = dns.resolver.resolve(hostname, 'A')
                ip_val = ip_address[0].to_text()
                print(f"{Fore.GREEN}[OK] IP Encontrado: {ip_val}{Fore.RESET}")
                return ip_val
            except Exception:
                print(f"{Fore.RED}[!] Erro: Não foi possível encontrar o IP de '{hostname}'.{Fore.RESET}")
                return None

    def get_vuln_info(self, port):
        return self.vuln_db.get(port, "Serviço genérico. Verifique versão e atualizações.")

    def scan_port(self, target_ip, port, timeout):
        result_data = None
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                result = s.connect_ex((target_ip, port))
                
                if result == 0:
                    try:
                        service = socket.getservbyport(port)
                    except:
                        service = "unknown"
                    
                    # 1. Mostra Porta Aberta
                    self.logger.info(f"{Fore.GREEN}[+] Porta {port:<5} ABERTA  ({service}){Fore.RESET}")
                    
                    # 2. Busca e Mostra Vulnerabilidade
                    vuln_info = self.get_vuln_info(port)
                    print(f"    {Fore.YELLOW}⚠️  Risco Potencial: {vuln_info}{Fore.RESET}")

                    # 3. Banner Grabbing
                    banner_str = ""
                    try:
                        s.send(b'HEAD / HTTP/1.0\r\n\r\n')
                        banner_bytes = s.recv(1024)
                        banner_str = banner_bytes.decode().strip()
                        if banner_str:
                            self.logger.info(f"    |_ Banner: {Style.DIM}{banner_str[:60]}...{Style.RESET_ALL}")
                    except:
                        pass
                    
                    # Prepara dados para JSON
                    result_data = {
                        "port": port,
                        "service": service,
                        "vulnerability_hint": vuln_info,
                        "banner": banner_str
                    }
        except:
            pass
            
        return result_data

    def parse_ports(self, port_str):
        ports = []
        if port_str == "all":
            return list(range(1, 65536))
        try:
            if "-" in port_str:
                start, end = map(int, port_str.split("-"))
                ports = list(range(start, end + 1))
            elif "," in port_str:
                ports = [int(p) for p in port_str.split(",")]
            else:
                ports = [int(port_str)]
        except ValueError:
            print(f"{Fore.RED}[!] Formato de porta inválido. Usando padrão 1-1024.{Fore.RESET}")
            return list(range(1, 1025))
        return ports

    def salvar_relatorio(self, target_ip, open_ports_list):
        filename = f"scan_{target_ip}.json"
        
        data = {
            "target": target_ip,
            "total_open": len(open_ports_list),
            "scan_results": open_ports_list
        }

        try:
            with open(filename, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=4, ensure_ascii=False)
            print(f"\n{Fore.YELLOW}[!] Relatório detalhado salvo em: {filename}{Fore.RESET}")
            print(f"{Style.DIM}(Contém dados sobre as vulnerabilidades detectadas){Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[!] Erro ao salvar arquivo: {e}{Fore.RESET}")

    def run(self):
        self.limpar_tela()
        self.exibir_logo()

        # --- INPUTS ---
        while True:
            target_input = input(f"{Fore.YELLOW}[?] Digite o Alvo (IP ou Site): {Fore.RESET}").strip()
            if target_input: break
            print(f"{Fore.RED}>> O alvo não pode ficar vazio!{Fore.RESET}")

        ports_input = input(f"{Fore.YELLOW}[?] Portas (ex: 80,443 ou 1-1000) [Enter para '1-1024']: {Fore.RESET}").strip()
        if not ports_input: ports_input = "1-1024"

        threads_input = input(f"{Fore.YELLOW}[?] Velocidade/Threads (1-200) [Enter para '100']: {Fore.RESET}").strip()
        try: threads = int(threads_input) if threads_input else 100
        except ValueError: threads = 100

        timeout_input = input(f"{Fore.YELLOW}[?] Timeout em segundos [Enter para '1.0']: {Fore.RESET}").strip()
        try: timeout = float(timeout_input.replace(',', '.')) if timeout_input else 1.0
        except ValueError: timeout = 1.0

        # --- EXECUÇÃO ---
        target_ip = self.resolve_dns(target_input)
        if not target_ip: return

        ports = self.parse_ports(ports_input)
        
        print(f"\n{Fore.CYAN}[*] Iniciando Scan em: {target_ip}")
        print(f"[*] Portas: {len(ports)} | Threads: {threads} | Timeout: {timeout}s")
        print(f"{'='*60}{Fore.RESET}\n")

        resultados_encontrados = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(self.scan_port, target_ip, port, timeout): port for port in ports}
            
            for future in concurrent.futures.as_completed(futures):
                dados = future.result()
                if dados is not None:
                    resultados_encontrados.append(dados)

        resultados_encontrados.sort(key=lambda x: x['port'])

        print(f"\n{Fore.CYAN}[*] Varredura Concluída!{Fore.RESET}")
        
        if resultados_encontrados:
            self.salvar_relatorio(target_ip, resultados_encontrados)
        else:
            print(f"{Fore.YELLOW}Nenhuma porta aberta foi encontrada.{Fore.RESET}")

        input("\nPressione Enter para sair...")

if __name__ == "__main__":
    scanner = PortScanner()
    scanner.run()