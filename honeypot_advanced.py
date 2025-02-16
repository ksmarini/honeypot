#!/usr/bin/env python3

import socket
import threading
import time
import json
import logging
from datetime import datetime
from collections import defaultdict
from urllib.request import urlopen

# Configurações
LISTEN_IP = "0.0.0.0"
PORTS = [22, 80, 445, 110, 389, 636, 443, 23, 8080, 6000, 5001, 8443, 123]
LOG_FILE = "honeypot.log"
JSON_LOG = "connections.json"
THREAT_FEED_URL = "https://feeds.dshield.org/top10-2.txt"
SCAN_THRESHOLD = 5
SCAN_WINDOW = 60

# Configuração de logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.FileHandler(LOG_FILE), logging.StreamHandler()],
)


class ThreatIntel:
    """Integração com feeds de ameaças"""

    def __init__(self):
        self.malicious_ips = set()
        self.update_threat_feed()

    def update_threat_feed(self):
        """Atualiza lista de IPs maliciosos"""
        try:
            with urlopen(THREAT_FEED_URL) as response:
                data = response.read().decode("utf-8")
                for line in data.splitlines():
                    if not line.startswith("#"):
                        parts = line.strip().split()
                        if len(parts) > 0:
                            self.malicious_ips.add(parts[0])
            logging.info(
                f"Feed de ameaças atualizado. IPs carregados: {len(self.malicious_ips)}"
            )
        except Exception as e:
            logging.error(f"Erro ao atualizar feed: {e}")

    def is_malicious(self, ip):
        """Verifica se IP está na lista de ameaças"""
        return ip in self.malicious_ips


class ScanDetector:
    """Detecção de varreduras de rede"""

    def __init__(self):
        self.connections = defaultdict(list)
        self.lock = threading.Lock()

    def log_connection(self, ip):
        """Registra nova conexão"""
        with self.lock:
            now = time.time()
            self.connections[ip].append(now)
            # Mantém apenas conexões dentro da janela temporal
            self.connections[ip] = [
                t for t in self.connections[ip] if now - t < SCAN_WINDOW
            ]

    def is_scan(self, ip):
        """Verifica se IP está realizando scan"""
        with self.lock:
            return len(self.connections[ip]) >= SCAN_THRESHOLD

    def get_scan_count(self, ip):
        """Retorna o número de portas acessadas"""
        with self.lock:
            return len(self.connections[ip])


class MockService:
    """Serviço honeypot completo com suporte a SSH"""

    def __init__(self, port, threat_intel, scan_detector):
        self.port = port
        self.running = True
        self.banner = self._get_banner()
        self.threat_intel = threat_intel
        self.scan_detector = scan_detector

    def _get_banner(self):
        """Retorna banners personalizados incluindo SSH"""
        banners = {
            22: b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.3\r\n",
            80: b"HTTP/1.1 200 OK\nContent-Type: text/html\n\n<html><h1>Welcome</h1></html>\n",
            443: b"HTTP/1.1 200 OK\nContent-Type: text/html\n\n<html><h1>Secure Site</h1></html>\n",
            23: b"Telnet Server Ready\nLogin: ",
            21: b"220 FTP Server Ready\n",
            25: b"220 SMTP Server Ready\n",
        }
        return banners.get(self.port, b"Connection established\n")

    def _log_connection(self, data):
        """Registra conexão em formato JSON"""
        try:
            with open(JSON_LOG, "a") as f:
                f.write(json.dumps(data) + "\n")
        except Exception as e:
            logging.error(f"Erro ao registrar conexão: {e}")

    def _handle_client(self, clientsocket, address):
        """Manipula conexões de clientes com tratamento especial para SSH"""
        try:
            client_ip, client_port = address
            metadata = {
                "timestamp": datetime.now().isoformat(),
                "client_ip": client_ip,
                "client_port": client_port,
                "port": self.port,
                "banner_sent": self.banner.decode().strip(),
                "data_received": "",
                "service_type": "ssh" if self.port == 22 else "generic",
            }

            # Detecção de ameaças
            if self.threat_intel.is_malicious(client_ip):
                logging.warning(f"Conexão de IP malicioso conhecido: {client_ip}")
                metadata["threat"] = True

            # Detecção de scans
            self.scan_detector.log_connection(client_ip)
            if self.scan_detector.is_scan(client_ip):
                port_count = self.scan_detector.get_scan_count(client_ip)
                logging.warning(
                    f"Possível scan detectado de {client_ip}. Portas acessadas: {port_count}"
                )

            # Envio imediato do banner
            clientsocket.send(self.banner)

            # Comportamento especial para SSH
            if self.port == 22:
                data = clientsocket.recv(1024)
                if data:
                    ssh_client_version = data.decode(errors="ignore").strip()
                    metadata["ssh_client_version"] = ssh_client_version
                    logging.info(f"Client SSH conectado: {ssh_client_version}")

            # Restante da interação
            data = clientsocket.recv(1024)
            if data:
                metadata["data_received"] = data.decode(errors="ignore").strip()
                logging.info(
                    f"Dados recebidos de {client_ip}:{client_port}: {metadata['data_received']}"
                )

            # Registra metadados
            self._log_connection(metadata)
            time.sleep(2)

        except Exception as e:
            logging.error(f"Erro na conexão: {e}")
        finally:
            clientsocket.close()

    def listen(self):
        """Inicia servidor TCP"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind((LISTEN_IP, self.port))
                s.listen(5)
                s.settimeout(2)

                logging.info(f"Serviço iniciado na porta {self.port}")

                while self.running:
                    try:
                        clientsocket, address = s.accept()
                        thread = threading.Thread(
                            target=self._handle_client, args=(clientsocket, address)
                        )
                        thread.start()
                    except socket.timeout:
                        continue

        except PermissionError:
            logging.error(f"Permissão negada para porta {self.port}")
        except Exception as e:
            logging.error(f"Erro fatal na porta {self.port}: {e}")

    def service_thread(self):
        """Inicia thread do serviço"""
        thread = threading.Thread(target=self.listen)
        thread.daemon = True
        thread.start()


if __name__ == "__main__":
    logging.info("Iniciando honeypot...")

    # Inicializa subsistemas
    threat_intel = ThreatIntel()
    scan_detector = ScanDetector()
    services = []

    # Inicia serviços
    for port in PORTS:
        service = MockService(port, threat_intel, scan_detector)
        service.service_thread()
        services.append(service)

    # Loop principal
    try:
        while True:
            time.sleep(300)
            threat_intel.update_threat_feed()
    except KeyboardInterrupt:
        logging.info("Desligando honeypot...")
        for service in services:
            service.running = False
