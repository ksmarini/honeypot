#!/usr/bin/env python3

import socket
import threading
import time
from datetime import datetime

LISTEN_IP = "0.0.0.0"  # Escuta em todas as interfaces de rede
PORTS = [80, 445, 110, 389, 636, 443, 23, 8080, 6000, 5001, 8443, 123]


class MockService:
    """Classe que simula serviços para criar um honeypot"""

    def __init__(self, port):
        self.port = port
        self.running = True
        self.banner = self._get_banner()

    def _get_banner(self):
        """Retorna banners personalizados com base na porta"""
        banners = {
            80: b"HTTP/1.1 200 OK\nContent-Type: text/html\n\n<html><h1>Welcome</h1></html>\n",
            443: b"HTTP/1.1 200 OK\nContent-Type: text/html\n\n<html><h1>Secure Site</h1></html>\n",
            23: b"Telnet Server Ready\nLogin: ",
            21: b"220 FTP Server Ready\n",
        }
        return banners.get(self.port, b"Connection established\n")

    def _handle_client(self, clientsocket, address):
        """Maneja a conexão do cliente"""
        try:
            # Coleta informações do cliente
            client_ip = address[0]
            client_port = address[1]
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            # Tenta resolver o hostname
            try:
                client_hostname = socket.getfqdn(client_ip)
            except socket.herror:
                client_hostname = "unknown"

            print(
                f"[{timestamp}] Conexão recebida: {client_ip}:{client_port} ({client_hostname}) -> Porta {self.port}"
            )

            # Simula interação com o serviço
            clientsocket.send(self.banner)
            data = clientsocket.recv(1024)  # Aguarda dados do cliente
            if data:
                print(
                    f"[{timestamp}] Dados recebidos ({self.port}): {data.decode().strip()}"
                )

            # Mantém a conexão aberta temporariamente
            time.sleep(5)

        except Exception as e:
            print(f"Erro na conexão: {e}")
        finally:
            clientsocket.close()

    def listen(self):
        """Inicia o servidor TCP"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as serversocket:
                serversocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                serversocket.bind((LISTEN_IP, self.port))
                serversocket.listen(5)
                serversocket.settimeout(
                    2
                )  # Timeout para verificar self.running periodicamente

                print(f"[*] Serviço simulado iniciado na porta {self.port}")

                while self.running:
                    try:
                        clientsocket, address = serversocket.accept()
                        client_thread = threading.Thread(
                            target=self._handle_client, args=(clientsocket, address)
                        )
                        client_thread.start()
                    except socket.timeout:
                        continue

        except PermissionError:
            print(f"[!] Erro: Permissão negada para abrir a porta {self.port}")
        except OSError as e:
            print(f"[!] Erro na porta {self.port}: {e}")

    def service_thread(self):
        """Inicia a thread do serviço"""
        server_thread = threading.Thread(target=self.listen)
        server_thread.daemon = True  # Permite que o programa termine adequadamente
        server_thread.start()


if __name__ == "__main__":
    print("[*] Iniciando honeypot...")
    services = []

    # Inicia todos os serviços
    for port in PORTS:
        service = MockService(port)
        service.service_thread()
        services.append(service)

    # Mantém o programa principal ativo
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Desligando honeypot...")
        for service in services:
            service.running = False
