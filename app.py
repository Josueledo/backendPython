import time
import re
import os
import asyncio
import websockets
import threading
import requests
from collections import defaultdict

# Caminho do arquivo de log
log_file_path = r"C:\Users\Josue Ledo\Desktop\crud-tcc\logs\application.log"

# Regex para capturar informações do log
pattern = re.compile(r".*Requisicao recebida: IP=(?P<ip>[0-9a-fA-F:\.]+) Metodo=(?P<method>\S+) URI=(?P<uri>\S+) Query=(?P<query>.*?) User-Agent=(?P<agent>.+)")

# Lista de clientes WebSocket conectados
clients = set()
logins_por_ip = defaultdict(list)
requisicoes_por_ip = defaultdict(list)
ips_bloqueados_local = set()  # <<< NOVO: Para não mandar várias vezes o mesmo IP

def bloquear_ip_backend(ip):
    """Chama o backend Spring Boot para bloquear o IP"""
    if ip in ips_bloqueados_local:
        print(f"🔒 IP {ip} já está bloqueado localmente.")
        return
    try:
        response = requests.post("http://localhost:8080/api/block?ip=" + ip)
        if response.status_code == 200:
            print(f"✅ IP {ip} bloqueado no backend!")
            ips_bloqueados_local.add(ip)  # <<< Marca como bloqueado
        else:
            print(f"⚠️ Erro ao bloquear IP {ip}: {response.status_code} - {response.text}")
    except Exception as e:
        print(f"❌ Erro ao tentar bloquear IP {ip}: {e}")

def analisar_ataque(ip, uri):
    agora = time.time()
    
    # Detectar força bruta em URIs de login
    if "/login" in uri.lower():
        logins_por_ip[ip].append(agora)
        # Limpa acessos antigos (mais de 60 segundos)
        logins_por_ip[ip] = [t for t in logins_por_ip[ip] if agora - t < 60]
        if len(logins_por_ip[ip]) > 5:
            bloquear_ip_backend(ip)  # <<< Bloqueia se passar limite de tentativas
            return "🚨 Possível ataque de força bruta"

    # Detectar DDoS: muitas requisições, mesmo fora do /login
    requisicoes_por_ip[ip].append(agora)
    requisicoes_por_ip[ip] = [t for t in requisicoes_por_ip[ip] if agora - t < 10]
    if len(requisicoes_por_ip[ip]) > 10:
        bloquear_ip_backend(ip)  # <<< Bloqueia se passar limite de requisições
        return "🌊 Possível ataque DDoS"

    return None

async def notify_clients(message):
    """Envia a mensagem para todos os clientes WebSocket conectados"""
    if clients:
        print(f"Enviando mensagem para {len(clients)} clientes: {message}")
        await asyncio.gather(*(client.send(message) for client in clients))

async def websocket_handler(websocket):
    """Manipula a conexão WebSocket de cada cliente"""
    clients.add(websocket)
    print(f"Novo cliente conectado. Total de clientes: {len(clients)}")
    try:
        async for _ in websocket:
            pass  # Mantém a conexão ativa
    finally:
        clients.remove(websocket)
        print(f"Cliente desconectado. Total de clientes: {len(clients)}")

async def start_websocket_server():
    """Inicia o servidor WebSocket"""
    async with websockets.serve(websocket_handler, "localhost", 8765):
        print("Servidor WebSocket iniciado em ws://localhost:8765")
        await asyncio.Future()  # Mantém o servidor rodando indefinidamente

def process_log_line(log_line, loop):
    """Processa cada linha do log"""
    match = pattern.search(log_line)
    
    if match:
        ip = match.group('ip')
        method = match.group('method')
        uri = match.group('uri')
        query = match.group('query')
        agent = match.group('agent')

        if ip == "0:0:0:0:0:0:0:1":
            ip = "127.0.0.1"

        log_message = f"IP: {ip}, Metodo: {method}, URI: {uri}, Query: {query}, Agente: {agent}"
        print(f"📩 Log processado: {log_message}")

        # Envia o log para os clientes WebSocket
        alerta = analisar_ataque(ip, uri)
        if alerta:
            print(alerta)
            log_message += f" | {alerta}"
        asyncio.run_coroutine_threadsafe(notify_clients(log_message), loop)

def desbloquear_ip(ip):
    try:
        response = requests.delete("http://localhost:8080/api/block", params={"ip": ip})
        print("✅ IP desbloqueado com sucesso:", ip)
    except Exception as e:
        print("❌ Erro ao desbloquear IP:", e)

def tail_f(log_path, loop):
    """Monitora o arquivo de log em tempo real"""
    print(f"🚀 Monitorando logs em tempo real: {log_path}")
    
    with open(log_path, "r", encoding="utf-8") as file:
        file.seek(0, os.SEEK_END)  # Vai para o final do arquivo
        
        while True:
            line = file.readline()
            if not line:
                time.sleep(0.1)  # Evita alto uso da CPU
                continue
            process_log_line(line.strip(), loop)

def run_event_loop(loop):
    """Executa o loop de eventos do servidor WebSocket"""
    asyncio.set_event_loop(loop)
    loop.run_until_complete(start_websocket_server())
    loop.run_forever()

# Criar um novo loop de eventos para o WebSocket
loop = asyncio.new_event_loop()

# Iniciar o servidor WebSocket em uma thread separada
threading.Thread(target=run_event_loop, args=(loop,), daemon=True).start()

# Iniciar monitoramento de logs em uma thread separada
threading.Thread(target=tail_f, args=(log_file_path, loop), daemon=True).start()

# Manter a execução principal ativa
while True:
    time.sleep(1)
