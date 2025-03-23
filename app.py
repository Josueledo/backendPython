import time
import re
import os

# Caminho do arquivo de log
log_file_path = r"C:\Users\Josue Ledo\Desktop\crud-tcc\logs/application.log"

# Regex corrigida para permitir mais flexibilidade
pattern = re.compile(r".*Requisicao recebida: IP=(?P<ip>[0-9a-fA-F:\.]+) Metodo=(?P<method>\S+) URI=(?P<uri>\S+) Query=(?P<query>.*?) User-Agent=(?P<agent>.+)")

# Função para processar os logs
def process_log_line(log_line):
    print(f"📜 Log recebido: {log_line}")  # Exibir log recebido
    
    match = pattern.search(log_line)  # Mudança para `search` para flexibilizar a busca
    
    if match:
        ip = match.group('ip')
        method = match.group('method')
        uri = match.group('uri')
        query = match.group('query')
        agent = match.group('agent')

        print(f"✅ Match encontrado! IP: {ip}, Método: {method}, URI: {uri}, Query: {query}, Agente: {agent}")
        
        # Exemplo de detecção de possíveis ataques
        if method == "POST" and "login" in uri.lower():
            print(f"⚠️ Possível ataque de força bruta detectado de {ip} na URI {uri}.")
        
        # Detecção de múltiplas tentativas de login
        if method == "POST" and "login" in uri.lower() and "user=" in query:
            print(f"⚠️ Tentativa de login com usuário suspeito: {query} de {ip}.")
    else:
        print("❌ Nenhuma correspondência encontrada!")

# Leitura contínua do arquivo de log (tail -f)
def tail_f(log_path):
    print(f"🚀 Monitorando logs em tempo real: {log_path}")

    with open(log_path, "r", encoding="utf-8") as file:
        file.seek(0, os.SEEK_END)  # Vai para o final do arquivo

        while True:
            line = file.readline()  # Lê a próxima linha
            if not line:
                time.sleep(0.1)  # Pequena pausa para evitar alto uso da CPU
                continue

            process_log_line(line.strip())  # Processa a linha nova

try:
    tail_f(log_file_path)
except KeyboardInterrupt:
    print("\n🛑 Monitoramento encerrado pelo usuário.")
