import time
import re
import os
import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

# Caminho do arquivo de log
log_file_path = r"C:\Users\luiza\Documents\tccserver\logs\application.log"

# Regex para extrair informações dos logs
pattern = re.compile(r".*Requisicao recebida: IP=(?P<ip>[0-9a-fA-F:\.]+) Método=(?P<method>\S+) URI=(?P<uri>\S+) Query=(?P<query>.*?) User-Agent=(?P<agent>.+)")

# Modelo de IA
model_path = "anomalia_model.pkl"

def train_model():
    print("🔄 Treinando modelo de IA...")
    
    # Simulação de dados normais (IP, Método, URI, User-Agent, Query)
    logs_treinamento = [
        [1, 0, 0, 1, 0],  # GET, /home, User-Agent Normal
        [1, 0, 1, 1, 0],  # GET, /produto, User-Agent Normal
        [1, 1, 1, 1, 1],  # POST, /login, User-Agent Normal
        [1, 0, 2, 0, 0],  # GET, /contato, User-Agent Normal
    ]

    # Adicionando logs anômalos ao treinamento
    logs_treinamento.extend([
        [9, 1, 9, 9, 9],  # DELETE, /admin, User-Agent suspeito
        [9, 1, 8, 9, 9],  # POST, /login, User-Agent hacker tool
        [9, 0, 7, 8, 9],  # GET, /unknown, User-Agent incomum
    ])
    
    modelo = IsolationForest(contamination=0.2, random_state=42)
    modelo.fit(logs_treinamento)
    joblib.dump(modelo, model_path)
    print("✅ Modelo treinado e salvo com dados normais e suspeitos!")

# Função para processar os logs e verificar anomalias
def process_log_line(log_line):
    print(f"📜 Log recebido: {log_line}")
    match = pattern.search(log_line)
    
    if match:
        ip = match.group('ip')
        method = match.group('method')
        uri = match.group('uri')
        query = match.group('query')
        agent = match.group('agent')
        
        print(f"✅ Match encontrado! IP: {ip}, Método: {method}, URI: {uri}, Query: {query}, Agente: {agent}")
        
        # Representação numérica dos logs
        method_numeric = 1 if method == "POST" else (2 if method == "DELETE" else 0)
        uri_numeric = hash(uri) % 10  
        agent_numeric = hash(agent) % 10  
        ip_numeric = hash(ip) % 10  
        query_numeric = hash(query) % 10 if query else 0  # Adicionando query ao modelo

        log_data = np.array([[ip_numeric, method_numeric, uri_numeric, agent_numeric, query_numeric]])

        # Carregar modelo e prever
        modelo = joblib.load(model_path)
        prediction = modelo.predict(log_data)
        
        if prediction[0] == -1:
            print("🚨 Anomalia detectada! Verifique o log.")
        else:
            print("✅ Log normal.")
    else:
        print("❌ Nenhuma correspondência encontrada!")

# Leitura contínua do arquivo de log (tail -f)
def tail_f(log_path):
    print(f"🚀 Monitorando logs em tempo real: {log_path}")
    with open(log_path, "r", encoding="utf-8") as file:
        file.seek(0, os.SEEK_END)
        while True:
            line = file.readline()
            if not line:
                time.sleep(0.1)
                continue
            process_log_line(line.strip())

# Treinar modelo se não existir
if not os.path.exists(model_path):
    train_model()
train_model()
# Iniciar monitoramento
try:
    tail_f(log_file_path)
except KeyboardInterrupt:
    print("\n🛑 Monitoramento encerrado pelo usuário.")
