import time
import re
import os
import pandas as pd
import joblib
from sklearn.ensemble import IsolationForest
from datetime import datetime

# Caminho do arquivo de log
log_file_path = r"C:\Users\luiza\Documents\tccserver\logs\application.log"

# Função para extrair dados do log
def process_log_line(log_line):
    pattern = r".*IP=(?P<ip>[\d\.]+) Método=(?P<method>\S+) URI=(?P<uri>\S+) Query=(?P<query>.*?) User-Agent=(?P<agent>.+)"
    match = re.match(pattern, log_line)

    if match:
        return {
            "ip": match.group('ip'),
            "method": match.group('method'),
            "uri": match.group('uri'),
            "query": match.group('query'),
            "agent": match.group('agent'),
            "timestamp": datetime.now()
        }
    return None

# Lista para armazenar logs processados
log_data = []

# Leitura contínua do arquivo de log (tail -f)
def tail_f(log_path, model):
    print(f"🚀 Monitorando logs em tempo real: {log_path}")

    with open(log_path, "r", encoding="utf-8") as file:
        file.seek(0, os.SEEK_END)  # Vai para o final do arquivo

        while True:
            line = file.readline()
            if not line:
                time.sleep(0.1)
                continue

            log_info = process_log_line(line.strip())
            if log_info:
                log_data.append(log_info)
                check_anomaly(log_info, model)

# Função para converter os logs em formato numérico e verificar anomalias
def check_anomaly(log_info, model):
    df = pd.DataFrame([log_info])

    # Transformar método HTTP em número
    df['method'] = df['method'].astype('category').cat.codes
    df['uri'] = df['uri'].astype('category').cat.codes
    df['query'] = df['query'].astype('category').cat.codes
    df['agent'] = df['agent'].astype('category').cat.codes

    # Prever se é uma anomalia (-1 = anomalia, 1 = normal)
    prediction = model.predict(df[['method', 'uri', 'query', 'agent']])

    if prediction[0] == -1:
        print(f"⚠️ ALERTA! Possível atividade suspeita detectada: {log_info}")

# Função para treinar o modelo Isolation Forest
def train_model():
    df = pd.DataFrame(log_data)

    df['method'] = df['method'].astype('category').cat.codes
    df['uri'] = df['uri'].astype('category').cat.codes
    df['query'] = df['query'].astype('category').cat.codes
    df['agent'] = df['agent'].astype('category').cat.codes

    # Treina o modelo com os logs conhecidos
    model = IsolationForest(contamination=0.05, random_state=42)
    model.fit(df[['method', 'uri', 'query', 'agent']])

    joblib.dump(model, "anomalia_model.pkl")
    print("✅ Modelo treinado e salvo!")
    return model

# Se houver um modelo salvo, carregamos
if os.path.exists("anomalia_model.pkl"):
    modelo_treinado = joblib.load("anomalia_model.pkl")
    print("📂 Modelo carregado com sucesso!")
else:
    modelo_treinado = train_model()

try:
    tail_f(log_file_path, modelo_treinado)
except KeyboardInterrupt:
    print("\n🛑 Monitoramento encerrado pelo usuário.")
