import pandas as pd
import joblib
import re
from sklearn.ensemble import IsolationForest

# Simulando logs normais para treinar o modelo
dados_normais = [
    "IP=192.168.1.10 Método=GET URI=/home Query=null User-Agent=Mozilla/5.0",
    "IP=192.168.1.11 Método=POST URI=/login Query=username=admin User-Agent=Chrome/100.0.0.0",
    "IP=192.168.1.12 Método=GET URI=/produto/listar Query=null User-Agent=Firefox/90.0"
]

# Função para extrair features de um log
def extrair_features(log):
    padrao = re.compile(r"IP=(?P<ip>[\d\.]+) Método=(?P<method>\S+) URI=(?P<uri>\S+) Query=(?P<query>.*?) User-Agent=(?P<agent>.+)")
    match = padrao.search(log)
    if match:
        return [
            len(match.group("ip")),
            len(match.group("method")),
            len(match.group("uri")),
            len(match.group("query")),
            len(match.group("agent"))
        ]
    return None

# Criando dataset de treinamento
features = [extrair_features(log) for log in dados_normais]
features = [f for f in features if f is not None]  # Removendo Nones

# Treinando modelo de Isolation Forest
modelo = IsolationForest(contamination=0.1, random_state=42)
modelo.fit(features)

# Salvando o modelo treinado
joblib.dump(modelo, "anomalia_model.pkl")
print("✅ Modelo treinado e salvooooo!")

# Função para testar um novo log
def analisar_log(log):
    modelo = joblib.load("anomalia_model.pkl")  # Carrega o modelo treinado
    features = extrair_features(log)
    if features:
        resultado = modelo.predict([features])
        if resultado[0] == -1:
            print(f"🚨 Anomalia detectada no log: {log}")
        else:
            print(f"✅ Log normal: {log}")
    else:
        print("⚠ Log inválido ou não pôde ser analisado.")

# Teste com um log normal e um log suspeito
logs_teste = [
    "IP=192.168.1.15 Método=GET URI=/home Query=null User-Agent=Mozilla/5.0",
    "IP=10.0.0.5 Método=POST URI=/admin Query='{\"cmd\":\"whoami\"}' User-Agent=AttackScanner"
]


for log in logs_teste:
    analisar_log(log)
