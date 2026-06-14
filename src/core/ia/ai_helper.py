import os

import requests
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("DEEPSEEK_API_KEY")
API_URL = os.getenv("DEEPSEEK_API_URL", "https://api.deepseek.com/chat/completions")
MODEL = os.getenv("DEEPSEEK_MODEL", "deepseek-chat")


def explain_vulnerability(check_id, message):
    if not API_KEY:
        return {
            "explicacao": "Chave da API DeepSeek não configurada.",
            "risco": "Não foi possível analisar o risco com IA real.",
            "correcao": "Configure a variável DEEPSEEK_API_KEY no arquivo .env.",
        }

    try:
        prompt = f"""
Você é um assistente de segurança de aplicações.

Analise a vulnerabilidade abaixo e responda em português do Brasil de forma objetiva.

ID da vulnerabilidade: {check_id}
Mensagem da ferramenta: {message}

Responda exatamente neste formato:
EXPLICACAO: ...
RISCO: ...
CORRECAO: ...
"""

        response = requests.post(
            API_URL,
            headers={
                "Authorization": f"Bearer {API_KEY}",
                "Content-Type": "application/json",
            },
            json={
                "model": MODEL,
                "messages": [
                    {
                        "role": "system",
                        "content": "Você é um especialista brasileiro em segurança de aplicações. Responda sempre em português brasileiro.",
                    },
                    {
                        "role": "user",
                        "content": prompt,
                    },
                ],
                "temperature": 0.2,
            },
            timeout=45,
        )

        response.raise_for_status()
        data = response.json()
        text = data["choices"][0]["message"]["content"].strip()

        explicacao = "Não disponível"
        risco = "Não disponível"
        correcao = "Não disponível"

        for line in text.splitlines():
            if line.startswith("EXPLICACAO:"):
                explicacao = line.replace("EXPLICACAO:", "").strip()
            elif line.startswith("RISCO:"):
                risco = line.replace("RISCO:", "").strip()
            elif line.startswith("CORRECAO:"):
                correcao = line.replace("CORRECAO:", "").strip()

        return {"explicacao": explicacao, "risco": risco, "correcao": correcao}

    except Exception as e:
        return {
            "explicacao": "Erro ao consultar o DeepSeek.",
            "risco": f"Detalhe: {str(e)}",
            "correcao": "Verifique a API key, conexão com internet e limite da API.",
        }
