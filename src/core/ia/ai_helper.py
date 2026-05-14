import os
import google.generativeai as genai
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("GEMINI_API_KEY")

if API_KEY:
    genai.configure(api_key=API_KEY)


def explain_vulnerability(check_id, message):
    if not API_KEY:
        return {
            "explicacao": "Chave da API Gemini não configurada.",
            "risco": "Não foi possível analisar o risco com IA real.",
            "correcao": "Configure a variável GEMINI_API_KEY no arquivo .env."
        }

    try:
        model = genai.GenerativeModel("gemini-1.5-flash")

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

        response = model.generate_content(prompt)
        text = response.text.strip()

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

        return {
            "explicacao": explicacao,
            "risco": risco,
            "correcao": correcao
        }

    except Exception as e:
        return {
            "explicacao": "Erro ao consultar o Gemini.",
            "risco": f"Detalhe: {str(e)}",
            "correcao": "Verifique a API key, conexão com internet e limite da API."
        }