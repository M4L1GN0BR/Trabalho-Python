"""
Cliente compartilhado para API DeepSeek.

Única fonte de verdade para chamadas à API.
Tanto ai_helper.py quanto dashboard/app.py importam daqui.
"""

import os

import requests
from dotenv import load_dotenv

load_dotenv()

DEEPSEEK_API_KEY = os.getenv("DEEPSEEK_API_KEY")
DEEPSEEK_MODEL = os.getenv("DEEPSEEK_MODEL", "deepseek-chat")
DEEPSEEK_API_URL = os.getenv(
    "DEEPSEEK_API_URL", "https://api.deepseek.com/chat/completions"
)

SYSTEM_ASPM = (
    "Você é um analista sênior de Application Security especializado em ASPM. "
    "Responda sempre em português brasileiro de forma direta, técnica e prática. "
    "Não invente informações que não estejam nos dados fornecidos."
)


def configure(api_key=None, model=None, api_url=None):
    """
    Permite sobrescrever as configs do .env em runtime.
    Útil para testes ou para o dashboard permitir configuração manual.
    """
    global DEEPSEEK_API_KEY, DEEPSEEK_MODEL, DEEPSEEK_API_URL
    if api_key:
        DEEPSEEK_API_KEY = api_key
    if model:
        DEEPSEEK_MODEL = model
    if api_url:
        DEEPSEEK_API_URL = api_url


def call_deepseek(
    prompt,
    system_prompt=None,
    temperature=0.2,
    max_tokens=2048,
    timeout=45,
):
    """
    Chama a API DeepSeek (chat completions) e retorna o texto da resposta.

    Parâmetros
    ----------
    prompt : str
        Mensagem do usuário.
    system_prompt : str, optional
        Mensagem de sistema. Se None, usa o padrão SYSTEM_ASPM.
    temperature : float
        Controle de criatividade (0.0 = determinístico).
    max_tokens : int
        Limite de tokens na resposta.
    timeout : int
        Timeout da requisição HTTP em segundos.

    Retorna
    -------
    str
        Conteúdo da resposta ou string vazia se sem chave ou erro.
    """
    if not DEEPSEEK_API_KEY:
        return ""

    messages = []
    if system_prompt is None:
        messages.append({"role": "system", "content": SYSTEM_ASPM})
    elif system_prompt:
        messages.append({"role": "system", "content": system_prompt})

    messages.append({"role": "user", "content": prompt})

    try:
        response = requests.post(
            DEEPSEEK_API_URL,
            headers={
                "Authorization": f"Bearer {DEEPSEEK_API_KEY}",
                "Content-Type": "application/json",
            },
            json={
                "model": DEEPSEEK_MODEL,
                "messages": messages,
                "temperature": temperature,
                "max_tokens": max_tokens,
            },
            timeout=timeout,
        )

        response.raise_for_status()
        data = response.json()
        return data["choices"][0]["message"]["content"].strip()

    except requests.exceptions.Timeout:
        return ""

    except requests.exceptions.HTTPError:
        return ""

    except Exception:
        return ""
