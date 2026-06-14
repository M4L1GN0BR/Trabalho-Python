import os

import requests
from dotenv import load_dotenv

load_dotenv()

API_KEY = os.getenv("DEEPSEEK_API_KEY")
API_URL = os.getenv("DEEPSEEK_API_URL", "https://api.deepseek.com/chat/completions")
MODEL = os.getenv("DEEPSEEK_MODEL", "deepseek-chat")

if not API_KEY:
    print("DEEPSEEK_API_KEY não configurada no .env")
    exit(1)

response = requests.post(
    API_URL,
    headers={
        "Authorization": f"Bearer {API_KEY}",
        "Content-Type": "application/json",
    },
    json={
        "model": MODEL,
        "messages": [{"role": "user", "content": "Say hello in one word"}],
        "temperature": 0.0,
    },
    timeout=30,
)

response.raise_for_status()
data = response.json()
print(f"Modelo: {MODEL}")
print(f"Resposta: {data['choices'][0]['message']['content'].strip()}")
