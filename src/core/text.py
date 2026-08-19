"""
Utilitários de texto e JSON.

Funções puras usadas pelo dashboard e pelos parsers de ferramentas.
Mantidas fora do app.py para organização.
"""

import json
import os


def clean_text(text):
    """Corrige caracteres corrompidos por encoding vindos das ferramentas."""
    if not isinstance(text, str):
        return text

    replacements = {
        "Poss├â┬¡vel": "Possível",
        "execu├º├úo": "execução",
        "usu├írio": "usuário",
        "fun├º├Áes": "funções",
        "seguran├ºa": "segurança",
    }

    for wrong, right in replacements.items():
        text = text.replace(wrong, right)

    return text


def load_json(file_path, default=None):
    """Carrega um arquivo JSON com tolerância a BOM. Retorna default se não existir."""
    if default is None:
        default = {}

    if not os.path.exists(file_path):
        return default

    with open(file_path, "r", encoding="utf-8-sig") as f:
        return json.load(f)
