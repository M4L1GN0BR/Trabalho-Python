"""
Caminho do banco de dados SQLite do projeto.

Centralizado aqui para evitar dependência circular entre módulos
que precisam do DB_PATH (auth, database, etc.).
"""

from pathlib import Path

# Resolve o caminho do banco relativo à raiz do projeto
PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
DB_PATH = str(PROJECT_ROOT / "data" / "history.db")
