"""
Módulo de autenticação e controle de acesso.

Centraliza a criação de usuários, verificação de senha (bcrypt),
perfis de acesso e registro de sessões. Não depende de Streamlit UI.
"""

import sqlite3
from datetime import datetime

import bcrypt
import pandas as pd

from .database_path import DB_PATH

ROLE_LABELS = {
    "admin": "Administrador",
    "analista": "Analista",
    "visualizador": "Visualizador",
}

# Permissões por perfil: admin > analista > visualizador
ROLE_PERMISSIONS = {
    "admin": ["upload", "scan", "url_analysis", "reset_history", "manage_users", "view_all"],
    "analista": ["upload", "scan", "url_analysis"],
    "visualizador": ["view"],
}


def verify_login(username, password):
    """Verifica credenciais e retorna dict do usuário ou None."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "SELECT id, username, password_hash, role FROM users WHERE username = ?",
        (username,),
    )
    row = cursor.fetchone()
    conn.close()

    if not row:
        return None

    user_id, db_username, pw_hash, role = row
    try:
        if bcrypt.checkpw(password.encode("utf-8"), pw_hash.encode("utf-8")):
            return {"id": user_id, "username": db_username, "role": role}
    except ValueError:
        return None
    return None


def register_user(username, password, role="analista"):
    """Cria um novo usuário. Retorna True se criou, False se já existe."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    try:
        pw_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
        cursor.execute(
            "INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
            (username, pw_hash, role, datetime.now().strftime("%Y-%m-%d %H:%M")),
        )
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()


def load_users():
    """Lista todos os usuários."""
    conn = sqlite3.connect(DB_PATH)
    df = pd.read_sql_query(
        "SELECT id, username, role, created_at FROM users ORDER BY id", conn
    )
    conn.close()
    return df


def delete_user(user_id):
    """Remove um usuário (não permite remover o admin principal)."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT username FROM users WHERE id = ?", (user_id,))
    row = cursor.fetchone()
    if row and row[0] == "admin":
        conn.close()
        return False
    cursor.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    conn.close()
    return True


def register_login(user_id, username):
    """Registra sessão de login."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO sessions (user_id, username, login_at) VALUES (?, ?, ?)",
        (user_id, username, datetime.now().strftime("%Y-%m-%d %H:%M")),
    )
    conn.commit()
    conn.close()
