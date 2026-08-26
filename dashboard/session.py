"""
Helpers de sessão do Streamlit.

Centraliza o acesso ao usuário logado e às permissões de perfil,
evitando repetir st.session_state.get("user") no app.py.
"""

import streamlit as st

from src.core.auth import ROLE_PERMISSIONS


def can(permission):
    """Verifica se o usuário atual tem permissão."""
    user = st.session_state.get("user")
    if not user:
        return False
    return permission in ROLE_PERMISSIONS.get(user.get("role", ""), [])


def is_admin():
    """True apenas para o perfil Administrador."""
    return st.session_state.get("user", {}).get("role") == "admin"


def get_current_username():
    """Nome do usuário logado."""
    user = st.session_state.get("user")
    return user.get("username", "desconhecido") if user else "desconhecido"


def get_current_user_id():
    """ID do usuário logado."""
    user = st.session_state.get("user")
    return user.get("id", 1) if user else 1
