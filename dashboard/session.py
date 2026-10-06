# NightSync - ASPM (Application Security Posture Management)
# Copyright (C) 2026 Felipe Barbosa Alves (RM570378),
#                    Murilo Garcia Godoy (RM564840),
#                    Lucas Moura Goncalves de Amorim (RM570161),
#                    Caio de Paula Goes (RM569052)
#
# This file is part of NightSync, free software under the GNU General
# Public License as published by the Free Software Foundation, either
# version 3 of the License, or (at your option) any later version.
#
# NightSync is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.
#
# SPDX-License-Identifier: GPL-3.0-or-later

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
