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
