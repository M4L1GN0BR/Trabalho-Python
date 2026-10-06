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
