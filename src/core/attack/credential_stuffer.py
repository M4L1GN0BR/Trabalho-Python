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
Teste de credenciais comuns (credential stuffing) — LABORATÓRIO SOMENTE.

Somente uso autorizado. Conjunto PADRÃO pequeno e limitado (8 combinações,
com delay). Não faz varredura de listas enormes, não contorna bloqueios
e não tenta burlar CAPTCHA/2FA.

A URL informada deve ser o endpoint de login (ex: http://lab/login.php).
"""

import time

import requests

HEADERS = {"User-Agent": "ASPM-Scanner/1.0"}

DEFAULT_CREDENTIALS = [
    ("admin", "admin"),
    ("admin", "admin123"),
    ("admin", "password"),
    ("admin", "123456"),
    ("user", "user"),
    ("user", "password"),
    ("test", "test"),
    ("root", "admin"),
]

SUCCESS_KEYWORDS = [
    "logout", "dashboard", "bem-vindo", "bem vindo", "painel", "sair", "conta",
]


def credential_stuff_test(
    login_url,
    user_field="username",
    pass_field="password",
    credentials=None,
    success_keywords=None,
    timeout=6,
    delay=0.4,
):
    """
    Testa um conjunto LIMITADO de credenciais comuns em um endpoint de login.

    Retorna lista de dicts {"usuario", "senha", "status", "sucesso", "indicio"}.
    """
    creds = (credentials or DEFAULT_CREDENTIALS)[:15]
    keywords = success_keywords or SUCCESS_KEYWORDS
    out = []

    for user, pwd in creds:
        try:
            r = requests.post(
                login_url,
                data={user_field: user, pass_field: pwd},
                headers=HEADERS,
                timeout=timeout,
                allow_redirects=False,
            )
            body = r.text[:3000].lower()
            location = r.headers.get("Location", "").lower()
            redirected_auth = r.status_code in (301, 302, 303) and "login" not in location
            keyword_hit = any(k in body for k in keywords)
            success = (r.status_code == 200 and keyword_hit) or redirected_auth
            indicio = "redirect" if redirected_auth else ("keyword" if keyword_hit else "")
            out.append(
                {
                    "usuario": user,
                    "senha": pwd,
                    "status": r.status_code,
                    "sucesso": bool(success),
                    "indicio": indicio,
                }
            )
        except Exception:
            out.append({"usuario": user, "senha": pwd, "status": "erro", "sucesso": False, "indicio": ""})
        time.sleep(delay)

    return out


def creds_findings(results):
    """
    Converte o resultado em achados padronizados.
    """
    from .engine import _finding

    if not results:
        return []

    sucessos = [r for r in results if r.get("sucesso")]

    if sucessos:
        usuarios = ", ".join(sorted({r["usuario"] for r in sucessos}))
        return [
            _finding(
                "Credenciais",
                f"{len(sucessos)} credencial(is) válida(s) no conjunto testado",
                "Acesso com credenciais comuns (LAB)",
                "Alta",
                f"As credenciais comuns testadas permitiram acesso no endpoint de login "
                f"(usuários: {usuarios}). Em ambiente real isso é crítico — em laboratório, "
                f"serve para demonstrar a importância de políticas de senha fortes.",
                "Achado Ativo",
                [
                    f"usuários acessados: {usuarios}",
                    "indícios: " + ", ".join(sorted({r['indicio'] for r in sucessos if r['indicio']})),
                ],
            )
        ]

    return [
        _finding(
            "Credenciais",
            "Credenciais comuns",
            "Nenhuma credencial do conjunto funcionou",
            "Baixa",
            f"Nenhuma das {len(results)} combinações de credenciais comuns obteve acesso "
            f"no endpoint de login testado.",
            "Controle OK",
            [f"{len(results)} combinações testadas com delay"],
        )
    ]
