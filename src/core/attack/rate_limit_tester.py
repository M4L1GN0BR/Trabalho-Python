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
Testador de rate limit — envia poucas requisições e verifica se há limitação.

Somente uso autorizado. Limite: 15 requisições GET com pequeno intervalo.
Não tenta contornar limitação nem autenticação.
"""

import time

import requests

HEADERS = {"User-Agent": "ASPM-Scanner/1.0"}


def rate_limit_test(url, n=15, delay=0.05, timeout=5):
    """
    Envia n requisições GET rápidas e retorna a lista de status codes.

    Retorna lista de status (int ou "erro").
    """
    statuses = []
    for _ in range(n):
        try:
            r = requests.get(url, timeout=timeout, headers=HEADERS)
            statuses.append(r.status_code)
        except Exception:
            statuses.append("erro")
        time.sleep(delay)
    return statuses


def rate_findings(statuses):
    """
    Converte o resultado em achados padronizados.
    """
    from .engine import _finding

    if not statuses:
        return []

    n = len(statuses)
    ok = sum(1 for s in statuses if s == 200)
    bloqueados = sum(1 for s in statuses if s == 429)

    if any(s == 429 for s in statuses):
        return [
            _finding(
                "Rate Limit",
                f"{n} requisições ao alvo",
                f"Rate limit detectado ({bloqueados} bloqueadas)",
                "Baixa",
                f"O alvo respondeu {bloqueados} de {n} requisições com 429, "
                f"indicando presença de limitação de taxa.",
                "Controle OK",
                [f"status codes: {_resume_statuses(statuses)}"],
            )
        ]

    if all(s == "erro" for s in statuses):
        return [
            _finding(
                "Rate Limit",
                f"{n} requisições ao alvo",
                "Teste inconclusivo",
                "Baixa",
                f"Todas as {n} requisições falharam por erro de conexão "
                f"(alvo fora do ar/DNS), impossibilitando avaliar o rate limit.",
                "Teste inconclusivo",
                [f"status codes: {_resume_statuses(statuses)}"],
            )
        ]

    return [
        _finding(
            "Rate Limit",
            f"{n} requisições ao alvo",
            "Sem indício de rate limit",
            "Média",
            f"{ok} de {n} requisições retornaram 200 sem bloqueio ou resposta 429. "
            f"Ausência de rate limit aparente permite abuso (brute force, scraping). "
            f"Recomendável implementar limitação de taxa (OWASP API4:2023).",
            "Achado Ativo",
            [f"status codes: {_resume_statuses(statuses)}"],
        )
    ]


def _resume_statuses(statuses):
    """Resume a lista de status para exibição (ex: 200x15)."""
    from collections import Counter

    return ", ".join(f"{k}x{v}" for k, v in Counter(str(s) for s in statuses).items())
