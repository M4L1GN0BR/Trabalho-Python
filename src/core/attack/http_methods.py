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
Testador de métodos HTTP — OPTIONS (Allow) e TRACE.

Somente uso autorizado. Apenas OPTIONS/TRACE/GET, sem mutação de dados.
"""

import requests

HEADERS = {"User-Agent": "ASPM-Scanner/1.0"}

WRITE_METHODS = ("PUT", "DELETE", "PATCH", "POST")


def http_methods_test(url, timeout=5):
    """
    Consulta os métodos permitidos via OPTIONS e testa TRACE.

    Retorna lista de dicts {"method", "status", "allow", "methods"}.
    """
    out = []

    try:
        r = requests.options(
            url, headers=HEADERS, timeout=timeout, allow_redirects=False
        )
        allow = r.headers.get("Allow", "")
        methods = [m.strip().upper() for m in allow.split(",") if m.strip()]
        out.append(
            {
                "method": "OPTIONS",
                "status": r.status_code,
                "allow": allow,
                "methods": methods,
            }
        )
    except Exception:
        out.append({"method": "OPTIONS", "status": "erro", "allow": "", "methods": []})

    try:
        r2 = requests.request(
            "TRACE", url, headers=HEADERS, timeout=timeout, allow_redirects=False
        )
        out.append({"method": "TRACE", "status": r2.status_code, "allow": "", "methods": []})
    except Exception:
        out.append({"method": "TRACE", "status": "erro", "allow": "", "methods": []})

    return out


def methods_findings(results):
    """
    Converte o resultado em achados padronizados.
    """
    from .engine import _finding

    findings = []
    if not results:
        return findings

    options = next((r for r in results if r.get("method") == "OPTIONS"), {})
    trace = next((r for r in results if r.get("method") == "TRACE"), {})
    methods = options.get("methods", [])

    if "TRACE" in methods or trace.get("status") == 200:
        findings.append(
            _finding(
                "HTTP Methods",
                "TRACE habilitado",
                "TRACE responde",
                "Média",
                "O método TRACE está habilitado no alvo. TRACE permite ataques de "
                "Cross-Site Tracing (XST) e deve ser desabilitado no servidor.",
                "Achado Ativo",
                [f"TRACE retornou {trace.get('status')}", f"Allow: {options.get('allow', '')}"],
            )
        )

    write_allowed = [m for m in methods if m in WRITE_METHODS]
    if write_allowed:
        findings.append(
            _finding(
                "HTTP Methods",
                f"Métodos de escrita permitidos: {', '.join(write_allowed)}",
                "Permitido no Allow",
                "Baixa",
                f"O servidor anuncia métodos de escrita ({', '.join(write_allowed)}) "
                f"via OPTIONS. Revisar se são necessários e se há controle de acesso.",
                "Melhoria Recomendada",
                [f"Allow: {options.get('allow', '')}"],
            )
        )

    if not findings:
        findings.append(
            _finding(
                "HTTP Methods",
                "Métodos HTTP",
                "Sem método de risco anunciado",
                "Baixa",
                "O alvo não anunciou TRACE nem métodos de escrita via OPTIONS. "
                "Superfície de métodos aparentemente controlada.",
                "Controle OK",
                [f"Allow: {options.get('allow', '') or 'não informado'}"],
            )
        )

    return findings
