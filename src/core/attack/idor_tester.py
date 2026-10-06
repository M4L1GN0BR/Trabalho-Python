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
Testador de IDOR/enumeração de IDs — compara respostas para IDs diferentes.

Somente uso autorizado. Limites: poucos IDs, timeout curto, sem mutação de dados.
O resultado é sempre "possível" (heurística de baixa confiança).
"""

import requests

DEFAULT_IDS = [1, 2, 3, 100000]

HEADERS = {"User-Agent": "ASPM-Scanner/1.0"}


def idor_test(url, id_param="id", ids=None, timeout=5):
    """
    Testa possíveis IDOR: envia o mesmo endpoint com IDs diferentes e
    compara status/comprimento da resposta.

    url aceita placeholder `{id}` (ex: https://site.com/user/{id})
    ou usa query param (ex: https://site.com/user?id=1).

    Retorna lista de dicts {"id", "status", "length"}.
    """
    out = []
    for value in (ids or DEFAULT_IDS):
        if "{id}" in url:
            target = url.replace("{id}", str(value))
        else:
            sep = "&" if "?" in url else "?"
            target = f"{url}{sep}{id_param}={value}"
        try:
            r = requests.get(
                target, timeout=timeout, headers=HEADERS, allow_redirects=True
            )
            out.append({"id": value, "status": r.status_code, "length": len(r.text)})
        except Exception:
            out.append({"id": value, "status": "erro", "length": 0})
    return out


def idor_findings(results, id_param="id"):
    """
    Converte o resultado em achados padronizados (heurística de baixa confiança).
    """
    from .engine import _finding

    findings = []
    if not results:
        return findings

    ok = [r for r in results if r.get("status") == 200]
    bloqueados = [r for r in results if r.get("status") in (401, 403, 404)]

    lengths = {r.get("length") for r in ok}

    if len(ok) >= 3 and len(lengths) >= 2:
        findings.append(
            _finding(
                "IDOR",
                "Possível enumeração de IDs",
                f"{len(ok)} IDs retornaram 200",
                "Média",
                f"Vários IDs ({', '.join(str(r['id']) for r in ok[:5])}) retornaram HTTP 200 "
                f"com conteúdos de tamanhos diferentes, o que pode indicar enumeração de recursos "
                f"ou acesso a objetos de outros usuários. Requer validação manual.",
                "Achado Ativo",
                [
                    f"{len(ok)} respostas 200 com comprimentos variados: {sorted(lengths)[:5]}",
                    f"{len(bloqueados)} respostas bloqueadas (401/403/404)",
                ],
            )
        )
    elif ok and bloqueados:
        findings.append(
            _finding(
                "IDOR",
                "Possível enumeração de IDs",
                f"{len(ok)} acessíveis / {len(bloqueados)} bloqueados",
                "Baixa",
                f"Alguns IDs retornaram 200 e outros foram bloqueados. Padrão comum de autorização, "
                f"mas vale revisar os IDs acessíveis manualmente.",
                "Melhoria Recomendada",
                [f"IDs 200: {len(ok)} | bloqueados: {len(bloqueados)}"],
            )
        )
    else:
        findings.append(
            _finding(
                "IDOR",
                "Teste de IDs",
                "Sem indício claro de IDOR",
                "Baixa",
                f"Os IDs testados não mostraram padrão claro de enumeração ou acesso indevido "
                f"(sem respostas 200 variadas nem mistura consistente).",
                "Controle OK",
                [f"{len(results)} IDs testados via parâmetro '{id_param}'"],
            )
        )

    return findings
