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
Proteção contra SSRF (Server-Side Request Forgery).

Valida se um alvo resolve apenas para endereços públicos antes de
permitir requisições HTTP a partir do dashboard. Stdlib puro — sem
dependência de Streamlit.
"""

import ipaddress
import socket
from urllib.parse import urlparse


def check_target(url, allow_private=False):
    """
    Valida se a URL é segura para requisição (anti-SSRF).

    Retorna (ok, mensagem). Quando ok é False, a mensagem explica o
    motivo do bloqueio e como prosseguir (laboratório local).
    """
    parsed = urlparse(url)
    if not parsed.scheme:
        parsed = urlparse(f"http://{url}")

    host = parsed.hostname
    if not host:
        return (False, "URL inválida: host não identificado.")

    try:
        addresses = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return (False, "Não foi possível resolver o host (DNS).")

    for addr_info in addresses:
        try:
            ip = ipaddress.ip_address(addr_info[4][0])
        except ValueError:
            continue

        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_reserved
            or ip.is_unspecified
        ):
            if not allow_private:
                return (
                    False,
                    "Alvo bloqueado: resolve para IP interno/privado (SSRF). "
                    "Para laboratórios locais, marque a opção de permitir alvos privados.",
                )

    return (True, "")


def resolve_and_report(url):
    """
    Resolve o host e retorna os endereços IP encontrados (exibição).
    """
    parsed = urlparse(url)
    if not parsed.scheme:
        parsed = urlparse(f"http://{url}")

    host = parsed.hostname
    if not host:
        return []

    try:
        addresses = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return []

    return sorted({addr_info[4][0] for addr_info in addresses})
