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
