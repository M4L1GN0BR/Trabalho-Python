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
Módulo de reconhecimento ativo — scan de portas TCP com banner grabbing.

Somente uso autorizado (laboratório, DVWA, Juice Shop, alvos próprios).
Testar terceiros sem autorização é ilegal no Brasil (Lei 12.737/2012).

Limites: portas comuns, timeout curto, sem payloads destrutivos.
"""

import socket

# (porta, serviço típico)
COMMON_PORTS = [
    (21, "FTP"), (22, "SSH"), (23, "Telnet"), (25, "SMTP"), (53, "DNS"),
    (80, "HTTP"), (110, "POP3"), (143, "IMAP"), (443, "HTTPS"), (445, "SMB"),
    (993, "IMAPS"), (995, "POP3S"), (1433, "MSSQL"), (1521, "Oracle"),
    (2049, "NFS"), (3306, "MySQL"), (3389, "RDP"), (5432, "PostgreSQL"),
    (5984, "CouchDB"), (6379, "Redis"), (8000, "HTTP-alt"), (8080, "HTTP-proxy"),
    (8443, "HTTPS-alt"), (8888, "HTTP-alt"), (9200, "Elasticsearch"),
    (27017, "MongoDB"),
]

# Portas de serviços sensíveis (banco, admin, arquivo, remoto)
SENSITIVE_PORTS = {
    21, 22, 23, 25, 445, 1433, 1521, 2049, 3306, 3389, 5432, 5984, 6379, 9200, 27017,
}

WEB_PORTS = {80, 443, 8000, 8080, 8443, 8888}


def active_recon(host, ports=None, timeout=2):
    """
    Varre portas comuns via TCP connect e tenta capturar banner.

    Retorna lista de dicts {"porta", "servico", "banner"}.
    """
    results = []
    for port, service in (ports or COMMON_PORTS):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        try:
            sock.connect((host, port))
            banner = ""
            try:
                sock.send(b"\r\n\r\n")
                banner = sock.recv(120).decode("utf-8", errors="replace").strip()[:80]
            except Exception:
                pass
            results.append({"porta": port, "servico": service, "banner": banner})
        except Exception:
            pass
        finally:
            sock.close()
    return results


def recon_findings(ports, host):
    """
    Converte o resultado do scan de portas em achados padronizados.
    """
    from .engine import _finding

    findings = []
    if not ports:
        findings.append(
            _finding(
                "Recon Ativo",
                "Portas comuns",
                "Nenhuma porta comum aberta",
                "Baixa",
                f"Nenhuma das portas comuns testadas está aberta em {host}.",
                "Controle OK",
                ["Scan TCP connect em 26 portas comuns"],
            )
        )
        return findings

    for p in ports:
        item = f"Porta {p['porta']} ({p['servico']})"
        banner_txt = f" | banner: {p['banner']}" if p["banner"] else ""
        if p["porta"] in SENSITIVE_PORTS:
            priority = (
                "Alta"
                if p["porta"] in (3306, 5432, 6379, 9200, 27017, 1433, 1521, 445, 3389, 23, 21)
                else "Média"
            )
            findings.append(
                _finding(
                    "Recon Ativo",
                    item,
                    "Aberta (serviço sensível)",
                    priority,
                    f"A porta {p['porta']} ({p['servico']}) está aberta e acessível em {host}. "
                    f"Serviços sensíveis expostos aumentam a superfície de ataque.{banner_txt}",
                    "Achado Ativo",
                    [f"TCP connect OK na porta {p['porta']}", p["banner"]]
                    if p["banner"]
                    else [f"TCP connect OK na porta {p['porta']}"],
                )
            )
        elif p["porta"] in WEB_PORTS:
            findings.append(
                _finding(
                    "Recon Ativo",
                    item,
                    "Aberta (serviço web)",
                    "Baixa",
                    f"Porta web {p['porta']} ({p['servico']}) aberta em {host} — esperado para aplicações web.{banner_txt}",
                    "Controle OK",
                    [f"TCP connect OK na porta {p['porta']}"],
                )
            )
        else:
            findings.append(
                _finding(
                    "Recon Ativo",
                    item,
                    "Aberta",
                    "Baixa",
                    f"A porta {p['porta']} ({p['servico']}) está aberta em {host}. "
                    f"Revisar necessidade de exposição pública.{banner_txt}",
                    "Melhoria Recomendada",
                    [f"TCP connect OK na porta {p['porta']}"],
                )
            )

    return findings
