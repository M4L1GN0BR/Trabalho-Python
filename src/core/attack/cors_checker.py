"""
Testador de CORS — envia Origin externa e verifica Access-Control-Allow-Origin.

Somente uso autorizado. Apenas GET com header Origin modificado.
"""

import requests

HEADERS = {"User-Agent": "ASPM-Scanner/1.0"}

TEST_ORIGINS = [
    "https://evil.example.com",
    "https://attacker.com",
]


def cors_check(url, origins=None, timeout=5):
    """
    Envia requisições com Origin de terceiros e captura a política CORS do alvo.

    Retorna lista de dicts {"origin_enviada", "status", "acao", "acac"}.
    """
    out = []
    for origin in (origins or TEST_ORIGINS):
        try:
            r = requests.get(
                url,
                headers={**HEADERS, "Origin": origin},
                timeout=timeout,
                allow_redirects=False,
            )
            out.append(
                {
                    "origin_enviada": origin,
                    "status": r.status_code,
                    "acao": r.headers.get("Access-Control-Allow-Origin", ""),
                    "acac": r.headers.get("Access-Control-Allow-Credentials", ""),
                }
            )
        except Exception:
            out.append({"origin_enviada": origin, "status": "erro", "acao": "", "acac": ""})
    return out


def cors_findings(results):
    """
    Converte o resultado em achados padronizados.
    """
    from .engine import _finding

    findings = []
    if not results:
        return findings

    echo = [
        r for r in results
        if r.get("acao") and r["acao"] == r.get("origin_enviada")
    ]
    wildcard = [r for r in results if r.get("acao") == "*"]

    if echo and any(r.get("acac", "").lower() == "true" for r in echo):
        findings.append(
            _finding(
                "CORS",
                "CORS reflete origem arbitrária",
                "Reflexo de origem + credenciais",
                "Alta",
                "O servidor reflete a Origin enviada e permite credenciais "
                "(Access-Control-Allow-Credentials: true). Isso permite que "
                "qualquer site leia respostas autenticadas do alvo.",
                "Achado Ativo",
                [f"Origem '{echo[0]['origin_enviada']}' ecoada com credenciais"],
            )
        )
    elif echo:
        findings.append(
            _finding(
                "CORS",
                "CORS reflete origem arbitrária",
                "Reflexo de origem",
                "Média",
                "O servidor reflete a Origin enviada na resposta "
                "(Access-Control-Allow-Origin). Sem credenciais o impacto é menor, "
                "mas origens arbitrárias não deveriam ser permitidas.",
                "Achado Ativo",
                [f"Origem '{echo[0]['origin_enviada']}' ecoada sem credenciais"],
            )
        )
    elif wildcard:
        findings.append(
            _finding(
                "CORS",
                "CORS com wildcard",
                "Access-Control-Allow-Origin: *",
                "Média",
                "O servidor responde Access-Control-Allow-Origin: * (qualquer origem). "
                "Wildcard impede uso com credenciais no navegador, mas reduz o controle "
                "de quem pode consumir a API.",
                "Melhoria Recomendada",
                ["Access-Control-Allow-Origin: *"],
            )
        )
    else:
        findings.append(
            _finding(
                "CORS",
                "Política CORS",
                "Sem reflexo de origem",
                "Baixa",
                "O alvo não refletiu Origins arbitrárias na resposta. Política CORS "
                "aparentemente restrita.",
                "Controle OK",
                [f"{len(results)} Origins testadas"],
            )
        )

    return findings
