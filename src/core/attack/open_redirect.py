"""
Testador de open redirect — parâmetros comuns de redirecionamento.

Somente uso autorizado. Apenas GET com allow_redirects=False (não segue o link).
"""

from urllib.parse import quote

import requests

HEADERS = {"User-Agent": "ASPM-Scanner/1.0"}

REDIRECT_PARAMS = [
    "url", "redirect", "next", "returnUrl", "return_url", "dest", "target", "goto", "r",
]

EXTERNAL_DOMAIN = "evil.example.com"
EXTERNAL_URL = f"https://{EXTERNAL_DOMAIN}/"


def open_redirect_test(url, params=None, timeout=5):
    """
    Testa parâmetros comuns de redirecionamento apontando para domínio externo.

    Retorna lista de dicts {"param", "status", "location"}.
    """
    out = []
    for param in (params or REDIRECT_PARAMS):
        sep = "&" if "?" in url else "?"
        target = f"{url}{sep}{param}={quote(EXTERNAL_URL, safe='')}"
        try:
            r = requests.get(
                target,
                headers=HEADERS,
                timeout=timeout,
                allow_redirects=False,
            )
            out.append({"param": param, "status": r.status_code, "location": r.headers.get("Location", "")})
        except Exception:
            out.append({"param": param, "status": "erro", "location": ""})
    return out


def redirect_findings(results):
    """
    Converte o resultado em achados padronizados.
    """
    from .engine import _finding

    findings = []
    if not results:
        return findings

    abertos = [
        r for r in results
        if EXTERNAL_DOMAIN in r.get("location", "")
    ]
    if abertos:
        findings.append(
            _finding(
                "Open Redirect",
                f"Redirecionamento aberto via {', '.join(r['param'] for r in abertos[:5])}",
                "Redireciona para domínio externo",
                "Média",
                "O alvo redireciona para domínio externo controlado pelo parâmetro. "
                "Open redirect pode ser usado em phishing e para driblar validações "
                "de URL em fluxos de autenticação.",
                "Achado Ativo",
                [f"Location: {abertos[0]['location']}", f"parâmetro: {abertos[0]['param']}"],
            )
        )
    else:
        findings.append(
            _finding(
                "Open Redirect",
                "Teste de redirecionamento",
                "Sem indício de open redirect",
                "Baixa",
                f"Nenhum dos {len(results)} parâmetros de redirecionamento testados "
                f"apontou para domínio externo.",
                "Controle OK",
                [f"{len(results)} parâmetros testados"],
            )
        )

    return findings
