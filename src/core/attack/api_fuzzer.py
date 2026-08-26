"""
API fuzzing passivo — tenta caminhos comuns de API e verifica respostas.

Somente uso autorizado. Lista curta de caminhos conhecidos, apenas GET,
timeout curto, sem payloads de exploração.
"""

import requests

API_PATHS = [
    "/api/users", "/api/v1/users", "/api/user", "/api/me", "/api/account",
    "/api/admin", "/api/config", "/api/health", "/api/token", "/api/login",
    "/api/docs", "/swagger.json", "/swagger-ui/", "/openapi.json", "/graphql",
    "/v1/", "/v2/", "/internal", "/debug", "/actuator", "/actuator/health",
    "/api/orders", "/api/payments", "/api/export", "/api/backup",
]

# Caminhos que merecem destaque se retornarem 200
SENSITIVE_HINTS = [
    "admin", "config", "internal", "debug", "token", "actuator",
    "users", "account", "orders", "payments", "export", "backup",
]

HEADERS = {"User-Agent": "ASPM-Scanner/1.0"}


def api_fuzz(base_url, paths=None, timeout=5):
    """
    Tenta caminhos comuns de API via GET e registra status/content-type.

    Retorna lista de dicts {"path", "status", "content_type", "length"}.
    """
    out = []
    for path in (paths or API_PATHS):
        target = base_url.rstrip("/") + path
        try:
            r = requests.get(
                target, timeout=timeout, headers=HEADERS, allow_redirects=True
            )
            out.append(
                {
                    "path": path,
                    "status": r.status_code,
                    "content_type": r.headers.get("Content-Type", ""),
                    "length": len(r.text),
                }
            )
        except Exception:
            out.append({"path": path, "status": "erro", "content_type": "", "length": 0})
    return out


def fuzz_findings(results):
    """
    Converte o resultado em achados padronizados.
    """
    from .engine import _finding

    findings = []
    if not results:
        return findings

    acessiveis = [r for r in results if r.get("status") == 200]
    protegidos = [r for r in results if r.get("status") in (401, 403)]
    inexistentes = [r for r in results if r.get("status") == 404]

    sensiveis = [
        r for r in acessiveis
        if any(h in r.get("path", "").lower() for h in SENSITIVE_HINTS)
    ]

    for r in sensiveis:
        findings.append(
            _finding(
                "API Fuzzing",
                r["path"],
                f"Acessível ({r['status']})",
                "Média",
                f"O caminho de API {r['path']} respondeu HTTP 200 "
                f"(Content-Type: {r['content_type'] or 'não informado'}). "
                f"Caminho potencialmente sensível acessível sem autenticação — validar manualmente.",
                "Achado Ativo",
                [f"GET {r['path']} -> {r['status']}", f"tamanho: {r['length']} bytes"],
            )
        )

    docs = [
        r for r in acessiveis
        if any(h in r["path"].lower() for h in ("swagger", "openapi", "docs", "graphql"))
    ]
    for r in docs:
        if r not in sensiveis:
            findings.append(
                _finding(
                    "API Fuzzing",
                    r["path"],
                    "Documentação/API acessível",
                    "Média",
                    f"Documentação ou interface de API acessível em {r['path']} (HTTP 200). "
                    f"Revisar se deve ser pública.",
                    "Achado Ativo",
                    [f"GET {r['path']} -> {r['status']}"],
                )
            )

    if protegidos:
        findings.append(
            _finding(
                "API Fuzzing",
                f"{len(protegidos)} caminhos protegidos",
                "Protegidos (401/403)",
                "Baixa",
                f"{len(protegidos)} caminhos de API retornaram 401/403, indicando controle de acesso. "
                f"Exemplos: {', '.join(r['path'] for r in protegidos[:5])}",
                "Controle OK",
                [f"{len(protegidos)} respostas 401/403"],
            )
        )

    if not acessiveis and not protegidos:
        findings.append(
            _finding(
                "API Fuzzing",
                "Caminhos de API",
                "Nenhum caminho relevante encontrado",
                "Baixa",
                f"{len(inexistentes)} caminhos retornaram 404. Nenhuma rota de API óbvia exposta "
                f"na lista testada.",
                "Controle OK",
                [f"{len(results)} caminhos testados"],
            )
        )

    return findings
