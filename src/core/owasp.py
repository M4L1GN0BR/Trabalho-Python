"""
Mapeamento de achados para o OWASP Top 10 (2025).

Classifica cada evidência normalizada (Evidence Engine) em uma categoria
do OWASP Top 10 usando padrões de texto, IDs de regra (Semgrep/Bandit),
ferramenta de origem e CVEs. Permite que o Risk Engine, o dashboard e o
relatório executivo mostrem as categorias de risco mais presentes no ambiente.

Observação: o mapeamento é automático e aproximado (baseado em padrões).
Recomenda-se revisão manual para confirmar a categoria de cada achado.

Sem dependências externas — funciona offline.
"""

OWASP_TOP10 = {
    "A01": {
        "id": "A01",
        "label": "A01:2025",
        "name": "Access Control",
        "name_pt": "Controle de Acesso Quebrado",
    },
    "A02": {
        "id": "A02",
        "label": "A02:2025",
        "name": "Cryptographic Failures",
        "name_pt": "Falhas Criptográficas",
    },
    "A03": {
        "id": "A03",
        "label": "A03:2025",
        "name": "Injection",
        "name_pt": "Injeção",
    },
    "A04": {
        "id": "A04",
        "label": "A04:2025",
        "name": "Insecure Design",
        "name_pt": "Design Inseguro",
    },
    "A05": {
        "id": "A05",
        "label": "A05:2025",
        "name": "Security Misconfiguration",
        "name_pt": "Configuração Incorreta de Segurança",
    },
    "A06": {
        "id": "A06",
        "label": "A06:2025",
        "name": "Vulnerable and Outdated Components",
        "name_pt": "Componentes Vulneráveis e Desatualizados",
    },
    "A07": {
        "id": "A07",
        "label": "A07:2025",
        "name": "Identification and Authentication Failures",
        "name_pt": "Falhas de Identificação e Autenticação",
    },
    "A08": {
        "id": "A08",
        "label": "A08:2025",
        "name": "Software and Data Integrity Failures",
        "name_pt": "Falhas de Integridade de Software e Dados",
    },
    "A09": {
        "id": "A09",
        "label": "A09:2025",
        "name": "Security Logging and Monitoring Failures",
        "name_pt": "Falhas de Registro e Monitoramento de Segurança",
    },
    "A10": {
        "id": "A10",
        "label": "A10:2025",
        "name": "Server-Side Request Forgery",
        "name_pt": "Falsificação de Solicitação no Lado do Servidor (SSRF)",
    },
    "OUTRO": {
        "id": "OUTRO",
        "label": "—",
        "name": "Outros / Não mapeado",
        "name_pt": "Outros / Não mapeado",
    },
}

# Palavras-chave por categoria (ordem de verificação importa: as mais
# específicas vêm primeiro).
_RULES = [
    # A10 - SSRF (mais específico, evita conflito com "url"/"request")
    ("A10", ["ssrf", "server-side request", "server side request"]),
    # A08 - Deserialização / integridade
    ("A08", ["deserialization", "pickle", "yaml.load", "yaml load", "integrity", "untrusted"]),
    # A03 - Injeção (SQL, XSS, comando, LDAP, eval, SSTI)
    (
        "A03",
        [
            "sql", "injection", "sqli", "eval", "xss", "command injection",
            "shell=True", "os.system", "subprocess", "ldap", "ssti",
            "query construction", "string-based", "payload",
        ],
    ),
    # A01 - Controle de acesso / traversal
    ("A01", ["access control", "broken access", "authorization", "idor",
             "path traversal", "traversal", "zip-slip", "privilege",
             "force browse", "missing access"]),
    # A02 - Criptografia / dados sensíveis
    (
        "A02",
        [
            "cryptographic", "crypto", "md5", "sha1", "cipher", "hashlib",
            "weak crypto", "tls", "ssl", "certificate", "openssl", "jwt",
            "secret", "api key", "apikey", "token", "private key",
            "encryption key", "verify=False",
        ],
    ),
    # A07 - Autenticação
    (
        "A07",
        [
            "authentication", "auth", "password", "login", "credential",
            "brute", "session", "hardcoded password", "bypass",
        ],
    ),
    # A05 - Configuração incorreta
    (
        "A05",
        [
            "misconfiguration", "misconfig", "header", "cors", "x-powered-by",
            "debug", "directory listing", "default", "stack trace", "verbose",
            "error handling", "phpinfo", "security headers",
        ],
    ),
    # A04 - Design inseguro
    ("A04", ["insecure design", "business logic", "rate limit", "design flaw"]),
    # A09 - Logging/monitoramento
    ("A09", ["logging", "monitoring", "log injection", "audit", "observability"]),
    # A06 - Componentes vulneráveis
    ("A06", ["cve", "dependency", "vulnerable", "outdated", "component",
             "library", "package", "upgrade", "fix_versions"]),
]

# IDs de regra (Semgrep check_id / Bandit test_name) por categoria.
_ID_RULES = {
    "A01": ["path-traversal", "idor"],
    "A02": ["weak-crypto", "insecure-hashlib", "jwt-hardcode", "smtplib",
            "ssl-verify", "b303", "b311", "b324", "b501", "b402", "b303"],
    "A03": ["sql", "xss", "eval", "command-injection", "dangerous-system-call",
            "ldap", "b608", "b602", "b307", "b404", "b506"],
    "A05": ["cors", "b110", "b112", "b201", "b325", "x-powered-by"],
    "A06": ["sca", "cve"],
    "A07": ["hardcoded-password", "b105", "b106", "b107"],
    "A08": ["deserialization", "yaml-load", "b301"],
    "A10": ["ssrf"],
}


def _evidence_text(evidence):
    """Monta o texto combinado da evidência para busca de padrões."""
    parts = [
        evidence.get("tool"),
        evidence.get("category"),
        evidence.get("title"),
        evidence.get("evidence"),
        evidence.get("function"),
        evidence.get("cve"),
        evidence.get("dependency"),
        evidence.get("endpoint"),
    ]
    return " ".join(str(p) for p in parts if p).lower()


def classify_evidence_owasp(evidence):
    """
    Classifica uma evidência normalizada em uma categoria OWASP Top 10.

    Retorna
    -------
    dict
        Entrada de OWASP_TOP10 ({"id", "label", "name", "name_pt"}).
    """
    text = _evidence_text(evidence)
    tool = str(evidence.get("tool", "")).lower()

    # Ferramenta SCA: todo CVE é componente vulnerável (A06).
    if tool == "sca":
        return OWASP_TOP10["A06"]

    # Secrets/Gitleaks: credenciais expostas = falha criptográfica/dado sensível (A02).
    if tool in ("secrets", "gitleaks"):
        return OWASP_TOP10["A02"]

    # IDs de regra conhecidos (mais precisos que palavras soltas).
    rule_id = str(evidence.get("function") or evidence.get("title") or "").lower()
    for cat, ids in _ID_RULES.items():
        for rid in ids:
            if rid in rule_id:
                return OWASP_TOP10[cat]

    # Palavras-chave no texto combinado.
    for cat, keywords in _RULES:
        for kw in keywords:
            if kw in text:
                return OWASP_TOP10[cat]

    return OWASP_TOP10["OUTRO"]


def enrich_evidences(evidences):
    """
    Adiciona os campos owasp_* a cada evidência da lista.

    Campos adicionados: owasp_id, owasp_label, owasp_name, owasp_name_pt.
    """
    enriched = []
    for ev in evidences:
        ev = dict(ev)
        ow = classify_evidence_owasp(ev)
        ev["owasp_id"] = ow["id"]
        ev["owasp_label"] = ow["label"]
        ev["owasp_name"] = ow["name"]
        ev["owasp_name_pt"] = ow["name_pt"]
        enriched.append(ev)
    return enriched


def top_owasp_categories(evidences, top_n=5):
    """
    Retorna as categorias OWASP mais frequentes no ambiente.

    Parâmetros
    ----------
    evidences : list
        Lista de evidências (já enriquecidas ou não).
    top_n : int
        Quantas categorias retornar.

    Retorna
    -------
    list[dict]
        [{"label": "A03:2025", "name": "Injection", "count": 4}, ...]
    """
    from collections import Counter

    enriched = enrich_evidences(evidences)
    counts = Counter(e["owasp_label"] for e in enriched)

    items = []
    for label, count in counts.most_common(top_n):
        info = next(
            (v for v in OWASP_TOP10.values() if v["label"] == label),
            OWASP_TOP10["OUTRO"],
        )
        items.append(
            {"label": label, "name": info["name"], "name_pt": info["name_pt"], "count": count}
        )
    return items
