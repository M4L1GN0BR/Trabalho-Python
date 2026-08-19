"""
Módulo de detecção de segredos.

Contém as regras de detecção (AWS, GitHub, Google, JWT, connection strings),
mascaração de credenciais e parsers para o formato do Gitleaks.
Não depende de Streamlit.
"""

import base64
import json as _json
import re
import time

SECRET_RULES = [
    {
        "id": "AWS_ACCESS_KEY_ID",
        "descricao": "Possível chave de acesso AWS encontrada.",
        "regex": r"AKIA[0-9A-Z]{16}",
        "prioridade": "Alta",
    },
    {
        "id": "GITHUB_TOKEN",
        "descricao": "Possível token do GitHub encontrado.",
        "regex": r"ghp_[A-Za-z0-9_]{30,}",
        "prioridade": "Alta",
    },
    {
        "id": "GOOGLE_API_KEY",
        "descricao": "Possível chave de API do Google encontrada.",
        "regex": r"AIza[0-9A-Za-z\-_]{30,}",
        "prioridade": "Alta",
    },
    {
        "id": "PRIVATE_KEY",
        "descricao": "Possível chave privada encontrada.",
        "regex": r"-----BEGIN (RSA|OPENSSH|EC|DSA) PRIVATE KEY-----",
        "prioridade": "Alta",
    },
    {
        "id": "GENERIC_SECRET_ASSIGNMENT",
        "descricao": "Possível segredo definido diretamente no código.",
        "regex": r"(?i)(secret|token|password|passwd|api_key|apikey|client_secret)\s*[:=]\s*['\"][^'\"]{8,}['\"]",
        "prioridade": "Média",
    },
    {
        "id": "DATABASE_URL",
        "descricao": "Possível string de conexão de banco de dados encontrada.",
        "regex": r"(?i)(postgres|mysql|mongodb|redis)://[^\s'\"]+",
        "prioridade": "Alta",
    },
    {
        "id": "JWT_TOKEN",
        "descricao": "Possível token JWT encontrado.",
        "regex": r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}",
        "prioridade": "Média",
    },
]

# Regex para identificar segredos com padrão mais realista.
# Isso reduz falso positivo porque procura formatos comuns de chaves reais.
SECRET_REGEX_PATTERNS = [
    r"AKIA[0-9A-Z]{16}",
    r"ghp_[A-Za-z0-9_]{30,}",
    r"AIza[0-9A-Za-z\-_]{30,}",
    r"-----BEGIN (RSA|OPENSSH|EC|DSA) PRIVATE KEY-----",
    r"(?i)(secret|token|password|passwd|api_key|apikey)\s*[:=]\s*['\"][^'\"]{8,}['\"]",
]


def mask_secret(value):
    """
    Mascara o segredo para evitar exibir credenciais completas no dashboard.
    """
    value = str(value)

    if len(value) <= 10:
        return "***"

    return value[:4] + "***" + value[-4:]


def get_line_number(text, index):
    """
    Calcula a linha aproximada onde o segredo foi encontrado.
    """
    return text[:index].count("\n") + 1


def analyze_jwt(token):
    """
    Analisa um token JWT de forma passiva (sem validar assinatura).

    Decodifica header e payload (base64url) e identifica sinais como
    alg=none, ausência de expiração e claims sensíveis (role/admin).

    Retorna
    -------
    dict
        {"alg": str, "typ": str, "claims": dict, "flags": list[str]}
    """
    token = str(token).strip()
    parts = token.split(".")
    if len(parts) < 2:
        return {
            "alg": "?",
            "typ": "?",
            "claims": {},
            "flags": ["Formato JWT inválido (menos de 2 partes)"],
        }

    def _decode(part):
        try:
            padding = "=" * (-len(part) % 4)
            raw = base64.urlsafe_b64decode(part + padding)
            return _json.loads(raw.decode("utf-8"))
        except Exception:
            return None

    header = _decode(parts[0]) or {}
    payload = _decode(parts[1]) or {}

    flags = []
    alg = header.get("alg", "?")
    if str(alg).lower() == "none":
        flags.append("alg=none (assinatura desabilitada)")
    if not payload.get("exp"):
        flags.append("sem expiração (exp) no payload")
    elif isinstance(payload.get("exp"), (int, float)) and payload["exp"] < time.time():
        flags.append("token expirado")
    if payload.get("role") or payload.get("admin") or payload.get("is_admin"):
        flags.append("claim sensível presente (role/admin)")

    return {
        "alg": alg,
        "typ": header.get("typ", "JWT"),
        "claims": payload,
        "flags": flags,
    }


def format_jwt_summary(info):
    """Converte o resultado do analyze_jwt em texto curto para o dashboard."""
    partes = [f"alg={info['alg']}"]
    if info["flags"]:
        partes.append("; ".join(info["flags"]))
    return " | ".join(partes)


def scan_text_for_secrets(filename, text):
    """
    Procura segredos em um arquivo de texto usando regex.
    """
    findings = []

    for rule in SECRET_RULES:
        for match in re.finditer(rule["regex"], text):
            secret_value = match.group(0)
            line_number = get_line_number(text, match.start())

            finding = {
                "Origem": "Scanner Interno",
                "Regra": rule["id"],
                "Arquivo": filename,
                "Linha": line_number,
                "Prioridade": rule["prioridade"],
                "Segredo Mascarado": mask_secret(secret_value),
                "Descrição": rule["descricao"],
            }

            # JWT: enriquece com análise passiva do header/payload
            if rule["id"] == "JWT_TOKEN":
                jwt_info = analyze_jwt(secret_value)
                finding["Análise JWT"] = format_jwt_summary(jwt_info)
                if jwt_info["flags"]:
                    finding["Descrição"] += (
                        " Análise JWT: " + "; ".join(jwt_info["flags"]) + "."
                    )

            findings.append(finding)

    return findings


def parse_gitleaks_json(data):
    """
    Converte JSON do Gitleaks para o formato padrão do dashboard.
    O Gitleaks normalmente retorna uma lista de achados.
    """
    findings = []

    if isinstance(data, dict):
        possible_items = data.get("findings") or data.get("results") or []
    elif isinstance(data, list):
        possible_items = data
    else:
        possible_items = []

    for item in possible_items:
        rule = (
            item.get("RuleID")
            or item.get("rule")
            or item.get("Rule")
            or "GITLEAKS_SECRET"
        )
        description = (
            item.get("Description")
            or item.get("description")
            or "Possível segredo detectado pelo Gitleaks."
        )
        file_path = (
            item.get("File") or item.get("file") or item.get("path") or "Não informado"
        )
        line = (
            item.get("StartLine")
            or item.get("Line")
            or item.get("line")
            or "Não informado"
        )
        secret = item.get("Secret") or item.get("secret") or ""

        finding = {
            "Origem": "Gitleaks",
            "Regra": rule,
            "Arquivo": file_path,
            "Linha": line,
            "Prioridade": "Alta",
            "Segredo Mascarado": mask_secret(secret),
            "Descrição": description,
        }

        # JWT: enriquece com análise passiva do header/payload
        if "jwt" in str(rule).lower():
            jwt_info = analyze_jwt(secret)
            finding["Análise JWT"] = format_jwt_summary(jwt_info)
            if jwt_info["flags"]:
                finding["Descrição"] += (
                    " Análise JWT: " + "; ".join(jwt_info["flags"]) + "."
                )

        findings.append(finding)

    return findings


def calculate_secret_counts(secret_df):
    """
    Calcula contadores da aba Secrets.
    """
    if secret_df.empty:
        return 0, 0, 0

    high = secret_df[secret_df["Prioridade"] == "Alta"].shape[0]
    medium = secret_df[secret_df["Prioridade"] == "Média"].shape[0]
    low = secret_df[secret_df["Prioridade"] == "Baixa"].shape[0]

    return high, medium, low
