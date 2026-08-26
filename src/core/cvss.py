"""
CVSS v3.1 — Calculadora de Base Score (implementação pura, sem dependências).

Implementa a especificação FIRST CVSS v3.1 para calcular o Base Score a partir
de um vetor como:

    CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H

Também fornece severidade qualitativa e descritores legíveis em pt-BR.

Fonte: https://www.first.org/cvss/specification-document

Valores de referência (validados em testes):
    AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H        -> 9.8 (Critical)
    AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H        -> 10.0 (Critical)
"""

import math

# ── Escalas de valores da especificação ──────────────────────────────────────
_AV = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC = {"L": 0.77, "H": 0.44}
_PR = {
    "U": {"N": 0.85, "L": 0.62, "H": 0.27},
    "C": {"N": 0.85, "L": 0.68, "H": 0.50},
}
_UI = {"N": 0.85, "R": 0.62}
_CI = {"H": 0.56, "L": 0.22, "N": 0.0}

_AV_LABEL = {"N": "Rede (Network)", "A": "Rede adjacente", "L": "Local", "P": "Físico"}
_AC_LABEL = {"L": "Baixa", "H": "Alta"}
_PR_LABEL = {"N": "Nenhum", "L": "Baixo", "H": "Alto"}
_UI_LABEL = {"N": "Nenhum", "R": "Requerido"}
_S_LABEL = {"U": "Inalterado", "C": "Alterado"}
_IMPACT_LABEL = {"H": "Alto", "L": "Baixo", "N": "Nenhum"}

VALID_METRICS = {"AV", "AC", "PR", "UI", "S", "C", "I", "A"}
VALID_VALUES = {
    "AV": set(_AV),
    "AC": set(_AC),
    "PR": set(_PR["U"]),
    "UI": set(_UI),
    "S": set(_S_LABEL),
    "C": set(_CI),
    "I": set(_CI),
    "A": set(_CI),
}

_DEFAULT_VECTOR = {
    "AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U",
    "C": "H", "I": "H", "A": "H",
}


def _roundup(value):
    """Arredonda para cima com 1 casa decimal (roundup da especificação)."""
    return math.ceil(value * 10.0) / 10.0


def parse_vector(vector):
    """
    Converte um vetor CVSS v3.1 em dict de métricas.

    Aceita prefixo "CVSS:3.1/" ou apenas as métricas. Métricas ausentes usam
    o padrão da especificação (tolerante a vetores parciais).
    """
    vec = {**_DEFAULT_VECTOR}

    # Aceita dict de métricas (ex.: o dict retornado por esta própria função e
    # reutilizado por base_score/score_vector/vector_description). Sem isso,
    # str(dict) viraria um vetor inválido e tudo cairia no _DEFAULT_VECTOR (9.8).
    if isinstance(vector, dict):
        for key, value in vector.items():
            if key in VALID_METRICS and str(value).upper() in VALID_VALUES.get(key, set()):
                vec[key] = str(value).upper()
        return vec

    raw = str(vector or "").strip()

    for prefix in ("CVSS:3.1/", "CVSS:3.0/", "cvss:3.1/", "cvss:3.0/"):
        if raw.lower().startswith(prefix.lower()):
            raw = raw[len(prefix):]
            break

    for part in raw.split("/"):
        part = part.strip()
        if not part or ":" not in part:
            continue
        key, _, value = part.partition(":")
        key = key.strip().upper()
        value = value.strip().upper()
        if key in VALID_METRICS and value in VALID_VALUES.get(key, set()):
            vec[key] = value

    return vec


def base_score(vector):
    """
    Calcula o Base Score CVSS v3.1 (0.0-10.0) a partir de um vetor.
    """
    v = parse_vector(vector)
    scope_changed = v["S"] == "C"

    iss = 1.0 - (
        (1.0 - _CI[v["C"]]) * (1.0 - _CI[v["I"]]) * (1.0 - _CI[v["A"]])
    )

    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss

    pr = _PR["C" if scope_changed else "U"][v["PR"]]
    exploitability = 8.22 * _AV[v["AV"]] * _AC[v["AC"]] * pr * _UI[v["UI"]]

    if impact <= 0:
        return 0.0

    if scope_changed:
        raw = min(1.08 * (impact + exploitability), 10.0)
    else:
        raw = min(impact + exploitability, 10.0)

    return round(_roundup(raw), 1)


def severity(score):
    """Classifica um score na escala qualitativa CVSS v3.1."""
    if score >= 9.0:
        return "Crítica"
    if score >= 7.0:
        return "Alta"
    if score >= 4.0:
        return "Média"
    if score >= 0.1:
        return "Baixa"
    return "Nenhuma"


def severity_code(score):
    """Versão em inglês (CRITICAL/HIGH/MEDIUM/LOW/NONE) para integrações."""
    return {
        "Crítica": "CRITICAL",
        "Alta": "HIGH",
        "Média": "MEDIUM",
        "Baixa": "LOW",
        "Nenhuma": "NONE",
    }[severity(score)]


def vector_description(vector):
    """Traduz um vetor CVSS para descritores legíveis em pt-BR."""
    v = parse_vector(vector)
    return {
        "Vetor de Ataque (AV)": _AV_LABEL[v["AV"]],
        "Complexidade (AC)": _AC_LABEL[v["AC"]],
        "Privilégios (PR)": _PR_LABEL[v["PR"]],
        "Interação (UI)": _UI_LABEL[v["UI"]],
        "Escopo (S)": _S_LABEL[v["S"]],
        "Confidencialidade (C)": _IMPACT_LABEL[v["C"]],
        "Integridade (I)": _IMPACT_LABEL[v["I"]],
        "Disponibilidade (A)": _IMPACT_LABEL[v["A"]],
    }


def score_vector(vector):
    """Análise completa de um vetor (útil para APIs/UI)."""
    parsed = parse_vector(vector)
    score = base_score(parsed)
    canonical = "CVSS:3.1/" + "/".join(f"{k}:{v}" for k, v in parsed.items())
    return {
        "vector": canonical,
        "score": score,
        "severity": severity(score),
        "severity_code": severity_code(score),
        "description": vector_description(parsed),
    }


# ── Vetores típicos por severidade (para estimativa quando a ferramenta
#    não fornece o vetor — ex.: pip-audit). ─────────────────────────────────

SEVERITY_TYPICAL_VECTOR = {
    "CRITICAL": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",  # 10.0
    "HIGH": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",     # 9.8
    "MEDIUM": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:L",   # 6.1
    "LOW": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N",      # 4.3
    "INFO": "CVSS:3.1/AV:L/AC:H/PR:N/UI:R/S:U/C:N/I:N/A:N",     # 0.0
}


def estimate_from_severity(severity_label):
    """
    Estima um score CVSS a partir de uma severidade qualitativa.

    Usado para enriquecer achados de ferramentas que não publicam vetor
    (ex.: pip-audit). O score retornado é o score do vetor típico.
    """
    key = str(severity_label or "").upper()
    vector = SEVERITY_TYPICAL_VECTOR.get(key, SEVERITY_TYPICAL_VECTOR["MEDIUM"])
    return base_score(vector), vector
