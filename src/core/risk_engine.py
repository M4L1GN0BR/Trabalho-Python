"""
Risk Engine — motor consolidado de risco para ASPM.

Não soma simplesmente alertas. Pontua cada evidência por:
- Severidade da ferramenta
- Palavras-chave de risco no texto (rce, sqli, secret...)
- Evidência concreta (código, resposta HTTP, payload)
- Correlação entre fontes (mesmo alvo apontado por várias ferramentas)

Gera score global, classificação, contagem por severidade,
riscos prioritários e justificativa.
"""

SEV_SCORE = {
    "CRITICAL": 10,
    "HIGH": 7,
    "ERROR": 7,
    "MEDIUM": 4,
    "WARNING": 4,
    "LOW": 1,
    "INFO": 0,
}

KEYWORD_SCORE = {
    "rce": 9, "remote code": 9, "command injection": 9, "os.system": 8, "subprocess": 6,
    "sqli": 8, "sql injection": 8, "sql": 5,
    "ssrf": 7, "path traversal": 7, "lfi": 7, "traversal": 6,
    "xss": 5, "csrf": 5, "idor": 6,
    "secret": 6, "token": 5, "api key": 5, "apikey": 5, "password": 4, "private key": 6,
    "admin": 4, "root": 4, "debug": 3, "stack trace": 4,
    "cve": 6, "vulnerable": 4, "dependency": 3,
    "cors": 4, "redirect": 3, "header": 2,
    "error": 2, "exposed": 3, "hardcoded": 5, "eval": 6, "pickle": 6,
}

# Fatores de correlação entre fontes
CORRELATION_BOOST = {
    2: 2,    # 2 fontes apontando o mesmo alvo: +2
    3: 5,    # 3 fontes: +5
    4: 9,    # 4 fontes: +9
}


def _severity_key(sev):
    return str(sev or "").upper()


def _severity_label(sev):
    s = _severity_key(sev)
    if s in ("CRITICAL", "HIGH", "ERROR"):
        return "Alta"
    if s in ("MEDIUM", "WARNING"):
        return "Média"
    return "Baixa"


def score_evidence(evidence):
    """
    Pontua uma única evidência.

    Retorna
    -------
    dict
        {"score": float, "keywords": list[str], "evidencia_extra": int}
    """
    total = 0.0
    sev = _severity_key(evidence.get("severity", "INFO"))
    total += SEV_SCORE.get(sev, 0)

    # Palavras-chave no texto combinado
    text = " ".join([
        str(evidence.get("title", "")),
        str(evidence.get("evidence", "")),
        str(evidence.get("code_snippet", "")),
        str(evidence.get("cve", "")),
        str(evidence.get("dependency", "")),
        str(evidence.get("endpoint", "")),
    ]).lower()

    keywords_found = []
    for kw, pts in KEYWORD_SCORE.items():
        if kw in text:
            keywords_found.append(kw)
            total += pts
            break  # evita double-counting de variantes

    # Bônus por evidência concreta
    evidencia_extra = 0
    if evidence.get("code_snippet"):
        evidencia_extra += 1
    if evidence.get("http_response") or evidence.get("status_code"):
        evidencia_extra += 1
    if evidence.get("cve"):
        evidencia_extra += 1
    if evidence.get("payload"):
        evidencia_extra += 1

    total += evidencia_extra

    return {
        "score": round(total, 1),
        "keywords": keywords_found,
        "evidencia_extra": evidencia_extra,
    }


def classify_score(score):
    """Classifica um score em severidade."""
    if score >= 15:
        return "Crítica"
    if score >= 10:
        return "Alta"
    if score >= 5:
        return "Média"
    return "Baixa"


def correlate_evidences(evidences):
    """
    Correlaciona evidências: agrupa por alvo (arquivo, endpoint, dependência)
    e aplica boost quando múltiplas fontes apontam o mesmo alvo.
    """
    targets = {}

    for ev in evidences:
        # Alvo primário: arquivo > endpoint > dependência
        target = (
            ev.get("file") or ev.get("endpoint") or ev.get("dependency") or ev.get("url") or "geral"
        )
        key = str(target)
        if key not in targets:
            targets[key] = {"sources": set(), "count": 0}
        targets[key]["sources"].add(ev.get("tool", ""))
        targets[key]["count"] += 1

    # Calcula boost por alvo
    boosts = {}
    for target, info in targets.items():
        n_sources = len(info["sources"])
        boost = 0
        for threshold, b in CORRELATION_BOOST.items():
            if n_sources >= threshold:
                boost = b
        if boost:
            boosts[target] = boost

    return boosts


def calculate_risk(evidences):
    """
    Calcula o risco consolidado de uma lista de evidências.

    Retorna
    -------
    dict
        {
            "score_geral": int,
            "classificacao": str,
            "by_severity": {"Alta": n, "Média": n, "Baixa": n},
            "total_evidencias": int,
            "riscos_prioritarios": [dict],
            "justificativa": str,
            "correlacoes": dict,
            "by_tool": dict,
        }
    """
    if not evidences:
        return {
            "score_geral": 100,
            "classificacao": "Boa",
            "by_severity": {"Alta": 0, "Média": 0, "Baixa": 0},
            "total_evidencias": 0,
            "riscos_prioritarios": [],
            "justificativa": "Nenhuma evidência carregada. Postura considerada boa por padrão.",
            "correlacoes": {},
            "by_tool": {},
        }

    # Pontua cada evidência
    scored = []
    for ev in evidences:
        ev = dict(ev)
        resultado = score_evidence(ev)
        ev["_score"] = resultado["score"]
        ev["_keywords"] = resultado["keywords"]
        ev["_evidencia_extra"] = resultado["evidencia_extra"]
        ev["_severity_label"] = _severity_label(ev.get("severity", ""))
        ev["_prioridade_final"] = classify_score(resultado["score"])
        scored.append(ev)

    # Correlação entre fontes
    boosts = correlate_evidences(evidences)
    for ev in scored:
        target = (
            ev.get("file") or ev.get("endpoint") or ev.get("dependency") or ev.get("url") or "geral"
        )
        ev["_score"] += boosts.get(str(target), 0)
        ev["_prioridade_final"] = classify_score(ev["_score"])

    # Ordena por score
    scored.sort(key=lambda x: x.get("_score", 0), reverse=True)

    # Contagens
    by_severity = {"Alta": 0, "Média": 0, "Baixa": 0}
    for ev in scored:
        label = ev.get("_severity_label", "Baixa")
        by_severity[label] = by_severity.get(label, 0) + 1

    # Score geral: 100 - penalidades ponderadas
    score = 100
    score -= by_severity["Alta"] * 10
    score -= by_severity["Média"] * 4
    score -= by_severity["Baixa"] * 1

    # Penalidade por correlação forte
    for target, boost in boosts.items():
        if boost >= 9:
            score -= 8
        elif boost >= 5:
            score -= 5

    score = max(score, 0)

    if score >= 85:
        classificacao = "Boa"
    elif score >= 65:
        classificacao = "Atenção"
    else:
        classificacao = "Crítica"

    # Riscos prioritários (top 5)
    riscos_prioritarios = []
    for ev in scored[:5]:
        riscos_prioritarios.append({
            "id": ev.get("id", ""),
            "tool": ev.get("tool", ""),
            "title": ev.get("title", ""),
            "evidence": ev.get("evidence", "")[:150],
            "severity": ev.get("_severity_label", "Baixa"),
            "priority": ev.get("_prioridade_final", "Baixa"),
            "score": ev.get("_score", 0),
            "file": ev.get("file", ""),
            "endpoint": ev.get("endpoint", ""),
            "dependency": ev.get("dependency", ""),
            "cve": ev.get("cve", ""),
            "owasp_label": ev.get("owasp_label", ""),
            "owasp_name": ev.get("owasp_name", ""),
        })

    # Justificativa
    just = []
    if by_severity["Alta"] > 0:
        just.append(f"{by_severity['Alta']} risco(s) de alta severidade")
    if by_severity["Média"] > 0:
        just.append(f"{by_severity['Média']} risco(s) médios")
    if boosts:
        just.append(f"{len(boosts)} alvo(s) com correlação entre ferramentas")
    justificativa = "; ".join(just) if just else "Sem achados relevantes."

    from collections import Counter
    by_tool = dict(Counter(ev.get("tool", "") for ev in scored))

    return {
        "score_geral": score,
        "classificacao": classificacao,
        "by_severity": by_severity,
        "total_evidencias": len(scored),
        "riscos_prioritarios": riscos_prioritarios,
        "justificativa": justificativa,
        "correlacoes": boosts,
        "by_tool": by_tool,
        "evidences_scored": scored,
    }


def calculate_general_score(total_high, total_medium, total_low):
    """
    Score simplificado por contagem de severidade.

    Usado no histórico global e no resumo do dashboard. Mantido separado
    do calculate_risk() para preservar o fluxo atual sem misturar as lógicas.
    """
    score = 100
    score -= total_high * 10
    score -= total_medium * 5
    score -= total_low * 2

    score = max(score, 0)

    if score >= 85:
        classification = "Boa"
    elif score >= 65:
        classification = "Atenção"
    else:
        classification = "Crítica"

    return score, classification
