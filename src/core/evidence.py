"""
Evidence Engine — normaliza e centraliza evidências de todos os findings.

Converte os achados de cada ferramenta (Semgrep, Bandit, SCA, Secrets, URL)
em um formato único de evidência que alimenta o Risk Engine e a IA.
"""

import hashlib


def _hash_id(*parts):
    """Gera um ID estável a partir das partes."""
    raw = "|".join(str(p) for p in parts if p)
    return hashlib.md5(raw.encode("utf-8", errors="replace")).hexdigest()[:12]


def normalize_semgrep(item):
    """Normaliza um achado do Semgrep em evidência."""
    extra = item.get("extra", {})
    start = item.get("start", {})
    return {
        "id": _hash_id("semgrep", item.get("check_id"), item.get("path"), start.get("line")),
        "tool": "Semgrep",
        "category": "SAST",
        "file": item.get("path", ""),
        "line": start.get("line"),
        "function": extra.get("metavars", {}).get("$FUNC", {}).get("abstract_content", "") if extra.get("metavars") else "",
        "endpoint": "",
        "url": "",
        "dependency": "",
        "cve": "",
        "vulnerable_version": "",
        "evidence": extra.get("message", ""),
        "code_snippet": extra.get("lines", ""),
        "http_response": "",
        "status_code": None,
        "severity": extra.get("severity", "WARNING"),
        "confidence": extra.get("confidence", ""),
        "priority": "",
        "title": item.get("check_id", ""),
    }


def normalize_bandit(item):
    """Normaliza um achado do Bandit em evidência."""
    return {
        "id": _hash_id("bandit", item.get("test_name"), item.get("filename"), item.get("line_number")),
        "tool": "Bandit",
        "category": "SAST",
        "file": item.get("filename", ""),
        "line": item.get("line_number"),
        "function": item.get("test_name", ""),
        "endpoint": "",
        "url": "",
        "dependency": "",
        "cve": "",
        "vulnerable_version": "",
        "evidence": item.get("issue_text", ""),
        "code_snippet": item.get("code", ""),
        "http_response": "",
        "status_code": None,
        "severity": item.get("issue_severity", "LOW"),
        "confidence": item.get("issue_confidence", ""),
        "priority": "",
        "title": item.get("test_name", ""),
    }


def normalize_sca(dep_name, dep_version, vuln):
    """Normaliza uma vulnerabilidade de SCA em evidência."""
    return {
        "id": _hash_id("sca", dep_name, vuln.get("id")),
        "tool": "SCA",
        "category": "SCA",
        "file": "",
        "line": None,
        "function": "",
        "endpoint": "",
        "url": "",
        "dependency": dep_name,
        "cve": vuln.get("id", ""),
        "vulnerable_version": dep_version,
        "evidence": vuln.get("description", ""),
        "code_snippet": "",
        "http_response": "",
        "status_code": None,
        "severity": "HIGH" if "CVE" in str(vuln.get("id", "")) else "MEDIUM",
        "confidence": "Alta",
        "priority": "",
        "title": f"{dep_name} {dep_version} - {vuln.get('id', '')}",
    }


def normalize_secret(item, origin="Gitleaks"):
    """Normaliza um segredo encontrado em evidência."""
    return {
        "id": _hash_id(origin.lower(), item.get("Regra") or item.get("RuleID"), item.get("Arquivo") or item.get("File"), item.get("Linha") or item.get("StartLine")),
        "tool": origin,
        "category": "Secrets",
        "file": item.get("Arquivo") or item.get("File") or item.get("file") or "",
        "line": item.get("Linha") or item.get("StartLine") or item.get("line"),
        "function": item.get("Regra") or item.get("RuleID") or item.get("rule") or "",
        "endpoint": "",
        "url": "",
        "dependency": "",
        "cve": "",
        "vulnerable_version": "",
        "evidence": item.get("Descrição") or item.get("Description") or item.get("description") or "Segredo detectado",
        "code_snippet": "",
        "http_response": "",
        "status_code": None,
        "severity": "HIGH",
        "confidence": "Alta",
        "priority": item.get("Prioridade", "Alta"),
        "title": item.get("Regra") or item.get("RuleID") or "Segredo",
    }


def normalize_url_finding(item):
    """Normaliza um achado de URL Analysis em evidência."""
    sev_map = {"Alta": "HIGH", "Média": "MEDIUM", "Baixa": "LOW"}
    return {
        "id": _hash_id("url", item.get("Categoria"), item.get("Item"), item.get("Status")),
        "tool": "URL Analysis",
        "category": item.get("Categoria", "URL"),
        "file": "",
        "line": None,
        "function": "",
        "endpoint": item.get("Item", ""),
        "url": item.get("URL", ""),
        "dependency": "",
        "cve": "",
        "vulnerable_version": "",
        "evidence": item.get("Descrição", ""),
        "code_snippet": "",
        "http_response": item.get("Evidências", ""),
        "status_code": None,
        "severity": sev_map.get(item.get("Prioridade", "Baixa"), "LOW"),
        "confidence": "Média",
        "priority": item.get("Prioridade", "Baixa"),
        "title": f"{item.get('Categoria', '')} - {item.get('Item', '')}",
    }


def build_evidence_store(semgrep_data=None, bandit_data=None, sca_data=None,
                         secrets_data=None, url_findings=None):
    """
    Constrói a lista unificada de evidências a partir de todas as ferramentas.

    Parâmetros
    ----------
    semgrep_data : dict
        JSON do Semgrep ({"results": [...]}).
    bandit_data : dict
        JSON do Bandit ({"results": [...]}).
    sca_data : dict
        JSON do SCA ({"dependencies": [{"name", "version", "vulns": [...]}]}).
    secrets_data : list
        Lista de segredos (formato interno ou Gitleaks).
    url_findings : list
        Lista de findings de URL Analysis.

    Retorna
    -------
    list[dict]
        Lista de evidências normalizadas.
    """
    evidences = []

    if semgrep_data:
        for item in semgrep_data.get("results", []):
            evidences.append(normalize_semgrep(item))

    if bandit_data:
        for item in bandit_data.get("results", []):
            evidences.append(normalize_bandit(item))

    if sca_data:
        for dep in sca_data.get("dependencies", []):
            name = dep.get("name", "")
            version = dep.get("version", "")
            for vuln in dep.get("vulns", []):
                evidences.append(normalize_sca(name, version, vuln))

    if secrets_data:
        for item in secrets_data:
            evidences.append(normalize_secret(item))

    if url_findings:
        for item in url_findings:
            evidences.append(normalize_url_finding(item))

    # Enriquece cada evidência com a categoria OWASP Top 10
    from .owasp import enrich_evidences
    return enrich_evidences(evidences)


def count_by_tool(evidences):
    """Conta evidências por ferramenta."""
    from collections import Counter
    return dict(Counter(e["tool"] for e in evidences))


def count_by_severity(evidences):
    """Conta evidências por severidade (Alta/Média/Baixa)."""
    sev = {"Alta": 0, "Média": 0, "Baixa": 0}
    for e in evidences:
        s = str(e.get("severity", "")).upper()
        if s in ("CRITICAL", "HIGH", "ERROR"):
            sev["Alta"] += 1
        elif s in ("MEDIUM", "WARNING"):
            sev["Média"] += 1
        else:
            sev["Baixa"] += 1
    return sev
