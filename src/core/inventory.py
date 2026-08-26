"""
Inventário de dependências (SBOM-lite).

Gera o inventário de componentes a partir dos dados de SCA (pip-audit)
com risco por pacote: total de CVEs, pior severidade e versões corrigidas.

Aprendizado do estudo de caso DefectDojo: o SCA listou 156 dependências
com 58 vulnerabilidades — a visão por pacote (e não por CVE solta) é o que
permite priorizar a atualização de componentes de alto risco.

Funções puras, sem dependência de UI.
"""


def _clean_name(name):
    return str(name or "").strip().lower()


def _cve_severity_code(vuln):
    """
    Deriva a severidade (rótulo em inglês) de um dict de CVE.

    O pip-audit não publica o campo `severity` — o rótulo é derivado do id:
    id contendo "CVE" vira HIGH, os demais (ex.: PYSEC/OSV) MEDIUM (mesmo
    racional de evidence.normalize_sca). O rótulo em inglês é o que
    cvss.estimate_from_severity entende (chaves de SEVERITY_TYPICAL_VECTOR).
    """
    sev = str(vuln.get("severity") or "").upper()
    if sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        return sev
    if "CVE" in str(vuln.get("id") or "").upper():
        return "HIGH"
    return "MEDIUM"


def _cve_severity_rank(vuln):
    """Converte a severidade de um dict de CVE em peso numérico."""
    return {
        "CRITICAL": (4, "Crítica"),
        "HIGH": (3, "Alta"),
        "MEDIUM": (2, "Média"),
        "LOW": (1, "Baixa"),
    }.get(_cve_severity_code(vuln), (0, "Desconhecida"))


def _cve_cvss(vuln):
    """
    Extrai o score CVSS de um dict de CVE.

    Prioriza campos numéricos (cvss_score/cvss3_score) fornecidos pela
    ferramenta; caso contrário, estima pelo vetor típico da severidade.
    """
    for key in ("cvss_score", "cvssv3_score", "cvss3_score", "cvss", "score"):
        val = vuln.get(key)
        if isinstance(val, (int, float)) and val > 0:
            return round(float(val), 1)
        if isinstance(val, str):
            try:
                num = float(val)
                if num > 0:
                    return round(num, 1)
            except ValueError:
                pass

    from .cvss import estimate_from_severity

    # Rótulo em inglês (HIGH/MEDIUM) que estimate_from_severity entende —
    # "Alta"/"Média" não existem em SEVERITY_TYPICAL_VECTOR e cairiam no
    # default MEDIUM (era isso que fazia todo pacote virar "OK").
    score, _ = estimate_from_severity(_cve_severity_code(vuln))
    return score


def build_inventory(sca_data):
    """
    Constrói o inventário de dependências com risco por pacote.

    Parâmetros
    ----------
    sca_data : dict
        Saída do pip-audit ({"dependencies": [{"name", "version", "vulns"}]}).

    Retorna
    -------
    list[dict]
        Pacotes com: name, version, cve_count, risk, risk_label,
        fix_versions, cves, cvss_score.
    """
    inventory = []
    for dep in sca_data.get("dependencies", []):
        name = dep.get("name", "")
        version = dep.get("version", "")
        vulns = dep.get("vulns", [])

        worst_rank = 0
        worst_label = "OK"
        worst_cvss = 0.0
        fix_versions = set()
        cves = []

        for vuln in vulns:
            vuln_id = str(vuln.get("id", ""))
            rank, label = _cve_severity_rank(vuln)
            if rank > worst_rank:
                worst_rank = rank
                worst_label = label
            c = _cve_cvss(vuln)
            worst_cvss = max(worst_cvss, c)
            if vuln_id:
                cves.append(vuln_id)
            for fix in vuln.get("fix_versions", []):
                fix_versions.add(fix)

        inventory.append(
            {
                "name": name,
                "version": version,
                "cve_count": len(cves),
                "risk": worst_rank,
                "risk_label": worst_label if cves else "OK",
                "cvss_score": round(worst_cvss, 1) if cves else 0.0,
                "fix_versions": sorted(fix_versions),
                "cves": cves,
                "has_fix": bool(fix_versions),
            }
        )

    # Ordena: maior risco primeiro, depois mais CVEs, depois maior CVSS
    inventory.sort(key=lambda p: (p["risk"], p["cvss_score"], p["cve_count"]), reverse=True)
    return inventory


def inventory_summary(sca_data):
    """
    Resumo agregado do inventário para cards do dashboard.

    Retorna
    -------
    dict
        {
            "total_packages", "packages_with_vulns", "total_vulns",
            "by_risk": {...}, "critical_packages": [nomes]
        }
    """
    inventory = build_inventory(sca_data)
    total_vulns = sum(p["cve_count"] for p in inventory)
    by_risk = {"Crítica": 0, "Alta": 0, "Média": 0, "Baixa": 0}
    for p in inventory:
        if p["risk_label"] in by_risk:
            by_risk[p["risk_label"]] += 1

    critical = [p for p in inventory if p["risk"] >= 3]
    return {
        "total_packages": len(inventory),
        "packages_with_vulns": sum(1 for p in inventory if p["cve_count"] > 0),
        "total_vulns": total_vulns,
        "by_risk": by_risk,
        "critical_packages": [p["name"] for p in critical[:5]],
    }


def package_table_rows(sca_data, limit=None):
    """
    Linhas prontas para DataFrame/CSV na aba SCA do dashboard.
    """
    inventory = build_inventory(sca_data)
    if limit:
        inventory = inventory[:limit]
    rows = []
    for p in inventory:
        fix = ", ".join(p["fix_versions"]) if p["fix_versions"] else "—"
        rows.append(
            {
                "Pacote": p["name"],
                "Versão": p["version"],
                "CVEs": p["cve_count"],
                "Risco": p["risk_label"],
                "CVSS": p.get("cvss_score", 0.0),
                "Correção": fix,
            }
        )
    return rows
