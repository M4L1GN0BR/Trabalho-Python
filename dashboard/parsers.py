"""
Parsers das ferramentas (Semgrep, Bandit, SCA) para o dashboard.

Normalizam o JSON de cada ferramenta em linhas com colunas padronizadas
e enriquecem cada achado com a explicação da IA (ask_ai).
"""

import pandas as pd

from src.core.text import clean_text
from dashboard.ai import ask_ai


def classify_semgrep_priority(severity):
    if severity == "ERROR":
        return "Alta"
    if severity == "WARNING":
        return "Média"
    return "Baixa"


def classify_bandit_priority(severity):
    severity = str(severity).upper()

    if severity == "HIGH":
        return "Alta"
    if severity == "MEDIUM":
        return "Média"
    return "Baixa"


def classify_sca_priority(vuln_id):
    vuln_id = str(vuln_id).upper()

    if "CVE" in vuln_id:
        return "Alta"

    if "JWT" in vuln_id:
        return "Alta"

    if "SSTI" in vuln_id:
        return "Alta"

    return "Média"


def get_semgrep_vulnerabilities(data):
    results = data.get("results", [])
    vulns = []

    for item in results:
        severity = item.get("extra", {}).get("severity")
        check_id = item.get("check_id")
        message = clean_text(item.get("extra", {}).get("message"))
        priority = classify_semgrep_priority(severity)

        ai_data = ask_ai(
            check_id,
            message,
            file_path=item.get("path"),
            line_number=item.get("start", {}).get("line"),
        )

        vulns.append(
            {
                "ID": check_id,
                "Arquivo": item.get("path"),
                "Linha": item.get("start", {}).get("line"),
                "Severidade": severity,
                "Prioridade": priority,
                "Descrição": message,
                "Explicação IA": ai_data["explicacao"],
                "Risco IA": ai_data["risco"],
                "Correção IA": ai_data["correcao"],
            }
        )

    return vulns


def get_bandit_vulnerabilities(data):
    results = data.get("results", [])
    vulns = []

    for item in results:
        test_name = item.get("test_name")
        severity = item.get("issue_severity")
        confidence = item.get("issue_confidence")
        text = clean_text(item.get("issue_text"))
        priority = classify_bandit_priority(severity)

        ai_data = ask_ai(
            test_name,
            text,
            file_path=item.get("filename"),
            line_number=item.get("line_number"),
        )

        vulns.append(
            {
                "Teste": test_name,
                "Arquivo": item.get("filename"),
                "Linha": item.get("line_number"),
                "Severidade": severity,
                "Confiança": confidence,
                "Prioridade": priority,
                "Descrição": text,
                "Explicação IA": ai_data["explicacao"],
                "Risco IA": ai_data["risco"],
                "Correção IA": ai_data["correcao"],
            }
        )

    return vulns


def get_sca_vulnerabilities(data):
    vulns = []
    dependencies = data.get("dependencies", [])

    for dep in dependencies:
        name = dep.get("name")
        version = dep.get("version")

        for vuln in dep.get("vulns", []):
            vuln_id = vuln.get("id")
            description = clean_text(vuln.get("description"))
            fixes = vuln.get("fix_versions", [])

            fixed_version = fixes[0] if fixes else "Não informado"
            priority = classify_sca_priority(vuln_id)

            ai_data = ask_ai(vuln_id, description)

            vulns.append(
                {
                    "Biblioteca": name,
                    "Versão Atual": version,
                    "CVE": vuln_id,
                    "Prioridade": priority,
                    "Correção Disponível": fixed_version,
                    "Descrição": description,
                    "Explicação IA": ai_data["explicacao"],
                    "Risco IA": ai_data["risco"],
                    "Correção IA": ai_data["correcao"],
                }
            )

    return vulns
