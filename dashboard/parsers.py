# NightSync - ASPM (Application Security Posture Management)
# Copyright (C) 2026 Felipe Barbosa Alves (RM570378),
#                    Murilo Garcia Godoy (RM564840),
#                    Lucas Moura Goncalves de Amorim (RM570161),
#                    Caio de Paula Goes (RM569052)
#
# This file is part of NightSync, free software under the GNU General
# Public License as published by the Free Software Foundation, either
# version 3 of the License, or (at your option) any later version.
#
# NightSync is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""
Parsers das ferramentas (Semgrep, Bandit, SCA) para o dashboard.

Normalizam o JSON de cada ferramenta em linhas com colunas padronizadas
e enriquecem cada achado com a explicação da IA (ask_ai).

O enriquecimento por IA respeita um **orçamento por relatório**: com
relatórios grandes (ex.: DefectDojo com ~2.000 achados), chamar a API
para cada achado inviabiliza a renderização. Os primeiros achados usam
IA real; os demais usam o fallback local (instantâneo).
"""

import pandas as pd
import streamlit as st

from src.core.text import clean_text
from src.core.mensagens_pt import humanize_bandit, humanize_semgrep
from dashboard.ai import ask_ai, local_ai_fallback

# Máximo de chamadas de IA por processamento de relatório.
MAX_AI_PER_RUN = 30


def reset_ai_budget():
    """Zera o orçamento de chamadas de IA (chamar ao carregar novo relatório)."""
    st.session_state["_ai_calls"] = 0


def _use_ai_budget():
    """
    Consome uma unidade do orçamento de IA.

    Retorna True se ainda houver orçamento (chamada real permitida).
    """
    calls = st.session_state.get("_ai_calls", 0)
    if calls >= MAX_AI_PER_RUN:
        return False
    st.session_state["_ai_calls"] = calls + 1
    return True


def _enrich_ai(title, description, file_path=None, line_number=None):
    """Enriquece com IA real se houver orçamento; senão, fallback local."""
    if _use_ai_budget():
        return ask_ai(title, description, file_path=file_path, line_number=line_number)
    return local_ai_fallback(title, description)


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
    seen = set()

    for item in results:
        severity = item.get("extra", {}).get("severity")
        check_id = item.get("check_id")
        message = clean_text(item.get("extra", {}).get("message"))
        priority = classify_semgrep_priority(severity)

        # Deduplicação de achados idênticos (mesmo check + arquivo + linha)
        # O Semgrep pode reportar a mesma regra duas vezes no mesmo local;
        # duplicatas quebram chaves únicas do Streamlit e poluem o relatório.
        fpath = item.get("path")
        fline = item.get("start", {}).get("line")
        dedup_key = (check_id, fpath, fline)
        if dedup_key in seen:
            continue
        seen.add(dedup_key)

        ai_data = _enrich_ai(
            check_id,
            message,
            file_path=fpath,
            line_number=fline,
        )

        # Descrição humanizada em pt-BR (fallback: mensagem original)
        desc_pt, _ = humanize_semgrep(check_id, message)

        vulns.append(
            {
                "ID": check_id,
                "Arquivo": fpath,
                "Linha": fline,
                "Severidade": severity,
                "Prioridade": priority,
                "Descrição": desc_pt if desc_pt != message else message,
                "Mensagem Original": message,
                "Explicação IA": ai_data["explicacao"],
                "Risco IA": ai_data["risco"],
                "Correção IA": ai_data["correcao"],
            }
        )

    return vulns


def get_bandit_vulnerabilities(data):
    results = data.get("results", [])
    vulns = []
    seen = set()

    for item in results:
        test_name = item.get("test_name")
        severity = item.get("issue_severity")
        confidence = item.get("issue_confidence")
        text = clean_text(item.get("issue_text"))
        priority = classify_bandit_priority(severity)

        # Deduplicação de achados idênticos (mesmo teste + arquivo + linha)
        fpath = item.get("filename")
        fline = item.get("line_number")
        dedup_key = (test_name, fpath, fline)
        if dedup_key in seen:
            continue
        seen.add(dedup_key)

        ai_data = _enrich_ai(
            test_name,
            text,
            file_path=fpath,
            line_number=fline,
        )

        # Descrição humanizada em pt-BR (fallback: mensagem original)
        desc_pt, _ = humanize_bandit(test_name, text)

        vulns.append(
            {
                "Teste": test_name,
                "Arquivo": fpath,
                "Linha": fline,
                "Severidade": severity,
                "Confiança": confidence,
                "Prioridade": priority,
                "Descrição": desc_pt if desc_pt != text else text,
                "Mensagem Original": text,
                "Explicação IA": ai_data["explicacao"],
                "Risco IA": ai_data["risco"],
                "Correção IA": ai_data["correcao"],
            }
        )

    return vulns


def get_sca_vulnerabilities(data):
    vulns = []
    dependencies = data.get("dependencies", [])
    seen = set()

    for dep in dependencies:
        name = dep.get("name")
        version = dep.get("version")

        for vuln in dep.get("vulns", []):
            vuln_id = vuln.get("id")
            description = clean_text(vuln.get("description"))
            fixes = vuln.get("fix_versions", [])

            # Deduplicação: o mesmo CVE da mesma biblioteca pode aparecer
            # em múltiplas entradas do pip-audit (versões/grafos duplicados).
            dedup_key = (name, vuln_id)
            if dedup_key in seen:
                continue
            seen.add(dedup_key)

            fixed_version = fixes[0] if fixes else "Não informado"
            priority = classify_sca_priority(vuln_id)

            ai_data = _enrich_ai(vuln_id, description)

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
