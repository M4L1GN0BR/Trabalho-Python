"""
Estado de sessão do dashboard.

Centraliza falsos positivos, auto-save do histórico de URL e o
scanner de secrets de arquivos enviados. Nenhuma regra de negócio
pesada — apenas o estado do Streamlit organizado fora do app.py.
"""

import streamlit as st

from src.core.secrets import parse_gitleaks_json, scan_text_for_secrets
from dashboard.db import save_scan_history, save_url_history


def init_false_positive_state():
    if "false_positives" not in st.session_state:
        st.session_state.false_positives = set()

    if "last_url_scan" not in st.session_state:
        st.session_state.last_url_scan = None

    if "secret_results" not in st.session_state:
        st.session_state.secret_results = []

    if "saved_url_scans" not in st.session_state:
        st.session_state.saved_url_scans = set()


def is_false_positive(unique_id):
    return unique_id in st.session_state.false_positives


def add_false_positive(unique_id):
    st.session_state.false_positives.add(unique_id)


def count_false_positives():
    return len(st.session_state.false_positives)


def filter_false_positives(df, source):
    if df.empty:
        return df

    if source == "semgrep":
        return df[
            ~df.apply(
                lambda row: is_false_positive(
                    f"semgrep_{row['ID']}_{row['Arquivo']}_{row['Linha']}"
                ),
                axis=1,
            )
        ]

    if source == "bandit":
        return df[
            ~df.apply(
                lambda row: is_false_positive(
                    f"bandit_{row['Teste']}_{row['Arquivo']}_{row['Linha']}"
                ),
                axis=1,
            )
        ]

    if source == "sca":
        return df[
            ~df.apply(
                lambda row: is_false_positive(f"sca_{row['Biblioteca']}_{row['CVE']}"),
                axis=1,
            )
        ]

    return df


def auto_save_url_scan_once(result, high_count, medium_count, low_count):
    """
    Salva automaticamente a análise de URL uma única vez por execução.
    Isso garante que o histórico apareça sem depender de clique manual.
    """
    if not result:
        return

    unique_key = f"{result.get('url_inicial')}|{result.get('url_final')}|{result.get('score')}|{high_count}|{medium_count}|{low_count}"

    if unique_key in st.session_state.saved_url_scans:
        return

    save_url_history(
        url=result["url_inicial"],
        final_url=result["url_final"],
        score=result["score"],
        classification=result["classificacao"],
        high_count=high_count,
        medium_count=medium_count,
        low_count=low_count,
    )

    st.session_state.saved_url_scans.add(unique_key)


def scan_uploaded_files_for_secrets(uploaded_files):
    """
    Escaneia arquivos enviados manualmente na aba Secrets.
    Arquivos binários são ignorados.
    """
    findings = []

    for uploaded_file in uploaded_files:
        try:
            raw = uploaded_file.getvalue()

            try:
                text = raw.decode("utf-8")
            except UnicodeDecodeError:
                text = raw.decode("latin-1", errors="ignore")

            findings.extend(scan_text_for_secrets(uploaded_file.name, text))

        except Exception:
            pass

    return findings


def process_consolidated_report(report):
    """
    Processa um aspm-report.json consolidado:
    - preenche o session_state com os dados de cada ferramenta
    - registra o scan no histórico global

    Retorna o total de achados (int).
    """
    semgrep_data = report.get("semgrep", {"results": []})
    bandit_data = report.get("bandit", {"results": []})
    sca_data = report.get("sca", {"dependencies": []})
    secrets_data = report.get("secrets", {}).get("gitleaks", [])

    # Converte os achados do Gitleaks para o formato da aba Secrets
    secret_findings = parse_gitleaks_json(secrets_data) if secrets_data else []

    st.session_state["aspm_report"] = report
    st.session_state["consolidated_semgrep"] = semgrep_data
    st.session_state["consolidated_bandit"] = bandit_data
    st.session_state["consolidated_sca"] = sca_data
    st.session_state["consolidated_secrets"] = secrets_data
    st.session_state["secret_results"] = secret_findings

    meta = report.get("scan_metadata", {})
    summary = meta.get("summary", {})
    n = summary.get("total_findings", 0)

    semgrep_count = len(semgrep_data.get("results", []))
    bandit_count = len(bandit_data.get("results", []))
    sca_count = sum(
        len(d.get("vulns", [])) for d in sca_data.get("dependencies", [])
    )
    secrets_count = len(secrets_data)
    high = summary.get("by_severity", {}).get("Alta", 0)
    medium = summary.get("by_severity", {}).get("Média", 0)
    low = summary.get("by_severity", {}).get("Baixa", 0)

    tools_list = []
    if semgrep_count > 0:
        tools_list.append("Semgrep")
    if bandit_count > 0:
        tools_list.append("Bandit")
    if sca_count > 0:
        tools_list.append("SCA")
    if secrets_count > 0:
        tools_list.append("Secrets")
    tools_str = ", ".join(tools_list) if tools_list else "Nenhuma"

    save_scan_history(
        n,
        high,
        medium,
        low,
        semgrep_count,
        bandit_count,
        sca_count,
        secrets_count,
        asset_id=1,
        asset_name="Geral",
        tools=tools_str,
        status="Concluído",
    )
    return n
