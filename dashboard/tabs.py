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
Corpo das abas do dashboard ASPM.

Cada aba do Streamlit virou uma função de renderização. O app.py apenas
cria as tabs e chama as funções na mesma ordem de antes.
"""

import html
import json
import sqlite3
from datetime import datetime

import pandas as pd
import streamlit as st

from dashboard.ai import ask_ai, ask_executive_summary, local_ai_fallback
from dashboard.db import (
    clear_url_history,
    load_ai_memory,
    load_assets,
    load_scan_history,
)
from dashboard.parsers import (
    get_bandit_vulnerabilities,
    get_sca_vulnerabilities,
    get_semgrep_vulnerabilities,
)
from dashboard.reports import generate_executive_report, generate_pdf_report
from dashboard.session import can, is_admin
from dashboard.state import (
    add_false_positive,
    auto_save_url_scan_once,
    count_false_positives,
    filter_false_positives,
    is_false_positive,
    scan_uploaded_files_for_secrets,
)
from dashboard.ui import (
    render_compact_cards,
    render_donut_chart,
    render_empty_state,
    render_source_cards,
    render_status_card,
    render_table_as_cards,
    render_technical_table,
)
from src.core.auth import ROLE_LABELS, delete_user, load_users, register_user
from src.core.attack.engine import run_attack_modules
from src.core.correlation import correlate_findings
from src.core.database_path import DB_PATH
from src.core.evidence import build_evidence_store
from src.core.owasp import top_owasp_categories
from src.core.risk_engine import calculate_general_score, calculate_risk
from src.core.secrets import calculate_secret_counts, parse_gitleaks_json
from src.core.url_analysis import analyze_url


def _consolidated_frames():
    """
    Constrói os DataFrames das ferramentas a partir do estado da sessão.

    Os dados começam vazios para evitar que resultados antigos apareçam
    automaticamente quando o dashboard é aberto. Se um relatório consolidado
    foi enviado via sidebar, usa ele.
    """
    semgrep_data = st.session_state.get("consolidated_semgrep", {"results": []})
    bandit_data = st.session_state.get("consolidated_bandit", {"results": []})
    sca_data = st.session_state.get("consolidated_sca", {"dependencies": []})

    semgrep_df = pd.DataFrame(get_semgrep_vulnerabilities(semgrep_data))
    bandit_df = pd.DataFrame(get_bandit_vulnerabilities(bandit_data))
    sca_df = pd.DataFrame(get_sca_vulnerabilities(sca_data))

    return {
        "semgrep_data": semgrep_data,
        "bandit_data": bandit_data,
        "sca_data": sca_data,
        "semgrep_df": semgrep_df,
        "bandit_df": bandit_df,
        "sca_df": sca_df,
        "semgrep_active": filter_false_positives(semgrep_df, "semgrep"),
        "bandit_active": filter_false_positives(bandit_df, "bandit"),
        "sca_active": filter_false_positives(sca_df, "sca"),
        "secrets_df": pd.DataFrame(st.session_state.get("secret_results", [])),
    }


# ═══════════════════════════════════════════════════════════════
# TAB 1 - RESUMO EXECUTIVO
# ═══════════════════════════════════════════════════════════════


def render_resumo_tab():
    st.subheader("Resumo Executivo")

    st.markdown(
        """
        <div class="enterprise-card">
            <div class="enterprise-section-title"></div>
            <div class="enterprise-muted">
                Consolidação dos resultados das ferramentas integradas, com foco em risco,
                priorização e leitura executiva para apresentação da Sprint ASPM.
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    frames = _consolidated_frames()
    semgrep_active_df = frames["semgrep_active"]
    bandit_active_df = frames["bandit_active"]
    sca_active_df = frames["sca_active"]
    secrets_df_default = frames["secrets_df"]

    total_semgrep = len(semgrep_active_df)
    total_bandit = len(bandit_active_df)
    total_sca = len(sca_active_df)
    total_secrets = len(secrets_df_default)

    total_high = 0
    total_medium = 0
    total_low = 0

    for df_source in [
        semgrep_active_df,
        bandit_active_df,
        sca_active_df,
        secrets_df_default,
    ]:
        if not df_source.empty:
            total_high += df_source[df_source["Prioridade"] == "Alta"].shape[0]
            total_medium += df_source[df_source["Prioridade"] == "Média"].shape[0]
            total_low += df_source[df_source["Prioridade"] == "Baixa"].shape[0]

    # O Resumo Executivo usa somente a análise atual da sessão.
    # Isso evita que dados antigos do histórico contaminem o score ao abrir o sistema.
    latest_url_score = "Sem análise"
    latest_url_classification = "Sem análise"
    total_url_active = 0

    current_url_result = st.session_state.get("last_url_scan")

    if current_url_result:
        latest_url_score = current_url_result.get("score", "Sem análise")
        latest_url_classification = current_url_result.get(
            "classificacao", "Sem análise"
        )

        current_url_df = pd.DataFrame(current_url_result.get("findings", []))

        if not current_url_df.empty:
            current_active_df = current_url_df[current_url_df["Tipo"] == "Achado Ativo"]
            total_url_active = len(current_active_df)
            total_high += current_active_df[
                current_active_df["Prioridade"] == "Alta"
            ].shape[0]
            total_medium += current_active_df[
                current_active_df["Prioridade"] == "Média"
            ].shape[0]
            total_low += current_active_df[
                current_active_df["Prioridade"] == "Baixa"
            ].shape[0]

    general_score, general_classification = calculate_general_score(
        total_high, total_medium, total_low
    )

    col1, col2, col3, col4, col5 = st.columns(5)

    col1.metric("Score Geral", general_score)
    col2.metric("Postura", general_classification)
    col3.metric("Riscos Altos", total_high)
    col4.metric("Riscos Médios", total_medium)
    col5.metric("Riscos Baixos", total_low)

    st.subheader("Fontes integradas")

    source_table = pd.DataFrame(
        [
            {
                "Fonte": "Semgrep",
                "Objetivo": "Análise estática de código",
                "Achados ativos": total_semgrep,
            },
            {
                "Fonte": "Bandit",
                "Objetivo": "Análise de segurança Python",
                "Achados ativos": total_bandit,
            },
            {
                "Fonte": "SCA",
                "Objetivo": "Análise de bibliotecas e CVEs",
                "Achados ativos": total_sca,
            },
            {
                "Fonte": "Secrets",
                "Objetivo": "Detecção de segredos e credenciais",
                "Achados ativos": total_secrets,
            },
            {
                "Fonte": "URL Analysis",
                "Objetivo": "Exposição, headers, TLS e discovery contextual",
                "Achados ativos": total_url_active,
            },
        ]
    )

    render_source_cards(
        total_semgrep, total_bandit, total_sca + total_secrets, latest_url_score
    )

    with st.expander("Ver tabela técnica das fontes"):
        st.dataframe(source_table, use_container_width=True)

    chart_col1, chart_col2 = st.columns(2)

    with chart_col1:
        st.subheader("Distribuição de Severidade")
        severity_chart = pd.DataFrame(
            [
                {"Severidade": "Alta", "Quantidade": total_high},
                {"Severidade": "Média", "Quantidade": total_medium},
                {"Severidade": "Baixa", "Quantidade": total_low},
            ]
        )
        render_donut_chart(
            severity_chart, "Severidade", "Quantidade", "Riscos por severidade"
        )

    with chart_col2:
        st.subheader("Cobertura por Fonte")
        source_chart = pd.DataFrame(
            [
                {"Fonte": "Semgrep", "Achados": total_semgrep},
                {"Fonte": "Bandit", "Achados": total_bandit},
                {"Fonte": "SCA", "Achados": total_sca},
                {"Fonte": "Secrets", "Achados": total_secrets},
            ]
        )
        render_donut_chart(source_chart, "Fonte", "Achados", "Achados por fonte")

    # ── Correlação de Riscos ──
    st.subheader("Correlação de Riscos (ASPM)")
    url_findings_list = []
    if current_url_result:
        url_findings_list = current_url_result.get("findings", [])

    # Contexto do ativo (aba Assets desativada - usa padrão)
    asset_ctx_name = "Geral"
    asset_ctx_crit = "Média"

    correlacoes = correlate_findings(
        semgrep_active_df,
        bandit_active_df,
        sca_active_df,
        secrets_df_default,
        url_findings_list,
        asset_name=asset_ctx_name,
        asset_criticidade=asset_ctx_crit,
    )

    if correlacoes:
        for c in correlacoes:
            cor_priority = c["prioridade"]
            cor_color = {
                "Crítica": "#ef4444",
                "Alta": "#f59e0b",
                "Média": "#38bdf8",
                "Baixa": "#22c55e",
            }.get(cor_priority, "#cbd5e1")
            st.markdown(
                f"""
                <div class="enterprise-card" style="border-left: 4px solid {cor_color}; margin-bottom: 0.75rem;">
                    <div style="display: flex; justify-content: space-between; align-items: center;">
                        <div>
                            <div style="font-weight: 950; color: #f8fafc;">{c["risco"]}</div>
                            <div style="color: #94a3b8; font-size: 0.84rem; margin-top: 0.3rem;">{c["evidencias"]}</div>
                            <div style="color: #cbd5e1; font-size: 0.84rem; margin-top: 0.3rem;">→ {c["acao"]}</div>
                        </div>
                        <div style="color: {cor_color}; font-weight: 950; font-size: 0.9rem;">{cor_priority}</div>
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )
    else:
        st.markdown(
            "<div class='enterprise-muted'>Nenhuma correlação significativa identificada entre as fontes.</div>",
            unsafe_allow_html=True,
        )

    # ── Risk Engine Consolidado ──
    st.subheader("Risk Engine Consolidado")
    try:
        # Monta evidências de todas as fontes
        evidence_list = build_evidence_store(
            semgrep_data=frames["semgrep_data"],
            bandit_data=frames["bandit_data"],
            sca_data=frames["sca_data"],
            secrets_data=st.session_state.get("secret_results", []),
            url_findings=url_findings_list,
        )

        risk = calculate_risk(evidence_list)

        # Categorias OWASP Top 10 mais frequentes no ambiente
        top_owasp = top_owasp_categories(evidence_list)

        # Score cards
        rc1, rc2, rc3, rc4 = st.columns(4)
        score_color = (
            "#22c55e" if risk["score_geral"] >= 85
            else "#f59e0b" if risk["score_geral"] >= 65
            else "#ef4444"
        )
        with rc1:
            st.markdown(
                f"""
                <div class="enterprise-card" style="text-align:center; min-height:120px;">
                    <div style="font-size:0.75rem; color:#94a3b8; font-weight:800; text-transform:uppercase; letter-spacing:0.08em;">Security Score</div>
                    <div style="font-size:2.6rem; font-weight:950; color:{score_color}; margin-top:0.2rem;">{risk['score_geral']}</div>
                    <div style="color:#cbd5e1; font-size:0.85rem;">{risk['classificacao']}</div>
                </div>
                """,
                unsafe_allow_html=True,
            )
        with rc2:
            st.markdown(
                f"""
                <div class="enterprise-card" style="text-align:center; min-height:120px;">
                    <div style="font-size:0.75rem; color:#94a3b8; font-weight:800; text-transform:uppercase; letter-spacing:0.08em;">Evidências</div>
                    <div style="font-size:2.6rem; font-weight:950; color:#38bdf8; margin-top:0.2rem;">{risk['total_evidencias']}</div>
                    <div style="color:#cbd5e1; font-size:0.85rem;">achados normalizados</div>
                </div>
                """,
                unsafe_allow_html=True,
            )
        with rc3:
            st.markdown(
                f"""
                <div class="enterprise-card" style="text-align:center; min-height:120px;">
                    <div style="font-size:0.75rem; color:#94a3b8; font-weight:800; text-transform:uppercase; letter-spacing:0.08em;">Correlações</div>
                    <div style="font-size:2.6rem; font-weight:950; color:#a78bfa; margin-top:0.2rem;">{len(risk['correlacoes'])}</div>
                    <div style="color:#cbd5e1; font-size:0.85rem;">alvos multi-ferramenta</div>
                </div>
                """,
                unsafe_allow_html=True,
            )
        with rc4:
            sev = risk["by_severity"]
            st.markdown(
                f"""
                <div class="enterprise-card" style="text-align:center; min-height:120px;">
                    <div style="font-size:0.75rem; color:#94a3b8; font-weight:800; text-transform:uppercase; letter-spacing:0.08em;">Por Severidade</div>
                    <div style="margin-top:0.4rem;">
                        <span style="color:#ef4444; font-weight:900; font-size:1.3rem;">{sev['Alta']}</span>
                        <span style="color:#94a3b8;"> alta · </span>
                        <span style="color:#f59e0b; font-weight:900; font-size:1.3rem;">{sev['Média']}</span>
                        <span style="color:#94a3b8;"> média · </span>
                        <span style="color:#38bdf8; font-weight:900; font-size:1.3rem;">{sev['Baixa']}</span>
                        <span style="color:#94a3b8;"> baixa</span>
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )

        # Riscos prioritários
        st.markdown("### Riscos Prioritários")
        if risk["riscos_prioritarios"]:
            for r in risk["riscos_prioritarios"]:
                p_color = {
                    "Crítica": "#ef4444", "Alta": "#f59e0b",
                    "Média": "#38bdf8", "Baixa": "#22c55e",
                }.get(r["priority"], "#cbd5e1")
                origem = html.escape(
                    str(r.get("file") or r.get("endpoint") or r.get("dependency") or "—")
                )
                score_line = f"{origem} · score {r['score']}"
                if r.get("owasp_label"):
                    score_line = f"{origem} · {html.escape(str(r['owasp_label']))} · score {r['score']}"

                # Título e descrição legíveis (pt-BR) com fallback para o original
                titulo = html.escape(str(r.get("title_pt") or r["title"]))
                descricao = html.escape(str(r.get("evidence_pt") or r["evidence"]))
                tool_ref = html.escape(str(r.get("tool", "")))

                # Contexto de arquivo de teste / falso positivo (estudo DefectDojo)
                contexto_badges = []
                if r.get("in_test_file"):
                    contexto_badges.append(
                        "<span style='background:#64748b22;color:#94a3b8;border:1px solid #64748b55;border-radius:999px;padding:0.1rem 0.5rem;font-size:0.7rem;font-weight:800;'>ARQUIVO DE TESTE</span>"
                    )
                if r.get("fp_candidate"):
                    contexto_badges.append(
                        "<span style='background:#f59e0b22;color:#f59e0b;border:1px solid #f59e0b55;border-radius:999px;padding:0.1rem 0.5rem;font-size:0.7rem;font-weight:800;'>FP PROVÁVEL</span>"
                    )
                badges_html = " ".join(contexto_badges)
                fp_note = (
                    f"<div style='color:#94a3b8;font-size:0.75rem;margin-top:0.2rem;'>{html.escape(str(r.get('fp_reason', '')))}</div>"
                    if r.get("fp_candidate") and r.get("fp_reason")
                    else ""
                )

                st.markdown(
                    f"""
                    <div class="enterprise-card" style="border-left: 4px solid {p_color}; padding: 0.9rem 1rem; margin-bottom: 0.6rem;">
                        <div style="display:flex; justify-content:space-between; align-items:center;">
                            <div style="max-width:82%;">
                                <div style="font-weight:900; color:#f8fafc; font-size:0.95rem;">
                                    <span style="color:#64748b; font-size:0.8rem;">[{tool_ref}]</span> {titulo}
                                </div>
                                <div style="color:#94a3b8; font-size:0.8rem; margin-top:0.25rem;">{score_line}</div>
                                <div style="margin-top:0.35rem;">{badges_html}{fp_note}</div>
                                <div style="color:#cbd5e1; font-size:0.82rem; margin-top:0.3rem;">{str(descricao)[:180]}</div>
                            </div>
                            <div style="color:{p_color}; font-weight:950; font-size:0.9rem; white-space:nowrap;">{html.escape(str(r['priority']))}</div>
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
        else:
            st.markdown(
                "<div class='enterprise-muted'>Sem riscos prioritários. Postura saudável.</div>",
                unsafe_allow_html=True,
            )

        # Justificativa
        with st.expander("Justificativa do Score"):
            st.write(risk["justificativa"])
            if risk["correlacoes"]:
                st.markdown("**Correlações entre ferramentas:**")
                for alvo, boost in list(risk["correlacoes"].items())[:8]:
                    st.write(f"- `{alvo}` → +{boost} pontos")
            if top_owasp:
                st.markdown("**Categorias OWASP Top 10:**")
                for cat in top_owasp:
                    st.write(f"- `{cat['label']}` {cat['name']} — {cat['count']} evidência(s)")

        # Categorias OWASP Top 10 (cards executivos)
        if top_owasp:
            st.markdown("### Categorias OWASP Top 10")
            ow_cols = st.columns(min(len(top_owasp), 5))
            for idx, cat in enumerate(top_owasp[:5]):
                with ow_cols[idx]:
                    st.markdown(
                        f"""
                        <div class="enterprise-card" style="text-align:center; min-height:118px;">
                            <div style="font-size:0.72rem; color:#94a3b8; font-weight:800; text-transform:uppercase; letter-spacing:0.06em;">{cat['label']}</div>
                            <div style="font-size:2rem; font-weight:950; color:#a78bfa; margin-top:0.2rem;">{cat['count']}</div>
                            <div style="color:#cbd5e1; font-size:0.78rem; margin-top:0.3rem;">{cat['name']}</div>
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )

        # Exportação do relatório executivo
        st.markdown("### Exportar Relatório")
        exec_pdf = generate_executive_report(
            risk,
            by_tool=risk.get("by_tool"),
            scan_time=datetime.now().strftime("%d/%m/%Y %H:%M"),
            owasp_top=top_owasp,
        )
        st.download_button(
            "Baixar Relatório Executivo (PDF)",
            exec_pdf,
            "relatorio_executivo_aspm.pdf",
            "application/pdf",
        )

    except Exception as e:
        st.warning(f"Risk Engine indisponível: {e}")

    # ── Histórico Global ──
    with st.expander("Histórico global de scans"):
        scan_hist_df = load_scan_history()
        if not scan_hist_df.empty:
            st.dataframe(scan_hist_df.head(10), use_container_width=True)
            if len(scan_hist_df) > 1:
                st.subheader("Evolução do Score")
                evo_df = scan_hist_df.sort_values("id")[["created_at", "score_geral"]]
                evo_df = evo_df.set_index("created_at")
                st.line_chart(evo_df)
        else:
            st.caption("Nenhum scan registrado. Use o upload consolidado na sidebar.")

    executive_context = f"""
Score geral: {general_score}
Classificação geral: {general_classification}
Achados Semgrep: {total_semgrep}
Achados Bandit: {total_bandit}
Achados SCA: {total_sca}
Achados Secrets: {total_secrets}
Riscos altos: {total_high}
Riscos médios: {total_medium}
Riscos baixos: {total_low}
Último score de URL: {latest_url_score}
Última classificação de URL: {latest_url_classification}
Falsos positivos manuais marcados: {count_false_positives()}
"""

    # Enriquece o contexto com riscos prioritários do Risk Engine (se disponível)
    try:
        if "risk" in locals() and risk:
            executive_context += "\nRiscos prioritários:\n"
            for r in risk.get("riscos_prioritarios", [])[:5]:
                origem = r.get("file") or r.get("endpoint") or r.get("dependency") or "-"
                executive_context += (
                    f"- [{r.get('tool', '')}] {r.get('title', '')} "
                    f"({r.get('priority', '')}) - {origem}\n"
                )
            executive_context += f"\nJustificativa: {risk.get('justificativa', '')}\n"
    except Exception:
        pass

    if st.button("Gerar resumo executivo com IA"):
        summary = ask_executive_summary(executive_context)
        st.subheader("Parecer executivo da IA")
        st.write(summary)


# ═══════════════════════════════════════════════════════════════
# TAB 2 - SEMGREP
# ═══════════════════════════════════════════════════════════════


def render_semgrep_tab():
    st.subheader("Análise SAST - Semgrep")

    uploaded_file = st.file_uploader(
        "Enviar arquivo JSON do Semgrep", type=["json"], key="upload_semgrep"
    )

    if uploaded_file is not None:
        semgrep_data = json.load(uploaded_file)
        st.success("Arquivo JSON do Semgrep carregado com sucesso.")
    else:
        st.info(
            "Nenhum arquivo do Semgrep enviado. Envie um JSON para iniciar a análise SAST."
        )
        semgrep_data = st.session_state.get("consolidated_semgrep", {"results": []})

    semgrep_vulns = get_semgrep_vulnerabilities(semgrep_data)

    if semgrep_vulns:
        df = pd.DataFrame(semgrep_vulns)
        filtered_df = filter_false_positives(df, "semgrep")

        high_count = filtered_df[filtered_df["Prioridade"] == "Alta"].shape[0]
        medium_count = filtered_df[filtered_df["Prioridade"] == "Média"].shape[0]
        low_count = filtered_df[filtered_df["Prioridade"] == "Baixa"].shape[0]

        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Total ativo", len(filtered_df))
        col2.metric("Alta", high_count)
        col3.metric("Média", medium_count)
        col4.metric("Baixa", low_count)

        tabela = filtered_df[
            ["ID", "Arquivo", "Linha", "Severidade", "Prioridade", "Descrição"]
        ]
        render_table_as_cards(
            tabela,
            title_key="ID",
            subtitle_keys=["Arquivo", "Linha", "Severidade"],
            badge_key="Prioridade",
            description_key="Descrição",
            limit=8,
        )
        render_technical_table("Ver tabela técnica completa", tabela)

        csv_data = tabela.to_csv(index=False).encode("utf-8-sig")
        st.download_button("Exportar CSV", csv_data, "semgrep.csv", "text/csv")

        pdf = generate_pdf_report(
            "Relatório Semgrep", f"Total ativo: {len(filtered_df)}", tabela
        )
        st.download_button("Exportar PDF", pdf, "semgrep.pdf", "application/pdf")

        st.subheader("Detalhes Técnicos com IA")

        # Limite de expanders por aba: com relatórios grandes (ex.: 1.500
        # achados do DefectDojo), renderizar um expander por achado trava o
        # Streamlit. Os demais ficam disponíveis na tabela técnica.
        MAX_EXPANDERS = 25
        total_rows = len(filtered_df)
        if total_rows > MAX_EXPANDERS:
            st.caption(
                f"Exibindo os {MAX_EXPANDERS} primeiros achados. "
                f"{total_rows - MAX_EXPANDERS} restantes na tabela técnica acima."
            )

        for idx, (_, row) in enumerate(filtered_df.iterrows()):
            if idx >= MAX_EXPANDERS:
                break
            canonical_id = f"semgrep_{row['ID']}_{row['Arquivo']}_{row['Linha']}"
            widget_key = f"{canonical_id}_{idx}"

            with st.expander(f"{row['ID']} | {row['Arquivo']} | Linha {row['Linha']}"):
                st.write(f"Severidade: {row['Severidade']}")
                st.write(f"Prioridade: {row['Prioridade']}")
                st.write(f"Descrição: {row['Descrição']}")
                st.write("---")
                st.write(f"Explicação IA: {row['Explicação IA']}")
                st.write(f"Risco IA: {row['Risco IA']}")
                st.write(f"Correção IA: {row['Correção IA']}")

                if st.button("Marcar como falso positivo", key=widget_key):
                    add_false_positive(canonical_id)
                    st.rerun()

    else:
        if uploaded_file is None:
            render_empty_state(
                "Aguardando arquivo do Semgrep.",
                "Envie o JSON gerado pelo Semgrep para visualizar os achados de análise estática.",
                "info",
            )
        else:
            st.info("Nenhuma vulnerabilidade encontrada pelo Semgrep.")


# ═══════════════════════════════════════════════════════════════
# TAB 3 - BANDIT
# ═══════════════════════════════════════════════════════════════


def render_bandit_tab():
    st.subheader("Análise Python - Bandit")

    uploaded_bandit = st.file_uploader(
        "Enviar arquivo JSON do Bandit", type=["json"], key="upload_bandit"
    )

    if uploaded_bandit is not None:
        bandit_data = json.load(uploaded_bandit)
        st.success("Arquivo JSON do Bandit carregado com sucesso.")
    else:
        st.info(
            "Nenhum arquivo do Bandit enviado. Envie um JSON para iniciar a análise Python."
        )
        bandit_data = st.session_state.get("consolidated_bandit", {"results": []})

    bandit_vulns = get_bandit_vulnerabilities(bandit_data)

    if bandit_vulns:
        df = pd.DataFrame(bandit_vulns)
        filtered_df = filter_false_positives(df, "bandit")

        high_count = filtered_df[filtered_df["Prioridade"] == "Alta"].shape[0]
        medium_count = filtered_df[filtered_df["Prioridade"] == "Média"].shape[0]
        low_count = filtered_df[filtered_df["Prioridade"] == "Baixa"].shape[0]

        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Total ativo", len(filtered_df))
        col2.metric("Alta", high_count)
        col3.metric("Média", medium_count)
        col4.metric("Baixa", low_count)

        tabela = filtered_df[
            [
                "Teste",
                "Arquivo",
                "Linha",
                "Severidade",
                "Confiança",
                "Prioridade",
                "Descrição",
            ]
        ]
        render_table_as_cards(
            tabela,
            title_key="Teste",
            subtitle_keys=["Arquivo", "Linha", "Severidade", "Confiança"],
            badge_key="Prioridade",
            description_key="Descrição",
            limit=8,
        )
        render_technical_table("Ver tabela técnica completa", tabela)

        csv_data = tabela.to_csv(index=False).encode("utf-8-sig")
        st.download_button("Exportar CSV", csv_data, "bandit.csv", "text/csv")

        pdf = generate_pdf_report(
            "Relatório Bandit", f"Total ativo: {len(filtered_df)}", tabela
        )
        st.download_button("Exportar PDF", pdf, "bandit.pdf", "application/pdf")

        st.subheader("Detalhamento com IA")

        # Limite de expanders (mesma política da aba Semgrep)
        MAX_EXPANDERS = 25
        total_rows = len(filtered_df)
        if total_rows > MAX_EXPANDERS:
            st.caption(
                f"Exibindo os {MAX_EXPANDERS} primeiros achados. "
                f"{total_rows - MAX_EXPANDERS} restantes na tabela técnica acima."
            )

        for idx, (_, row) in enumerate(filtered_df.iterrows()):
            if idx >= MAX_EXPANDERS:
                break
            canonical_id = f"bandit_{row['Teste']}_{row['Arquivo']}_{row['Linha']}"
            widget_key = f"{canonical_id}_{idx}"

            with st.expander(
                f"{row['Teste']} | {row['Arquivo']} | Linha {row['Linha']}"
            ):
                st.write(f"Severidade: {row['Severidade']}")
                st.write(f"Confiança: {row['Confiança']}")
                st.write(f"Prioridade: {row['Prioridade']}")
                st.write(f"Descrição: {row['Descrição']}")
                st.write("---")
                st.write(f"Explicação IA: {row['Explicação IA']}")
                st.write(f"Risco IA: {row['Risco IA']}")
                st.write(f"Correção IA: {row['Correção IA']}")

                if st.button("Marcar como falso positivo", key=widget_key):
                    add_false_positive(canonical_id)
                    st.rerun()

    else:
        if uploaded_bandit is None:
            render_empty_state(
                "Aguardando arquivo do Bandit.",
                "Envie o JSON gerado pelo Bandit para visualizar os achados de segurança Python.",
                "info",
            )
        else:
            st.success("Nenhum achado encontrado pelo Bandit.")


# ═══════════════════════════════════════════════════════════════
# TAB 4 - SCA
# ═══════════════════════════════════════════════════════════════


def render_sca_tab():
    st.subheader("Software Composition Analysis - SCA")

    uploaded_sca = st.file_uploader(
        "Enviar arquivo JSON da SCA", type=["json"], key="upload_sca"
    )

    if uploaded_sca is not None:
        sca_data = json.load(uploaded_sca)
        st.success("Arquivo SCA carregado com sucesso.")
    else:
        st.info(
            "Nenhum arquivo SCA enviado. Envie um JSON para iniciar a análise de dependências."
        )
        sca_data = st.session_state.get("consolidated_sca", {"dependencies": []})

    sca_vulns = get_sca_vulnerabilities(sca_data)

    # ── Inventário de dependências (SBOM-lite) ──
    # Visão por pacote: risco agregado e versões corrigidas.
    # Aprendizado do estudo DefectDojo: priorizar por pacote, não por CVE solta.
    try:
        from src.core.inventory import inventory_summary, package_table_rows

        summary = inventory_summary(sca_data)
        if summary["total_packages"] > 0:
            st.subheader("Inventário de dependências")
            c1, c2, c3, c4 = st.columns(4)
            c1.metric("Dependências", summary["total_packages"])
            c2.metric("Com vulnerabilidades", summary["packages_with_vulns"])
            c3.metric("CVEs totais", summary["total_vulns"])
            c4.metric("Críticas/Alta", summary["by_risk"]["Crítica"] + summary["by_risk"]["Alta"])

            rows = package_table_rows(sca_data, limit=15)
            st.dataframe(pd.DataFrame(rows), use_container_width=True)

            if summary["critical_packages"]:
                st.caption(
                    "Prioridade de atualização: " + ", ".join(summary["critical_packages"])
                )
    except Exception as e:
        st.caption(f"Inventário indisponível: {e}")

    if sca_vulns:
        df = pd.DataFrame(sca_vulns)
        filtered_df = filter_false_positives(df, "sca")

        high_count = filtered_df[filtered_df["Prioridade"] == "Alta"].shape[0]
        medium_count = filtered_df[filtered_df["Prioridade"] == "Média"].shape[0]

        col1, col2, col3 = st.columns(3)
        col1.metric("Total ativo", len(filtered_df))
        col2.metric("Alta", high_count)
        col3.metric("Média", medium_count)

        tabela = filtered_df[
            [
                "Biblioteca",
                "Versão Atual",
                "CVE",
                "Prioridade",
                "Correção Disponível",
                "Descrição",
            ]
        ]
        render_table_as_cards(
            tabela,
            title_key="Biblioteca",
            subtitle_keys=["Versão Atual", "CVE", "Correção Disponível"],
            badge_key="Prioridade",
            description_key="Descrição",
            limit=8,
        )
        render_technical_table("Ver tabela técnica completa", tabela)

        csv_data = tabela.to_csv(index=False).encode("utf-8-sig")
        st.download_button("Exportar CSV", csv_data, "sca.csv", "text/csv")

        pdf = generate_pdf_report(
            "Relatório SCA",
            f"Total ativo de vulnerabilidades: {len(filtered_df)}",
            tabela,
        )
        st.download_button("Exportar PDF", pdf, "sca.pdf", "application/pdf")

        st.subheader("Detalhamento com IA")

        # Limite de expanders (mesma política da aba Semgrep)
        MAX_EXPANDERS = 25
        total_rows = len(filtered_df)
        if total_rows > MAX_EXPANDERS:
            st.caption(
                f"Exibindo os {MAX_EXPANDERS} primeiros achados. "
                f"{total_rows - MAX_EXPANDERS} restantes na tabela técnica acima."
            )

        for idx, (_, row) in enumerate(filtered_df.iterrows()):
            if idx >= MAX_EXPANDERS:
                break
            canonical_id = f"sca_{row['Biblioteca']}_{row['CVE']}"
            widget_key = f"{canonical_id}_{idx}"

            with st.expander(f"{row['Biblioteca']} | {row['CVE']}"):
                st.write(f"Versão Atual: {row['Versão Atual']}")
                st.write(f"Prioridade: {row['Prioridade']}")
                st.write(f"Correção Disponível: {row['Correção Disponível']}")
                st.write(f"Descrição: {row['Descrição']}")
                st.write("---")
                st.write(f"Explicação IA: {row['Explicação IA']}")
                st.write(f"Risco IA: {row['Risco IA']}")
                st.write(f"Correção IA: {row['Correção IA']}")

                if st.button("Marcar como falso positivo", key=widget_key):
                    add_false_positive(canonical_id)
                    st.rerun()

    else:
        if uploaded_sca is None:
            render_empty_state(
                "Aguardando arquivo SCA.",
                "Envie o JSON da análise de dependências para visualizar CVEs, versões vulneráveis e correções disponíveis.",
                "info",
            )
        else:
            st.success("Nenhuma vulnerabilidade encontrada na SCA.")


# ═══════════════════════════════════════════════════════════════
# TAB 5 - URL ANALYSIS
# ═══════════════════════════════════════════════════════════════


def render_url_tab():
    st.subheader("Análise Passiva de URL")

    if not can("url_analysis"):
        st.warning("Acesso restrito aos perfis Analista e Administrador.")
        st.stop()

    url = st.text_input("Digite a URL", placeholder="https://exemplo.com")

    usar_ia_url = st.checkbox("Usar IA para explicar cada achado da URL", value=True)

    enum_subdominios = st.checkbox(
        "Incluir subdomínios (crt.sh, passivo)", value=True
    )

    fazer_crawl = st.checkbox(
        "Crawl de páginas internas (limitado, mesmo domínio)", value=True
    )

    limite_ia_url = st.number_input(
        "Limite de achados explicados pela IA", min_value=1, max_value=50, value=10
    )

    allow_private = st.checkbox(
        "Alvo em laboratório local (permitir IPs privados/loopback)",
        key="url_allow_private",
    )

    if st.button("Analisar URL"):
        if not url.strip():
            st.warning("Digite uma URL.")
        else:
            from src.core.target_guard import check_target

            ok, msg = check_target(url, allow_private)
            if not ok:
                st.error(msg)
                st.stop()

            with st.spinner("Analisando URL..."):
                st.session_state.last_url_scan = analyze_url(
                    url,
                    subdomains=enum_subdominios,
                    crawl=fazer_crawl,
                    crawl_max=12,
                )

    result = st.session_state.last_url_scan

    if result:
        st.write(f"URL Final: {result['url_final']}")
        st.write(f"Domínio: {result['dominio']}")
        st.write(f"Status HTTP: {result['status_code']}")

        url_df = pd.DataFrame(result["findings"])

        manual_filtered_url_df = url_df[
            ~url_df.apply(
                lambda row: is_false_positive(
                    f"url_{row['Tipo']}_{row['Categoria']}_{row['Item']}"
                ),
                axis=1,
            )
        ]

        active_url_df = manual_filtered_url_df[
            manual_filtered_url_df["Tipo"] == "Achado Ativo"
        ]
        improvements_df = manual_filtered_url_df[
            manual_filtered_url_df["Tipo"] == "Melhoria Recomendada"
        ]
        controls_ok_df = manual_filtered_url_df[
            manual_filtered_url_df["Tipo"] == "Controle OK"
        ]
        auto_fp_df = manual_filtered_url_df[
            manual_filtered_url_df["Tipo"] == "Falso Positivo Automático"
        ]

        high_count = active_url_df[active_url_df["Prioridade"] == "Alta"].shape[0]
        medium_count = active_url_df[active_url_df["Prioridade"] == "Média"].shape[0]
        low_count = active_url_df[active_url_df["Prioridade"] == "Baixa"].shape[0]
        discovery_count = active_url_df[
            active_url_df["Categoria"] == "Discovery"
        ].shape[0]
        improvement_count = len(improvements_df)
        auto_fp_count = len(auto_fp_df)
        controls_ok_count = len(controls_ok_df)

        # Salva automaticamente no histórico após cada análise
        auto_save_url_scan_once(result, high_count, medium_count, low_count)

        st.subheader("Resumo da Análise")

        kpi_col1, kpi_col2, kpi_col3, kpi_col4 = st.columns(4)

        with kpi_col1:
            render_status_card(
                "Security Score",
                result["score"],
                "Pontuação calculada apenas com achados ativos.",
                "good"
                if result["score"] >= 85
                else "warning"
                if result["score"] >= 65
                else "critical",
            )

        with kpi_col2:
            render_status_card(
                "Achados Ativos",
                len(active_url_df),
                "Vulnerabilidades ou riscos com evidência real.",
                "critical" if len(active_url_df) > 0 else "good",
            )

        with kpi_col3:
            render_status_card(
                "Melhorias",
                improvement_count,
                "Itens de hardening recomendados.",
                "warning" if improvement_count > 0 else "good",
            )

        with kpi_col4:
            render_status_card(
                "Controles OK",
                controls_ok_count,
                "Controles verificados e funcionando.",
                "good",
            )

        kpi_col5, kpi_col6, kpi_col7, kpi_col8 = st.columns(4)

        with kpi_col5:
            render_status_card(
                "Alta",
                high_count,
                "Prioridade imediata.",
                "critical" if high_count > 0 else "good",
            )

        with kpi_col6:
            render_status_card(
                "Média",
                medium_count,
                "Correção planejada.",
                "warning" if medium_count > 0 else "good",
            )

        with kpi_col7:
            render_status_card("Baixa", low_count, "Baixo impacto.", "info")

        with kpi_col8:
            # Falsos positivos: visíveis apenas para o Administrador
            if is_admin():
                render_status_card(
                    "Falsos Positivos",
                    auto_fp_count,
                    "Itens descartados automaticamente.",
                    "info",
                )

        chart_col1, chart_col2 = st.columns(2)

        with chart_col1:
            st.subheader("Distribuição da Análise de URL")
            chart_rows = [
                {"Tipo": "Achados Ativos", "Quantidade": len(active_url_df)},
                {"Tipo": "Melhorias", "Quantidade": improvement_count},
                {"Tipo": "Controles OK", "Quantidade": controls_ok_count},
            ]
            if is_admin():
                chart_rows.append({"Tipo": "Falsos Positivos", "Quantidade": auto_fp_count})
            url_distribution_chart = pd.DataFrame(chart_rows)
            render_donut_chart(
                url_distribution_chart, "Tipo", "Quantidade", "Resultado por tipo"
            )

        with chart_col2:
            st.subheader("Prioridade dos Achados Ativos")
            url_priority_chart = pd.DataFrame(
                [
                    {"Prioridade": "Alta", "Quantidade": high_count},
                    {"Prioridade": "Média", "Quantidade": medium_count},
                    {"Prioridade": "Baixa", "Quantidade": low_count},
                ]
            )
            render_donut_chart(
                url_priority_chart, "Prioridade", "Quantidade", "Achados por prioridade"
            )

        st.subheader("Achados Ativos")

        if active_url_df.empty:
            render_empty_state(
                "Nenhuma vulnerabilidade ativa encontrada.",
                "A análise não encontrou evidências fortes de exposição, vazamento, debug, stack trace, API sensível ou painel acessível sem autenticação.",
                "good",
            )
        else:
            render_compact_cards(active_url_df, limit=6)
            render_technical_table(
                "Ver tabela técnica de achados ativos", active_url_df
            )

        st.subheader("Melhorias Recomendadas")

        if improvements_df.empty:
            render_empty_state(
                "Nenhuma melhoria obrigatória identificada.",
                "Os principais pontos de hardening analisados não geraram recomendações adicionais.",
                "good",
            )
        else:
            render_compact_cards(improvements_df, limit=8)
            render_technical_table("Ver tabela técnica de melhorias", improvements_df)

        st.subheader("Controles OK")

        if controls_ok_df.empty:
            render_empty_state(
                "Nenhum controle validado nesta análise.",
                "A ferramenta não encontrou controles classificados como OK para esta URL.",
                "info",
            )
        else:
            render_compact_cards(controls_ok_df, limit=8)
            render_technical_table("Ver tabela técnica de controles OK", controls_ok_df)

        # Falsos positivos: seção visível apenas para o Administrador
        if is_admin():
            st.subheader("Falsos Positivos Detectados Automaticamente")

            if auto_fp_df.empty:
                render_empty_state(
                    "Nenhum falso positivo automático identificado.",
                    "Todos os itens encontrados foram classificados como controles, melhorias ou achados ativos.",
                    "info",
                )
            else:
                render_compact_cards(auto_fp_df, limit=8)
                render_technical_table("Ver tabela técnica de falsos positivos", auto_fp_df)

        csv_url = active_url_df.to_csv(index=False).encode("utf-8-sig")
        st.download_button(
            "Exportar CSV - Achados Ativos", csv_url, "url_analysis.csv", "text/csv"
        )

        pdf_url = generate_pdf_report(
            "Relatório URL Analysis",
            f"URL analisada: {result['url_final']} | Score: {result['score']} | Classificação: {result['classificacao']}",
            active_url_df,
        )
        st.download_button(
            "Exportar PDF - Achados Ativos",
            pdf_url,
            "url_analysis.pdf",
            "application/pdf",
        )

        st.subheader("Detalhamento com IA")

        detail_df = pd.concat(
            [active_url_df, improvements_df, controls_ok_df], ignore_index=True
        )

        # Limite de expanders (mesma política das demais abas)
        MAX_EXPANDERS = 25
        total_detail = len(detail_df)
        if total_detail > MAX_EXPANDERS:
            st.caption(
                f"Exibindo os {MAX_EXPANDERS} primeiros itens. "
                f"{total_detail - MAX_EXPANDERS} restantes nas tabelas acima."
            )

        for index, (_, row) in enumerate(detail_df.iterrows()):
            if index >= MAX_EXPANDERS:
                break
            canonical_id = f"url_{row['Tipo']}_{row['Categoria']}_{row['Item']}"
            widget_key = f"{canonical_id}_{index}"

            description_for_ai = (
                f"Tipo: {row['Tipo']}. "
                f"Status: {row['Status']}. "
                f"Evidências: {row['Evidências']}. "
                f"{row['Descrição']}"
            )

            if usar_ia_url and index < limite_ia_url:
                ai_result = ask_ai(row["Item"], description_for_ai)
            else:
                ai_result = local_ai_fallback(row["Item"], description_for_ai)

            with st.expander(
                f"{row['Tipo']} | {row['Categoria']} | {row['Item']} | {row['Status']}"
            ):
                st.write(f"Tipo: {row['Tipo']}")
                st.write(f"Categoria: {row['Categoria']}")
                st.write(f"Status: {row['Status']}")
                st.write(f"Prioridade: {row['Prioridade']}")
                st.write(f"Evidências: {row['Evidências']}")
                st.write(f"Descrição: {row['Descrição']}")
                st.write("---")
                st.write(f"Explicação IA: {ai_result['explicacao']}")
                st.write(f"Risco IA: {ai_result['risco']}")
                st.write(f"Correção IA: {ai_result['correcao']}")

                if row["Tipo"] == "Achado Ativo":
                    if st.button("Marcar como falso positivo", key=widget_key):
                        add_false_positive(canonical_id)
                        st.rerun()

        if is_admin() and not auto_fp_df.empty:
            st.subheader("Explicação dos Falsos Positivos Automáticos")

            for _, row in auto_fp_df.iterrows():
                with st.expander(f"Falso positivo | {row['Item']} | {row['Status']}"):
                    st.write(f"Endpoint: {row['Item']}")
                    st.write(f"Status: {row['Status']}")
                    st.write(f"Motivo: {row['Descrição']}")
                    st.write(
                        "Esse item foi separado automaticamente porque o sistema não encontrou "
                        "evidência suficiente de vulnerabilidade real no conteúdo da página."
                    )

        st.caption("A análise atual é salva automaticamente no histórico.")


# ═══════════════════════════════════════════════════════════════
# TAB 6 - SECRETS
# ═══════════════════════════════════════════════════════════════


def render_secrets_tab():
    st.subheader("Secrets Scanner")

    st.info(
        "Use esta aba para detectar segredos em arquivos do projeto ou importar um relatório JSON do Gitleaks."
    )

    uploaded_secret_files = st.file_uploader(
        "Enviar arquivos de código para análise de segredos",
        type=[
            "py",
            "js",
            "ts",
            "tsx",
            "jsx",
            "json",
            "env",
            "txt",
            "yaml",
            "yml",
            "ini",
            "cfg",
            "toml",
        ],
        accept_multiple_files=True,
        key="upload_secret_files",
    )

    uploaded_gitleaks = st.file_uploader(
        "Enviar relatório JSON do Gitleaks", type=["json"], key="upload_gitleaks_json"
    )

    secret_findings = []

    if uploaded_secret_files or uploaded_gitleaks is not None:
        if uploaded_secret_files:
            secret_findings.extend(scan_uploaded_files_for_secrets(uploaded_secret_files))

        if uploaded_gitleaks is not None:
            try:
                gitleaks_data = json.load(uploaded_gitleaks)
                secret_findings.extend(parse_gitleaks_json(gitleaks_data))
                st.success("Relatório Gitleaks carregado com sucesso.")
            except Exception as e:
                st.error(f"Erro ao carregar JSON do Gitleaks: {e}")

        st.session_state.secret_results = secret_findings
    else:
        # Sem novo upload: mantém o que já está carregado na sessão
        # (ex: upload consolidado na sidebar ou modo demonstração)
        secret_findings = st.session_state.get("secret_results", [])

    secret_df = pd.DataFrame(secret_findings)

    if secret_df.empty:
        render_empty_state(
            "Nenhum segredo analisado.",
            "Envie arquivos do projeto ou um JSON do Gitleaks para iniciar o Secrets Scanner.",
            "info",
        )
    else:
        high_count, medium_count, low_count = calculate_secret_counts(secret_df)

        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Segredos", len(secret_df))
        col2.metric("Alta", high_count)
        col3.metric("Média", medium_count)
        col4.metric("Baixa", low_count)

        render_table_as_cards(
            secret_df,
            title_key="Regra",
            subtitle_keys=["Origem", "Arquivo", "Linha"],
            badge_key="Prioridade",
            description_key="Descrição",
            limit=10,
        )

        render_technical_table("Ver tabela técnica de secrets", secret_df)

        csv_secrets = secret_df.to_csv(index=False).encode("utf-8-sig")
        st.download_button(
            "Exportar CSV - Secrets", csv_secrets, "secrets_scan.csv", "text/csv"
        )

        pdf_secrets = generate_pdf_report(
            "Relatório Secrets Scanner",
            f"Total de possíveis segredos encontrados: {len(secret_df)}",
            secret_df,
        )
        st.download_button(
            "Exportar PDF - Secrets", pdf_secrets, "secrets_scan.pdf", "application/pdf"
        )


# ═══════════════════════════════════════════════════════════════
# TAB 7 - ATTACK SURFACE
# ═══════════════════════════════════════════════════════════════


def render_attack_surface_tab():
    st.subheader("Attack Surface")

    current_url_result = st.session_state.get("last_url_scan")

    if not current_url_result:
        render_empty_state(
            "Nenhuma superfície de ataque carregada.",
            "Execute uma análise em URL Analysis para visualizar endpoints, controles, melhorias e falsos positivos contextualizados.",
            "info",
        )
    else:
        attack_df = pd.DataFrame(current_url_result.get("findings", []))

        if attack_df.empty:
            render_empty_state(
                "Nenhum dado de superfície encontrado.",
                "A última análise não retornou endpoints ou controles para exibição.",
                "info",
            )
        else:
            discovery_df = attack_df[attack_df["Categoria"] == "Discovery"]
            active_df = attack_df[attack_df["Tipo"] == "Achado Ativo"]
            improvements_df = attack_df[attack_df["Tipo"] == "Melhoria Recomendada"]
            controls_df = attack_df[attack_df["Tipo"] == "Controle OK"]
            false_positive_df = attack_df[
                attack_df["Tipo"] == "Falso Positivo Automático"
            ]

            col1, col2, col3, col4 = st.columns(4)
            col1.metric("Endpoints", len(discovery_df))
            col2.metric("Achados Ativos", len(active_df))
            col3.metric("Melhorias", len(improvements_df))
            col4.metric("Falsos Positivos", len(false_positive_df))

            # Resumo do domínio analisado (escapado antes de montar o HTML)
            dominio = html.escape(str(current_url_result.get("dominio", "-")))
            url_final = html.escape(str(current_url_result.get("url_final", "-")))
            status_code = html.escape(str(current_url_result.get("status_code", "-")))
            st.markdown(
                f"""
                <div class="enterprise-card" style="margin-bottom: 1rem;">
                    <div style="font-size:0.72rem; color:#94a3b8; font-weight:800; text-transform:uppercase; letter-spacing:0.08em;">Domínio Analisado</div>
                    <div style="font-weight:950; color:#f8fafc; font-size:1.2rem; margin-top:0.3rem;">{dominio}</div>
                    <div style="color:#94a3b8; font-size:0.82rem; margin-top:0.2rem;">{url_final} · HTTP {status_code}</div>
                </div>
                """,
                unsafe_allow_html=True,
            )

            # Classificação dos endpoints por categoria
            st.subheader("Classificação dos Endpoints")
            cat_counts = attack_df["Categoria"].value_counts().to_dict()
            if cat_counts:
                cat_labels = {
                    "Discovery": "Discovery",
                    "Headers": "Headers",
                    "Cookies": "Cookies",
                    "HTTPS": "HTTPS",
                    "TLS": "TLS",
                    "Rede": "Rede",
                    "Exposição": "Exposição",
                }
                cat_cols = st.columns(min(len(cat_counts), 4))
                for idx, (cat, qtd) in enumerate(list(cat_counts.items())[:4]):
                    with cat_cols[idx]:
                        st.metric(cat_labels.get(cat, cat), qtd)
            else:
                st.caption("Nenhuma categoria identificada.")

            # Paths sensíveis encontrados no discovery
            sens_paths = [
                f for f in discovery_df.to_dict("records")
                if str(f.get("Item", "")).startswith("/")
            ]
            if sens_paths:
                sens_cats = {"Admin/Login": [], "API": [], "Debug/Dev": [], "Sensíveis": []}
                for p in sens_paths:
                    item_lower = str(p.get("Item", "")).lower()
                    if any(x in item_lower for x in ["admin", "login", "dashboard", "wp-admin"]):
                        sens_cats["Admin/Login"].append(p.get("Item"))
                    elif any(x in item_lower for x in ["api", "graphql", "swagger", "openapi", "docs"]):
                        sens_cats["API"].append(p.get("Item"))
                    elif any(x in item_lower for x in ["debug", "dev", "test", "actuator", "phpinfo", "config"]):
                        sens_cats["Debug/Dev"].append(p.get("Item"))
                    elif any(x in item_lower for x in ["env", "git", "backup", "sql", "htaccess", "aws"]):
                        sens_cats["Sensíveis"].append(p.get("Item"))

                with st.expander("Paths sensíveis identificados por categoria"):
                    for cat, items in sens_cats.items():
                        if items:
                            st.markdown(f"**{cat}** ({len(items)})")
                            st.write(", ".join(str(i) for i in items[:10]))
                            st.markdown("---")

            distribution_df = pd.DataFrame(
                [
                    {"Tipo": "Achados Ativos", "Quantidade": len(active_df)},
                    {"Tipo": "Melhorias", "Quantidade": len(improvements_df)},
                    {"Tipo": "Controles OK", "Quantidade": len(controls_df)},
                    {"Tipo": "Falsos Positivos", "Quantidade": len(false_positive_df)},
                ]
            )
            render_donut_chart(
                distribution_df, "Tipo", "Quantidade", "Superfície por classificação"
            )

            st.subheader("Endpoints descobertos")
            if discovery_df.empty:
                render_empty_state(
                    "Nenhum endpoint de discovery identificado.",
                    "A análise não encontrou rotas relevantes no discovery contextual.",
                    "info",
                )
            else:
                render_table_as_cards(
                    discovery_df,
                    title_key="Item",
                    subtitle_keys=["Tipo", "Status", "Prioridade"],
                    badge_key="Tipo",
                    description_key="Descrição",
                    limit=12,
                )
                render_technical_table(
                    "Ver tabela técnica da superfície de ataque", discovery_df
                )

        # Headers de segurança e cookies detectados
        if current_url_result:
            headers_findings = [
                f
                for f in attack_df.to_dict("records")
                if f.get("Categoria") in ("Headers", "Cookies")
            ]
            if headers_findings:
                st.subheader("Headers de Segurança e Cookies")
                headers_df = pd.DataFrame(headers_findings)
                render_compact_cards(
                    headers_df,
                    title_col="Item",
                    subtitle_col="Status",
                    limit=10,
                )

        # Subdomínios via Certificate Transparency (crt.sh) — informativo
        subdominios = current_url_result.get("subdominios", [])
        if subdominios:
            st.subheader(f"Subdomínios identificados ({len(subdominios)})")
            st.caption("Fonte: Certificate Transparency (crt.sh) — consulta pública e passiva.")
            st.write(", ".join(subdominios[:40]))

        # Páginas internas mapeadas no crawl (informativo)
        crawl_links = current_url_result.get("crawl_links", [])
        if crawl_links:
            with st.expander(f"Páginas internas mapeadas no crawl ({len(crawl_links)})"):
                st.write("\n".join(crawl_links))

        # Tecnologias detectadas
        if current_url_result:
            tech_indicators = []
            url_lower = str(current_url_result.get("url_final", "")).lower()
            tech_map = {
                "WordPress": ["wp-", "wp-content", "wordpress"],
                "Nginx": ["nginx"],
                "Apache": ["apache"],
                "Cloudflare": ["cloudflare"],
                "React": ["react", "_next"],
                "ASP.NET": ["asp.net", "aspx"],
                "PHP": [".php", "phpmyadmin"],
                "Node.js": ["node_modules", "package.json"],
                "GraphQL": ["graphql"],
                "Swagger": ["swagger", "openapi"],
            }
            for tech, patterns in tech_map.items():
                if any(p in url_lower for p in patterns):
                    tech_indicators.append(tech)
            if tech_indicators:
                st.subheader("Tecnologias Detectadas")
                st.write(", ".join(tech_indicators))


# ═══════════════════════════════════════════════════════════════
# TAB 8 - TESTES OFENSIVOS (LABORATÓRIO AUTORIZADO)
# ═══════════════════════════════════════════════════════════════


def render_offensive_tab():
    st.subheader("Testes Ofensivos (Laboratório Autorizado)")

    if not can("scan"):
        st.warning("Acesso restrito aos perfis Analista e Administrador.")
        st.stop()

    autorizado = st.checkbox(
        "Confirmo que tenho autorização para testar este alvo", value=False
    )

    url = st.text_input("URL do alvo", placeholder="https://alvo-autorizado.com")

    mods = st.multiselect(
        "Módulos",
        ["recon", "idor", "fuzz", "rate", "cors", "methods", "traversal", "redirect", "sqli", "xss", "creds"],
        default=["recon", "idor", "fuzz", "rate", "cors", "methods", "traversal", "redirect", "sqli", "xss", "creds"],
        format_func=lambda m: {
            "recon": "Recon Ativo (portas)",
            "idor": "IDOR / Enumeração de IDs",
            "fuzz": "API Fuzzing (caminhos comuns)",
            "rate": "Rate Limit",
            "cors": "CORS Misconfiguration",
            "methods": "HTTP Methods / TRACE",
            "traversal": "Path Traversal (LFI)",
            "redirect": "Open Redirect",
            "sqli": "SQL Injection (detecção)",
            "xss": "XSS Refletido (detecção)",
            "creds": "Credenciais comuns (LAB)",
        }[m],
    )

    id_param = st.text_input("Parâmetro de ID (IDOR)", value="id")
    traversal_param = st.text_input("Parâmetro de arquivo (Path Traversal)", value="file")
    web_param = st.text_input("Parâmetro de teste (SQLi / XSS)", value="id")

    allow_private = st.checkbox(
        "Alvo em laboratório local (permitir IPs privados/loopback)",
        key="off_allow_private",
    )

    if st.button(
        "Executar testes",
        disabled=not (autorizado and url.strip()),
        use_container_width=True,
    ):
        from src.core.target_guard import check_target

        ok, msg = check_target(url, allow_private)
        if not ok:
            st.error(msg)
            st.stop()

        with st.spinner("Executando testes (limitados e sem ações destrutivas)..."):
            st.session_state.attack_results = run_attack_modules(
                url,
                modules=mods,
                id_param=id_param,
                traversal_param=traversal_param,
                web_param=web_param,
            )

    result = st.session_state.get("attack_results")

    if not result:
        render_empty_state(
            "Nenhum teste executado.",
            "Configure o alvo autorizado, confirme a autorização e execute os módulos.",
            "info",
        )
        return

    df = pd.DataFrame(result["findings"])
    # Ruído (Controle OK / Falso Positivo / Inconclusivo) fica visível apenas
    # para o Administrador; demais perfis veem somente achados relevantes.
    if not is_admin():
        df = df[
            ~df["Tipo"].isin(
                ["Controle OK", "Falso Positivo Automático", "Teste inconclusivo"]
            )
        ]

    if is_admin():
        st.success(
            f"Testes concluídos em {result['target']} — {result['total_findings']} achado(s)"
        )
    else:
        st.success(
            f"Testes concluídos em {result['target']} — {len(df)} achado(s) relevantes"
        )

    if not df.empty:
        alta = df[df["Prioridade"] == "Alta"].shape[0]
        media = df[df["Prioridade"] == "Média"].shape[0]
        baixa = df[df["Prioridade"] == "Baixa"].shape[0]

        c1, c2, c3 = st.columns(3)
        c1.metric("Riscos Altos", alta)
        c2.metric("Riscos Médios", media)
        c3.metric("Baixos / OK", baixa)

        render_table_as_cards(
            df,
            title_key="Item",
            subtitle_keys=["Categoria", "Status"],
            badge_key="Prioridade",
            description_key="Descrição",
            limit=12,
        )
        render_technical_table("Ver tabela técnica completa", df)

    for mod, label in [
        ("recon", "Recon Ativo (portas)"),
        ("idor", "IDOR"),
        ("fuzz", "API Fuzzing"),
        ("rate", "Rate Limit"),
        ("cors", "CORS"),
        ("methods", "HTTP Methods"),
        ("traversal", "Path Traversal"),
        ("redirect", "Open Redirect"),
        ("sqli", "SQL Injection"),
        ("xss", "XSS Refletido"),
        ("creds", "Credenciais comuns"),
    ]:
        if mod in result["module_results"]:
            with st.expander(f"{label} — detalhes"):
                st.json(result["module_results"][mod])


# ═══════════════════════════════════════════════════════════════
# ABA DESATIVADA: "Assets / Ativos" (tab8)
# Para reativar, remova o # de todas as linhas deste bloco
# e reative a linha "Assets / Ativos" na lista de tabs do app.py.
# ═══════════════════════════════════════════════════════════════
#
# def render_assets_tab():
#     st.subheader("📦 Assets / Ativos")
#     st.caption("Cadastre e gerencie os ativos monitorados pela plataforma ASPM.")
#
#     col_add1, col_add2 = st.columns([2, 1])
#
#     with col_add1:
#         with st.expander("➕ Novo Ativo", expanded=False):
#             with st.form("asset_form"):
#                 a_name = st.text_input("Nome do ativo")
#                 a_type = st.selectbox(
#                     "Tipo",
#                     [
#                         "Web App",
#                         "API",
#                         "Repositório",
#                         "Serviço Externo",
#                         "Banco de Dados",
#                         "Outro",
#                     ],
#                 )
#                 a_url = st.text_input("URL ou repositório")
#                 a_tech = st.text_input("Tecnologia principal")
#                 a_crit = st.selectbox(
#                     "Criticidade", ["Baixa", "Média", "Alta", "Crítica"]
#                 )
#                 submitted = st.form_submit_button("Salvar")
#                 if submitted and a_name:
#                     save_asset(a_name, a_type, a_url, a_tech, a_crit)
#                     st.success(f"Ativo '{a_name}' cadastrado!")
#                     st.rerun()
#
#     with col_add2:
#         st.markdown("### Atalhos")
#         quick_types = ["Web App", "API", "Repositório"]
#         for qt in quick_types:
#             if st.button(f"+ {qt}", key=f"qt_{qt}", use_container_width=True):
#                 save_asset(f"Novo {qt}", qt, "", "", "Média")
#                 st.rerun()
#
#     # Lista de ativos
#     all_assets = load_assets()
#
#     if all_assets.empty:
#         render_empty_state(
#             "Nenhum ativo cadastrado.",
#             "Crie um ativo usando o formulário acima ou os atalhos rápidos.",
#             "info",
#         )
#     else:
#         # Enriquecer com dados dos scans
#         enriched = []
#         for _, row in all_assets.iterrows():
#             fid = row["id"]
#             fcount = get_asset_findings_count(fid)
#             # Pega último score do scan_history
#             sh = load_scan_history(asset_id=fid)
#             last_score = sh["score_geral"].iloc[0] if not sh.empty else "-"
#             last_scan = sh["created_at"].iloc[0] if not sh.empty else "Nunca"
#             enriched.append(
#                 {
#                     "ID": fid,
#                     "Nome": row["name"],
#                     "Tipo": row["asset_type"],
#                     "URL/Repo": row["url_or_repo"],
#                     "Criticidade": row["criticidade"],
#                     "Score Risco": last_score,
#                     "Achados": fcount,
#                     "Último Scan": last_scan,
#                 }
#             )
#
#         enriched_df = pd.DataFrame(enriched)
#
#         st.dataframe(enriched_df, use_container_width=True)
#
#         # Ação de deletar
#         with st.expander("🗑️ Remover ativo"):
#             del_opts = {}
#             for _, row in all_assets.iterrows():
#                 del_opts[row["name"]] = row["id"]
#             to_del = st.selectbox(
#                 "Selecionar ativo", list(del_opts.keys()), key="del_asset"
#             )
#             if st.button("Remover ativo", type="primary"):
#                 delete_asset(del_opts[to_del])
#                 st.success(f"Ativo '{to_del}' removido.")
#                 st.rerun()
#
# ═══════════════════════════════════════════════════════════════
# FIM DA ABA DESATIVADA
# ═══════════════════════════════════════════════════════════════


# ═══════════════════════════════════════════════════════════════
# TAB 9 - ENGAGEMENTS & SCANS
# ═══════════════════════════════════════════════════════════════


def render_engagements_tab():
    st.subheader("Engagements & Scans")
    st.caption("Histórico completo de scans associados a ativos.")

    # Reset de histórico (somente admin)
    if can("reset_history"):
        reset_col1, reset_col2 = st.columns([1, 4])
        with reset_col1:
            if st.button("Resetar histórico", type="secondary"):
                clear_url_history()
                st.session_state.last_url_scan = None
                st.session_state.saved_url_scans = set()
                st.success("Histórico de URL resetado.")
                st.rerun()
        with reset_col2:
            st.caption("Limpa o histórico de análises de URL. Disponível apenas para Administrador.")

    # Filtro por ativo
    assets_df_e = load_assets()
    asset_filter_opts = {"Todos": 0}
    for _, row in assets_df_e.iterrows():
        asset_filter_opts[row["name"]] = row["id"]

    selected_filter = st.selectbox("Filtrar por ativo", list(asset_filter_opts.keys()))
    filter_id = asset_filter_opts[selected_filter]

    if filter_id == 0:
        scan_hist_df = load_scan_history()
    else:
        scan_hist_df = load_scan_history(asset_id=filter_id)

    if not scan_hist_df.empty:
        st.dataframe(
            scan_hist_df[
                [
                    "id",
                    "created_at",
                    "asset_name",
                    "total_findings",
                    "high_count",
                    "medium_count",
                    "low_count",
                    "score_geral",
                    "classificacao",
                    "status",
                    "tools_used",
                ]
            ],
            use_container_width=True,
        )

        if len(scan_hist_df) > 1:
            st.subheader("Evolução do Score")
            evo_df = scan_hist_df.sort_values("id")[["created_at", "score_geral"]]
            evo_df = evo_df.set_index("created_at")
            st.line_chart(evo_df)

        csv_data = scan_hist_df.to_csv(index=False).encode("utf-8-sig")
        st.download_button("Exportar CSV", csv_data, "engagements.csv", "text/csv")

    else:
        render_empty_state(
            "Nenhum scan registrado.",
            "Faça upload de um aspm-report.json na sidebar para registrar o primeiro scan.",
            "info",
        )


# ═══════════════════════════════════════════════════════════════
# TAB 10 - ADMINISTRAÇÃO
# ═══════════════════════════════════════════════════════════════


def render_admin_tab():
    st.subheader("Administração")

    if not can("manage_users"):
        st.warning("Acesso restrito ao perfil Administrador.")
        st.stop()

    # ── Criar usuário ──
    with st.expander("Criar usuário", expanded=True):
        with st.form("create_user_form"):
            c1, c2, c3 = st.columns(3)
            with c1:
                new_username = st.text_input("Usuário")
            with c2:
                new_password = st.text_input("Senha", type="password")
            with c3:
                new_role = st.selectbox("Perfil", ["analista", "visualizador", "admin"])
            submitted_user = st.form_submit_button("Criar usuário")
            if submitted_user:
                if not new_username or not new_password:
                    st.error("Informe usuário e senha.")
                else:
                    try:
                        criado = register_user(new_username, new_password, new_role)
                    except ValueError as e:
                        st.error(str(e))
                    else:
                        if criado:
                            st.success(
                                f"Usuário '{new_username}' criado com perfil {ROLE_LABELS.get(new_role, new_role)}."
                            )
                            st.rerun()
                        else:
                            st.error("Usuário já existe.")

    # ── Lista de usuários ──
    users_df = load_users()
    if not users_df.empty:
        display_df = users_df.copy()
        display_df["perfil"] = display_df["role"].map(lambda r: ROLE_LABELS.get(r, r))
        st.dataframe(display_df[["id", "username", "perfil", "created_at"]], use_container_width=True)

        # ── Remover usuário ──
        with st.expander("Remover usuário"):
            del_opts = {}
            for _, row in users_df.iterrows():
                if row["username"] != "admin":
                    del_opts[row["username"]] = row["id"]
            if del_opts:
                to_del = st.selectbox("Selecionar usuário", list(del_opts.keys()))
                if st.button("Remover usuário", type="primary"):
                    if delete_user(del_opts[to_del]):
                        st.success(f"Usuário '{to_del}' removido.")
                        st.rerun()
            else:
                st.caption("Nenhum usuário removível além do admin.")

    # ── Sessões registradas ──
    with st.expander("Sessões de acesso registradas"):
        conn = sqlite3.connect(DB_PATH)
        sessions_df = pd.read_sql_query(
            "SELECT id, username, login_at FROM sessions ORDER BY id DESC LIMIT 20", conn
        )
        conn.close()
        if not sessions_df.empty:
            st.dataframe(sessions_df, use_container_width=True)
        else:
            st.caption("Nenhuma sessão registrada ainda.")

    # ── Memória da IA ──
    with st.expander("Memória da IA (análises recentes)"):
        memory_df = load_ai_memory(limit=20)
        if not memory_df.empty:
            st.caption(
                f"{len(memory_df)} análises mais recentes persistidas pelo engine de IA "
                "(explicações, riscos e correções de cada achado)."
            )
            st.dataframe(memory_df, use_container_width=True)
        else:
            st.caption(
                "Nenhuma análise da IA registrada ainda. As explicações dos achados "
                "são salvas automaticamente conforme o dashboard processa findings."
            )


# ═══════════════════════════════════════════════════════════════
# TAB 11 - CI/CD & TEMPLATES (GitHub Actions + XSS)
# ═══════════════════════════════════════════════════════════════


def render_ci_cd_tab():
    st.subheader("CI/CD & Templates")

    if not can("scan"):
        st.warning("Acesso restrito aos perfis Analista e Administrador.")
        st.stop()

    st.markdown(
        """
        <div class="enterprise-card">
            <div class="enterprise-muted">
                Análise dedicada de <b>GitHub Actions</b> (shell injection, secrets herdados,
                <code>pull_request_target</code>, permissões amplas) e de <b>templates</b>
                (XSS por <code>autoescape off</code>, <code>|safe</code> e <code>blocktranslate</code>).
                Aprendizado do estudo DefectDojo: 21 shell-injections e 175 XSS em templates.
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    from src.core.github_actions import scan_repo_workflows
    from src.core.template_xss import scan_repo_templates

    repo_path = st.text_input(
        "Caminho do repositório",
        placeholder="ex.: C:/projetos/meu-app",
        key="ci_repo_path",
    )

    if st.button("Analisar CI/CD e Templates", type="primary"):
        if not repo_path.strip():
            st.warning("Informe o caminho do repositório.")
        else:
            with st.spinner("Analisando workflows e templates..."):
                workflows = scan_repo_workflows(repo_path)
                templates = scan_repo_templates(repo_path)
                st.session_state["ci_cd_findings"] = {
                    "workflows": workflows,
                    "templates": templates,
                    "repo": repo_path,
                }
            st.success(
                f"Análise concluída: {len(workflows)} achado(s) em workflows, "
                f"{len(templates)} em templates."
            )

    result = st.session_state.get("ci_cd_findings")
    if not result:
        render_empty_state(
            "Nenhuma análise de CI/CD executada.",
            "Informe o caminho de um repositório e clique em Analisar. "
            "Funciona com o DefectDojo clonado ou qualquer projeto com .github/workflows.",
            "info",
        )
        return

    workflows = result["workflows"]
    templates = result["templates"]

    c1, c2, c3 = st.columns(3)
    c1.metric("Workflows", f"{len(workflows)} achados")
    c2.metric("Templates", f"{len(templates)} achados")
    c3.metric("Total", len(workflows) + len(templates))

    # ── GitHub Actions ──
    st.markdown("### GitHub Actions")
    if workflows:
        wf_df = pd.DataFrame(workflows)
        high = wf_df[wf_df["Prioridade"] == "Alta"].shape[0]
        st.caption(f"{len(workflows)} achados (Alta: {high})")
        render_table_as_cards(
            wf_df,
            title_key="Item",
            subtitle_keys=["Categoria", "Evidências"],
            badge_key="Prioridade",
            description_key="Descrição",
            limit=10,
        )
        render_technical_table("Ver tabela técnica dos workflows", wf_df)
        csv = wf_df.to_csv(index=False).encode("utf-8-sig")
        st.download_button("Exportar CSV - CI/CD", csv, "ci_cd_workflows.csv", "text/csv")
    else:
        render_empty_state(
            "Nenhum risco em workflows.",
            "Não foram encontrados padrões de shell injection, secrets herdados ou pull_request_target.",
            "good",
        )

    # ── Templates ──
    st.markdown("### Templates (XSS)")
    if templates:
        tpl_df = pd.DataFrame(templates)
        alta = tpl_df[tpl_df["Prioridade"] == "Alta"].shape[0]
        st.caption(f"{len(templates)} achados (Alta: {alta})")
        render_table_as_cards(
            tpl_df,
            title_key="Item",
            subtitle_keys=["Categoria", "Evidências"],
            badge_key="Prioridade",
            description_key="Descrição",
            limit=10,
        )
        render_technical_table("Ver tabela técnica dos templates", tpl_df)
        csv = tpl_df.to_csv(index=False).encode("utf-8-sig")
        st.download_button("Exportar CSV - Templates", csv, "templates_xss.csv", "text/csv")
    else:
        render_empty_state(
            "Nenhum risco em templates.",
            "Não foram encontrados autoescape off, |safe ou blocktranslate com variáveis.",
            "good",
        )

    # ── Guia rápido ──
    with st.expander("Guia de remediação"):
        st.markdown(
            """
            **Shell injection em GitHub Actions**
            - Nunca concatene `${{ github.event.* }}` em strings de `run:`.
            - Use `env:` mapeado e acesse como variável de ambiente dentro do shell.
            - Evite `pull_request_target`; se necessário, faça checkout com `ref` validado.

            **XSS em templates**
            - Prefira o escape automático do Django; evite `{% autoescape off %}`.
            - Filtro `|safe` apenas em conteúdo confiável/sanitizado.
            - Em `blocktranslate`, garanta que as variáveis são escapadas ou sanitizadas na origem.
            - Use `format_html`/`escape` do Django para construir HTML dinâmico.
            """
        )
