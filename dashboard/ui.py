"""
Componentes visuais do dashboard (Streamlit).

Login, header, sidebar, cards e estados vazios. Tudo que é renderização
pura fica aqui, fora do app.py.
"""

import json

import pandas as pd
import streamlit as st

from dashboard.state import process_consolidated_report
from dashboard.theme import ENTERPRISE_CSS, LOGIN_CSS
from src.core.auth import ROLE_LABELS, register_login, verify_login


def logout():
    """Encerra a sessão do usuário."""
    st.session_state.pop("user", None)
    st.rerun()


def render_login_page():
    """Renderiza a tela de login. Retorna True se autenticou."""
    st.set_page_config(page_title="ASPM Enterprise - Login", layout="centered")

    st.markdown(LOGIN_CSS, unsafe_allow_html=True)

    st.markdown(
        """
        <div style="text-align: center; margin-bottom: 1.2rem;">
            <div class="login-badge">ASPM Security Command Center</div>
            <div class="login-title">Application Security<br><span class="grad">Posture Management</span></div>
            <div class="login-sub">Acesso restrito à plataforma de governança, evidências e priorização de riscos.</div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    with st.form("login_form"):
        username = st.text_input("Usuário", placeholder="admin")
        password = st.text_input("Senha", type="password", placeholder="********")
        submitted = st.form_submit_button("Entrar", use_container_width=True)

        if submitted:
            if not username or not password:
                st.error("Informe usuário e senha.")
            else:
                user = verify_login(username, password)
                if user:
                    st.session_state["user"] = user
                    register_login(user["id"], user["username"])
                    st.rerun()
                else:
                    st.error("Usuário ou senha inválidos.")

    st.markdown(
        '<div class="login-footer">FIAP - ASPM Enterprise · Credenciais padrão: admin / admin</div>',
        unsafe_allow_html=True,
    )


# ═══════════════════════════════════════════════════════════════
# COMPONENTES VISUAIS REUTILIZÁVEIS
# ═══════════════════════════════════════════════════════════════


def render_status_card(title, value, description, tone="neutral"):
    """
    Renderiza um card executivo para destacar resultado sem depender de st.metric.
    Usado para resumir Achados Ativos, Melhorias, Controles OK e Falsos Positivos.
    """
    tone_color = {
        "good": "#22c55e",
        "warning": "#f59e0b",
        "critical": "#ef4444",
        "info": "#38bdf8",
        "neutral": "#cbd5e1",
    }.get(tone, "#cbd5e1")

    st.markdown(
        f"""
        <div class="enterprise-card" style="min-height: 135px;">
            <div style="font-size: 0.78rem; color: #94a3b8; font-weight: 900; text-transform: uppercase; letter-spacing: 0.08em;">
                {title}
            </div>
            <div style="font-size: 2.25rem; color: {tone_color}; font-weight: 950; line-height: 1; margin-top: 0.45rem;">
                {value}
            </div>
            <div style="font-size: 0.86rem; color: #cbd5e1; line-height: 1.45; margin-top: 0.75rem;">
                {description}
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_empty_state(title, description, tone="good"):
    """
    Exibe mensagem visual quando uma seção não possui itens.
    Evita tabela vazia aparecendo como 'empty' no dashboard.
    """
    tone_color = "#22c55e" if tone == "good" else "#38bdf8"

    st.markdown(
        f"""
        <div class="enterprise-card" style="border-color: rgba(34, 197, 94, 0.24);">
            <div style="font-size: 1.05rem; color: {tone_color}; font-weight: 900;">
                {title}
            </div>
            <div style="font-size: 0.92rem; color: #cbd5e1; margin-top: 0.4rem; line-height: 1.55;">
                {description}
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_compact_cards(
    df, title_col="Item", subtitle_col="Categoria", status_col="Status", limit=8
):
    """
    Mostra itens em formato de cards compactos antes da tabela.
    Isso deixa a leitura mais executiva e reduz a sensação de lista técnica infinita.
    """
    if df.empty:
        return

    preview_df = df.head(limit)

    for _, item in preview_df.iterrows():
        title = item.get(title_col, "Item")
        subtitle = item.get(subtitle_col, "")
        status = item.get(status_col, "")
        prioridade = item.get("Prioridade", "")
        evidencias = item.get("Evidências", "")

        st.markdown(
            f"""
            <div class="enterprise-card" style="padding: 0.95rem 1rem; margin-bottom: 0.65rem;">
                <div style="display: flex; justify-content: space-between; gap: 1rem; align-items: center;">
                    <div>
                        <div style="font-weight: 900; color: #f8fafc; font-size: 1rem;">{title}</div>
                        <div style="color: #94a3b8; font-size: 0.84rem; margin-top: 0.25rem;">{subtitle} | {status}</div>
                        <div style="color: #cbd5e1; font-size: 0.80rem; margin-top: 0.35rem;">{evidencias}</div>
                    </div>
                    <div style="color: #cbd5e1; font-weight: 800; font-size: 0.86rem; white-space: nowrap;">
                        {prioridade}
                    </div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )


def render_donut_chart(df, category_col, value_col, title):
    """
    Renderiza gráfico de pizza/donut usando Altair.
    Altair costuma vir junto com Streamlit, então evita depender de Plotly.
    """
    try:
        import altair as alt

        chart_df = df.copy()
        chart_df[value_col] = pd.to_numeric(
            chart_df[value_col], errors="coerce"
        ).fillna(0)

        if chart_df[value_col].sum() <= 0:
            st.info("Sem dados suficientes para gerar o gráfico.")
            return

        chart = (
            alt.Chart(chart_df)
            .mark_arc(innerRadius=72, outerRadius=145, stroke="#020617", strokeWidth=2)
            .encode(
                theta=alt.Theta(field=value_col, type="quantitative"),
                color=alt.Color(
                    field=category_col,
                    type="nominal",
                    legend=alt.Legend(
                        title=None,
                        orient="bottom",
                        labelColor="#cbd5e1",
                        labelFontSize=13,
                    ),
                    scale=alt.Scale(
                        range=[
                            "#ef4444",
                            "#f59e0b",
                            "#38bdf8",
                            "#22c55e",
                            "#a78bfa",
                            "#64748b",
                        ]
                    ),
                ),
                tooltip=[
                    alt.Tooltip(field=category_col, type="nominal", title="Categoria"),
                    alt.Tooltip(
                        field=value_col, type="quantitative", title="Quantidade"
                    ),
                ],
            )
            .properties(height=360, title=title)
            .configure_title(color="#f8fafc", fontSize=18, anchor="start")
            .configure_view(strokeWidth=0)
            .configure(background="transparent")
        )

        st.altair_chart(chart, use_container_width=True)

    except Exception as exc:
        st.warning(f"Não foi possível gerar o gráfico de pizza: {exc}")


def render_source_cards(total_semgrep, total_bandit, total_sca, latest_url_score):
    """
    Mostra fontes integradas como cards, evitando tabela pesada no resumo.
    """
    sources = [
        ("Semgrep", total_semgrep, "Análise estática de código"),
        ("Bandit", total_bandit, "Análise de segurança Python"),
        ("SCA", total_sca, "Bibliotecas e CVEs"),
        ("URL Analysis", latest_url_score, "Headers, TLS e discovery"),
    ]

    cols = st.columns(4)

    for index, (name, value, description) in enumerate(sources):
        with cols[index]:
            st.markdown(
                f"""
                <div class="enterprise-card" style="min-height: 128px;">
                    <div style="font-size: 0.80rem; color: #94a3b8; font-weight: 900; text-transform: uppercase; letter-spacing: 0.08em;">
                        {name}
                    </div>
                    <div style="font-size: 1.7rem; color: #f8fafc; font-weight: 950; margin-top: 0.35rem;">
                        {value}
                    </div>
                    <div style="font-size: 0.84rem; color: #cbd5e1; margin-top: 0.5rem;">
                        {description}
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )


def render_history_cards(history_df):
    """
    Exibe o histórico em cards executivos, antes da tabela técnica.
    """
    if history_df.empty:
        render_empty_state(
            "Nenhuma análise registrada.",
            "Execute uma análise de URL na aba URL Analysis. O histórico é salvo automaticamente.",
            "info",
        )
        return

    preview_df = history_df.head(5)

    for _, row in preview_df.iterrows():
        score = int(row.get("score", 0))
        classification = row.get("classification", "")
        url = row.get("url", "")
        created_at = row.get("created_at", "")
        high_count = row.get("high_count", 0)
        medium_count = row.get("medium_count", 0)
        low_count = row.get("low_count", 0)

        if score >= 85:
            tone_color = "#22c55e"
        elif score >= 65:
            tone_color = "#f59e0b"
        else:
            tone_color = "#ef4444"

        st.markdown(
            f"""
            <div class="enterprise-card" style="padding: 1rem 1.15rem; margin-bottom: 0.75rem;">
                <div style="display: flex; justify-content: space-between; gap: 1rem; align-items: center;">
                    <div>
                        <div style="font-weight: 900; color: #f8fafc; font-size: 1rem;">{url}</div>
                        <div style="color: #94a3b8; font-size: 0.84rem; margin-top: 0.25rem;">{created_at}</div>
                        <div style="color: #cbd5e1; font-size: 0.82rem; margin-top: 0.45rem;">
                            Alta: {high_count} | Média: {medium_count} | Baixa: {low_count}
                        </div>
                    </div>
                    <div style="text-align: right;">
                        <div style="font-size: 1.75rem; color: {tone_color}; font-weight: 950; line-height: 1;">{score}</div>
                        <div style="color: #cbd5e1; font-size: 0.84rem; margin-top: 0.35rem;">{classification}</div>
                    </div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )


def render_table_as_cards(
    df,
    title_key=None,
    subtitle_keys=None,
    badge_key=None,
    description_key=None,
    limit=10,
):
    """
    Renderiza linhas de DataFrame como cards para evitar aparência de planilha.
    A tabela completa continua disponível no expander técnico.
    """
    if df.empty:
        return

    if subtitle_keys is None:
        subtitle_keys = []

    preview_df = df.head(limit)

    for _, row in preview_df.iterrows():
        if title_key and title_key in row:
            title = row.get(title_key, "Item")
        else:
            title = row.iloc[0]

        subtitle_parts = []

        for key in subtitle_keys:
            if key in row and str(row.get(key, "")).strip():
                subtitle_parts.append(f"{key}: {row.get(key)}")

        subtitle = " | ".join(subtitle_parts)

        badge = ""
        if badge_key and badge_key in row:
            badge = str(row.get(badge_key, ""))

        description = ""
        if description_key and description_key in row:
            description = str(row.get(description_key, ""))

        badge_lower = badge.lower()

        if badge_lower in ["alta", "high", "error"]:
            badge_color = "#ef4444"
        elif badge_lower in ["média", "media", "medium", "warning"]:
            badge_color = "#f59e0b"
        elif badge_lower in ["baixa", "low", "info"]:
            badge_color = "#38bdf8"
        else:
            badge_color = "#cbd5e1"

        st.markdown(
            f"""
            <div class="enterprise-card" style="padding: 1rem 1.15rem; margin-bottom: 0.75rem;">
                <div style="display: flex; justify-content: space-between; gap: 1rem; align-items: flex-start;">
                    <div style="max-width: 82%;">
                        <div style="font-weight: 950; color: #f8fafc; font-size: 1rem;">{title}</div>
                        <div style="color: #94a3b8; font-size: 0.84rem; margin-top: 0.35rem;">{subtitle}</div>
                        <div style="color: #cbd5e1; font-size: 0.84rem; margin-top: 0.55rem; line-height: 1.45;">{description}</div>
                    </div>
                    <div style="color: {badge_color}; font-weight: 950; font-size: 0.9rem; white-space: nowrap;">
                        {badge}
                    </div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )


def render_technical_table(label, df):
    """
    Mantém tabela completa em expander para consulta técnica.
    """
    with st.expander(label):
        st.dataframe(df, use_container_width=True)


def apply_enterprise_theme():
    st.markdown(ENTERPRISE_CSS, unsafe_allow_html=True)


def render_enterprise_header():
    st.markdown(
        """
        <div class="enterprise-hero">
            <div class="enterprise-eyebrow">ASPM Security Command Center</div>
            <h1 class="enterprise-title">
                Application Security<br>
                <span class="enterprise-gradient">Posture Management</span>
            </h1>
            <p class="enterprise-subtitle">
                Centralize achados de Semgrep, Bandit, SCA e URL Analysis em uma visão executiva.
                A plataforma prioriza riscos por evidências reais, separa falsos positivos automaticamente
                e oferece explicações assistidas por IA.
            </p>
            <div>
                <span class="enterprise-pill">Semgrep</span>
                <span class="enterprise-pill">Bandit</span>
                <span class="enterprise-pill">SCA</span>
                <span class="enterprise-pill">URL Analysis</span>
                <span class="enterprise-pill">IA</span>
                <span class="enterprise-pill">Evidence Based</span>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_enterprise_sidebar():
    st.sidebar.markdown(
        """
        <div class="enterprise-sidebar-logo">
            <strong>ASPM Control</strong><br>
            <small>FIAP Security Dashboard</small>
        </div>
        """,
        unsafe_allow_html=True,
    )
    st.sidebar.caption("Governança, evidências, priorização e postura de segurança.")

    # ── Usuário logado ──
    user = st.session_state.get("user", {})
    role_label = ROLE_LABELS.get(user.get("role", ""), user.get("role", ""))
    st.sidebar.markdown(
        f"""
        <div style="background: rgba(37, 99, 235, 0.12); border: 1px solid rgba(96, 165, 250, 0.25);
             border-radius: 14px; padding: 0.7rem 0.9rem; margin-bottom: 1rem;">
            <div style="color: #f8fafc; font-weight: 800; font-size: 0.92rem;">{user.get('username', '')}</div>
            <div style="color: #94a3b8; font-size: 0.78rem; margin-top: 0.15rem;">{role_label}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    if st.sidebar.button("Sair", use_container_width=True):
        logout()

    # ── Upload consolidado ──
    st.sidebar.markdown("---")
    st.sidebar.markdown("### Upload Consolidado")
    st.sidebar.caption(
        "Envie o aspm-report.json gerado pelo orquestrador para preencher as abas."
    )
    consolidated = st.sidebar.file_uploader(
        "Selecionar aspm-report.json",
        type=["json"],
        key="upload_consolidated",
        label_visibility="collapsed",
    )

    if consolidated is not None:
        try:
            report = json.load(consolidated)
            n = process_consolidated_report(report)
            st.sidebar.success(f"Scan registrado: {n} achados")
        except Exception as e:
            st.sidebar.error(f"Erro ao ler relatório: {e}")

    if "aspm_report" in st.session_state:
        st.sidebar.info("Dados consolidados disponíveis")
