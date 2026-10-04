"""
ASPM Enterprise - Dashboard Streamlit.

Ponto de entrada do dashboard. A lógica foi organizada em módulos:

- dashboard/theme.py   → CSS visual (dark corporativo)
- dashboard/ui.py      → componentes visuais (login, cards, sidebar)
- dashboard/db.py      → banco SQLite (históricos, ativos, scans)
- dashboard/state.py   → estado de sessão (falsos positivos, secrets)
- dashboard/ai.py      → IA DeepSeek + fallback local
- dashboard/parsers.py → parsers das ferramentas (Semgrep, Bandit, SCA)
- dashboard/reports.py → relatórios PDF
- dashboard/tabs.py    → corpo de cada aba
- src/core/            → regras de negócio (risk engine, evidências, correlação)
"""

import json as _json
import os as _os
import sys as _sys
import textwrap as _textwrap
from pathlib import Path as _Path

import streamlit as st

# Torna a raiz do projeto importável, para que os imports "from dashboard..."
# e "from src..." funcionem independentemente de como o script é executado
# (python dashboard/app.py, streamlit run, etc.) e do diretório de trabalho.
_PROJECT_ROOT = str(_Path(__file__).resolve().parent.parent)
if _PROJECT_ROOT not in _sys.path:
    _sys.path.insert(0, _PROJECT_ROOT)

# ── Correção global de renderização HTML ──
# O parser de Markdown do Streamlit trata linhas com 4+ espaços como bloco
# de código. Como os cards HTML são construídos em f-strings indentadas,
# o HTML aparecia como texto cru. O wrapper aplica dedent automaticamente.
_original_markdown = st.markdown


def _safe_markdown(body, *args, unsafe_allow_html=None, **kwargs):
    if unsafe_allow_html is None:
        unsafe_allow_html = False
    if unsafe_allow_html and isinstance(body, str):
        body = _textwrap.dedent(body)
        # No parser CommonMark do Streamlit, uma linha em branco ENCERRA um
        # bloco HTML; o que vem depois (indentado 4+) vira "bloco de código"
        # e é exibido como texto cru. Como o conteúdo aqui é sempre HTML/CSS
        # (linhas em branco não têm significado), removê-las mantém o bloco
        # íntegro sem alterar a renderização.
        body = "\n".join(line for line in body.splitlines() if line.strip())
    return _original_markdown(body, *args, unsafe_allow_html=unsafe_allow_html, **kwargs)


st.markdown = _safe_markdown

from dashboard.db import init_db
from dashboard.state import (
    count_false_positives,
    init_false_positive_state,
    process_consolidated_report,
)
from dashboard.tabs import (
    render_admin_tab,
    render_attack_surface_tab,
    render_bandit_tab,
    render_ci_cd_tab,
    render_engagements_tab,
    render_offensive_tab,
    render_resumo_tab,
    render_sca_tab,
    render_secrets_tab,
    render_semgrep_tab,
    render_url_tab,
)
from dashboard.ui import (
    apply_enterprise_theme,
    render_enterprise_header,
    render_enterprise_sidebar,
    render_login_page,
)

# Caminho do relatório de demonstração (definido pelo comando `python src/main.py demo`)
_DEMO_REPORT_ENV = _os.getenv("ASPM_DEMO_REPORT")
if _DEMO_REPORT_ENV:
    DEMO_REPORT_PATH = _Path(_DEMO_REPORT_ENV)
else:
    DEMO_REPORT_PATH = _Path(__file__).resolve().parent.parent / "data" / "demo" / "aspm-report.json"


init_db()

st.set_page_config(page_title="ASPM Enterprise", layout="wide")

# ── Gate de autenticação ──
if "user" not in st.session_state:
    render_login_page()
    st.stop()

# Aviso para visualizadores (modo somente leitura)
if st.session_state.get("user", {}).get("role") == "visualizador":
    st.sidebar.warning("Modo somente leitura. Faça upload com um perfil Analista ou Administrador.")

init_false_positive_state()


def _auto_load_demo():
    """
    Carrega o aspm-report.json de demonstração automaticamente, sem upload
    manual, apenas quando o modo demonstração é acionado explicitamente
    (ASPM_AUTO_DEMO=1, definido por `python src/main.py demo` e por
    `python run_defectdojo.py`). Executa uma única vez por sessão.

    Um `streamlit run` comum NÃO carrega nada: o dashboard inicia vazio e os
    achados entram apenas por upload manual ou pelo modo demo explícito.
    """
    if _os.getenv("ASPM_AUTO_DEMO") != "1":
        return

    if st.session_state.get("demo_auto_loaded"):
        return

    # Se já há um relatório carregado (ex.: upload consolidado), não sobrescreve.
    if "aspm_report" in st.session_state:
        return

    if not DEMO_REPORT_PATH.exists():
        st.sidebar.warning(
            "Modo demonstração ativado, mas o aspm-report.json não foi encontrado. "
            "Rode 'python src/main.py demo' antes de abrir o dashboard."
        )
        return

    try:
        with open(DEMO_REPORT_PATH, encoding="utf-8") as f:
            report = _json.load(f)
        total = process_consolidated_report(report)
        st.session_state["demo_auto_loaded"] = True
        st.sidebar.success(
            f"Modo demonstração: {total} achados carregados automaticamente"
        )
    except Exception as exc:
        st.sidebar.error(f"Erro ao carregar dados de demonstração: {exc}")


_auto_load_demo()  # roda antes da sidebar/abas para popular o session_state

apply_enterprise_theme()
render_enterprise_header()
render_enterprise_sidebar()

st.sidebar.subheader("Governança")
st.sidebar.metric("Falsos positivos manuais", count_false_positives())

if st.sidebar.button("Limpar falsos positivos manuais"):
    st.session_state.false_positives = set()
    st.rerun()

st.sidebar.markdown("---")
st.sidebar.caption(
    "ASPM Enterprise v2.1.2 — correções de renderização HTML, deduplicação "
    "de achados, orçamento de IA e descrições em pt-BR."
)


# ATENÇÃO: aba "Assets / Ativos" desativada (lógica comentada em tabs.py).
# A aba "Testes Ofensivos" ocupa a posição 8 (somente uso autorizado).
tab1, tab2, tab3, tab4, tab5, tab6, tab7, tab8, tab9, tab10, tab11 = st.tabs(
    [
        "Resumo Executivo",
        "Semgrep",
        "Bandit",
        "SCA",
        "URL Analysis",
        "Secrets",
        "Attack Surface",
        "Testes Ofensivos (Lab)",
        "Engagements & Scans",
        "Administração",
        "CI/CD & Templates",
    ]
)

with tab1:
    render_resumo_tab()

with tab2:
    render_semgrep_tab()

with tab3:
    render_bandit_tab()

with tab4:
    render_sca_tab()

with tab5:
    render_url_tab()

with tab6:
    render_secrets_tab()

with tab7:
    render_attack_surface_tab()

with tab8:
    render_offensive_tab()

with tab9:
    render_engagements_tab()

with tab10:
    render_admin_tab()

with tab11:
    render_ci_cd_tab()
