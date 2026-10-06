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
Tema visual do dashboard (CSS corporativo dark).

Centraliza todo o CSS do Streamlit em strings puras.
O app.py e ui.py apenas aplicam via st.markdown(unsafe_allow_html=True).
"""

# ── CSS principal do dashboard (dark/corporativo) ──
ENTERPRISE_CSS = """
<style>
    .stApp {
        background:
            radial-gradient(circle at 15% 0%, rgba(56, 189, 248, 0.18), transparent 28%),
            radial-gradient(circle at 84% 4%, rgba(168, 85, 247, 0.16), transparent 30%),
            linear-gradient(180deg, #030712 0%, #07111f 48%, #020617 100%);
        color: #e5e7eb;
    }

    .block-container {
        padding-top: 1.5rem;
        padding-bottom: 3rem;
        max-width: 1500px;
    }

    section[data-testid="stSidebar"] {
        background: linear-gradient(180deg, rgba(2, 6, 23, 0.98), rgba(15, 23, 42, 0.96));
        border-right: 1px solid rgba(148, 163, 184, 0.18);
    }

    section[data-testid="stSidebar"] * {
        color: #e5e7eb;
    }

    h1, h2, h3 {
        color: #f8fafc !important;
        letter-spacing: -0.04em;
        font-weight: 850 !important;
    }

    div[data-testid="stMetric"] {
        background: linear-gradient(180deg, rgba(15, 23, 42, 0.94), rgba(15, 23, 42, 0.60));
        border: 1px solid rgba(148, 163, 184, 0.20);
        border-radius: 24px;
        padding: 1.1rem 1.15rem;
        box-shadow: 0 20px 58px rgba(0, 0, 0, 0.28);
    }

    div[data-testid="stMetricLabel"] p {
        color: #94a3b8 !important;
        font-size: 0.82rem;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.05em;
    }

    div[data-testid="stMetricValue"] {
        color: #f8fafc !important;
        font-weight: 900;
    }

    div[data-testid="stDataFrame"] {
        border-radius: 22px;
        overflow: hidden;
        border: 1px solid rgba(148, 163, 184, 0.18);
        box-shadow: 0 18px 55px rgba(0, 0, 0, 0.24);
    }

    .stButton > button,
    .stDownloadButton > button {
        border-radius: 14px;
        border: 1px solid rgba(255,255,255,0.16);
        background: linear-gradient(135deg, #2563eb, #7c3aed);
        color: white;
        font-weight: 800;
        box-shadow: 0 14px 35px rgba(37, 99, 235, 0.30);
    }

    button[data-baseweb="tab"] {
        background: rgba(15, 23, 42, 0.72);
        border: 1px solid rgba(148, 163, 184, 0.18);
        border-radius: 999px;
        padding: 0.62rem 1.05rem;
        margin-right: 0.35rem;
        color: #cbd5e1;
        font-weight: 700;
    }

    button[data-baseweb="tab"][aria-selected="true"] {
        background: linear-gradient(135deg, rgba(37, 99, 235, 0.95), rgba(124, 58, 237, 0.95));
        color: white;
        border-color: rgba(255, 255, 255, 0.24);
        box-shadow: 0 14px 38px rgba(59, 130, 246, 0.25);
    }

    .enterprise-hero {
        padding: 2.1rem;
        border-radius: 32px;
        border: 1px solid rgba(148, 163, 184, 0.20);
        background:
            linear-gradient(135deg, rgba(15, 23, 42, 0.94), rgba(30, 41, 59, 0.74)),
            radial-gradient(circle at top right, rgba(56, 189, 248, 0.26), transparent 35%);
        box-shadow: 0 28px 90px rgba(0, 0, 0, 0.38);
        margin-bottom: 1.5rem;
    }

    .enterprise-eyebrow {
        display: inline-block;
        padding: 0.38rem 0.8rem;
        border-radius: 999px;
        color: #bfdbfe;
        background: rgba(37, 99, 235, 0.18);
        border: 1px solid rgba(96, 165, 250, 0.25);
        font-size: 0.82rem;
        font-weight: 800;
        margin-bottom: 0.9rem;
    }

    .enterprise-title {
        font-size: clamp(2.2rem, 5vw, 4.2rem);
        line-height: 0.95;
        font-weight: 950;
        color: #f8fafc;
        letter-spacing: -0.075em;
        margin: 0;
    }

    .enterprise-gradient {
        background: linear-gradient(135deg, #38bdf8, #a78bfa, #f472b6);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
    }

    .enterprise-subtitle {
        color: #cbd5e1;
        max-width: 980px;
        font-size: 1.02rem;
        line-height: 1.7;
        margin-top: 1rem;
    }

    .enterprise-pill {
        display: inline-block;
        padding: 0.48rem 0.8rem;
        border-radius: 999px;
        background: rgba(15, 23, 42, 0.65);
        border: 1px solid rgba(148, 163, 184, 0.20);
        color: #cbd5e1;
        font-size: 0.78rem;
        font-weight: 800;
        margin-right: 0.45rem;
        margin-top: 0.9rem;
    }

    .enterprise-card {
        padding: 1.25rem;
        border-radius: 24px;
        background: linear-gradient(180deg, rgba(15, 23, 42, 0.86), rgba(15, 23, 42, 0.54));
        border: 1px solid rgba(148, 163, 184, 0.18);
        box-shadow: 0 20px 60px rgba(0, 0, 0, 0.26);
        margin-bottom: 1rem;
    }

    .enterprise-section-title {
        font-size: 1.18rem;
        font-weight: 900;
        color: #f8fafc;
        margin: 0 0 0.45rem 0;
    }

    .enterprise-muted {
        color: #94a3b8;
        font-size: 0.92rem;
        line-height: 1.58;
    }

    .enterprise-sidebar-logo {
        padding: 1rem 0.9rem;
        border-radius: 22px;
        background: linear-gradient(135deg, rgba(37, 99, 235, 0.22), rgba(124, 58, 237, 0.18));
        border: 1px solid rgba(148, 163, 184, 0.20);
        margin-bottom: 1rem;
    }

    .enterprise-sidebar-logo strong {
        font-size: 1.16rem;
        color: #f8fafc;
    }

    .enterprise-sidebar-logo small {
        color: #94a3b8;
    }
</style>
"""


# ── CSS da tela de login ──
LOGIN_CSS = """
<style>
    .stApp {
        background:
            radial-gradient(circle at 20% 10%, rgba(56, 189, 248, 0.15), transparent 32%),
            radial-gradient(circle at 80% 20%, rgba(124, 58, 237, 0.12), transparent 30%),
            linear-gradient(160deg, #030712 0%, #0a1122 55%, #020617 100%);
        color: #e5e7eb;
    }
    /* Esconde header e footer padrão do Streamlit */
    #MainMenu, footer, header {visibility: hidden;}
    .block-container {padding-top: 3rem; max-width: 460px;}
    .login-badge {
        display: inline-block;
        padding: 0.38rem 0.85rem;
        border-radius: 999px;
        background: rgba(37, 99, 235, 0.15);
        border: 1px solid rgba(96, 165, 250, 0.3);
        color: #7dd3fc;
        font-size: 0.72rem;
        font-weight: 800;
        text-transform: uppercase;
        letter-spacing: 0.12em;
        margin-bottom: 1.1rem;
    }
    .login-title {
        font-size: 2.1rem;
        font-weight: 950;
        color: #f8fafc;
        letter-spacing: -0.045em;
        line-height: 1.05;
    }
    .login-title .grad {
        background: linear-gradient(135deg, #38bdf8, #a78bfa);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
    }
    .login-sub {
        color: #94a3b8;
        font-size: 0.92rem;
        line-height: 1.6;
        margin-top: 0.8rem;
        margin-bottom: 1.8rem;
    }
    /* Inputs mais limpos */
    .stTextInput input {
        background: rgba(15, 23, 42, 0.8) !important;
        border: 1px solid rgba(148, 163, 184, 0.25) !important;
        border-radius: 12px !important;
        color: #f8fafc !important;
        padding: 0.75rem 1rem !important;
    }
    .stTextInput input:focus {
        border-color: #38bdf8 !important;
        box-shadow: 0 0 0 3px rgba(56, 189, 248, 0.15) !important;
    }
    .stFormSubmitButton > button {
        border-radius: 12px !important;
        background: linear-gradient(135deg, #2563eb, #7c3aed) !important;
        border: none !important;
        color: white !important;
        font-weight: 800 !important;
        padding: 0.7rem !important;
        box-shadow: 0 14px 35px rgba(37, 99, 235, 0.3) !important;
    }
    .stFormSubmitButton > button:hover {
        opacity: 0.9;
    }
    .login-footer {
        color: #475569;
        font-size: 0.78rem;
        text-align: center;
        margin-top: 1.6rem;
    }
</style>
"""
