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
Camada de banco de dados (SQLite) do dashboard.

Centraliza init_db, histórico de URL, histórico global de scans e ativos.
Nenhuma renderização de UI acontece aqui.
"""

import os
import sqlite3
from datetime import datetime

import bcrypt
import pandas as pd

from src.core.database_path import DB_PATH
from src.core.risk_engine import calculate_general_score
from dashboard.session import can, get_current_user_id, get_current_username


def init_db():
    os.makedirs("data", exist_ok=True)

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # ── Tabela de usuários ──
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT DEFAULT 'analista',
            created_at TEXT
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS sessions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            username TEXT,
            login_at TEXT
        )
    """)

    # Usuário padrão admin — senha definida via ambiente (ASPM_ADMIN_PASSWORD)
    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        admin_password = os.getenv("ASPM_ADMIN_PASSWORD")
        if not admin_password:
            admin_password = "admin"
            print(
                "[!] AVISO: usando senha padrão 'admin' para o usuário 'admin'. "
                "Defina ASPM_ADMIN_PASSWORD no ambiente."
            )
        pw_hash = bcrypt.hashpw(admin_password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")
        cursor.execute(
            "INSERT INTO users (username, password_hash, role, created_at) VALUES (?, ?, ?, ?)",
            ("admin", pw_hash, "admin", datetime.now().strftime("%Y-%m-%d %H:%M")),
        )

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS url_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT,
            url TEXT,
            final_url TEXT,
            score INTEGER,
            classification TEXT,
            high_count INTEGER,
            medium_count INTEGER,
            low_count INTEGER
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT,
            asset_id INTEGER DEFAULT 1,
            asset_name TEXT DEFAULT 'Geral',
            total_findings INTEGER,
            high_count INTEGER,
            medium_count INTEGER,
            low_count INTEGER,
            semgrep_count INTEGER DEFAULT 0,
            bandit_count INTEGER DEFAULT 0,
            sca_count INTEGER DEFAULT 0,
            secrets_count INTEGER DEFAULT 0,
            score_geral INTEGER DEFAULT 0,
            classificacao TEXT DEFAULT 'N/A',
            status TEXT DEFAULT 'Concluído',
            tools_used TEXT DEFAULT ''
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS assets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            asset_type TEXT DEFAULT 'Web App',
            url_or_repo TEXT DEFAULT '',
            technology TEXT DEFAULT '',
            criticidade TEXT DEFAULT 'Média',
            created_at TEXT,
            last_scan TEXT,
            score_risco INTEGER DEFAULT 100
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS ai_memory (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT,
            username TEXT,
            title TEXT,
            category TEXT DEFAULT 'achado',
            response TEXT
        )
    """)

    # Migração: adiciona colunas novas se não existirem
    migracoes = [
        ("scan_history", "asset_id", "INTEGER DEFAULT 1"),
        ("scan_history", "asset_name", "TEXT DEFAULT 'Geral'"),
        ("scan_history", "status", "TEXT DEFAULT 'Concluído'"),
        ("scan_history", "tools_used", "TEXT DEFAULT ''"),
        ("scan_history", "user_id", "INTEGER DEFAULT 1"),
        ("scan_history", "username", "TEXT DEFAULT 'admin'"),
    ]
    for table, col, col_type in migracoes:
        try:
            cursor.execute(f"ALTER TABLE {table} ADD COLUMN {col} {col_type}")
        except sqlite3.OperationalError:
            pass  # coluna já existe

    # Garante que existe pelo menos um ativo padrão
    cursor.execute("SELECT COUNT(*) FROM assets")
    if cursor.fetchone()[0] == 0:
        cursor.execute(
            """
            INSERT INTO assets (name, asset_type, url_or_repo, criticidade, created_at)
            VALUES (?, ?, ?, ?, ?)
        """,
            (
                "Geral",
                "Repositório",
                "local",
                "Média",
                datetime.now().strftime("%Y-%m-%d"),
            ),
        )

    conn.commit()
    conn.close()


# ── Histórico de URL ──


def save_url_history(
    url, final_url, score, classification, high_count, medium_count, low_count
):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute(
        """
        INSERT INTO url_history (
            created_at, url, final_url, score, classification,
            high_count, medium_count, low_count
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """,
        (
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            url,
            final_url,
            score,
            classification,
            high_count,
            medium_count,
            low_count,
        ),
    )

    conn.commit()
    conn.close()


def load_url_history():
    conn = sqlite3.connect(DB_PATH)
    df = pd.read_sql_query("SELECT * FROM url_history ORDER BY id DESC", conn)
    conn.close()
    return df


def clear_url_history():
    """
    Limpa todo o histórico de análises de URL.
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM url_history")
    conn.commit()
    conn.close()


# ── Histórico global de scans ──


def save_scan_history(
    total,
    high,
    medium,
    low,
    semgrep_c,
    bandit_c,
    sca_c,
    secrets_c,
    asset_id=1,
    asset_name="Geral",
    tools="",
    status="Concluído",
    user_id=None,
    username=None,
):
    """Salva resultado de scan completo no histórico global, vinculado ao usuário."""
    score, classificacao = calculate_general_score(high, medium, low)
    if user_id is None:
        user_id = get_current_user_id()
    if username is None:
        username = get_current_username()

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO scan_history
            (created_at, total_findings, high_count, medium_count, low_count,
             semgrep_count, bandit_count, sca_count, secrets_count,
             score_geral, classificacao, asset_id, asset_name, tools_used, status,
             user_id, username)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """,
        (
            datetime.now().strftime("%Y-%m-%d %H:%M"),
            total,
            high,
            medium,
            low,
            semgrep_c,
            bandit_c,
            sca_c,
            secrets_c,
            score,
            classificacao,
            asset_id,
            asset_name,
            tools,
            status,
            user_id,
            username,
        ),
    )

    # Atualiza last_scan do ativo
    cursor.execute(
        "UPDATE assets SET last_scan = ?, score_risco = ? WHERE id = ?",
        (datetime.now().strftime("%Y-%m-%d %H:%M"), score, asset_id),
    )

    conn.commit()
    conn.close()
    return score, classificacao


def load_scan_history(asset_id=None, user_filter=True):
    """
    Carrega histórico global de scans.
    - Admin vê tudo.
    - Analista/Visualizador veem apenas os próprios scans.
    Filtra por asset_id se informado.
    """
    conn = sqlite3.connect(DB_PATH)

    # Filtro por usuário (admin vê tudo)
    user_where = ""
    params = []
    if user_filter and not can("view_all"):
        user_where = "WHERE user_id = ?"
        params.append(get_current_user_id())

    if asset_id:
        if user_where:
            user_where += " AND asset_id = ?"
        else:
            user_where = "WHERE asset_id = ?"
        params.append(asset_id)

    sql = f"SELECT * FROM scan_history {user_where} ORDER BY id DESC"
    df = pd.read_sql_query(sql, conn, params=params)
    conn.close()
    return df


# ── Ativos ──


def load_assets():
    """Carrega todos os ativos cadastrados."""
    conn = sqlite3.connect(DB_PATH)
    df = pd.read_sql_query("SELECT * FROM assets ORDER BY id", conn)
    conn.close()
    return df


def save_asset(name, asset_type, url_or_repo, technology, criticidade):
    """Cria ou atualiza um ativo."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        """INSERT INTO assets (name, asset_type, url_or_repo, technology, criticidade, created_at)
           VALUES (?, ?, ?, ?, ?, ?)""",
        (
            name,
            asset_type,
            url_or_repo,
            technology,
            criticidade,
            datetime.now().strftime("%Y-%m-%d"),
        ),
    )
    conn.commit()
    conn.close()


def delete_asset(asset_id):
    """Remove um ativo."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "UPDATE scan_history SET asset_id = 1, asset_name = 'Geral' WHERE asset_id = ?",
        (asset_id,),
    )
    cursor.execute("DELETE FROM assets WHERE id = ?", (asset_id,))
    conn.commit()
    conn.close()


def get_asset_findings_count(asset_id):
    """Soma total de achados dos scans de um ativo."""
    conn = sqlite3.connect(DB_PATH)
    df = pd.read_sql_query(
        "SELECT SUM(total_findings) as total FROM scan_history WHERE asset_id = ?",
        conn,
        params=[asset_id],
    )
    conn.close()
    if df.empty:
        return 0
    total = df["total"].iloc[0]
    return int(total) if total else 0


# ── Memória da IA ──


def save_ai_memory(title, category, response):
    """
    Persiste uma análise da IA (memória) para consulta posterior.

    Parâmetros
    ----------
    title : str
        Título do achado/item analisado.
    category : str
        Categoria (achado, resumo, url...).
    response : str
        Resposta da IA (explicação/risco/correção).
    """
    try:
        conn = sqlite3.connect(DB_PATH)
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO ai_memory (created_at, username, title, category, response)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                get_current_username(),
                str(title)[:200],
                category,
                str(response)[:2000],
            ),
        )
        conn.commit()
        conn.close()
    except Exception:
        pass  # memória é acessória: nunca deve quebrar o fluxo principal


def load_ai_memory(limit=20):
    """Carrega as análises da IA mais recentes."""
    conn = sqlite3.connect(DB_PATH)
    df = pd.read_sql_query(
        "SELECT id, created_at, username, title, category, response FROM ai_memory ORDER BY id DESC LIMIT ?",
        conn,
        params=[limit],
    )
    conn.close()
    return df
