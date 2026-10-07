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
Bateria de hardening: robustez a dados malformados e segurança.

Cobre resistência a relatórios malformados, path traversal, SSRF, injeção de
SQL no cadastro de usuários, hash de senha, mascaramento de segredos e injeção
de HTML/JS (XSS) nos dados externos renderizados pelo dashboard.

Execução:
    python test_hardening.py
"""

import os
import sqlite3
import sys
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

# IA real desligada: testes offline e determinísticos.
os.environ["DEEPSEEK_API_KEY"] = ""
from src.core.ia import deepseek_client as _dsc  # noqa: E402

_dsc.DEEPSEEK_API_KEY = None

PASSED = []


def check(name, condition, detail=""):
    PASSED.append(bool(condition))
    status = "OK" if condition else "FALHOU"
    print(f"[{status}] {name}" + (f" — {detail}" if detail and not condition else ""))


# ──────────────────────────────────────────────────────────────
# 1. Robustez a dados malformados
# ──────────────────────────────────────────────────────────────
def test_parsers_robust():
    import dashboard.ai as dai
    dai.DEEPSEEK_API_KEY = None

    from dashboard.parsers import (
        get_bandit_vulnerabilities,
        get_sca_vulnerabilities,
        get_semgrep_vulnerabilities,
    )

    malformed = [
        {},
        {"results": None},
        {"results": []},
        {"results": [{}]},
        {"results": [{"extra": None, "start": None}]},
        {"dependencies": None},
        {"dependencies": [{}]},
        {"dependencies": [{"name": None, "vulns": [{}]}]},
    ]
    falhas = []
    for data in malformed:
        for parser in (get_semgrep_vulnerabilities, get_bandit_vulnerabilities, get_sca_vulnerabilities):
            try:
                out = parser(data)
                if not isinstance(out, list):
                    falhas.append(f"{parser.__name__} retornou {type(out)}")
            except Exception as exc:  # noqa: BLE001
                falhas.append(f"{parser.__name__}({data}) -> {type(exc).__name__}: {exc}")
    check("parsers resistem a relatório malformado", not falhas, "; ".join(falhas[:3]))


def test_core_robust():
    from src.core.evidence import build_evidence_store
    from src.core.risk_engine import calculate_risk, score_evidence
    from src.core.inventory import build_inventory, inventory_summary
    from src.core.cvss import base_score, parse_vector, severity

    try:
        ev = build_evidence_store(
            semgrep_data={"results": [{}]},
            bandit_data={"results": [{}]},
            sca_data={"dependencies": [{}]},
            secrets_data=[{}],
            url_findings=[{}],
        )
        check("evidence store com itens vazios", isinstance(ev, list))
        risk = calculate_risk(ev)
        check("risk engine com evidência vazia", isinstance(risk, dict) and "score_geral" in risk)
        check("score_evidence vazio", isinstance(score_evidence({}), dict))
        check("calculate_risk vazio", calculate_risk([])["score_geral"] == 100)
    except Exception as exc:  # noqa: BLE001
        check("núcleo resiste a dados vazios", False, f"{type(exc).__name__}: {exc}")

    try:
        inv = build_inventory({"dependencies": [{"name": "x", "version": "1", "vulns": []}]})
        check("inventário básico", len(inv) == 1)
        inventory_summary({"dependencies": []})
        check("inventário vazio", True)
    except Exception as exc:  # noqa: BLE001
        check("inventário resiste", False, f"{type(exc).__name__}: {exc}")

    try:
        check("cvss vector inválido não quebra", isinstance(parse_vector("lixo-completamente-invalido"), dict))
        check("cvss base_score tolerante", 0.0 <= base_score("AV:N") <= 10.0)
        check("cvss severity", severity(7.5) in ("Alta", "Crítica", "Média", "Baixa"))
    except Exception as exc:  # noqa: BLE001
        check("cvss resiste", False, f"{type(exc).__name__}: {exc}")

    # Analisadores estáticos com entradas inválidas
    try:
        from src.core.github_actions import analyze_workflow
        check("github_actions YAML inválido", isinstance(analyze_workflow("][ not: yaml", path="x.yml"), list))
    except Exception as exc:  # noqa: BLE001
        check("github_actions resiste", False, f"{type(exc).__name__}: {exc}")

    try:
        from src.core.template_xss import analyze_template
        check("template_xss vazio", isinstance(analyze_template("", path="x.html"), list))
    except Exception as exc:  # noqa: BLE001
        check("template_xss resiste", False, f"{type(exc).__name__}: {exc}")


def test_reports_robust():
    from dashboard.reports import generate_executive_report, generate_pdf_report

    try:
        df = pd.DataFrame({"A": [float("nan"), None], "B": ["<x>", "y"]})
        pdf = generate_pdf_report("t", "s", df)
        check("PDF com NaN/None e HTML", pdf.getvalue()[:4] == b"%PDF")
        ex = generate_executive_report({"score_geral": 50}, by_tool=None, owasp_top=None)
        check("PDF executivo mínimo", ex.getvalue()[:4] == b"%PDF")
    except Exception as exc:  # noqa: BLE001
        check("relatórios resistem a dados sujos", False, f"{type(exc).__name__}: {exc}")


# ──────────────────────────────────────────────────────────────
# 2. Path traversal
# ──────────────────────────────────────────────────────────────
def test_path_traversal():
    from src.core.context import extract_code_snippet, extract_imports

    check("bloqueia ../../etc/passwd", extract_code_snippet("../../etc/passwd", 1) == "")
    check("bloqueia caminho absoluto Unix", extract_code_snippet("/etc/passwd", 1) == "")
    check("bloqueia caminho absoluto Windows", extract_code_snippet("C:/Windows/win.ini", 1) == "")
    check("bloqueia .. no meio", extract_code_snippet("src/../../secret.txt", 1) == "")
    check("bloqueia imports de caminho absoluto", extract_imports("/etc/passwd") == "")
    ok = extract_code_snippet("src/core/context.py", 40)
    check("libera caminho legítimo do projeto", ok != "" and "def _safe_resolve" in ok or "Path" in ok, ok[:40])


# ──────────────────────────────────────────────────────────────
# 3. SSRF (guarda anti-SSRF)
# ──────────────────────────────────────────────────────────────
def test_ssrf():
    from src.core.target_guard import check_target

    bloqueios = {
        "loopback 127.0.0.1": "http://127.0.0.1/",
        "localhost": "http://localhost/",
        "privado 10.0.0.1": "http://10.0.0.1/",
        "privado 192.168.0.1": "http://192.168.0.1/",
        "metadata 169.254.169.254": "http://169.254.169.254/",
        "IPv6 loopback": "http://[::1]/",
    }
    for nome, url in bloqueios.items():
        ok, _ = check_target(url)
        check(f"SSRF bloqueia {nome}", ok is False, f"retornou {ok}")

    liberados = {"Google DNS público": "http://8.8.8.8/"}
    for nome, url in liberados.items():
        ok, _ = check_target(url)
        check(f"SSRF libera {nome}", ok is True, f"retornou {ok}")

    # allow_private precisa liberar laboratório local
    ok, _ = check_target("http://127.0.0.1/", allow_private=True)
    check("SSRF libera loopback com allow_private", ok is True)


# ──────────────────────────────────────────────────────────────
# 4. Autenticação: injeção de SQL, hash de senha
# ──────────────────────────────────────────────────────────────
def test_auth_security():
    from src.core.auth import delete_user, load_users, register_user, verify_login
    from src.core.database_path import DB_PATH

    malicious = "x'); DROP TABLE users;--"
    register_user(malicious, "SenhaForte123", "analista")
    users = load_users()
    check("SQL injection não derruba a tabela de usuários", "admin" in set(users["username"]))
    check("username malicioso persistido literalmente", malicious in set(users["username"]))

    row = users[users["username"] == malicious]
    if not row.empty:
        delete_user(int(row["id"].iloc[0]))

    conn = sqlite3.connect(DB_PATH)
    stored = conn.execute("SELECT password_hash FROM users WHERE username = 'admin'").fetchone()
    conn.close()
    check("senha do admin não é texto puro", bool(stored) and stored[0] != "admin")
    check("hash bcrypt (prefixo $2)", bool(stored) and stored[0].startswith("$2"))

    check("login rejeita senha vazia", verify_login("admin", "") is None)


# ──────────────────────────────────────────────────────────────
# 5. Mascaramento de segredos
# ──────────────────────────────────────────────────────────────
def test_secret_masking():
    from src.core.secrets import scan_text_for_secrets

    real = "AKIAIOSFODNN7EXAMPLE"
    findings = scan_text_for_secrets("x.py", f'key = "{real}"')
    check("segredo detectado", len(findings) >= 1, f"{len(findings)}")
    if findings:
        masked = findings[0].get("Segredo Mascarado", "")
        check("segredo vem mascarado", "***" in masked)
        check("segredo completo NÃO é exposto", real not in masked, masked)


# ──────────────────────────────────────────────────────────────
# 6. XSS: dados externos não podem sair crus em HTML (unsafe_allow_html)
# ──────────────────────────────────────────────────────────────
def test_xss_dashboard():
    from streamlit.testing.v1 import AppTest

    payload = "<img src=x onerror=alert(1)>"
    report = {
        "semgrep": {
            "results": [
                {
                    "check_id": payload,
                    "path": payload,
                    "start": {"line": 1},
                    "extra": {"severity": "ERROR", "message": payload},
                }
            ]
        },
        "bandit": {
            "results": [
                {
                    "test_name": payload,
                    "filename": payload,
                    "line_number": 1,
                    "issue_severity": "HIGH",
                    "issue_confidence": "HIGH",
                    "issue_text": payload,
                }
            ]
        },
        "sca": {
            "dependencies": [
                {"name": payload, "version": "1.0", "vulns": [{"id": payload, "description": payload, "fix_versions": []}]}
            ]
        },
        "secrets": {"gitleaks": []},
        "scan_metadata": {"summary": {"total_findings": 3, "by_severity": {"Alta": 3, "Média": 0, "Baixa": 0}}},
    }
    url_scan = {
        "url_inicial": payload,
        "url_final": payload,
        "dominio": payload,
        "status_code": 200,
        "score": 90,
        "classificacao": "Crítica",
        "findings": [
            {
                "Tipo": "Achado Ativo",
                "Categoria": payload,
                "Item": payload,
                "Status": payload,
                "Prioridade": "Alta",
                "Evidências": payload,
                "Descrição": payload,
            }
        ],
    }

    at = AppTest.from_file("dashboard/app.py", default_timeout=200)
    at.session_state["user"] = {"id": 1, "username": "admin", "role": "admin"}
    at.session_state["aspm_report"] = report
    at.session_state["consolidated_semgrep"] = report["semgrep"]
    at.session_state["consolidated_bandit"] = report["bandit"]
    at.session_state["consolidated_sca"] = report["sca"]
    at.session_state["consolidated_secrets"] = []
    at.session_state["secret_results"] = []
    at.session_state["last_url_scan"] = url_scan
    at.run()

    check("dashboard renderiza mesmo com payload malicioso", not at.exception, str(at.exception))

    # Procura o payload CRU dentro de blocos HTML (unsafe_allow_html) do dashboard.
    raw_hits = []
    for el in at.markdown:
        value = str(getattr(el, "value", ""))
        if payload in value and ("<div" in value or "<span" in value):
            raw_hits.append(value[:160])

    check(
        "dados externos escapados em HTML (sem XSS cru)",
        not raw_hits,
        f"{len(raw_hits)} bloco(s) HTML com payload cru: {raw_hits[:1]}",
    )

    # Controle positivo: o payload deve aparecer ESCAPADO em algum lugar (cards seguros)
    escaped = any("&lt;img" in str(getattr(el, "value", "")) for el in at.markdown)
    check("controle: payload aparece escapado (cards seguros)", escaped)


# ──────────────────────────────────────────────────────────────
# 7. Site inteiro com dados vazios/malformados
# ──────────────────────────────────────────────────────────────
def test_site_empty_and_malformed():
    from streamlit.testing.v1 import AppTest

    # 7a. Relatório totalmente vazio
    at = AppTest.from_file("dashboard/app.py", default_timeout=200)
    at.session_state["user"] = {"id": 1, "username": "admin", "role": "admin"}
    at.session_state["aspm_report"] = {}
    at.session_state["consolidated_semgrep"] = {"results": []}
    at.session_state["consolidated_bandit"] = {"results": []}
    at.session_state["consolidated_sca"] = {"dependencies": []}
    at.session_state["consolidated_secrets"] = []
    at.session_state["secret_results"] = []
    at.run()
    check("site renderiza com dados vazios", not at.exception, str(at.exception))

    # 7b. Relatório com chaves nulas (upload malformado)
    mal = AppTest.from_file("dashboard/app.py", default_timeout=200)
    mal.session_state["user"] = {"id": 1, "username": "admin", "role": "admin"}
    mal.session_state["aspm_report"] = {}
    mal.session_state["consolidated_semgrep"] = {"results": None}
    mal.session_state["consolidated_bandit"] = {"results": None}
    mal.session_state["consolidated_sca"] = {"dependencies": None}
    mal.session_state["consolidated_secrets"] = []
    mal.session_state["secret_results"] = []
    mal.run()
    check("site renderiza com relatório nulo (não quebra)", not mal.exception, str(mal.exception))


if __name__ == "__main__":
    print("=" * 60)
    print("  BATERIA DE HARDENING - ROBUSTEZ E SEGURANÇA")
    print("=" * 60)
    test_parsers_robust()
    test_core_robust()
    test_reports_robust()
    test_path_traversal()
    test_ssrf()
    test_auth_security()
    test_secret_masking()
    test_xss_dashboard()
    test_site_empty_and_malformed()
    print("-" * 60)
    total = len(PASSED)
    ok = sum(PASSED)
    print(f"  {ok}/{total} verificações passaram")
    if ok == total:
        print("  TODOS OS TESTES DE HARDENING PASSARAM")
    else:
        print(f"  {total - ok} FALHAS")
        sys.exit(1)
