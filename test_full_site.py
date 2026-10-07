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
Teste de ponta a ponta de TODO o site, com os dados reais do scan
(data/aspm-report.json) em vez do modo demonstração.

Cobre: núcleo de risco, relatórios PDF (técnico e executivo), autenticação e
banco, análise de URL contra servidor local, guarda anti-SSRF, secrets e a
renderização de todas as 11 abas do dashboard para os três perfis.

Execução:
    python test_full_site.py
"""

import json
import os
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pandas as pd

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

# IA real desligada em todo o processo: testes rápidos, offline e determinísticos.
os.environ["DEEPSEEK_API_KEY"] = ""
from src.core.ia import deepseek_client as _dsc  # noqa: E402

_dsc.DEEPSEEK_API_KEY = None

PASSED = []


def check(name, condition, detail=""):
    PASSED.append(bool(condition))
    status = "OK" if condition else "FALHOU"
    print(f"[{status}] {name}" + (f" — {detail}" if detail and not condition else ""))


REAL_REPORT_PATH = ROOT / "data" / "aspm-report.json"


def load_real_report():
    with open(REAL_REPORT_PATH, encoding="utf-8") as f:
        return json.load(f)


# ──────────────────────────────────────────────────────────────
# 1. Núcleo de regras de negócio com dados reais
# ──────────────────────────────────────────────────────────────
def test_core_real_data():
    import dashboard.ai as dai
    dai.DEEPSEEK_API_KEY = None  # garante fallback local

    from dashboard.parsers import (
        get_bandit_vulnerabilities,
        get_sca_vulnerabilities,
        get_semgrep_vulnerabilities,
    )
    from src.core.evidence import build_evidence_store
    from src.core.risk_engine import calculate_risk

    report = load_real_report()
    s = get_semgrep_vulnerabilities(report.get("semgrep", {}))
    b = get_bandit_vulnerabilities(report.get("bandit", {}))
    sc = get_sca_vulnerabilities(report.get("sca", {}))

    check("parser Semgrep (dados reais)", isinstance(s, list), f"{len(s)}")
    check("parser Bandit (dados reais)", len(b) >= 1, f"{len(b)}")
    check("parser SCA (dados reais)", len(sc) >= 1, f"{len(sc)}")
    check(
        "parser Bandit com colunas padronizadas",
        {"Teste", "Arquivo", "Linha", "Prioridade"} <= set(b[0]),
    )
    check(
        "parser SCA com colunas padronizadas",
        {"Biblioteca", "CVE", "Correção Disponível"} <= set(sc[0]),
    )
    check(
        "IA fallback preenche explicação/risco/correção",
        bool(b[0]["Explicação IA"]) and bool(b[0]["Risco IA"]) and bool(b[0]["Correção IA"]),
    )

    ev = build_evidence_store(
        semgrep_data=report.get("semgrep", {}),
        bandit_data=report.get("bandit", {}),
        sca_data=report.get("sca", {}),
        secrets_data=report.get("secrets", {}).get("gitleaks", []),
    )
    check("evidence store consolidado", len(ev) >= 1, f"{len(ev)}")

    risk = calculate_risk(ev)
    check("risk score entre 0 e 100", 0 <= risk["score_geral"] <= 100, str(risk["score_geral"]))
    check("risk classificação válida", risk["classificacao"] in ("Boa", "Atenção", "Crítica"), risk["classificacao"])
    check("risk lista riscos prioritários", isinstance(risk["riscos_prioritarios"], list))
    check("risk agrega por ferramenta", isinstance(risk["by_tool"], dict) and len(risk["by_tool"]) >= 1)


# ──────────────────────────────────────────────────────────────
# 2. Relatórios PDF (técnico e executivo)
# ──────────────────────────────────────────────────────────────
def test_reports():
    from dashboard.reports import generate_executive_report, generate_pdf_report

    # Tabela grande, com HTML/CSS perigoso e descrições longas (caso que quebrava antes)
    big = pd.DataFrame(
        {
            "ID": [f"rule-{i}" for i in range(250)],
            "Arquivo": [f"dojo/tools/parser_{i}.py" for i in range(250)],
            "Descrição": ["<b>texto & especial</b> " + "x" * 800 for i in range(250)],
        }
    )
    pdf = generate_pdf_report("Relatório <técnico>", "Resumo com & e <caracteres>", big)
    data = pdf.getvalue()
    check("PDF técnico gerado (250 linhas, HTML especial)", data[:4] == b"%PDF" and len(data) > 2000, f"{len(data)} bytes")

    empty = generate_pdf_report("Vazio", "sem dados", pd.DataFrame())
    check("PDF técnico sem dados", empty.getvalue()[:4] == b"%PDF")

    risk = {
        "score_geral": 72,
        "classificacao": "Atenção",
        "by_severity": {"Alta": 2, "Média": 3, "Baixa": 1},
        "total_evidencias": 6,
        "justificativa": "2 riscos altos ativos",
        "riscos_prioritarios": [
            {
                "tool": "Bandit",
                "title": "B307",
                "priority": "Alta",
                "score": 12,
                "file": "a.py",
                "evidence": "subprocess",
                "owasp_label": "A03",
            }
        ],
        "correlacoes": {"a.py": 5},
    }
    ex = generate_executive_report(
        risk,
        by_tool={"Bandit": 3},
        owasp_top=[{"label": "A03", "name": "Injection", "count": 2}],
    )
    check("PDF executivo gerado", ex.getvalue()[:4] == b"%PDF" and len(ex.getvalue()) > 1000)


# ──────────────────────────────────────────────────────────────
# 3. Autenticação e banco
# ──────────────────────────────────────────────────────────────
def test_auth_db():
    from src.core.auth import delete_user, load_users, register_user, verify_login
    from dashboard import db

    db.init_db()

    uname = "qa_full_site"
    register_user(uname, "SenhaForte123", "analista")
    u = verify_login(uname, "SenhaForte123")
    check("registro + login de usuário", bool(u) and u["username"] == uname and u["role"] == "analista")
    check("senha incorreta rejeitada", verify_login(uname, "senha_errada") is None)

    try:
        register_user("x_curto", "123", "analista")
        check("senha curta rejeitada", False, "não levantou ValueError")
    except ValueError:
        check("senha curta rejeitada", True)

    users = load_users()
    check("carga de usuários", uname in set(users["username"]))

    row = users[users["username"] == uname]
    if not row.empty:
        check("remoção de usuário de teste", delete_user(int(row["id"].iloc[0])) is True)

    db.save_scan_history(
        2, 1, 1, 0, 0, 1, 1, 0,
        asset_id=1, asset_name="Geral", tools="Bandit,SCA",
        status="Concluído", user_id=1, username="admin",
    )
    hist = db.load_scan_history(asset_id=1, user_filter=False)
    check("histórico de scans salvo/carregado", len(hist) >= 1 and "score_geral" in hist.columns)
    check("ativos carregados", len(db.load_assets()) >= 1)


# ──────────────────────────────────────────────────────────────
# 4. URL Analysis (funções puras + servidor local) e guarda anti-SSRF
# ──────────────────────────────────────────────────────────────
class _LocalHandler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass

    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Set-Cookie", "sid=abc; Path=/")  # sem Secure/HttpOnly
        self.send_header("Server", "nginx")
        self.end_headers()
        self.wfile.write(
            b"<html><head><title>Teste</title></head><body>"
            b"<form><input name='username'><input type='password'></form>"
            b"</body></html>"
        )


def test_url_and_guard():
    from src.core import url_analysis as ua
    from src.core.target_guard import check_target

    check("normalize_url", ua.normalize_url("exemplo.com") == "https://exemplo.com")
    check("get_base_domain", ua.get_base_domain("https://sub.exemplo.com/x") == "exemplo.com")
    check("strip_html", "texto" in ua.strip_html("<script>x</script><b>texto</b>"))
    check("has_login_form", ua.has_login_form('<form><input name="username"><input type="password"></form>') is True)
    check("parse_set_cookie", ua.parse_set_cookie("sid=1; Secure; HttpOnly")[0] == "sid")
    check("detect_waf retorna lista", isinstance(ua.detect_waf({"cf-ray": "x"}), list))

    ok, _ = check_target("http://127.0.0.1/")
    check("anti-SSRF bloqueia loopback", ok is False)
    ok2, _ = check_target("http://8.8.8.8/")
    check("anti-SSRF libera IP público", ok2 is True)

    srv = HTTPServer(("127.0.0.1", 0), _LocalHandler)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        res = ua.analyze_url(f"http://127.0.0.1:{port}/", subdomains=False, crawl=False)
        check("analyze_url retorna dicionário", isinstance(res, dict), str(type(res)))
        check("analyze_url gera achados", len(res.get("findings", [])) >= 1, f"{len(res.get('findings', []))}")
        check("analyze_url calcula score", 0 <= res.get("score", 0) <= 100, str(res.get("score")))
    finally:
        srv.shutdown()


# ──────────────────────────────────────────────────────────────
# 5. Secrets (scanner interno + upload de arquivos)
# ──────────────────────────────────────────────────────────────
def test_secrets_and_state():
    from src.core.secrets import scan_text_for_secrets
    from dashboard.state import scan_uploaded_files_for_secrets

    found = scan_text_for_secrets("x.py", 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"')
    check("secrets scanner detecta AWS key", any(f["Regra"] == "AWS_ACCESS_KEY_ID" for f in found))

    class _FakeUpload:
        name = "cfg.py"

        def getvalue(self):
            return b'password = "secret123"\n-----BEGIN RSA PRIVATE KEY-----'

    res = scan_uploaded_files_for_secrets([_FakeUpload()])
    check("upload de arquivo analisado por secrets", isinstance(res, list) and len(res) >= 1, f"{len(res)}")


# ──────────────────────────────────────────────────────────────
# 6. Site completo (todas as 11 abas) via Streamlit AppTest
# ──────────────────────────────────────────────────────────────
def _all_text(at):
    parts = []
    for attr in ("title", "header", "subheader", "caption", "markdown", "text", "code", "info"):
        elements = getattr(at, attr, None)
        if not elements:
            continue
        try:
            for el in elements:
                parts.append(str(getattr(el, "value", "")))
        except TypeError:
            pass
    return " ".join(parts)


def _fill_real_data(at, report):
    from streamlit.testing.v1 import AppTest  # noqa: F401

    at.session_state["aspm_report"] = report
    at.session_state["consolidated_semgrep"] = report.get("semgrep", {"results": []})
    at.session_state["consolidated_bandit"] = report.get("bandit", {"results": []})
    at.session_state["consolidated_sca"] = report.get("sca", {"dependencies": []})
    at.session_state["consolidated_secrets"] = report.get("secrets", {}).get("gitleaks", [])
    at.session_state["secret_results"] = [
        {
            "Regra": "AWS_ACCESS_KEY_ID",
            "Origem": "Manual",
            "Arquivo": "config.py",
            "Linha": 3,
            "Prioridade": "Alta",
            "Descrição": "AKIA*** (mascarado)",
            "Segredo Mascarado": "AKIA***",
        }
    ]
    at.session_state["last_url_scan"] = {
        "url_inicial": "https://exemplo.com",
        "url_final": "https://exemplo.com",
        "dominio": "exemplo.com",
        "status_code": 200,
        "score": 70,
        "classificacao": "Atenção",
        "findings": [
            {
                "Tipo": "Achado Ativo",
                "Categoria": "Exposição",
                "Item": "/admin",
                "Status": "Expõe",
                "Prioridade": "Alta",
                "Evidências": "Painel acessível",
                "Descrição": "Painel administrativo exposto",
            },
            {
                "Tipo": "Controle OK",
                "Categoria": "HTTPS",
                "Item": "HTTPS",
                "Status": "OK",
                "Prioridade": "Baixa",
                "Evidências": "TLS válido",
                "Descrição": "HTTPS habilitado",
            },
        ],
    }


def test_site():
    from streamlit.testing.v1 import AppTest
    from src.core.auth import verify_login

    report = load_real_report()

    # Boot sem login → tela de login
    at = AppTest.from_file("dashboard/app.py", default_timeout=150)
    at.run()
    check("boot sem login (tela de login)", not at.exception, str(at.exception))
    check("formulário de login presente", len(at.text_input) >= 2)

    # Login pela tela (só se a senha padrão admin/admin estiver ativa)
    if verify_login("admin", "admin"):
        try:
            at.text_input[0].input("admin")
            at.text_input[1].input("admin")
            at.button[0].click()
            at.run()
            try:
                logged_user = dict(at.session_state["user"])
            except Exception:  # noqa: BLE001
                logged_user = {}
            check(
                "login pela tela (admin)",
                not at.exception and logged_user.get("username") == "admin",
                str(at.exception),
            )
        except Exception as exc:  # noqa: BLE001
            print(f"[SKIP] não foi possível dirigir o formulário de login: {exc}")
    else:
        print("[SKIP] senha do admin != 'admin' (ASPM_ADMIN_PASSWORD definido)")

    # Administrador com dados reais em todas as abas
    at = AppTest.from_file("dashboard/app.py", default_timeout=200)
    at.session_state["user"] = {"id": 1, "username": "admin", "role": "admin"}
    _fill_real_data(at, report)
    at.run()
    text_admin = _all_text(at)
    check("admin: site inteiro renderiza (dados reais)", not at.exception, str(at.exception))
    check("admin: 11 abas declaradas", len(at.tabs) == 11, f"{len(at.tabs)}")
    check("admin: tabelas renderizadas", len(at.dataframe) >= 1, f"{len(at.dataframe)}")
    check("admin: métricas renderizadas", len(at.metric) >= 1, f"{len(at.metric)}")
    check("admin: aba Engagements renderizada", "Engagements" in text_admin)
    check("admin: aba CI/CD & Templates renderizada", "CI/CD" in text_admin or "Templates" in text_admin)

    # Analista
    at2 = AppTest.from_file("dashboard/app.py", default_timeout=200)
    at2.session_state["user"] = {"id": 2, "username": "analista", "role": "analista"}
    _fill_real_data(at2, report)
    at2.run()
    text_analista = _all_text(at2)
    check("analista: renderiza sem erro", not at2.exception, str(at2.exception))
    check("analista: aba Engagements renderizada", "Engagements" in text_analista)

    # Visualizador (somente leitura) — as abas permitidas devem continuar renderizando
    at3 = AppTest.from_file("dashboard/app.py", default_timeout=200)
    at3.session_state["user"] = {"id": 3, "username": "visualizador", "role": "visualizador"}
    _fill_real_data(at3, report)
    at3.run()
    text_visual = _all_text(at3)
    check("visualizador: renderiza sem erro", not at3.exception, str(at3.exception))
    check(
        "visualizador: abas após a de URL continuam renderizando",
        "Engagements" in text_visual,
        "st.stop() interrompeu o restante do site",
    )


if __name__ == "__main__":
    print("=" * 60)
    print("  TESTE DE PONTA A PONTA - SITE COMPLETO (dados reais)")
    print("=" * 60)
    test_core_real_data()
    test_reports()
    test_auth_db()
    test_url_and_guard()
    test_secrets_and_state()
    test_site()
    print("-" * 60)
    total = len(PASSED)
    ok = sum(PASSED)
    print(f"  {ok}/{total} verificações passaram")
    if ok == total:
        print("  TODOS OS TESTES DO SITE PASSARAM")
    else:
        print(f"  {total - ok} FALHAS")
        sys.exit(1)
