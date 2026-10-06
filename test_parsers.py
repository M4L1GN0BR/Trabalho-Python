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
test_parsers.py — Testes dos parsers com fixtures reais.

Usa amostras extraídas do scan real do DefectDojo (tests/fixtures/) para
validar: parsers (Semgrep/Bandit/SCA), Evidence Engine com contexto de
arquivo de teste e falso positivo, Risk Engine com rebaixamento, inventário
de dependências e o Secrets Scanner ampliado.

Execução:
    python test_parsers.py
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

# Desabilita a IA real no teste: os parsers usam o fallback local,
# mantendo a execução rápida, offline e determinística.
from src.core.ia import deepseek_client as _dsc  # noqa: E402

_dsc.DEEPSEEK_API_KEY = None

FIXTURES = Path(__file__).resolve().parent / "tests" / "fixtures"

PASSED = []


def check(name, condition, detail=""):
    status = "OK" if condition else "FALHOU"
    PASSED.append(condition)
    print(f"[{status}] {name}" + (f" — {detail}" if detail and not condition else ""))


def load(name):
    with open(FIXTURES / name, encoding="utf-8") as f:
        return json.load(f)


def test_parsers():
    from dashboard.parsers import (
        get_bandit_vulnerabilities,
        get_sca_vulnerabilities,
        get_semgrep_vulnerabilities,
    )

    semgrep = load("semgrep.json")
    bandit = load("bandit.json")
    sca = load("sca.json")

    s = get_semgrep_vulnerabilities(semgrep)
    b = get_bandit_vulnerabilities(bandit)
    sc = get_sca_vulnerabilities(sca)

    check("parser semgrep (fixture real)", len(s) >= 5, f"{len(s)} achados")
    check("parser bandit (fixture real)", len(b) >= 5, f"{len(b)} achados")
    check("parser sca (fixture real)", len(sc) >= 1, f"{len(sc)} achados")

    check(
        "colunas padronizadas semgrep",
        all(k in s[0] for k in ["ID", "Arquivo", "Linha", "Prioridade", "Descrição"]),
    )
    check(
        "colunas padronizadas bandit",
        all(k in b[0] for k in ["Teste", "Arquivo", "Severidade", "Prioridade"]),
    )
    check(
        "colunas padronizadas sca",
        all(k in sc[0] for k in ["Biblioteca", "CVE", "Correção Disponível"]),
    )


def test_evidence_context():
    """Valida detecção de arquivos de teste e candidatos a falso positivo."""
    from src.core.evidence import (
        build_evidence_store,
        detect_fp_candidate,
        is_test_file,
    )

    check("is_test_file unittests", is_test_file("unittests/tools/test_parser.py") is True)
    check("is_test_file producao", is_test_file("dojo/finding/ui/views.py") is False)
    check("is_test_file fixtures", is_test_file("tests/fixtures/data.json") is True)

    # Hash usado para deduplicação (padrão do DefectDojo)
    fp, reason = detect_fp_candidate(
        {
            "tool": "Bandit",
            "title": "hashlib",
            "function": "dupe_key = hashlib.md5",
            "evidence": "Possible insecure use of MD5",
            "file": "dojo/tools/parser.py",
            "code_snippet": "dupe_key = hashlib.md5(data).hexdigest()",
        }
    )
    check("FP: hashlib para deduplicação", fp is True, reason)

    # Sem contexto de FP
    fp2, _ = detect_fp_candidate(
        {
            "tool": "Semgrep",
            "title": "sqlalchemy-execute-raw-query",
            "evidence": "raw query with user input",
            "file": "dojo/views.py",
            "code_snippet": "cursor.execute(sql)",
        }
    )
    check("sem FP em sql raw real", fp2 is False)

    # Evidências do relatório real recebem flags
    semgrep = load("semgrep.json")
    evidences = build_evidence_store(semgrep_data=semgrep)
    check("evidências enriquecidas com contexto", all("fp_candidate" in e for e in evidences))


def test_risk_engine_rebaixa_fp():
    """Valida que o Risk Engine rebaixa achados de teste/FP por contexto."""
    from src.core.evidence import build_evidence_store
    from src.core.risk_engine import calculate_risk, score_evidence

    # Achado grave em arquivo de teste (ex.: chave PGP em fixture)
    ev_test = build_evidence_store(
        semgrep_data={
            "results": [
                {
                    "check_id": "generic.secrets.security.detected-pgp-private-key-block",
                    "path": "unittests/tools/test_parser.py",
                    "start": {"line": 5},
                    "extra": {"severity": "ERROR", "message": "PGP private key block detected"},
                }
            ]
        }
    )[0]
    check("in_test_file marcado", ev_test["in_test_file"] is True)

    # Mesmo achado em arquivo de produção
    ev_prod = build_evidence_store(
        semgrep_data={
            "results": [
                {
                    "check_id": "generic.secrets.security.detected-pgp-private-key-block",
                    "path": "dojo/config/settings.py",
                    "start": {"line": 5},
                    "extra": {"severity": "ERROR", "message": "PGP private key block detected"},
                }
            ]
        }
    )[0]

    score_test = score_evidence(ev_test)["score"]
    score_prod = score_evidence(ev_prod)["score"]
    check(
        "score em arquivo de teste é menor",
        score_test < score_prod,
        f"teste={score_test} vs producao={score_prod}",
    )

    risk = calculate_risk([ev_test, ev_prod])
    check("fp_count contabilizado", risk["fp_count"] >= 1)
    check("by_severity_active existe", "by_severity_active" in risk)
    check(
        "justificativa menciona FPs",
        "falso positivo" in risk["justificativa"].lower(),
        risk["justificativa"],
    )


def test_secrets_ampliado():
    from src.core.secrets import SECRET_RULES, scan_text_for_secrets

    check("total de regras ampliado", len(SECRET_RULES) >= 12, f"{len(SECRET_RULES)} regras")

    # PGP private key (novo)
    findings = scan_text_for_secrets(
        "keys.py",
        "-----BEGIN PGP PRIVATE KEY BLOCK-----\nabc123\n-----END PGP PRIVATE KEY BLOCK-----",
    )
    check("detecta PGP private key", any(f["Regra"] == "PRIVATE_KEY" for f in findings))

    # AWS secret access key (novo)
    findings = scan_text_for_secrets(
        "aws.py",
        'aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"',
    )
    check("detecta AWS secret access key", any(f["Regra"] == "AWS_SECRET_ACCESS_KEY" for f in findings))

    # Stripe (novo)
    findings = scan_text_for_secrets("pay.py", "sk_live_1234567890ABCDEFGHIJ")
    check("detecta Stripe secret key", any(f["Regra"] == "STRIPE_SECRET_KEY" for f in findings))

    # GitHub fine-grained (novo)
    findings = scan_text_for_secrets("ci.py", "github_pat_11AAABBBCCCDDDEEEFFFGGG")
    check("detecta GitHub fine-grained token", any(f["Regra"] == "GITHUB_FINE_GRAINED_TOKEN" for f in findings))

    # Mascaramento continua funcionando
    findings = scan_text_for_secrets("x.py", 'api_key = "AKIAIOSFODNN7EXAMPLE1234"')
    masked = [f for f in findings if f["Regra"] == "AWS_ACCESS_KEY_ID"]
    check("segredo mascarado", bool(masked) and "***" in masked[0]["Segredo Mascarado"])


def test_inventory():
    from src.core.inventory import build_inventory, inventory_summary, package_table_rows

    sca = load("sca.json")
    inv = build_inventory(sca)
    check("inventário construído", len(inv) >= 1, f"{len(inv)} pacotes")

    with_vulns = [p for p in inv if p["cve_count"] > 0]
    check("pacotes com CVE", len(with_vulns) >= 1)

    summary = inventory_summary(sca)
    check("summary total", summary["total_packages"] == len(inv))
    check("summary total_vulns", summary["total_vulns"] >= 1)

    rows = package_table_rows(sca)
    check("linhas para tabela", len(rows) == len(inv))

    # CVSS enriquecido
    with_cvss = [p for p in with_vulns if p.get("cvss_score", 0) > 0]
    check("inventário com score CVSS", len(with_cvss) >= 1, f"{len(with_cvss)} pacotes")


def test_cvss():
    from src.core.cvss import (
        base_score,
        estimate_from_severity,
        parse_vector,
        severity,
        severity_code,
    )

    # Valores oficiais conhecidos
    check("CVSS Log4Shell = 10.0", base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H") == 10.0)
    check("CVSS EternalBlue = 8.1", base_score("AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H") == 8.1)
    check("CVSS classico = 9.8", base_score("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 9.8)

    v = parse_vector("AV:N/AC:L")
    check("parse_vector tolerante", v["S"] == "U" and v["C"] == "H")

    check("severity 9.8 = Crítica", severity(9.8) == "Crítica")
    check("severity_code HIGH", severity_code(8.0) == "HIGH")

    score, vector = estimate_from_severity("HIGH")
    check("estimativa HIGH = 9.8", score == 9.8, f"{score}")


def test_github_actions_parser():
    from src.core.github_actions import analyze_workflow, scan_repo_workflows

    # Shell injection em run:
    wf = """
name: build
on:
  pull_request:
    branches: [main]
permissions: write-all
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Echo repo
        run: echo "repository=${{ github.repository }}"
"""
    findings = analyze_workflow(wf, path=".github/workflows/build.yml")
    check("detecta shell injection", any(f["Categoria"] == "Shell Injection" for f in findings))
    check("detecta permissões amplas", any("permissões" in f["Item"].lower() for f in findings))

    # pull_request_target
    wf2 = """
name: pr
on:
  pull_request_target:
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
"""
    findings2 = analyze_workflow(wf2, path="pr.yml")
    check("detecta pull_request_target", any("pull_request_target" in f["Item"] for f in findings2))

    # secrets: inherit
    wf3 = """
name: ci
on: [push]
jobs:
  deploy:
    runs-on: ubuntu-latest
    secrets: inherit
    steps:
      - run: echo ok
"""
    findings3 = analyze_workflow(wf3, path="ci.yml")
    check("detecta secrets inherit", any("secrets herdados" in f["Item"].lower() or "inherit" in f["Item"].lower() for f in findings3))

    # Workflow seguro: sem achados
    wf4 = """
name: safe
on:
  push:
    branches: [main]
permissions:
  contents: read
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: pip install -r requirements.txt
"""
    findings4 = analyze_workflow(wf4, path="safe.yml")
    check("workflow seguro sem achados", len(findings4) == 0, f"{len(findings4)} achados")


def test_template_xss_parser():
    from src.core.template_xss import analyze_template, scan_repo_templates

    tpl = """
{% autoescape off %}
  <p>{{ user_input }}</p>
{% endautoescape %}
<p>{{ name|safe }}</p>
{% blocktranslate with name=c_prod.name %}{{ name }} is affected{% endblocktranslate %}
"""
    findings = analyze_template(tpl, path="templates/dojo/page.html")
    check("detecta autoescape off", any("autoescape off" in f["Item"] for f in findings))
    check("detecta |safe", any("safe" in f["Item"] and "|" in f["Item"] or "filtro safe" in f["Item"] for f in findings))
    check("detecta blocktranslate", any("blocktranslate" in f["Item"] for f in findings))

    # Template seguro
    tpl2 = "<p>{{ name|escape }}</p><p>{{ value }}</p>"
    findings2 = analyze_template(tpl2, path="safe.html")
    check("template seguro sem achados", len(findings2) == 0, f"{len(findings2)} achados")


if __name__ == "__main__":
    print("=" * 60)
    print("  TESTES DE PARSERS COM FIXTURES REAIS (DefectDojo)")
    print("=" * 60)
    test_parsers()
    test_evidence_context()
    test_risk_engine_rebaixa_fp()
    test_secrets_ampliado()
    test_inventory()
    test_cvss()
    test_github_actions_parser()
    test_template_xss_parser()
    print("-" * 60)
    total = len(PASSED)
    ok = sum(PASSED)
    print(f"  {ok}/{total} verificações passaram")
    if ok == total:
        print("  TODOS OS TESTES DE PARSERS PASSARAM")
    else:
        print(f"  {total - ok} FALHAS")
        sys.exit(1)
