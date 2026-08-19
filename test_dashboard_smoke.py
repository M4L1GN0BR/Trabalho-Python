"""Smoke test do dashboard refatorado usando Streamlit AppTest."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from streamlit.testing.v1 import AppTest

# 1) Boot sem login -> tela de login
at = AppTest.from_file("dashboard/app.py", default_timeout=60)
at.run()
assert not at.exception, f"Erro no boot: {at.exception}"
print("[OK] Boot sem login (tela de login renderizada)")

# 2) Login como admin -> todas as abas executam
at.session_state["user"] = {"id": 1, "username": "admin", "role": "admin"}
at.run()
assert not at.exception, f"Erro pós-login: {at.exception}"
print("[OK] Login admin e renderização de todas as abas")

# 3) Com dados consolidados (simula upload do aspm-report.json)
at.session_state["consolidated_semgrep"] = {
    "results": [
        {
            "check_id": "python.lang.security.audit.eval-usage",
            "path": "src/main.py",
            "start": {"line": 10},
            "extra": {
                "severity": "ERROR",
                "message": "Uso de eval com entrada não sanitizada",
            },
        }
    ]
}
at.session_state["consolidated_bandit"] = {
    "results": [
        {
            "test_name": "B307",
            "filename": "src/main.py",
            "line_number": 12,
            "issue_severity": "HIGH",
            "issue_confidence": "MEDIUM",
            "issue_text": "Possível uso de subprocess inseguro",
        }
    ]
}
at.session_state["consolidated_sca"] = {
    "dependencies": [
        {
            "name": "requests",
            "version": "2.20.0",
            "vulns": [
                {"id": "CVE-2018-18074", "description": "Open redirect", "fix_versions": ["2.21.0"]}
            ],
        }
    ]
}
at.session_state["secret_results"] = [
    {
        "Regra": "AWS Access Key",
        "Origem": "Manual",
        "Arquivo": "config.py",
        "Linha": 3,
        "Prioridade": "Alta",
        "Descrição": "AKIA... (mascarado)",
    }
]
at.run()
assert not at.exception, f"Erro com dados consolidados: {at.exception}"
print("[OK] Renderização com dados consolidados (Semgrep + Bandit + SCA + Secrets)")

# 4) URL analysis simulada (attack surface)
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
at.run()
assert not at.exception, f"Erro com URL analysis: {at.exception}"
print("[OK] Renderização com URL analysis / Attack Surface")

print("\nTODOS OS TESTES PASSARAM")
