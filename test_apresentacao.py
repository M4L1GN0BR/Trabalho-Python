"""Valida o fluxo completo do `python src/main.py demo`:
gera dados -> dashboard abre com os achados carregados automaticamente."""
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from streamlit.testing.v1 import AppTest

# Simula exatamente o que o comando `python src/main.py demo` define
os.environ["ASPM_AUTO_DEMO"] = "1"
os.environ["ASPM_DEMO_REPORT"] = str(
    Path(__file__).resolve().parent / "data" / "demo" / "aspm-report.json"
)

report = json.load(open("data/demo/aspm-report.json", encoding="utf-8"))
summary = report["scan_metadata"]["summary"]

at = AppTest.from_file("dashboard/app.py", default_timeout=90)
at.session_state["user"] = {"id": 1, "username": "admin", "role": "admin"}
at.run()

assert not at.exception, f"Erro ao renderizar: {at.exception}"
assert "demo_auto_loaded" in at.session_state, "demo não foi auto-carregado"
assert at.session_state["demo_auto_loaded"] is True
assert "consolidated_semgrep" in at.session_state
assert len(at.session_state["consolidated_semgrep"]["results"]) > 0
assert len(at.session_state["consolidated_bandit"]["results"]) > 0
assert len(at.session_state["consolidated_sca"]["dependencies"]) > 0
assert len(at.session_state["secret_results"]) > 0, "secrets vazio no modo demo"

print(f"[OK] Modo demo: site renderizou com {summary['total_findings']} achados carregados automaticamente")
print("[OK] Semgrep + Bandit + SCA + Secrets populados no session_state")
print("FLUXO OK: python src/main.py demo -> site abre com os graficos prontos")
