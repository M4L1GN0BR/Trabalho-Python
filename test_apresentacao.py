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
