"""
Atalho: abre o dashboard com o relatório real do DefectDojo carregado.

Não roda scan (o relatório já existe em data/defectdojo-scan/). Se o
relatório não existir, roda o scan primeiro (pode levar ~3 min).

IMPORTANTE: use SEMPRE este script (ou o run_defectdojo.bat) para abrir o
dashboard com o DefectDojo. Abrir via `python src/main.py dashboard` não
define as variáveis de ambiente do carregamento automático.

Uso:
    python run_defectdojo.py
"""

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
REPORT = ROOT / "data" / "defectdojo-scan" / "aspm-report.json"
REPO = os.getenv("DEFECTDOJO_PATH", r"C:\Users\AMD\AppData\Local\Temp\defectdojo")


def main():
    # 1. Garante o relatório (roda o scan apenas na primeira vez)
    if not REPORT.exists():
        print(f"[i] Relatório não encontrado em {REPORT}")
        print(f"[i] Rodando o scan do DefectDojo ({REPO}) — pode levar ~3 min...")
        code = subprocess.run(
            [
                sys.executable,
                "src/main.py",
                "scan",
                "--repo",
                REPO,
                "--output",
                str(ROOT / "data" / "defectdojo-scan"),
                "--skip-trivy",
            ],
            cwd=ROOT,
        ).returncode
        if code != 0:
            print("[!] Scan falhou. Verifique o caminho do DefectDojo (env DEFECTDOJO_PATH).")
            sys.exit(1)
    else:
        print(f"[i] Usando relatório pronto: {REPORT}")

    # 2. Define as variáveis que o dashboard lê para carregar automaticamente
    os.environ["ASPM_AUTO_DEMO"] = "1"
    os.environ["ASPM_DEMO_REPORT"] = str(REPORT)
    print(f"[i] ASPM_DEMO_REPORT = {os.environ['ASPM_DEMO_REPORT']}")

    # 3. Sobe o dashboard (o Streamlit herda as variáveis de ambiente)
    print("[i] Abrindo dashboard em http://localhost:8501")
    print("[i] Login: admin / admin")
    print("[i] Após o login, o relatório do DefectDojo carrega automaticamente.")
    subprocess.run(
        [sys.executable, "-m", "streamlit", "run", str(ROOT / "dashboard" / "app.py")]
    )


if __name__ == "__main__":
    main()
