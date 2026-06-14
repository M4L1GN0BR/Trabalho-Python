"""
ASPM CLI - Application Security Posture Management.

Uso:
    python src/main.py scan --repo ./meu-projeto
    python src/main.py scan --repo ./meu-projeto --output ./data --skip-trivy
    python src/main.py scan --repo ./meu-projeto --ai  (enriquece com IA)
"""

import argparse
import json
from pathlib import Path


def cmd_scan(args):
    """Executa o scan orquestrado."""
    from orchestrator import run_all

    report = run_all(
        repo_path=args.repo,
        output_dir=args.output,
        skip_trivy=args.skip_trivy,
    )

    # Se --ai, enriquece com DeepSeek
    if args.ai:
        print("\n🧠 Enriqueciendo achados com IA...")
        try:
            from core.ia.ai_helper import explain_vulnerability

            total = 0
            # Semgrep
            for vuln in report.get("semgrep", {}).get("results", []):
                check_id = vuln.get("check_id", "")
                message = vuln.get("extra", {}).get("message", "")
                ia = explain_vulnerability(check_id, message)
                vuln["_ia"] = ia
                total += 1

            # Bandit
            for vuln in report.get("bandit", {}).get("results", []):
                test_name = vuln.get("test_name", "")
                text = vuln.get("issue_text", "")
                ia = explain_vulnerability(test_name, text)
                vuln["_ia"] = ia
                total += 1

            print(f"  ✓ {total} achados enriquecidos com IA")
            # Re-salva o report com IA
            report_path = Path(args.output) / "aspm-report.json"
            with open(report_path, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            print(f"  💾 Relatório atualizado: {report_path}")

        except Exception as e:
            print(f"  ⚠ Erro ao enriquecer com IA: {e}")

    return report


def cmd_dashboard(args):
    """Inicia o dashboard Streamlit."""
    import subprocess
    import sys as _sys

    dashboard_path = Path(__file__).resolve().parent.parent / "dashboard" / "app.py"
    cmd = [_sys.executable, "-m", "streamlit", "run", str(dashboard_path)]
    print(f"🚀 Iniciando dashboard: {' '.join(cmd)}")
    subprocess.run(cmd)


def main():
    parser = argparse.ArgumentParser(
        description="ASPM - Application Security Posture Management",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos:
  python src/main.py scan --repo ./meu-projeto
  python src/main.py scan --repo ./meu-projeto --ai
  python src/main.py dashboard
        """,
    )
    subparsers = parser.add_subparsers(dest="command", help="Comando")

    # ── scan ──
    scan_parser = subparsers.add_parser("scan", help="Executa scan de segurança")
    scan_parser.add_argument(
        "--repo", "-r", required=True, help="Caminho do repositório"
    )
    scan_parser.add_argument(
        "--output", "-o", default="./data", help="Diretório de saída"
    )
    scan_parser.add_argument("--skip-trivy", action="store_true", help="Pula Trivy")
    scan_parser.add_argument(
        "--ai", action="store_true", help="Enriquece com IA via DeepSeek"
    )

    # ── dashboard ──
    subparsers.add_parser("dashboard", help="Inicia o dashboard Streamlit")

    args = parser.parse_args()

    if args.command == "scan":
        cmd_scan(args)
    elif args.command == "dashboard":
        cmd_dashboard(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
