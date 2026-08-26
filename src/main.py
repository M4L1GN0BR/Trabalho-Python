"""
ASPM CLI - Application Security Posture Management.

Uso:
    python src/main.py scan --repo ./meu-projeto
    python src/main.py scan --repo ./meu-projeto --output ./data --skip-trivy
    python src/main.py scan --repo ./meu-projeto --ai  (enriquece com IA)
    python src/main.py demo             (gera dados simulados p/ apresentação)
"""

import argparse
import json
import os
from pathlib import Path


def cmd_scan(args):
    """Executa o scan orquestrado."""
    from orchestrator import run_all

    report = run_all(
        repo_path=args.repo,
        output_dir=args.output,
        skip_trivy=args.skip_trivy,
    )

    # Se --ai, enriquece com DeepSeek usando análise profunda com contexto do código
    if args.ai:
        print("\nAnálise profunda com IA (contexto de código)...")
        try:
            from core.ia.ai_helper import explain_vulnerability
            from core.context import (
                extract_code_snippet,
                extract_function_context,
                format_context_for_prompt,
            )

            repo = Path(args.repo).resolve()
            total = 0

            # Semgrep
            for vuln in report.get("semgrep", {}).get("results", []):
                check_id = vuln.get("check_id", "")
                message = vuln.get("extra", {}).get("message", "")
                fpath = vuln.get("path", "")
                fline = vuln.get("start", {}).get("line")

                ia = explain_vulnerability(check_id, message, fpath, fline)
                vuln["_ia"] = ia
                total += 1

            # Bandit
            for vuln in report.get("bandit", {}).get("results", []):
                test_name = vuln.get("test_name", "")
                text = vuln.get("issue_text", "")
                fpath = vuln.get("filename", "")
                fline = vuln.get("line_number")

                ia = explain_vulnerability(test_name, text, fpath, fline)
                vuln["_ia"] = ia
                total += 1

            print(f"  [OK] {total} achados analisados em profundidade com IA")
            # Re-salva o report com IA
            report_path = Path(args.output) / "aspm-report.json"
            with open(report_path, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            print(f"  Salvo: {report_path}")

        except Exception as e:
            print(f"  [ERRO] Erro ao enriquecer com IA: {e}")

    return report


def cmd_attack(args):
    """Executa testes ofensivos (somente uso autorizado)."""
    from core.attack.engine import run_attack_modules

    print("=" * 60)
    print("  TESTES OFENSIVOS - ASPM")
    print("  ATENÇÃO: somente uso autorizado (laboratório). Testar terceiros")
    print("  sem autorização é ilegal no Brasil (Lei 12.737/2012).")
    print("=" * 60)

    modules = args.modules.split(",") if args.modules else None
    res = run_attack_modules(
        args.url,
        modules=modules,
        id_param=args.id_param,
        traversal_param=args.traversal_param,
        web_param=args.web_param,
        user_field=args.user_field,
        pass_field=args.pass_field,
    )

    print(f"\nAlvo: {res['target']}")
    print(f"Módulos: {', '.join(res['modules_executados'])}")
    print(f"Total de achados: {res['total_findings']}")
    print("-" * 60)
    for f in res["findings"]:
        print(f"  [{f['Prioridade']}] {f['Categoria']} - {f['Item']}: {f['Status']}")
        print(f"      {f['Descrição'][:140]}")

    out = Path(args.output)
    out.mkdir(parents=True, exist_ok=True)
    path = out / "attack-results.json"
    with open(path, "w", encoding="utf-8") as f:
        json.dump(res, f, indent=2, ensure_ascii=False)
    print(f"\nSalvo: {path.resolve()}")


def _launch_dashboard():
    """Inicia o dashboard Streamlit (subprocess)."""
    import subprocess
    import sys as _sys

    dashboard_path = Path(__file__).resolve().parent.parent / "dashboard" / "app.py"
    cmd = [_sys.executable, "-m", "streamlit", "run", str(dashboard_path)]
    print(f"Iniciando dashboard: {' '.join(cmd)}")
    try:
        subprocess.run(cmd)
    except KeyboardInterrupt:
        # Ctrl+C no terminal: o Streamlit recebe o sinal e encerra junto.
        # Sai limpo, sem traceback.
        print("\nDashboard encerrado.")


def cmd_demo(args):
    """
    Gera dados de demonstração (simulados) e abre o dashboard já com
    os achados carregados e os gráficos prontos.
    """
    from generate_demo_data import generate_demo_data

    out = generate_demo_data(output_dir=args.output, seed=args.seed)
    print(f"\nDados de demonstração gerados em: {out.resolve()}")

    # Sinaliza para o dashboard carregar o relatório automaticamente
    os.environ["ASPM_AUTO_DEMO"] = "1"
    os.environ["ASPM_DEMO_REPORT"] = str((out / "aspm-report.json").resolve())

    print("\nAbrindo o dashboard com os dados de demonstração...")
    _launch_dashboard()


def cmd_dashboard(args):
    """Inicia o dashboard Streamlit."""
    _launch_dashboard()


def main():
    parser = argparse.ArgumentParser(
        description="ASPM - Application Security Posture Management",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos:
  python src/main.py scan --repo ./meu-projeto
  python src/main.py scan --repo ./meu-projeto --ai
  python src/main.py demo --seed 42   (gera dados e abre o dashboard com eles)
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

    # ── demo ──
    demo_parser = subparsers.add_parser(
        "demo", help="Gera dados de demonstração (simulados) para o dashboard"
    )
    demo_parser.add_argument(
        "--output", "-o", default="./data/demo", help="Diretório de saída"
    )
    demo_parser.add_argument(
        "--seed",
        type=int,
        default=None,
        help="Seed para reproduzir a mesma execução (mesma seed = mesmos achados)",
    )

    # ── attack ──
    attack_parser = subparsers.add_parser(
        "attack", help="Testes ofensivos (somente uso autorizado / laboratório)"
    )
    attack_parser.add_argument("--url", required=True, help="URL do alvo autorizado")
    attack_parser.add_argument(
        "--modules",
        default=None,
        help="Módulos: recon,idor,fuzz,rate,cors,methods,traversal,redirect,sqli,xss,creds (padrão: todos)",
    )
    attack_parser.add_argument(
        "--id-param", default="id", help="Parâmetro de ID usado no teste de IDOR"
    )
    attack_parser.add_argument(
        "--traversal-param",
        default="file",
        help="Parâmetro usado no teste de Path Traversal",
    )
    attack_parser.add_argument(
        "--web-param",
        default="id",
        help="Parâmetro usado nos testes de SQLi e XSS",
    )
    attack_parser.add_argument(
        "--user-field",
        default="username",
        help="Campo de usuário no endpoint de login (creds)",
    )
    attack_parser.add_argument(
        "--pass-field",
        default="password",
        help="Campo de senha no endpoint de login (creds)",
    )
    attack_parser.add_argument(
        "--output", "-o", default="./data", help="Diretório de saída"
    )

    args = parser.parse_args()

    if args.command == "scan":
        cmd_scan(args)
    elif args.command == "dashboard":
        cmd_dashboard(args)
    elif args.command == "demo":
        cmd_demo(args)
    elif args.command == "attack":
        cmd_attack(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
