"""
Orquestrador de scans ASPM.

Coordena a execução de múltiplas ferramentas de segurança:
- Semgrep (SAST)
- Bandit (segurança Python)
- Safety (SCA - dependências)
- Gitleaks / TruffleHog (segredos)
- Trivy (container + IaC)

Uso:
    python -m src.orchestrator --repo /caminho/do/projeto --output ./data
"""

import argparse
import json
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

# ──────────────────────────────────────────────
# Utilitário de execução
# ──────────────────────────────────────────────


def run(cmd, cwd=None, timeout=120):
    """
    Executa um comando e retorna (stdout, stderr, returncode).
    Se o comando não existir ou exceder o timeout, retorna (None, None, -1).
    """
    try:
        result = subprocess.run(
            cmd,
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
        return result.stdout, result.stderr, result.returncode
    except FileNotFoundError:
        return None, f"Comando não encontrado: {cmd[0]}", -1
    except subprocess.TimeoutExpired:
        return None, f"Timeout de {timeout}s excedido", -1


def check_tool(name, cmd):
    """Verifica se uma ferramenta está instalada."""
    stdout, _, _ = run(
        [cmd, "--version"] if cmd != "safety" else [cmd, "--version"], timeout=10
    )
    if stdout:
        print(f"  ✓ {name}: {stdout.splitlines()[0].strip()}")
        return True
    print(f"  ✗ {name}: não instalado")
    return False


# ──────────────────────────────────────────────
# Scanners individuais
# ──────────────────────────────────────────────


def scan_semgrep(repo_path):
    """Roda Semgrep com regras auto e retorna dados."""
    print("\n🔍 Semgrep (SAST)...")
    if not check_tool("Semgrep", "semgrep"):
        return {"results": []}

    stdout, stderr, code = run(
        ["semgrep", "--config=auto", "--json", str(repo_path)],
        timeout=300,
    )
    if not stdout:
        print(f"  ⚠ Semgrep falhou: {stderr[:200] if stderr else 'sem saída'}")
        return {"results": []}

    try:
        data = json.loads(stdout)
        n = len(data.get("results", []))
        print(f"  ✓ {n} achados encontrados")
        return data
    except json.JSONDecodeError:
        print("  ⚠ Resposta do Semgrep não é JSON válido")
        return {"results": []}


def scan_bandit(repo_path):
    """Roda Bandit em arquivos Python."""
    print("\n🔍 Bandit (segurança Python)...")
    if not check_tool("Bandit", "bandit"):
        return {"results": []}

    py_files = list(Path(repo_path).rglob("*.py"))
    if not py_files:
        print("  ℹ Nenhum arquivo .py encontrado")
        return {"results": []}

    stdout, stderr, code = run(
        ["bandit", "-r", str(repo_path), "-f", "json"],
        timeout=120,
    )
    if not stdout:
        print(f"  ⚠ Bandit falhou: {stderr[:200] if stderr else 'sem saída'}")
        return {"results": []}

    try:
        data = json.loads(stdout)
        n = len(data.get("results", []))
        print(f"  ✓ {n} achados encontrados")
        return data
    except json.JSONDecodeError:
        print("  ⚠ Resposta do Bandit não é JSON válido")
        return {"results": []}


def scan_safety():
    """Roda Safety check para SCA."""
    print("\n🔍 Safety (SCA - dependências)...")
    if not check_tool("Safety", "safety"):
        return {"dependencies": []}

    stdout, stderr, code = run(["safety", "check", "--json"], timeout=120)
    if not stdout:
        print(f"  ⚠ Safety falhou: {stderr[:200] if stderr else 'sem saída'}")
        return {"dependencies": []}

    try:
        raw = json.loads(stdout)
        # Safety retorna uma lista plana. Convertemos para o formato sca.json
        # que o dashboard espera: { "dependencies": [ { "name": ..., "vulns": [...] } ] }
        deps_map = {}
        for vuln in raw:
            if len(vuln) >= 5:
                name = (
                    vuln[0]
                    if isinstance(vuln, list)
                    else vuln.get("package_name", "desconhecido")
                )
                if name not in deps_map:
                    deps_map[name] = {
                        "name": name,
                        "version": vuln[1]
                        if isinstance(vuln, list)
                        else vuln.get("installed_version", ""),
                        "vulns": [],
                    }
                deps_map[name]["vulns"].append(
                    {
                        "id": vuln[2]
                        if isinstance(vuln, list)
                        else vuln.get("CVE", ""),
                        "description": vuln[3]
                        if isinstance(vuln, list)
                        else vuln.get("advisory", ""),
                        "fix_versions": [
                            vuln[4]
                            if isinstance(vuln, list)
                            else vuln.get("fixed_version", "")
                        ],
                    }
                )

        dependencies = list(deps_map.values())
        n = sum(len(d["vulns"]) for d in dependencies)
        print(f"  ✓ {n} vulnerabilidades em {len(dependencies)} dependências")
        return {"dependencies": dependencies}

    except (json.JSONDecodeError, IndexError, TypeError) as e:
        print(f"  ⚠ Erro ao processar Safety: {e}")
        return {"dependencies": []}


def scan_gitleaks(repo_path):
    """Roda Gitleaks para detecção de segredos."""
    print("\n🔍 Gitleaks (segredos)...")
    if not check_tool("Gitleaks", "gitleaks"):
        return []

    stdout, stderr, code = run(
        [
            "gitleaks",
            "detect",
            "--source",
            str(repo_path),
            "--report-format",
            "json",
            "--no-git",
            "-v",
        ],
        timeout=120,
    )
    if stdout:
        try:
            data = json.loads(stdout)
            if isinstance(data, list):
                print(f"  ✓ {len(data)} segredos encontrados")
                return data
        except json.JSONDecodeError:
            pass

    print("  ℹ Nenhum segredo detectado ou ferramenta não compatível")
    return []


def scan_trivy_fs(repo_path):
    """Roda Trivy para escanear filesystem (IaC + dependências)."""
    print("\n🔍 Trivy (IaC + filesystem)...")
    if not check_tool("Trivy", "trivy"):
        return {"results": []}

    stdout, stderr, code = run(
        [
            "trivy",
            "fs",
            "--format",
            "json",
            "--severity",
            "CRITICAL,HIGH,MEDIUM",
            str(repo_path),
        ],
        timeout=300,
    )
    if not stdout:
        print(f"  ⚠ Trivy falhou: {stderr[:200] if stderr else 'sem saída'}")
        return {"results": []}

    try:
        data = json.loads(stdout)
        n = len(data.get("Results", []))
        print(f"  ✓ {n} categorias analisadas")
        return data
    except json.JSONDecodeError:
        print("  ⚠ Resposta do Trivy não é JSON válido")
        return {"results": []}


# ──────────────────────────────────────────────
# Consolidado e salvamento
# ──────────────────────────────────────────────


def build_report(
    repo_path, semgrep_data, bandit_data, safety_data, gitleaks_data, trivy_data
):
    """Monta o relatório consolidado ASPM."""
    total_semgrep = len(semgrep_data.get("results", []))
    total_bandit = len(bandit_data.get("results", []))
    total_safety = sum(
        len(d.get("vulns", [])) for d in safety_data.get("dependencies", [])
    )
    total_gitleaks = len(gitleaks_data)

    # Contagem por severidade
    severities = {"Alta": 0, "Média": 0, "Baixa": 0}

    for r in semgrep_data.get("results", []):
        sev = r.get("extra", {}).get("severity", "")
        if sev == "ERROR":
            severities["Alta"] += 1
        elif sev == "WARNING":
            severities["Média"] += 1
        else:
            severities["Baixa"] += 1

    for r in bandit_data.get("results", []):
        sev = str(r.get("issue_severity", "")).upper()
        if sev == "HIGH":
            severities["Alta"] += 1
        elif sev == "MEDIUM":
            severities["Média"] += 1
        else:
            severities["Baixa"] += 1

    report = {
        "scan_metadata": {
            "timestamp": datetime.now().isoformat(),
            "repo_path": str(repo_path),
            "duration_seconds": 0,  # preenchido depois
            "tools": {
                "semgrep": total_semgrep > 0,
                "bandit": total_bandit > 0,
                "safety": total_safety > 0,
                "gitleaks": total_gitleaks > 0,
                "trivy": len(trivy_data.get("Results", [])) > 0,
            },
            "summary": {
                "total_findings": total_semgrep
                + total_bandit
                + total_safety
                + total_gitleaks,
                "by_severity": severities,
            },
        },
        "semgrep": semgrep_data,
        "bandit": bandit_data,
        "sca": safety_data,
        "secrets": {"gitleaks": gitleaks_data},
        "trivy": trivy_data,
    }
    return report


def save_json(path, data):
    """Salva dados como JSON indentado."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    print(f"  💾 Salvo: {path}")
    return path


# ──────────────────────────────────────────────
# CLI
# ──────────────────────────────────────────────


def run_all(repo_path, output_dir="./data", skip_trivy=False):
    """
    Executa todos os scanners e salva resultados.

    Parâmetros
    ----------
    repo_path : str ou Path
        Caminho do repositório a ser escaneado.
    output_dir : str
        Diretório onde salvar os JSONs.
    skip_trivy : bool
        Se True, pula o scan do Trivy (mais rápido).
    """
    repo_path = Path(repo_path).resolve()
    output_dir = Path(output_dir).resolve()

    if not repo_path.is_dir():
        print(f"❌ Diretório não encontrado: {repo_path}")
        sys.exit(1)

    bar = "=" * 60
    print(f"\n{bar}")
    print("  ASPM Scan Orchestrator")
    print(f"  Repositório: {repo_path}")
    print(f"  Data: {datetime.now().strftime('%d/%m/%Y %H:%M')}")
    print(bar)

    start = time.time()

    # ── Scans ──
    semgrep_data = scan_semgrep(repo_path)
    bandit_data = scan_bandit(repo_path)
    safety_data = scan_safety()
    gitleaks_data = scan_gitleaks(repo_path)
    trivy_data = {"results": []}
    if not skip_trivy:
        trivy_data = scan_trivy_fs(repo_path)

    # ── Consolidar ──
    print(f"\n{bar}")
    print("  Consolidando relatório...")
    report = build_report(
        repo_path, semgrep_data, bandit_data, safety_data, gitleaks_data, trivy_data
    )
    report["scan_metadata"]["duration_seconds"] = round(time.time() - start, 1)

    s = report["scan_metadata"]["summary"]
    print(f"  Total de achados: {s['total_findings']}")
    print(
        f"  Alta: {s['by_severity']['Alta']} | Média: {s['by_severity']['Média']} | Baixa: {s['by_severity']['Baixa']}"
    )
    print(f"  Duração: {report['scan_metadata']['duration_seconds']}s")

    # ── Salvar ──
    print(f"\n  Salvando relatórios em: {output_dir}")
    save_json(output_dir / "aspm-report.json", report)
    save_json(output_dir / "results.json", semgrep_data)
    save_json(output_dir / "bandit.json", bandit_data)
    save_json(output_dir / "sca.json", safety_data)
    save_json(output_dir / "gitleaks.json", gitleaks_data)
    save_json(output_dir / "trivy.json", trivy_data)

    bar = "=" * 60
    print(f"\n{bar}")
    print("  ✅ Scan concluído!")
    print(bar)

    return report


def main():
    parser = argparse.ArgumentParser(
        description="ASPM Scan Orchestrator - Executa múltiplos scanners de segurança",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Exemplos:
  python -m src.orchestrator --repo ./meu-projeto
  python -m src.orchestrator --repo ./meu-projeto --output ./data --skip-trivy
  python -m src.orchestrator --repo ./meu-projeto --skip-trivy
        """,
    )
    parser.add_argument(
        "--repo",
        "-r",
        required=True,
        help="Caminho do repositório/projeto a ser escaneado",
    )
    parser.add_argument(
        "--output",
        "-o",
        default="./data",
        help="Diretório de saída para os relatórios (default: ./data)",
    )
    parser.add_argument(
        "--skip-trivy",
        action="store_true",
        help="Pula o scan do Trivy (mais rápido, útil para projetos sem container/IaC)",
    )
    args = parser.parse_args()

    run_all(
        repo_path=args.repo,
        output_dir=args.output,
        skip_trivy=args.skip_trivy,
    )


if __name__ == "__main__":
    main()
