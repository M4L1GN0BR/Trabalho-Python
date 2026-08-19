"""
Gerador de dados de demonstração para o ASPM dashboard.

A cada execução sorteia achados diferentes (arquivos, linhas, regras e CVEs)
para parecer um scan real. Os dados são SIMULADOS — apenas para apresentação.

Uso:
    python src/main.py demo                        # aleatório a cada execução
    python src/main.py demo --seed 42              # reproduz a mesma execução
    python src/main.py demo --output ./data/demo

Arquivos gerados:
    semgrep.json    → {"results": [...]}
    bandit.json     → {"results": [...]}
    sca.json        → {"dependencies": [...]}
    gitleaks.json   → [achados no formato Gitleaks]
    aspm-report.json→ relatório consolidado (upload único na sidebar)
"""

import json
import random
from datetime import datetime
from pathlib import Path

# ═══════════════════════════════════════════════════════════════
# POOLS DE ACHADOS REALISTAS (semgrep, bandit, sca, gitleaks)
# ═══════════════════════════════════════════════════════════════

PATHS = [
    "src/app/routes.py",
    "src/app/views.py",
    "src/app/utils.py",
    "src/app/proxy.py",
    "src/app/main.py",
    "src/config/settings.py",
    "src/services/payment.py",
    "src/services/api_client.py",
    "src/repository/user_repo.py",
    "src/repository/order_repo.py",
    "src/auth/tokens.py",
    "src/ci/deploy.py",
    "src/workers/queue.py",
    "src/db/connection.py",
]

SEMGREP_POOL = [
    {
        "check_id": "python.lang.security.audit.eval-usage",
        "severity": "ERROR",
        "confidence": "HIGH",
        "message": "Data from request may be passed to eval(). Audit the use of eval to ensure untrusted data is never evaluated.",
        "code": "    result = eval(request.args.get('expr', '0'))",
    },
    {
        "check_id": "python.django.security.injection.sql",
        "severity": "ERROR",
        "confidence": "HIGH",
        "message": "Possible SQL injection vector through string-based query construction. Use parameterized queries or an ORM.",
        "code": '    query = f"SELECT * FROM users WHERE id = {user_id}"',
    },
    {
        "check_id": "python.lang.security.audit.command-injection",
        "severity": "ERROR",
        "confidence": "HIGH",
        "message": "Command injection: user-controlled data flows into subprocess without sanitization.",
        "code": '    subprocess.call(f"ping -c 1 {host}", shell=True)',
    },
    {
        "check_id": "python.lang.security.audit.path-traversal",
        "severity": "ERROR",
        "confidence": "MEDIUM",
        "message": "Path traversal: file path built from user input without normalization.",
        "code": '    data = open(os.path.join(UPLOAD_DIR, filename)).read()',
    },
    {
        "check_id": "python.lang.security.audit.jwt-hardcode-secret",
        "severity": "ERROR",
        "confidence": "HIGH",
        "message": "Hardcoded JWT secret detected. Rotate the secret and store it in environment variables.",
        "code": '    payload = jwt.encode(data, "my_super_secret_key", algorithm="HS256")',
    },
    {
        "check_id": "python.lang.security.audit.dangerous-system-call",
        "severity": "WARNING",
        "confidence": "MEDIUM",
        "message": "Detected subprocess call with shell=True. Validate and sanitize any user-controlled input before passing to the shell.",
        "code": "    subprocess.run(cmd, shell=True)",
    },
    {
        "check_id": "python.lang.security.audit.hardcoded-password",
        "severity": "WARNING",
        "confidence": "HIGH",
        "message": "Possible hardcoded password detected. Use environment variables or a secrets manager instead.",
        "code": '    DB_PASSWORD = "admin123"',
    },
    {
        "check_id": "python.lang.security.audit.requests-ssrf",
        "severity": "WARNING",
        "confidence": "MEDIUM",
        "message": "Requests call using user-controlled URL. Review for SSRF risk and restrict allowed destinations.",
        "code": "    return requests.get(url).text",
    },
    {
        "check_id": "python.lang.security.audit.insecure-deserialization",
        "severity": "WARNING",
        "confidence": "MEDIUM",
        "message": "Pickle deserialization of untrusted data can lead to arbitrary code execution.",
        "code": "    obj = pickle.loads(request.data)",
    },
    {
        "check_id": "python.lang.security.audit.insecure-hashlib",
        "severity": "WARNING",
        "confidence": "HIGH",
        "message": "Use of insecure hash function (MD5/SHA1) for sensitive data. Prefer SHA-256 or stronger.",
        "code": '    digest = hashlib.md5(password.encode()).hexdigest()',
    },
    {
        "check_id": "python.lang.security.audit.weak-crypto",
        "severity": "WARNING",
        "confidence": "MEDIUM",
        "message": "Weak cryptographic primitive detected. Prefer modern algorithms with adequate key sizes.",
        "code": "    cipher = AES.new(key, AES.MODE_ECB)",
    },
    {
        "check_id": "python.lang.security.audit.yaml-load",
        "severity": "WARNING",
        "confidence": "MEDIUM",
        "message": "yaml.load without Loader can execute arbitrary code. Use yaml.safe_load.",
        "code": "    config = yaml.load(request.data)",
    },
    {
        "check_id": "python.django.security.xss.audit-unsafe-html",
        "severity": "WARNING",
        "confidence": "MEDIUM",
        "message": "Django template marks content as safe without escaping. Potential XSS via user input.",
        "code": "    return render(request, 'page.html', {'html': content | safe})",
    },
    {
        "check_id": "python.lang.security.audit.cors-access-control-allow-origin",
        "severity": "WARNING",
        "confidence": "MEDIUM",
        "message": "CORS configured with a wildcard origin. Restrict to trusted domains.",
        "code": '    resp.headers["Access-Control-Allow-Origin"] = "*"',
    },
    {
        "check_id": "python.lang.security.audit.unsafe-tarfile-extract",
        "severity": "WARNING",
        "confidence": "MEDIUM",
        "message": "Tarfile extraction without path validation allows zip-slip path traversal.",
        "code": "    tar.extractall(EXTRACT_DIR)",
    },
    {
        "check_id": "python.lang.security.audit.ldap-injection",
        "severity": "WARNING",
        "confidence": "LOW",
        "message": "LDAP query built from user input. Validate and sanitize filter values.",
        "code": '    results = conn.search("dc=corp", f"(uid={username})")',
    },
]

BANDIT_POOL = [
    {
        "test_name": "B608",
        "severity": "HIGH",
        "confidence": "HIGH",
        "text": "Possible SQL injection vector through string-based query construction. Prefer parameterized queries.",
        "code": '    query = f"SELECT * FROM users WHERE id = {user_id}"',
    },
    {
        "test_name": "B501",
        "severity": "HIGH",
        "confidence": "MEDIUM",
        "text": "Requests call with verify=False disables TLS certificate verification.",
        "code": '    resp = requests.get(url, verify=False)',
    },
    {
        "test_name": "B506",
        "severity": "HIGH",
        "confidence": "MEDIUM",
        "text": "yaml.load with unsafe Loader can lead to arbitrary code execution. Use yaml.safe_load.",
        "code": "    data = yaml.load(stream)",
    },
    {
        "test_name": "B105",
        "severity": "MEDIUM",
        "confidence": "HIGH",
        "text": "Possible hardcoded password. Store credentials in environment variables or a secrets manager.",
        "code": '    DB_PASSWORD = "admin123"',
    },
    {
        "test_name": "B307",
        "severity": "MEDIUM",
        "confidence": "MEDIUM",
        "text": "Consider possible security implications associated with subprocess module with shell=True.",
        "code": "    subprocess.run(cmd, shell=True)",
    },
    {
        "test_name": "B324",
        "severity": "MEDIUM",
        "confidence": "HIGH",
        "text": "Use of insecure MD2/MD4/MD5/SHA1 hash function. Prefer SHA-256 or stronger.",
        "code": '    digest = hashlib.md5(password.encode()).hexdigest()',
    },
    {
        "test_name": "B201",
        "severity": "MEDIUM",
        "confidence": "MEDIUM",
        "text": "Flask app running with debug=True exposes the Werkzeug debugger in production.",
        "code": "    app.run(host='0.0.0.0', port=5000, debug=True)",
    },
    {
        "test_name": "B301",
        "severity": "MEDIUM",
        "confidence": "MEDIUM",
        "text": "Pickle deserialization of untrusted data can lead to arbitrary code execution.",
        "code": "    obj = pickle.loads(request.data)",
    },
    {
        "test_name": "B325",
        "severity": "MEDIUM",
        "confidence": "MEDIUM",
        "text": "tempfile.mktemp is insecure: use tempfile.mkstemp or TemporaryFile instead.",
        "code": '    tmp = tempfile.mktemp(suffix=".log")',
    },
    {
        "test_name": "B402",
        "severity": "MEDIUM",
        "confidence": "MEDIUM",
        "text": "Use of insecure FTP (ftplib). Prefer SFTP or a secure file transfer protocol.",
        "code": "    ftp = ftplib.FTP(host)",
    },
    {
        "test_name": "B110",
        "severity": "LOW",
        "confidence": "MEDIUM",
        "text": "Try, Except, Pass detected. Consider logging the exception instead of silently ignoring it.",
        "code": "        except Exception:\n            pass",
    },
    {
        "test_name": "B112",
        "severity": "LOW",
        "confidence": "MEDIUM",
        "text": "Try, Except, Continue detected. Consider logging the exception instead of silently continuing.",
        "code": "        except Exception:\n            continue",
    },
    {
        "test_name": "B311",
        "severity": "LOW",
        "confidence": "HIGH",
        "text": "Standard pseudo-random generators are not suitable for security/cryptographic purposes.",
        "code": '    otp = str(random.randint(100000, 999999))',
    },
    {
        "test_name": "B404",
        "severity": "LOW",
        "confidence": "HIGH",
        "text": "Consider possible security implications associated with the subprocess module.",
        "code": "    import subprocess",
    },
]

SCA_POOL = [
    {
        "name": "flask",
        "version": "2.2.2",
        "vulns": [
            {
                "id": "CVE-2023-30861",
                "description": "Flask vulnerable to denial of service via specially crafted JSON request data.",
                "fix_versions": ["2.2.5"],
            },
            {
                "id": "CVE-2024-24762",
                "description": "Flask vulnerable to resource exhaustion through large multipart form uploads.",
                "fix_versions": ["3.0.3"],
            },
        ],
    },
    {
        "name": "requests",
        "version": "2.28.1",
        "vulns": [
            {
                "id": "CVE-2023-32681",
                "description": "Requests vulnerable to information disclosure via improper handling of proxy credentials.",
                "fix_versions": ["2.31.0"],
            },
            {
                "id": "CVE-2024-35195",
                "description": "Requests can leak cookies across domains during redirects in certain scenarios.",
                "fix_versions": ["2.32.0"],
            },
        ],
    },
    {
        "name": "urllib3",
        "version": "1.26.14",
        "vulns": [
            {
                "id": "CVE-2023-43804",
                "description": "urllib3 vulnerable to cookie header injection when redirecting with special characters.",
                "fix_versions": ["1.26.17"],
            },
            {
                "id": "CVE-2023-45803",
                "description": "urllib3 request body desynchronization when using HTTP/1.1 keep-alive.",
                "fix_versions": ["1.26.18"],
            },
            {
                "id": "CVE-2024-37891",
                "description": "urllib3 can leak Proxy-Authorization header across requests on the same connection.",
                "fix_versions": ["1.26.19", "2.2.2"],
            },
        ],
    },
    {
        "name": "cryptography",
        "version": "39.0.0",
        "vulns": [
            {
                "id": "CVE-2023-0286",
                "description": "OpenSSL X.400 address type confusion leading to possible man-in-the-middle.",
                "fix_versions": ["39.0.1"],
            },
            {
                "id": "CVE-2023-23931",
                "description": "cryptography vulnerable to denial of service when processing crafted certificates.",
                "fix_versions": ["39.0.1"],
            },
            {
                "id": "CVE-2024-26130",
                "description": "OpenSSL null dereference when verifying specially crafted certificates.",
                "fix_versions": ["42.0.4"],
            },
        ],
    },
    {
        "name": "jinja2",
        "version": "3.1.1",
        "vulns": [
            {
                "id": "CVE-2024-22195",
                "description": "Jinja2 xmlattr filter vulnerable to cross-site scripting via attribute name injection.",
                "fix_versions": ["3.1.3"],
            },
            {
                "id": "CVE-2024-34064",
                "description": "Jinja2 html attribute filter vulnerable to cross-site scripting via attribute escaping bypass.",
                "fix_versions": ["3.1.4"],
            },
        ],
    },
    {
        "name": "werkzeug",
        "version": "2.2.2",
        "vulns": [
            {
                "id": "CVE-2023-25577",
                "description": "Werkzeug vulnerable to denial of service via multipart form data with many parts.",
                "fix_versions": ["2.2.3"],
            },
            {
                "id": "CVE-2024-34069",
                "description": "Werkzeug development server vulnerable to denial of service via crafted requests.",
                "fix_versions": ["3.0.3"],
            },
        ],
    },
    {
        "name": "pip",
        "version": "23.1",
        "vulns": [
            {
                "id": "CVE-2023-5752",
                "description": "pip vulnerable to Mercurial config injection when installing from crafted packages.",
                "fix_versions": ["23.3"],
            }
        ],
    },
]

GITLEAKS_POOL = [
    {
        "RuleID": "aws-access-token",
        "Description": "AWS Access Key",
        "secret": lambda: "AKIA" + _rand_chars(16, "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"),
    },
    {
        "RuleID": "github-pat",
        "Description": "GitHub Personal Access Token",
        "secret": lambda: "ghp_" + _rand_chars(36),
    },
    {
        "RuleID": "google-api-key",
        "Description": "Google API Key",
        "secret": lambda: "AIza" + _rand_chars(35, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"),
    },
    {
        "RuleID": "slack-token",
        "Description": "Slack Token",
        "secret": lambda: "xoxb-" + _rand_chars(24),
    },
    {
        "RuleID": "npm-token",
        "Description": "NPM Access Token",
        "secret": lambda: "npm_" + _rand_chars(36),
    },
    {
        "RuleID": "private-key",
        "Description": "Private Key",
        "secret": lambda: "-----BEGIN RSA PRIVATE KEY-----",
    },
    {
        "RuleID": "jwt-token",
        "Description": "JWT Token",
        "secret": lambda: _make_demo_jwt(),
    },
    {
        "RuleID": "telegram-bot-token",
        "Description": "Telegram Bot Token",
        "secret": lambda: str(random.randint(100000000, 999999999)) + ":AAF" + _rand_chars(30),
    },
]


# ═══════════════════════════════════════════════════════════════
# AMOSTRAGEM E GERAÇÃO
# ═══════════════════════════════════════════════════════════════


def _rand_chars(n, alphabet=None):
    import string

    if alphabet is None:
        alphabet = string.ascii_letters + string.digits
    return "".join(random.choice(alphabet) for _ in range(n))


def _make_demo_jwt():
    """Gera um JWT estruturado (header/payload válidos, assinatura aleatória)."""
    import base64
    import json as _json

    def _enc(obj):
        raw = _json.dumps(obj, separators=(",", ":")).encode()
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    header = {"alg": "HS256", "typ": "JWT"}
    payload = {"sub": "user_1042", "role": "admin", "iat": int(datetime.now().timestamp())}
    return _enc(header) + "." + _enc(payload) + "." + _rand_chars(43)


def _sample(pool, min_n, max_n):
    """Sorteia uma quantidade aleatória de itens do pool."""
    n = random.randint(min_n, max_n)
    n = min(n, len(pool))
    return random.sample(pool, k=n)


def _build_semgrep_results():
    results = []
    for item in _sample(SEMGREP_POOL, 4, 7):
        line = random.randint(8, 380)
        results.append(
            {
                "check_id": item["check_id"],
                "path": random.choice(PATHS),
                "start": {"line": line},
                "extra": {
                    "severity": item["severity"],
                    "confidence": item["confidence"],
                    "message": item["message"],
                    "lines": item["code"],
                },
            }
        )
    return results


def _build_bandit_results():
    results = []
    for item in _sample(BANDIT_POOL, 4, 7):
        results.append(
            {
                "test_name": item["test_name"],
                "filename": random.choice(PATHS),
                "line_number": random.randint(8, 380),
                "issue_severity": item["severity"],
                "issue_confidence": item["confidence"],
                "issue_text": item["text"],
                "code": item["code"],
            }
        )
    return results


def _build_sca_dependencies():
    dependencies = []
    for dep in _sample(SCA_POOL, 3, 6):
        vulns = _sample(dep["vulns"], 1, min(2, len(dep["vulns"])))
        dependencies.append({"name": dep["name"], "version": dep["version"], "vulns": vulns})
    return dependencies


def _build_gitleaks_findings():
    findings = []
    for item in _sample(GITLEAKS_POOL, 2, 5):
        findings.append(
            {
                "RuleID": item["RuleID"],
                "Description": item["Description"],
                "File": random.choice(PATHS),
                "StartLine": random.randint(4, 120),
                "Secret": item["secret"](),
            }
        )
    return findings


def _severity_label(severity):
    """Mesma semântica dos parsers do dashboard (Semgrep/Bandit)."""
    severity = str(severity).upper()
    if severity in ("ERROR", "HIGH"):
        return "Alta"
    if severity in ("WARNING", "MEDIUM"):
        return "Média"
    return "Baixa"


def _build_summary(semgrep_results, bandit_results, sca_dependencies, gitleaks_findings):
    """Calcula total_findings e by_severity consistentes com o dashboard."""
    alta = 0
    media = 0
    baixa = 0

    for r in semgrep_results:
        label = _severity_label(r["extra"]["severity"])
        if label == "Alta":
            alta += 1
        elif label == "Média":
            media += 1
        else:
            baixa += 1

    for r in bandit_results:
        label = _severity_label(r["issue_severity"])
        if label == "Alta":
            alta += 1
        elif label == "Média":
            media += 1
        else:
            baixa += 1

    # SCA: o parser do dashboard classifica todo CVE como Alta
    sca_total = sum(len(d.get("vulns", [])) for d in sca_dependencies)
    alta += sca_total

    # Gitleaks: o parser classifica todo achado como Alta
    alta += len(gitleaks_findings)

    return {
        "total_findings": len(semgrep_results) + len(bandit_results)
        + sca_total + len(gitleaks_findings),
        "by_severity": {"Alta": alta, "Média": media, "Baixa": baixa},
        "demo_data": True,
    }


def generate_demo_data(output_dir="./data/demo", seed=None):
    """
    Gera arquivos de demonstração com achados aleatórios.

    Parâmetros
    ----------
    output_dir : str
        Diretório de saída.
    seed : int, optional
        Se informado, reproduz a mesma execução (mesma seed = mesmos achados).

    Retorna
    -------
    Path
        Diretório de saída.
    """
    if seed is not None:
        random.seed(seed)

    semgrep_results = _build_semgrep_results()
    bandit_results = _build_bandit_results()
    sca_dependencies = _build_sca_dependencies()
    gitleaks_findings = _build_gitleaks_findings()

    report = {
        "scan_metadata": {
            "timestamp": datetime.now().isoformat(),
            "repo_path": "./demo-app",
            "duration_seconds": 0,
            "tools": {
                "semgrep": True,
                "bandit": True,
                "safety": False,
                "gitleaks": True,
                "trivy": False,
            },
            "summary": _build_summary(
                semgrep_results, bandit_results, sca_dependencies, gitleaks_findings
            ),
        },
        "semgrep": {"results": semgrep_results},
        "bandit": {"results": bandit_results},
        "sca": {"dependencies": sca_dependencies},
        "secrets": {"gitleaks": gitleaks_findings},
        "trivy": {"Results": []},
    }

    files = {
        "semgrep.json": {"results": semgrep_results},
        "bandit.json": {"results": bandit_results},
        "sca.json": {"dependencies": sca_dependencies},
        "gitleaks.json": gitleaks_findings,
        "aspm-report.json": report,
    }

    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    print("=" * 60)
    print("  DADOS DE DEMONSTRAÇÃO - ASPM (aleatórios)")
    print("  Atenção: achados SIMULADOS, apenas para apresentação")
    if seed is not None:
        print(f"  Seed: {seed} (reproduza com --seed {seed})")
    print("=" * 60)

    for name, data in files.items():
        path = out / name
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        print(f"  [OK] {path}")

    summary = report["scan_metadata"]["summary"]
    sev = summary["by_severity"]
    print("-" * 60)
    print(
        f"  Total: {summary['total_findings']} | "
        f"Alta: {sev['Alta']} | Média: {sev['Média']} | Baixa: {sev['Baixa']}"
    )
    print("  Use o 'Upload Consolidado' na sidebar com aspm-report.json")
    print("=" * 60)

    return out


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Gera dados de demonstração ASPM")
    parser.add_argument(
        "--output", "-o", default="./data/demo", help="Diretório de saída"
    )
    parser.add_argument(
        "--seed", type=int, default=None, help="Seed p/ reproduzir a mesma execução"
    )
    args = parser.parse_args()
    generate_demo_data(args.output, seed=args.seed)
