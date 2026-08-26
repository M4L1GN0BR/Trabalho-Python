"""
Análise de workflows GitHub Actions (CI/CD Security).

Detecta padrões de risco em `.github/workflows/*.yml`:

- **Shell injection**: interpolação `${{ ... }}` dentro de bloco `run:` de shell
  (o contexto do evento — `github.repository`, `github.event.*` — pode ser
  controlado por atacante via PR, issue title, etc.)
- **Secrets herdados sem necessidade** (`secrets: inherit`): amplia superfície
  de segredos para jobs filhos.
- **`pull_request_target`**: executa código do PR no contexto do repositório
  base, com acesso a secrets — um dos vetores mais explorados em CI.
- **Permissões amplas**: `permissions: write-all` ou ausência de permissões
  restritas (princípio do menor privilégio).
- **Checkout de PR não confiável**: checkout sem restrição em eventos de PR.

Os findings seguem o formato do dashboard (Tipo/Categoria/Item/Status/Prioridade/
Evidências/Descrição), reutilizando a UI existente.

Aprendizado do estudo DefectDojo: o Semgrep encontrou 21 shell-injections e
16 secrets-inherit nos workflows do projeto — esta é uma fonte ASPM dedicada.
"""

import re
from pathlib import Path

try:
    import yaml
except ImportError:  # pragma: no cover
    yaml = None

# Interpolação de contexto do GitHub dentro de strings
_CTX_PATTERN = re.compile(r"\$\{\{\s*[^}]+?\}\}")

# Expressões de contexto que indicam entrada potencialmente controlada
_DANGEROUS_CTX = (
    "github.event",
    "github.head_ref",
    "github.ref_name",
    "github.repository",
    "github.actor",
    "github.event_name",
    "github.ref",
    "github.base_ref",
    "github.event.commits",
    "github.event.issue",
    "github.event.pull_request",
    "github.event.head_commit",
    "github.event.release",
    "github.event.workflow_run",
    "github.event.comment",
)

# Eventos que disparam a partir de conteúdo não confiável (PRs/forks)
_UNTRUSTED_EVENTS = (
    "pull_request",
    "pull_request_target",
    "issue_comment",
    "issues",
    "discussion",
    "discussion_comment",
    "workflow_run",
    "repository_dispatch",
)

# Extensões tratadas como script/shell dentro de run:
_SHELL_PATTERNS = re.compile(r"\b(bash|sh|pwsh|powershell|cmd)\b", re.IGNORECASE)


def _make_finding(categoria, item, prioridade, evidencias, descricao):
    """Monta um finding no formato padrão do dashboard."""
    return {
        "Tipo": "Achado Ativo" if prioridade in ("Alta", "Crítica") else "Melhoria Recomendada",
        "Categoria": categoria,
        "Item": item,
        "Status": "Risco",
        "Prioridade": prioridade,
        "Evidências": evidencias,
        "Descrição": descricao,
        "URL": "",
    }


def _extract_step(step, job_name):
    """Retorna o conteúdo de run/uses de um step."""
    run = step.get("run")
    if run is not None:
        return "run", str(run)
    uses = step.get("uses")
    if uses is not None:
        return "uses", str(uses)
    return None, None


def analyze_workflow(content, path="workflow.yml"):
    """
    Analisa o conteúdo YAML de um workflow GitHub Actions.

    Parâmetros
    ----------
    content : str
        Conteúdo do arquivo YAML.
    path : str
        Caminho do workflow (para exibição).

    Retorna
    -------
    list[dict]
        Findings no formato do dashboard.
    """
    findings = []
    if yaml is None:
        return findings

    try:
        data = yaml.safe_load(content)
    except Exception:
        return findings
    if not isinstance(data, dict):
        return findings

    # ── Eventos não confiáveis ──
    # PyYAML (YAML 1.1) interpreta a chave "on:" como booleano True.
    on = data.get("on")
    if on is None:
        on = data.get(True)
    if on is None:
        on = data.get("on:")
    if isinstance(on, dict):
        for event in on:
            if event == "pull_request_target":
                findings.append(
                    _make_finding(
                        "CI/CD",
                        f"{path} — pull_request_target",
                        "Alta",
                        f"evento `{event}` configurado",
                        "pull_request_target executa código do PR no contexto do repositório "
                        "base, com acesso a secrets. Se o checkout não for validado, um PR "
                        "malicioso pode exfiltrar secrets.",
                    )
                )
            elif event in ("issue_comment", "issues", "discussion", "discussion_comment"):
                findings.append(
                    _make_finding(
                        "CI/CD",
                        f"{path} — {event}",
                        "Média",
                        f"evento `{event}` configurado",
                        "Evento disparado por conteúdo não confiável (issues/comentários). "
                        "Conteúdo do evento nunca deve ser interpolado em run: sem validação.",
                    )
                )

    # ── Jobs: permissões e steps ──
    jobs = data.get("jobs") or {}
    if not isinstance(jobs, dict):
        return findings

    for job_name, job in jobs.items():
        if not isinstance(job, dict):
            continue

        # Permissões amplas
        perms = job.get("permissions", data.get("permissions"))
        if perms == "write-all" or (
            isinstance(perms, dict) and perms.get("contents") == "write"
        ):
            findings.append(
                _make_finding(
                    "CI/CD",
                    f"{path} — job {job_name}: permissões amplas",
                    "Média",
                    f"permissions={perms}",
                    "Permissões de escrita amplas violam o princípio do menor privilégio. "
                    "Restrinja permissões por job.",
                )
            )

        # Secrets herdados
        if job.get("secrets") == "inherit":
            findings.append(
                _make_finding(
                    "CI/CD",
                    f"{path} — job {job_name}: secrets herdados",
                    "Média",
                    "secrets: inherit",
                    "Herdar todos os secrets do repositório para um job filho amplia a "
                    "superfície de exposição. Prefira passar apenas os secrets necessários.",
                )
            )

        # Steps
        steps = job.get("steps") or []
        for step in steps:
            if not isinstance(step, dict):
                continue
            kind, value = _extract_step(step, job_name)
            if kind == "run":
                self_hosted = "self-hosted" in str(job.get("runs-on", ""))
                findings.extend(
                    _analyze_run_step(step, value, path, job_name, self_hosted)
                )
            elif kind == "uses":
                # Checkout de PR não confiável
                if (
                    "actions/checkout" in value
                    and "pull_request_target" in str(on)
                    and "ref" in step
                    and ("github.event.pull_request.head" in str(step.get("ref")) or "head" in str(step.get("ref")).lower())
                ):
                    findings.append(
                        _make_finding(
                            "CI/CD",
                            f"{path} — checkout de PR em pull_request_target",
                            "Crítica",
                            "checkout com ref do PR em contexto pull_request_target",
                            "Combinar pull_request_target com checkout do PR é o vetor clássico "
                            "de exfiltração de secrets. Valide o código antes de executá-lo.",
                        )
                    )

    return findings


def _analyze_run_step(step, run_content, path, job_name, self_hosted):
    """Analisa o conteúdo de um bloco run: em busca de interpolações perigosas."""
    findings = []
    run_lines = run_content.splitlines()
    step_name = str(step.get("name") or f"step {job_name}").replace("`", "")

    for line_no, line in enumerate(run_lines, start=1):
        # Interpolação de contexto em linha de shell
        for m in _CTX_PATTERN.finditer(line):
            ctx = m.group(0)
            ctx_inner = ctx[3:-2].strip()

            # Só considera contextos que podem ser controlados por evento/PR
            if any(dc in ctx_inner for dc in _DANGEROUS_CTX):
                prioridade = "Alta"
                if any(dc in ctx_inner for dc in ("github.event.commits", "github.event.head_commit")):
                    prioridade = "Crítica"
                findings.append(
                    _make_finding(
                        "Shell Injection",
                        f"{path} — {step_name} (linha {line_no})",
                        prioridade,
                        f"`{ctx}` interpolado em run:",
                        f"Contexto do evento ({ctx_inner}) interpolado em comando shell. "
                        "Se o conteúdo for controlado por PR/issue, um atacante pode injetar "
                        "comandos. Use env: mapeado e nunca concatene contexto em strings de shell.",
                    )
                )
                break  # uma linha já basta

        # shell: explícito
        if "shell:" in line and _SHELL_PATTERNS.search(line):
            # já coberto pelas interpolações; sem interpolação, apenas informativo
            pass

    return findings


def scan_repo_workflows(repo_path):
    """
    Percorre `.github/workflows/*.yml` de um repositório.

    Parâmetros
    ----------
    repo_path : str | Path
        Caminho do repositório.

    Retorna
    -------
    list[dict]
        Findings consolidados de todos os workflows.
    """
    base = Path(repo_path) / ".github" / "workflows"
    findings = []
    if not base.is_dir():
        return findings

    for wf in sorted(base.glob("*.yml")) + sorted(base.glob("*.yaml")):
        try:
            content = wf.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        findings.extend(analyze_workflow(content, path=str(wf.relative_to(Path(repo_path)))))

    return findings


def findings_to_evidences(findings):
    """Converte findings de CI/CD em evidências normalizadas (Evidence Engine)."""
    from src.core.evidence import normalize_url_finding, enrich_evidences

    return enrich_evidences([normalize_url_finding(f) for f in findings])
