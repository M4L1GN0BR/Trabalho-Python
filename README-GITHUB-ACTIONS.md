# GitHub Actions — Guia de Uso

Este guia cobre os **dois usos** de GitHub Actions neste projeto:

1. **CI do próprio projeto** — workflow de scan de segurança automático
   (`.github/workflows/aspm-scan.yml`).
2. **Análise de workflows de outros repositórios** — aba "CI/CD & Templates"
   do dashboard, que detecta shell injection, secrets herdados e
   `pull_request_target` em `.github/workflows/*.yml`.

---

## 1. CI do projeto (workflow de scan)

O workflow `aspm-scan.yml` executa os scanners da plataforma e publica o
relatório como artefato. Está entregue como **`.disabled`** para não disparar
sem configuração — ative renomeando o arquivo:

```bash
git mv .github/workflows/aspm-scan.yml.disabled .github/workflows/aspm-scan.yml
```

### O que o workflow faz

| Passo | Descrição |
|---|---|
| `tests` (job) | Roda `test_api.py`, `test_core.py` e `test_dashboard_smoke.py` |
| `scan` (job) | Instala Semgrep, Bandit, pip-audit, Gitleaks e Trivy |
| Execução | `python src/main.py scan --repo . --output ./aspm-output --skip-trivy` |
| Artefato | Publica `aspm-output/*.json` (relatório consolidado, retenção 30 dias) |
| Resumo | Comentário no GitHub (PR) e `$GITHUB_STEP_SUMMARY` com total/severidades |

### Agendamento e gatilhos

```yaml
on:
  schedule:
    - cron: '0 6 * * *'   # todos os dias às 6h UTC
  push:
    branches: [main]
  pull_request:
    branches: [main]
  workflow_dispatch:        # execução manual pela aba "Actions"
```

### Como visualizar o resultado

1. Acesse **Actions** → selecione o workflow **ASPM Scan & Tests**.
2. Abra a execução mais recente → seção **Artefatos** → baixe `aspm-report`.
3. No dashboard, use **Upload Consolidado** na sidebar com o
   `aspm-report.json` baixado.

---

## 2. Análise de CI/CD de outros repositórios (aba do dashboard)

Além do CI do próprio projeto, a plataforma **analisa workflows de qualquer
repositório** (ex.: o DefectDojo) na aba **"CI/CD & Templates"**:

1. Informe o caminho do repositório (ex.: `C:/projetos/django-defectdojo`).
2. Clique em **Analisar CI/CD e Templates**.
3. A aba lista achados de:

| Regra | Risco | O que detecta |
|---|---|---|
| **Shell Injection** | Alta | `${{ github.event.* }}` interpolado em `run:` de shell |
| **pull_request_target** | Alta | Evento que executa código do PR com secrets do repo base |
| **Secrets: inherit** | Média | Job filho herdando todos os secrets |
| **Permissões amplas** | Média | `permissions: write-all` ou `contents: write` |
| **Eventos não confiáveis** | Média | `issue_comment`, `issues`, `discussion` |
| **Checkout de PR** | Crítica | Checkout do head do PR em contexto `pull_request_target` |

### Exemplo de shell injection detectado

```yaml
- name: Echo repo
  run: echo "repository=${{ github.repository }}"   # ← detectado
```

**Correção recomendada** — usar `env:` mapeado:

```yaml
- name: Echo repo
  env:
    REPO: ${{ github.repository }}
  run: echo "repository=$REPO"
```

### Uso via Python (CLI)

```python
from src.core.github_actions import scan_repo_workflows, analyze_workflow

findings = scan_repo_workflows("/caminho/do/repo")   # todos os workflows
# ou, para um único arquivo:
with open(".github/workflows/ci.yml", encoding="utf-8") as f:
    findings = analyze_workflow(f.read(), path=".github/workflows/ci.yml")
```

---

## Referência rápida

| Comando | Efeito |
|---|---|
| `git mv .github/workflows/aspm-scan.yml.disabled .github/workflows/aspm-scan.yml` | Ativa o CI |
| (GitHub) Actions → workflow → Run workflow | Executa manualmente |
| (GitHub) Artefatos → `aspm-report` | Baixa o relatório para o dashboard |
