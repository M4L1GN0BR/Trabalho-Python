# ASPM - Novas Funcionalidades e Melhorias

## 📋 Sumário

1. [Orquestrador de Scans](#1-orquestrador-de-scans)
2. [CLI Unificada](#2-cli-unificada)
3. [Integração GitHub Actions](#3-integração-github-actions)
4. [Novas Ferramentas](#4-novas-ferramentas)
5. [Prompts de IA Aprimorados](#5-prompts-de-ia-aprimorados)
6. [Cliente DeepSeek Compartilhado](#6-cliente-deepseek-compartilhado)
7. [Correção do Histórico de URL](#7-correção-do-histórico-de-url)
8. [Estrutura de Pacotes](#8-estrutura-de-pacotes)

---

## 1. Orquestrador de Scans

**Arquivo:** `src/orchestrator.py` (NOVO)

Antes o `main.py` só printava resultados de um JSON pré-existente. Agora criamos um **orquestrador** que executa todas as ferramentas de segurança automaticamente.

```bash
python src/main.py scan --repo ./caminho/do-projeto
```

O que ele faz:
- Roda **Semgrep** (SAST), **Bandit** (Python), **Safety** (SCA), **Gitleaks** (segredos) e **Trivy** (IaC/container)
- Se a ferramenta não estiver instalada, ele **pula silenciosamente** sem quebrar
- Gera **5 arquivos JSON** no diretório de saída:
  - `aspm-report.json` — relatório consolidado com metadados e sumário
  - `results.json` — output do Semgrep
  - `bandit.json` — output do Bandit
  - `sca.json` — output do Safety (convertido para o formato do dashboard)
  - `gitleaks.json` — output do Gitleaks
  - `trivy.json` — output do Trivy
- Exibe resumo no terminal com contagem por severidade

---

## 2. CLI Unificada

**Arquivo:** `src/main.py` (REESCRITO)

O `main.py` virou uma CLI com subcomandos:

| Comando | Descrição |
|---|---|
| `python src/main.py scan --repo ./dir` | Executa scan orquestrado |
| `python src/main.py scan --repo ./dir --ai` | Scan + enriquecimento com IA (DeepSeek) |
| `python src/main.py scan --repo ./dir --skip-trivy` | Scan sem Trivy (mais rápido) |
| `python src/main.py dashboard` | Abre o Streamlit dashboard |

Exemplos:
```bash
# Scan básico
python src/main.py scan --repo ./meu-projeto

# Scan com análise de IA
python src/main.py scan --repo ./meu-projeto --ai

# Scan rápido (sem Trivy)
python src/main.py scan --repo ./meu-projeto --skip-trivy

# Abrir dashboard
python src/main.py dashboard
```

---

## 3. Integração GitHub Actions

**Arquivo:** `.github/workflows/aspm-scan.yml` (NOVO)

Workflow que roda os scans automaticamente no GitHub:

```yaml
on:
  schedule:
    - cron: '0 6 * * *'   # todo dia às 6h UTC
  push:
    branches: [main]
  pull_request:
    branches: [main]
  workflow_dispatch:        # execução manual
```

O que ele faz:
1. **Checkout** do repositório
2. **Instala** Python, dependências e ferramentas (Semgrep, Bandit, Safety, Gitleaks, Trivy)
3. **Executa** `python src/main.py scan --repo .`
4. **Faz upload** dos JSONs como artefato (30 dias de retenção)
5. **Exibe resumo** no job summary do GitHub
6. **Comenta na PR** com total de achados e segredos encontrados

---

## 4. Novas Ferramentas

**Arquivo:** `requirements.txt` (ATUALIZADO)

| Ferramenta | Tipo | Como instalar |
|---|---|---|
| **Safety** | SCA (dependências Python) | `pip install safety` |
| **Semgrep** | SAST | `pip install semgrep` (já estava) |
| **Bandit** | Segurança Python | `pip install bandit` |
| **Gitleaks** | Segredos | `brew install gitleaks` / `apt install gitleaks` |
| **Trivy** | IaC + Container + Filesystem | `brew install trivy` / script oficial |

O Safety substitui os dados mockados de SCA (`sca.json`, `sca_real.json`) por **dados reais de CVEs** consultando o banco da pyup.io.

---

## 5. Prompts de IA Aprimorados

**Arquivos:** `src/core/ia/ai_helper.py` e `dashboard/app.py` (REESCRITOS)

Os prompts da IA foram reformulados para serem **decisórios**, não apenas explicativos:

### Antes (genérico):
> "Você é um especialista. Analise a vulnerabilidade. Responda com EXPLICACAO, RISCO, CORRECAO."

### Agora (analista sênior ASPM):
> "Classifique o tipo real do achado (Vulnerabilidade / Hardening / Controle OK / Falso Positivo). Re-priorize com base em exploitabilidade. Explique em linguagem de negócio para um CISO."

Mudanças práticas:
- Temperatura reduzida de `0.2` para `0.1` (respostas mais determinísticas)
- IA agora distingue **vulnerabilidade real** de **hardening** e **falso positivo**
- IA avalia **exploitabilidade** ("Exploitável remotamente", "Requer autenticação", etc.)
- IA **re-prioriza** baseado em contexto real, não na severidade da ferramenta

---

## 6. Cliente DeepSeek Compartilhado

**Arquivo:** `src/core/ia/deepseek_client.py` (NOVO)

Antes a chamada à API DeepSeek estava **duplicada** em `ai_helper.py` e `dashboard/app.py`. Agora:

- **Único ponto de chamada** HTTP para a API
- Ambos os módulos importam daqui
- `SYSTEM_ASPM` padrão para todas as chamadas
- Função `configure()` para sobrescrever config em runtime (útil para testes)
- Tratamento de erros centralizado (timeout, HTTPError, exceções genéricas)

---

## 7. Correção do Histórico de URL

**Arquivo:** `dashboard/app.py` (CORRIGIDO)

**Problema:** O histórico de URL não funcionava — a aba "Histórico" nunca mostrava nada.

**Causa:** A função `auto_save_url_scan_once` foi criada mas **nunca era chamada**.

**Solução:** Adicionamos a chamada `auto_save_url_scan_once(result, high_count, medium_count, low_count)` logo após cada análise de URL. Agora o salvamento é **automático** — não precisa clicar em botão "Salvar".

---

## 8. Estrutura de Pacotes

**Arquivos:** `src/__init__.py`, `src/core/__init__.py`, `src/core/ia/__init__.py` (NOVOS)

Adicionados arquivos `__init__.py` para transformar `src` em um pacote Python próprio. Isso permite imports limpos como:

```python
from src.core.ia.deepseek_client import call_deepseek
```

---

## 🔧 Instalação

```bash
# 1. Clonar o projeto
git clone <seu-repo>
cd <seu-repo>

# 2. Criar virtualenv
python -m venv .venv
source .venv/bin/activate  # Linux/Mac
.venv\Scripts\activate     # Windows

# 3. Instalar dependências
pip install -r requirements.txt

# 4. Instalar ferramentas de scan (opcional para o dashboard)
pip install semgrep bandit safety
# Gitleaks: https://gitleaks.io
# Trivy: https://trivy.dev

# 5. Configurar .env
echo "DEEPSEEK_API_KEY=sua_chave" > .env

# 6. Rodar
python src/main.py scan --repo ./meu-projeto
python src/main.py dashboard
```
