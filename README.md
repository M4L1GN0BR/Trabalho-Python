
# ASPM - Application Security Posture Management

![ASPM](https://img.shields.io/badge/ASPM-Enterprise-2563eb)
![Python](https://img.shields.io/badge/Python-3.11%2B-22c55e)
![Streamlit](https://img.shields.io/badge/Streamlit-Dashboard-ef4444)
![DeepSeek](https://img.shields.io/badge/IA-DeepSeek-38bdf8)

Plataforma ASPM (Application Security Posture Management) desenvolvida para centralizar, priorizar e correlacionar achados de segurança de múltiplas ferramentas em uma visão executiva unificada.

> Projeto acadêmico baseado nos frameworks **OWASP SAMM**, **OWASP Top 10:2025** e **OWASP SCVS**.

---

## 🎯 Problema que resolve

Times de segurança recebem relatórios isolados de diferentes ferramentas (SAST, SCA, segredos, análise de URL). Não há uma visão consolidada de risco, a priorização é manual e não existe correlação entre achados.

**ASPM resolve isso com:**

- **Pipeline automatizado** — um comando roda múltiplos scanners
- **Correlação de riscos** — cruza achados entre ferramentas (ex: segredo + endpoint exposto = crítico)
- **IA decisória** — DeepSeek classifica se é vulnerabilidade real, hardening ou falso positivo
- **Dashboard executivo** — visão consolidada para CISO/gerente

---

## 🧰 Ferramentas integradas

| Ferramenta | Tipo | Instalação |
|---|---|---|
| [Semgrep](https://semgrep.dev) | SAST (análise estática) | `pip install semgrep` |
| [Bandit](https://bandit.readthedocs.io) | Segurança Python | `pip install bandit` |
| [Safety](https://pyup.io/safety) | SCA (dependências) | `pip install safety` |
| [Gitleaks](https://gitleaks.io) | Segredos | `brew install gitleaks` / [download](https://gitleaks.io) |
| [Trivy](https://trivy.dev) | IaC + Container | `brew install trivy` / [script](https://trivy.dev) |
| [DeepSeek](https://deepseek.com) | IA generativa | Chave via `.env` |
| Streamlit | Dashboard | `pip install streamlit` |

---

## 📦 Estrutura do projeto

```
aspm/
├── .github/workflows/
│   └── aspm-scan.yml          # GitHub Action com cron + push + PR
├── dashboard/
│   └── app.py                 # Dashboard Streamlit (3200+ linhas)
├── src/
│   ├── main.py                # CLI principal
│   ├── orchestrator.py        # Orquestrador de scans
│   ├── core/
│   │   ├── parser.py          # Parsers de JSON
│   │   ├── prioritization.py  # Classificação de prioridade
│   │   └── ia/
│   │       ├── deepseek_client.py  # Cliente compartilhado DeepSeek
│   │       └── ai_helper.py        # Análise de vulnerabilidades com IA
├── data/                      # JSONs de saída dos scans
├── .env.example               # Template do .env
├── .gitignore
├── requirements.txt
└── CHANGELOG.md
```

---

## 🚀 Como usar

### 1. Clonar e configurar

```bash
git clone <seu-repo>
cd aspm
cp .env.example .env
```

Edite o `.env` com sua chave do DeepSeek:

```env
DEEPSEEK_API_KEY=sk-sua_chave_aqui
```

### 2. Instalar dependências

```bash
python -m venv .venv
source .venv/bin/activate     # Linux/Mac
.venv\Scripts\activate        # Windows

pip install -r requirements.txt
```

> **Atenção:** Gitleaks e Trivy não são bibliotecas Python. Instale separadamente.

### 3. Rodar o dashboard (modo manual)

```bash
python src/main.py dashboard
```

Abra o navegador em `http://localhost:8501`. Envie os JSONs de cada ferramenta nas abas correspondentes.

### 4. Rodar scan completo (modo automático)

```bash
# Scan básico
python src/main.py scan --repo ./caminho/do-projeto

# Scan com IA
python src/main.py scan --repo ./caminho/do-projeto --ai

# Scan sem Trivy (mais rápido)
python src/main.py scan --repo ./caminho/do-projeto --skip-trivy
```

Isso gera os arquivos em `./data/`:
- `aspm-report.json` — relatório consolidado
- `results.json` — Semgrep
- `bandit.json` — Bandit
- `sca.json` — Safety
- `gitleaks.json` — Gitleaks
- `trivy.json` — Trivy

Depois no dashboard, use o **Upload Consolidado** na sidebar para carregar tudo de uma vez.

---

## 🤖 Integração GitHub Actions

O workflow `.github/workflows/aspm-scan.yml` roda automaticamente:

| Evento | Quando |
|---|---|
| `schedule` | Todo dia às 6h UTC |
| `push` | Na branch `main` |
| `pull_request` | Comenta na PR com resumo dos achados |
| `workflow_dispatch` | Manualmente pela interface do GitHub |

---

## 🔬 Funcionalidades principais

### Pipeline de segurança
```
Código → Semgrep + Bandit + Safety + Gitleaks + Trivy → aspm-report.json → Dashboard
```

### Correlação de riscos
Cruza achados entre ferramentas para identificar riscos combinados:

- Segredos + Vulnerabilidades SAST → **Alta**
- CVE crítica + Credenciais expostas → **Alta**
- Endpoint exposto + Segredo no repositório → **Crítica**
- Múltiplas fontes com achados → **Postura fragilizada**

### IA decisória (DeepSeek)
A IA não só explica — ela **decide**:
- Classifica o tipo real (Vulnerabilidade / Hardening / Controle OK / Falso Positivo)
- Avalia exploitabilidade (remoto? requer auth? improvávavel?)
- Re-prioriza baseado em contexto real

### Histórico global
Acompanhe a evolução da postura de segurança ao longo do tempo com scores e gráficos.

---

## 🧪 Melhorias futuras

- [ ] Refatorar `dashboard/app.py` em módulos (`ui.py`, `reports.py`, `url_analysis.py`, etc.)
- [ ] Suporte a SBOM CycloneDX para SCA
- [ ] Scan de containers com Docker Scout
- [ ] Notificações via Slack/Email para novos achados críticos
- [ ] Modo offline (sem IA) com fallback local aprimorado
- [ ] Testes automatizados com `pytest`

---

## 📄 Licença

Projeto acadêmico — FIAP.
