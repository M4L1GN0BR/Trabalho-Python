
# ASPM - Application Security Posture Management

![ASPM](https://img.shields.io/badge/ASPM-Enterprise-2563eb)
![Python](https://img.shields.io/badge/Python-3.11%2B-22c55e)
![Streamlit](https://img.shields.io/badge/Streamlit-Dashboard-ef4444)
![DeepSeek](https://img.shields.io/badge/IA-DeepSeek-38bdf8)

Plataforma ASPM (Application Security Posture Management) desenvolvida para centralizar, priorizar e correlacionar achados de segurança de múltiplas ferramentas em uma visão executiva unificada.

> Projeto acadêmico baseado nos frameworks **OWASP SAMM**, **OWASP Top 10:2025** e **OWASP SCVS**.

---

##  Problema que resolve

Times de segurança recebem relatórios isolados de diferentes ferramentas (SAST, SCA, segredos, análise de URL). Não há uma visão consolidada de risco, a priorização é manual e não existe correlação entre achados.

**ASPM resolve isso com:**

- **Pipeline automatizado** — um comando roda múltiplos scanners
- **Correlação de riscos** — cruza achados entre ferramentas (ex: segredo + endpoint exposto = crítico)
- **IA decisória** — DeepSeek classifica se é vulnerabilidade real, hardening ou falso positivo
- **Dashboard executivo** — visão consolidada para CISO/gerente

---

##  Ferramentas integradas

| Ferramenta | Tipo | Instalação |
|---|---|---|
| [Semgrep](https://semgrep.dev) | SAST (análise estática) | `pip install semgrep` |
| [Bandit](https://bandit.readthedocs.io) | Segurança Python | `pip install bandit` |
| [pip-audit](https://github.com/pypa/pip-audit) | SCA (dependências) | `pip install pip-audit` |
| [Gitleaks](https://gitleaks.io) | Segredos | `brew install gitleaks` / [download](https://gitleaks.io) |
| [Trivy](https://trivy.dev) | IaC + Container | `brew install trivy` / [script](https://trivy.dev) |
| [DeepSeek](https://deepseek.com) | IA generativa | Chave via `.env` |
| Streamlit | Dashboard | `pip install streamlit` |

> **Nota:** O SCA usa `pip-audit` (substituto do Safety, cuja versão 3.x passou a exigir login).

---

##  Estrutura do projeto

```
aspm/
├── .github/workflows/
│   └── aspm-scan.yml.disabled   # GitHub Action (desativado por ora)
├── dashboard/
│   ├── app.py                   # Ponto de entrada do Streamlit (~110 linhas)
│   ├── theme.py                 # CSS dark corporativo (login + dashboard)
│   ├── ui.py                    # Componentes visuais: cards, donuts, sidebar
│   ├── db.py                    # SQLite: histórico de URL/scans, ativos, usuários
│   ├── state.py                 # Estado de sessão: falsos positivos, secrets
│   ├── ai.py                    # IA DeepSeek + fallback local
│   ├── parsers.py               # Parsers Semgrep/Bandit/SCA
│   ├── reports.py               # Relatórios PDF (técnico e executivo)
│   ├── session.py               # Sessão/perfil e permissões
│   └── tabs.py                  # Corpo das abas do dashboard
├── src/
│   ├── main.py                  # CLI principal (scan + dashboard + demo)
│   ├── orchestrator.py          # Orquestrador de scans
│   ├── generate_demo_data.py    # Gerador de dados simulados p/ apresentação
│   └── core/
│       ├── auth.py              # Login, bcrypt e perfis de acesso
│       ├── risk_engine.py       # Risk Engine consolidado (score + priorização)
│       ├── evidence.py          # Evidence Engine (normaliza achados)
│       ├── correlation.py       # Correlação de riscos entre ferramentas
│       ├── owasp.py             # Mapeamento OWASP Top 10 (classificação por evidência)
│       ├── secrets.py           # Secrets Scanner (regras + Gitleaks)
│       ├── url_analysis.py      # Análise de URL, headers, TLS, WAF, cookies, subdomínios
│       ├── attack/              # Testes ofensivos (lab autorizado): recon, IDOR, fuzz, rate
│       ├── context.py           # Extração de contexto do código para a IA
│       ├── text.py              # Utilidades de texto/JSON
│       ├── parser.py            # Parsers de JSON simples
│       ├── prioritization.py    # Classificação de prioridade
│       ├── database_path.py     # Caminho centralizado do banco SQLite
│       └── ia/
│           ├── deepseek_client.py   # Cliente compartilhado DeepSeek
│           └── ai_helper.py         # Análise de vulnerabilidades com IA
├── data/                        # JSONs de saída dos scans
├── .env.example                 # Template do .env
├── .gitignore
├── requirements.txt
├── test_dashboard_smoke.py      # Smoke test do dashboard (AppTest)
├── test_apresentacao.py         # Valida o fluxo de apresentação (modo demo)
├── ROTEIRO-APRESENTACAO.md      # Guia passo a passo para a apresentação
└── CHANGELOG.md
```

---

##  Como usar

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

Abra o navegador em `http://localhost:8501`.

O dashboard exige **login** (usuários e senhas com hash bcrypt no SQLite):

| Usuário | Senha | Perfil | Acesso |
|---|---|---|---|
| `admin` | `admin` | Administrador | Tudo, incluindo gestão de usuários e reset de histórico |
| *(criar)* | — | Analista | Uploads, scans e análise de URL |
| *(criar)* | — | Visualizador | Somente leitura |

> Usuários com perfil **Analista** e **Visualizador** podem ser criados na aba **Administração** (somente admin).

O upload pode ser feito de duas formas:

1. **Upload Consolidado** (recomendado): envie o `aspm-report.json` na sidebar — preenche Semgrep, Bandit, SCA e Secrets de uma vez e registra o scan no histórico.
2. **Upload individual**: envie o JSON de cada ferramenta na aba correspondente.

A aba **URL Analysis** permite análise passiva de qualquer URL (headers, TLS, WAF, cookies, subdomínios via crt.sh e crawler limitado — todos com checkbox para ligar/desligar).

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
- `sca.json` — pip-audit
- `gitleaks.json` — Gitleaks
- `trivy.json` — Trivy

Depois no dashboard, use o **Upload Consolidado** na sidebar para carregar tudo de uma vez.

### 5. Gerar dados de demonstração (para apresentação)

Se as ferramentas reais não estiverem instaladas (ou o Semgrep falhar no Windows), gere dados **simulados** no formato exato do dashboard e **abra o site já com eles carregados**:

```bash
python src/main.py demo
# ou em outro diretório:
python src/main.py demo --output ./data/demo
# reproduzir exatamente a mesma execução (mesma seed = mesmos achados):
python src/main.py demo --seed 42
```

O comando faz tudo: gera os arquivos em `./data/demo/`, sobe o dashboard (`http://localhost:8501`) e **carrega os achados automaticamente** — é só fazer login (`admin` / `admin`) e os gráficos, cards e o Risk Engine já aparecem preenchidos, sem upload manual.

Arquivos gerados:

- `semgrep.json`, `bandit.json`, `sca.json`, `gitleaks.json` — upload individual por aba (se preferir)
- `aspm-report.json` — **Upload Consolidado** na sidebar (carregado automaticamente no modo demo)

> Os achados são **simulados** (marcados como `demo_data: true` no relatório) — usam regras reais do Semgrep, testes reais do Bandit e CVEs reais com versões de correção, para a apresentação ficar realista. A IA do dashboard continua explicando cada achado normalmente.

### 6. Testes Ofensivos (somente uso autorizado / laboratório)

Módulos de teste ativo (Recon Ativo, IDOR, API Fuzzing, Rate Limit) — **apenas para alvos autorizados** (DVWA, Juice Shop, laboratório próprio). Testar terceiros sem autorização é ilegal no Brasil (Lei 12.737/2012).

**Pela CLI:**

```bash
python src/main.py attack --url https://alvo-autorizado.com
# só alguns módulos:
python src/main.py attack --url https://alvo-autorizado.com --modules recon,fuzz,cors,redirect
# parâmetro de ID diferente (IDOR) e de arquivo (Path Traversal):
python src/main.py attack --url https://alvo-autorizado.com/api/user/{id} --id-param id --traversal-param file
```

Módulos disponíveis: `recon, idor, fuzz, rate, cors, methods, traversal, redirect`. Gera `data/attack-results.json` com os achados.

**Pelo dashboard:** aba **Testes Ofensivos (Lab)** → confirme a autorização no checkbox (obrigatório) → informe a URL e os módulos → **Executar testes**.

### 7. Roteiro de apresentação

O arquivo **`ROTEIRO-APRESENTACAO.md`** é um guia passo a passo para apresentar o projeto (comandos em ordem, o que falar em cada etapa e fallbacks). Recomendado para a entrega da FIAP.

---

##  Integração GitHub Actions

O workflow `.github/workflows/aspm-scan.yml` foi preparado para rodar automaticamente:

| Evento | Quando |
|---|---|
| `schedule` | Todo dia às 6h UTC |
| `push` | Na branch `main` |
| `pull_request` | Comenta na PR com resumo dos achados |
| `workflow_dispatch` | Manualmente pela interface do GitHub |

> **Status atual:** o workflow está **desativado** (arquivo renomeado para `.disabled`) enquanto o grupo decide a publicação do repositório. Para reativar, remova o sufixo `.disabled` do arquivo.

---

##  Funcionalidades principais

### Pipeline de segurança
```
Código → Semgrep + Bandit + pip-audit + Gitleaks + Trivy → aspm-report.json → Dashboard
```

### Autenticação e controle de acesso
- Login com SQLite e senhas com **hash bcrypt**
- Três perfis: **Administrador**, **Analista** e **Visualizador**
- Histórico vinculado ao usuário (admin vê tudo; analista vê o próprio)
- Reset de histórico restrito ao Administrador

### Risk Engine consolidado
Motor único que correlaciona **Semgrep, Bandit, SCA, Secrets, URL Analysis e Attack Surface**:

- Security Score global (0–100) com classificação (Boa / Atenção / Crítica)
- Total de riscos por severidade e riscos prioritários
- Justificativa do score baseada em evidências, exposição e possibilidade real de exploração
- Redução de peso para falsos positivos, controles OK e melhorias
- Prioridade elevada quando várias fontes apontam o mesmo alvo

### Evidence Engine
Normaliza todos os achados em um formato único (ferramenta, categoria, arquivo, linha, endpoint, dependência, CVE, severidade, confiança, trecho de código, resposta HTTP). É a base do Risk Engine e da IA.

### Mapeamento OWASP Top 10
Cada achado é classificado automaticamente em uma categoria do **OWASP Top 10:2025** (A01–A10). O Resumo Executivo mostra as categorias mais presentes no ambiente em cards, os riscos prioritários exibem a categoria OWASP, e o relatório executivo em PDF traz a seção "Categorias OWASP Top 10".

Exemplos de mapeamento: SQLi/XSS → `A03:2025 Injection` · segredos e criptografia fraca → `A02:2025 Cryptographic Failures` · CVEs → `A06:2025 Vulnerable and Outdated Components` · hardcoded password → `A07:2025 Identification and Authentication Failures`.

### IA decisória (DeepSeek)
A IA não só explica — ela **decide**:
- Classifica o tipo real (Vulnerabilidade / Hardening / Controle OK / Falso Positivo)
- Avalia exploitabilidade e re-prioriza baseado no contexto real do código
- Gera resumo executivo e justifica a priorização
- Nunca inventa vulnerabilidades: sem evidência, informa que não há informação suficiente

### Relatório executivo (PDF)
Exporte o relatório executivo consolidado (score, severidades, justificativa, riscos prioritários e correlações) em PDF a partir do Resumo Executivo.

### Histórico global
Acompanhe a evolução da postura de segurança ao longo do tempo com scores e gráficos.

### Assets / Ativos
Estrutura de ativos pronta no banco (tabela `assets`) e nos módulos. A aba de cadastro está **desativada por ora** (decisão do grupo) — a lógica permanece em `dashboard/tabs.py` como `render_assets_tab()` e pode ser reativada na lista de tabs do `app.py`.

### Engagements & Scans
Histórico completo de scans com filtro por ativo, evolução do score e exportação CSV.

### Attack Surface
Análise de endpoints, headers de segurança, TLS, **WAF/CDN** e tecnologias detectadas — sempre baseada em evidências, sem tratar `/admin` ou `/api` como vulnerabilidade apenas pela existência.

### WAF, Cookies e JWT (análise passiva)
- **WAF/CDN**: detecta proteção de borda pelos headers da resposta (Cloudflare, Akamai, Incapsula, Sucuri, F5, AWS WAF...) → aparece como Controle OK; ausência vira Melhoria Recomendada
- **Cookies**: analisa flags `Secure`, `HttpOnly` e `SameSite` de cada `Set-Cookie` → Controle OK ou Melhoria Recomendada
- **JWT**: o Secrets Scanner decodifica header/payload do JWT (sem validar assinatura) e sinaliza `alg=none`, ausência de `exp` e claims sensíveis (`role`/`admin`)

### Subdomínios e crawler (recon passivo)
- **Enumeração de subdomínios**: consulta Certificate Transparency (crt.sh) com fallback no HackerTarget — fontes públicas e passivas, sem scan direto no alvo (ex: `betano.bet.br` → 17 subdomínios)
- **Crawler limitado**: segue links internos do mesmo domínio (máx. 12 páginas) para mapear rotas — mostra as páginas internas encontradas no Attack Surface
- Ambos com checkboxes na aba URL Analysis e degradação graciosa offline

### Memória da IA
As análises da IA (explicações, riscos e correções de cada achado) são **persistidas no SQLite** e podem ser consultadas na aba **Administração → Memória da IA** — mostrando o histórico do que a IA analisou, por usuário e data.

### Testes Ofensivos (Lab)
Módulos de teste ativo em aba própria (**Testes Ofensivos**), **somente para uso autorizado** (DVWA, Juice Shop, alvos próprios):

- **Recon Ativo**: scan TCP de portas comuns + banner grabbing; serviços sensíveis expostos (banco, RDP, SMB...) viram achados
- **IDOR**: compara respostas para IDs diferentes e sinaliza possível enumeração
- **API Fuzzing**: tenta caminhos comuns de API e destaca rotas sensíveis acessíveis
- **Rate Limit**: verifica se o alvo limita requisições (ausência = achado, OWASP API4)
- **CORS**: envia `Origin` de terceiros e detecta reflexo de origem com credenciais
- **HTTP Methods**: lista métodos via `OPTIONS` e testa `TRACE` (XST)
- **Path Traversal**: testa payloads de LFI (`../../etc/passwd`) no parâmetro informado
- **Open Redirect**: testa parâmetros comuns de redirecionamento (`url`, `next`, `returnUrl`...)

A execução exige **confirmação explícita de autorização** e é limitada (poucas requisições, timeouts, sem ações destrutivas). Também disponível via CLI: `python src/main.py attack --url <alvo>` — resultados salvos em `data/attack-results.json`.

---

##  Evolução Arquitetural

### Conceitos

| Conceito | Descrição |
|---|---|
| **Assets** | Aplicações, APIs, repositórios ou serviços monitorados |
| **Engagements** | Execuções de análise vinculadas a um ativo |
| **Findings** | Vulnerabilidades retornadas pelas ferramentas |
| **Attack Surface** | Endpoints, headers e tecnologias expostas |
| **Correlation** | Cruzamento de achados entre ferramentas com contexto do ativo |

### Arquitetura do dashboard

O `app.py` é apenas o ponto de entrada (~110 linhas). Cada responsabilidade vive em um módulo:

| Módulo | Responsabilidade |
|---|---|
| `dashboard/tabs.py` | Corpo das abas (Resumo, Semgrep, Bandit, SCA, URL, Secrets, Attack Surface, Engagements, Admin) |
| `dashboard/ui.py` | Cards, estados vazios, gráficos donut, login e sidebar |
| `dashboard/db.py` | SQLite: histórico, scans, ativos e migrações |
| `dashboard/state.py` | Falsos positivos, secrets e auto-save do histórico |
| `dashboard/ai.py` | Chamadas à IA com cache e fallback local |
| `dashboard/parsers.py` | JSON das ferramentas → DataFrame padronizado |
| `dashboard/reports.py` | Geração de PDF técnico e executivo |
| `dashboard/theme.py` | CSS dark corporativo |
| `dashboard/session.py` | Sessão do usuário e permissões |
| `src/core/owasp.py` | Mapeamento OWASP Top 10 (classificação por evidência) |

As regras de negócio ficam em `src/core/` (risk engine, evidências, correlação, secrets, URL analysis, auth), sem dependência de Streamlit.

### API REST (futura)

| Método | Endpoint | Descrição |
|---|---|---|
| `GET` | `/api/v1/assets` | Listar ativos |
| `POST` | `/api/v1/assets` | Criar ativo |
| `GET` | `/api/v1/assets/{id}` | Detalhes do ativo |
| `DELETE` | `/api/v1/assets/{id}` | Remover ativo |
| `GET` | `/api/v1/assets/{id}/attack-surface` | Superfície de ataque |
| `GET` | `/api/v1/scans` | Listar scans |
| `POST` | `/api/v1/scans` | Disparar scan |
| `GET` | `/api/v1/scans/{id}` | Detalhes do scan |
| `PATCH` | `/api/v1/scans/{id}/status` | Atualizar status |
| `GET` | `/api/v1/findings` | Listar achados |
| `GET` | `/api/v1/correlation` | Correlação de riscos |
| `GET` | `/api/v1/reports/{scan_id}` | Relatório consolidado |

A API será documentada com Swagger/OpenAPI e permitirá integração CI/CD.

---

##  Melhorias futuras

- [ ] Reativar a aba **Assets / Ativos** no dashboard (lógica já pronta)
- [ ] Reativar a **GitHub Action** de scans periódicos (cron diário)
- [ ] Suporte a SBOM CycloneDX para SCA
- [ ] Notificações via Slack/Email
- [ ] API REST com Swagger/OpenAPI
- [ ] Ampliar testes automatizados com `pytest`
- [ ] Módulos de exploração avançada (SQLi/XSS/credential stuffing) — apenas em laboratório, com decisão do grupo

---

##  Verificação rápida antes de apresentar

```bash
# Smoke test do dashboard (login + todas as abas + dados consolidados)
python test_dashboard_smoke.py

# Valida o fluxo de apresentação (modo demo)
python test_apresentacao.py

# Dados de demonstração (gera e abre o site com os achados carregados)
python src/main.py demo

# Testes ofensivos (somente uso autorizado / laboratório)
python src/main.py attack --url https://alvo-autorizado.com

# Scan completo de exemplo
python src/main.py scan --repo ./src --output ./data --skip-trivy

# Dashboard
python src/main.py dashboard   # login: admin / admin

# Roteiro completo da apresentação (comandos em ordem + fallbacks)
# → veja ROTEIRO-APRESENTACAO.md
```

---

##  Licença

Projeto acadêmico — FIAP.
