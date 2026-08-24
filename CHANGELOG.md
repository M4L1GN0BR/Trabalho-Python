# ASPM - Novas Funcionalidades e Melhorias

##  Sumário

1. [Orquestrador de Scans](#1-orquestrador-de-scans)
2. [CLI Unificada](#2-cli-unificada)
3. [Integração GitHub Actions](#3-integração-github-actions)
4. [Novas Ferramentas](#4-novas-ferramentas)
5. [Prompts de IA Aprimorados](#5-prompts-de-ia-aprimorados)
6. [Cliente DeepSeek Compartilhado](#6-cliente-deepseek-compartilhado)
7. [Correção do Histórico de URL](#7-correção-do-histórico-de-url)
8. [Estrutura de Pacotes](#8-estrutura-de-pacotes)
9. [Refatoração do Dashboard em Módulos](#9-refatoração-do-dashboard-em-módulos)
10. [Dados de Demonstração](#10-dados-de-demonstração)
11. [Classificação de API corrigida (evidência real)](#11-classificação-de-api-corrigida-evidência-real)
12. [Mapeamento OWASP Top 10](#12-mapeamento-owasp-top-10)
13. [WAF, Cookies e JWT Analyzer (análise passiva)](#13-waf-cookies-e-jwt-analyzer-análise-passiva)
14. [Subdomínios, Crawler e Memória de IA](#14-subdomínios-crawler-e-memória-de-ia)
15. [Testes Ofensivos (Laboratório Autorizado)](#15-testes-ofensivos-laboratório-autorizado)
16. [Novos módulos ofensivos (CORS, HTTP Methods, Path Traversal, Open Redirect)](#16-novos-módulos-ofensivos-cors-http-methods-path-traversal-open-redirect)

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

## 9. Refatoração do Dashboard em Módulos

**Arquivo:** `dashboard/app.py` (REDUZIDO de ~3.400 para ~110 linhas)

O `app.py` concentrava banco, IA, PDF, parsers, CSS e renderização de todas as abas. Agora cada responsabilidade tem seu módulo:

```
dashboard/
├── app.py        # ponto de entrada (autenticação + criação das abas)
├── theme.py      # CSS dark corporativo (login + dashboard)
├── ui.py         # componentes visuais: cards, estados vazios, donuts, sidebar
├── db.py         # SQLite: init_db, histórico de URL/scans, ativos
├── state.py      # estado de sessão: falsos positivos, secrets, auto-save
├── ai.py         # IA DeepSeek + fallback local (ask_ai, resumo executivo)
├── parsers.py    # parsers Semgrep/Bandit/SCA para DataFrame
├── reports.py    # relatórios PDF (técnico e executivo)
├── session.py    # helpers de sessão/perfil (can, usuário logado)
└── tabs.py       # corpo de cada aba do dashboard
```

Novos módulos em `src/core/`:

- `src/core/text.py` — `clean_text()` e `load_json()` (utilidades puras)
- `src/core/correlation.py` — `correlate_findings()` (correlação entre ferramentas)
- `src/core/risk_engine.py` — ganhou `calculate_general_score()` (score simples do histórico)

O comportamento do dashboard foi preservado (mesmas abas, mesmos fluxos). Também foi corrigido um aviso no Resumo Executivo: a coluna "Achados ativos" da tabela de fontes misturava números com texto ("Score atual: X"), o que gerava erro de serialização no Arrow/Streamlit — agora a coluna é numérica e o score da URL continua visível nos cards.

**Teste de fumaça:** `test_dashboard_smoke.py` (NOVO) valida via `streamlit.testing.v1.AppTest` o boot, o login e a renderização das abas com dados consolidados.

---

## 10. Dados de Demonstração

**Arquivo:** `src/generate_demo_data.py` (NOVO) + comando `demo` no `src/main.py`

Para a apresentação, quando as ferramentas reais (Semgrep/Gitleaks/Trivy) não estão instaladas ou falham no Windows, o projeto gera dados simulados no formato exato do dashboard:

```bash
python src/main.py demo          # gera dados e ABRE o dashboard com eles carregados
python src/main.py demo -o ./x   # gera em ./x e abre
python src/main.py demo --seed 42  # reproduz a mesma execução
```

Gera `semgrep.json`, `bandit.json`, `sca.json`, `gitleaks.json` e `aspm-report.json` (upload consolidado na sidebar). Os achados são realistas (regras reais do Semgrep, testes do Bandit, CVEs reais com fix_versions, segredos mascarados), marcados como `demo_data: true` no relatório.

A cada execução o gerador **sorteia achados diferentes** (quantidade, regras, arquivos e linhas) para parecer um scan real. O parâmetro `--seed` reproduz exatamente a mesma execução — útil para ensaiar a apresentação com um resultado específico.

O comando `demo` agora **sobe o dashboard automaticamente** e carrega o `aspm-report.json` na sessão (modo demonstração via `ASPM_AUTO_DEMO=1`): após o login `admin/admin`, os gráficos, cards e o Risk Engine já aparecem preenchidos, sem upload manual.

Escolhemos um **gerador determinístico em Python** em vez de pedir para a IA gerar os JSONs: garante JSON sempre válido, funciona offline e evita alucinações de CVEs. A IA do dashboard continua explicando cada achado normalmente.

---

## 11. Classificação de API corrigida (evidência real)

**Arquivo:** `src/core/url_analysis.py`

Antes, qualquer `/api` que respondesse com JSON viraria "Achado Ativo / Média" só por "aparência de API" — mesmo sendo uma API pública legítima (ex: o frontend do site que consome os próprios dados). Agora a classificação segue a filosofia evidence-based do projeto:

| Cenário | Classificação |
|---|---|
| `/api` com JSON público, sem dado sensível | **Melhoria Recomendada** / Baixa (hardening) |
| Swagger UI, OpenAPI, GraphQL Playground reais | **Achado Ativo** / Média |
| API com credencial/token/dado sensível no corpo | **Achado Ativo** / Alta |
| Resposta sem indício técnico ou sensível | **Falso Positivo Automático** |

A mudança alinha a ferramenta com o que a IA já recomendava (expor `/api` sem evidência = hardening, não vulnerabilidade) e evita inflar o score com endpoints públicos legítimos.

---

## 12. Mapeamento OWASP Top 10

**Arquivo:** `src/core/owasp.py` (NOVO)

Cada evidência normalizada (Evidence Engine) agora recebe uma categoria do **OWASP Top 10:2025**:

- Classificação por padrões de texto, IDs de regra (Semgrep check_id / Bandit test_name), ferramenta e CVEs
- `build_evidence_store()` já retorna evidências enriquecidas (`owasp_id`, `owasp_label`, `owasp_name`)
- Riscos prioritários do Risk Engine exibem a categoria OWASP
- Resumo Executivo ganhou os cards "Categorias OWASP Top 10" (top 5 por frequência)
- Relatório executivo em PDF ganhou a seção "Categorias OWASP Top 10"
- Sem dependências externas; o mapeamento é automático e aproximado (revisão manual recomendada)

Exemplos de mapeamento no demo atual: CVEs → `A06:2025` · segredos/cripto fraca → `A02:2025` · SQLi/XSS → `A03:2025` · pickle/yaml → `A08:2025` · path traversal → `A01:2025`.

---

## 13. WAF, Cookies e JWT Analyzer (análise passiva)

**Arquivos:** `src/core/url_analysis.py`, `src/core/secrets.py`, `src/generate_demo_data.py`

Três análises defensivas adicionadas (nenhuma exploração — apenas leitura de respostas e decodificação):

| Recurso | O que faz | Classificação |
|---|---|---|
| **Detecção de WAF/CDN** | Reconhece Cloudflare, Akamai, Incapsula, Sucuri, F5 BIG-IP, AWS WAF etc. via headers (`cf-ray`, `x-sucuri-id`, `Server`...) | WAF presente = Controle OK · ausente = Melhoria Recomendada |
| **Análise de cookies** | Verifica `Secure`, `HttpOnly` e `SameSite` de cada `Set-Cookie` | Flags OK = Controle OK · flag faltando = Melhoria Recomendada |
| **JWT analyzer** | Decodifica header/payload do JWT (sem validar assinatura) | Sinaliza `alg=none`, sem `exp`, token expirado e claims `role`/`admin` |

O demo (`src/generate_demo_data.py`) agora gera um JWT estruturado (`alg=HS256`, payload com `role=admin` e sem `exp`) para a análise aparecer na apresentação. A aba Attack Surface ganhou a categoria **Cookies** e a seção "Headers de Segurança e Cookies".

Validação real: `betano.bet.br` → WAF **Cloudflare** detectado (Controle OK) e cookie `_cfuvid` com Secure/HttpOnly/SameSite (Controle OK).

---

## 14. Subdomínios, Crawler e Memória de IA

**Arquivos:** `src/core/url_analysis.py`, `dashboard/db.py`, `dashboard/ai.py`, `dashboard/tabs.py`

Três recursos passivos/defensivos adicionados:

| Recurso | O que faz | Onde aparece |
|---|---|---|
| **Enumeração de subdomínios** | Consulta crt.sh (Certificate Transparency) com fallback no HackerTarget — fontes públicas e passivas | Attack Surface → "Subdomínios identificados" |
| **Crawler limitado** | Segue links internos do mesmo domínio (máx. 12 páginas, timeouts curtos) | Attack Surface → "Páginas internas mapeadas no crawl" |
| **Memória da IA** | Persiste as análises da IA (explicação/risco/correção) no SQLite (`ai_memory`) com usuário e data | Administração → "Memória da IA" |

Ambos os recursos de recon têm checkbox na aba URL Analysis e degradam graciosamente offline. Validação real: `betano.bet.br` → **17 subdomínios** encontrados e **5 páginas** no crawl.

Os módulos ofensivos (recon ativo, IDOR, API fuzzing, rate-limit) permanecem fora do escopo — aguardando decisão do grupo.

---

## 15. Testes Ofensivos (Laboratório Autorizado)

**Arquivos:** `src/core/attack/` (NOVO pacote: `engine.py`, `recon_active.py`, `idor_tester.py`, `api_fuzzer.py`, `rate_limit_tester.py`) + aba "Testes Ofensivos" no dashboard + comando `attack` na CLI

Módulos de teste ativo implementados **após decisão do grupo**, com travas de segurança:

| Módulo | O que faz | Limites |
|---|---|---|
| **Recon Ativo** | Scan TCP de 26 portas comuns + banner grabbing; serviços sensíveis (banco, RDP, SMB...) expostos viram achados | timeout 2s/porta |
| **IDOR** | Compara respostas para IDs diferentes (1, 2, 3, 100000) e sinaliza possível enumeração | 4 IDs, GET |
| **API Fuzzing** | Tenta 25 caminhos comuns de API e destaca rotas sensíveis acessíveis (admin/config/token...) | 25 GETs |
| **Rate Limit** | Envia 15 requisições e verifica presença de limitação (ausência = achado, OWASP API4:2023) | 15 GETs |

**Travas:** aviso de autorização na interface com checkbox obrigatório, nenhuma ação destrutiva (só GET/connect), timeouts curtos, resultado sempre rotulado como "possível" quando heurístico. CLI: `python src/main.py attack --url <alvo> --modules recon,idor,fuzz,rate` → salva `data/attack-results.json`.

Validado contra servidor local de teste (autorizado): os 4 módulos geraram achados corretamente.

> Aviso legal: testar terceiros sem autorização é ilegal no Brasil (Lei 12.737/2012). Os módulos são ferramentas legítimas para laboratório/uso autorizado.

---

## 16. Novos módulos ofensivos (CORS, HTTP Methods, Path Traversal, Open Redirect)

**Arquivos:** `src/core/attack/cors_checker.py`, `src/core/attack/http_methods.py`, `src/core/attack/path_traversal.py`, `src/core/attack/open_redirect.py` (NOVOS) + engine atualizado

O pacote de testes ofensivos agora tem **8 módulos** (antes 4):

| Módulo | Detecção | Classificação |
|---|---|---|
| **CORS** | Reflexo de `Origin` arbitrária + `Access-Control-Allow-Credentials: true` | Achado Ativo Alta (eco+credenciais) / Média (eco) / Melhoria (wildcard) |
| **HTTP Methods** | `TRACE` habilitado (XST) e métodos de escrita no `Allow` | TRACE = Achado Ativo Média · escrita = Melhoria |
| **Path Traversal** | Payloads de LFI (`../../etc/passwd`, variações encoded) com detecção de conteúdo sensível | Confirmado = Achado Ativo Alta |
| **Open Redirect** | Parâmetros comuns (`url`, `next`, `returnUrl`...) apontando para domínio externo | Achado Ativo Média |

CLI: `python src/main.py attack --url <alvo> --modules recon,idor,fuzz,rate,cors,methods,traversal,redirect --traversal-param file`. Dashboard: aba Testes Ofensivos com os 8 módulos selecionáveis. Validado contra servidor local (autorizado) — os 4 novos módulos geraram os achados esperados.

Exploração avançada (SQLi/XSS ativos, credential stuffing) permanece como evolução futura documentada no README, aguardando decisão do grupo.

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
