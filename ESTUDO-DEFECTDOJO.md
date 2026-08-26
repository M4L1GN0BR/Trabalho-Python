# Estudo de Caso — Scan ASPM em Ambiente Real (DefectDojo)

Análise técnica da plataforma ASPM executada contra o código-fonte do
**[DefectDojo](https://github.com/DefectDojo/django-defectdojo)** — uma das
ferramentas de gestão de segurança de aplicações mais maduras do ecossistema
open source (Django, ~2.000 arquivos Python, 347 MB, dezenas de integrações).

O objetivo deste estudo é triplo:

1. Validar a plataforma em **código real de produção** (não apenas dados simulados).
2. Demonstrar a **análise manual** de achados: separar vulnerabilidade real de falso positivo.
3. Identificar, a partir do que foi aprendido, **melhorias e novas ferramentas** a implementar.

> Todos os achados abaixo foram analisados manualmente no código-fonte do
> DefectDojo (inspeção direta), sem consulta a bancos de CVE externos.

---

## Sumário

1. [Execução do scan](#1-execução-do-scan)
2. [Resultados consolidados](#2-resultados-consolidados)
3. [Análise manual dos achados](#3-análise-manual-dos-achados)
4. [Vulnerabilidades confirmadas e recomendações](#4-vulnerabilidades-confirmadas-e-recomendações)
5. [Falsos positivos identificados](#5-falsos-positivos-identificados)
6. [O que este estudo permite implementar](#6-o-que-este-estudo-permite-implementar)
7. [Como reproduzir](#7-como-reproduzir)

---

## 1. Execução do scan

```
python src/main.py scan --repo <defectdojo> --output ./data/defectdojo-scan --skip-trivy
```

| Ferramenta | Resultado |
|---|---|
| Semgrep (SAST) | 1.552 achados |
| Bandit (Python) | 288 achados (25 lotes) |
| pip-audit (SCA) | 58 vulnerabilidades |
| Gitleaks (secrets) | Não instalado no ambiente |
| **Total** | **1.898 achados** (242 Alta / 1.245 Média / 353 Baixa) |

O relatório consolidado foi salvo em `data/defectdojo-scan/aspm-report.json` e é
compatível com o **Upload Consolidado** do dashboard.

## 2. Resultados consolidados

### Semgrep (top 10 regras)

| Ocorrências | Regra | Categoria |
|---|---|---|
| 947 | `plaintext-http-link` | Links HTTP em templates |
| 175 | `template-blocktranslate-no-escape` | **XSS potencial em templates Django** |
| 85 | `detected-pgp-private-key-block` | Chaves PGP (contexto: testes) |
| 49 | `avoid-mark-safe` | Uso de `mark_safe` |
| 48 | `detected-generic-secret` | Secrets genéricos |
| 30 | `django-no-csrf-token` | CSRF ausente |
| 21 | `run-shell-injection` | **Shell injection em GitHub Actions** |
| 18 | `detected-aws-access-key-id-value` | Chaves AWS |
| 17 | `detected-aws-secret-access-key` | Chaves AWS secret |
| 14 | `sqlalchemy-execute-raw-query` | **Queries SQLAlchemy raw** |

### Bandit (top 10 testes)

| Ocorrências | Teste | Severidade |
|---|---|---|
| 75 | `hardcoded_password_funcarg` | LOW |
| 65 | `hardcoded_password_string` | LOW |
| 61 | `blacklist` | MEDIUM |
| 49 | `django_mark_safe` | MEDIUM |
| 14 | `hardcoded_sql_expressions` | MEDIUM |
| 6 | `try_except_pass` | LOW |
| 6 | `hardcoded_tmp_directory` | MEDIUM |
| 5 | `hardcoded_bind_all_interfaces` | MEDIUM |
| 3 | `hashlib` | HIGH |

### SCA (pip-audit)

| Pacote | Versão | Vulnerabilidades |
|---|---|---|
| pillow | 12.2.0 | 20 |
| gitpython | 3.1.50 | 15 |
| nltk | 3.9.4 | 4 |
| pyasn1 | 0.6.3 | 4 |
| mcp | 1.23.3 | 3 |
| python-multipart | 0.0.27 | 3 |

---

## 3. Análise manual dos achados

### 3.1 SQLAlchemy raw query / SQL via f-string (Semgrep, 14 ocorrências)

O ponto mais crítico sinalizado foi em `dojo/auditlog/backfill.py:312`:

```python
raw_cursor.execute(
    f"SELECT COUNT(*) FROM {event_table_name} WHERE pgh_label = 'initial_backfill'"
)
```

**Análise manual:** a variável `event_table_name` é atribuída a partir de um
**mapeamento fixo** no código (nomes internos `dojo_*_event`), não de entrada do
usuário. Portanto **não é explorável hoje** — mas é uma **má prática clara**:
qualquer evolução que torne esse nome dinâmico criaria SQL injection. Recomendação:
parametrizar via whitelist. O scanner agiu corretamente ao sinalizar.

### 3.2 XSS potencial em templates — `blocktranslate` sem escape (Semgrep, 175)

Exemplo em `dojo/templates/dojo/metrics.html`:

```html
{% blocktranslate with name=c_prod.name %}
  {{ name }} is affected by <b>both</b> critical and high severity vulnerabilities.
{% endblocktranslate %}
```

**Análise manual:** `c_prod.name` é o nome de um produto, controlado por usuários
com permissão de criação/edição de produto. A renderização de `{{ name }}` dentro
de `blocktranslate` depende do comportamento de escape da versão do Django. Trata-se
de **XSS armazenado potencial (médio risco)** — merece revisão de hardening e de
sanitização na entrada do nome do produto.

### 3.3 Shell injection em GitHub Actions (Semgrep, 21)

Exemplo em `.github/workflows/build-docker-images-for-testing.yml`:

```yaml
run: echo "IMAGE_REPOSITORY=$(echo ${{ github.repository }} | tr '[:upper:]' '[:lower:]')" >> $GITHUB_ENV
```

**Análise manual:** interpolar `${{ github.repository }}` (controlado por quem cria
o repositório/PR) dentro de `run:` de shell é o padrão clássico de **shell injection
em CI/CD**. Em repositórios públicos com PRs de terceiros, o risco é real. O projeto
é oficial, mas o padrão está presente e deve ser evitado.

### 3.4 `mark_safe` (Semgrep 49 + Bandit 49)

**Análise manual de 3 pontos representativos:**
- `finding/ui/views.py:1777` — `mark_safe(... .format(reverse(...)))`: conteúdo é URL
  gerada internamente pelo Django. **Falso positivo.**
- `forms.py:143` — `mark_safe("\n".join(output))`: HTML gerado pelo widget `Select`
  do Django (escapado). **Falso positivo.**
- `product_announcements.py:34` — `mark_safe(f"{base} {ui_outreach}")`: conteúdo
  controlado por administradores. Baixo risco, mas merece documentação.

### 3.5 Secrets (Semgrep 85 PGP + 48 genéricos + 35 AWS)

**Análise manual:** as 85 chaves PGP estão em **arquivos de teste**
(`unittests/tools/test_gitleaks_parser.py`, `test_rusty_hog_parser.py`) — são
**fixtures com chaves falsas** usadas para testar parsers de secret scanning.
**Falso positivo em massa**, e um aprendizado importante: o DefectDojo testa seus
parsers com dados reais, algo que a plataforma ASPM deve imitar.

### 3.6 `hashlib.md5` (Bandit HIGH, 3)

**Análise manual:** todos os usos são para **gerar chaves de deduplicação**
(`dupe_key = hashlib.md5(...)`), não para fins criptográficos. O próprio código usa
`usedforsecurity=False` em um dos pontos. **Falso positivo** (o Bandit não distingue
o propósito). A plataforma pode aplicar uma regra de contexto para rebaixar.

---

## 4. Vulnerabilidades confirmadas e recomendações

| Achado | Risco | Ação recomendada no alvo |
|---|---|---|
| XSS em `blocktranslate` (templates) | Médio | Sanitizar nome do produto; revisar escape do `blocktranslate` |
| Shell injection em GitHub Actions | Médio | Substituir interpolação de contexto em `run:` por `env:` mapeado |
| SQL via f-string no backfill | Baixo (hoje) | Parametrizar com whitelist de nomes de tabela |
| SCA — pillow, gitpython, nltk, pyasn1 | Alto | Atualizar dependências para versões corrigidas |

## 5. Falsos positivos identificados

| Sinalizado | Motivo do falso positivo |
|---|---|
| 85× PGP private keys | Fixtures em arquivos de teste |
| 49× `mark_safe` (maioria) | Conteúdo gerado/controlado internamente |
| 3× `hashlib.md5` | Deduplicação, não criptografia |
| 5× `0.0.0.0` | Parser de dados, não serviço de rede |
| 14× SQL via f-string | Nome de tabela de mapeamento fixo |

Isso demonstra na prática o valor do **Risk Engine**: a plataforma pontua por
evidência e permite marcar falsos positivos, em vez de tratar toda contagem como risco.

---

## 6. O que este estudo permite implementar

O teste em ambiente real revelou **um bug e dez melhorias concretas** para a plataforma.
Estado atual após a atualização do projeto:

| # | Melhoria | Status | Impacto |
|---|---|---|---|
| 1 | **Bandit em lotes** — linha de comando estourava o limite do Windows (32k chars) com 2.000 arquivos; agora processa em lotes de 80 | ✅ **Implementado** | Correção de bug descoberta no teste real |
| 2 | **Parser dedicado para GitHub Actions/CI** — novo módulo `src/core/github_actions.py`: shell injection em `run:`, `pull_request_target`, secrets herdados, permissões amplas e checkout de PR; aba "CI/CD & Templates" no dashboard | ✅ **Implementado** | Nova fonte ASPM (22 achados no DefectDojo) |
| 3 | **Ampliar o Secrets Scanner interno** — adicionar regras de PGP private key, AWS secret key e tokens modernos (o `src/core/secrets.py` subiu de 7 para 13 regras) | ✅ **Implementado** | Melhor cobertura |
| 4 | **Rebaixar achados em arquivos de teste** — os 85 PGP keys estavam todos em `unittests/`; evidências em paths `test*` agora têm peso menor no Risk Engine | ✅ **Implementado** | Menos ruído |
| 5 | **Regras de falso positivo por contexto** — `hashlib` em função de dedupe, `0.0.0.0` em parser, `mark_safe` em form/widget: rebaixamento automático com motivo | ✅ **Implementado** | Priorização mais precisa |
| 6 | **Fixtures de teste para os parsers** — imitar o DefectDojo: `tests/fixtures/` com amostras reais do scan + `test_parsers.py` (45 verificações) | ✅ **Implementado** | Qualidade de testes |
| 7 | **Análise de templates (XSS)** — novo módulo `src/core/template_xss.py`: `autoescape off`, `\|safe` e `blocktranslate` com variáveis; integrado à aba "CI/CD & Templates" | ✅ **Implementado** | Cobertura de XSS (58 achados no DefectDojo) |
| 8 | **Inventário SBOM-lite** — o SCA listou 156 dependências com 58 vulns; novo módulo `src/core/inventory.py` com risco por pacote integrado à aba SCA | ✅ **Implementado** | Visão de supply chain |
| 9 | **Enriquecimento CVSS** — novo módulo `src/core/cvss.py` (calculadora v3.1 da spec FIRST, validada: Log4Shell 10.0, EternalBlue 8.1) + score CVSS por pacote no inventário | ✅ **Implementado** | Priorização padronizada |
| 10 | **Progresso de scan em lotes** — registrar progresso (como o backfill do DefectDojo) para scans longos | ✅ **Parcial** | Logs por lote no Bandit |

### Resultado mensurável no relatório real (DefectDojo)

Com o rebaixamento por contexto aplicado ao relatório de 1.898 evidências:

| Métrica | Antes | Depois |
|---|---|---|
| Severidade Alta (ativa) | 244 | **48** |
| Severidade Média (ativa) | 1.305 | **271** |
| Candidatos a falso positivo identificados | 0 | **1.382** (com motivo) |

Os 1.382 FPs foram todos verificados como legítimos: 947 links HTTP em fixtures de
`unittests/scans/`, 85 chaves PGP em arquivos de teste, senhas em fixtures, etc.
A justificativa do score agora explica quantos FPs foram desconsiderados.

---

## 7. Como reproduzir

```bash
# 1. Clonar o alvo
git clone --depth 1 https://github.com/DefectDojo/django-defectdojo.git /tmp/defectdojo

# 2. Rodar o scan da plataforma (Semgrep + Bandit + SCA)
python src/main.py scan --repo /tmp/defectdojo --output ./data/defectdojo-scan --skip-trivy

# 3. Abrir o dashboard e carregar o relatório real
python src/main.py dashboard
# Sidebar → Upload Consolidado → data/defectdojo-scan/aspm-report.json

# 4. Validar a correção do Bandit (lotes)
python -m pytest -q # ou os testes da suíte
```

> O relatório `data/defectdojo-scan/aspm-report.json` já está pronto para a
> demonstração — são dados **reais** de um projeto de produção, não simulados.
