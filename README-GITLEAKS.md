# Gitleaks — Guia de Uso e Integração

O **Gitleaks** é a ferramenta de detecção de segredos integrada à plataforma
ASPM. Ele escaneia o repositório em busca de chaves, tokens e credenciais
vazadas, e o resultado pode ser importado no dashboard (aba **Secrets**).

---

## 1. Instalação

O Gitleaks **não é uma biblioteca Python** — é um binário. Instale conforme
seu sistema:

| Sistema | Comando |
|---|---|
| macOS | `brew install gitleaks` |
| Linux | `curl -sSfL https://github.com/gitleaks/gitleaks/releases/latest/download/gitleaks-linux-amd64 -o /usr/local/bin/gitleaks && chmod +x /usr/local/bin/gitleaks` |
| Windows | Baixe o binário em https://github.com/gitleaks/gitleaks/releases (arquivo `gitleaks-windows-amd64.zip`), extraia e adicione ao PATH |

Confirme a instalação:

```bash
gitleaks version
```

> O orquestrador da plataforma detecta a ausência do Gitleaks e **continua o
> scan normalmente** com as demais ferramentas.

---

## 2. Uso direto (linha de comando)

### Scan de um repositório (sem histórico git)

```bash
gitleaks detect --source ./meu-projeto --report-format json --no-git -v
```

- `--no-git` escaneia os arquivos atuais (mais rápido, não precisa do histórico).
- `--report-format json` gera saída JSON (formato aceito pelo dashboard).
- `-v` (verbose) inclui o segredo no relatório (para análise; o dashboard mascara).

### Scan completo com histórico git

```bash
gitleaks detect --source ./meu-projeto --report-format json
```

### Gerar arquivo de relatório

```bash
gitleaks detect --source ./meu-projeto --report-format json --report-path gitleaks.json
```

---

## 3. Integração com a plataforma ASPM

### Opção A — Scan orquestrado (recomendado)

O `src/orchestrator.py` executa o Gitleaks automaticamente durante o scan:

```bash
python src/main.py scan --repo ./meu-projeto
```

O resultado é salvo em `data/gitleaks.json` e consolidado no
`aspm-report.json` (que o dashboard carrega via **Upload Consolidado**).

### Opção B — Importação manual no dashboard

1. Gere o JSON: `gitleaks detect --source ./meu-projeto --report-format json`
2. No dashboard, abra a aba **Secrets Scanner**.
3. Em **"Enviar relatório JSON do Gitleaks"**, selecione o arquivo.

A plataforma normaliza os achados, **mascara os segredos** (ex.: `AKIA***...`)
e os adiciona ao Risk Engine.

### Opção C — Upload de arquivos direto

Na aba **Secrets**, envie arquivos do projeto (`.py`, `.env`, `.yaml`, etc.)
diretamente — o scanner interno da plataforma (13 regras) processa na hora,
sem depender do Gitleaks.

---

## 4. O que a plataforma faz com os achados do Gitleaks

| Etapa | Comportamento |
|---|---|
| **Normalização** | Converte cada achado no formato padrão do Evidence Engine |
| **Mascaramento** | Segredos exibidos parcialmente (`AKIA***...`) |
| **JWT** | Se o segredo for JWT, analisa header/payload (alg=none, sem exp, claims) |
| **Risco** | Alimenta o Risk Engine com severidade Alta |
| **Contexto** | Achados em arquivos de teste/fixture recebem peso reduzido |
| **OWASP** | Mapeados para A02 (Cryptographic Failures) |

### Regras internas de detecção (além do Gitleaks)

O scanner interno da plataforma (`src/core/secrets.py`) cobre 13 padrões:

| Regra | Exemplo |
|---|---|
| AWS Access Key ID | `AKIA...` |
| AWS Secret Access Key | `aws_secret_access_key = "..."` (40 chars) |
| GitHub Token | `ghp_...` |
| GitHub Fine-grained | `github_pat_...` |
| Google API Key | `AIza...` |
| Stripe Secret | `sk_live_...` |
| Slack Token | `xoxb-...` |
| npm Token | `npm_...` |
| PyPI Token | `pypi-AgEIcHlwaS5vcmc...` |
| Chaves privadas | `BEGIN (RSA/OPENSSH/EC/DSA/PGP) PRIVATE KEY` |
| Segredos genéricos | `password = "..."`, `api_key = "..."` |
| Connection strings | `postgres://`, `mysql://` |
| JWT | `eyJ...` |

---

## 5. Dicas

- **Nunca commite o `.env`** — a plataforma detecta, mas a prevenção é melhor.
- Use `gitleaks detect` em **pre-commit** ou no CI (o workflow do projeto já
  instala o Gitleaks e o executa no scan).
- Segredos em arquivos de **teste/fixture** são sinalizados pela plataforma
  como candidatos a falso positivo (aprendizado do estudo DefectDojo).

---

## Referência rápida

| Comando | Efeito |
|---|---|
| `gitleaks detect --source ./repo --report-format json` | Scan de segredos |
| `python src/main.py scan --repo ./repo` | Scan completo (inclui Gitleaks) |
| Dashboard → Secrets → upload JSON | Importa relatório do Gitleaks |
