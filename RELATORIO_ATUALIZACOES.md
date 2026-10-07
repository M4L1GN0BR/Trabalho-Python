# Relatório de Atualizações — NightSync ASPM

**Período:** da criação das demos (`4630294`, 19/08/2026) até a entrega (`d26cd51`, 06/10/2026)
**Repositório:** https://github.com/M4L1GN0BR/Trabalho-Python
**Branches sincronizados:** `main` e `master` (mesmo commit)

Grupo: Felipe Barbosa Alves (RM570378) · Murilo Garcia Godoy (RM564840) · Lucas Moura Gonçalves de Amorim (RM570161) · Caio de Paula Goes (RM569052)

---

## 1. Linha do tempo (commits)

| Commit | Data | Descrição |
|---|---|---|
| `4630294` | 19/08 | Atualização do código — **marco inicial das demos** (`data/demo/`) |
| `ee9a6e7` | 23/08 | Adiciona análises passivas (URL) e módulos ofensivos |
| `4abcb91` | 23/08 | Adiciona módulos de SQLi, XSS e credenciais |
| `63f750a` | 26/08 | Hardening do dashboard, IA, CVSS e módulos ofensivos |
| `2dc15df` | 26/08 | Correção do fallback de IA em pt-BR e shutdown gracioso |
| `31484a6` | 26/08 | Generaliza detecção de ataques e fortalece o dashboard |
| `5464280` | 01/10 | Consolida a documentação e adiciona a identidade visual NightSync |
| `d63b870` | 03/10 | **Correção do layout do relatório PDF** e robustez de inicialização |
| `5dd6727` | 06/10 | **Licença GPL-3.0** + cabeçalho de licenciamento nos arquivos |
| `1a1ece9` | 06/10 | Higiene: ignora `.zip` gerados |
| `0555573` | 06/10 | **Correção das abas por perfil** + teste de ponta a ponta do site |
| `ffe0792` | 06/10 | **Robustez dos parsers** a relatório nulo + bateria de segurança |
| `34f714f` | 06/10 | Integrantes do grupo no README |
| `d26cd51` | 06/10 | Roteiro de apresentação (requisito 04) |

> Os commits de `d63b870` a `d26cd51` são as entregas finais de correção, licenciamento, testes e documentação.

---

## 2. Atualizações por área

### 2.1 Licenciamento (requisito 00) — `5dd6727`
- Criação do **`LICENSE.md`** com o texto integral da **GNU GPL v3.0**.
- Cabeçalho de licenciamento + `SPDX-License-Identifier: GPL-3.0-or-later` aplicado em **61 arquivos-fonte** (`.py`, `.html`, `.css`, `.bat`, workflow `.yml`).
- README: badge de licença e seção "Licença" com os autores.

### 2.2 Correção do relatório PDF — `d63b870`
- `dashboard/reports.py` reescrito para usar **`LongTable`** com:
  - células como `Paragraph` com **escape de HTML** e **truncamento**;
  - `wordWrap="CJK"` para quebrar tokens longos (caminhos, URLs, IDs);
  - **largura de colunas proporcional** — resolve tabelas que estouravam a página em relatórios grandes (ex.: descrições de milhares de caracteres).

### 2.3 Correção de abas por perfil (bug real) — `0555573`
- **Problema:** `st.stop()` dentro dos guards de permissão em `dashboard/tabs.py` interrompia **o site inteiro**, então no perfil **Visualizador** as abas após "URL Analysis" não renderizavam.
- **Correção:** os 6 `st.stop()` trocados por `return` (interrompe só a aba, não o site).

### 2.4 Robustez a dados malformados — `ffe0792`
- **Problema:** um relatório com `"results": null` (ou `"extra": null`, `"start": null`, `"dependencies": null`) derrubava o dashboard inteiro com `TypeError: 'NoneType' object is not iterable`.
- **Correção:** `dashboard/parsers.py` e `src/core/evidence.py` passaram a tratar valores nulos e itens não-dicionário.

### 2.5 Inicialização do dashboard e modo demo — `d63b870`
- `dashboard/app.py`: adiciona a raiz do projeto ao `sys.path` (imports funcionam em qualquer forma de execução).
- Auto-carregamento do demo agora **só** com `ASPM_AUTO_DEMO=1` — um `streamlit run` comum **sobe vazio** (as demos continuam funcionando em `python src/main.py demo` e `run_defectdojo.py`).

### 2.6 Segurança (IA e dados)
- **Fallback local de IA** mantém o dashboard operacional sem chave/offline (DeepSeek quando configurado).
- Escape de HTML antes de `unsafe_allow_html`, **contenção de path**, **guarda anti-SSRF** e **mascaramento de segredos** — validados por testes.

### 2.7 Testes automatizados (novos)
- **`test_full_site.py`** (`0555573`): ponta a ponta com **dados reais**, cobrindo núcleo de risco, PDF, auth/banco, URL Analysis e as **11 abas** para os 3 perfis — **47/47**.
- **`test_hardening.py`** (`ffe0792`): robustez a dados malformados + **path traversal, SSRF, SQLi, bcrypt, mascaramento de segredos e XSS** — **41/41**.

### 2.8 Documentação e apresentação
- `5464280` consolidou o README e adicionou a identidade visual NightSync.
- `34f714f` adicionou os **integrantes do grupo** (topo do README + seção com tabela de RMs).
- `d26cd51` adicionou **`APRESENTACAO.md`**: roteiro cronometrado (≤10 min) das funcionalidades para o vídeo (requisito 04).

### 2.9 Higiene do repositório — `1a1ece9`
- `.gitignore` passa a ignorar `*.zip` (deliveráveis gerados).
- Remoção do `.env` antigo do histórico local; repositório sem segredos versionados (só `.env.example`).
- `main` e `master` mantidos idênticos.

---

## 3. Validação (resultados dos testes)

| Suíte | Resultado |
|---|---|
| `test_parsers.py` | 45/45 |
| `test_full_site.py` | 47/47 |
| `test_hardening.py` | 41/41 |
| `test_dashboard_smoke.py` | OK (todas as abas) |
| `test_apresentacao.py` | OK (fluxo demo) |
| `test_attack.py` | OK (11 módulos ofensivos) |
| `compileall` (`src/`, `dashboard/`) | Sem erros |

---

## 4. Estado final

- **Branches:** `main` e `master` em `d26cd51` (idênticos, no `origin`).
- **Licença:** GPL-3.0 (`LICENSE.md`) + cabeçalhos nos fontes.
- **Sem segredos** na árvore versionada (`.env` fora do Git).
- **Requisitos:** 00 (licença) ✅ · 01 (código + repo) ✅ · 02 (demo/IA documentada) ✅ · 04 (roteiro do vídeo) ✅.

---

## 5. Roadmap (próximos passos sugeridos)

- API REST com documentação Swagger/OpenAPI para integração CI/CD.
- Reativar o CI (`.github/workflows/aspm-scan.yml.disabled`) e a aba de Assets.
- SBOM no formato CycloneDX; notificações Slack/E-mail.
- Ampliar a suíte de testes com `pytest` e fixar versões no `requirements.txt`.
- Integração com ferramentas externas (Nuclei, Nikto).

Projeto acadêmico — FIAP · Licença GPL-3.0-or-later (ver `LICENSE.md`).
