#  Roteiro de Apresentação — ASPM Enterprise

Passo a passo para a apresentação da FIAP. **Siga na ordem.** Cada bloco tem: comando, o que deve acontecer, o que falar e o que fazer se der errado.

---

## NA VÉSPERA (10 min)

1. Rode a verificação rápida (deve sair `TODOS OS TESTES PASSARAM`):

```bash
python test_dashboard_smoke.py
```

2. Regere os dados de demonstração com seed fixo (para a demo ficar igual ao ensaio):

```bash
python src/generate_demo_data.py --seed 42
```

3. Ensaie a apresentação 1 vez inteira (10 min):
   - Abra o site com `python src/main.py demo --seed 42`
   - Login `admin` / `admin`
   - Clique em todas as abas, baixe o PDF
4. Confirme que o `.env` tem a chave do DeepSeek (sem abrir o arquivo na tela!):

```bash
python -c "from dotenv import load_dotenv; load_dotenv(); import os; print('chave configurada' if os.getenv('DEEPSEEK_API_KEY') else 'SEM CHAVE')"
```

5. Feche todos os terminais e janelas com Streamlit abertos (para liberar a porta 8501).

---

##  DIA DA APRESENTAÇÃO — ROTEIRO (≈ 30–40 min)

### ETAPA 0 — Abrir o projeto (2 min)

Abra o terminal na pasta do projeto e confirme o ambiente:

```bash
python -c "import streamlit, pandas, reportlab; print('ambiente OK')"
```

> Se der erro de módulo: `pip install -r requirements.txt`

---

### ETAPA 1 — Subir o site com os dados de demonstração (2 min)

```bash
python src/main.py demo --seed 42
```

- O terminal mostra os achados gerados e o navegador abre o dashboard.
- **Este terminal fica aberto durante toda a apresentação** (é o servidor).
- Se o navegador não abrir sozinho: digite `http://localhost:8501` manualmente.
- Login: **`admin`** / **`admin`** (credenciais padrão, fale isso para a banca).

> **FALLBACK** — se o site não abrir ou der erro:
> ```bash
> python -m streamlit run dashboard/app.py
> ```
> E depois, na sidebar, use **Upload Consolidado** → selecione `data/demo/aspm-report.json`.

**O que falar:** *"Este é o ASPM — plataforma de postura de segurança de aplicações. Centraliza Semgrep, Bandit, SCA, segredos e análise de URL em uma visão executiva, com IA e correlação de riscos."*

---

### ETAPA 2 — Resumo Executivo (5 min) ← mais importante

Fique na aba **Resumo Executivo** e aponte, de cima para baixo:

1. **Score Geral / Postura** (cards do topo) — *"Score consolidado de segurança"*
2. **Cards de Fontes** (Semgrep, Bandit, SCA, URL) — *"cada ferramenta integrada"*
3. **Donuts** (severidade + cobertura) — *"distribuição de riscos"*
4. **Correlação de Riscos** — *"o diferencial: cruza achados de ferramentas diferentes; segredo + SQLi = risco maior"*
5. **Risk Engine Consolidado** — cards: Security Score, Evidências, Correlações
6. **Categorias OWASP Top 10** (cards roxos) — *"cada achado mapeado para o OWASP Top 10:2025 — A03 Injection, A06 Componentes Vulneráveis..."*
7. **Riscos Prioritários** — *"priorização por evidência, não por quantidade"*
8. **Baixar Relatório Executivo (PDF)** — clique e mostre o PDF

**O que falar:** *"O sistema não soma alertas: pontua cada evidência, reduz peso de falsos positivos e eleva prioridade quando várias fontes apontam o mesmo risco."*

> **FALLBACK** — se o Risk Engine não aparecer, role até o fim e use o **Upload Consolidado** na sidebar (selecionar `data/demo/aspm-report.json`).

---

### ETAPA 3 — Abas das ferramentas (5 min)

Vá em cada aba e mostre **1–2 achados** (não precisa mostrar tudo):

| Aba | O que mostrar | Clicar em |
|---|---|---|
| **Semgrep** | 1 card de achado (ex: eval-usage) | expander do achado → **Explicação IA / Risco IA / Correção IA** |
| **Bandit** | 1 achado (ex: B608 SQLi) | expander → explicação IA |
| **SCA** | CVE com correção disponível | expander → fix_versions |
| **Secrets** | segredo mascarado | cards → mostrar que está **mascarado** (`AKIA***...`) |

**O que falar:** *"Cada achado tem explicação da IA que diferencia vulnerabilidade real, hardening, controle OK e falso positivo."*

> Se a IA não responder (sem internet/chave), ela usa o **fallback local** automaticamente — o dashboard continua funcionando.

---

### ETAPA 4 — URL Analysis ao vivo (opcional, 5 min)

Na aba **URL Analysis**:

1. Cole uma URL (sugestão: `https://www.betano.bet.br` — análise **passiva**, igual abrir no navegador)
2. Clique em **Analisar URL**
3. Mostre: score, cards (Achados Ativos / Melhorias / Controles OK), donuts
4. Vá em **Attack Surface** e mostre: **WAF detectado (Cloudflare)**, **headers de segurança**, **cookies** (Secure/HttpOnly/SameSite), **subdomínios** (crt.sh), **páginas do crawl**

**O que falar:** *"Análise baseada em evidências: /api exposto sem dado sensível vira melhoria recomendada, não vulnerabilidade. Só marcamos achado com evidência real."*

> Se a rede estiver lenta, desmarque **"Subdomínios (crt.sh)"** e **"Crawl"** nos checkboxes e clique de novo.

---

### ETAPA 5 — Testes Ofensivos (opcional, 5 min) ⚠️ LAB SOMENTE

**NUNCA usar contra site de terceiros.** Só se tiver um alvo de laboratório (DVWA, Juice Shop local):

```bash
# Se tiver DVWA/Juice Shop rodando local, exemplo:
python src/main.py attack --url http://localhost:8080 --modules recon,idor,fuzz,rate,cors,methods,traversal,redirect
```

Ou mostre a aba **Testes Ofensivos (Lab)**:
1. Marque **"Confirmo que tenho autorização"**
2. URL do alvo de laboratório
3. Módulos: os 8 disponíveis (Recon, IDOR, API Fuzzing, Rate Limit, **CORS**, **HTTP Methods/TRACE**, **Path Traversal**, **Open Redirect**)
4. **Executar testes** → mostre os cards

**O que falar:** *"Oito módulos de teste ativo com trava de autorização — uso exclusivo em laboratório. Ferramentas legítimas, como Burp/ZAP, com limites e sem ações destrutivas: CORS, TRACE, path traversal e open redirect são os clássicos que o OWASP Top 10 cobre."*

> Se não tiver alvo de lab, **pule esta etapa** — não é obrigatória.

---

### ETAPA 6 — Engagements & Scans + Administração (5 min)

**Engagements & Scans:**
- Mostre o histórico registrado (o upload demo já gravou um scan)
- Filtro por ativo + **Evolução do Score** (gráfico de linha)

**Administração** (prova de controle de acesso):
1. **Criar usuário**: crie um perfil `analista` (mostre os 3 perfis no selectbox)
2. **Lista de usuários**: mostre a tabela
3. **Sessões registradas**: expander → mostra logins com data
4. **Memória da IA**: expander → mostra as análises da IA persistidas

**O que falar:** *"Histórico vinculado ao usuário — admin vê tudo, analista vê o próprio. Reset de histórico é exclusivo do administrador. A memória da IA registra cada análise feita."*

---

### ETAPA 7 — Encerramento (2 min)

- Volte ao **Resumo Executivo**
- **O que falar:** *"O projeto integra o fluxo ASPM completo: scan → evidências → correlação → priorização com IA → relatório executivo. Baseado em OWASP SAMM, Top 10:2025 e SCVS. Evolução futura: API REST com Swagger para CI/CD."*

---

##  FALLBACKS RÁPIDOS (se algo falhar)

| Problema | Solução |
|---|---|
| Site não abre | `python -m streamlit run dashboard/app.py` e abra `http://localhost:8501` |
| Login não funciona | Credenciais padrão `admin`/`admin`. Se apagaram o banco: excluir `data/history.db` e reiniciar (recria o admin) |
| Dados demo não aparecem | Sidebar → **Upload Consolidado** → `data/demo/aspm-report.json` |
| Demo sumiu / quer regenerar | `python src/generate_demo_data.py --seed 42` (gera em 1s, sem abrir site) |
| IA não responde | Sem problema — fallback local assume; o dashboard não quebra |
| Semgrep falha no Windows (bug conhecido) | Use o **demo** (não depende do Semgrep) |
| Esqueceu a senha de um usuário | Excluir `data/history.db` e reiniciar (volta admin/admin) |

---

##  LEMBRETES IMPORTANTES

- O terminal da **ETAPA 1 fica aberto** até o fim (é o servidor). Não feche.
- **Não mostre o `.env`** na tela em nenhum momento (tem a chave da API).
- Testes ofensivos: **somente laboratório autorizado**. Nunca o Betano ou terceiros.
- Os módulos de ataque são ferramentas de teste (Burp/ZAP) — se a banca perguntar, explique a trava de autorização.
- Termine sempre no **Resumo Executivo** com o **PDF baixado** — é a imagem final que fica na memória.
