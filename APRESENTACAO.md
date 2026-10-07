# Roteiro de Apresentação (Vídeo) — NightSync ASPM

**Requisito 04** — Demonstração e explicação das principais funcionalidades do ASPM.
**Duração alvo:** até 10 minutos (roteiro abaixo ≈ 8min30, com folga).

> Este documento é só para gravar. Não é necessário commitá-lo, mas ele fica no
> repositório como material de apoio da entrega.

---

## 0. Preparação (antes de gravar)

1. Feche outros programas pesados (o dashboard usa Streamlit).
2. Ative o ambiente virtual e gere os dados de demonstração **com seed fixa** (mesmos achados toda vez):
   ```powershell
   cd "C:\Trabalho Python"
   .\.venv\Scripts\Activate.ps1
   python src/main.py demo --seed 42
   ```
   Isso gera os dados e **abre o dashboard** em `http://localhost:8501`.
3. Faça login com **usuário `admin`** e senha **`admin`**.
4. Aumente o zoom do navegador (Ctrl + `+`) para o texto ficar legível no vídeo.
5. Deixe pronto numa segunda guia **o README no GitHub** (para mostrar a arquitetura/identidade).
6. Faça um teste cronometrado rápido (grave 30s e apague) para acertar a ordem das abas.

---

## 1. Roteiro cronometrado

### 0:00 – 0:45 · Introdução e problema
- Apresente o grupo (Felipe, Murilo, Lucas, Caio).
- O que é ASPM: centralizar achados de vários scanners, correlacionar evidências e priorizar risco.
- Mostre rapidamente o diagrama de fluxo no **README** (Scanners → Evidence → Correlation → Risk → IA → Dashboard).

**Fala sugerida:** *“Ferramentas de segurança geram relatórios isolados. Nosso ASPM normaliza, correlaciona e prioriza esses achados numa visão executiva única, com apoio de IA.”*

### 0:45 – 1:30 · Subindo a aplicação
- Mostre o terminal: `.\.venv\Scripts\Activate.ps1` e `python src/main.py demo --seed 42`.
- Explique: um comando gera os dados de demonstração e sobe o dashboard.
- Destaque a **tela de login** (autenticação com bcrypt e 3 perfis: Administrador, Analista, Visualizador).

### 1:30 – 2:45 · Resumo Executivo (o “coração” do ASPM)
- **Security Score**, total de evidências, correlações e classificação.
- Explique as **3 camadas**: Evidence Engine (normaliza), Correlation Engine (cruza ferramentas), Risk Engine (pontua).
- Mostre o card de **correlações** (ex.: “segredo exposto + achado SAST”) e as **categorias OWASP Top 10**.
- Mostre os **riscos prioritários** (top 5) com prioridade recalculada.

### 2:45 – 4:15 · Scanners + IA
- **Aba Semgrep (SAST):** mostre os achados com colunas **Explicação IA / Risco IA / Correção IA**.
  - **Fala-chave:** *“A IA lê cada achado (e o trecho de código) e classifica entre Vulnerabilidade, Hardening, Controle OK ou Falso Positivo, explicando em linguagem de negócio.”*
- **Aba Bandit:** mostre severidade/confiança e a explicação da IA.
- **Aba SCA:** CVEs de bibliotecas, **correção disponível**, inventário (SBOM-lite) e score **CVSS**.

### 4:15 – 5:15 · URL Analysis (análise passiva)
- Cole uma URL (ex.: `https://example.com`) e clique **Analisar URL**.
- Mostre: headers de segurança, HTTPS/TLS, WAF/CDN, cookies (Secure/HttpOnly/SameSite), JWT, subdomínios (crt.sh) e o crawler limitado.
- Destaque que cada achado tem **explicação pela IA** e que a análise é **passiva** (não invasiva).

### 5:15 – 6:00 · Attack Surface (baseada em evidência)
- Mostre que a superfície de ataque só marca algo como risco **com evidência real** (não porque `/admin` existe).
- Mostre os cards de **Endpoints, Achados Ativos, Melhorias e Falsos Positivos**.

### 6:00 – 6:45 · Secrets
- **Aba Secrets:** envie um arquivo (ou mostre o relatório do Gitleaks).
- Mostre o **mascaramento** do segredo (`AKIA***`) e a prioridade.
- Mencione as **13 regras internas** (AWS, GitHub, Google, Stripe, PGP, etc.).

### 6:45 – 7:30 · Testes Ofensivos (Laboratório)
- Explique o aviso de uso autorizado (Lei 12.737/2012) e o **checkbox de autorização**.
- Mostre os **11 módulos** (recon, IDOR, fuzzing, rate limit, CORS, HTTP methods, path traversal, open redirect, SQLi, XSS, credenciais).
- Destaque: **guarda anti-SSRF** bloqueia alvos internos fora do modo lab, e os testes são **limitados e não destrutivos**.
- *(Opcional)* Rode contra um alvo local de laboratório; se preferir não rodar ao vivo, mostre a tela e explique.

### 7:30 – 8:15 · Histórico e Relatórios
- **Aba Engagements & Scans:** histórico de scans por ativo e evolução do score.
- Gere/baixe o **Relatório executivo em PDF** (score, severidades, riscos prioritários e correlações) e o **CSV**.

### 8:15 – 9:00 · Administração e CI/CD
- **Aba Administração:** criação de usuários, perfis e registro de sessões de login.
- **Aba CI/CD & Templates:** análise estática de **GitHub Actions** (shell injection, `pull_request_target`, permissões) e de **templates (XSS)** (`autoescape off`, `|safe`).

### 9:00 – 9:30 · Conclusão e roadmap
- Recapitula o que o ASPM entrega: pipeline único, correlação, IA decisória, dashboard executivo.
- Cite diferenciais de engenharia: Evidence/Correlation/Risk Engine, fallback de IA offline, testes automatizados (`test_full_site.py`, `test_hardening.py`), segurança (bcrypt, anti-SSRF, contenção de path, escape de dados).
- Roadmap: API REST/Swagger, SBOM CycloneDX, notificações (Slack/E-mail), integração Nuclei/Nikto.

---

## 2. Checklist — o que o vídeo PRECISA mostrar

- [ ] Login e perfis de acesso
- [ ] Resumo Executivo (score, correlações, OWASP, riscos prioritários)
- [ ] Semgrep / Bandit / SCA com **explicação da IA**
- [ ] URL Analysis (passiva) com achados + IA
- [ ] Attack Surface baseada em evidência
- [ ] Secrets (mascaramento + regras)
- [ ] Testes Ofensivos (módulos + guarda anti-SSRF + aviso legal)
- [ ] Histórico/Engagements e **relatório PDF**
- [ ] Administração (usuários/sessões)
- [ ] CI/CD & Templates (GitHub Actions + XSS)
- [ ] Menção às 3 camadas (Evidence/Correlation/Risk)

---

## 3. Dicas de gravação

- Grave a tela inteira (1920×1080), cursor visível, áudio limpo.
- Fale devagar ao “narrar” os números do dashboard.
- Não abra 10 abas de uma vez; siga a ordem do roteiro para não se perder.
- Se um recurso exigir internet (DeepSeek, crt.sh), tenha o **fallback local de IA** em mente: sem chave, o dashboard continua funcionando — pode mencionar isso como robustez.

## 4. Plano B (se algo falhar ao vivo)

| Situação | Contorno |
|---|---|
| Sem `DEEPSEEK_API_KEY` | O fallback local assume; explique que é proposital (offline) |
| Semgrep falha no Windows (encoding) | Use o modo demo (não depende do Semgrep) |
| Sem internet para crt.sh/subdomínios | Desmarque “Incluir subdomínios” na aba URL Analysis |
| Dashboard não sobe | `python -m streamlit run dashboard/app.py` e faça upload do `data/aspm-report.json` |

---

## 5. Comandos de referência

```powershell
# Demonstração (recomendado para o vídeo)
python src/main.py demo --seed 42

# Dashboard vazio (upload manual do relatório)
python src/main.py dashboard
#  → Sidebar → Upload Consolidado → data/aspm-report.json

# Scan real de um repositório
python src/main.py scan --repo ./caminho/do-projeto
```

Projeto acadêmico — FIAP · Licença GPL-3.0-or-later (ver `LICENSE.md`).
