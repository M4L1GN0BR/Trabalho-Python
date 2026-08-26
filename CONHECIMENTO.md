# CONHECIMENTO.md — Aprendizados e decisões de código

Registro do conhecimento adquirido ao longo do desenvolvimento e dos testes
dos laboratórios. Serve de referência para o time e para a apresentação.

---

## 1. XSS — Tipos e como o detector os encontra

| Tipo | Onde acontece | Como o ASPM detecta | Exemplo real |
|------|---------------|---------------------|--------------|
| Refletido (servidor) | O servidor ecoa o valor sem escape | Envio de marcadores `ASPMXSSMARKER` em parâmetros (GET/POST) | — |
| Refletido via JavaScript (DOM) | O browser lê a URL (`URLSearchParams`/`location.search`) e escreve no DOM | Análise estática: sink (`document.write`/`innerHTML`) alimentado por fonte de URL na mesma expressão | `lab-xss/index.html` (`document.write(params.get("nome"))`) |
| Armazenado (client-side) | Dado do `localStorage`/`sessionStorage` vira `innerHTML` sem escape | Variável que recebe dados do storage e vira conteúdo do sink (`var.join(...)`) | `lab-xss/stored.html` |
| DOM-Based (fragmento `#`) | `location.hash` → `innerHTML` | Variável de `location.hash` vira conteúdo do sink | `lab-xss/dom.html` |
| Refletido via parâmetro → `innerHTML` | `?cart=` → `JSON.parse` → `items.map(...)` no `innerHTML` | Taint de 2º salto: variável com dado de URL usada como conteúdo do sink (`var.map(...)` / `${var}`) | `puffpod.com.br/checkout.html` |

**Regra anti-falso-positivo:** a variável precisa virar **conteúdo** do sink
(`${var}`, `var.map(`, `var.join(`, ou o RHS começar com a var). Aparecer só em
filtro/comparação (`x.uid == id`) NÃO é XSS (lição do NovaMart `orders.html`).

**Comentários JS são ignorados** na análise (`// document.write(...)` documentado
não é sink real).

## 2. Lições práticas de scanning

- **Sites estáticos (Vercel) respondem `308`**: o scanner precisa seguir
  redirects (`allow_redirects=True`) para ler o conteúdo real — sem isso, lê a
  página "Redirecting..." e perde tudo (lição do NovaMart).
- **Descoberta de parâmetros**: usar `name` E `id` de inputs (`<input id="q">`
  sem `name` é comum em páginas com JS), formulários `method=POST` e padrões
  `.get("x")` do JavaScript.
- **Regex de taint não pode cruzar vírgulas**: em `me=...,id=URLSearchParams(...)`,
  a captura de `me` engolia o `id` (lição do NovaMart `account.html`).

## 3. Segurança client-side (falhas comuns em sites de treinamento)

- **Credenciais hardcoded no JS**: `users={admin:{password:"admin123",...}}` —
  qualquer um lê o código-fonte. Detector: padrão `password:"..."` literal.
  Ex.: `testevercel-rosy.vercel.app/login.html`.
- **Controle de acesso só no cliente**: `if(u.role!=="admin")` com dados do
  `localStorage` — basta editar o storage no console. Detector: `localStorage`
  + comparação de `.role`. Ex.: `testevercel-rosy.vercel.app/admin.html`.

## 4. IA / idioma

- O modelo DeepSeek às vezes responde em inglês mesmo com prompt pt-BR:
  - **Retry** com reforço "responda em português";
  - **Checagem por seção** (`EXPLICACAO`/`RISCO`/`CORRECAO`): seção em inglês cai
    para o fallback local;
  - **Fallback não ecoa mensagem original sem tradução** — usa texto pt-BR
    genérico e heurísticas de risco/correção por palavras-chave.
- Traduções pt-BR do Semgrep vivem em `src/core/mensagens_pt.py` (famílias
  `package_managers.dependabot`/`renovate` incluídas).

## 5. Segurança do dashboard (aplicado)

- **Containment de path**: snippets de código só são lidos dentro da raiz do
  repositório (paths absolutos e `..` rejeitados) antes de ir à API.
- **SSRF**: `src/core/target_guard.py` bloqueia IPs privados/loopback/link-local
  no dashboard (com checkbox explícito para laboratórios locais).
- **XSS no dashboard**: todo dado externo é escapado antes de `unsafe_allow_html`.
- **Perfil admin**: achados de ruído (Controle OK / Falso Positivo / Inconclusivo)
  aparecem apenas para Administrador.

## 6. Laboratórios criados

- `lab-xss-fixed/` — versão corrigida do lab de XSS (document.write → textContent;
  innerHTML → createElement; hash → textContent), com README antes/depois.

## 7. Pendências conhecidas (não resolvidas)

- TLS `verify` configurável nos módulos de ataque (lab com certificado
  autoassinado falha silencioso).
- CI do GitHub Actions desabilitado (`.github/workflows/aspm-scan.yml.disabled`).
- `requirements.txt` sem pin de versões; `tabs.py` com ~1.900 linhas (refactor).
- Versão corrigida do NovaMart (login server-side, sem creds hardcoded) — pendente.
