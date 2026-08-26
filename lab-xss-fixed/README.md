# Laboratório XSS — Versão Corrigida

Versão endurecida do laboratório de XSS (`https://lab-xss.vercel.app`), com as
3 falhas corrigidas. Serve para demonstrar o **antes × depois** na apresentação
e para validar que o módulo "Testes Ofensivos" do ASPM não acusa mais achados.

## Falhas corrigidas

### 1. `index.html` — XSS Refletido via JavaScript (DOM)

**Antes (vulnerável):**
```javascript
const params = new URLSearchParams(window.location.search);
document.write(params.get("nome"));          // interpreta o valor como HTML
```

**Depois (corrigido):**
```javascript
const params = new URLSearchParams(window.location.search);
document.getElementById("nome").textContent = params.get("nome");  // texto puro
```

`document.write()` insere o valor como HTML — `?nome=<img src=x onerror=alert(1)>`
executa script. `textContent` nunca interpreta HTML.

### 2. `stored.html` — XSS Armazenado (client-side)

**Antes (vulnerável):**
```javascript
div.innerHTML = dados.join("<hr>");          // comentário vira HTML executável
```

**Depois (corrigido):**
```javascript
div.textContent = "";
dados.forEach(com => {
  const p = document.createElement("p");
  p.textContent = com;                       // cria elementos de texto
  div.appendChild(p);
});
```

O comentário armazenado (`<img src=x onerror=...>`) era renderizado como HTML.
Agora cada comentário é um elemento de texto — impossível injetar tags.

### 3. `dom.html` — XSS DOM-Based (fragmento `#`)

**Antes (vulnerável):**
```javascript
const hash = decodeURIComponent(location.hash.slice(1));
document.getElementById("saida").innerHTML = hash;   // fragmento vira HTML
```

**Depois (corrigido):**
```javascript
const hash = decodeURIComponent(location.hash.slice(1));
document.getElementById("saida").textContent = hash; // texto puro
```

O fragmento (`#<img src=x onerror=...>`) nunca chega ao servidor — por isso só
a análise estática do JavaScript (módulo XSS do ASPM) detecta esse tipo.

## Como validar

1. Suba esta pasta num host estático (ex.: Vercel) ou abra localmente.
2. Repita os PoCs que funcionavam na versão vulnerável — agora o conteúdo
   aparece como **texto literal**, sem executar:
   - `?nome=<img src=x onerror=alert(1)>` → exibe a tag como texto
   - comentário `<img src=x onerror=alert(1)>` → exibido como texto
   - `#<img src=x onerror=alert(1)>` → exibido como texto
3. No ASPM: aba "Testes Ofensivos" → módulo XSS contra a versão corrigida
   deve retornar **Controle OK** (nenhum sink de DOM alimentado por URL).
