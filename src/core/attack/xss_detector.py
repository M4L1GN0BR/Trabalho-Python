# NightSync - ASPM (Application Security Posture Management)
# Copyright (C) 2026 Felipe Barbosa Alves (RM570378),
#                    Murilo Garcia Godoy (RM564840),
#                    Lucas Moura Goncalves de Amorim (RM570161),
#                    Caio de Paula Goes (RM569052)
#
# This file is part of NightSync, free software under the GNU General
# Public License as published by the Free Software Foundation, either
# version 3 of the License, or (at your option) any later version.
#
# NightSync is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""
Detector de XSS — refletido, DOM-based e armazenado (client-side).

Somente uso autorizado. Envia marcadores inofensivos (com e sem tags HTML) e
verifica reflexo na resposta; também DESCOBRE parâmetros de formulários/JS da
página e analisa estaticamente os <script> em busca de sinks de DOM
(document.write/innerHTML) alimentados por fontes controláveis (URL, hash,
localStorage, cookie). NÃO rouba cookies, NÃO executa payloads destrutivos e
NÃO usa exploração real.
"""

import re
from urllib.parse import urljoin, urlparse

import requests

HEADERS = {"User-Agent": "ASPM-Scanner/1.0"}

MARKER = "ASPMXSSMARKER"

XSS_PAYLOADS = [
    MARKER,
    f"<b>{MARKER}</b>",
    f'\"><b>{MARKER}</b>',
    f"'><svg/onload={MARKER}>",
]

# ── Descoberta de parâmetros ──────────────────────────────────────────────
_PARAM_RE = [
    re.compile(r"<input[^>]*\bname=\"([^\"]+)\"", re.I),
    re.compile(r"<textarea[^>]*\bname=\"([^\"]+)\"", re.I),
    re.compile(r"<select[^>]*\bname=\"([^\"]+)\"", re.I),
    re.compile(r"\.get\(\s*[\"']([^\"']+)[\"']\s*\)"),  # JS: params.get("x")
    # Lição NovaMart: inputs sem `name` usam `id` (ex.: <input id="q">) e são
    # lidos via getElementById — o `id` também pode ser um parâmetro real.
    re.compile(r"<input[^>]*\bid=\"([^\"]+)\"", re.I),
]

_POST_FORM_RE = re.compile(
    r"<form[^>]*method\s*=\s*[\"']post[\"'][^>]*>(.*?)</form>", re.I | re.S
)

MAX_PARAMS = 10


def _discover_params(html):
    """Extrai nomes de parâmetros de formulários e de JS (URLSearchParams/location)."""
    params = []
    for rx in _PARAM_RE:
        for m in rx.finditer(html or ""):
            p = m.group(1).strip()
            if p and p not in params:
                params.append(p)
    return params[:MAX_PARAMS]


def _discover_post_params(html):
    """Nomes de inputs dentro de formulários method=POST."""
    params = []
    for m in _POST_FORM_RE.finditer(html or ""):
        for rx in _PARAM_RE[:3]:
            for im in rx.finditer(m.group(1)):
                p = im.group(1).strip()
                if p and p not in params:
                    params.append(p)
    return params[:MAX_PARAMS]


def xss_detection_test(url, param="q", timeout=5):
    """
    Testa reflexo de marcadores em parâmetros (GET e POST).

    Além do parâmetro informado, testa automaticamente os parâmetros
    descobertos na página: inputs (name E id), selects, textareas, padrões
    params.get(...) do JS e formulários method=POST.

    Retorna lista de dicts {"method", "param", "payload", "status",
    "refletido", "refletido_sem_encoding"}.
    """
    out = []
    params_get = [param] if param else []
    params_post = []

    # Descobre parâmetros reais da página (uma requisição extra, no máximo)
    try:
        r0 = requests.get(url, headers=HEADERS, timeout=timeout, allow_redirects=True)
        html0 = r0.text
        for p in _discover_params(html0):
            if p not in params_get:
                params_get.append(p)
        params_post = _discover_post_params(html0)
    except Exception:
        html0 = ""

    for p in params_get:
        for payload in XSS_PAYLOADS:
            try:
                r = requests.get(
                    url,
                    params={p: payload},
                    headers=HEADERS,
                    timeout=timeout,
                    allow_redirects=True,
                )
                body = r.text[:5000]
                out.append(
                    {
                        "method": "GET",
                        "param": p,
                        "payload": payload,
                        "status": r.status_code,
                        "refletido": MARKER in body,
                        "refletido_sem_encoding": (
                            f"<b>{MARKER}</b>" in body
                            or ("<svg" in body.lower() and MARKER in body)
                        ),
                    }
                )
            except Exception:
                out.append(
                    {
                        "method": "GET",
                        "param": p,
                        "payload": payload,
                        "status": "erro",
                        "refletido": False,
                        "refletido_sem_encoding": False,
                    }
                )

    for p in params_post:
        for payload in XSS_PAYLOADS:
            try:
                r = requests.post(
                    url,
                    data={p: payload},
                    headers=HEADERS,
                    timeout=timeout,
                    allow_redirects=True,
                )
                body = r.text[:5000]
                out.append(
                    {
                        "method": "POST",
                        "param": p,
                        "payload": payload,
                        "status": r.status_code,
                        "refletido": MARKER in body,
                        "refletido_sem_encoding": (
                            f"<b>{MARKER}</b>" in body
                            or ("<svg" in body.lower() and MARKER in body)
                        ),
                    }
                )
            except Exception:
                out.append(
                    {
                        "method": "POST",
                        "param": p,
                        "payload": payload,
                        "status": "erro",
                        "refletido": False,
                        "refletido_sem_encoding": False,
                    }
                )
    return out


# ── Análise estática de DOM XSS ───────────────────────────────────────────
_DOM_SINKS = (
    "document.write",
    "innerHTML",
    "outerHTML",
    "insertAdjacentHTML",
    "eval(",
    "srcdoc",
)

# fonte → (tipo legível, descrição da evidência)
_DOM_SOURCES = (
    ("location.hash", ("DOM-based (fragmento #)", "localizador de fragmento (#) alimenta sink de DOM")),
    ("URLSearchParams", ("Refletido via JavaScript (DOM)", "parâmetro de URL (URLSearchParams) alimenta sink de DOM")),
    ("params.get", ("Refletido via JavaScript (DOM)", "parâmetro de URL (params.get) alimenta sink de DOM")),
    ("location.search", ("Refletido via JavaScript (DOM)", "parâmetro de URL (location.search) alimenta sink de DOM")),
    ("window.location", ("Refletido via JavaScript (DOM)", "URL da página alimenta sink de DOM")),
    ("localStorage", ("Armazenado (client-side)", "dados do localStorage alimentam sink de DOM")),
    ("sessionStorage", ("Armazenado (client-side)", "dados do sessionStorage alimentam sink de DOM")),
    ("document.cookie", ("Baseado em cookie", "cookie alimenta sink de DOM")),
)

# Distância máxima (em caracteres) entre a fonte e o sink dentro do script.
# Em bundles grandes (ex.: e-commerce), a fonte e o sink podem coexistir no
# mesmo <script> sem nenhuma relação — a proximidade evita o falso positivo.
_DOM_PROXIMITY = 500

_DOM_SINK_RE = re.compile("|".join(re.escape(s) for s in _DOM_SINKS))
_DOM_SOURCE_RE = {
    name: re.compile(re.escape(name)) for name, _ in _DOM_SOURCES
}

# Atribuições de sink: <el>.innerHTML = <expr> / document.write(<expr>)
_SINK_ASSIGN_RE = re.compile(r"\.(?:innerHTML|outerHTML)\s*=\s*[^;]{0,150}")


def _strip_js_comments(script):
    """
    Remove comentários // e /* */ do JavaScript antes da análise.

    Código antigo/vulnerável documentado em comentário (ex.: "// document.write("
    ...) não é sink real e gerava falso positivo. Strings são protegidas para
    não confundir "//" dentro de literais (ex.: URLs).
    """
    strings = []

    def _keep(m):
        strings.append(m.group(0))
        return f"\x00{len(strings) - 1}\x00"

    s = re.sub(r'"(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\'', _keep, script)
    s = re.sub(r"/\*.*?\*/", " ", s, flags=re.S)
    s = re.sub(r"//[^\n]*", " ", s)
    for i, st in enumerate(strings):
        s = s.replace(f"\x00{i}\x00", st)
    return s


def _url_taint_vars(script):
    """
    Variáveis que recebem dado da URL/hash (2º salto de taint).

    Ex.: `items = JSON.parse(decodeURIComponent(params.get('cart') || '[]'))`
    captura `items` — que pode ser usado depois num innerHTML sem escape.
    """
    vars_ = set()
    for m in re.finditer(
        # [^;,] não cruza vírgulas: em `me=...,id=URLSearchParams(...)` a captura
        # de `me` engoliria o `id` (lição NovaMart/account.html).
        r"(\w+)\s*=\s*[^;,]{0,200}?(?:params\.get|location\.search|location\.hash|URLSearchParams)",
        script,
    ):
        vars_.add(m.group(1))
    return vars_


def _storage_taint_vars(script):
    """Variáveis que recebem dados do localStorage/sessionStorage."""
    vars_ = set()
    for m in re.finditer(
        r"(\w+)\s*=\s*(?:JSON\.parse\()?(?:localStorage|sessionStorage)\.getItem",
        script,
    ):
        vars_.add(m.group(1))
    return vars_


def _var_feeds_sink(span, var):
    """
    A variável é CONTEÚDO do sink (não apenas usado em filtro/comparação)?

    - ${var} em template literal (ex.: account.html do NovaMart)
    - var.map( / var.join( (o dado vira HTML — checkout do puffpod, stored do lab)
    - RHS começa com a variável (ex.: innerHTML = hash — dom.html do lab)

    Evita falso positivo em sites com dados demo estáticos, em que a variável
    de URL só aparece em filtros/comparações do RHS (ex.: orders.html).
    """
    return bool(
        re.search(rf"\$\{{\s*{re.escape(var)}\s*\}}", span)
        or re.search(rf"\b{re.escape(var)}\.map\(", span)
        or re.search(rf"\b{re.escape(var)}\.join\(", span)
        # RHS COMEÇA com a variável (innerHTML = var) — âncora no início do
        # span; sem isso, "x.uid==id" dentro do RHS casaria com "= id" (FP).
        or re.match(rf"\.(?:innerHTML|outerHTML)\s*=\s*\b{re.escape(var)}\b", span)
    )


def _nearest_flow(script):
    """
    Retorna (fonte, distância) do par fonte→sink, com prioridade:

    1. Fonte de URL/hash usada DIRETAMENTE na expressão do sink
       (ex.: document.write(params.get("x")) — index.html do lab);
    2. Variável que recebe dado de URL/hash e vira CONTEÚDO do sink
       (ex.: items.map(...) em innerHTML — checkout do puffpod);
    3. Variável que recebe dado do storage e vira conteúdo do sink
       (ex.: dados.join(...) — stored.html do lab).
    """
    # Remove comentários para não tratar código documentado como sink real
    script = _strip_js_comments(script)
    sinks = [m.start() for m in _DOM_SINK_RE.finditer(script)]
    if not sinks:
        return None

    best = None

    def _consider(name, dist):
        nonlocal best
        if best is None or dist < best[1]:
            best = (name, dist)

    # 1) fonte de URL/hash DENTRO da expressão do sink (logo após o sink)
    for name, rx in _DOM_SOURCE_RE.items():
        if name in ("localStorage", "sessionStorage", "document.cookie"):
            continue
        for m in rx.finditer(script):
            for s_pos in sinks:
                dist = m.start() - s_pos
                # fonte depois do sink (RHS da atribuição / argumento da chamada)
                if 0 < dist <= 60:
                    _consider(name, dist)
    if best:
        return best

    # 2) variável com dado de URL/hash virando conteúdo do sink
    for var in _url_taint_vars(script):
        for m in _SINK_ASSIGN_RE.finditer(script):
            if _var_feeds_sink(script[m.start():m.end()], var):
                _consider("URLSearchParams", 0)
    if best:
        return best

    # 3) variável com dado do storage virando conteúdo do sink
    for var in _storage_taint_vars(script):
        for m in _SINK_ASSIGN_RE.finditer(script):
            if _var_feeds_sink(script[m.start():m.end()], var):
                _consider("localStorage", 0)
    return best if best else None


def _dom_flow_pair(script):
    """Compat: delega para _nearest_flow (proximidade + taint leve)."""
    return _nearest_flow(script)


def _same_origin_links(html, url, limit=8):
    """Links da mesma origem na página (1 nível, sem recursão)."""
    base_host = urlparse(url).netloc
    links = []
    for m in re.finditer(r'href=["\']([^"\'#]+)["\']', html or "", re.I):
        href = m.group(1)
        abs_url = urljoin(url, href)
        if urlparse(abs_url).netloc == base_host and abs_url != url:
            links.append(abs_url)
    seen, out = set(), []
    for link in links:
        if link not in seen:
            seen.add(link)
            out.append(link)
    return out[:limit]


def _sink_snippet(script, max_len=90):
    """Trecho compacto do script para a evidência."""
    s = re.sub(r"\s+", " ", (script or "").strip())
    return s[:max_len]


def xss_dom_findings(url, timeout=5):
    """
    Analisa os <script> da página (e páginas da mesma origem linkadas) em busca
    de sinks de DOM alimentados por fontes controláveis (URL, hash, storage).

    Cobre XSS que o teste de reflexo NÃO vê: o valor é lido e inserido no DOM
    pelo JavaScript do navegador, então o servidor nunca reflete o marcador.
    """
    from .engine import _finding

    urls = [url]
    try:
        r0 = requests.get(url, headers=HEADERS, timeout=timeout, allow_redirects=True)
        urls += _same_origin_links(r0.text, url)
    except Exception:
        pass

    findings = []
    vistos = set()
    for u in urls:
        try:
            r = requests.get(u, headers=HEADERS, timeout=timeout, allow_redirects=True)
            page_html = r.text
        except Exception:
            continue

        for script in re.findall(r"<script[^>]*>(.*?)</script>", page_html, re.S | re.I):
            par = _dom_flow_pair(script)
            if not par:
                continue
            source, dist = par
            tipo, ev = dict(_DOM_SOURCES)[source]
            chave = (u, tipo)
            if chave in vistos:
                continue
            vistos.add(chave)
            findings.append(
                _finding(
                    "XSS",
                    f"Possível XSS {tipo}",
                    f"Sink de DOM alimentado por fonte controlável ({source})",
                    "Média",
                    f"A página contém um sink de DOM (document.write/innerHTML) "
                    f"alimentado por {ev} — padrão compatível com execução de "
                    "script no navegador da vítima. Validar manualmente em laboratório.",
                    "Achado Ativo",
                    [f"url: {u}", f"script: {_sink_snippet(script)}", "análise estática do JavaScript"],
                )
            )
    return findings


# ── Segurança client-side (lição NovaMart) ────────────────────────────────
# Credenciais hardcoded no JS do cliente: password:"x" (literais de string).
_CRED_RE = re.compile(r"\b(?:password|passwd|senha)\s*:\s*[\"'][^\"']{4,}[\"']", re.I)
# Controle de acesso apenas no cliente: comparação de role com "admin".
_ROLE_GATE_RE = re.compile(r"\.role\s*[!=]==?\s*[\"']admin[\"']?", re.I)


def client_side_findings(url, timeout=5):
    """
    Detecta falhas de segurança client-side nas páginas (mesma origem):

    - Credenciais hardcoded no JavaScript (ex.: users={admin:{password:"..."}});
    - Controle de acesso apenas no cliente (role checada via localStorage/JS).

    Lição do NovaMart: sites estáticos de treinamento costumam ter o login e a
    autorização 100% no navegador — qualquer usuário lê as credenciais no
    código-fonte e burla o "admin" editando o localStorage.
    """
    from .engine import _finding

    urls = [url]
    try:
        r0 = requests.get(url, headers=HEADERS, timeout=timeout, allow_redirects=True)
        urls += _same_origin_links(r0.text, url)
    except Exception:
        pass

    findings = []
    vistos = set()
    for u in urls:
        try:
            r = requests.get(u, headers=HEADERS, timeout=timeout, allow_redirects=True)
            page_html = r.text
        except Exception:
            continue

        scripts = re.findall(r"<script[^>]*>(.*?)</script>", page_html, re.S | re.I)
        for script in scripts:
            script_limpo = _strip_js_comments(script)

            if _CRED_RE.search(script_limpo) and (u, "creds") not in vistos:
                vistos.add((u, "creds"))
                achado = _CRED_RE.search(script_limpo).group(0)
                findings.append(
                    _finding(
                        "Client-Side",
                        "Credenciais hardcoded no JavaScript",
                        "Usuário/senha expostos no código do cliente",
                        "Alta",
                        "O JavaScript da página contém credenciais em texto claro "
                        f"({achado}). Qualquer pessoa pode ler o código-fonte e "
                        "autenticar sem conhecer a senha — o login não deveria "
                        "existir no cliente.",
                        "Achado Ativo",
                        [f"url: {u}", f"achado: {achado}", "análise estática do JavaScript"],
                    )
                )

            if (
                "localStorage" in script_limpo
                and _ROLE_GATE_RE.search(script_limpo)
                and (u, "role") not in vistos
            ):
                vistos.add((u, "role"))
                findings.append(
                    _finding(
                        "Client-Side",
                        "Controle de acesso apenas no cliente",
                        "Verificação de role via localStorage/JS (bypassável)",
                        "Alta",
                        "A autorização (ex.: role de admin) é verificada apenas no "
                        "JavaScript, usando dados do localStorage. Qualquer usuário "
                        "pode editar o localStorage no console e obter acesso de "
                        "administrador sem passar pelo servidor.",
                        "Achado Ativo",
                        [f"url: {u}", "controle de acesso existe somente no cliente", "análise estática do JavaScript"],
                    )
                )
    return findings


def xss_findings(results):
    """
    Converte o resultado do teste de reflexo em achados padronizados.
    """
    from .engine import _finding

    if not results:
        return []

    raw = [r for r in results if r.get("refletido_sem_encoding")]
    reflected_encoded = [
        r for r in results
        if r.get("refletido") and not r.get("refletido_sem_encoding")
    ]

    if raw:
        params_afetados = ", ".join(sorted({str(r.get("param", "?")) for r in raw}))
        return [
            _finding(
                "XSS",
                "Possível XSS refletido",
                f"Marcador refletido sem encoding ({len(raw)} payload(s))",
                "Média",
                f"O marcador de teste foi refletido sem codificação HTML no parâmetro "
                f"'{params_afetados}' — padrão compatível com XSS refletido. "
                "Validar manualmente em laboratório.",
                "Achado Ativo",
                [f"param: {raw[0].get('param', '?')}", f"method: {raw[0].get('method', 'GET')}",
                 f"payload: {raw[0]['payload']}",
                 "resposta contém a tag HTML original"],
            )
        ]

    if reflected_encoded:
        return [
            _finding(
                "XSS",
                "Reflexo com encoding",
                "Marcador refletido, mas codificado",
                "Baixa",
                "O marcador foi refletido, porém com codificação HTML (escaped). "
                "Indica saída sanitizada — reforçar encoding em todas as saídas.",
                "Melhoria Recomendada",
                ["marcador refletido sem execução possível (escape presente)"],
            )
        ]

    return [
        _finding(
            "XSS",
            "Teste de XSS",
            "Sem reflexo de marcador",
            "Baixa",
            "Os marcadores de XSS não foram refletidos na resposta dos parâmetros testados.",
            "Controle OK",
            [f"{len(results)} payloads testados"],
        )
    ]
