"""
Análise de templates HTML/Django (XSS).

Detecta padrões de XSS em templates renderizados pelo servidor:

- `{% autoescape off %}` — desativa o escape automático do Django.
- `{{ var|safe }}` — marca uma variável como segura sem garantir sanitização.
- `{% blocktranslate %}` com variáveis — o escape pode variar por versão/uso
  (aprendizado do estudo DefectDojo: 175 achados desse padrão).
- `|escapejs` usado em contexto HTML (marcador de mau uso do filtro).
- `{% verbatim %}` com input? (informativo, sem risco direto).

Os findings seguem o formato do dashboard (Tipo/Categoria/Item/Status/Prioridade/
Evidências/Descrição), reutilizando a UI existente.
"""

import re
from pathlib import Path

# Bloco autoescape off (com conteúdo)
_AUTOESCAPE_OFF = re.compile(
    r"{%\s*autoescape\s+off\s*%}.*?{%\s*endautoescape\s*%}",
    re.DOTALL | re.IGNORECASE,
)

# Variável com filtro safe
_VAR_SAFE = re.compile(r"{{\s*[^}|]+\|[^}]*\bsafe\b[^}]*}}")

# Variável dentro de blocktranslate
_BLOCKTRANSLATE_VAR = re.compile(
    r"{%\s*blocktranslate[^%]*%}(?P<body>.*?){%\s*endblocktranslate\s*%}",
    re.DOTALL | re.IGNORECASE,
)
_VAR_INSIDE = re.compile(r"{{\s*[^}]+}}")

# Filtro escapejs (não substitui escape de HTML)
_ESCAPEJS = re.compile(r"{{\s*[^}|]+\|escapejs\s*}}")


def _make_finding(categoria, item, prioridade, evidencias, descricao, linha=None):
    return {
        "Tipo": "Achado Ativo" if prioridade == "Alta" else "Melhoria Recomendada",
        "Categoria": categoria,
        "Item": item if linha is None else f"{item} (linha {linha})",
        "Status": "Risco",
        "Prioridade": prioridade,
        "Evidências": evidencias,
        "Descrição": descricao,
        "URL": "",
    }


def analyze_template(content, path="template.html"):
    """
    Analisa o conteúdo de um template em busca de padrões XSS.

    Parâmetros
    ----------
    content : str
        Conteúdo do template.
    path : str
        Caminho do template (para exibição).

    Retorna
    -------
    list[dict]
        Findings no formato do dashboard.
    """
    findings = []

    # 1. autoescape off
    for m in _AUTOESCAPE_OFF.finditer(content):
        line = content[: m.start()].count("\n") + 1
        snippet = m.group(0).strip().replace("\n", " ")[:100]
        findings.append(
            _make_finding(
                "XSS",
                f"{path} — autoescape off",
                "Alta",
                snippet,
                "Bloco com autoescape off desativa a proteção padrão do Django contra "
                "XSS. Se alguma variável do bloco receber entrada do usuário, o conteúdo "
                "será renderizado sem escape.",
                linha=line,
            )
        )

    # 2. Variáveis com |safe
    for m in _VAR_SAFE.finditer(content):
        line = content[: m.start()].count("\n") + 1
        snippet = m.group(0).strip()
        var_name = snippet.strip("{} ").split("|")[0].strip()
        findings.append(
            _make_finding(
                "XSS",
                f"{path} — {var_name} com filtro safe",
                "Média",
                snippet,
                "O filtro |safe marca a variável como HTML seguro. Use apenas em conteúdo "
                "confiável e sanitizado; para dados do usuário, prefira escape explícito.",
                linha=line,
            )
        )

    # 3. Variáveis dentro de blocktranslate
    for m in _BLOCKTRANSLATE_VAR.finditer(content):
        body = m.group("body")
        for vm in _VAR_INSIDE.finditer(body):
            line = content[: m.start() + vm.start()].count("\n") + 1
            snippet = vm.group(0).strip()
            var_name = snippet.strip("{} ").split("|")[0].strip()
            findings.append(
                _make_finding(
                    "XSS",
                    f"{path} — {var_name} em blocktranslate",
                    "Média",
                    snippet,
                    "Variável renderizada dentro de blocktranslate sem filtro de escape "
                    "explícito. O comportamento de escape depende da versão/configuração do "
                    "Django — valide e sanitize a entrada na origem.",
                    linha=line,
                )
            )

    # 4. escapejs em contexto HTML
    for m in _ESCAPEJS.finditer(content):
        line = content[: m.start()].count("\n") + 1
        findings.append(
            _make_finding(
                "XSS",
                f"{path} — escapejs em contexto HTML",
                "Baixa",
                m.group(0).strip(),
                "O filtro escapejs escapa para contexto JavaScript, não para HTML. "
                "Se a variável for renderizada entre tags HTML, use escape manual/format_html.",
                linha=line,
            )
        )

    return findings


def scan_repo_templates(repo_path):
    """
    Percorre templates Django/HTML de um repositório.

    Busca em: **/templates/**/*.html e **/*.html (limitado a diretórios de
    templates para evitar ruído).

    Parâmetros
    ----------
    repo_path : str | Path
        Caminho do repositório.

    Retorna
    -------
    list[dict]
        Findings consolidados de todos os templates.
    """
    base = Path(repo_path)
    findings = []

    candidates = list(base.rglob("templates/**/*.html")) + list(base.rglob("**/templates/*.html"))
    seen = set()
    for f in candidates:
        if f in seen:
            continue
        seen.add(f)
        try:
            content = f.read_text(encoding="utf-8", errors="replace")
        except Exception:
            continue
        rel = f.relative_to(base)
        findings.extend(analyze_template(content, path=str(rel)))

    return findings


def findings_to_evidences(findings):
    """Converte findings de templates em evidências normalizadas."""
    from src.core.evidence import enrich_evidences, normalize_url_finding

    return enrich_evidences([normalize_url_finding(f) for f in findings])
