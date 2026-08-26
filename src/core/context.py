"""
Extração de contexto de código-fonte para análise profunda com IA.

Permite que o sistema envie para a IA não apenas o ID e mensagem do achado,
mas também o código real, a função que contém a linha, e os imports do arquivo.
Isso dá à IA material para rastrear fluxos de dados e encontrar evidências reais.
"""

import re
from pathlib import Path

# Limite máximo de bytes lidos de um arquivo para análise (64 KB).
MAX_SNIPPET_BYTES = 64 * 1024


def _safe_resolve(repo_root, file_path):
    """
    Resolve um caminho de arquivo garantindo que ele fique contido no repositório.

    Regras de contenção (anti path traversal):
    - Caminhos absolutos (ex.: "C:\\...", "/etc/...") são rejeitados.
    - Qualquer parte do caminho igual a ".." é rejeitada.
    - O caminho final precisa estar dentro de repo_root (ou do diretório de
      trabalho atual, se repo_root for None).

    Retorna
    -------
    Path or None
        Caminho absoluto contido no repositório, ou None se rejeitado.
    """
    if not file_path:
        return None

    path = Path(file_path)

    # Rejeita caminhos absolutos (ex.: C:\Users\... ou /etc/passwd).
    if path.is_absolute():
        return None

    # Rejeita path traversal: qualquer parte do caminho igual a "..".
    if any(part == ".." for part in path.parts):
        return None

    base = Path(repo_root).resolve() if repo_root else Path.cwd().resolve()

    try:
        candidate = (base / path).resolve()
    except (OSError, ValueError, RuntimeError):
        return None

    if not candidate.is_relative_to(base):
        return None

    return candidate


def _read_file_safe(repo_root, file_path, max_bytes=MAX_SNIPPET_BYTES):
    """
    Lê o conteúdo de um arquivo com contenção de path e limite de tamanho.

    Retorna
    -------
    (str or None, bool)
        Tupla com o conteúdo (possivelmente truncado em max_bytes) e um
        indicador de truncamento. Conteúdo None indica arquivo rejeitado,
        inexistente ou ilegível (sem levantar exceção).
    """
    candidate = _safe_resolve(repo_root, file_path)
    if candidate is None:
        return None, False

    try:
        if candidate.stat().st_size > max_bytes:
            # Arquivo grande demais: lê apenas o início, sem carregar tudo.
            with candidate.open("r", encoding="utf-8", errors="replace") as fh:
                return fh.read(max_bytes), True
        return candidate.read_text(encoding="utf-8", errors="replace"), False
    except (OSError, ValueError):
        return None, False


def extract_code_snippet(file_path, line_number, radius=10, repo_root=None):
    """
    Extrai um snippet de código ao redor de uma linha.

    Parâmetros
    ----------
    file_path : str
        Caminho do arquivo.
    line_number : int
        Linha do achado.
    radius : int
        Quantas linhas antes/depois incluir.
    repo_root : str, optional
        Raiz do repositório escaneado. Se None, usa o diretório de trabalho
        atual como base. Caminhos absolutos e com ".." são rejeitados.

    Retorna
    -------
    str
        Snippet formatado com números de linha, ou "" se o arquivo for
        rejeitado, não existir, exceder o limite de tamanho ou não puder
        ser lido.
    """
    content, truncated = _read_file_safe(repo_root, file_path)
    if content is None:
        return ""

    lines = content.splitlines()
    if not lines:
        return ""

    start = max(0, line_number - 1 - radius)
    end = min(len(lines), line_number + radius)

    snippet = []
    for i in range(start, end):
        marker = ">>>" if (i + 1) == line_number else "   "
        snippet.append(f"{marker} {i + 1:4d} | {lines[i]}")

    texto = "\n".join(snippet)
    if truncated:
        texto += "\n[aviso: arquivo excede 64 KB — snippet truncado]"

    return texto


def extract_function_context(file_path, line_number, repo_root=None):
    """
    Encontra a função/classe que contém a linha.

    Parâmetros
    ----------
    file_path : str
        Caminho do arquivo.
    line_number : int
        Linha do achado.
    repo_root : str, optional
        Raiz do repositório escaneado (mesma regra de contenção de
        extract_code_snippet).

    Retorna
    -------
    dict
        {"funcao": str, "classe": str, "arquivo": str}
    """
    content, _ = _read_file_safe(repo_root, file_path)
    if content is None:
        return {"funcao": "?", "classe": "", "arquivo": str(file_path)}

    lines = content.splitlines()

    funcao_atual = "?"
    classe_atual = ""
    indent_atual = -1

    func_pattern = re.compile(r"^\s*def\s+(\w+)\s*\(")
    class_pattern = re.compile(r"^\s*class\s+(\w+)")

    for i, line in enumerate(lines[:line_number]):
        m_class = class_pattern.match(line)
        if m_class:
            classe_atual = m_class.group(1)
            funcao_atual = "?"  # nova classe, zera função

        m_func = func_pattern.match(line)
        if m_func:
            indent = len(line) - len(line.lstrip())
            # Só considera se a função está num nível razoável (não nested lambda)
            funcao_atual = m_func.group(1)
            indent_atual = indent

    return {
        "funcao": funcao_atual,
        "classe": classe_atual,
        "arquivo": str(file_path),
    }


def extract_imports(file_path, limit=15, repo_root=None):
    """
    Extrai os imports do arquivo.

    Parâmetros
    ----------
    file_path : str
        Caminho do arquivo.
    limit : int
        Máximo de imports retornados.
    repo_root : str, optional
        Raiz do repositório escaneado (mesma regra de contenção).

    Retorna
    -------
    str
        Lista de imports como texto, ou "" se não houver.
    """
    content, _ = _read_file_safe(repo_root, file_path)
    if content is None:
        return ""

    lines = content.splitlines()

    imports = []
    for line in lines:
        stripped = line.strip()
        if stripped.startswith(("import ", "from ")) and not stripped.startswith("#"):
            imports.append(stripped)
        if len(imports) >= limit:
            break

    return "\n".join(imports)


def build_vulnerability_context(check_id, message, file_path=None, line_number=None, radius=12, repo_root=None):
    """
    Monta o contexto completo de uma vulnerabilidade para envio à IA.

    Parâmetros
    ----------
    check_id : str
        ID da regra.
    message : str
        Mensagem da ferramenta.
    file_path : str, optional
        Caminho do arquivo (se disponível).
    line_number : int, optional
        Linha do achado.
    radius : int
        Raio do snippet.
    repo_root : str, optional
        Raiz do repositório escaneado (mesma regra de contenção).

    Retorna
    -------
    dict
        Dicionário com: snippet, funcao, imports e mensagem.
    """
    contexto = {
        "check_id": check_id,
        "message": message,
        "snippet": "",
        "funcao": "?",
        "classe": "",
        "imports": "",
    }

    if file_path and line_number:
        try:
            line_number = int(line_number)
        except (TypeError, ValueError):
            return contexto

        contexto["snippet"] = extract_code_snippet(file_path, line_number, radius, repo_root)
        ctx_func = extract_function_context(file_path, line_number, repo_root)
        contexto["funcao"] = ctx_func["funcao"]
        contexto["classe"] = ctx_func["classe"]
        contexto["imports"] = extract_imports(file_path, repo_root=repo_root)

    return contexto


def format_context_for_prompt(contexto):
    """
    Formata o contexto em texto legível para o prompt da IA.
    """
    partes = [f"ID da regra: {contexto.get('check_id', '')}"]

    if contexto.get("funcao") and contexto["funcao"] != "?":
        partes.append(f"Função: {contexto['funcao']}()")

    if contexto.get("classe"):
        partes.append(f"Classe: {contexto['classe']}")

    if contexto.get("message"):
        partes.append(f"Mensagem da ferramenta: {contexto['message']}")

    if contexto.get("snippet"):
        partes.append(f"\nCódigo-fonte (linha do achado marcada com >>>):\n{contexto['snippet']}")

    if contexto.get("imports"):
        partes.append(f"\nImports do arquivo:\n{contexto['imports']}")

    return "\n".join(partes)
