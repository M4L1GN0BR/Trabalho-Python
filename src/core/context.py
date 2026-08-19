"""
Extração de contexto de código-fonte para análise profunda com IA.

Permite que o sistema envie para a IA não apenas o ID e mensagem do achado,
mas também o código real, a função que contém a linha, e os imports do arquivo.
Isso dá à IA material para rastrear fluxos de dados e encontrar evidências reais.
"""

import re
from pathlib import Path


def extract_code_snippet(file_path, line_number, radius=10):
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

    Retorna
    -------
    str
        Snippet formatado com números de linha, ou "" se arquivo não existir.
    """
    path = Path(file_path)
    if not path.exists():
        return ""

    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ""

    if not lines:
        return ""

    start = max(0, line_number - 1 - radius)
    end = min(len(lines), line_number + radius)

    snippet = []
    for i in range(start, end):
        marker = ">>>" if (i + 1) == line_number else "   "
        snippet.append(f"{marker} {i + 1:4d} | {lines[i]}")

    return "\n".join(snippet)


def extract_function_context(file_path, line_number):
    """
    Encontra a função/classe que contém a linha.

    Retorna
    -------
    dict
        {"funcao": str, "classe": str, "arquivo": str}
    """
    path = Path(file_path)
    if not path.exists():
        return {"funcao": "?", "classe": "", "arquivo": str(file_path)}

    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return {"funcao": "?", "classe": "", "arquivo": str(file_path)}

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


def extract_imports(file_path, limit=15):
    """
    Extrai os imports do arquivo.

    Retorna
    -------
    str
        Lista de imports como texto, ou "" se não houver.
    """
    path = Path(file_path)
    if not path.exists():
        return ""

    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return ""

    imports = []
    for line in lines:
        stripped = line.strip()
        if stripped.startswith(("import ", "from ")) and not stripped.startswith("#"):
            imports.append(stripped)
        if len(imports) >= limit:
            break

    return "\n".join(imports)


def build_vulnerability_context(check_id, message, file_path=None, line_number=None, radius=12):
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

        contexto["snippet"] = extract_code_snippet(file_path, line_number, radius)
        ctx_func = extract_function_context(file_path, line_number)
        contexto["funcao"] = ctx_func["funcao"]
        contexto["classe"] = ctx_func["classe"]
        contexto["imports"] = extract_imports(file_path)

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
