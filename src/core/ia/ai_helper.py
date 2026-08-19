"""
Módulo de análise profunda de vulnerabilidades assistida por IA.

A IA agora age como um analista investigativo: recebe o código-fonte real,
o contexto da função e os imports, e rastreia fluxos de dados para decidir
se existe evidência real de vulnerabilidade — em vez de confiar só no ID da regra.
"""

from pathlib import Path

from .deepseek_client import DEEPSEEK_API_KEY, call_deepseek
from .context import build_vulnerability_context, format_context_for_prompt

SYSTEM_DEEP_ANALYST = """
Você é um analista sênior de Application Security em uma plataforma ASPM, especializado em análise profunda de código.

Seu trabalho é INVESTIGAR, não apenas listar regras. Para cada achado, você deve:

1. RASTREAR O FLUXO DE DADOS (taint analysis manual):
   - De onde vem a entrada (usuário, rede, arquivo, banco, env)?
   - Por onde ela passa (sanitização, validação, encoding)?
   - Onde ela chega (sink: SQL, shell, eval, template, path, header)?
   - Existe sanitização suficiente entre source e sink?

2. ANALISAR O CONTEXTO REAL do código fornecido:
   - O dado é controlado pelo usuário ou é interno/constante?
   - Existe validação antes do uso? (whitelist, parametrização, escaping)
   - A função é alcançável por rede/HTTP ou só por chamada interna?
   - A classe/função sugere privilégios elevados ou exposição?

3. IDENTIFICAR COMBINAÇÕES DE FALHAS (chaining):
   - Uma falha sozinha pode ser inofensiva, mas combinada com outra vira crítico.
   - Ex: upload sem validação + execução = RCE; IDOR + admin = acesso total.

4. DECIDIR SE É VULNERABILIDADE REAL:
   - Confirme apenas se houver EVIDÊNCIA no código fornecido.
   - Se faltar informação para confirmar, classifique como "provável" ou "não confirmado".
   - Se for hardening, falso positivo ou risco teórico, diga isso claramente.

REGRAS DE CONFIANÇA:
- "Alta" → código mostra fluxo source→sink sem sanitização
- "Média" → fluxo plausível mas requer condição (auth, config, outra falha)
- "Baixa" → achado genérico, sem evidência clara no código

REGRAS DE PRIORIDADE:
- Crítica: RCE, SQLi, auth bypass, SSRF com confirmação no código
- Alta: XSS, IDOR, path traversal, secret exposto com uso real
- Média: hardening, header ausente, versão antiga, risco condicional
- Baixa: informativo, falso positivo provável

Responda EXATAMENTE no formato abaixo, uma linha por campo, sem markdown:
""".strip()


def explain_vulnerability(check_id, message, file_path=None, line_number=None):
    """
    Analisa uma vulnerabilidade usando DeepSeek com contexto profundo do código.

    Parameters
    ----------
    check_id : str
        ID da regra/check que disparou.
    message : str
        Mensagem descritiva da ferramenta.
    file_path : str, optional
        Caminho do arquivo com o achado (para extrair snippet).
    line_number : int, optional
        Linha do achado.

    Returns
    -------
    dict
        {
            "explicacao": str,
            "risco": str,
            "correcao": str,
            "evidencia": str,
            "confianca": str,
            "prioridade_sugerida": str,
        }
    """
    if not DEEPSEEK_API_KEY:
        return {
            "explicacao": "Chave da API DeepSeek não configurada.",
            "risco": "Não foi possível analisar o risco com IA real.",
            "correcao": "Configure a variável DEEPSEEK_API_KEY no arquivo .env.",
            "evidencia": "",
            "confianca": "Nenhuma",
            "prioridade_sugerida": "",
        }

    # Monta contexto profundo com código-fonte
    contexto = build_vulnerability_context(
        check_id=check_id,
        message=message,
        file_path=file_path,
        line_number=line_number,
    )

    prompt = f"""
Analise profundamente o achado abaixo e retorne no formato exato solicitado.

{format_context_for_prompt(contexto)}

Investigue:
1. Fluxo de dados: existe entrada não sanitizada chegando a um sink perigoso?
2. O código mostra evidência real de exploração ou é risco teórico?
3. Existem combinações com outras falhas que elevam a gravidade?
4. Qual a confiança na confirmação e a prioridade final?

Formato de resposta (uma linha por campo, sem markdown):
EXPLICACAO: <resumo técnico do problema, 1-2 frases>
RISCO: <impacto real se explorado, considerando o fluxo analisado, 1-2 frases>
CORRECAO: <ação específica no contexto do código, 1 frase>
EVIDENCIA: <o que no código confirma ou descarta a vulnerabilidade, 1 frase>
CONFIANCA: <Alta|Média|Baixa>
PRIORIDADE_SUGERIDA: <Crítica|Alta|Média|Baixa>
"""

    try:
        text = call_deepseek(
            prompt=prompt,
            system_prompt=SYSTEM_DEEP_ANALYST,
            temperature=0.1,
            max_tokens=1500,
        )

        if not text:
            return {
                "explicacao": "A IA não retornou resposta.",
                "risco": "Não foi possível analisar o risco com IA.",
                "correcao": "Tente novamente ou revise a configuração da API.",
                "evidencia": "",
                "confianca": "Nenhuma",
                "prioridade_sugerida": "",
            }

        campos = {
            "EXPLICACAO": "Não disponível",
            "RISCO": "Não disponível",
            "CORRECAO": "Não disponível",
            "EVIDENCIA": "Não disponível",
            "CONFIANCA": "Nenhuma",
            "PRIORIDADE_SUGERIDA": "Não informada",
        }

        for line in text.splitlines():
            line = line.strip()
            for campo in campos:
                if line.upper().startswith(campo + ":"):
                    campos[campo] = line.split(":", 1)[1].strip()
                    break

        return {
            "explicacao": campos["EXPLICACAO"],
            "risco": campos["RISCO"],
            "correcao": campos["CORRECAO"],
            "evidencia": campos["EVIDENCIA"],
            "confianca": campos["CONFIANCA"],
            "prioridade_sugerida": campos["PRIORIDADE_SUGERIDA"],
        }

    except Exception as e:
        return {
            "explicacao": "Erro ao consultar o DeepSeek.",
            "risco": f"Detalhe: {str(e)}",
            "correcao": "Verifique a API key, conexão com internet e limite da API.",
            "evidencia": "",
            "confianca": "Nenhuma",
            "prioridade_sugerida": "",
        }


def explain_vulnerability_deep(check_id, message, repo_path=None, file_path=None, line_number=None):
    """
    Wrapper de compatibilidade: se repo_path for fornecido, tenta localizar o arquivo
    relativo a ele. Mantém a assinatura antiga funcionando.
    """
    if repo_path and file_path and not Path(file_path).exists():
        candidate = Path(repo_path) / file_path
        if candidate.exists():
            file_path = str(candidate)

    return explain_vulnerability(check_id, message, file_path, line_number)
