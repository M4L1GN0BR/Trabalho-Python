"""
Módulo de análise de vulnerabilidades assistida por IA.

Usa o DeepSeek para analisar achados de segurança e retornar:
- Explicação em linguagem de negócio
- Avaliação de exploitabilidade real
- Re-priorização baseada em contexto
- Recomendação de correção
"""

from .deepseek_client import DEEPSEEK_API_KEY, call_deepseek

SYSTEM_VULN_ANALYST = """
Você é um analista sênior de Application Security especializado em ASPM.

Para cada vulnerabilidade, você deve:

1. EXPLICAR o problema em linguagem que um CISO ou gerente entenda
   - Não seja puramente técnico — traduza o risco em impacto de negócio
   - Use português brasileiro claro e direto

2. AVALIAR a EXPLOITABILIDADE real:
   - Requer autenticação? Apenas ataque remoto sem interação? Depende de outra condição?
   - Existe CVE pública? exploit conhecido? É provável ser atacado no mundo real?
   - Classifique como: "Exploitável remotamente", "Exploitável com autenticação",
     "Baixa exploitabilidade" ou "Improvável"

3. RE-PRIORIZAR com base no contexto real, não na severidade da ferramenta:
   - Alta → risco real e explorável sem autenticação
   - Média → risco condicional ou que requer outra vulnerabilidade
   - Baixa → hardening, informação, falso positivo ou risco teórico

4. RECOMENDAR uma ação de correção específica, priorizada e acionável

REGRAS:
- Se o ID indicar falso positivo conhecido (ex: regra muito genérica), rebaixe a prioridade
- Se for um "Controle OK", apenas confirme que está seguro, não invente risco
- Se for hardening (ex: header CSP ausente), trate como melhoria, não como vulnerabilidade
- NUNCA invente informações que não estejam nos dados fornecidos
- Responda EXATAMENTE no formato abaixo, uma linha por campo
""".strip()


def explain_vulnerability(check_id, message):
    """
    Analisa uma vulnerabilidade usando DeepSeek.

    Parameters
    ----------
    check_id : str
        ID da regra/check que disparou (ex: "python.lang.security.exec.os-system")
    message : str
        Mensagem descritiva da ferramenta sobre o achado.

    Returns
    -------
    dict
        {
            "explicacao": str,   # explicação em linguagem de negócio
            "risco": str,        # risco + exploitabilidade + prioridade sugerida
            "correcao": str,     # ação recomendada
        }
    """
    if not DEEPSEEK_API_KEY:
        return {
            "explicacao": "Chave da API DeepSeek não configurada.",
            "risco": "Não foi possível analisar o risco com IA real.",
            "correcao": "Configure a variável DEEPSEEK_API_KEY no arquivo .env.",
        }

    prompt = f"""
Analise a vulnerabilidade abaixo e retorne a análise no formato exato solicitado.

ID da vulnerabilidade (check_id):
{check_id}

Descrição da ferramenta:
{message}

Formato de resposta (uma linha por campo, sem pular linhas):
EXPLICACAO: <explicação em linguagem de negócio, 1-2 frases>
RISCO: <exploitabilidade + prioridade sugerida + impacto, 1-2 frases>
CORRECAO: <ação específica e priorizada, 1 frase>
"""

    try:
        text = call_deepseek(
            prompt=prompt,
            system_prompt=SYSTEM_VULN_ANALYST,
            temperature=0.1,  # baixa temperatura = mais determinístico
            max_tokens=1024,
        )

        if not text:
            return {
                "explicacao": "A IA não retornou resposta.",
                "risco": "Não foi possível analisar o risco com IA.",
                "correcao": "Tente novamente ou revise a configuração da API.",
            }

        explicacao = "Não disponível"
        risco = "Não disponível"
        correcao = "Não disponível"

        for line in text.splitlines():
            line = line.strip()
            if line.upper().startswith("EXPLICACAO:"):
                explicacao = line.split(":", 1)[1].strip()
            elif line.upper().startswith("RISCO:"):
                risco = line.split(":", 1)[1].strip()
            elif line.upper().startswith("CORRECAO:"):
                correcao = line.split(":", 1)[1].strip()

        return {
            "explicacao": explicacao,
            "risco": risco,
            "correcao": correcao,
        }

    except Exception as e:
        return {
            "explicacao": "Erro ao consultar o DeepSeek.",
            "risco": f"Detalhe: {str(e)}",
            "correcao": "Verifique a API key, conexão com internet e limite da API.",
        }
