"""
Camada de IA do dashboard (DeepSeek + fallback local).

- ask_ai: explica um achado com contexto de código (cacheado).
- ask_executive_summary: gera resumo executivo para o dashboard.
- local_ai_fallback: resposta local sem chamar a API (sem chave ou erro).
"""

import streamlit as st

from src.core.ia.deepseek_client import DEEPSEEK_API_KEY, call_deepseek
from src.core.text import clean_text


def extract_section(text, labels):
    if not text:
        return None

    for line in text.splitlines():
        normalized = clean_text(line).strip().upper()

        for label in labels:
            if normalized.startswith(label) and ":" in line:
                return clean_text(line.split(":", 1)[1].strip())

    return None


def default_correction(text):
    text = str(text).lower()

    if "site utiliza https" in text or "https ok" in text:
        return "Nenhuma ação necessária para HTTPS. O site já utiliza conexão segura."

    if "certificado tls com" in text and "expirado" not in text and "erro" not in text:
        return "Nenhuma ação necessária imediata. Manter monitoramento da validade do certificado TLS."

    if "strict-transport-security" in text:
        return "Configurar HSTS para reforçar o uso obrigatório de HTTPS. Tratar como melhoria de hardening, não como falha crítica isolada."

    if "content-security-policy" in text:
        return "Configurar uma política CSP adequada para reduzir risco de XSS."

    if "x-frame-options" in text:
        return "Configurar X-Frame-Options ou CSP frame-ancestors para reduzir risco de clickjacking."

    if "x-content-type-options" in text:
        return "Configurar X-Content-Type-Options como nosniff."

    if "x-powered-by" in text:
        return "Remover ou ocultar o header X-Powered-By no servidor."

    if ".env" in text:
        return "Remover arquivos .env da aplicação pública e bloquear acesso via servidor web."

    if "swagger" in text or "graphql" in text:
        return "Proteger documentação de API com autenticação e restringir exposição pública."

    if "os.system" in text:
        return "Evitar uso de os.system com entrada do usuário. Prefira subprocess.run com lista de argumentos."

    if "subprocess" in text:
        return "Evitar subprocess com shell=True e validar entradas externas."

    if "hardcoded" in text or "password" in text or "secret" in text:
        return "Remover segredo do código e usar variável de ambiente ou cofre de segredos."

    if "cve" in text or "biblioteca" in text or "depend" in text:
        return "Atualizar a dependência para uma versão corrigida e validar compatibilidade da aplicação."

    return "Revisar configuração e aplicar hardening."


def local_ai_fallback(title, description):
    text = f"{title} {description}".lower()

    if (
        "tipo: controle ok" in text
        or "site utiliza https" in text
        or "status: ok" in text
    ):
        return {
            "explicacao": "Este item representa um controle de segurança funcionando corretamente.",
            "risco": "Nenhum risco direto identificado neste item.",
            "correcao": "Nenhuma ação necessária, apenas manter monitoramento periódico.",
        }

    if "tipo: falso positivo automático" in text:
        return {
            "explicacao": "O item foi identificado pelo discovery, mas a análise contextual não encontrou evidência de vulnerabilidade real.",
            "risco": "Baixo. O item foi separado como falso positivo automático.",
            "correcao": "Nenhuma correção obrigatória. Recomenda-se apenas revisão manual se necessário.",
        }

    if "tipo: melhoria recomendada" in text:
        return {
            "explicacao": "Este item representa uma melhoria de hardening. Ele fortalece a segurança, mas não comprova uma vulnerabilidade explorável sozinho.",
            "risco": "Baixo a moderado, dependendo do contexto. Deve ser priorizado após vulnerabilidades confirmadas.",
            "correcao": default_correction(text),
        }

    return {
        "explicacao": f"O item analisado ({title}) pode representar uma fragilidade de segurança.",
        "risco": description,
        "correcao": default_correction(f"{title} {description}"),
    }


@st.cache_data(show_spinner=False)
def ask_ai(title, description, file_path=None, line_number=None):
    """
    Usa DeepSeek para analisar achados com contexto decisório.
    Se file_path/line_number forem fornecidos, inclui o snippet do código na análise.
    Caso a chave não esteja configurada ou a API falhe, usa fallback local.
    """
    if not DEEPSEEK_API_KEY:
        return local_ai_fallback(title, description)

    system_prompt = """
Você é um analista sênior de Application Security em uma plataforma ASPM.

Para cada item, você deve:

1. EXPLICAR em linguagem de negócio (como se fosse para um CISO)
2. CLASSIFICAR o tipo real:
   - "Vulnerabilidade" → risco confirmado e explorável
   - "Hardening" → melhoria de segurança, não vulnerabilidade
   - "Controle OK" → item seguro, sem ação
   - "Falso Positivo" → não é vulnerabilidade real
3. RE-PRIORIZAR se necessário: a severidade original da ferramenta pode não refletir o risco real
4. RECOMENDAR correção acionável e priorizada

Se código-fonte for fornecido, INVESTIGUE o fluxo de dados (source→sink):
- O dado vem do usuário? Existe sanitização?
- Há evidência real de exploração ou é risco teórico?
- Confirme a vulnerabilidade apenas se o código mostrar evidência.

Regras obrigatórias:
- Se o item for "Controle OK", apenas confirme que está correto
- Se for "Falso Positivo Automático", explique por que não é vulnerabilidade
- Se for "Melhoria Recomendada" (ex: header CSP ausente), trate como hardening, não como vulnerabilidade
- NUNCA invente informações que não estejam na descrição
- Responda EXATAMENTE no formato abaixo
""".strip()

    try:
        snippet = ""
        if file_path and line_number:
            from src.core.context import extract_code_snippet
            snippet = extract_code_snippet(file_path, line_number)

        snippet_block = (
            f"\nCÓDIGO-FONTE (linha do achado marcada com >>>):\n{snippet}"
            if snippet
            else ""
        )

        prompt = f"""
Analise o item abaixo e retorne no formato exato solicitado.

TÍTULO:
{title}

DESCRIÇÃO:
{description}
{snippet_block}

Formato de resposta (uma linha por campo):
EXPLICACAO: <explicação em linguagem de negócio, 1-2 frases>
RISCO: <tipo real + exploitabilidade + prioridade sugerida, 1-2 frases>
CORRECAO: <ação específica e priorizada, 1 frase>
"""

        text = clean_text(
            call_deepseek(
                prompt=prompt,
                system_prompt=system_prompt,
                temperature=0.1,
                max_tokens=1024,
            )
        )
        fallback = local_ai_fallback(title, description)

        explicacao = extract_section(text, ["EXPLICACAO", "EXPLICAÇÃO"])
        risco = extract_section(text, ["RISCO"])
        correcao = extract_section(text, ["CORRECAO", "CORREÇÃO"])

        return {
            "explicacao": explicacao or fallback["explicacao"],
            "risco": risco or fallback["risco"],
            "correcao": correcao or fallback["correcao"],
        }

    except Exception:
        return local_ai_fallback(title, description)


@st.cache_data(show_spinner=False)
def ask_executive_summary(context):
    """
    Gera resumo executivo usando DeepSeek com análise decisória.
    """
    if not DEEPSEEK_API_KEY:
        return (
            "A aplicação apresenta achados distribuídos entre análise estática, segurança Python, "
            "dependências, segredos e exposição de URL. A prioridade deve ser corrigir riscos altos, "
            "revisar endpoints expostos e manter dependências atualizadas."
        )

    system_prompt = """
Você é um diretor de segurança (CISO) revisando o relatório executivo de uma plataforma ASPM.

Gere um resumo executivo que:
1. DESTAQUE os riscos mais críticos (o que precisa de atenção imediata)
2. CONTEXTE a postura geral de segurança com base nos números
3. RECOMENDE prioridades de ação na próxima sprint

Seja direto, profissional e evite linguagem acadêmica.
Use português brasileiro.
""".strip()

    try:
        prompt = f"""
Com base no contexto abaixo, gere um resumo executivo CURTO, DIRETO e PROFISSIONAL
para um relatório ASPM.

Inclua:
- Quantos riscos críticos merecem atenção imediata
- Qual o score geral de segurança
- Recomendação principal de curto prazo

CONTEXTO:
{context}
"""

        text = call_deepseek(
            prompt=prompt,
            system_prompt=system_prompt,
            temperature=0.1,
            max_tokens=1024,
        )

        return clean_text(text) if text else "A IA não retornou resumo executivo."

    except Exception:
        return (
            "Não foi possível gerar o resumo executivo com IA. Recomenda-se priorizar os achados "
            "classificados como Alta, revisar exposição externa, corrigir segredos e atualizar dependências vulneráveis."
        )
