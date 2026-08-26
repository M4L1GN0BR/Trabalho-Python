"""
Camada de IA do dashboard (DeepSeek + fallback local).

- ask_ai: explica um achado com contexto de código (cacheado).
- ask_executive_summary: gera resumo executivo para o dashboard.
- local_ai_fallback: resposta local sem chamar a API (sem chave ou erro).
"""

import re

import streamlit as st

from src.core.ia.deepseek_client import DEEPSEEK_API_KEY, call_deepseek
from src.core.text import clean_text

# Stopwords inglesas para detectar respostas fora do pt-BR (o modelo pode
# responder em inglês mesmo com prompt pedindo português).
_EN_STOPWORDS = {
    "the", "and", "to", "of", "in", "is", "it", "for", "that", "with",
    "this", "be", "are", "as", "on", "at", "by", "from", "an", "or",
    "your", "you", "should", "can", "will", "not", "using", "use",
    "ensure", "configure", "setting", "within", "would", "may", "have",
    "has", "been", "was", "were", "do", "does", "its", "their", "there",
    "if", "but", "which", "when", "where", "while", "because", "about",
    "into", "them", "they", "then", "than", "also", "more", "most",
    "some", "such", "any", "all", "only", "how", "why", "what", "who",
    "these", "those", "new", "between", "during", "after", "before",
    "without", "out", "over", "under", "we", "our", "us", "up", "down",
}


# Textos curtos têm poucas amostras: limiar menor evita falso negativo.
def _english_threshold(word_count):
    return 0.20 if word_count < 14 else 0.28


def _is_mostly_english(text):
    """Heurística: proporção de palavras funcionais do inglês no texto."""
    words = re.findall(r"[a-záéíóúâêôãõçü]+", str(text or "").lower())
    if len(words) < 6:
        return False
    en = sum(1 for w in words if w in _EN_STOPWORDS)
    return en / len(words) > _english_threshold(len(words))


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

    if "shell injection" in text or ("shell" in text and "injection" in text) or ("github" in text and "run:" in text):
        return "Usar env: mapeado para passar contexto ao shell (ex.: \"$ENVVAR\") e nunca concatena ${{ github.* }} em run:. Validar o checkout em pull_request_target."

    if "mark_safe" in text or "|safe" in text:
        return "Evitar mark_safe/|safe com dados do usuário. Usar escape explícito (django.utils.html.escape) ou format_html com argumentos escapados."

    if "csrf" in text or "cross-site" in text:
        return "Garantir token CSRF na view (decorator @csrf_protect) e incluir {% csrf_token %} nos formulários."

    if "raw query" in text or ("sql" in text and ("raw" in text or "concat" in text or "f-string" in text or "format" in text)):
        return "Substituir SQL construído por string por parâmetros parametrizados/ORM (ex.: cursor.execute(sql, params))."

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

    if "hashlib" in text or ("md5" in text and "hash" in text) or "sha1" in text:
        return "Confirmar se o hash é usado para segurança; se sim, trocar por SHA-256 ou superior (ex.: hashlib.sha256)."

    if "hardcoded" in text or "password" in text or "secret" in text:
        return "Remover segredo do código e usar variável de ambiente ou cofre de segredos."

    if "cve" in text or "biblioteca" in text or "depend" in text:
        return "Atualizar a dependência para uma versão corrigida e validar compatibilidade da aplicação."

    return "Revisar configuração e aplicar hardening."


def _risco_from_text(text):
    """Estima o risco em pt-BR a partir de palavras-chave (fallback local)."""
    # Normaliza separadores (check_ids usam hífen: run-shell-injection)
    text = str(text).lower().replace("-", " ").replace("_", " ")
    if any(k in text for k in ("shell injection", "command injection", "rce", "sql injection", "sql raw", "execution")):
        return "Alto: pode permitir execução de código/consultas por atacante, com possível exfiltração de dados ou secrets."
    if "xss" in text or "mark safe" in text:
        return "Médio: execução de script no navegador da vítima (roubo de sessão) se o dado for controlado pelo usuário."
    if "secret" in text or "password" in text or "hardcoded" in text or "api key" in text or "private key" in text:
        return "Alto: credencial exposta pode permitir acesso não autorizado se o repositório for público ou vazado."
    if "csrf" in text:
        return "Médio: requisições forjadas podem executar ações em nome do usuário autenticado."
    if "http:" in text or "plaintext" in text:
        return "Baixo a médio: tráfego não criptografado sujeito a interceptação."
    if "cve" in text or "depend" in text or "library" in text:
        return "Depende da severidade da CVE; vulnerabilidades conhecidas podem ser exploradas remotamente."
    return "Risco a confirmar: depende do contexto real de uso no código."


def _call_pt_retry(prompt, system_prompt, temperature=0.1, max_tokens=1024):
    """
    Chama a IA e, se a resposta vier em inglês, tenta UMA segunda chamada
    reforçando que a resposta deve ser em pt-BR (mantém a qualidade da IA).
    """
    text = clean_text(
        call_deepseek(
            prompt=prompt,
            system_prompt=system_prompt,
            temperature=temperature,
            max_tokens=max_tokens,
        )
    )
    if not _is_mostly_english(text):
        return text

    retry_prompt = (
        prompt
        + "\n\nIMPORTANTE: a resposta anterior veio em inglês. "
        "Responda novamente TODA a resposta em português brasileiro (pt-BR)."
    )
    return clean_text(
        call_deepseek(
            prompt=retry_prompt,
            system_prompt=system_prompt,
            temperature=temperature,
            max_tokens=max_tokens,
        )
    )


def _parse_ai_response(text, fallback):
    """
    Extrai as seções da resposta e troca por fallback local (sempre pt-BR)
    qualquer seção que ainda esteja em inglês — a checagem é por seção, não
    sobre o texto inteiro, para não ser diluída por seções em português.
    """
    explicacao = extract_section(text, ["EXPLICACAO", "EXPLICAÇÃO"])
    risco = extract_section(text, ["RISCO"])
    correcao = extract_section(text, ["CORRECAO", "CORREÇÃO"])

    if explicacao and _is_mostly_english(explicacao):
        explicacao = None
    if risco and _is_mostly_english(risco):
        risco = None
    if correcao and _is_mostly_english(correcao):
        correcao = None

    return {
        "explicacao": explicacao or fallback["explicacao"],
        "risco": risco or fallback["risco"],
        "correcao": correcao or fallback["correcao"],
    }


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

    # Fallback geral: usa a humanização pt-BR para explicar e estimar risco/correção
    try:
        from src.core.mensagens_pt import humanize_auto

        titulo_pt, descricao_pt = humanize_auto(title, description)
    except Exception:
        titulo_pt, descricao_pt = title, description

    return {
        "explicacao": descricao_pt or f"O item ({titulo_pt}) pode representar uma fragilidade de segurança.",
        "risco": _risco_from_text(f"{title} {description}"),
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

IMPORTANTE: responda SEMPRE em português brasileiro (pt-BR). Se o texto de
entrada estiver em inglês, traduza o conteúdo da sua resposta para português.

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
- Responda em PORTUGUÊS BRASILEIRO, mesmo que o input esteja em inglês
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

            # Contenção de path (repo_root=None → cwd do dashboard, que é a raiz
            # do projeto): caminhos absolutos e com ".." são rejeitados.
            snippet = extract_code_snippet(file_path, line_number)
            if not snippet:
                # Snippet inválido/rejeitado: não envia conteúdo de arquivo à API.
                return local_ai_fallback(title, description)

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

        text = _call_pt_retry(prompt, system_prompt)
        fallback = local_ai_fallback(title, description)

        # Seção a seção: o que estiver em inglês (mesmo após o retry) é
        # substituído pelo fallback local, que é sempre em pt-BR.
        result = _parse_ai_response(text, fallback)

        # Memória da IA: persiste a análise para consulta posterior
        _save_memory(title, "achado", result)
        return result

    except Exception:
        return local_ai_fallback(title, description)


def _save_memory(title, category, result):
    """Salva a análise da IA no histórico (memória). Falhas são ignoradas."""
    try:
        from dashboard.db import save_ai_memory

        resumo = (
            f"Explicação: {result.get('explicacao', '')} | "
            f"Risco: {result.get('risco', '')} | "
            f"Correção: {result.get('correcao', '')}"
        )
        save_ai_memory(title, category, resumo)
    except Exception:
        pass


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

        text = _call_pt_retry(
            prompt,
            system_prompt,
            temperature=0.1,
            max_tokens=1024,
        )

        # Mesmo após o retry, se ainda vier em inglês, garante pt-BR.
        if _is_mostly_english(text):
            return (
                "O relatório indica riscos distribuídos entre análise estática, "
                "segurança Python, dependências, segredos e exposição de URL. "
                "A prioridade deve ser corrigir riscos altos, revisar endpoints "
                "expostos e manter dependências atualizadas."
            )

        return clean_text(text) if text else "A IA não retornou resumo executivo."

    except Exception:
        return (
            "Não foi possível gerar o resumo executivo com IA. Recomenda-se priorizar os achados "
            "classificados como Alta, revisar exposição externa, corrigir segredos e atualizar dependências vulneráveis."
        )
