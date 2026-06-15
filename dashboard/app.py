import base64
import hashlib
import json
import os
import re
import socket
import sqlite3
import ssl
import sys
from datetime import datetime
from io import BytesIO
from pathlib import Path
from urllib.parse import urlparse

import altair as alt
import pandas as pd
import requests
import streamlit as st
import tldextract
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle

# Garante que o diretório raiz do projeto está no path para imports
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from src.core.ia.deepseek_client import DEEPSEEK_API_KEY, call_deepseek

DB_PATH = "data/history.db"


COMMON_PATHS = [
    "/admin",
    "/login",
    "/dashboard",
    "/robots.txt",
    "/sitemap.xml",
    "/swagger",
    "/swagger-ui",
    "/api",
    "/api/",
    "/api/docs",
    "/graphql",
    "/config",
    "/.env",
    "/phpinfo.php",
    "/backup",
    "/backups",
    "/test",
    "/dev",
    "/debug",
    "/server-status",
    "/wp-admin",
    "/wp-login.php",
    "/administrator",
]


ADMIN_INDICATORS = [
    "admin panel",
    "administrator",
    "painel administrativo",
    "área administrativa",
    "dashboard administrativo",
    "admin dashboard",
    "manage users",
    "gerenciar usuários",
    "user management",
    "controle de acesso",
]


PUBLIC_CONTENT_INDICATORS = [
    "notícia",
    "news",
    "blog",
    "matéria",
    "artigo",
    "faculdade",
    "universidade",
    "curso",
    "graduação",
    "administração",
    "institucional",
    "sobre nós",
    "portal",
    "aluno",
    "conteúdo",
    "educação",
    "fiap",
]


TECHNICAL_EXPOSURE_INDICATORS = [
    "index of /",
    "directory listing",
    "api documentation",
    "swagger ui",
    "openapi",
    "graphql playground",
    "phpinfo()",
    "database error",
    "stack trace",
    "traceback",
    "debug mode",
    "environment",
    "secret_key",
    "db_password",
    "aws_access_key",
    "private key",
]


# Evidências fortes de vazamento sensível.
# Essas regras ajudam a diferenciar uma página pública comum de uma vulnerabilidade real.
SENSITIVE_EVIDENCE_PATTERNS = [
    "DB_PASSWORD",
    "DATABASE_URL",
    "SECRET_KEY",
    "AWS_ACCESS_KEY",
    "AWS_SECRET_ACCESS_KEY",
    "PRIVATE KEY",
    "BEGIN RSA PRIVATE KEY",
    "BEGIN OPENSSH PRIVATE KEY",
    "API_KEY",
    "ACCESS_TOKEN",
    "GITHUB_TOKEN",
    "JWT_SECRET",
    "password=",
    "passwd=",
    "db_user",
    "db_pass",
    "authorization: bearer",
]

# Regex para identificar segredos com padrão mais realista.
# Isso reduz falso positivo porque procura formatos comuns de chaves reais.
SECRET_REGEX_PATTERNS = [
    r"AKIA[0-9A-Z]{16}",
    r"ghp_[A-Za-z0-9_]{30,}",
    r"AIza[0-9A-Za-z\-_]{30,}",
    r"-----BEGIN (RSA|OPENSSH|EC|DSA) PRIVATE KEY-----",
    r"(?i)(secret|token|password|passwd|api_key|apikey)\s*[:=]\s*['\"][^'\"]{8,}['\"]",
]


def init_db():
    os.makedirs("data", exist_ok=True)

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS url_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT,
            url TEXT,
            final_url TEXT,
            score INTEGER,
            classification TEXT,
            high_count INTEGER,
            medium_count INTEGER,
            low_count INTEGER
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT,
            total_findings INTEGER,
            high_count INTEGER,
            medium_count INTEGER,
            low_count INTEGER,
            semgrep_count INTEGER DEFAULT 0,
            bandit_count INTEGER DEFAULT 0,
            sca_count INTEGER DEFAULT 0,
            secrets_count INTEGER DEFAULT 0,
            score_geral INTEGER DEFAULT 0,
            classificacao TEXT DEFAULT 'N/A'
        )
    """)

    conn.commit()
    conn.close()


def save_url_history(
    url, final_url, score, classification, high_count, medium_count, low_count
):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute(
        """
        INSERT INTO url_history (
            created_at, url, final_url, score, classification,
            high_count, medium_count, low_count
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """,
        (
            datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            url,
            final_url,
            score,
            classification,
            high_count,
            medium_count,
            low_count,
        ),
    )

    conn.commit()
    conn.close()


def load_url_history():
    conn = sqlite3.connect(DB_PATH)
    df = pd.read_sql_query("SELECT * FROM url_history ORDER BY id DESC", conn)
    conn.close()
    return df


def auto_save_url_scan_once(result, high_count, medium_count, low_count):
    """
    Salva automaticamente a análise de URL uma única vez por execução.
    Isso garante que o histórico apareça sem depender de clique manual.
    """
    if not result:
        return

    unique_key = f"{result.get('url_inicial')}|{result.get('url_final')}|{result.get('score')}|{high_count}|{medium_count}|{low_count}"

    if unique_key in st.session_state.saved_url_scans:
        return

    save_url_history(
        url=result["url_inicial"],
        final_url=result["url_final"],
        score=result["score"],
        classification=result["classificacao"],
        high_count=high_count,
        medium_count=medium_count,
        low_count=low_count,
    )

    st.session_state.saved_url_scans.add(unique_key)


def clear_url_history():
    """
    Limpa todo o histórico de análises de URL.
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM url_history")
    conn.commit()
    conn.close()


def save_scan_history(total, high, medium, low, semgrep_c, bandit_c, sca_c, secrets_c):
    """Salva resultado de scan completo no histórico global."""
    score, classificacao = calculate_general_score(high, medium, low)
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        """
        INSERT INTO scan_history
            (created_at, total_findings, high_count, medium_count, low_count,
             semgrep_count, bandit_count, sca_count, secrets_count,
             score_geral, classificacao)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """,
        (
            datetime.now().strftime("%Y-%m-%d %H:%M"),
            total,
            high,
            medium,
            low,
            semgrep_c,
            bandit_c,
            sca_c,
            secrets_c,
            score,
            classificacao,
        ),
    )
    conn.commit()
    conn.close()


def load_scan_history():
    """Carrega histórico global de scans."""
    conn = sqlite3.connect(DB_PATH)
    df = pd.read_sql_query("SELECT * FROM scan_history ORDER BY id DESC", conn)
    conn.close()
    return df


def correlate_findings(semgrep_df, bandit_df, sca_df, secrets_df, url_findings):
    """
    Correlaciona achados entre ferramentas para identificar riscos combinados.
    Exemplo: endpoint admin exposto + segredo vazado = prioridade máxima.
    """
    correlacoes = []

    # 1. Segredos + qualquer achado alto = crítico
    if not secrets_df.empty and (not semgrep_df.empty or not bandit_df.empty):
        correlacoes.append(
            {
                "risco": "Código com segredos expostos e vulnerabilidades ativas",
                "evidencias": f"{len(secrets_df)} segredo(s) + {len(semgrep_df) + len(bandit_df)} achado(s) SAST",
                "prioridade": "Alta",
                "acao": "Remover segredos do código antes de corrigir vulnerabilidades",
            }
        )

    # 2. SCA crítico + segredos = supply chain + credential leak
    if not sca_df.empty and not secrets_df.empty:
        sca_altas = (
            len(sca_df[sca_df["Prioridade"] == "Alta"])
            if "Prioridade" in sca_df.columns
            else 0
        )
        if sca_altas > 0:
            correlacoes.append(
                {
                    "risco": "Dependências vulneráveis combinadas com credenciais expostas",
                    "evidencias": f"{sca_altas} CVE(s) crítica(s) + {len(secrets_df)} segredo(s)",
                    "prioridade": "Alta",
                    "acao": "Atualizar dependências críticas e rodar Gitleaks no repositório",
                }
            )

    # 3. URL: endpoint exposto + segredo = superfície de ataque
    if url_findings:
        expostos = [
            f
            for f in url_findings
            if f.get("Status") in ["Expõe", "Expõe recurso"]
            or f.get("Prioridade") == "Alta"
        ]
        if expostos and not secrets_df.empty:
            correlacoes.append(
                {
                    "risco": "Endpoint exposto com credenciais no repositório",
                    "evidencias": f"{len(expostos)} endpoint(s) exposto(s) + {len(secrets_df)} segredo(s)",
                    "prioridade": "Crítica",
                    "acao": "Revisar acesso ao endpoint e rodar scan de segredos imediatamente",
                }
            )

    # 4. Muitos achados de várias fontes = postura fraca
    fontes_com_achados = sum(
        [
            not semgrep_df.empty,
            not bandit_df.empty,
            not sca_df.empty,
            not secrets_df.empty,
            bool(url_findings),
        ]
    )
    if fontes_com_achados >= 3:
        total = (
            len(semgrep_df)
            + len(bandit_df)
            + len(sca_df)
            + len(secrets_df)
            + len(url_findings)
        )
        if total > 10:
            correlacoes.append(
                {
                    "risco": "Postura de segurança fragilizada em múltiplas camadas",
                    "evidencias": f"{fontes_com_achados} fontes com achados - {total} no total",
                    "prioridade": "Alta",
                    "acao": "Estabelecer programa de remediação por prioridade: segredos > SAST > SCA",
                }
            )

    return correlacoes


def clean_text(text):
    if not isinstance(text, str):
        return text

    replacements = {
        "Poss├â┬¡vel": "Possível",
        "execu├º├úo": "execução",
        "usu├írio": "usuário",
        "fun├º├Áes": "funções",
        "seguran├ºa": "segurança",
    }

    for wrong, right in replacements.items():
        text = text.replace(wrong, right)

    return text


def normalize_url(url):
    url = url.strip()

    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    return url


def get_base_domain(url):
    parsed = urlparse(url)
    extracted = tldextract.extract(parsed.netloc)

    if extracted.domain and extracted.suffix:
        return f"{extracted.domain}.{extracted.suffix}"

    return parsed.netloc


def strip_html(html):
    if not html:
        return ""

    html = re.sub(r"<script.*?</script>", " ", html, flags=re.DOTALL | re.IGNORECASE)
    html = re.sub(r"<style.*?</style>", " ", html, flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r"<[^>]+>", " ", html)
    text = re.sub(r"\s+", " ", text)

    return text.strip()


def extract_html_title(html):
    if not html:
        return ""

    match = re.search(r"<title>(.*?)</title>", html, flags=re.DOTALL | re.IGNORECASE)

    if not match:
        return ""

    return strip_html(match.group(1))


def has_login_form(html):
    if not html:
        return False

    html_lower = html.lower()

    has_form = "<form" in html_lower
    has_password = 'type="password"' in html_lower or "type='password'" in html_lower
    has_user_field = (
        "username" in html_lower
        or "email" in html_lower
        or "login" in html_lower
        or "usuario" in html_lower
        or "usuário" in html_lower
        or "user_login" in html_lower
    )

    return has_form and has_password and has_user_field


def count_indicators(text, indicators):
    text = str(text).lower()
    return sum(1 for indicator in indicators if indicator.lower() in text)


def find_evidence(text, indicators):
    """
    Procura evidências textuais em um conteúdo e retorna os indicadores encontrados.
    Diferente de contar palavras, essa função guarda exatamente o que foi encontrado
    para mostrar no dashboard e justificar a classificação.
    """
    found = []
    raw_text = str(text)

    for indicator in indicators:
        if indicator.lower() in raw_text.lower():
            found.append(indicator)

    return sorted(set(found))


def find_regex_evidence(text):
    """
    Procura evidências por regex, como chaves AWS, tokens GitHub e chaves privadas.
    Esses padrões são sinais mais fortes de vazamento real do que apenas encontrar
    uma rota chamada /admin ou /api.
    """
    found = []
    raw_text = str(text)

    for pattern in SECRET_REGEX_PATTERNS:
        if re.search(pattern, raw_text):
            found.append(pattern)

    return sorted(set(found))


def is_probably_json_or_api_response(content_type, body):
    """
    Detecta resposta com aparência real de API ou documentação técnica.
    Uma rota /api só vira achado ativo se tiver conteúdo técnico real,
    como JSON, OpenAPI, Swagger ou GraphQL.
    """
    body = str(body).strip()
    content_type = str(content_type).lower()

    if "application/json" in content_type:
        return True

    if body.startswith("{") or body.startswith("["):
        return True

    if '"openapi"' in body.lower() or '"swagger"' in body.lower():
        return True

    return False


def build_evidence_summary(evidences):
    """
    Monta um texto amigável para a coluna Evidências.
    """
    if not evidences:
        return "Nenhuma evidência forte encontrada."

    return ", ".join(sorted(set(evidences)))


def classify_discovered_endpoint(path, target, status, html, content_type, final_url):
    """
    Classifica endpoints encontrados pelo discovery usando evidências reais.

    Regra central:
    - O nome da rota não prova vulnerabilidade.
    - /admin, /dashboard, /api, /dev e /wp-admin só viram problema se houver evidência.
    - Login comum, WordPress login, 401/403, robots.txt e páginas públicas são separados
      como falso positivo automático quando não há vazamento ou exposição técnica.

    Tipos retornados:
    - Achado Ativo: entra no score.
    - Melhoria Recomendada: hardening, não vulnerabilidade confirmada.
    - Falso Positivo Automático: não entra no score.
    - Controle OK: não entra no score.
    """
    title = extract_html_title(html)
    text = strip_html(html)
    combined = f"{title} {text}"
    combined_lower = combined.lower()
    final_url_lower = str(final_url).lower()

    sensitive_evidence = find_evidence(html, SENSITIVE_EVIDENCE_PATTERNS)
    regex_evidence = find_regex_evidence(html)
    technical_evidence = find_evidence(combined, TECHNICAL_EXPOSURE_INDICATORS)
    public_score = count_indicators(combined, PUBLIC_CONTENT_INDICATORS)
    login_form = has_login_form(html)
    api_like_response = is_probably_json_or_api_response(content_type, html)

    evidences = sorted(set(sensitive_evidence + regex_evidence + technical_evidence))

    # 401/403 normalmente significam bloqueio, não vazamento.
    if status in [401, 403]:
        return {
            "tipo": "Falso Positivo Automático",
            "priority": "Baixa",
            "status_text": f"Acesso bloqueado ou protegido ({status})",
            "reason": (
                f"O endpoint {path} respondeu {status}, indicando restrição de acesso. "
                f"Não houve evidência de conteúdo sensível exposto."
            ),
            "evidencias": [],
        }

    # robots.txt e sitemap.xml são esperados em sites públicos.
    if path in ["/robots.txt", "/sitemap.xml"]:
        if sensitive_evidence or regex_evidence:
            return {
                "tipo": "Achado Ativo",
                "priority": "Média",
                "status_text": f"Possível referência sensível ({status})",
                "reason": f"O arquivo {path} é público e contém possíveis referências sensíveis.",
                "evidencias": sensitive_evidence + regex_evidence,
            }

        return {
            "tipo": "Falso Positivo Automático",
            "priority": "Baixa",
            "status_text": f"Arquivo público esperado ({status})",
            "reason": f"O arquivo {path} é comum em sites públicos e não representa vulnerabilidade crítica sozinho.",
            "evidencias": [],
        }

    # WordPress login/admin comum não é falha sem evidência.
    if path in ["/wp-admin", "/wp-login.php"]:
        if evidences:
            return {
                "tipo": "Achado Ativo",
                "priority": "Média",
                "status_text": f"WordPress com evidência técnica ({status})",
                "reason": f"O endpoint {path} apresentou evidência técnica ou sensível que exige revisão.",
                "evidencias": evidences,
            }

        return {
            "tipo": "Falso Positivo Automático",
            "priority": "Baixa",
            "status_text": f"Login WordPress esperado ({status})",
            "reason": (
                f"O endpoint {path} indica presença de WordPress/login, mas não há evidência de bypass, "
                f"acesso sem autenticação, enumeração ou falha explorável."
            ),
            "evidencias": [],
        }

    # APIs e documentações só são achado se houver API real exposta.
    if path in ["/api", "/api/", "/api/docs", "/swagger", "/swagger-ui", "/graphql"]:
        if sensitive_evidence or regex_evidence:
            return {
                "tipo": "Achado Ativo",
                "priority": "Alta",
                "status_text": f"API com possível dado sensível ({status})",
                "reason": f"O endpoint {path} aparenta conter dado sensível.",
                "evidencias": sensitive_evidence + regex_evidence,
            }

        if (
            api_like_response
            or "swagger ui" in combined_lower
            or "openapi" in combined_lower
            or "graphql playground" in combined_lower
            or "graphiql" in combined_lower
        ):
            return {
                "tipo": "Achado Ativo",
                "priority": "Média",
                "status_text": f"Documentação/API exposta ({status})",
                "reason": f"O endpoint {path} aparenta expor documentação técnica ou interface de API.",
                "evidencias": technical_evidence
                or ["Resposta com aparência de API/documentação técnica"],
            }

        return {
            "tipo": "Falso Positivo Automático",
            "priority": "Baixa",
            "status_text": f"Sem evidência de API exposta ({status})",
            "reason": (
                f"O endpoint {path} respondeu, mas não apresentou JSON técnico, OpenAPI, Swagger, "
                f"GraphQL Playground, endpoints exploráveis ou dados sensíveis."
            ),
            "evidencias": [],
        }

    # Admin, login e dashboard: login comum não é vulnerabilidade.
    if path in ["/admin", "/login", "/dashboard", "/administrator"]:
        if "wp-login.php" in final_url_lower:
            return {
                "tipo": "Falso Positivo Automático",
                "priority": "Baixa",
                "status_text": f"Redireciona para login esperado ({status})",
                "reason": (
                    f"O endpoint {path} redirecionou para wp-login.php. Isso indica tela de login comum, "
                    f"não vulnerabilidade confirmada."
                ),
                "evidencias": [],
            }

        if sensitive_evidence or regex_evidence:
            return {
                "tipo": "Achado Ativo",
                "priority": "Alta",
                "status_text": f"Dado sensível em área sensível ({status})",
                "reason": f"O endpoint {path} apresentou possíveis dados sensíveis.",
                "evidencias": sensitive_evidence + regex_evidence,
            }

        if technical_evidence:
            return {
                "tipo": "Achado Ativo",
                "priority": "Média",
                "status_text": f"Evidência técnica em área sensível ({status})",
                "reason": f"O endpoint {path} contém sinais técnicos de exposição.",
                "evidencias": technical_evidence,
            }

        if login_form:
            return {
                "tipo": "Falso Positivo Automático",
                "priority": "Baixa",
                "status_text": f"Tela de login identificada ({status})",
                "reason": (
                    f"O endpoint {path} possui formulário de login, mas login comum não prova vulnerabilidade, "
                    f"bypass ou acesso indevido."
                ),
                "evidencias": [],
            }

        if public_score > 0:
            return {
                "tipo": "Falso Positivo Automático",
                "priority": "Baixa",
                "status_text": f"Página pública ou institucional ({status})",
                "reason": (
                    f"O endpoint {path} respondeu, mas o conteúdo parece público, institucional "
                    f"ou informativo."
                ),
                "evidencias": [],
            }

        return {
            "tipo": "Falso Positivo Automático",
            "priority": "Baixa",
            "status_text": f"Inconclusivo sem evidência crítica ({status})",
            "reason": (
                f"O endpoint {path} respondeu, mas não há evidência de acesso indevido, vazamento, "
                f"debug, erro interno ou painel administrativo acessível."
            ),
            "evidencias": [],
        }

    # dev, test e debug só são achado se tiver evidência técnica real.
    if path in ["/dev", "/test", "/debug"]:
        if sensitive_evidence or regex_evidence:
            return {
                "tipo": "Achado Ativo",
                "priority": "Alta",
                "status_text": f"Possível vazamento em endpoint técnico ({status})",
                "reason": f"O endpoint {path} apresentou possíveis dados sensíveis.",
                "evidencias": sensitive_evidence + regex_evidence,
            }

        if technical_evidence:
            return {
                "tipo": "Achado Ativo",
                "priority": "Alta",
                "status_text": f"Recurso técnico exposto ({status})",
                "reason": f"O endpoint {path} apresenta sinais técnicos como debug, stack trace, ambiente ou erro interno.",
                "evidencias": technical_evidence,
            }

        return {
            "tipo": "Falso Positivo Automático",
            "priority": "Baixa",
            "status_text": f"Sem evidência técnica crítica ({status})",
            "reason": (
                f"O endpoint {path} respondeu, mas não apresentou debug, stack trace, arquivos internos "
                f"ou dados sensíveis."
            ),
            "evidencias": [],
        }

    # Arquivos sensíveis só são achado se o conteúdo realmente parecer sensível.
    if path in ["/.env", "/config", "/backup", "/backups", "/phpinfo.php"]:
        if sensitive_evidence or regex_evidence or technical_evidence:
            return {
                "tipo": "Achado Ativo",
                "priority": "Alta",
                "status_text": f"Exposição sensível ({status})",
                "reason": f"O endpoint {path} aparenta expor informação técnica ou configuração sensível.",
                "evidencias": evidences,
            }

        return {
            "tipo": "Falso Positivo Automático",
            "priority": "Baixa",
            "status_text": f"Sem evidência sensível ({status})",
            "reason": f"O endpoint {path} respondeu, mas não há evidência suficiente de vazamento sensível.",
            "evidencias": [],
        }

    if status in [301, 302]:
        return {
            "tipo": "Falso Positivo Automático",
            "priority": "Baixa",
            "status_text": f"Redireciona ({status})",
            "reason": f"O endpoint {path} apenas redireciona e não apresentou evidência direta de exposição sensível.",
            "evidencias": [],
        }

    return {
        "tipo": "Falso Positivo Automático",
        "priority": "Baixa",
        "status_text": f"Sem evidência crítica ({status})",
        "reason": f"O endpoint {path} respondeu, mas não há evidência suficiente para classificar como vulnerabilidade real.",
        "evidencias": [],
    }


def generate_pdf_report(title, summary, dataframe):
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4)

    styles = getSampleStyleSheet()
    elements = []

    elements.append(Paragraph(title, styles["Title"]))
    elements.append(Spacer(1, 12))
    elements.append(Paragraph(summary, styles["BodyText"]))
    elements.append(Spacer(1, 12))

    if not dataframe.empty:
        table_data = [list(dataframe.columns)] + dataframe.astype(str).values.tolist()
        table = Table(table_data, repeatRows=1)

        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 7),
                ]
            )
        )

        elements.append(table)

    doc.build(elements)
    buffer.seek(0)

    return buffer


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
def ask_ai(title, description):
    """
    Usa DeepSeek para analisar achados com contexto decisório.
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

Regras obrigatórias:
- Se o item for "Controle OK", apenas confirme que está correto
- Se for "Falso Positivo Automático", explique por que não é vulnerabilidade
- Se for "Melhoria Recomendada" (ex: header CSP ausente), trate como hardening, não como vulnerabilidade
- NUNCA invente informações que não estejam na descrição
- Responda EXATAMENTE no formato abaixo
""".strip()

    try:
        prompt = f"""
Analise o item abaixo e retorne no formato exato solicitado.

TÍTULO:
{title}

DESCRIÇÃO:
{description}

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


def load_json(file_path, default=None):
    if default is None:
        default = {}

    if not os.path.exists(file_path):
        return default

    with open(file_path, "r", encoding="utf-8-sig") as f:
        return json.load(f)


def classify_semgrep_priority(severity):
    if severity == "ERROR":
        return "Alta"
    if severity == "WARNING":
        return "Média"
    return "Baixa"


def classify_bandit_priority(severity):
    severity = str(severity).upper()

    if severity == "HIGH":
        return "Alta"
    if severity == "MEDIUM":
        return "Média"
    return "Baixa"


def classify_sca_priority(vuln_id):
    vuln_id = str(vuln_id).upper()

    if "CVE" in vuln_id:
        return "Alta"

    if "JWT" in vuln_id:
        return "Alta"

    if "SSTI" in vuln_id:
        return "Alta"

    return "Média"


def get_semgrep_vulnerabilities(data):
    results = data.get("results", [])
    vulns = []

    for item in results:
        severity = item.get("extra", {}).get("severity")
        check_id = item.get("check_id")
        message = clean_text(item.get("extra", {}).get("message"))
        priority = classify_semgrep_priority(severity)

        ai_data = ask_ai(check_id, message)

        vulns.append(
            {
                "ID": check_id,
                "Arquivo": item.get("path"),
                "Linha": item.get("start", {}).get("line"),
                "Severidade": severity,
                "Prioridade": priority,
                "Descrição": message,
                "Explicação IA": ai_data["explicacao"],
                "Risco IA": ai_data["risco"],
                "Correção IA": ai_data["correcao"],
            }
        )

    return vulns


def get_bandit_vulnerabilities(data):
    results = data.get("results", [])
    vulns = []

    for item in results:
        test_name = item.get("test_name")
        severity = item.get("issue_severity")
        confidence = item.get("issue_confidence")
        text = clean_text(item.get("issue_text"))
        priority = classify_bandit_priority(severity)

        ai_data = ask_ai(test_name, text)

        vulns.append(
            {
                "Teste": test_name,
                "Arquivo": item.get("filename"),
                "Linha": item.get("line_number"),
                "Severidade": severity,
                "Confiança": confidence,
                "Prioridade": priority,
                "Descrição": text,
                "Explicação IA": ai_data["explicacao"],
                "Risco IA": ai_data["risco"],
                "Correção IA": ai_data["correcao"],
            }
        )

    return vulns


def get_sca_vulnerabilities(data):
    vulns = []
    dependencies = data.get("dependencies", [])

    for dep in dependencies:
        name = dep.get("name")
        version = dep.get("version")

        for vuln in dep.get("vulns", []):
            vuln_id = vuln.get("id")
            description = clean_text(vuln.get("description"))
            fixes = vuln.get("fix_versions", [])

            fixed_version = fixes[0] if fixes else "Não informado"
            priority = classify_sca_priority(vuln_id)

            ai_data = ask_ai(vuln_id, description)

            vulns.append(
                {
                    "Biblioteca": name,
                    "Versão Atual": version,
                    "CVE": vuln_id,
                    "Prioridade": priority,
                    "Correção Disponível": fixed_version,
                    "Descrição": description,
                    "Explicação IA": ai_data["explicacao"],
                    "Risco IA": ai_data["risco"],
                    "Correção IA": ai_data["correcao"],
                }
            )

    return vulns


# ============================================================
# SECRETS SCANNER
# ============================================================
# Esta seção adiciona uma camada típica de ASPM:
# detecção de segredos em código-fonte ou JSON do Gitleaks.
# Ela é defensiva e serve para identificar credenciais expostas no próprio projeto.

SECRET_RULES = [
    {
        "id": "AWS_ACCESS_KEY_ID",
        "descricao": "Possível chave de acesso AWS encontrada.",
        "regex": r"AKIA[0-9A-Z]{16}",
        "prioridade": "Alta",
    },
    {
        "id": "GITHUB_TOKEN",
        "descricao": "Possível token do GitHub encontrado.",
        "regex": r"ghp_[A-Za-z0-9_]{30,}",
        "prioridade": "Alta",
    },
    {
        "id": "GOOGLE_API_KEY",
        "descricao": "Possível chave de API do Google encontrada.",
        "regex": r"AIza[0-9A-Za-z\-_]{30,}",
        "prioridade": "Alta",
    },
    {
        "id": "PRIVATE_KEY",
        "descricao": "Possível chave privada encontrada.",
        "regex": r"-----BEGIN (RSA|OPENSSH|EC|DSA) PRIVATE KEY-----",
        "prioridade": "Alta",
    },
    {
        "id": "GENERIC_SECRET_ASSIGNMENT",
        "descricao": "Possível segredo definido diretamente no código.",
        "regex": r"(?i)(secret|token|password|passwd|api_key|apikey|client_secret)\s*[:=]\s*['\"][^'\"]{8,}['\"]",
        "prioridade": "Média",
    },
    {
        "id": "DATABASE_URL",
        "descricao": "Possível string de conexão de banco de dados encontrada.",
        "regex": r"(?i)(postgres|mysql|mongodb|redis)://[^\s'\"]+",
        "prioridade": "Alta",
    },
    {
        "id": "JWT_TOKEN",
        "descricao": "Possível token JWT encontrado.",
        "regex": r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}",
        "prioridade": "Média",
    },
]


def mask_secret(value):
    """
    Mascara o segredo para evitar exibir credenciais completas no dashboard.
    """
    value = str(value)

    if len(value) <= 10:
        return "***"

    return value[:4] + "***" + value[-4:]


def get_line_number(text, index):
    """
    Calcula a linha aproximada onde o segredo foi encontrado.
    """
    return text[:index].count("\n") + 1


def scan_text_for_secrets(filename, text):
    """
    Procura segredos em um arquivo de texto usando regex.
    """
    findings = []

    for rule in SECRET_RULES:
        for match in re.finditer(rule["regex"], text):
            secret_value = match.group(0)
            line_number = get_line_number(text, match.start())

            findings.append(
                {
                    "Origem": "Scanner Interno",
                    "Regra": rule["id"],
                    "Arquivo": filename,
                    "Linha": line_number,
                    "Prioridade": rule["prioridade"],
                    "Segredo Mascarado": mask_secret(secret_value),
                    "Descrição": rule["descricao"],
                }
            )

    return findings


def scan_uploaded_files_for_secrets(uploaded_files):
    """
    Escaneia arquivos enviados manualmente na aba Secrets.
    Arquivos binários são ignorados.
    """
    findings = []

    for uploaded_file in uploaded_files:
        try:
            raw = uploaded_file.getvalue()

            try:
                text = raw.decode("utf-8")
            except UnicodeDecodeError:
                text = raw.decode("latin-1", errors="ignore")

            findings.extend(scan_text_for_secrets(uploaded_file.name, text))

        except Exception:
            pass

    return findings


def parse_gitleaks_json(data):
    """
    Converte JSON do Gitleaks para o formato padrão do dashboard.
    O Gitleaks normalmente retorna uma lista de achados.
    """
    findings = []

    if isinstance(data, dict):
        possible_items = data.get("findings") or data.get("results") or []
    elif isinstance(data, list):
        possible_items = data
    else:
        possible_items = []

    for item in possible_items:
        rule = (
            item.get("RuleID")
            or item.get("rule")
            or item.get("Rule")
            or "GITLEAKS_SECRET"
        )
        description = (
            item.get("Description")
            or item.get("description")
            or "Possível segredo detectado pelo Gitleaks."
        )
        file_path = (
            item.get("File") or item.get("file") or item.get("path") or "Não informado"
        )
        line = (
            item.get("StartLine")
            or item.get("Line")
            or item.get("line")
            or "Não informado"
        )
        secret = item.get("Secret") or item.get("secret") or ""

        findings.append(
            {
                "Origem": "Gitleaks",
                "Regra": rule,
                "Arquivo": file_path,
                "Linha": line,
                "Prioridade": "Alta",
                "Segredo Mascarado": mask_secret(secret),
                "Descrição": description,
            }
        )

    return findings


def calculate_secret_counts(secret_df):
    """
    Calcula contadores da aba Secrets.
    """
    if secret_df.empty:
        return 0, 0, 0

    high = secret_df[secret_df["Prioridade"] == "Alta"].shape[0]
    medium = secret_df[secret_df["Prioridade"] == "Média"].shape[0]
    low = secret_df[secret_df["Prioridade"] == "Baixa"].shape[0]

    return high, medium, low


def check_port(host, port, timeout=3):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return "Aberta"
    except Exception:
        return "Fechada"


def check_ssl_certificate(host):
    try:
        context = ssl.create_default_context()

        with socket.create_connection((host, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=host) as secure_sock:
                cert = secure_sock.getpeercert()

        not_after = cert.get("notAfter")
        expiration = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
        days_left = (expiration - datetime.utcnow()).days

        if days_left >= 30:
            priority = "Baixa"
            status = "Válido"
            tipo = "Controle OK"
        elif days_left >= 0:
            priority = "Média"
            status = "Expirando"
            tipo = "Achado Ativo"
        else:
            priority = "Alta"
            status = "Expirado"
            tipo = "Achado Ativo"

        return {
            "status": status,
            "priority": priority,
            "description": f"Certificado TLS com {days_left} dias restantes.",
            "tipo": tipo,
        }

    except Exception as e:
        return {
            "status": "Erro",
            "priority": "Média",
            "description": str(e),
            "tipo": "Achado Ativo",
        }


def make_url_finding(
    category, item, status, priority, description, tipo="Achado Ativo", evidencias=None
):
    """
    Cria um item padronizado para URL Analysis.

    Campos:
    - Tipo: Achado Ativo, Melhoria Recomendada, Controle OK ou Falso Positivo Automático.
    - Evidências: mostra por que algo foi classificado como risco real.
    """
    if evidencias is None:
        evidencias = []

    return {
        "Tipo": tipo,
        "Categoria": category,
        "Item": item,
        "Status": status,
        "Prioridade": priority,
        "Evidências": build_evidence_summary(evidencias),
        "Descrição": description,
    }


def scan_common_paths(base_url):
    findings = []

    for path in COMMON_PATHS:
        try:
            target = base_url.rstrip("/") + path

            response = requests.get(
                target,
                timeout=5,
                allow_redirects=True,
                headers={"User-Agent": "ASPM-Scanner/1.0"},
            )

            status = response.status_code
            content_type = response.headers.get("Content-Type", "")
            html = response.text[:12000] if response.text else ""
            final_url = response.url

            if status in [200, 301, 302, 401, 403]:
                classification = classify_discovered_endpoint(
                    path=path,
                    target=target,
                    status=status,
                    html=html,
                    content_type=content_type,
                    final_url=final_url,
                )

                tipo = classification["tipo"]
                priority = classification["priority"]
                status_text = classification["status_text"]
                reason = classification["reason"]
                evidencias = classification.get("evidencias", [])

                description = (
                    f"Endpoint analisado: {target}. "
                    f"URL final: {final_url}. "
                    f"Status HTTP: {status}. "
                    f"Content-Type: {content_type}. "
                    f"Análise contextual: {reason}"
                )

                findings.append(
                    make_url_finding(
                        "Discovery",
                        path,
                        status_text,
                        priority,
                        description,
                        tipo,
                        evidencias,
                    )
                )

        except Exception:
            pass

    return findings


def calculate_score(findings):
    score = 100

    for finding in findings:
        if finding.get("Tipo") != "Achado Ativo":
            continue

        if finding["Prioridade"] == "Alta":
            score -= 15
        elif finding["Prioridade"] == "Média":
            score -= 6
        else:
            score -= 1

    score = max(score, 0)

    if score >= 85:
        classification = "Boa"
    elif score >= 65:
        classification = "Atenção"
    else:
        classification = "Crítica"

    return score, classification


def calculate_general_score(total_high, total_medium, total_low):
    score = 100
    score -= total_high * 10
    score -= total_medium * 5
    score -= total_low * 2

    score = max(score, 0)

    if score >= 85:
        classification = "Boa"
    elif score >= 65:
        classification = "Atenção"
    else:
        classification = "Crítica"

    return score, classification


def analyze_url(url):
    url = normalize_url(url)
    findings = []

    try:
        response = requests.get(
            url,
            timeout=10,
            allow_redirects=True,
            headers={"User-Agent": "ASPM-Scanner/1.0"},
        )

        headers = response.headers
        final_url = response.url
        parsed = urlparse(final_url)
        host = parsed.hostname
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        uses_https = parsed.scheme == "https"

        findings.append(
            make_url_finding(
                "HTTPS",
                "HTTPS",
                "OK" if uses_https else "Ausente",
                "Baixa" if uses_https else "Alta",
                "Site utiliza HTTPS." if uses_https else "Site não utiliza HTTPS.",
                "Controle OK" if uses_https else "Achado Ativo",
            )
        )

        if uses_https and host:
            cert_result = check_ssl_certificate(host)
            findings.append(
                make_url_finding(
                    "TLS",
                    "Certificado SSL",
                    cert_result["status"],
                    cert_result["priority"],
                    cert_result["description"],
                    cert_result["tipo"],
                )
            )

        security_headers = {
            "Content-Security-Policy": "Média",
            "Strict-Transport-Security": "Média",
            "X-Frame-Options": "Média",
            "X-Content-Type-Options": "Média",
            "Referrer-Policy": "Baixa",
            "Permissions-Policy": "Baixa",
        }

        for header, priority in security_headers.items():
            if header in headers:
                findings.append(
                    make_url_finding(
                        "Headers",
                        header,
                        "Presente",
                        "Baixa",
                        headers.get(header),
                        "Controle OK",
                    )
                )
            else:
                findings.append(
                    make_url_finding(
                        "Headers",
                        header,
                        "Ausente",
                        priority,
                        f"{header} ausente. Isso representa melhoria de hardening, não vulnerabilidade explorável confirmada.",
                        "Melhoria Recomendada",
                        [f"Header {header} ausente"],
                    )
                )

        if headers.get("Server"):
            findings.append(
                make_url_finding(
                    "Exposição",
                    "Server",
                    "Exposto",
                    "Baixa",
                    headers.get("Server"),
                    "Melhoria Recomendada",
                    ["Header Server exposto"],
                )
            )

        if headers.get("X-Powered-By"):
            findings.append(
                make_url_finding(
                    "Exposição",
                    "X-Powered-By",
                    "Exposto",
                    "Média",
                    headers.get("X-Powered-By"),
                    "Melhoria Recomendada",
                    ["Header X-Powered-By exposto"],
                )
            )

        if host:
            findings.append(
                make_url_finding(
                    "Rede",
                    "Porta 80",
                    check_port(host, 80),
                    "Baixa",
                    "Verificação HTTP.",
                    "Controle OK",
                )
            )

            findings.append(
                make_url_finding(
                    "Rede",
                    "Porta 443",
                    check_port(host, 443),
                    "Baixa",
                    "Verificação HTTPS.",
                    "Controle OK",
                )
            )

        findings.extend(scan_common_paths(base_url))

        score, classification = calculate_score(findings)

        return {
            "url_inicial": url,
            "url_final": final_url,
            "dominio": get_base_domain(final_url),
            "status_code": response.status_code,
            "score": score,
            "classificacao": classification,
            "findings": findings,
        }

    except Exception as e:
        return {
            "url_inicial": url,
            "url_final": "Erro",
            "dominio": "Erro",
            "status_code": "Erro",
            "score": 0,
            "classificacao": "Crítica",
            "findings": [
                make_url_finding(
                    "Erro", "Conexão", "Erro", "Alta", str(e), "Achado Ativo"
                )
            ],
        }


def init_false_positive_state():
    if "false_positives" not in st.session_state:
        st.session_state.false_positives = set()

    if "last_url_scan" not in st.session_state:
        st.session_state.last_url_scan = None

    if "secret_results" not in st.session_state:
        st.session_state.secret_results = []

    if "saved_url_scans" not in st.session_state:
        st.session_state.saved_url_scans = set()


def is_false_positive(unique_id):
    return unique_id in st.session_state.false_positives


def add_false_positive(unique_id):
    st.session_state.false_positives.add(unique_id)


def count_false_positives():
    return len(st.session_state.false_positives)


def filter_false_positives(df, source):
    if df.empty:
        return df

    if source == "semgrep":
        return df[
            ~df.apply(
                lambda row: is_false_positive(
                    f"semgrep_{row['ID']}_{row['Arquivo']}_{row['Linha']}"
                ),
                axis=1,
            )
        ]

    if source == "bandit":
        return df[
            ~df.apply(
                lambda row: is_false_positive(
                    f"bandit_{row['Teste']}_{row['Arquivo']}_{row['Linha']}"
                ),
                axis=1,
            )
        ]

    if source == "sca":
        return df[
            ~df.apply(
                lambda row: is_false_positive(f"sca_{row['Biblioteca']}_{row['CVE']}"),
                axis=1,
            )
        ]

    return df


init_db()

st.set_page_config(page_title="ASPM Enterprise", layout="wide")

init_false_positive_state()

# ============================================================
# VISUAL ENTERPRISE CORRIGIDO
# ============================================================
# Esta camada altera somente o visual do Streamlit.
# A lógica principal do projeto foi preservada:
# - classify_discovered_endpoint()
# - scan_common_paths()
# - analyze_url()
# - calculate_score()
# - Semgrep, Bandit, SCA, IA, histórico e exportações
ENTERPRISE_CSS = """
<style>
    .stApp {
        background:
            radial-gradient(circle at 15% 0%, rgba(56, 189, 248, 0.18), transparent 28%),
            radial-gradient(circle at 84% 4%, rgba(168, 85, 247, 0.16), transparent 30%),
            linear-gradient(180deg, #030712 0%, #07111f 48%, #020617 100%);
        color: #e5e7eb;
    }

    .block-container {
        padding-top: 1.5rem;
        padding-bottom: 3rem;
        max-width: 1500px;
    }

    section[data-testid="stSidebar"] {
        background: linear-gradient(180deg, rgba(2, 6, 23, 0.98), rgba(15, 23, 42, 0.96));
        border-right: 1px solid rgba(148, 163, 184, 0.18);
    }

    section[data-testid="stSidebar"] * {
        color: #e5e7eb;
    }

    h1, h2, h3 {
        color: #f8fafc !important;
        letter-spacing: -0.04em;
        font-weight: 850 !important;
    }

    div[data-testid="stMetric"] {
        background: linear-gradient(180deg, rgba(15, 23, 42, 0.94), rgba(15, 23, 42, 0.60));
        border: 1px solid rgba(148, 163, 184, 0.20);
        border-radius: 24px;
        padding: 1.1rem 1.15rem;
        box-shadow: 0 20px 58px rgba(0, 0, 0, 0.28);
    }

    div[data-testid="stMetricLabel"] p {
        color: #94a3b8 !important;
        font-size: 0.82rem;
        font-weight: 700;
        text-transform: uppercase;
        letter-spacing: 0.05em;
    }

    div[data-testid="stMetricValue"] {
        color: #f8fafc !important;
        font-weight: 900;
    }

    div[data-testid="stDataFrame"] {
        border-radius: 22px;
        overflow: hidden;
        border: 1px solid rgba(148, 163, 184, 0.18);
        box-shadow: 0 18px 55px rgba(0, 0, 0, 0.24);
    }

    .stButton > button,
    .stDownloadButton > button {
        border-radius: 14px;
        border: 1px solid rgba(255,255,255,0.16);
        background: linear-gradient(135deg, #2563eb, #7c3aed);
        color: white;
        font-weight: 800;
        box-shadow: 0 14px 35px rgba(37, 99, 235, 0.30);
    }

    button[data-baseweb="tab"] {
        background: rgba(15, 23, 42, 0.72);
        border: 1px solid rgba(148, 163, 184, 0.18);
        border-radius: 999px;
        padding: 0.62rem 1.05rem;
        margin-right: 0.35rem;
        color: #cbd5e1;
        font-weight: 700;
    }

    button[data-baseweb="tab"][aria-selected="true"] {
        background: linear-gradient(135deg, rgba(37, 99, 235, 0.95), rgba(124, 58, 237, 0.95));
        color: white;
        border-color: rgba(255, 255, 255, 0.24);
        box-shadow: 0 14px 38px rgba(59, 130, 246, 0.25);
    }

    .enterprise-hero {
        padding: 2.1rem;
        border-radius: 32px;
        border: 1px solid rgba(148, 163, 184, 0.20);
        background:
            linear-gradient(135deg, rgba(15, 23, 42, 0.94), rgba(30, 41, 59, 0.74)),
            radial-gradient(circle at top right, rgba(56, 189, 248, 0.26), transparent 35%);
        box-shadow: 0 28px 90px rgba(0, 0, 0, 0.38);
        margin-bottom: 1.5rem;
    }

    .enterprise-eyebrow {
        display: inline-block;
        padding: 0.38rem 0.8rem;
        border-radius: 999px;
        color: #bfdbfe;
        background: rgba(37, 99, 235, 0.18);
        border: 1px solid rgba(96, 165, 250, 0.25);
        font-size: 0.82rem;
        font-weight: 800;
        margin-bottom: 0.9rem;
    }

    .enterprise-title {
        font-size: clamp(2.2rem, 5vw, 4.2rem);
        line-height: 0.95;
        font-weight: 950;
        color: #f8fafc;
        letter-spacing: -0.075em;
        margin: 0;
    }

    .enterprise-gradient {
        background: linear-gradient(135deg, #38bdf8, #a78bfa, #f472b6);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
    }

    .enterprise-subtitle {
        color: #cbd5e1;
        max-width: 980px;
        font-size: 1.02rem;
        line-height: 1.7;
        margin-top: 1rem;
    }

    .enterprise-pill {
        display: inline-block;
        padding: 0.48rem 0.8rem;
        border-radius: 999px;
        background: rgba(15, 23, 42, 0.65);
        border: 1px solid rgba(148, 163, 184, 0.20);
        color: #cbd5e1;
        font-size: 0.78rem;
        font-weight: 800;
        margin-right: 0.45rem;
        margin-top: 0.9rem;
    }

    .enterprise-card {
        padding: 1.25rem;
        border-radius: 24px;
        background: linear-gradient(180deg, rgba(15, 23, 42, 0.86), rgba(15, 23, 42, 0.54));
        border: 1px solid rgba(148, 163, 184, 0.18);
        box-shadow: 0 20px 60px rgba(0, 0, 0, 0.26);
        margin-bottom: 1rem;
    }

    .enterprise-section-title {
        font-size: 1.18rem;
        font-weight: 900;
        color: #f8fafc;
        margin: 0 0 0.45rem 0;
    }

    .enterprise-muted {
        color: #94a3b8;
        font-size: 0.92rem;
        line-height: 1.58;
    }

    .enterprise-sidebar-logo {
        padding: 1rem 0.9rem;
        border-radius: 22px;
        background: linear-gradient(135deg, rgba(37, 99, 235, 0.22), rgba(124, 58, 237, 0.18));
        border: 1px solid rgba(148, 163, 184, 0.20);
        margin-bottom: 1rem;
    }

    .enterprise-sidebar-logo strong {
        font-size: 1.16rem;
        color: #f8fafc;
    }

    .enterprise-sidebar-logo small {
        color: #94a3b8;
    }
</style>
"""


def render_status_card(title, value, description, tone="neutral"):
    """
    Renderiza um card executivo para destacar resultado sem depender de st.metric.
    Usado para resumir Achados Ativos, Melhorias, Controles OK e Falsos Positivos.
    """
    tone_color = {
        "good": "#22c55e",
        "warning": "#f59e0b",
        "critical": "#ef4444",
        "info": "#38bdf8",
        "neutral": "#cbd5e1",
    }.get(tone, "#cbd5e1")

    st.markdown(
        f"""
        <div class="enterprise-card" style="min-height: 135px;">
            <div style="font-size: 0.78rem; color: #94a3b8; font-weight: 900; text-transform: uppercase; letter-spacing: 0.08em;">
                {title}
            </div>
            <div style="font-size: 2.25rem; color: {tone_color}; font-weight: 950; line-height: 1; margin-top: 0.45rem;">
                {value}
            </div>
            <div style="font-size: 0.86rem; color: #cbd5e1; line-height: 1.45; margin-top: 0.75rem;">
                {description}
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_empty_state(title, description, tone="good"):
    """
    Exibe mensagem visual quando uma seção não possui itens.
    Evita tabela vazia aparecendo como 'empty' no dashboard.
    """
    tone_color = "#22c55e" if tone == "good" else "#38bdf8"

    st.markdown(
        f"""
        <div class="enterprise-card" style="border-color: rgba(34, 197, 94, 0.24);">
            <div style="font-size: 1.05rem; color: {tone_color}; font-weight: 900;">
                {title}
            </div>
            <div style="font-size: 0.92rem; color: #cbd5e1; margin-top: 0.4rem; line-height: 1.55;">
                {description}
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_compact_cards(
    df, title_col="Item", subtitle_col="Categoria", status_col="Status", limit=8
):
    """
    Mostra itens em formato de cards compactos antes da tabela.
    Isso deixa a leitura mais executiva e reduz a sensação de lista técnica infinita.
    """
    if df.empty:
        return

    preview_df = df.head(limit)

    for _, item in preview_df.iterrows():
        title = item.get(title_col, "Item")
        subtitle = item.get(subtitle_col, "")
        status = item.get(status_col, "")
        prioridade = item.get("Prioridade", "")
        evidencias = item.get("Evidências", "")

        st.markdown(
            f"""
            <div class="enterprise-card" style="padding: 0.95rem 1rem; margin-bottom: 0.65rem;">
                <div style="display: flex; justify-content: space-between; gap: 1rem; align-items: center;">
                    <div>
                        <div style="font-weight: 900; color: #f8fafc; font-size: 1rem;">{title}</div>
                        <div style="color: #94a3b8; font-size: 0.84rem; margin-top: 0.25rem;">{subtitle} | {status}</div>
                        <div style="color: #cbd5e1; font-size: 0.80rem; margin-top: 0.35rem;">{evidencias}</div>
                    </div>
                    <div style="color: #cbd5e1; font-weight: 800; font-size: 0.86rem; white-space: nowrap;">
                        {prioridade}
                    </div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )


def render_donut_chart(df, category_col, value_col, title):
    """
    Renderiza gráfico de pizza/donut usando Altair.
    Altair costuma vir junto com Streamlit, então evita depender de Plotly.
    """
    try:
        chart_df = df.copy()
        chart_df[value_col] = pd.to_numeric(
            chart_df[value_col], errors="coerce"
        ).fillna(0)

        if chart_df[value_col].sum() <= 0:
            st.info("Sem dados suficientes para gerar o gráfico.")
            return

        chart = (
            alt.Chart(chart_df)
            .mark_arc(innerRadius=72, outerRadius=145, stroke="#020617", strokeWidth=2)
            .encode(
                theta=alt.Theta(field=value_col, type="quantitative"),
                color=alt.Color(
                    field=category_col,
                    type="nominal",
                    legend=alt.Legend(
                        title=None,
                        orient="bottom",
                        labelColor="#cbd5e1",
                        labelFontSize=13,
                    ),
                    scale=alt.Scale(
                        range=[
                            "#ef4444",
                            "#f59e0b",
                            "#38bdf8",
                            "#22c55e",
                            "#a78bfa",
                            "#64748b",
                        ]
                    ),
                ),
                tooltip=[
                    alt.Tooltip(field=category_col, type="nominal", title="Categoria"),
                    alt.Tooltip(
                        field=value_col, type="quantitative", title="Quantidade"
                    ),
                ],
            )
            .properties(height=360, title=title)
            .configure_title(color="#f8fafc", fontSize=18, anchor="start")
            .configure_view(strokeWidth=0)
            .configure(background="transparent")
        )

        st.altair_chart(chart, use_container_width=True)

    except Exception as exc:
        st.warning(f"Não foi possível gerar o gráfico de pizza: {exc}")


def render_source_cards(total_semgrep, total_bandit, total_sca, latest_url_score):
    """
    Mostra fontes integradas como cards, evitando tabela pesada no resumo.
    """
    sources = [
        ("Semgrep", total_semgrep, "Análise estática de código"),
        ("Bandit", total_bandit, "Análise de segurança Python"),
        ("SCA", total_sca, "Bibliotecas e CVEs"),
        ("URL Analysis", latest_url_score, "Headers, TLS e discovery"),
    ]

    cols = st.columns(4)

    for index, (name, value, description) in enumerate(sources):
        with cols[index]:
            st.markdown(
                f"""
                <div class="enterprise-card" style="min-height: 128px;">
                    <div style="font-size: 0.80rem; color: #94a3b8; font-weight: 900; text-transform: uppercase; letter-spacing: 0.08em;">
                        {name}
                    </div>
                    <div style="font-size: 1.7rem; color: #f8fafc; font-weight: 950; margin-top: 0.35rem;">
                        {value}
                    </div>
                    <div style="font-size: 0.84rem; color: #cbd5e1; margin-top: 0.5rem;">
                        {description}
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )


def render_history_cards(history_df):
    """
    Exibe o histórico em cards executivos, antes da tabela técnica.
    """
    if history_df.empty:
        render_empty_state(
            "Nenhuma análise registrada.",
            "Execute uma análise de URL na aba URL Analysis. O histórico é salvo automaticamente.",
            "info",
        )
        return

    preview_df = history_df.head(5)

    for _, row in preview_df.iterrows():
        score = int(row.get("score", 0))
        classification = row.get("classification", "")
        url = row.get("url", "")
        created_at = row.get("created_at", "")
        high_count = row.get("high_count", 0)
        medium_count = row.get("medium_count", 0)
        low_count = row.get("low_count", 0)

        if score >= 85:
            tone_color = "#22c55e"
        elif score >= 65:
            tone_color = "#f59e0b"
        else:
            tone_color = "#ef4444"

        st.markdown(
            f"""
            <div class="enterprise-card" style="padding: 1rem 1.15rem; margin-bottom: 0.75rem;">
                <div style="display: flex; justify-content: space-between; gap: 1rem; align-items: center;">
                    <div>
                        <div style="font-weight: 900; color: #f8fafc; font-size: 1rem;">{url}</div>
                        <div style="color: #94a3b8; font-size: 0.84rem; margin-top: 0.25rem;">{created_at}</div>
                        <div style="color: #cbd5e1; font-size: 0.82rem; margin-top: 0.45rem;">
                            Alta: {high_count} | Média: {medium_count} | Baixa: {low_count}
                        </div>
                    </div>
                    <div style="text-align: right;">
                        <div style="font-size: 1.75rem; color: {tone_color}; font-weight: 950; line-height: 1;">{score}</div>
                        <div style="color: #cbd5e1; font-size: 0.84rem; margin-top: 0.35rem;">{classification}</div>
                    </div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )


def render_table_as_cards(
    df,
    title_key=None,
    subtitle_keys=None,
    badge_key=None,
    description_key=None,
    limit=10,
):
    """
    Renderiza linhas de DataFrame como cards para evitar aparência de planilha.
    A tabela completa continua disponível no expander técnico.
    """
    if df.empty:
        return

    if subtitle_keys is None:
        subtitle_keys = []

    preview_df = df.head(limit)

    for _, row in preview_df.iterrows():
        if title_key and title_key in row:
            title = row.get(title_key, "Item")
        else:
            title = row.iloc[0]

        subtitle_parts = []

        for key in subtitle_keys:
            if key in row and str(row.get(key, "")).strip():
                subtitle_parts.append(f"{key}: {row.get(key)}")

        subtitle = " | ".join(subtitle_parts)

        badge = ""
        if badge_key and badge_key in row:
            badge = str(row.get(badge_key, ""))

        description = ""
        if description_key and description_key in row:
            description = str(row.get(description_key, ""))

        badge_lower = badge.lower()

        if badge_lower in ["alta", "high", "error"]:
            badge_color = "#ef4444"
        elif badge_lower in ["média", "media", "medium", "warning"]:
            badge_color = "#f59e0b"
        elif badge_lower in ["baixa", "low", "info"]:
            badge_color = "#38bdf8"
        else:
            badge_color = "#cbd5e1"

        st.markdown(
            f"""
            <div class="enterprise-card" style="padding: 1rem 1.15rem; margin-bottom: 0.75rem;">
                <div style="display: flex; justify-content: space-between; gap: 1rem; align-items: flex-start;">
                    <div style="max-width: 82%;">
                        <div style="font-weight: 950; color: #f8fafc; font-size: 1rem;">{title}</div>
                        <div style="color: #94a3b8; font-size: 0.84rem; margin-top: 0.35rem;">{subtitle}</div>
                        <div style="color: #cbd5e1; font-size: 0.84rem; margin-top: 0.55rem; line-height: 1.45;">{description}</div>
                    </div>
                    <div style="color: {badge_color}; font-weight: 950; font-size: 0.9rem; white-space: nowrap;">
                        {badge}
                    </div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )


def render_technical_table(label, df):
    """
    Mantém tabela completa em expander para consulta técnica.
    """
    with st.expander(label):
        st.dataframe(df, use_container_width=True)


def apply_enterprise_theme():
    st.markdown(ENTERPRISE_CSS, unsafe_allow_html=True)


def render_enterprise_header():
    st.markdown(
        """
        <div class="enterprise-hero">
            <div class="enterprise-eyebrow">ASPM Security Command Center</div>
            <h1 class="enterprise-title">
                Application Security<br>
                <span class="enterprise-gradient">Posture Management</span>
            </h1>
            <p class="enterprise-subtitle">
                Centralize achados de Semgrep, Bandit, SCA e URL Analysis em uma visão executiva.
                A plataforma prioriza riscos por evidências reais, separa falsos positivos automaticamente
                e oferece explicações assistidas por IA.
            </p>
            <div>
                <span class="enterprise-pill">Semgrep</span>
                <span class="enterprise-pill">Bandit</span>
                <span class="enterprise-pill">SCA</span>
                <span class="enterprise-pill">URL Analysis</span>
                <span class="enterprise-pill">IA</span>
                <span class="enterprise-pill">Evidence Based</span>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_enterprise_sidebar():
    st.sidebar.markdown(
        """
        <div class="enterprise-sidebar-logo">
            <strong>ASPM Control</strong><br>
            <small>FIAP Security Dashboard</small>
        </div>
        """,
        unsafe_allow_html=True,
    )
    st.sidebar.caption("Governança, evidências, priorização e postura de segurança.")

    # ── Upload consolidado ──
    st.sidebar.markdown("---")
    st.sidebar.markdown("### 📦 Upload Consolidado")
    st.sidebar.caption(
        "Envie o aspm-report.json gerado pelo orquestrador para preencher todas as abas de uma vez."
    )
    consolidated = st.sidebar.file_uploader(
        "Selecionar aspm-report.json",
        type=["json"],
        key="upload_consolidated",
        label_visibility="collapsed",
    )

    if consolidated is not None:
        try:
            report = json.load(consolidated)
            st.session_state["aspm_report"] = report

            # Extrai dados de cada ferramenta
            semgrep_data = report.get("semgrep", {"results": []})
            bandit_data = report.get("bandit", {"results": []})
            sca_data = report.get("sca", {"dependencies": []})
            secrets_data = report.get("secrets", {}).get("gitleaks", [])

            # Salva no session_state pra uso nas abas
            st.session_state["consolidated_semgrep"] = semgrep_data
            st.session_state["consolidated_bandit"] = bandit_data
            st.session_state["consolidated_sca"] = sca_data
            st.session_state["consolidated_secrets"] = secrets_data

            meta = report.get("scan_metadata", {})
            summary = meta.get("summary", {})
            n = summary.get("total_findings", 0)

            # Salva no histórico global
            semgrep_count = len(semgrep_data.get("results", []))
            bandit_count = len(bandit_data.get("results", []))
            sca_count = sum(
                len(d.get("vulns", [])) for d in sca_data.get("dependencies", [])
            )
            secrets_count = len(secrets_data)
            high = summary.get("by_severity", {}).get("Alta", 0)
            medium = summary.get("by_severity", {}).get("Média", 0)
            low = summary.get("by_severity", {}).get("Baixa", 0)

            save_scan_history(
                n,
                high,
                medium,
                low,
                semgrep_count,
                bandit_count,
                sca_count,
                secrets_count,
            )

            st.sidebar.success(f"✅ Relatório carregado: {n} achados")
        except Exception as e:
            st.sidebar.error(f"Erro ao ler relatório: {e}")

    # Mostra indicador se já carregou
    if "aspm_report" in st.session_state:
        st.sidebar.info("📊 Dados consolidados disponíveis")


apply_enterprise_theme()
render_enterprise_header()
render_enterprise_sidebar()

st.sidebar.subheader("Governança")
st.sidebar.metric("Falsos positivos manuais", count_false_positives())

if st.sidebar.button("Limpar falsos positivos manuais"):
    st.session_state.false_positives = set()
    st.rerun()


tab1, tab2, tab3, tab4, tab5, tab6, tab7, tab8 = st.tabs(
    [
        "Resumo Executivo",
        "Semgrep",
        "Bandit",
        "SCA",
        "URL Analysis",
        "Secrets",
        "Attack Surface",
        "Histórico",
    ]
)


# Os dados das ferramentas começam vazios para evitar que resultados antigos
# apareçam automaticamente quando o dashboard é aberto.
# Se um relatório consolidado foi enviado via sidebar, usa ele.
semgrep_data_default = st.session_state.get("consolidated_semgrep", {"results": []})
bandit_data_default = st.session_state.get("consolidated_bandit", {"results": []})
sca_data_default = st.session_state.get("consolidated_sca", {"dependencies": []})

semgrep_df_default = pd.DataFrame(get_semgrep_vulnerabilities(semgrep_data_default))
bandit_df_default = pd.DataFrame(get_bandit_vulnerabilities(bandit_data_default))
sca_df_default = pd.DataFrame(get_sca_vulnerabilities(sca_data_default))

semgrep_active_df = filter_false_positives(semgrep_df_default, "semgrep")
bandit_active_df = filter_false_positives(bandit_df_default, "bandit")
sca_active_df = filter_false_positives(sca_df_default, "sca")

secrets_df_default = pd.DataFrame(st.session_state.get("secret_results", []))


with tab1:
    st.subheader("Resumo Executivo")

    st.markdown(
        """
        <div class="enterprise-card">
            <div class="enterprise-section-title"></div>
            <div class="enterprise-muted">
                Consolidação dos resultados das ferramentas integradas, com foco em risco,
                priorização e leitura executiva para apresentação da Sprint ASPM.
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    total_semgrep = len(semgrep_active_df)
    total_bandit = len(bandit_active_df)
    total_sca = len(sca_active_df)
    total_secrets = len(secrets_df_default)

    total_high = 0
    total_medium = 0
    total_low = 0

    for df_source in [
        semgrep_active_df,
        bandit_active_df,
        sca_active_df,
        secrets_df_default,
    ]:
        if not df_source.empty:
            total_high += df_source[df_source["Prioridade"] == "Alta"].shape[0]
            total_medium += df_source[df_source["Prioridade"] == "Média"].shape[0]
            total_low += df_source[df_source["Prioridade"] == "Baixa"].shape[0]

    # O Resumo Executivo usa somente a análise atual da sessão.
    # Isso evita que dados antigos do histórico contaminem o score ao abrir o sistema.
    latest_url_score = "Sem análise"
    latest_url_classification = "Sem análise"

    current_url_result = st.session_state.get("last_url_scan")

    if current_url_result:
        latest_url_score = current_url_result.get("score", "Sem análise")
        latest_url_classification = current_url_result.get(
            "classificacao", "Sem análise"
        )

        current_url_df = pd.DataFrame(current_url_result.get("findings", []))

        if not current_url_df.empty:
            current_active_df = current_url_df[current_url_df["Tipo"] == "Achado Ativo"]
            total_high += current_active_df[
                current_active_df["Prioridade"] == "Alta"
            ].shape[0]
            total_medium += current_active_df[
                current_active_df["Prioridade"] == "Média"
            ].shape[0]
            total_low += current_active_df[
                current_active_df["Prioridade"] == "Baixa"
            ].shape[0]

    general_score, general_classification = calculate_general_score(
        total_high, total_medium, total_low
    )

    col1, col2, col3, col4, col5 = st.columns(5)

    col1.metric("Score Geral", general_score)
    col2.metric("Postura", general_classification)
    col3.metric("Riscos Altos", total_high)
    col4.metric("Riscos Médios", total_medium)
    col5.metric("Riscos Baixos", total_low)

    st.subheader("Fontes integradas")

    source_table = pd.DataFrame(
        [
            {
                "Fonte": "Semgrep",
                "Objetivo": "Análise estática de código",
                "Achados ativos": total_semgrep,
            },
            {
                "Fonte": "Bandit",
                "Objetivo": "Análise de segurança Python",
                "Achados ativos": total_bandit,
            },
            {
                "Fonte": "SCA",
                "Objetivo": "Análise de bibliotecas e CVEs",
                "Achados ativos": total_sca,
            },
            {
                "Fonte": "Secrets",
                "Objetivo": "Detecção de segredos e credenciais",
                "Achados ativos": total_secrets,
            },
            {
                "Fonte": "URL Analysis",
                "Objetivo": "Exposição, headers, TLS e discovery contextual",
                "Achados ativos": "Score atual: " + str(latest_url_score),
            },
        ]
    )

    render_source_cards(
        total_semgrep, total_bandit, total_sca + total_secrets, latest_url_score
    )

    with st.expander("Ver tabela técnica das fontes"):
        st.dataframe(source_table, use_container_width=True)

    chart_col1, chart_col2 = st.columns(2)

    with chart_col1:
        st.subheader("Distribuição de Severidade")
        severity_chart = pd.DataFrame(
            [
                {"Severidade": "Alta", "Quantidade": total_high},
                {"Severidade": "Média", "Quantidade": total_medium},
                {"Severidade": "Baixa", "Quantidade": total_low},
            ]
        )
        render_donut_chart(
            severity_chart, "Severidade", "Quantidade", "Riscos por severidade"
        )

    with chart_col2:
        st.subheader("Cobertura por Fonte")
        source_chart = pd.DataFrame(
            [
                {"Fonte": "Semgrep", "Achados": total_semgrep},
                {"Fonte": "Bandit", "Achados": total_bandit},
                {"Fonte": "SCA", "Achados": total_sca},
                {"Fonte": "Secrets", "Achados": total_secrets},
            ]
        )
        render_donut_chart(source_chart, "Fonte", "Achados", "Achados por fonte")

    # ── Correlação de Riscos ──
    st.subheader("🔄 Correlação de Riscos (ASPM)")
    url_findings_list = []
    if current_url_result:
        url_findings_list = current_url_result.get("findings", [])

    correlacoes = correlate_findings(
        semgrep_active_df,
        bandit_active_df,
        sca_active_df,
        secrets_df_default,
        url_findings_list,
    )

    if correlacoes:
        for c in correlacoes:
            cor_priority = c["prioridade"]
            cor_color = {
                "Crítica": "#ef4444",
                "Alta": "#f59e0b",
                "Média": "#38bdf8",
                "Baixa": "#22c55e",
            }.get(cor_priority, "#cbd5e1")
            st.markdown(
                f"""
                <div class="enterprise-card" style="border-left: 4px solid {cor_color}; margin-bottom: 0.75rem;">
                    <div style="display: flex; justify-content: space-between; align-items: center;">
                        <div>
                            <div style="font-weight: 950; color: #f8fafc;">{c["risco"]}</div>
                            <div style="color: #94a3b8; font-size: 0.84rem; margin-top: 0.3rem;">{c["evidencias"]}</div>
                            <div style="color: #cbd5e1; font-size: 0.84rem; margin-top: 0.3rem;">→ {c["acao"]}</div>
                        </div>
                        <div style="color: {cor_color}; font-weight: 950; font-size: 0.9rem;">{cor_priority}</div>
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )
    else:
        st.markdown(
            "<div class='enterprise-muted'>Nenhuma correlação significativa identificada entre as fontes.</div>",
            unsafe_allow_html=True,
        )

    # ── Histórico Global ──
    with st.expander("📊 Histórico global de scans"):
        scan_hist_df = load_scan_history()
        if not scan_hist_df.empty:
            st.dataframe(scan_hist_df.head(10), use_container_width=True)
            if len(scan_hist_df) > 1:
                st.subheader("Evolução do Score")
                evo_df = scan_hist_df.sort_values("id")[["created_at", "score_geral"]]
                evo_df = evo_df.set_index("created_at")
                st.line_chart(evo_df)
        else:
            st.caption("Nenhum scan registrado. Use o upload consolidado na sidebar.")

    executive_context = f"""
Score geral: {general_score}
Classificação geral: {general_classification}
Achados Semgrep: {total_semgrep}
Achados Bandit: {total_bandit}
Achados SCA: {total_sca}
Achados Secrets: {total_secrets}
Riscos altos: {total_high}
Riscos médios: {total_medium}
Riscos baixos: {total_low}
Último score de URL: {latest_url_score}
Última classificação de URL: {latest_url_classification}
Falsos positivos manuais marcados: {count_false_positives()}
"""

    if st.button("Gerar resumo executivo com IA"):
        summary = ask_executive_summary(executive_context)
        st.subheader("Parecer executivo da IA")
        st.write(summary)


with tab2:
    st.subheader("Análise SAST - Semgrep")

    uploaded_file = st.file_uploader(
        "Enviar arquivo JSON do Semgrep", type=["json"], key="upload_semgrep"
    )

    if uploaded_file is not None:
        semgrep_data = json.load(uploaded_file)
        st.success("Arquivo JSON do Semgrep carregado com sucesso.")
    else:
        st.info(
            "Nenhum arquivo do Semgrep enviado. Envie um JSON para iniciar a análise SAST."
        )
        semgrep_data = semgrep_data_default

    semgrep_vulns = get_semgrep_vulnerabilities(semgrep_data)

    if semgrep_vulns:
        df = pd.DataFrame(semgrep_vulns)
        filtered_df = filter_false_positives(df, "semgrep")

        high_count = filtered_df[filtered_df["Prioridade"] == "Alta"].shape[0]
        medium_count = filtered_df[filtered_df["Prioridade"] == "Média"].shape[0]
        low_count = filtered_df[filtered_df["Prioridade"] == "Baixa"].shape[0]

        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Total ativo", len(filtered_df))
        col2.metric("Alta", high_count)
        col3.metric("Média", medium_count)
        col4.metric("Baixa", low_count)

        tabela = filtered_df[
            ["ID", "Arquivo", "Linha", "Severidade", "Prioridade", "Descrição"]
        ]
        render_table_as_cards(
            tabela,
            title_key="ID",
            subtitle_keys=["Arquivo", "Linha", "Severidade"],
            badge_key="Prioridade",
            description_key="Descrição",
            limit=8,
        )
        render_technical_table("Ver tabela técnica completa", tabela)

        csv_data = tabela.to_csv(index=False).encode("utf-8-sig")
        st.download_button("Exportar CSV", csv_data, "semgrep.csv", "text/csv")

        pdf = generate_pdf_report(
            "Relatório Semgrep", f"Total ativo: {len(filtered_df)}", tabela
        )
        st.download_button("Exportar PDF", pdf, "semgrep.pdf", "application/pdf")

        st.subheader("Detalhes Técnicos com IA")

        for _, row in filtered_df.iterrows():
            unique_id = f"semgrep_{row['ID']}_{row['Arquivo']}_{row['Linha']}"

            with st.expander(f"{row['ID']} | {row['Arquivo']} | Linha {row['Linha']}"):
                st.write(f"Severidade: {row['Severidade']}")
                st.write(f"Prioridade: {row['Prioridade']}")
                st.write(f"Descrição: {row['Descrição']}")
                st.write("---")
                st.write(f"Explicação IA: {row['Explicação IA']}")
                st.write(f"Risco IA: {row['Risco IA']}")
                st.write(f"Correção IA: {row['Correção IA']}")

                if st.button("Marcar como falso positivo", key=unique_id):
                    add_false_positive(unique_id)
                    st.rerun()

    else:
        if uploaded_file is None:
            render_empty_state(
                "Aguardando arquivo do Semgrep.",
                "Envie o JSON gerado pelo Semgrep para visualizar os achados de análise estática.",
                "info",
            )
        else:
            st.info("Nenhuma vulnerabilidade encontrada pelo Semgrep.")


with tab3:
    st.subheader("Análise Python - Bandit")

    uploaded_bandit = st.file_uploader(
        "Enviar arquivo JSON do Bandit", type=["json"], key="upload_bandit"
    )

    if uploaded_bandit is not None:
        bandit_data = json.load(uploaded_bandit)
        st.success("Arquivo JSON do Bandit carregado com sucesso.")
    else:
        st.info(
            "Nenhum arquivo do Bandit enviado. Envie um JSON para iniciar a análise Python."
        )
        bandit_data = bandit_data_default

    bandit_vulns = get_bandit_vulnerabilities(bandit_data)

    if bandit_vulns:
        df = pd.DataFrame(bandit_vulns)
        filtered_df = filter_false_positives(df, "bandit")

        high_count = filtered_df[filtered_df["Prioridade"] == "Alta"].shape[0]
        medium_count = filtered_df[filtered_df["Prioridade"] == "Média"].shape[0]
        low_count = filtered_df[filtered_df["Prioridade"] == "Baixa"].shape[0]

        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Total ativo", len(filtered_df))
        col2.metric("Alta", high_count)
        col3.metric("Média", medium_count)
        col4.metric("Baixa", low_count)

        tabela = filtered_df[
            [
                "Teste",
                "Arquivo",
                "Linha",
                "Severidade",
                "Confiança",
                "Prioridade",
                "Descrição",
            ]
        ]
        render_table_as_cards(
            tabela,
            title_key="Teste",
            subtitle_keys=["Arquivo", "Linha", "Severidade", "Confiança"],
            badge_key="Prioridade",
            description_key="Descrição",
            limit=8,
        )
        render_technical_table("Ver tabela técnica completa", tabela)

        csv_data = tabela.to_csv(index=False).encode("utf-8-sig")
        st.download_button("Exportar CSV", csv_data, "bandit.csv", "text/csv")

        pdf = generate_pdf_report(
            "Relatório Bandit", f"Total ativo: {len(filtered_df)}", tabela
        )
        st.download_button("Exportar PDF", pdf, "bandit.pdf", "application/pdf")

        st.subheader("Detalhamento com IA")

        for _, row in filtered_df.iterrows():
            unique_id = f"bandit_{row['Teste']}_{row['Arquivo']}_{row['Linha']}"

            with st.expander(
                f"{row['Teste']} | {row['Arquivo']} | Linha {row['Linha']}"
            ):
                st.write(f"Severidade: {row['Severidade']}")
                st.write(f"Confiança: {row['Confiança']}")
                st.write(f"Prioridade: {row['Prioridade']}")
                st.write(f"Descrição: {row['Descrição']}")
                st.write("---")
                st.write(f"Explicação IA: {row['Explicação IA']}")
                st.write(f"Risco IA: {row['Risco IA']}")
                st.write(f"Correção IA: {row['Correção IA']}")

                if st.button("Marcar como falso positivo", key=unique_id):
                    add_false_positive(unique_id)
                    st.rerun()

    else:
        if uploaded_bandit is None:
            render_empty_state(
                "Aguardando arquivo do Bandit.",
                "Envie o JSON gerado pelo Bandit para visualizar os achados de segurança Python.",
                "info",
            )
        else:
            st.success("Nenhum achado encontrado pelo Bandit.")


with tab4:
    st.subheader("Software Composition Analysis - SCA")

    uploaded_sca = st.file_uploader(
        "Enviar arquivo JSON da SCA", type=["json"], key="upload_sca"
    )

    if uploaded_sca is not None:
        sca_data = json.load(uploaded_sca)
        st.success("Arquivo SCA carregado com sucesso.")
    else:
        st.info(
            "Nenhum arquivo SCA enviado. Envie um JSON para iniciar a análise de dependências."
        )
        sca_data = sca_data_default

    sca_vulns = get_sca_vulnerabilities(sca_data)

    if sca_vulns:
        df = pd.DataFrame(sca_vulns)
        filtered_df = filter_false_positives(df, "sca")

        high_count = filtered_df[filtered_df["Prioridade"] == "Alta"].shape[0]
        medium_count = filtered_df[filtered_df["Prioridade"] == "Média"].shape[0]

        col1, col2, col3 = st.columns(3)
        col1.metric("Total ativo", len(filtered_df))
        col2.metric("Alta", high_count)
        col3.metric("Média", medium_count)

        tabela = filtered_df[
            [
                "Biblioteca",
                "Versão Atual",
                "CVE",
                "Prioridade",
                "Correção Disponível",
                "Descrição",
            ]
        ]
        render_table_as_cards(
            tabela,
            title_key="Biblioteca",
            subtitle_keys=["Versão Atual", "CVE", "Correção Disponível"],
            badge_key="Prioridade",
            description_key="Descrição",
            limit=8,
        )
        render_technical_table("Ver tabela técnica completa", tabela)

        csv_data = tabela.to_csv(index=False).encode("utf-8-sig")
        st.download_button("Exportar CSV", csv_data, "sca.csv", "text/csv")

        pdf = generate_pdf_report(
            "Relatório SCA",
            f"Total ativo de vulnerabilidades: {len(filtered_df)}",
            tabela,
        )
        st.download_button("Exportar PDF", pdf, "sca.pdf", "application/pdf")

        st.subheader("Detalhamento com IA")

        for _, row in filtered_df.iterrows():
            unique_id = f"sca_{row['Biblioteca']}_{row['CVE']}"

            with st.expander(f"{row['Biblioteca']} | {row['CVE']}"):
                st.write(f"Versão Atual: {row['Versão Atual']}")
                st.write(f"Prioridade: {row['Prioridade']}")
                st.write(f"Correção Disponível: {row['Correção Disponível']}")
                st.write(f"Descrição: {row['Descrição']}")
                st.write("---")
                st.write(f"Explicação IA: {row['Explicação IA']}")
                st.write(f"Risco IA: {row['Risco IA']}")
                st.write(f"Correção IA: {row['Correção IA']}")

                if st.button("Marcar como falso positivo", key=unique_id):
                    add_false_positive(unique_id)
                    st.rerun()

    else:
        if uploaded_sca is None:
            render_empty_state(
                "Aguardando arquivo SCA.",
                "Envie o JSON da análise de dependências para visualizar CVEs, versões vulneráveis e correções disponíveis.",
                "info",
            )
        else:
            st.success("Nenhuma vulnerabilidade encontrada na SCA.")


with tab5:
    st.subheader("Análise Passiva de URL")

    url = st.text_input("Digite a URL", placeholder="https://exemplo.com")

    usar_ia_url = st.checkbox("Usar IA para explicar cada achado da URL", value=True)

    limite_ia_url = st.number_input(
        "Limite de achados explicados pela IA", min_value=1, max_value=50, value=10
    )

    if st.button("Analisar URL"):
        if not url.strip():
            st.warning("Digite uma URL.")
        else:
            with st.spinner("Analisando URL..."):
                st.session_state.last_url_scan = analyze_url(url)

    result = st.session_state.last_url_scan

    if result:
        st.write(f"URL Final: {result['url_final']}")
        st.write(f"Domínio: {result['dominio']}")
        st.write(f"Status HTTP: {result['status_code']}")

        url_df = pd.DataFrame(result["findings"])

        manual_filtered_url_df = url_df[
            ~url_df.apply(
                lambda row: is_false_positive(
                    f"url_{row['Tipo']}_{row['Categoria']}_{row['Item']}"
                ),
                axis=1,
            )
        ]

        active_url_df = manual_filtered_url_df[
            manual_filtered_url_df["Tipo"] == "Achado Ativo"
        ]
        improvements_df = manual_filtered_url_df[
            manual_filtered_url_df["Tipo"] == "Melhoria Recomendada"
        ]
        controls_ok_df = manual_filtered_url_df[
            manual_filtered_url_df["Tipo"] == "Controle OK"
        ]
        auto_fp_df = manual_filtered_url_df[
            manual_filtered_url_df["Tipo"] == "Falso Positivo Automático"
        ]

        high_count = active_url_df[active_url_df["Prioridade"] == "Alta"].shape[0]
        medium_count = active_url_df[active_url_df["Prioridade"] == "Média"].shape[0]
        low_count = active_url_df[active_url_df["Prioridade"] == "Baixa"].shape[0]
        discovery_count = active_url_df[
            active_url_df["Categoria"] == "Discovery"
        ].shape[0]
        improvement_count = len(improvements_df)
        auto_fp_count = len(auto_fp_df)
        controls_ok_count = len(controls_ok_df)

        # Salva automaticamente no histórico após cada análise
        auto_save_url_scan_once(result, high_count, medium_count, low_count)

        st.subheader("Resumo da Análise")

        kpi_col1, kpi_col2, kpi_col3, kpi_col4 = st.columns(4)

        with kpi_col1:
            render_status_card(
                "Security Score",
                result["score"],
                "Pontuação calculada apenas com achados ativos.",
                "good"
                if result["score"] >= 85
                else "warning"
                if result["score"] >= 65
                else "critical",
            )

        with kpi_col2:
            render_status_card(
                "Achados Ativos",
                len(active_url_df),
                "Vulnerabilidades ou riscos com evidência real.",
                "critical" if len(active_url_df) > 0 else "good",
            )

        with kpi_col3:
            render_status_card(
                "Melhorias",
                improvement_count,
                "Itens de hardening recomendados.",
                "warning" if improvement_count > 0 else "good",
            )

        with kpi_col4:
            render_status_card(
                "Controles OK",
                controls_ok_count,
                "Controles verificados e funcionando.",
                "good",
            )

        kpi_col5, kpi_col6, kpi_col7, kpi_col8 = st.columns(4)

        with kpi_col5:
            render_status_card(
                "Alta",
                high_count,
                "Prioridade imediata.",
                "critical" if high_count > 0 else "good",
            )

        with kpi_col6:
            render_status_card(
                "Média",
                medium_count,
                "Correção planejada.",
                "warning" if medium_count > 0 else "good",
            )

        with kpi_col7:
            render_status_card("Baixa", low_count, "Baixo impacto.", "info")

        with kpi_col8:
            render_status_card(
                "Falsos Positivos",
                auto_fp_count,
                "Itens descartados automaticamente.",
                "info",
            )

        chart_col1, chart_col2 = st.columns(2)

        with chart_col1:
            st.subheader("Distribuição da Análise de URL")
            url_distribution_chart = pd.DataFrame(
                [
                    {"Tipo": "Achados Ativos", "Quantidade": len(active_url_df)},
                    {"Tipo": "Melhorias", "Quantidade": improvement_count},
                    {"Tipo": "Controles OK", "Quantidade": controls_ok_count},
                    {"Tipo": "Falsos Positivos", "Quantidade": auto_fp_count},
                ]
            )
            render_donut_chart(
                url_distribution_chart, "Tipo", "Quantidade", "Resultado por tipo"
            )

        with chart_col2:
            st.subheader("Prioridade dos Achados Ativos")
            url_priority_chart = pd.DataFrame(
                [
                    {"Prioridade": "Alta", "Quantidade": high_count},
                    {"Prioridade": "Média", "Quantidade": medium_count},
                    {"Prioridade": "Baixa", "Quantidade": low_count},
                ]
            )
            render_donut_chart(
                url_priority_chart, "Prioridade", "Quantidade", "Achados por prioridade"
            )

        st.subheader("Achados Ativos")

        if active_url_df.empty:
            render_empty_state(
                "Nenhuma vulnerabilidade ativa encontrada.",
                "A análise não encontrou evidências fortes de exposição, vazamento, debug, stack trace, API sensível ou painel acessível sem autenticação.",
                "good",
            )
        else:
            render_compact_cards(active_url_df, limit=6)
            render_technical_table(
                "Ver tabela técnica de achados ativos", active_url_df
            )

        st.subheader("Melhorias Recomendadas")

        if improvements_df.empty:
            render_empty_state(
                "Nenhuma melhoria obrigatória identificada.",
                "Os principais pontos de hardening analisados não geraram recomendações adicionais.",
                "good",
            )
        else:
            render_compact_cards(improvements_df, limit=8)
            render_technical_table("Ver tabela técnica de melhorias", improvements_df)

        st.subheader("Controles OK")

        if controls_ok_df.empty:
            render_empty_state(
                "Nenhum controle validado nesta análise.",
                "A ferramenta não encontrou controles classificados como OK para esta URL.",
                "info",
            )
        else:
            render_compact_cards(controls_ok_df, limit=8)
            render_technical_table("Ver tabela técnica de controles OK", controls_ok_df)

        st.subheader("Falsos Positivos Detectados Automaticamente")

        if auto_fp_df.empty:
            render_empty_state(
                "Nenhum falso positivo automático identificado.",
                "Todos os itens encontrados foram classificados como controles, melhorias ou achados ativos.",
                "info",
            )
        else:
            render_compact_cards(auto_fp_df, limit=8)
            render_technical_table("Ver tabela técnica de falsos positivos", auto_fp_df)

        csv_url = active_url_df.to_csv(index=False).encode("utf-8-sig")
        st.download_button(
            "Exportar CSV - Achados Ativos", csv_url, "url_analysis.csv", "text/csv"
        )

        pdf_url = generate_pdf_report(
            "Relatório URL Analysis",
            f"URL analisada: {result['url_final']} | Score: {result['score']} | Classificação: {result['classificacao']}",
            active_url_df,
        )
        st.download_button(
            "Exportar PDF - Achados Ativos",
            pdf_url,
            "url_analysis.pdf",
            "application/pdf",
        )

        st.subheader("Detalhamento com IA")

        detail_df = pd.concat(
            [active_url_df, improvements_df, controls_ok_df], ignore_index=True
        )

        for index, row in detail_df.iterrows():
            unique_id = f"url_{row['Tipo']}_{row['Categoria']}_{row['Item']}"

            description_for_ai = (
                f"Tipo: {row['Tipo']}. "
                f"Status: {row['Status']}. "
                f"Evidências: {row['Evidências']}. "
                f"{row['Descrição']}"
            )

            if usar_ia_url and index < limite_ia_url:
                ai_result = ask_ai(row["Item"], description_for_ai)
            else:
                ai_result = local_ai_fallback(row["Item"], description_for_ai)

            with st.expander(
                f"{row['Tipo']} | {row['Categoria']} | {row['Item']} | {row['Status']}"
            ):
                st.write(f"Tipo: {row['Tipo']}")
                st.write(f"Categoria: {row['Categoria']}")
                st.write(f"Status: {row['Status']}")
                st.write(f"Prioridade: {row['Prioridade']}")
                st.write(f"Evidências: {row['Evidências']}")
                st.write(f"Descrição: {row['Descrição']}")
                st.write("---")
                st.write(f"Explicação IA: {ai_result['explicacao']}")
                st.write(f"Risco IA: {ai_result['risco']}")
                st.write(f"Correção IA: {ai_result['correcao']}")

                if row["Tipo"] == "Achado Ativo":
                    if st.button("Marcar como falso positivo", key=unique_id):
                        add_false_positive(unique_id)
                        st.rerun()

        if not auto_fp_df.empty:
            st.subheader("Explicação dos Falsos Positivos Automáticos")

            for _, row in auto_fp_df.iterrows():
                with st.expander(f"Falso positivo | {row['Item']} | {row['Status']}"):
                    st.write(f"Endpoint: {row['Item']}")
                    st.write(f"Status: {row['Status']}")
                    st.write(f"Motivo: {row['Descrição']}")
                    st.write(
                        "Esse item foi separado automaticamente porque o sistema não encontrou "
                        "evidência suficiente de vulnerabilidade real no conteúdo da página."
                    )

        st.caption("A análise atual é salva automaticamente no histórico.")


with tab6:
    st.subheader("Secrets Scanner")

    st.info(
        "Use esta aba para detectar segredos em arquivos do projeto ou importar um relatório JSON do Gitleaks."
    )

    uploaded_secret_files = st.file_uploader(
        "Enviar arquivos de código para análise de segredos",
        type=[
            "py",
            "js",
            "ts",
            "tsx",
            "jsx",
            "json",
            "env",
            "txt",
            "yaml",
            "yml",
            "ini",
            "cfg",
            "toml",
        ],
        accept_multiple_files=True,
        key="upload_secret_files",
    )

    uploaded_gitleaks = st.file_uploader(
        "Enviar relatório JSON do Gitleaks", type=["json"], key="upload_gitleaks_json"
    )

    secret_findings = []

    if uploaded_secret_files:
        secret_findings.extend(scan_uploaded_files_for_secrets(uploaded_secret_files))

    if uploaded_gitleaks is not None:
        try:
            gitleaks_data = json.load(uploaded_gitleaks)
            secret_findings.extend(parse_gitleaks_json(gitleaks_data))
            st.success("Relatório Gitleaks carregado com sucesso.")
        except Exception as e:
            st.error(f"Erro ao carregar JSON do Gitleaks: {e}")

    st.session_state.secret_results = secret_findings

    secret_df = pd.DataFrame(secret_findings)

    if secret_df.empty:
        render_empty_state(
            "Nenhum segredo analisado.",
            "Envie arquivos do projeto ou um JSON do Gitleaks para iniciar o Secrets Scanner.",
            "info",
        )
    else:
        high_count, medium_count, low_count = calculate_secret_counts(secret_df)

        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Segredos", len(secret_df))
        col2.metric("Alta", high_count)
        col3.metric("Média", medium_count)
        col4.metric("Baixa", low_count)

        render_table_as_cards(
            secret_df,
            title_key="Regra",
            subtitle_keys=["Origem", "Arquivo", "Linha"],
            badge_key="Prioridade",
            description_key="Descrição",
            limit=10,
        )

        render_technical_table("Ver tabela técnica de secrets", secret_df)

        csv_secrets = secret_df.to_csv(index=False).encode("utf-8-sig")
        st.download_button(
            "Exportar CSV - Secrets", csv_secrets, "secrets_scan.csv", "text/csv"
        )

        pdf_secrets = generate_pdf_report(
            "Relatório Secrets Scanner",
            f"Total de possíveis segredos encontrados: {len(secret_df)}",
            secret_df,
        )
        st.download_button(
            "Exportar PDF - Secrets", pdf_secrets, "secrets_scan.pdf", "application/pdf"
        )


with tab7:
    st.subheader("Attack Surface")

    current_url_result = st.session_state.get("last_url_scan")

    if not current_url_result:
        render_empty_state(
            "Nenhuma superfície de ataque carregada.",
            "Execute uma análise em URL Analysis para visualizar endpoints, controles, melhorias e falsos positivos contextualizados.",
            "info",
        )
    else:
        attack_df = pd.DataFrame(current_url_result.get("findings", []))

        if attack_df.empty:
            render_empty_state(
                "Nenhum dado de superfície encontrado.",
                "A última análise não retornou endpoints ou controles para exibição.",
                "info",
            )
        else:
            discovery_df = attack_df[attack_df["Categoria"] == "Discovery"]
            active_df = attack_df[attack_df["Tipo"] == "Achado Ativo"]
            improvements_df = attack_df[attack_df["Tipo"] == "Melhoria Recomendada"]
            controls_df = attack_df[attack_df["Tipo"] == "Controle OK"]
            false_positive_df = attack_df[
                attack_df["Tipo"] == "Falso Positivo Automático"
            ]

            col1, col2, col3, col4 = st.columns(4)
            col1.metric("Endpoints", len(discovery_df))
            col2.metric("Achados Ativos", len(active_df))
            col3.metric("Melhorias", len(improvements_df))
            col4.metric("Falsos Positivos", len(false_positive_df))

            distribution_df = pd.DataFrame(
                [
                    {"Tipo": "Achados Ativos", "Quantidade": len(active_df)},
                    {"Tipo": "Melhorias", "Quantidade": len(improvements_df)},
                    {"Tipo": "Controles OK", "Quantidade": len(controls_df)},
                    {"Tipo": "Falsos Positivos", "Quantidade": len(false_positive_df)},
                ]
            )
            render_donut_chart(
                distribution_df, "Tipo", "Quantidade", "Superfície por classificação"
            )

            st.subheader("Endpoints descobertos")
            if discovery_df.empty:
                render_empty_state(
                    "Nenhum endpoint de discovery identificado.",
                    "A análise não encontrou rotas relevantes no discovery contextual.",
                    "info",
                )
            else:
                render_table_as_cards(
                    discovery_df,
                    title_key="Item",
                    subtitle_keys=["Tipo", "Status", "Prioridade"],
                    badge_key="Tipo",
                    description_key="Descrição",
                    limit=12,
                )
                render_technical_table(
                    "Ver tabela técnica da superfície de ataque", discovery_df
                )


with tab8:
    st.subheader("Histórico de análises de URL")

    history_df = load_url_history()

    reset_col1, reset_col2 = st.columns([1, 4])

    with reset_col1:
        if st.button("Resetar histórico"):
            clear_url_history()
            st.session_state.last_url_scan = None
            st.session_state.saved_url_scans = set()
            st.success("Histórico de URL resetado.")
            st.rerun()

    with reset_col2:
        st.caption(
            "Use o reset para limpar análises antigas e impedir que resultados desatualizados confundam a apresentação."
        )

    if history_df.empty:
        render_empty_state(
            "Nenhuma análise registrada.",
            "Execute uma análise de URL na aba URL Analysis. O histórico é salvo automaticamente.",
            "info",
        )
    else:
        st.subheader("Últimas análises")
        render_history_cards(history_df)

        with st.expander("Ver tabela técnica completa do histórico"):
            st.dataframe(history_df, use_container_width=True)

        csv_history = history_df.to_csv(index=False).encode("utf-8-sig")
        st.download_button(
            "Exportar histórico CSV", csv_history, "historico_url.csv", "text/csv"
        )

        st.subheader("Evolução do Score")

        chart_df = history_df.sort_values("id")[["created_at", "score"]]
        chart_df = chart_df.set_index("created_at")

        st.line_chart(chart_df)
