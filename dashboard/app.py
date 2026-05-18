import json
import os
import ssl
import socket
import sqlite3
from datetime import datetime
from urllib.parse import urlparse
from io import BytesIO

import pandas as pd
import requests
import streamlit as st
import tldextract

from dotenv import load_dotenv
from google import genai

from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors


# Carrega variáveis do arquivo .env
load_dotenv()

API_KEY = os.getenv("GEMINI_API_KEY")
client = genai.Client(api_key=API_KEY) if API_KEY else None

DB_PATH = "data/history.db"


# Caminhos sensíveis usados no discovery da análise de URL
COMMON_PATHS = [
    "/admin",
    "/login",
    "/dashboard",
    "/robots.txt",
    "/sitemap.xml",
    "/swagger",
    "/swagger-ui",
    "/api",
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
    "/administrator",
]


# Inicializa banco SQLite para histórico das análises de URL
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

    conn.commit()
    conn.close()


# Salva uma análise de URL no histórico
def save_url_history(url, final_url, score, classification, high_count, medium_count, low_count):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute("""
        INSERT INTO url_history (
            created_at, url, final_url, score, classification,
            high_count, medium_count, low_count
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        url,
        final_url,
        score,
        classification,
        high_count,
        medium_count,
        low_count
    ))

    conn.commit()
    conn.close()


# Carrega histórico de análises de URL
def load_url_history():
    conn = sqlite3.connect(DB_PATH)
    df = pd.read_sql_query("SELECT * FROM url_history ORDER BY id DESC", conn)
    conn.close()
    return df


# Corrige alguns problemas comuns de acentuação
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


# Garante que a URL tenha protocolo
def normalize_url(url):
    url = url.strip()

    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url

    return url


# Extrai domínio base da URL
def get_base_domain(url):
    parsed = urlparse(url)
    extracted = tldextract.extract(parsed.netloc)

    if extracted.domain and extracted.suffix:
        return f"{extracted.domain}.{extracted.suffix}"

    return parsed.netloc


# Gera relatório PDF a partir de um DataFrame
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

        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.lightgrey),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 7),
        ]))

        elements.append(table)

    doc.build(elements)
    buffer.seek(0)

    return buffer


# Extrai campos EXPLICACAO, RISCO e CORRECAO da resposta da IA
def extract_section(text, labels):
    if not text:
        return None

    for line in text.splitlines():
        normalized = clean_text(line).strip().upper()

        for label in labels:
            if normalized.startswith(label) and ":" in line:
                return clean_text(line.split(":", 1)[1].strip())

    return None


# Correção local padrão caso a IA não responda
def default_correction(text):
    text = str(text).lower()

    if "x-powered-by" in text:
        return "Remover ou ocultar o header X-Powered-By no servidor."

    if "content-security-policy" in text:
        return "Configurar uma política CSP adequada para reduzir risco de XSS."

    if "strict-transport-security" in text:
        return "Configurar HSTS para reforçar uso obrigatório de HTTPS."

    if "https" in text:
        return "Habilitar HTTPS com certificado TLS válido."

    if "admin" in text:
        return "Restringir o acesso ao painel administrativo, exigir autenticação forte e aplicar controle de acesso."

    if "robots" in text:
        return "Revisar o robots.txt para evitar exposição de diretórios sensíveis."

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


# Resposta local caso a API da IA falhe ou não esteja configurada
def local_ai_fallback(title, description):
    return {
        "explicacao": f"O item analisado ({title}) pode representar uma fragilidade de segurança.",
        "risco": description,
        "correcao": default_correction(f"{title} {description}")
    }


# Consulta o Gemini para explicar risco e correção
@st.cache_data(show_spinner=False)
def ask_ai(title, description):
    if not API_KEY or client is None:
        return local_ai_fallback(title, description)

    try:
        prompt = f"""
Você é um especialista brasileiro em ASPM, AppSec e segurança de aplicações.

RESPONDA SEMPRE EM PORTUGUÊS BRASILEIRO.
NUNCA responda em inglês ou espanhol.
Use linguagem técnica profissional.

Analise o item abaixo:

TÍTULO:
{title}

DESCRIÇÃO:
{description}

Responda EXATAMENTE neste formato e em português brasileiro:

EXPLICACAO: ...
RISCO: ...
CORRECAO: ...
"""

        response = client.models.generate_content(
            model="models/gemini-2.0-flash-lite",
            contents=prompt,
        )

        text = clean_text(response.text.strip()) if response.text else ""

        explicacao = extract_section(text, ["EXPLICACAO", "EXPLICAÇÃO"])
        risco = extract_section(text, ["RISCO"])
        correcao = extract_section(text, ["CORRECAO", "CORREÇÃO"])

        return {
            "explicacao": explicacao or "A IA não retornou explicação.",
            "risco": risco or description,
            "correcao": correcao or default_correction(f"{title} {description}"),
        }

    except Exception:
        return local_ai_fallback(title, description)


# Gera um resumo executivo consolidado usando IA
@st.cache_data(show_spinner=False)
def ask_executive_summary(context):
    if not API_KEY or client is None:
        return (
            "A aplicação apresenta achados distribuídos entre análise estática, segurança Python, "
            "dependências e exposição de URL. A prioridade deve ser corrigir riscos altos, revisar "
            "endpoints expostos e manter as dependências atualizadas."
        )

    try:
        prompt = f"""
Você é um especialista brasileiro em ASPM e DevSecOps.

RESPONDA SEMPRE EM PORTUGUÊS BRASILEIRO.

Com base no contexto abaixo, gere um resumo executivo curto para apresentação de uma plataforma ASPM.

O texto deve conter:
1. visão geral da postura de segurança
2. principais riscos
3. prioridade de correção
4. recomendação final

CONTEXTO:
{context}
"""

        response = client.models.generate_content(
            model="models/gemini-2.0-flash-lite",
            contents=prompt,
        )

        return clean_text(response.text.strip()) if response.text else "A IA não retornou resumo executivo."

    except Exception:
        return (
            "Não foi possível gerar o resumo executivo com IA. Recomenda-se priorizar os achados "
            "classificados como Alta, revisar exposição externa e corrigir dependências vulneráveis."
        )


# Carrega arquivo JSON com fallback seguro
def load_json(file_path, default=None):
    if default is None:
        default = {}

    if not os.path.exists(file_path):
        return default

    with open(file_path, "r", encoding="utf-8-sig") as f:
        return json.load(f)


# Classificação de prioridade do Semgrep
def classify_semgrep_priority(severity):
    if severity == "ERROR":
        return "Alta"
    if severity == "WARNING":
        return "Média"
    return "Baixa"


# Classificação de prioridade do Bandit
def classify_bandit_priority(severity):
    severity = str(severity).upper()

    if severity == "HIGH":
        return "Alta"
    if severity == "MEDIUM":
        return "Média"
    return "Baixa"


# Classificação de prioridade da SCA
def classify_sca_priority(vuln_id):
    vuln_id = str(vuln_id).upper()

    if "CVE" in vuln_id:
        return "Alta"

    if "JWT" in vuln_id:
        return "Alta"

    if "SSTI" in vuln_id:
        return "Alta"

    return "Média"


# Converte JSON do Semgrep em tabela padronizada
def get_semgrep_vulnerabilities(data):
    results = data.get("results", [])
    vulns = []

    for item in results:
        severity = item.get("extra", {}).get("severity")
        check_id = item.get("check_id")
        message = clean_text(item.get("extra", {}).get("message"))
        priority = classify_semgrep_priority(severity)

        ai_data = ask_ai(check_id, message)

        vulns.append({
            "ID": check_id,
            "Arquivo": item.get("path"),
            "Linha": item.get("start", {}).get("line"),
            "Severidade": severity,
            "Prioridade": priority,
            "Descrição": message,
            "Explicação IA": ai_data["explicacao"],
            "Risco IA": ai_data["risco"],
            "Correção IA": ai_data["correcao"],
        })

    return vulns


# Converte JSON do Bandit em tabela padronizada
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

        vulns.append({
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
        })

    return vulns


# Converte JSON SCA em tabela padronizada
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

            vulns.append({
                "Biblioteca": name,
                "Versão Atual": version,
                "CVE": vuln_id,
                "Prioridade": priority,
                "Correção Disponível": fixed_version,
                "Descrição": description,
                "Explicação IA": ai_data["explicacao"],
                "Risco IA": ai_data["risco"],
                "Correção IA": ai_data["correcao"],
            })

    return vulns


# Verifica se porta está aberta
def check_port(host, port, timeout=3):
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return "Aberta"
    except Exception:
        return "Fechada"


# Verifica validade do certificado TLS
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
        elif days_left >= 0:
            priority = "Média"
            status = "Expirando"
        else:
            priority = "Alta"
            status = "Expirado"

        return {
            "status": status,
            "priority": priority,
            "description": f"Certificado TLS com {days_left} dias restantes.",
        }

    except Exception as e:
        return {
            "status": "Erro",
            "priority": "Média",
            "description": str(e),
        }


# Faz discovery de caminhos sensíveis
def scan_common_paths(base_url):
    findings = []

    for path in COMMON_PATHS:
        try:
            target = base_url.rstrip("/") + path

            response = requests.get(
                target,
                timeout=5,
                allow_redirects=True
            )

            status = response.status_code
            content_type = response.headers.get("Content-Type", "")

            if status in [200, 301, 302, 401, 403]:
                if status == 200:
                    priority = "Alta"
                    status_text = f"Exposto ({status})"
                elif status in [401, 403]:
                    priority = "Média"
                    status_text = f"Existe, mas protegido ({status})"
                else:
                    priority = "Baixa"
                    status_text = f"Redireciona ({status})"

                description = (
                    f"Endpoint sensível identificado: {target}. "
                    f"Status HTTP: {status}. "
                    f"Content-Type: {content_type}."
                )

                findings.append({
                    "Categoria": "Discovery",
                    "Item": path,
                    "Status": status_text,
                    "Prioridade": priority,
                    "Descrição": description
                })

        except Exception:
            pass

    return findings


# Calcula score de segurança com base nas prioridades
def calculate_score(findings):
    score = 100

    for finding in findings:
        if finding["Prioridade"] == "Alta":
            score -= 15
        elif finding["Prioridade"] == "Média":
            score -= 8
        else:
            score -= 2

    score = max(score, 0)

    if score >= 85:
        classification = "Boa"
    elif score >= 65:
        classification = "Atenção"
    else:
        classification = "Crítica"

    return score, classification


# Calcula score geral considerando Semgrep, Bandit, SCA e último histórico de URL
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


# Analisa uma URL: HTTPS, TLS, headers, exposição, portas e discovery
def analyze_url(url):
    url = normalize_url(url)
    findings = []

    try:
        response = requests.get(url, timeout=10, allow_redirects=True)

        headers = response.headers
        final_url = response.url
        parsed = urlparse(final_url)
        host = parsed.hostname
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        uses_https = parsed.scheme == "https"

        findings.append({
            "Categoria": "HTTPS",
            "Item": "HTTPS",
            "Status": "OK" if uses_https else "Ausente",
            "Prioridade": "Baixa" if uses_https else "Alta",
            "Descrição": "Site utiliza HTTPS." if uses_https else "Site não utiliza HTTPS.",
        })

        if uses_https and host:
            cert_result = check_ssl_certificate(host)
            findings.append({
                "Categoria": "TLS",
                "Item": "Certificado SSL",
                "Status": cert_result["status"],
                "Prioridade": cert_result["priority"],
                "Descrição": cert_result["description"],
            })

        security_headers = {
            "Content-Security-Policy": "Alta",
            "Strict-Transport-Security": "Alta",
            "X-Frame-Options": "Média",
            "X-Content-Type-Options": "Média",
            "Referrer-Policy": "Baixa",
            "Permissions-Policy": "Baixa",
        }

        for header, priority in security_headers.items():
            if header in headers:
                findings.append({
                    "Categoria": "Headers",
                    "Item": header,
                    "Status": "Presente",
                    "Prioridade": "Baixa",
                    "Descrição": headers.get(header),
                })
            else:
                findings.append({
                    "Categoria": "Headers",
                    "Item": header,
                    "Status": "Ausente",
                    "Prioridade": priority,
                    "Descrição": f"{header} ausente.",
                })

        if headers.get("Server"):
            findings.append({
                "Categoria": "Exposição",
                "Item": "Server",
                "Status": "Exposto",
                "Prioridade": "Baixa",
                "Descrição": headers.get("Server"),
            })

        if headers.get("X-Powered-By"):
            findings.append({
                "Categoria": "Exposição",
                "Item": "X-Powered-By",
                "Status": "Exposto",
                "Prioridade": "Média",
                "Descrição": headers.get("X-Powered-By"),
            })

        if host:
            findings.append({
                "Categoria": "Rede",
                "Item": "Porta 80",
                "Status": check_port(host, 80),
                "Prioridade": "Baixa",
                "Descrição": "Verificação HTTP.",
            })

            findings.append({
                "Categoria": "Rede",
                "Item": "Porta 443",
                "Status": check_port(host, 443),
                "Prioridade": "Baixa",
                "Descrição": "Verificação HTTPS.",
            })

        discovery_findings = scan_common_paths(base_url)
        findings.extend(discovery_findings)

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
            "findings": [{
                "Categoria": "Erro",
                "Item": "Conexão",
                "Status": "Erro",
                "Prioridade": "Alta",
                "Descrição": str(e),
            }],
        }


# Gerenciamento simples de falso positivo usando session_state
def init_false_positive_state():
    if "false_positives" not in st.session_state:
        st.session_state.false_positives = set()


def is_false_positive(unique_id):
    return unique_id in st.session_state.false_positives


def add_false_positive(unique_id):
    st.session_state.false_positives.add(unique_id)


def count_false_positives():
    return len(st.session_state.false_positives)


# Filtra falsos positivos de um DataFrame
def filter_false_positives(df, source):
    if df.empty:
        return df

    if source == "semgrep":
        return df[
            ~df.apply(
                lambda row: is_false_positive(f"semgrep_{row['ID']}_{row['Arquivo']}_{row['Linha']}"),
                axis=1
            )
        ]

    if source == "bandit":
        return df[
            ~df.apply(
                lambda row: is_false_positive(f"bandit_{row['Teste']}_{row['Arquivo']}_{row['Linha']}"),
                axis=1
            )
        ]

    if source == "sca":
        return df[
            ~df.apply(
                lambda row: is_false_positive(f"sca_{row['Biblioteca']}_{row['CVE']}"),
                axis=1
            )
        ]

    return df


# Inicialização geral
init_db()

st.set_page_config(page_title="ASPM Dashboard", layout="wide")

init_false_positive_state()

st.title("ASPM Dashboard")
st.caption("Plataforma ASPM com Semgrep, Bandit, SCA, URL Analysis, Discovery, IA, histórico, resumo executivo e gestão de falso positivo.")

st.sidebar.subheader("Governança")
st.sidebar.metric("Falsos positivos marcados", count_false_positives())

if st.sidebar.button("Limpar falsos positivos"):
    st.session_state.false_positives = set()
    st.rerun()


tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
    "Resumo Executivo",
    "Semgrep",
    "Bandit",
    "SCA",
    "URL Analysis",
    "Histórico"
])


# Carregamento padrão dos dados usados no resumo executivo
semgrep_data_default = load_json("data/results.json", {"results": []})
bandit_data_default = load_json("data/bandit.json", {"results": []})
sca_data_default = load_json("data/sca.json", {"dependencies": []})

semgrep_df_default = pd.DataFrame(get_semgrep_vulnerabilities(semgrep_data_default))
bandit_df_default = pd.DataFrame(get_bandit_vulnerabilities(bandit_data_default))
sca_df_default = pd.DataFrame(get_sca_vulnerabilities(sca_data_default))

semgrep_active_df = filter_false_positives(semgrep_df_default, "semgrep")
bandit_active_df = filter_false_positives(bandit_df_default, "bandit")
sca_active_df = filter_false_positives(sca_df_default, "sca")


# Aba Resumo Executivo
with tab1:
    st.subheader("Resumo Executivo")

    st.info(
        "Esta aba consolida os resultados das ferramentas integradas e apresenta uma visão executiva "
        "da postura de segurança da aplicação."
    )

    total_semgrep = len(semgrep_active_df)
    total_bandit = len(bandit_active_df)
    total_sca = len(sca_active_df)

    total_high = 0
    total_medium = 0
    total_low = 0

    for df_source in [semgrep_active_df, bandit_active_df, sca_active_df]:
        if not df_source.empty:
            total_high += df_source[df_source["Prioridade"] == "Alta"].shape[0]
            total_medium += df_source[df_source["Prioridade"] == "Média"].shape[0]
            total_low += df_source[df_source["Prioridade"] == "Baixa"].shape[0]

    history_df = load_url_history()

    latest_url_score = "Sem análise"
    latest_url_classification = "Sem análise"

    if not history_df.empty:
        latest = history_df.iloc[0]
        latest_url_score = latest["score"]
        latest_url_classification = latest["classification"]
        total_high += int(latest["high_count"])
        total_medium += int(latest["medium_count"])
        total_low += int(latest["low_count"])

    general_score, general_classification = calculate_general_score(
        total_high,
        total_medium,
        total_low
    )

    col1, col2, col3, col4, col5 = st.columns(5)

    col1.metric("Score Geral", general_score)
    col2.metric("Postura", general_classification)
    col3.metric("Riscos Altos", total_high)
    col4.metric("Riscos Médios", total_medium)
    col5.metric("Riscos Baixos", total_low)

    st.subheader("Fontes integradas")

    source_table = pd.DataFrame([
        {
            "Fonte": "Semgrep",
            "Objetivo": "Análise estática de código",
            "Achados ativos": total_semgrep
        },
        {
            "Fonte": "Bandit",
            "Objetivo": "Análise de segurança Python",
            "Achados ativos": total_bandit
        },
        {
            "Fonte": "SCA",
            "Objetivo": "Análise de bibliotecas e CVEs",
            "Achados ativos": total_sca
        },
        {
            "Fonte": "URL Analysis",
            "Objetivo": "Exposição, headers, TLS e discovery",
            "Achados ativos": "Último score: " + str(latest_url_score)
        }
    ])

    st.dataframe(source_table, use_container_width=True)

    executive_context = f"""
Score geral: {general_score}
Classificação geral: {general_classification}
Achados Semgrep: {total_semgrep}
Achados Bandit: {total_bandit}
Achados SCA: {total_sca}
Riscos altos: {total_high}
Riscos médios: {total_medium}
Riscos baixos: {total_low}
Último score de URL: {latest_url_score}
Última classificação de URL: {latest_url_classification}
Falsos positivos marcados: {count_false_positives()}
"""

    if st.button("Gerar resumo executivo com IA"):
        summary = ask_executive_summary(executive_context)

        st.subheader("Parecer executivo da IA")
        st.write(summary)

    st.subheader("Recomendação de priorização")

    if total_high > 0:
        st.warning(
            "Priorizar imediatamente os achados de alta severidade, principalmente os relacionados "
            "a execução de código, injeção, exposição de endpoints sensíveis e dependências vulneráveis."
        )
    elif total_medium > 0:
        st.info(
            "A aplicação possui riscos moderados que devem ser tratados antes de novas entregas ou deploys."
        )
    else:
        st.success(
            "Nenhum risco alto ou médio ativo foi identificado nas fontes analisadas."
        )


# Aba Semgrep
with tab2:
    st.subheader("Análise SAST - Semgrep")

    uploaded_file = st.file_uploader(
        "Enviar arquivo JSON do Semgrep",
        type=["json"],
        key="upload_semgrep"
    )

    if uploaded_file is not None:
        semgrep_data = json.load(uploaded_file)
        st.success("Arquivo JSON do Semgrep carregado com sucesso.")
    else:
        st.info("Nenhum arquivo enviado. Usando data/results.json como padrão.")
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

        tabela = filtered_df[["ID", "Arquivo", "Linha", "Severidade", "Prioridade", "Descrição"]]
        st.dataframe(tabela, use_container_width=True)

        csv_data = tabela.to_csv(index=False).encode("utf-8-sig")
        st.download_button("Exportar CSV", csv_data, "semgrep.csv", "text/csv")

        pdf = generate_pdf_report("Relatório Semgrep", f"Total ativo: {len(filtered_df)}", tabela)
        st.download_button("Exportar PDF", pdf, "semgrep.pdf", "application/pdf")

        st.subheader("Detalhamento com IA")

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
        st.info("Nenhuma vulnerabilidade encontrada pelo Semgrep.")


# Aba Bandit
with tab3:
    st.subheader("Análise Python - Bandit")

    st.info(
        "O Bandit é uma ferramenta especializada em segurança para código Python. "
        "Ele ajuda a identificar padrões inseguros como subprocess, exec, eval, pickle, "
        "senhas hardcoded e outros riscos comuns."
    )

    uploaded_bandit = st.file_uploader(
        "Enviar arquivo JSON do Bandit",
        type=["json"],
        key="upload_bandit"
    )

    if uploaded_bandit is not None:
        bandit_data = json.load(uploaded_bandit)
        st.success("Arquivo JSON do Bandit carregado com sucesso.")
    else:
        st.info("Nenhum arquivo enviado. Usando data/bandit.json como padrão.")
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

        tabela = filtered_df[["Teste", "Arquivo", "Linha", "Severidade", "Confiança", "Prioridade", "Descrição"]]
        st.dataframe(tabela, use_container_width=True)

        csv_data = tabela.to_csv(index=False).encode("utf-8-sig")
        st.download_button("Exportar CSV", csv_data, "bandit.csv", "text/csv")

        pdf = generate_pdf_report("Relatório Bandit", f"Total ativo: {len(filtered_df)}", tabela)
        st.download_button("Exportar PDF", pdf, "bandit.pdf", "application/pdf")

        st.subheader("Detalhamento com IA")

        for _, row in filtered_df.iterrows():
            unique_id = f"bandit_{row['Teste']}_{row['Arquivo']}_{row['Linha']}"

            with st.expander(f"{row['Teste']} | {row['Arquivo']} | Linha {row['Linha']}"):
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
        st.success("Nenhum achado encontrado pelo Bandit.")


# Aba SCA
with tab4:
    st.subheader("Software Composition Analysis - SCA")

    st.info(
        "A SCA identifica bibliotecas vulneráveis, CVEs conhecidas e dependências inseguras "
        "utilizadas pela aplicação."
    )

    uploaded_sca = st.file_uploader(
        "Enviar arquivo JSON da SCA",
        type=["json"],
        key="upload_sca"
    )

    if uploaded_sca is not None:
        sca_data = json.load(uploaded_sca)
        st.success("Arquivo SCA carregado com sucesso.")
    else:
        st.info("Nenhum arquivo enviado. Usando data/sca.json como padrão.")
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
                "Descrição"
            ]
        ]

        st.dataframe(tabela, use_container_width=True)

        csv_data = tabela.to_csv(index=False).encode("utf-8-sig")
        st.download_button("Exportar CSV", csv_data, "sca.csv", "text/csv")

        pdf = generate_pdf_report(
            "Relatório SCA",
            f"Total ativo de vulnerabilidades: {len(filtered_df)}",
            tabela
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
        st.success("Nenhuma vulnerabilidade encontrada na SCA.")


# Aba URL Analysis
with tab5:
    st.subheader("Análise Passiva de URL")

    st.info(
        "Esta análise verifica HTTPS, TLS, headers, exposição de servidor, portas e caminhos sensíveis "
        "como /admin, /robots.txt, /swagger, /graphql e /.env."
    )

    url = st.text_input("Digite a URL", placeholder="https://exemplo.com")

    usar_ia_url = st.checkbox("Usar IA para explicar cada achado da URL", value=True)

    limite_ia_url = st.number_input(
        "Limite de achados explicados pela IA",
        min_value=1,
        max_value=50,
        value=10
    )

    if st.button("Analisar URL"):
        if not url.strip():
            st.warning("Digite uma URL.")
        else:
            result = analyze_url(url)

            st.write(f"URL Final: {result['url_final']}")
            st.write(f"Domínio: {result['dominio']}")
            st.write(f"Status HTTP: {result['status_code']}")

            url_df = pd.DataFrame(result["findings"])

            filtered_url_df = url_df[
                ~url_df.apply(
                    lambda row: is_false_positive(f"url_{row['Categoria']}_{row['Item']}"),
                    axis=1
                )
            ]

            high_count = filtered_url_df[filtered_url_df["Prioridade"] == "Alta"].shape[0]
            medium_count = filtered_url_df[filtered_url_df["Prioridade"] == "Média"].shape[0]
            low_count = filtered_url_df[filtered_url_df["Prioridade"] == "Baixa"].shape[0]
            discovery_count = filtered_url_df[filtered_url_df["Categoria"] == "Discovery"].shape[0]

            save_url_history(
                url=result["url_inicial"],
                final_url=result["url_final"],
                score=result["score"],
                classification=result["classificacao"],
                high_count=high_count,
                medium_count=medium_count,
                low_count=low_count
            )

            col1, col2, col3, col4, col5, col6 = st.columns(6)
            col1.metric("Score", result["score"])
            col2.metric("Classificação", result["classificacao"])
            col3.metric("Alta", high_count)
            col4.metric("Média", medium_count)
            col5.metric("Baixa", low_count)
            col6.metric("Discovery", discovery_count)

            st.dataframe(filtered_url_df, use_container_width=True)

            csv_url = filtered_url_df.to_csv(index=False).encode("utf-8-sig")
            st.download_button("Exportar CSV", csv_url, "url_analysis.csv", "text/csv")

            pdf_url = generate_pdf_report(
                "Relatório URL Analysis",
                f"URL analisada: {result['url_final']} | Score: {result['score']} | Classificação: {result['classificacao']}",
                filtered_url_df
            )
            st.download_button("Exportar PDF", pdf_url, "url_analysis.pdf", "application/pdf")

            st.subheader("Detalhamento com IA")

            for index, row in filtered_url_df.iterrows():
                unique_id = f"url_{row['Categoria']}_{row['Item']}"

                if usar_ia_url and index < limite_ia_url:
                    ai_result = ask_ai(row["Item"], row["Descrição"])
                else:
                    ai_result = local_ai_fallback(row["Item"], row["Descrição"])

                with st.expander(f"{row['Categoria']} | {row['Item']} | {row['Status']}"):
                    st.write(f"Categoria: {row['Categoria']}")
                    st.write(f"Status: {row['Status']}")
                    st.write(f"Prioridade: {row['Prioridade']}")
                    st.write(f"Descrição: {row['Descrição']}")
                    st.write("---")
                    st.write(f"Explicação IA: {ai_result['explicacao']}")
                    st.write(f"Risco IA: {ai_result['risco']}")
                    st.write(f"Correção IA: {ai_result['correcao']}")

                    if st.button("Marcar como falso positivo", key=unique_id):
                        add_false_positive(unique_id)
                        st.rerun()


# Aba Histórico
with tab6:
    st.subheader("Histórico de análises de URL")

    history_df = load_url_history()

    if history_df.empty:
        st.info("Nenhuma análise registrada.")
    else:
        st.dataframe(history_df, use_container_width=True)

        csv_history = history_df.to_csv(index=False).encode("utf-8-sig")
        st.download_button("Exportar histórico CSV", csv_history, "historico_url.csv", "text/csv")

        st.subheader("Evolução do Score")

        chart_df = history_df.sort_values("id")[["created_at", "score"]]
        chart_df = chart_df.set_index("created_at")

        st.line_chart(chart_df)