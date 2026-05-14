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


load_dotenv()

API_KEY = os.getenv("GEMINI_API_KEY")
client = genai.Client(api_key=API_KEY) if API_KEY else None
DB_PATH = "data/history.db"


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


def load_url_history():
    conn = sqlite3.connect(DB_PATH)
    df = pd.read_sql_query("SELECT * FROM url_history ORDER BY id DESC", conn)
    conn.close()
    return df


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

    if "x-powered-by" in text:
        return "Remover ou ocultar o header X-Powered-By no servidor."

    if "content-security-policy" in text:
        return "Configurar uma política CSP adequada para reduzir risco de XSS."

    if "strict-transport-security" in text:
        return "Configurar HSTS para reforçar uso obrigatório de HTTPS."

    if "https" in text:
        return "Habilitar HTTPS com certificado TLS válido."

    if "os.system" in text:
        return "Evitar uso de os.system com entrada do usuário. Prefira subprocess.run com lista de argumentos."

    if "subprocess" in text:
        return "Evitar subprocess com shell=True e validar entradas externas."

    if "hardcoded" in text or "password" in text or "secret" in text:
        return "Remover segredo do código e usar variável de ambiente ou cofre de segredos."

    return "Revisar configuração e aplicar hardening."


def local_ai_fallback(title, description):
    return {
        "explicacao": f"O item analisado ({title}) pode representar uma fragilidade de segurança.",
        "risco": description,
        "correcao": default_correction(f"{title} {description}")
    }


@st.cache_data(show_spinner=False)
def ask_ai(title, description):
    if not API_KEY or client is None:
        return local_ai_fallback(title, description)

    try:
        prompt = f"""
Você é um especialista em ASPM, AppSec e segurança de aplicações.

Analise o item abaixo:

TÍTULO:
{title}

DESCRIÇÃO:
{description}

Responda exatamente neste formato:

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


def analyze_url(url):
    url = normalize_url(url)
    findings = []

    try:
        response = requests.get(url, timeout=10, allow_redirects=True)

        headers = response.headers
        final_url = response.url
        parsed = urlparse(final_url)
        host = parsed.hostname
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


init_db()

st.set_page_config(page_title="ASPM Dashboard", layout="wide")

st.title("ASPM Dashboard")
st.caption("Plataforma ASPM com Semgrep, Bandit, análise passiva de URL, IA e histórico.")

tab1, tab2, tab3, tab4 = st.tabs([
    "Semgrep",
    "Bandit",
    "URL Analysis",
    "Histórico"
])


with tab1:
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
        semgrep_data = load_json("data/results.json", {"results": []})

    semgrep_vulns = get_semgrep_vulnerabilities(semgrep_data)

    if semgrep_vulns:
        df = pd.DataFrame(semgrep_vulns)

        high_count = df[df["Prioridade"] == "Alta"].shape[0]
        medium_count = df[df["Prioridade"] == "Média"].shape[0]
        low_count = df[df["Prioridade"] == "Baixa"].shape[0]

        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Total", len(df))
        col2.metric("Alta", high_count)
        col3.metric("Média", medium_count)
        col4.metric("Baixa", low_count)

        tabela = df[["ID", "Arquivo", "Linha", "Severidade", "Prioridade", "Descrição"]]
        st.dataframe(tabela, use_container_width=True)

        csv_data = tabela.to_csv(index=False).encode("utf-8-sig")
        st.download_button("Exportar CSV", csv_data, "semgrep.csv", "text/csv")

        pdf = generate_pdf_report("Relatório Semgrep", f"Total: {len(df)}", tabela)
        st.download_button("Exportar PDF", pdf, "semgrep.pdf", "application/pdf")

        st.subheader("Detalhamento com IA")

        for _, row in df.iterrows():
            with st.expander(f"{row['ID']} | {row['Arquivo']} | Linha {row['Linha']}"):
                st.write(f"Severidade: {row['Severidade']}")
                st.write(f"Prioridade: {row['Prioridade']}")
                st.write(f"Descrição: {row['Descrição']}")
                st.write("---")
                st.write(f"Explicação IA: {row['Explicação IA']}")
                st.write(f"Risco IA: {row['Risco IA']}")
                st.write(f"Correção IA: {row['Correção IA']}")
    else:
        st.info("Nenhuma vulnerabilidade encontrada pelo Semgrep.")


with tab2:
    st.subheader("Análise Python - Bandit")

    st.info(
        "O Bandit é uma ferramenta especializada em segurança para código Python. "
        "Ele ajuda a identificar padrões inseguros como uso perigoso de subprocess, exec, eval, pickle, "
        "senhas hardcoded e outros riscos comuns em aplicações Python."
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
        bandit_data = load_json("data/bandit.json", {"results": []})

    bandit_vulns = get_bandit_vulnerabilities(bandit_data)

    if bandit_vulns:
        df = pd.DataFrame(bandit_vulns)

        high_count = df[df["Prioridade"] == "Alta"].shape[0]
        medium_count = df[df["Prioridade"] == "Média"].shape[0]
        low_count = df[df["Prioridade"] == "Baixa"].shape[0]

        col1, col2, col3, col4 = st.columns(4)
        col1.metric("Total", len(df))
        col2.metric("Alta", high_count)
        col3.metric("Média", medium_count)
        col4.metric("Baixa", low_count)

        tabela = df[["Teste", "Arquivo", "Linha", "Severidade", "Confiança", "Prioridade", "Descrição"]]
        st.dataframe(tabela, use_container_width=True)

        csv_data = tabela.to_csv(index=False).encode("utf-8-sig")
        st.download_button("Exportar CSV", csv_data, "bandit.csv", "text/csv")

        pdf = generate_pdf_report("Relatório Bandit", f"Total: {len(df)}", tabela)
        st.download_button("Exportar PDF", pdf, "bandit.pdf", "application/pdf")

        st.subheader("Detalhamento com IA")

        for _, row in df.iterrows():
            with st.expander(f"{row['Teste']} | {row['Arquivo']} | Linha {row['Linha']}"):
                st.write(f"Severidade: {row['Severidade']}")
                st.write(f"Confiança: {row['Confiança']}")
                st.write(f"Prioridade: {row['Prioridade']}")
                st.write(f"Descrição: {row['Descrição']}")
                st.write("---")
                st.write(f"Explicação IA: {row['Explicação IA']}")
                st.write(f"Risco IA: {row['Risco IA']}")
                st.write(f"Correção IA: {row['Correção IA']}")
    else:
        st.success("Nenhum achado encontrado pelo Bandit.")
        st.write(
            "Isso significa que, no arquivo JSON analisado, o Bandit não encontrou padrões inseguros relevantes "
            "para código Python."
        )


with tab3:
    st.subheader("Análise Passiva de URL")

    st.info(
        "Esta análise verifica configurações expostas pela aplicação, como HTTPS, TLS, headers de segurança, "
        "exposição de servidor e portas HTTP/HTTPS. Use apenas em sites próprios, autorizados ou ambientes de laboratório."
    )

    url = st.text_input("Digite a URL", placeholder="https://exemplo.com")

    usar_ia_url = st.checkbox("Usar IA para explicar cada achado da URL", value=True)

    limite_ia_url = st.number_input(
        "Limite de achados explicados pela IA",
        min_value=1,
        max_value=20,
        value=5
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

            high_count = url_df[url_df["Prioridade"] == "Alta"].shape[0]
            medium_count = url_df[url_df["Prioridade"] == "Média"].shape[0]
            low_count = url_df[url_df["Prioridade"] == "Baixa"].shape[0]

            save_url_history(
                url=result["url_inicial"],
                final_url=result["url_final"],
                score=result["score"],
                classification=result["classificacao"],
                high_count=high_count,
                medium_count=medium_count,
                low_count=low_count
            )

            col1, col2, col3, col4, col5 = st.columns(5)
            col1.metric("Score", result["score"])
            col2.metric("Classificação", result["classificacao"])
            col3.metric("Alta", high_count)
            col4.metric("Média", medium_count)
            col5.metric("Baixa", low_count)

            st.dataframe(url_df, use_container_width=True)

            csv_url = url_df.to_csv(index=False).encode("utf-8-sig")
            st.download_button("Exportar CSV", csv_url, "url_analysis.csv", "text/csv")

            pdf_url = generate_pdf_report(
                "Relatório URL Analysis",
                f"URL analisada: {result['url_final']} | Score: {result['score']} | Classificação: {result['classificacao']}",
                url_df
            )
            st.download_button("Exportar PDF", pdf_url, "url_analysis.pdf", "application/pdf")

            st.subheader("Detalhamento com IA")

            for index, row in url_df.iterrows():
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


with tab4:
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