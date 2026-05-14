import json
import os
import ssl
import socket
import sqlite3
import subprocess
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
            created_at,
            url,
            final_url,
            score,
            classification,
            high_count,
            medium_count,
            low_count
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
    df = pd.read_sql_query(
        "SELECT * FROM url_history ORDER BY id DESC",
        conn
    )
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

    lines = text.splitlines()

    for line in lines:
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

    if "os.system" in text or "command" in text or "injection" in text:
        return "Evite usar os.system com entrada controlada pelo usuário. Prefira subprocess.run com lista de argumentos, sem shell=True."

    return "Revisar a configuração de segurança correspondente e aplicar hardening."


def local_ai_fallback(title, description):
    return {
        "explicacao": f"O item analisado ({title}) indica uma possível fragilidade de configuração ou implementação.",
        "risco": description,
        "correcao": default_correction(f"{title} {description}"),
    }


@st.cache_data(show_spinner=False)
def ask_ai(title, description):
    if not API_KEY or client is None:
        return local_ai_fallback(title, description)

    try:
        prompt = f"""
Você é um especialista em Application Security Posture Management (ASPM).

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


def classify_priority(severity):
    if severity == "ERROR":
        return "Alta"
    if severity == "WARNING":
        return "Média"
    return "Baixa"


def load_results(file_path):
    with open(file_path, "r", encoding="utf-8-sig") as f:
        return json.load(f)


def get_vulnerabilities(data):
    results = data.get("results", [])
    vulns = []

    for item in results:
        severity = item.get("extra", {}).get("severity")
        check_id = item.get("check_id")
        message = clean_text(item.get("extra", {}).get("message"))
        priority = classify_priority(severity)

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


def zap_risk_to_priority(risk):
    risk = str(risk).lower()

    if risk in ["high"]:
        return "Alta"

    if risk in ["medium"]:
        return "Média"

    return "Baixa"


def parse_zap_json(report_path):
    if not os.path.exists(report_path):
        return []

    with open(report_path, "r", encoding="utf-8-sig") as f:
        data = json.load(f)

    alerts = []

    sites = data.get("site", [])

    for site in sites:
        for alert in site.get("alerts", []):
            risk = alert.get("riskdesc", alert.get("risk", "Info"))
            priority = zap_risk_to_priority(str(risk).split(" ")[0])

            alerts.append({
                "Fonte": "OWASP ZAP",
                "Nome": alert.get("name"),
                "Risco": risk,
                "Prioridade": priority,
                "Confiança": alert.get("confidence", "Não informado"),
                "Descrição": clean_text(alert.get("desc", "")),
                "Solução": clean_text(alert.get("solution", "")),
                "Referência": clean_text(alert.get("reference", "")),
            })

    return alerts


def run_zap_baseline(target_url):
    os.makedirs("data/zap", exist_ok=True)

    report_file = "zap_report.json"
    local_report_path = os.path.abspath(os.path.join("data", "zap", report_file))

    if os.path.exists(local_report_path):
        os.remove(local_report_path)

    target_url = normalize_url(target_url)

    command = [
        "docker",
        "run",
        "--rm",
        "-v",
        f"{os.path.abspath('data/zap')}:/zap/wrk:rw",
        "ghcr.io/zaproxy/zaproxy:stable",
        "zap-baseline.py",
        "-t",
        target_url,
        "-J",
        report_file,
    ]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=600,
            encoding="utf-8",
            errors="replace",
        )

        alerts = parse_zap_json(local_report_path)

        return {
            "success": os.path.exists(local_report_path),
            "target": target_url,
            "report_path": local_report_path,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "returncode": result.returncode,
            "alerts": alerts,
        }

    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "target": target_url,
            "report_path": local_report_path,
            "stdout": "",
            "stderr": "Tempo limite atingido ao executar OWASP ZAP.",
            "returncode": -1,
            "alerts": [],
        }

    except Exception as e:
        return {
            "success": False,
            "target": target_url,
            "report_path": local_report_path,
            "stdout": "",
            "stderr": str(e),
            "returncode": -1,
            "alerts": [],
        }


init_db()

st.set_page_config(page_title="ASPM Dashboard", layout="wide")

st.title("ASPM Dashboard")

tab1, tab2, tab3, tab4 = st.tabs([
    "Análise SAST - Semgrep",
    "Análise Passiva de URL",
    "OWASP ZAP Baseline",
    "Histórico"
])


with tab1:
    st.subheader("Análise SAST - Semgrep")

    uploaded_file = st.file_uploader(
        "Enviar arquivo JSON do Semgrep",
        type=["json"]
    )

    if uploaded_file is not None:
        data = json.load(uploaded_file)
        st.success("Arquivo JSON carregado com sucesso.")
    else:
        st.info("Nenhum arquivo enviado. Usando data/results.json como padrão.")
        data = load_results("data/results.json")

    vulnerabilities = get_vulnerabilities(data)

    if vulnerabilities:
        df = pd.DataFrame(vulnerabilities)

        st.subheader("Resumo Geral")
        st.write(f"Total de vulnerabilidades: {len(df)}")

        tabela = df[["ID", "Arquivo", "Linha", "Severidade", "Prioridade", "Descrição"]]
        st.dataframe(tabela, use_container_width=True)

        csv_sast = tabela.to_csv(index=False).encode("utf-8-sig")
        st.download_button("Exportar CSV - Semgrep", csv_sast, "relatorio_semgrep.csv", "text/csv")

        pdf_sast = generate_pdf_report(
            "Relatório ASPM - Semgrep",
            f"Total de vulnerabilidades: {len(df)}",
            tabela,
        )

        st.download_button("Exportar PDF - Semgrep", pdf_sast, "relatorio_semgrep.pdf", "application/pdf")

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
        st.warning("Nenhuma vulnerabilidade encontrada.")


with tab2:
    st.subheader("Análise Passiva de URL")

    st.info(
        "Esta análise verifica configurações expostas pela aplicação. "
        "Use apenas em sites próprios, autorizados ou ambientes de laboratório."
    )

    url = st.text_input("Digite a URL", placeholder="https://exemplo.com", key="url_passiva")

    usar_ia_url = st.checkbox("Usar IA para explicar cada achado da URL", value=True)
    limite_ia_url = st.number_input("Limite de achados explicados pela IA", min_value=1, max_value=20, value=5)

    if st.button("Analisar URL"):
        if not url.strip():
            st.warning("Digite uma URL para analisar.")
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
            st.download_button("Exportar CSV - URL", csv_url, "relatorio_url.csv", "text/csv")

            pdf_url = generate_pdf_report(
                "Relatório ASPM - URL",
                f"URL analisada: {result['url_final']} | Score: {result['score']} | Classificação: {result['classificacao']}",
                url_df,
            )

            st.download_button("Exportar PDF - URL", pdf_url, "relatorio_url.pdf", "application/pdf")

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


with tab3:
    st.subheader("OWASP ZAP Baseline")

    st.info(
        "O ZAP Baseline roda via Docker e usa spider com análise passiva. "
        "Use apenas em aplicações próprias, autorizadas ou ambientes de laboratório."
    )

    zap_url = st.text_input("URL para ZAP Baseline", placeholder="https://juice-shop.herokuapp.com", key="url_zap")

    if st.button("Rodar ZAP Baseline"):
        if not zap_url.strip():
            st.warning("Digite uma URL para executar o ZAP.")
        else:
            with st.spinner("Executando OWASP ZAP Baseline via Docker. Isso pode levar alguns minutos..."):
                zap_result = run_zap_baseline(zap_url)

            st.write(f"Alvo: {zap_result['target']}")
            st.write(f"Return code: {zap_result['returncode']}")
            st.write(f"Relatório: {zap_result['report_path']}")

            if zap_result["stderr"]:
                with st.expander("Logs de erro/aviso do ZAP"):
                    st.code(zap_result["stderr"])

            if zap_result["stdout"]:
                with st.expander("Logs de saída do ZAP"):
                    st.code(zap_result["stdout"])

            alerts = zap_result["alerts"]

            if alerts:
                zap_df = pd.DataFrame(alerts)

                high_count = zap_df[zap_df["Prioridade"] == "Alta"].shape[0]
                medium_count = zap_df[zap_df["Prioridade"] == "Média"].shape[0]
                low_count = zap_df[zap_df["Prioridade"] == "Baixa"].shape[0]

                col1, col2, col3, col4 = st.columns(4)
                col1.metric("Total", len(zap_df))
                col2.metric("Alta", high_count)
                col3.metric("Média", medium_count)
                col4.metric("Baixa", low_count)

                st.dataframe(zap_df, use_container_width=True)

                csv_zap = zap_df.to_csv(index=False).encode("utf-8-sig")
                st.download_button("Exportar CSV - ZAP", csv_zap, "relatorio_zap.csv", "text/csv")

                pdf_zap = generate_pdf_report(
                    "Relatório ASPM - OWASP ZAP Baseline",
                    f"Alvo analisado: {zap_result['target']} | Total de alertas: {len(zap_df)}",
                    zap_df,
                )

                st.download_button("Exportar PDF - ZAP", pdf_zap, "relatorio_zap.pdf", "application/pdf")

                st.subheader("Detalhamento com IA")

                limite_ia_zap = st.number_input("Limite de alertas explicados pela IA", min_value=1, max_value=20, value=5)

                for index, row in zap_df.iterrows():
                    if index < limite_ia_zap:
                        ai_result = ask_ai(row["Nome"], row["Descrição"])
                    else:
                        ai_result = local_ai_fallback(row["Nome"], row["Descrição"])

                    with st.expander(f"{row['Nome']} | {row['Risco']}"):
                        st.write(f"Prioridade: {row['Prioridade']}")
                        st.write(f"Confiança: {row['Confiança']}")
                        st.write(f"Descrição: {row['Descrição']}")
                        st.write(f"Solução ZAP: {row['Solução']}")
                        st.write("---")
                        st.write(f"Explicação IA: {ai_result['explicacao']}")
                        st.write(f"Risco IA: {ai_result['risco']}")
                        st.write(f"Correção IA: {ai_result['correcao']}")
            else:
                st.warning("Nenhum alerta encontrado ou relatório ZAP não foi gerado.")


with tab4:
    st.subheader("Histórico de Análises de URL")

    history_df = load_url_history()

    if history_df.empty:
        st.info("Nenhuma análise registrada ainda.")
    else:
        st.dataframe(history_df, use_container_width=True)

        csv_history = history_df.to_csv(index=False).encode("utf-8-sig")
        st.download_button(
            "Exportar Histórico CSV",
            csv_history,
            "historico_url.csv",
            "text/csv"
        )

        st.subheader("Evolução do Score")

        chart_df = history_df.sort_values("id")[["created_at", "score"]]
        chart_df = chart_df.set_index("created_at")

        st.line_chart(chart_df)