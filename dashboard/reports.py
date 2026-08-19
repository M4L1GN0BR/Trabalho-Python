"""
Geração de relatórios PDF (técnicos e executivo).

Usa ReportLab. Funções puras de apresentação, sem dependência de UI.
"""

from datetime import datetime
from io import BytesIO

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle


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


def generate_executive_report(risk, by_tool=None, scan_time=None, owasp_top=None):
    """
    Gera relatório executivo em PDF com os dados do Risk Engine.

    Parâmetros
    ----------
    risk : dict
        Saída de calculate_risk().
    by_tool : dict, optional
        Contagem de evidências por ferramenta.
    scan_time : str, optional
        Data/hora do scan.
    owasp_top : list, optional
        Categorias OWASP mais frequentes ([{"label", "name", "count"}]).

    Retorna
    -------
    BytesIO
        PDF gerado.
    """
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4)

    styles = getSampleStyleSheet()
    elements = []

    # Cabeçalho
    elements.append(Paragraph("Relatório Executivo - ASPM", styles["Title"]))
    elements.append(Spacer(1, 6))
    elements.append(
        Paragraph(
            f"Gerado em: {scan_time or datetime.now().strftime('%d/%m/%Y %H:%M')}",
            styles["BodyText"],
        )
    )
    elements.append(Spacer(1, 16))

    # Métricas principais
    score_color = colors.green if risk.get("score_geral", 0) >= 85 else (
        colors.orange if risk.get("score_geral", 0) >= 65 else colors.red
    )
    score_para = Paragraph(
        f"Security Score: <b><font color='{score_color.hexval()}'>"
        f"{risk.get('score_geral', 0)}</font></b> - "
        f"Classificação: <b>{risk.get('classificacao', 'N/A')}</b>",
        styles["BodyText"],
    )
    elements.append(score_para)
    elements.append(Spacer(1, 10))

    sev = risk.get("by_severity", {})
    sev_para = Paragraph(
        f"Riscos: Alta <b>{sev.get('Alta', 0)}</b> | "
        f"Média <b>{sev.get('Média', 0)}</b> | "
        f"Baixa <b>{sev.get('Baixa', 0)}</b> | "
        f"Total de evidências: <b>{risk.get('total_evidencias', 0)}</b>",
        styles["BodyText"],
    )
    elements.append(sev_para)
    elements.append(Spacer(1, 10))

    if by_tool:
        tools_para = Paragraph(
            "Ferramentas: " + "; ".join(f"{k}: {v}" for k, v in by_tool.items()),
            styles["BodyText"],
        )
        elements.append(tools_para)
        elements.append(Spacer(1, 10))

    # Justificativa
    elements.append(Paragraph("Justificativa do Score", styles["Heading2"]))
    elements.append(Paragraph(risk.get("justificativa", ""), styles["BodyText"]))
    elements.append(Spacer(1, 12))

    # Riscos prioritários
    elements.append(Paragraph("Riscos Prioritários", styles["Heading2"]))
    prioritarios = risk.get("riscos_prioritarios", [])
    if prioritarios:
        for r in prioritarios[:10]:
            origem = r.get("file") or r.get("endpoint") or r.get("dependency") or "-"
            owasp_tag = f" [{r.get('owasp_label', '')}]" if r.get("owasp_label") else ""
            texto = (
                f"<b>[{r.get('tool', '')}] {r.get('title', '')}</b>{owasp_tag} - "
                f"{r.get('priority', '')} (score {r.get('score', 0)})<br/>"
                f"{origem}<br/>"
                f"{str(r.get('evidence', ''))[:150]}"
            )
            elements.append(Paragraph(texto, styles["BodyText"]))
            elements.append(Spacer(1, 6))
    else:
        elements.append(
            Paragraph("Nenhum risco prioritário. Postura saudável.", styles["BodyText"])
        )

    # Correlações
    correlacoes = risk.get("correlacoes", {})
    if correlacoes:
        elements.append(Spacer(1, 10))
        elements.append(Paragraph("Correlações entre Ferramentas", styles["Heading2"]))
        for alvo, boost in list(correlacoes.items())[:8]:
            elements.append(
                Paragraph(f"- {alvo}: +{boost} pontos", styles["BodyText"])
            )

    # Categorias OWASP Top 10
    if owasp_top:
        elements.append(Spacer(1, 10))
        elements.append(Paragraph("Categorias OWASP Top 10", styles["Heading2"]))
        for cat in owasp_top:
            elements.append(
                Paragraph(
                    f"- {cat['label']} - {cat['name']}: <b>{cat['count']}</b> evidência(s)",
                    styles["BodyText"],
                )
            )

    doc.build(elements)
    buffer.seek(0)
    return buffer
