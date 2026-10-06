# NightSync - ASPM (Application Security Posture Management)
# Copyright (C) 2026 Felipe Barbosa Alves (RM570378),
#                    Murilo Garcia Godoy (RM564840),
#                    Lucas Moura Goncalves de Amorim (RM570161),
#                    Caio de Paula Goes (RM569052)
#
# This file is part of NightSync, free software under the GNU General
# Public License as published by the Free Software Foundation, either
# version 3 of the License, or (at your option) any later version.
#
# NightSync is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""
Geração de relatórios PDF (técnicos e executivo).

Usa ReportLab. Funções puras de apresentação, sem dependência de UI.
"""

from datetime import datetime
from html import escape
from io import BytesIO

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (
    LongTable,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    TableStyle,
)


def _compute_col_widths(columns, df, available=527.0, min_w=26.0, max_w=190.0):
    """Distribui a largura das colunas proporcionalmente, preservando o cabeçalho."""
    header_ws = []
    content_ws = []
    for col in columns:
        # Largura mínima para o cabeçalho caber em uma linha (negrito 7pt).
        header_ws.append(len(str(col)) * 4.0 + 8.0)

        longest = len(str(col))
        for value in df[col]:
            longest = max(longest, len(str(value)))
        content_ws.append(max(min_w, min(max_w, longest * 3.4)))

    widths = [max(h, c) for h, c in zip(header_ws, content_ws)]

    total = sum(widths)
    if total > available:
        slack = total - available
        # Reduz primeiro as colunas com folga (acima do mínimo do cabeçalho).
        reducible = sum(w - h for w, h in zip(widths, header_ws))
        if reducible > 0:
            for i in range(len(widths)):
                excess = widths[i] - header_ws[i]
                if excess > 0:
                    widths[i] -= slack * (excess / reducible)
        else:
            # Muitas colunas: até os cabeçalhos precisam encolher.
            widths = [w * (available / total) for w in widths]

    return widths


def _truncate_cell(value, limit=400):
    """Limita o texto de uma célula para nunca exceder a altura de uma página.

    Descrições muito longas (ex.: avisos do GitHub Security Advisory com
    milhares de caracteres) tornariam a célula mais alta que uma página e o
    ReportLab não consegue dividir uma única célula entre páginas.
    """
    s = str(value)
    if len(s) <= limit:
        return s
    cut = s[: limit - 1]
    space = cut.rfind(" ")
    if space > limit // 2:
        cut = cut[:space]
    return cut.rstrip() + "…"


def generate_pdf_report(title, summary, dataframe):
    buffer = BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        leftMargin=28,
        rightMargin=28,
        topMargin=32,
        bottomMargin=32,
    )

    styles = getSampleStyleSheet()
    elements = []

    elements.append(Paragraph(escape(title), styles["Title"]))
    elements.append(Spacer(1, 10))
    elements.append(Paragraph(escape(summary), styles["BodyText"]))
    elements.append(Spacer(1, 14))

    if not dataframe.empty:
        df = dataframe.astype(str)
        columns = list(df.columns)

        header_style = ParagraphStyle(
            "aspm_pdf_header",
            fontName="Helvetica-Bold",
            fontSize=7,
            leading=9,
            textColor=colors.white,
        )
        body_style = ParagraphStyle(
            "aspm_pdf_body",
            fontName="Helvetica",
            fontSize=6.5,
            leading=8.5,
            wordWrap="CJK",
        )

        def _cell(value, style):
            # Escapa caracteres especiais (<>&) para não quebrar o XML do
            # ReportLab, limita o comprimento para a célula caber na página e
            # usa wordWrap='CJK' para quebrar tokens longos (caminhos, URLs,
            # IDs) sem cortar o conteúdo.
            return Paragraph(escape(_truncate_cell(value)), style)

        header_row = [_cell(col, header_style) for col in columns]
        rows = [[_cell(value, body_style) for value in row] for row in df.values.tolist()]
        table_data = [header_row] + rows

        table = LongTable(
            table_data,
            repeatRows=1,
            colWidths=_compute_col_widths(columns, df),
        )
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1e293b")),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("LEFTPADDING", (0, 0), (-1, -1), 4),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                    ("TOPPADDING", (0, 0), (-1, -1), 3),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
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
