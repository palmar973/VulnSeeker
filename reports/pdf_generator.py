#!/usr/bin/env python3.14
"""
VulnSeeker Enterprise — PDF Report Generator (Dark Mode Enterprise Edition).

Genera reportes PDF con estética cyberpunk alineada con la GUI y la landing web.
Paleta: fondo #0A0A0A, acento #00FF88 (verde neón), severidad con colores neón.
"""

from reportlab.lib.pagesizes import A4
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
    Image, PageBreak, HRFlowable
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch, cm
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
from reportlab.pdfgen import canvas as pdf_canvas
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.figure import Figure
from io import BytesIO
from pathlib import Path
from datetime import datetime
from typing import List, Optional
from xml.sax.saxutils import escape as _xml_escape
from core.db_manager import DatabaseManager
import traceback


# ═══════════════════════════════════════════════════════════════
#  PALETA DE COLORES — Alineada con GUI + Landing Web
# ═══════════════════════════════════════════════════════════════
class Theme:
    """Colores del sistema VulnSeeker (cyberpunk dark mode)."""
    BG_PRIMARY = colors.HexColor('#0A0A0A')      # Fondo principal
    BG_SECONDARY = colors.HexColor('#151515')     # Fondo cards/tablas
    BG_CARD = colors.HexColor('#1A1A2E')          # Fondo tarjetas KPI
    BG_ROW_ALT = colors.HexColor('#111111')       # Filas alternadas

    TEXT_PRIMARY = colors.HexColor('#E0E0E0')     # Texto principal
    TEXT_SECONDARY = colors.HexColor('#888888')   # Texto secundario
    TEXT_MONO = colors.HexColor('#AAAAAA')        # URLs / código

    ACCENT = colors.HexColor('#00FF88')           # Verde neón (landing)
    ACCENT_DIM = colors.HexColor('#00CC6A')       # Verde neón suave
    BORDER = colors.HexColor('#333333')           # Bordes sutiles

    # Severidad
    CRITICAL = colors.HexColor('#FF3333')
    HIGH = colors.HexColor('#FF3366')             # Rosa neón (landing)
    MEDIUM = colors.HexColor('#FFAA00')           # Naranja (landing)
    LOW = colors.HexColor('#FFFF99')
    INFO = colors.HexColor('#666666')

    SEVERITY_MAP = {
        'CRITICAL': CRITICAL, 'HIGH': HIGH,
        'MEDIUM': MEDIUM, 'LOW': LOW, 'INFO': INFO
    }

    # Colores para gráficos (neón)
    CHART_COLORS = ['#00FF88', '#FF3366', '#FFAA00', '#00BFFF', '#FF66FF']
    PIE_COLORS = {
        'CRITICAL': '#FF3333', 'HIGH': '#FF3366',
        'MEDIUM': '#FFAA00', 'LOW': '#FFFF99', 'INFO': '#666666'
    }


# ═══════════════════════════════════════════════════════════════
#  BACKGROUND RENDERER — Fondo oscuro en cada página
# ═══════════════════════════════════════════════════════════════
class DarkPageTemplate:
    """Dibuja fondo oscuro + footer en cada página del PDF."""

    def __init__(self, target_url: str = ""):
        self.target_url = target_url

    def on_page(self, canvas: pdf_canvas.Canvas, doc) -> None:
        """Callback para cada página."""
        width, height = A4

        # Fondo oscuro completo
        canvas.setFillColor(Theme.BG_PRIMARY)
        canvas.rect(0, 0, width, height, fill=True, stroke=False)

        # Línea verde neón arriba
        canvas.setStrokeColor(Theme.ACCENT)
        canvas.setLineWidth(2)
        canvas.line(40, height - 35, width - 40, height - 35)

        # Header: nombre de herramienta
        canvas.setFont('Helvetica-Bold', 8)
        canvas.setFillColor(Theme.ACCENT)
        canvas.drawString(42, height - 30, 'VULNSEEKER')
        canvas.setFillColor(Theme.TEXT_SECONDARY)
        canvas.setFont('Helvetica', 7)
        canvas.drawRightString(width - 42, height - 30, 'CONFIDENCIAL')

        # Footer
        canvas.setFont('Helvetica', 7)
        canvas.setFillColor(Theme.TEXT_SECONDARY)
        canvas.drawString(42, 25, f'VulnSeeker Enterprise — {self.target_url}')
        canvas.drawRightString(width - 42, 25, f'Página {canvas.getPageNumber()}')

        # Línea verde neón abajo
        canvas.setStrokeColor(Theme.ACCENT_DIM)
        canvas.setLineWidth(0.5)
        canvas.line(40, 38, width - 40, 38)


# ═══════════════════════════════════════════════════════════════
#  PDF GENERATOR — Enterprise Dark Mode
# ═══════════════════════════════════════════════════════════════
class PDFReportGenerator:
    def __init__(self, output_dir: str = "reports") -> None:
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.db_manager = DatabaseManager()
        self._setup_styles()

    def _setup_styles(self) -> None:
        """Configura estilos de texto con paleta dark mode."""
        self.styles = getSampleStyleSheet()

        # Título principal (portada)
        self.title_style = ParagraphStyle(
            'DarkTitle', parent=self.styles['Title'],
            fontSize=36, spaceAfter=10, alignment=TA_CENTER,
            textColor=Theme.ACCENT, fontName='Helvetica-Bold'
        )

        # Subtítulo
        self.subtitle_style = ParagraphStyle(
            'DarkSubtitle', parent=self.styles['Heading2'],
            fontSize=14, spaceAfter=8, alignment=TA_CENTER,
            textColor=Theme.TEXT_SECONDARY, fontName='Helvetica'
        )

        # Heading para secciones
        self.heading_style = ParagraphStyle(
            'DarkHeading', parent=self.styles['Heading1'],
            fontSize=18, spaceBefore=20, spaceAfter=12,
            textColor=Theme.ACCENT, fontName='Helvetica-Bold'
        )

        # Heading 2
        self.heading2_style = ParagraphStyle(
            'DarkHeading2', parent=self.styles['Heading2'],
            fontSize=14, spaceBefore=15, spaceAfter=8,
            textColor=Theme.ACCENT_DIM, fontName='Helvetica-Bold'
        )

        # Texto normal
        self.body_style = ParagraphStyle(
            'DarkBody', parent=self.styles['Normal'],
            fontSize=10, leading=14, spaceAfter=6,
            textColor=Theme.TEXT_PRIMARY, fontName='Helvetica'
        )

        # Texto monoespaciado (URLs, payloads)
        self.mono_style = ParagraphStyle(
            'DarkMono', parent=self.styles['Normal'],
            fontSize=9, leading=12,
            textColor=Theme.TEXT_MONO, fontName='Courier'
        )

        # Texto del resumen IA
        self.ai_style = ParagraphStyle(
            'AIStyle', parent=self.styles['Normal'],
            fontSize=10, leading=15, spaceAfter=6, alignment=TA_JUSTIFY,
            textColor=Theme.TEXT_PRIMARY, fontName='Helvetica',
            leftIndent=10, rightIndent=10
        )

    # ─── ENTRY POINT ───────────────────────────────────────────
    def generate_pdf(self, scan_id: int, ai_summary: Optional[str] = None,
                     output_path: Optional[str] = None) -> str:
        try:
            if not output_path:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"vulnseeker_scan_{scan_id}_{timestamp}.pdf"
                output_path = str(self.output_dir / filename)

            target_url = self.db_manager.get_scan_target(scan_id) or "Unknown"
            page_template = DarkPageTemplate(target_url)

            doc = SimpleDocTemplate(
                output_path, pagesize=A4,
                rightMargin=50, leftMargin=50,
                topMargin=55, bottomMargin=50
            )
            story = []

            # Portada
            story.extend(self._create_cover_page(scan_id))
            story.append(PageBreak())

            # Resumen IA
            if ai_summary:
                story.extend(self._create_executive_summary(ai_summary))
                story.append(PageBreak())

            # Métricas
            story.extend(self._create_metrics_section(scan_id))
            story.append(PageBreak())

            # Hallazgos
            story.extend(self._create_findings_table(scan_id))

            doc.build(story, onFirstPage=page_template.on_page,
                      onLaterPages=page_template.on_page)
            return output_path

        except Exception as e:
            print(f"🔥 ERROR PDF GENERATOR: {e}")
            traceback.print_exc()
            raise

    # ─── PORTADA ───────────────────────────────────────────────
    def _create_cover_page(self, scan_id: int) -> List:
        target_url = self.db_manager.get_scan_target(scan_id)
        scan_date = self.db_manager.get_scan_date(scan_id)
        story = []

        story.append(Spacer(1, 120))

        # Logo / Título
        story.append(Paragraph("VULN<br/>SEEKER", self.title_style))
        story.append(Spacer(1, 5))
        story.append(Paragraph("&lt;SEEKER/&gt;", ParagraphStyle(
            'TagLine', parent=self.subtitle_style,
            fontSize=12, textColor=Theme.ACCENT, fontName='Courier'
        )))
        story.append(Spacer(1, 30))

        # Línea separadora
        story.append(HRFlowable(
            width="80%", thickness=1, color=Theme.ACCENT,
            spaceAfter=30, spaceBefore=0, hAlign='CENTER'
        ))

        # Subtítulo
        story.append(Paragraph(
            "REPORTE DE AUDITORÍA DAST", ParagraphStyle(
                'CoverSub', parent=self.subtitle_style,
                fontSize=16, textColor=Theme.TEXT_PRIMARY,
                fontName='Helvetica-Bold'
            )
        ))
        story.append(Spacer(1, 40))

        # Datos del scan en tabla oscura
        info_data = [
            [self._accent_text('OBJETIVO'), self._mono_text(target_url)],
            [self._accent_text('SCAN ID'), self._mono_text(f'#{scan_id}')],
            [self._accent_text('FECHA'), self._mono_text(scan_date)],
            [self._accent_text('MOTOR'), self._mono_text('VulnSeeker DAST v2.0')],
        ]
        info_table = Table(info_data, colWidths=[2.2 * inch, 3.8 * inch])
        info_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), Theme.BG_SECONDARY),
            ('BOX', (0, 0), (-1, -1), 1, Theme.BORDER),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, Theme.BG_ROW_ALT),
            ('TOPPADDING', (0, 0), (-1, -1), 10),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 10),
            ('LEFTPADDING', (0, 0), (-1, -1), 15),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ]))
        story.append(info_table)

        story.append(Spacer(1, 60))
        story.append(Paragraph(
            "CONFIDENCIAL — SOLO PARA USO INTERNO",
            ParagraphStyle('Conf', parent=self.subtitle_style,
                           fontSize=9, textColor=Theme.HIGH)
        ))

        return story

    # ─── RESUMEN EJECUTIVO IA ──────────────────────────────────
    def _create_executive_summary(self, ai_summary: str) -> List:
        story = []
        story.append(Paragraph("Resumen Ejecutivo (IA)", self.heading_style))
        story.append(Spacer(1, 5))

        # Indicador de fuente
        story.append(Paragraph(
            "Generado por Llama 3.3 70B vía Groq",
            ParagraphStyle('AITag', parent=self.mono_style,
                           fontSize=8, textColor=Theme.ACCENT_DIM)
        ))
        story.append(Spacer(1, 12))

        # Contenido del resumen
        safe_summary = self._safe(ai_summary).replace('\n', '<br/>')
        story.append(Paragraph(safe_summary, self.ai_style))

        return story

    # ─── MÉTRICAS ──────────────────────────────────────────────
    def _create_metrics_section(self, scan_id: int) -> List:
        story = []
        story.append(Paragraph("Métricas de Seguridad", self.heading_style))
        story.append(Spacer(1, 10))

        stats = self.db_manager.get_scan_stats(scan_id)

        # KPI Cards
        kpi_data = [[
            self._kpi_card(str(stats['total_vulns']), 'Vulnerabilidades', Theme.ACCENT),
            self._kpi_card(str(stats['critical_high']), 'Críticas / Alta', Theme.HIGH),
            self._kpi_card(str(stats['medium_low']), 'Media / Baja', Theme.MEDIUM),
        ]]
        kpi_table = Table(kpi_data, colWidths=[2.1 * inch, 2.1 * inch, 2.1 * inch])
        kpi_table.setStyle(TableStyle([
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('TOPPADDING', (0, 0), (-1, -1), 0),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 0),
            ('LEFTPADDING', (0, 0), (-1, -1), 5),
            ('RIGHTPADDING', (0, 0), (-1, -1), 5),
        ]))
        story.append(kpi_table)
        story.append(Spacer(1, 25))

        # Gráficos
        pie_image = self._generate_severity_pie_chart(scan_id)
        if pie_image:
            story.append(Paragraph("Distribución por Severidad", self.heading2_style))
            story.append(Image(pie_image, width=5.5 * inch, height=3.5 * inch))
            story.append(Spacer(1, 15))

        bar_image = self._generate_top_vulns_bar_chart(scan_id)
        if bar_image:
            story.append(Paragraph("Top 5 Vulnerabilidades Recurrentes", self.heading2_style))
            story.append(Image(bar_image, width=5.8 * inch, height=4.5 * inch))

        return story

    # ─── HALLAZGOS ─────────────────────────────────────────────
    def _create_findings_table(self, scan_id: int) -> List:
        story = [Paragraph("Hallazgos Detallados", self.heading_style)]
        vulns = self.db_manager.get_vulnerabilities_by_scan(scan_id)

        if not vulns:
            story.append(Paragraph(
                "No se encontraron vulnerabilidades.",
                self.body_style
            ))
            return story

        story.append(Spacer(1, 8))

        # Header
        header = [
            self._header_text('#'),
            self._header_text('Tipo'),
            self._header_text('Severidad'),
            self._header_text('URL'),
        ]
        table_data = [header]

        for idx, vuln in enumerate(vulns, 1):
            sev_color = Theme.SEVERITY_MAP.get(vuln.severity, Theme.TEXT_SECONDARY)
            safe_sev = self._safe(vuln.severity)
            sev_para = Paragraph(
                f'<font color="{sev_color.hexval()}"><b>{safe_sev}</b></font>',
                self.body_style
            )
            safe_type = self._safe(vuln.vuln_type)
            url_display = vuln.url[:55] + "..." if len(vuln.url) > 55 else vuln.url
            safe_url = self._safe(url_display)

            table_data.append([
                Paragraph(f'<font color="#888888">{idx}</font>', self.body_style),
                Paragraph(f'<font color="#E0E0E0">{safe_type}</font>', self.body_style),
                sev_para,
                Paragraph(f'<font color="#AAAAAA"><font face="Courier">{safe_url}</font></font>',
                          self.body_style),
            ])

        findings_table = Table(table_data,
                               colWidths=[0.55 * inch, 1.9 * inch, 1 * inch, 3.05 * inch])

        # Estilo tabla oscura
        table_style_cmds = [
            # Header
            ('BACKGROUND', (0, 0), (-1, 0), Theme.BG_CARD),
            ('TOPPADDING', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 10),
            # Grid
            ('BOX', (0, 0), (-1, -1), 1, Theme.BORDER),
            ('LINEBELOW', (0, 0), (-1, 0), 1.5, Theme.ACCENT),
            ('INNERGRID', (0, 1), (-1, -1), 0.5, Theme.BG_ROW_ALT),
            # Padding
            ('TOPPADDING', (0, 1), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 1), (-1, -1), 6),
            ('LEFTPADDING', (0, 0), (-1, -1), 8),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ]

        # Filas alternadas oscuras
        for i in range(1, len(table_data)):
            bg = Theme.BG_SECONDARY if i % 2 == 0 else Theme.BG_PRIMARY
            table_style_cmds.append(('BACKGROUND', (0, i), (-1, i), bg))

        findings_table.setStyle(TableStyle(table_style_cmds))
        story.extend([Spacer(1, 8), findings_table])
        return story

    # ─── GRÁFICOS DARK MODE ────────────────────────────────────
    def _generate_severity_pie_chart(self, scan_id: int) -> Optional[BytesIO]:
        try:
            severity_data = self.db_manager.get_severity_distribution_by_scan(scan_id)
            if not severity_data:
                return None
            labels = [row[0] for row in severity_data]
            sizes = [row[1] for row in severity_data]

            fig = Figure(figsize=(8, 5), facecolor='#0A0A0A')
            ax = fig.add_subplot(111)
            ax.set_facecolor('#0A0A0A')

            pie_colors = [Theme.PIE_COLORS.get(l, '#444444') for l in labels]

            wedges, texts, autotexts = ax.pie(
                sizes, labels=None, colors=pie_colors,
                autopct='%1.1f%%', startangle=90, pctdistance=0.82,
                wedgeprops={'edgecolor': '#333333', 'linewidth': 0.5}
            )

            for autotext in autotexts:
                autotext.set_color('#FFFFFF')
                autotext.set_fontsize(10)
                autotext.set_fontweight('bold')

            legend = ax.legend(
                wedges, labels, title="Severidad",
                loc="center left", bbox_to_anchor=(1, 0, 0.5, 1),
                facecolor='#151515', edgecolor='#333333'
            )
            plt.setp(legend.get_texts(), color='#E0E0E0', fontsize=10)
            plt.setp(legend.get_title(), color='#00FF88', fontsize=11, fontweight='bold')

            buf = BytesIO()
            fig.savefig(buf, format='png', dpi=150, bbox_inches='tight',
                        pad_inches=0.2, facecolor='#0A0A0A')
            buf.seek(0)
            plt.close(fig)
            return buf
        except Exception as e:
            print(f"Error Chart PIE: {e}")
            return None

    def _generate_top_vulns_bar_chart(self, scan_id: int) -> Optional[BytesIO]:
        try:
            vuln_data = self.db_manager.get_top_vulns_by_scan(scan_id, 5)
            if not vuln_data:
                return None
            names = [row[0] for row in vuln_data]
            counts = [row[1] for row in vuln_data]

            fig = Figure(figsize=(8, 6), facecolor='#0A0A0A')
            fig.subplots_adjust(bottom=0.35, top=0.92, left=0.1, right=0.95)
            ax = fig.add_subplot(111)
            ax.set_facecolor('#111111')

            bar_colors = Theme.CHART_COLORS[:len(counts)]
            bars = ax.bar(range(len(counts)), counts, color=bar_colors,
                          edgecolor='#333333', linewidth=0.5, width=0.6)

            # Valor encima de cada barra
            for bar, count in zip(bars, counts):
                ax.text(bar.get_x() + bar.get_width() / 2, bar.get_height() + 0.5,
                        str(count), ha='center', va='bottom',
                        color='#E0E0E0', fontsize=11, fontweight='bold')

            max_count = max(counts) if counts else 10
            ax.set_ylim(0, max_count * 1.15)
            ax.set_xticks([])

            # Estilo de ejes
            ax.tick_params(axis='y', labelcolor='#888888', colors='#333333')
            for spine in ax.spines.values():
                spine.set_color('#333333')
                spine.set_linewidth(0.5)
            ax.yaxis.grid(True, linestyle='--', color='#222222', alpha=0.5)
            ax.set_axisbelow(True)

            # Leyenda
            legend_labels = [f"{n} ({c})" for n, c in zip(names, counts)]
            legend = ax.legend(
                bars, legend_labels,
                loc='upper center', bbox_to_anchor=(0.5, -0.02),
                ncol=1, frameon=True, fontsize=9,
                facecolor='#151515', edgecolor='#333333'
            )
            plt.setp(legend.get_texts(), color='#E0E0E0')

            buf = BytesIO()
            fig.savefig(buf, format='png', dpi=150, bbox_inches='tight',
                        pad_inches=0.2, facecolor='#0A0A0A')
            buf.seek(0)
            plt.close(fig)
            return buf
        except Exception as e:
            print(f"Error Chart BAR: {e}")
            traceback.print_exc()
            return None

    # ─── HELPERS ───────────────────────────────────────────────
    @staticmethod
    def _safe(text: str) -> str:
        """Escapa caracteres XML/HTML para ReportLab."""
        if not text:
            return ""
        return _xml_escape(str(text))

    def _accent_text(self, text: str) -> Paragraph:
        """Texto con color acento verde neón."""
        return Paragraph(
            f'<font color="#00FF88"><b>{self._safe(text)}</b></font>',
            self.body_style
        )

    def _mono_text(self, text: str) -> Paragraph:
        """Texto monoespaciado."""
        return Paragraph(
            f'<font face="Courier" color="#AAAAAA">{self._safe(text)}</font>',
            self.body_style
        )

    def _header_text(self, text: str) -> Paragraph:
        """Texto de header de tabla."""
        return Paragraph(
            f'<font color="#00FF88"><b>{self._safe(text)}</b></font>',
            self.body_style
        )

    def _kpi_card(self, value: str, label: str, accent_color: colors.HexColor) -> Table:
        """Crea una tarjeta KPI con número grande y etiqueta."""
        card_data = [
            [Paragraph(
                f'<font color="{accent_color.hexval()}" size="28"><b>{value}</b></font>',
                ParagraphStyle('KPIVal', alignment=TA_CENTER,
                               textColor=accent_color, fontSize=28,
                               leading=34)
            )],
            [Spacer(1, 6)],
            [Paragraph(
                f'<font color="#888888" size="9">{label}</font>',
                ParagraphStyle('KPILabel', alignment=TA_CENTER,
                               textColor=Theme.TEXT_SECONDARY, fontSize=9)
            )]
        ]
        card = Table(card_data, colWidths=[1.9 * inch])
        card.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), Theme.BG_SECONDARY),
            ('BOX', (0, 0), (-1, -1), 1, accent_color),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('TOPPADDING', (0, 0), (-1, 0), 15),
            ('BOTTOMPADDING', (0, -1), (-1, -1), 12),
            ('LEFTPADDING', (0, 0), (-1, -1), 10),
            ('RIGHTPADDING', (0, 0), (-1, -1), 10),
        ]))
        return card
