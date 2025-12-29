#!/usr/bin/env python3.14
"""
VulnSeeker Enterprise - FASE FINAL: PDF PERFECTO.
- FIX: Leyendas con texto NEGRO FORZADO (anula el dark mode global).
- FIX: Visualización garantizada de datos en fondo blanco.
"""

from reportlab.lib.pagesizes import A4
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image, PageBreak
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
import matplotlib

matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.figure import Figure
from io import BytesIO
from pathlib import Path
from datetime import datetime
from typing import List, Optional
from core.db_manager import DatabaseManager
import traceback


class PDFReportGenerator:
    def __init__(self, output_dir: str = "reports") -> None:
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.db_manager = DatabaseManager()
        self.styles = getSampleStyleSheet()

        self.title_style = ParagraphStyle(
            'CustomTitle', parent=self.styles['Title'], fontSize=24,
            spaceAfter=30, alignment=TA_CENTER, textColor=colors.darkblue,
            fontName='Helvetica-Bold'
        )
        self.subtitle_style = ParagraphStyle(
            'CustomSubtitle', parent=self.styles['Heading2'], fontSize=18,
            spaceAfter=12, alignment=TA_CENTER, textColor=colors.darkblue
        )
        self.severity_colors = {
            'CRITICAL': colors.red, 'HIGH': colors.darkred,
            'MEDIUM': colors.orange, 'LOW': colors.yellow, 'INFO': colors.grey
        }

    def generate_pdf(self, scan_id: int, ai_summary: Optional[str] = None, output_path: Optional[str] = None) -> str:
        try:
            if not output_path:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                filename = f"vulnseeker_scan_{scan_id}_{timestamp}.pdf"
                output_path = str(self.output_dir / filename)

            doc = SimpleDocTemplate(
                output_path, pagesize=A4, rightMargin=72, leftMargin=72,
                topMargin=72, bottomMargin=18
            )
            story = []

            story.extend(self._create_cover_page(scan_id))
            story.append(PageBreak())

            if ai_summary:
                story.extend(self._create_executive_summary(ai_summary))
                story.append(PageBreak())

            story.extend(self._create_metrics_section(scan_id))
            story.append(PageBreak())

            story.extend(self._create_findings_table(scan_id))

            doc.build(story)
            return output_path
        except Exception as e:
            print(f"🔥 ERROR PDF GENERATOR: {e}")
            traceback.print_exc()
            raise

    def _create_cover_page(self, scan_id: int) -> List:
        target_url = self.db_manager.get_scan_target(scan_id)
        scan_date = self.db_manager.get_scan_date(scan_id)
        story = []
        story.append(Paragraph("Reporte de Seguridad", self.title_style))
        story.append(Spacer(1, 20))
        story.append(Paragraph("VulnSeeker Enterprise", self.subtitle_style))
        story.append(Spacer(1, 40))
        info_data = [
            ['Objetivo:', target_url], ['Scan ID:', str(scan_id)],
            ['Fecha:', scan_date], ['Herramienta:', 'VulnSeeker DAST']
        ]
        info_table = Table(info_data, colWidths=[2 * inch, 4 * inch])
        info_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('FONTNAME', (0, 0), (0, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 12),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        story.append(info_table)
        return story

    def _create_executive_summary(self, ai_summary: str) -> List:
        story = [
            Paragraph("Resumen Ejecutivo (IA)", self.styles['Heading1']),
            Spacer(1, 12),
            Paragraph(ai_summary.replace('\n', '<br/>'), self.styles['Normal'])
        ]
        return story

    def _create_metrics_section(self, scan_id: int) -> List:
        story = [Paragraph("Métricas de Seguridad", self.styles['Heading1'])]
        stats = self.db_manager.get_scan_stats(scan_id)
        kpi_data = [
            ['Total Vulnerabilidades', str(stats['total_vulns'])],
            ['Críticas/Alta', str(stats['critical_high'])],
            ['Medias/Bajas', str(stats['medium_low'])]
        ]
        kpi_table = Table(kpi_data, colWidths=[3 * inch, 2 * inch])
        kpi_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, -1), colors.lightblue),
            ('FONTNAME', (0, 0), (0, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 14),
            ('ALIGN', (1, 0), (1, -1), 'CENTER'),
            ('GRID', (0, 0), (-1, -1), 2, colors.darkblue)
        ]))
        story.extend([Spacer(1, 12), kpi_table, Spacer(1, 25)])

        pie_image = self._generate_severity_pie_chart(scan_id)
        if pie_image:
            story.append(Paragraph("Distribución de Severidad", self.subtitle_style))
            story.append(Image(pie_image, width=6 * inch, height=4 * inch))
            story.append(Spacer(1, 20))

        bar_image = self._generate_top_vulns_bar_chart(scan_id)
        if bar_image:
            story.append(Paragraph("Top 5 Vulnerabilidades Recurrentes", self.subtitle_style))
            story.append(Image(bar_image, width=6 * inch, height=5.5 * inch))
            story.append(Spacer(1, 12))
        return story

    def _generate_severity_pie_chart(self, scan_id: int) -> Optional[BytesIO]:
        try:
            severity_data = self.db_manager.get_severity_distribution_by_scan(scan_id)
            if not severity_data: return None
            labels = [row[0] for row in severity_data]
            sizes = [row[1] for row in severity_data]

            fig = Figure(figsize=(8, 6), facecolor='white')
            ax = fig.add_subplot(111)
            color_map = {'INFO': '#999999', 'LOW': '#ffff99', 'MEDIUM': '#ffcc99', 'HIGH': '#ff6666',
                         'CRITICAL': '#ff3333'}
            colors = [color_map.get(l, '#cccccc') for l in labels]

            wedges, texts, autotexts = ax.pie(sizes, labels=None, colors=colors, autopct='%1.1f%%', startangle=90,
                                              pctdistance=0.85)

            for autotext in autotexts:
                autotext.set_color('black')
                autotext.set_fontsize(10)
                autotext.set_fontweight('bold')

            legend = ax.legend(wedges, labels, title="Niveles", loc="center left", bbox_to_anchor=(1, 0, 0.5, 1))
            # FIX: Forzar texto negro en leyenda
            plt.setp(legend.get_texts(), color='black')
            plt.setp(legend.get_title(), color='black')

            buf = BytesIO()
            fig.savefig(buf, format='png', dpi=150, bbox_inches='tight', pad_inches=0.2)
            buf.seek(0)
            plt.close(fig)
            return buf
        except Exception as e:
            print(f"Error Chart PIE: {e}")
            return None

    def _generate_top_vulns_bar_chart(self, scan_id: int) -> Optional[BytesIO]:
        """
        Gráfico de Barras con LEYENDA DETALLADA y TEXTO NEGRO FORZADO.
        """
        try:
            vuln_data = self.db_manager.get_top_vulns_by_scan(scan_id, 5)
            if not vuln_data: return None
            names = [row[0] for row in vuln_data]
            counts = [row[1] for row in vuln_data]

            # Ajustamos margen inferior grande para la leyenda
            fig = Figure(figsize=(8, 7), facecolor='white')
            fig.subplots_adjust(bottom=0.35, top=0.9, left=0.1, right=0.9)
            ax = fig.add_subplot(111)

            colors_list = ['#4facfe', '#00f2fe', '#fa709a', '#febefe', '#ffecd2']
            bars = ax.bar(range(len(counts)), counts, color=colors_list[:len(counts)], edgecolor='black', linewidth=0.5)

            max_count = max(counts) if counts else 10
            ax.set_ylim(0, max_count * 1.1)

            ax.set_xticks([])
            ax.tick_params(axis='y', labelcolor='black', colors='black')

            for spine in ax.spines.values():
                spine.set_visible(True)
                spine.set_color('black')
                spine.set_linewidth(1)

            ax.yaxis.grid(True, linestyle='--', which='major', color='grey', alpha=0.25)
            ax.set_axisbelow(True)

            # Leyenda detallada
            legend_labels = [f"{n}: ({c})" for n, c in zip(names, counts)]

            legend = ax.legend(bars, legend_labels,
                               loc='upper center',
                               bbox_to_anchor=(0.5, -0.05),
                               ncol=1,
                               frameon=False,
                               fontsize=10)

            # FIX: Forzar texto negro en la leyenda del gráfico de barras
            plt.setp(legend.get_texts(), color='black')

            buf = BytesIO()
            fig.savefig(buf, format='png', dpi=150, bbox_inches='tight', pad_inches=0.2)
            buf.seek(0)
            plt.close(fig)
            return buf
        except Exception as e:
            print(f"Error Chart BAR: {e}")
            traceback.print_exc()
            return None

    def _create_findings_table(self, scan_id: int) -> List:
        story = [Paragraph("Hallazgos Detallados", self.styles['Heading1'])]
        vulns = self.db_manager.get_vulnerabilities_by_scan(scan_id)
        if not vulns:
            story.append(Paragraph("No se encontraron vulnerabilidades.", self.styles['Normal']))
            return story
        table_data = [['#', 'Tipo', 'Severidad', 'URL']]
        for idx, vuln in enumerate(vulns, 1):
            sev_color = self.severity_colors.get(vuln.severity, colors.black)
            sev_text = f'<font color="{sev_color.hexval()}"><b>{vuln.severity}</b></font>'
            table_data.append([
                str(idx), Paragraph(vuln.vuln_type, self.styles['Normal']),
                Paragraph(sev_text, self.styles['Normal']),
                Paragraph(vuln.url[:60] + "..." if len(vuln.url) > 60 else vuln.url, self.styles['Normal'])
            ])
        findings_table = Table(table_data, colWidths=[0.5 * inch, 2 * inch, 1 * inch, 3 * inch])
        findings_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.darkblue),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('FONTNAME', (0, 0), (0, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.whitesmoke, colors.white]),
            ('VALIGN', (0, 0), (-1, -1), 'TOP')
        ]))
        story.extend([Spacer(1, 12), findings_table])
        return story