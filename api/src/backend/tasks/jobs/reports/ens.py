import os
from collections import defaultdict

from reportlab.lib import colors
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import Image, PageBreak, Paragraph, Spacer, Table, TableStyle

from api.models import StatusChoices

from .base import (
    BaseComplianceReportGenerator,
    ComplianceData,
    get_requirement_metadata,
)
from .charts import create_horizontal_bar_chart, create_radar_chart
from .components import get_color_for_compliance
from .config import (
    COLOR_BG_BLUE,
    COLOR_BLUE,
    COLOR_BORDER_GRAY,
    COLOR_ENS_ALTO,
    COLOR_ENS_AUTO,
    COLOR_ENS_BAJO,
    COLOR_ENS_MANUAL,
    COLOR_ENS_MEDIO,
    COLOR_ENS_OPCIONAL,
    COLOR_ENS_TIPO,
    COLOR_GRAY,
    COLOR_GRID_GRAY,
    COLOR_HIGH_RISK,
    COLOR_SAFE,
    COLOR_WHITE,
    DIMENSION_KEYS,
    DIMENSION_MAPPING,
    DIMENSION_NAMES,
    ENS_NIVEL_ORDER,
    ENS_TIPO_ORDER,
)


class ENSReportGenerator(BaseComplianceReportGenerator):
    """
    PDF report generator for ENS RD2022 framework.

    This generator creates comprehensive PDF reports containing:
    - Cover page with both Prowler and ENS logos
    - Executive summary with overall compliance score
    - Marco/Categoría analysis with charts
    - Security dimensions radar chart
    - Requirement type distribution
    - Execution mode distribution
    - Critical failed requirements (nivel alto)
    - Requirements index
    - Detailed findings for failed and manual requirements
    """

    def create_cover_page(self, data: ComplianceData) -> list:
        """
        Create the ENS report cover page with both logos and legend.

        Args:
            data: Aggregated compliance data.

        Returns:
            List of ReportLab elements.
        """
        elements = []

        # Create logos side by side
        prowler_logo_path = os.path.join(
            os.path.dirname(__file__), "../../assets/img/prowler_logo.png"
        )
        ens_logo_path = os.path.join(
            os.path.dirname(__file__), "../../assets/img/ens_logo.png"
        )

        prowler_logo = Image(prowler_logo_path, width=3.5 * inch, height=0.7 * inch)
        ens_logo = Image(ens_logo_path, width=1.5 * inch, height=2 * inch)

        logos_table = Table(
            [[prowler_logo, ens_logo]], colWidths=[4 * inch, 2.5 * inch]
        )
        logos_table.setStyle(
            TableStyle(
                [
                    ("ALIGN", (0, 0), (0, 0), "LEFT"),
                    ("ALIGN", (1, 0), (1, 0), "RIGHT"),
                    ("VALIGN", (0, 0), (0, 0), "MIDDLE"),
                    ("VALIGN", (1, 0), (1, 0), "TOP"),
                ]
            )
        )
        elements.append(logos_table)
        elements.append(Spacer(1, 0.3 * inch))
        elements.append(
            Paragraph("Informe de Cumplimiento ENS RD 311/2022", self.styles["title"])
        )
        elements.append(Spacer(1, 0.5 * inch))

        # Compliance info table - use base class helper for consistency
        info_rows = self._build_info_rows(data, language="es")
        # Convert tuples to lists and wrap long text in Paragraphs
        info_data = []
        for label, value in info_rows:
            if label in ("Nombre:", "Descripción:") and value:
                info_data.append(
                    [label, Paragraph(value, self.styles["normal_center"])]
                )
            else:
                info_data.append([label, value])

        info_table = Table(info_data, colWidths=[2 * inch, 4 * inch])
        info_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (0, -1), COLOR_BLUE),
                    ("TEXTCOLOR", (0, 0), (0, -1), COLOR_WHITE),
                    ("FONTNAME", (0, 0), (0, -1), "FiraCode"),
                    ("BACKGROUND", (1, 0), (1, -1), COLOR_BG_BLUE),
                    ("TEXTCOLOR", (1, 0), (1, -1), COLOR_GRAY),
                    ("FONTNAME", (1, 0), (1, -1), "PlusJakartaSans"),
                    ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("FONTSIZE", (0, 0), (-1, -1), 11),
                    ("GRID", (0, 0), (-1, -1), 1, colors.Color(0.7, 0.8, 0.9)),
                    ("LEFTPADDING", (0, 0), (-1, -1), 10),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                    ("TOPPADDING", (0, 0), (-1, -1), 8),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                ]
            )
        )
        elements.append(info_table)
        elements.append(Spacer(1, 0.5 * inch))

        # Warning about excluded manual requirements
        manual_count = self._count_manual_requirements(data)
        auto_count = len(
            [r for r in data.requirements if r.status != StatusChoices.MANUAL]
        )

        warning_text = (
            f"<b>AVISO:</b> Este informe no incluye los requisitos de ejecución manual. "
            f"El compliance <b>{data.compliance_id}</b> contiene un total de "
            f"<b>{manual_count} requisitos manuales</b> que no han sido evaluados "
            f"automáticamente y por tanto no están reflejados en las estadísticas de este reporte. "
            f"El análisis se basa únicamente en los <b>{auto_count} requisitos automatizados</b>."
        )
        warning_paragraph = Paragraph(warning_text, self.styles["normal"])
        warning_table = Table([[warning_paragraph]], colWidths=[6 * inch])
        warning_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (0, 0), colors.Color(1.0, 0.95, 0.7)),
                    ("TEXTCOLOR", (0, 0), (0, 0), colors.Color(0.4, 0.3, 0.0)),
                    ("ALIGN", (0, 0), (0, 0), "LEFT"),
                    ("VALIGN", (0, 0), (0, 0), "MIDDLE"),
                    ("BOX", (0, 0), (-1, -1), 2, colors.Color(0.9, 0.7, 0.0)),
                    ("LEFTPADDING", (0, 0), (-1, -1), 15),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 15),
                    ("TOPPADDING", (0, 0), (-1, -1), 12),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
                ]
            )
        )
        elements.append(warning_table)
        elements.append(Spacer(1, 0.5 * inch))

        # Legend
        elements.append(self._create_legend())

        return elements

    def create_executive_summary(self, data: ComplianceData) -> list:
        """
        Create the executive summary with compliance metrics.

        Args:
            data: Aggregated compliance data.

        Returns:
            List of ReportLab elements.
        """
        elements = []

        elements.append(Paragraph("Resumen Ejecutivo", self.styles["h1"]))
        elements.append(Spacer(1, 0.2 * inch))

        # Filter out manual requirements
        auto_requirements = [
            r for r in data.requirements if r.status != StatusChoices.MANUAL
        ]
        total = len(auto_requirements)
        passed = sum(1 for r in auto_requirements if r.status == StatusChoices.PASS)
        failed = sum(1 for r in auto_requirements if r.status == StatusChoices.FAIL)

        overall_compliance = (passed / total * 100) if total > 0 else 0
        compliance_color = get_color_for_compliance(overall_compliance)

        # Summary table
        summary_data = [["Nivel de Cumplimiento Global:", f"{overall_compliance:.2f}%"]]
        summary_table = Table(summary_data, colWidths=[3 * inch, 2 * inch])
        summary_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (0, 0), colors.Color(0.1, 0.3, 0.5)),
                    ("TEXTCOLOR", (0, 0), (0, 0), COLOR_WHITE),
                    ("FONTNAME", (0, 0), (0, 0), "FiraCode"),
                    ("FONTSIZE", (0, 0), (0, 0), 12),
                    ("BACKGROUND", (1, 0), (1, 0), compliance_color),
                    ("TEXTCOLOR", (1, 0), (1, 0), COLOR_WHITE),
                    ("FONTNAME", (1, 0), (1, 0), "FiraCode"),
                    ("FONTSIZE", (1, 0), (1, 0), 16),
                    ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("GRID", (0, 0), (-1, -1), 1.5, colors.Color(0.5, 0.6, 0.7)),
                    ("LEFTPADDING", (0, 0), (-1, -1), 12),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 12),
                    ("TOPPADDING", (0, 0), (-1, -1), 10),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
                ]
            )
        )
        elements.append(summary_table)
        elements.append(Spacer(1, 0.3 * inch))

        # Counts table
        counts_data = [
            ["Estado", "Cantidad", "Porcentaje"],
            [
                "CUMPLE",
                str(passed),
                f"{(passed / total * 100):.1f}%" if total > 0 else "0%",
            ],
            [
                "NO CUMPLE",
                str(failed),
                f"{(failed / total * 100):.1f}%" if total > 0 else "0%",
            ],
            ["TOTAL", str(total), "100%"],
        ]
        counts_table = Table(counts_data, colWidths=[2 * inch, 1.5 * inch, 1.5 * inch])
        counts_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), COLOR_BLUE),
                    ("TEXTCOLOR", (0, 0), (-1, 0), COLOR_WHITE),
                    ("FONTNAME", (0, 0), (-1, 0), "FiraCode"),
                    ("BACKGROUND", (0, 1), (0, 1), COLOR_SAFE),
                    ("TEXTCOLOR", (0, 1), (0, 1), COLOR_WHITE),
                    ("BACKGROUND", (0, 2), (0, 2), COLOR_HIGH_RISK),
                    ("TEXTCOLOR", (0, 2), (0, 2), COLOR_WHITE),
                    ("BACKGROUND", (0, 3), (0, 3), colors.Color(0.4, 0.4, 0.4)),
                    ("TEXTCOLOR", (0, 3), (0, 3), COLOR_WHITE),
                    ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("FONTSIZE", (0, 0), (-1, -1), 10),
                    ("GRID", (0, 0), (-1, -1), 1, COLOR_GRID_GRAY),
                    ("LEFTPADDING", (0, 0), (-1, -1), 8),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                    ("TOPPADDING", (0, 0), (-1, -1), 6),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ]
            )
        )
        elements.append(counts_table)
        elements.append(Spacer(1, 0.3 * inch))

        # Compliance by Nivel
        elements.extend(self._create_nivel_table(data))

        return elements

    def create_charts_section(self, data: ComplianceData) -> list:
        """
        Create the charts section with Marco analysis and radar chart.

        Args:
            data: Aggregated compliance data.

        Returns:
            List of ReportLab elements.
        """
        elements = []

        # Critical failed requirements section (nivel alto) - new page
        elements.append(PageBreak())
        elements.extend(self._create_critical_failed_section(data))

        # Marco y Categorías chart - new page
        elements.append(PageBreak())
        elements.append(
            Paragraph("Análisis por Marcos y Categorías", self.styles["h1"])
        )
        elements.append(Spacer(1, 0.2 * inch))

        marco_cat_chart = self._create_marco_category_chart(data)
        marco_cat_image = Image(marco_cat_chart, width=7 * inch, height=5.5 * inch)
        elements.append(marco_cat_image)

        # Security dimensions radar chart - new page
        elements.append(PageBreak())
        elements.append(
            Paragraph("Análisis por Dimensiones de Seguridad", self.styles["h1"])
        )
        elements.append(Spacer(1, 0.2 * inch))

        radar_buffer = self._create_dimensions_radar_chart(data)
        radar_image = Image(radar_buffer, width=6 * inch, height=6 * inch)
        elements.append(radar_image)
        elements.append(PageBreak())

        # Type distribution
        elements.extend(self._create_tipo_section(data))

        return elements

    def create_requirements_index(self, data: ComplianceData) -> list:
        """
        Create the requirements index organized by Marco and Categoria.

        Args:
            data: Aggregated compliance data.

        Returns:
            List of ReportLab elements.
        """
        elements = []

        elements.append(Paragraph("Índice de Requisitos", self.styles["h1"]))
        elements.append(Spacer(1, 0.2 * inch))

        # Organize by Marco and Categoria
        marcos = {}
        for req in data.requirements:
            if req.status == StatusChoices.MANUAL:
                continue

            m = get_requirement_metadata(req.id, data.attributes_by_requirement_id)
            if m:
                marco = getattr(m, "Marco", "Otros")
                categoria = getattr(m, "Categoria", "Sin categoría")
                descripcion = getattr(m, "DescripcionControl", req.description)
                nivel = getattr(m, "Nivel", "")

                if marco not in marcos:
                    marcos[marco] = {}
                if categoria not in marcos[marco]:
                    marcos[marco][categoria] = []

                marcos[marco][categoria].append(
                    {
                        "id": req.id,
                        "descripcion": descripcion,
                        "nivel": nivel,
                        "status": req.status,
                    }
                )

        for marco_name, categorias in marcos.items():
            elements.append(Paragraph(f"Marco: {marco_name}", self.styles["h2"]))

            for categoria_name, reqs in categorias.items():
                elements.append(Paragraph(f"{categoria_name}", self.styles["h3"]))

                for req in reqs:
                    status_indicator = (
                        "✓" if req["status"] == StatusChoices.PASS else "✗"
                    )
                    nivel_badge = f"[{req['nivel'].upper()}]" if req["nivel"] else ""
                    elements.append(
                        Paragraph(
                            f"{status_indicator} {req['id']} {nivel_badge}",
                            self.styles["normal"],
                        )
                    )

            elements.append(Spacer(1, 0.1 * inch))

        return elements

    def get_footer_text(self, page_num: int) -> tuple[str, str]:
        """
        Get Spanish footer text for ENS report.

        Args:
            page_num: Current page number.

        Returns:
            Tuple of (left_text, right_text) for the footer.
        """
        return f"Página {page_num}", "Powered by Prowler"

    def _count_manual_requirements(self, data: ComplianceData) -> int:
        """Count requirements with manual execution mode."""
        return sum(1 for r in data.requirements if r.status == StatusChoices.MANUAL)

    def _create_legend(self) -> Table:
        """Create the ENS values legend table."""
        legend_text = """
        <b>Nivel (Criticidad del requisito):</b><br/>
        • <b>Alto:</b> Requisitos críticos que deben cumplirse prioritariamente<br/>
        • <b>Medio:</b> Requisitos importantes con impacto moderado<br/>
        • <b>Bajo:</b> Requisitos complementarios de menor criticidad<br/>
        • <b>Opcional:</b> Recomendaciones adicionales no obligatorias<br/>
        <br/>
        <b>Tipo (Clasificación del requisito):</b><br/>
        • <b>Requisito:</b> Obligación establecida por el ENS<br/>
        • <b>Refuerzo:</b> Medida adicional que refuerza un requisito<br/>
        • <b>Recomendación:</b> Buena práctica sugerida<br/>
        • <b>Medida:</b> Acción concreta de implementación<br/>
        <br/>
        <b>Dimensiones de Seguridad:</b><br/>
        • <b>C (Confidencialidad):</b> Protección contra accesos no autorizados<br/>
        • <b>I (Integridad):</b> Garantía de exactitud y completitud<br/>
        • <b>T (Trazabilidad):</b> Capacidad de rastrear acciones<br/>
        • <b>A (Autenticidad):</b> Verificación de identidad<br/>
        • <b>D (Disponibilidad):</b> Acceso cuando se necesita
        """
        legend_paragraph = Paragraph(legend_text, self.styles["normal"])
        legend_table = Table([[legend_paragraph]], colWidths=[6.5 * inch])
        legend_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (0, 0), COLOR_BG_BLUE),
                    ("TEXTCOLOR", (0, 0), (0, 0), COLOR_GRAY),
                    ("ALIGN", (0, 0), (0, 0), "LEFT"),
                    ("VALIGN", (0, 0), (0, 0), "TOP"),
                    ("BOX", (0, 0), (-1, -1), 1.5, colors.Color(0.5, 0.6, 0.8)),
                    ("LEFTPADDING", (0, 0), (-1, -1), 15),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 15),
                    ("TOPPADDING", (0, 0), (-1, -1), 12),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 12),
                ]
            )
        )
        return legend_table

    def _create_nivel_table(self, data: ComplianceData) -> list:
        """Create compliance by nivel table."""
        elements = []
        elements.append(Paragraph("Cumplimiento por Nivel", self.styles["h2"]))

        nivel_data = defaultdict(lambda: {"passed": 0, "total": 0})
        for req in data.requirements:
            if req.status == StatusChoices.MANUAL:
                continue

            m = get_requirement_metadata(req.id, data.attributes_by_requirement_id)
            if m:
                nivel = getattr(m, "Nivel", "").lower()
                nivel_data[nivel]["total"] += 1
                if req.status == StatusChoices.PASS:
                    nivel_data[nivel]["passed"] += 1

        table_data = [["Nivel", "Cumplidos", "Total", "Porcentaje"]]
        nivel_colors = {
            "alto": COLOR_ENS_ALTO,
            "medio": COLOR_ENS_MEDIO,
            "bajo": COLOR_ENS_BAJO,
            "opcional": COLOR_ENS_OPCIONAL,
        }

        for nivel in ENS_NIVEL_ORDER:
            if nivel in nivel_data:
                d = nivel_data[nivel]
                pct = (d["passed"] / d["total"] * 100) if d["total"] > 0 else 0
                table_data.append(
                    [
                        nivel.capitalize(),
                        str(d["passed"]),
                        str(d["total"]),
                        f"{pct:.1f}%",
                    ]
                )

        table = Table(
            table_data, colWidths=[1.5 * inch, 1.5 * inch, 1.5 * inch, 1.5 * inch]
        )
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), COLOR_BLUE),
                    ("TEXTCOLOR", (0, 0), (-1, 0), COLOR_WHITE),
                    ("FONTNAME", (0, 0), (-1, 0), "FiraCode"),
                    ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("FONTSIZE", (0, 0), (-1, -1), 10),
                    ("GRID", (0, 0), (-1, -1), 1, COLOR_GRID_GRAY),
                    ("LEFTPADDING", (0, 0), (-1, -1), 8),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                    ("TOPPADDING", (0, 0), (-1, -1), 6),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ]
            )
        )

        # Color nivel column
        for idx, nivel in enumerate(ENS_NIVEL_ORDER):
            if nivel in nivel_data:
                row_idx = idx + 1
                if row_idx < len(table_data):
                    color = nivel_colors.get(nivel, COLOR_GRAY)
                    table.setStyle(
                        TableStyle(
                            [
                                ("BACKGROUND", (0, row_idx), (0, row_idx), color),
                                ("TEXTCOLOR", (0, row_idx), (0, row_idx), COLOR_WHITE),
                            ]
                        )
                    )

        elements.append(table)
        return elements

    def _create_marco_category_chart(self, data: ComplianceData):
        """Create Marco - Categoría combined compliance chart."""
        # Group by marco + categoria combination
        marco_cat_scores = defaultdict(lambda: {"passed": 0, "total": 0})

        for req in data.requirements:
            if req.status == StatusChoices.MANUAL:
                continue

            m = get_requirement_metadata(req.id, data.attributes_by_requirement_id)
            if m:
                marco = getattr(m, "Marco", "otros")
                categoria = getattr(m, "Categoria", "sin categoría")
                # Combined key: "marco - categoría"
                key = f"{marco} - {categoria}"
                marco_cat_scores[key]["total"] += 1
                if req.status == StatusChoices.PASS:
                    marco_cat_scores[key]["passed"] += 1

        labels = []
        values = []
        for key, scores in sorted(marco_cat_scores.items()):
            if scores["total"] > 0:
                pct = (scores["passed"] / scores["total"]) * 100
                labels.append(key)
                values.append(pct)

        return create_horizontal_bar_chart(
            labels=labels,
            values=values,
            xlabel="Porcentaje de Cumplimiento (%)",
        )

    def _create_dimensions_radar_chart(self, data: ComplianceData):
        """Create security dimensions radar chart."""
        dimension_scores = {dim: {"passed": 0, "total": 0} for dim in DIMENSION_KEYS}

        for req in data.requirements:
            if req.status == StatusChoices.MANUAL:
                continue

            m = get_requirement_metadata(req.id, data.attributes_by_requirement_id)
            if m:
                dimensiones = getattr(m, "Dimensiones", [])
                if isinstance(dimensiones, str):
                    dimensiones = [d.strip().lower() for d in dimensiones.split(",")]
                elif isinstance(dimensiones, list):
                    dimensiones = [
                        d.lower() if isinstance(d, str) else d for d in dimensiones
                    ]

                for dim in dimensiones:
                    if dim in dimension_scores:
                        dimension_scores[dim]["total"] += 1
                        if req.status == StatusChoices.PASS:
                            dimension_scores[dim]["passed"] += 1

        values = []
        for dim in DIMENSION_KEYS:
            scores = dimension_scores[dim]
            if scores["total"] > 0:
                pct = (scores["passed"] / scores["total"]) * 100
            else:
                pct = 100
            values.append(pct)

        return create_radar_chart(
            labels=DIMENSION_NAMES,
            values=values,
            color="#2196F3",
        )

    def _create_tipo_section(self, data: ComplianceData) -> list:
        """Create type distribution section."""
        elements = []
        elements.append(
            Paragraph("Distribución por Tipo de Requisito", self.styles["h1"])
        )
        elements.append(Spacer(1, 0.2 * inch))

        tipo_data = defaultdict(lambda: {"passed": 0, "total": 0})
        for req in data.requirements:
            if req.status == StatusChoices.MANUAL:
                continue

            m = get_requirement_metadata(req.id, data.attributes_by_requirement_id)
            if m:
                tipo = getattr(m, "Tipo", "").lower()
                tipo_data[tipo]["total"] += 1
                if req.status == StatusChoices.PASS:
                    tipo_data[tipo]["passed"] += 1

        table_data = [["Tipo", "Cumplidos", "Total", "Porcentaje"]]
        for tipo in ENS_TIPO_ORDER:
            if tipo in tipo_data:
                d = tipo_data[tipo]
                pct = (d["passed"] / d["total"] * 100) if d["total"] > 0 else 0
                table_data.append(
                    [
                        tipo.capitalize(),
                        str(d["passed"]),
                        str(d["total"]),
                        f"{pct:.1f}%",
                    ]
                )

        table = Table(
            table_data, colWidths=[2 * inch, 1.5 * inch, 1.5 * inch, 1.5 * inch]
        )
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), COLOR_BLUE),
                    ("TEXTCOLOR", (0, 0), (-1, 0), COLOR_WHITE),
                    ("FONTNAME", (0, 0), (-1, 0), "FiraCode"),
                    ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("FONTSIZE", (0, 0), (-1, -1), 10),
                    ("GRID", (0, 0), (-1, -1), 1, COLOR_GRID_GRAY),
                    ("LEFTPADDING", (0, 0), (-1, -1), 8),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                    ("TOPPADDING", (0, 0), (-1, -1), 6),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ]
            )
        )
        elements.append(table)
        return elements

    def _create_critical_failed_section(self, data: ComplianceData) -> list:
        """Create section for critical failed requirements (nivel alto)."""
        elements = []

        elements.append(
            Paragraph("Requisitos Críticos No Cumplidos", self.styles["h1"])
        )
        elements.append(Spacer(1, 0.2 * inch))

        # Get failed requirements with nivel alto
        critical_failed = []
        for req in data.requirements:
            if req.status != StatusChoices.FAIL:
                continue

            m = get_requirement_metadata(req.id, data.attributes_by_requirement_id)
            if m:
                nivel = getattr(m, "Nivel", "").lower()
                if nivel == "alto":
                    critical_failed.append(
                        {
                            "id": req.id,
                            "descripcion": getattr(
                                m, "DescripcionControl", req.description
                            ),
                            "marco": getattr(m, "Marco", ""),
                            "categoria": getattr(m, "Categoria", ""),
                            "tipo": getattr(m, "Tipo", ""),
                        }
                    )

        if not critical_failed:
            elements.append(
                Paragraph(
                    "✅ No hay requisitos críticos (nivel ALTO) que hayan fallado.",
                    self.styles["normal"],
                )
            )
            return elements

        elements.append(
            Paragraph(
                f"Se encontraron <b>{len(critical_failed)} requisitos de nivel ALTO</b> "
                "que no cumplen y requieren atención inmediata:",
                self.styles["normal"],
            )
        )
        elements.append(Spacer(1, 0.2 * inch))

        # Create table - use a cell style without leftIndent for proper alignment
        cell_style = ParagraphStyle(
            "CellStyle",
            parent=self.styles["normal"],
            leftIndent=0,
            spaceBefore=0,
            spaceAfter=0,
        )
        table_data: list = [["ID Requisito", "Marco", "Categoría", "Tipo"]]
        for req in critical_failed:
            table_data.append(
                [
                    req["id"],
                    req["marco"],
                    Paragraph(req["categoria"], cell_style),
                    req["tipo"].capitalize() if req["tipo"] else "",
                ]
            )

        table = Table(
            table_data,
            colWidths=[2 * inch, 1.5 * inch, 1.8 * inch, 1.2 * inch],
        )
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), COLOR_ENS_ALTO),
                    ("TEXTCOLOR", (0, 0), (-1, 0), COLOR_WHITE),
                    ("FONTNAME", (0, 0), (-1, 0), "FiraCode"),
                    ("FONTSIZE", (0, 0), (-1, 0), 10),
                    ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("FONTSIZE", (0, 1), (-1, -1), 9),
                    ("GRID", (0, 0), (-1, -1), 0.5, COLOR_GRID_GRAY),
                    ("LEFTPADDING", (0, 0), (-1, -1), 6),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                    ("TOPPADDING", (0, 0), (-1, -1), 4),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                    (
                        "ROWBACKGROUNDS",
                        (0, 1),
                        (-1, -1),
                        [COLOR_WHITE, colors.Color(1.0, 0.95, 0.95)],
                    ),
                ]
            )
        )
        elements.append(table)

        return elements

    def create_detailed_findings(self, data: ComplianceData, **kwargs) -> list:
        """
        Create detailed findings section with ENS-specific format.

        Shows each failed requirement with:
        - Requirement ID as title
        - Status, Nivel, Tipo, ModoEjecucion badges
        - Dimensiones badges
        - Info table with Descripción, Marco, Categoría, etc.

        Args:
            data: Aggregated compliance data.
            **kwargs: Additional options.

        Returns:
            List of ReportLab elements.
        """
        elements = []
        include_manual = kwargs.get("include_manual", True)

        elements.append(Paragraph("Detalle de Requisitos", self.styles["h1"]))
        elements.append(Spacer(1, 0.2 * inch))

        # Get failed requirements, and optionally manual requirements
        if include_manual:
            failed_requirements = [
                r
                for r in data.requirements
                if r.status in (StatusChoices.FAIL, StatusChoices.MANUAL)
            ]
        else:
            failed_requirements = [
                r for r in data.requirements if r.status == StatusChoices.FAIL
            ]

        if not failed_requirements:
            elements.append(
                Paragraph(
                    "No hay requisitos fallidos para mostrar.",
                    self.styles["normal"],
                )
            )
            return elements

        elements.append(
            Paragraph(
                f"Se muestran {len(failed_requirements)} requisitos que requieren "
                "atención:",
                self.styles["normal"],
            )
        )
        elements.append(Spacer(1, 0.3 * inch))

        # Nivel colors mapping
        nivel_colors = {
            "alto": COLOR_ENS_ALTO,
            "medio": COLOR_ENS_MEDIO,
            "bajo": COLOR_ENS_BAJO,
            "opcional": COLOR_ENS_OPCIONAL,
        }

        for req in failed_requirements:
            m = get_requirement_metadata(req.id, data.attributes_by_requirement_id)

            if not m:
                continue

            nivel = getattr(m, "Nivel", "").lower()
            tipo = getattr(m, "Tipo", "")
            modo = getattr(m, "ModoEjecucion", "")
            dimensiones = getattr(m, "Dimensiones", [])
            descripcion = getattr(m, "DescripcionControl", req.description)
            marco = getattr(m, "Marco", "")
            categoria = getattr(m, "Categoria", "")
            id_grupo = getattr(m, "IdGrupoControl", "")

            # Requirement ID title
            req_title = Table([[req.id]], colWidths=[6.5 * inch])
            req_title.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (0, 0), COLOR_BG_BLUE),
                        ("TEXTCOLOR", (0, 0), (0, 0), COLOR_BLUE),
                        ("FONTNAME", (0, 0), (0, 0), "FiraCode"),
                        ("FONTSIZE", (0, 0), (0, 0), 14),
                        ("ALIGN", (0, 0), (0, 0), "LEFT"),
                        ("BOX", (0, 0), (-1, -1), 2, COLOR_BLUE),
                        ("LEFTPADDING", (0, 0), (-1, -1), 12),
                        ("RIGHTPADDING", (0, 0), (-1, -1), 12),
                        ("TOPPADDING", (0, 0), (-1, -1), 10),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
                    ]
                )
            )
            elements.append(req_title)
            elements.append(Spacer(1, 0.15 * inch))

            # Status and Nivel badges row
            status_color = COLOR_HIGH_RISK  # FAIL
            nivel_color = nivel_colors.get(nivel, COLOR_GRAY)

            badges_row1 = [
                ["State:", "FAIL", "", f"Nivel: {nivel.upper()}"],
            ]
            badges_table1 = Table(
                badges_row1,
                colWidths=[0.7 * inch, 0.8 * inch, 1.5 * inch, 1.5 * inch],
            )
            badges_table1.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (0, 0), colors.Color(0.9, 0.9, 0.9)),
                        ("FONTNAME", (0, 0), (0, 0), "PlusJakartaSans"),
                        ("BACKGROUND", (1, 0), (1, 0), status_color),
                        ("TEXTCOLOR", (1, 0), (1, 0), COLOR_WHITE),
                        ("FONTNAME", (1, 0), (1, 0), "FiraCode"),
                        ("BACKGROUND", (3, 0), (3, 0), nivel_color),
                        ("TEXTCOLOR", (3, 0), (3, 0), COLOR_WHITE),
                        ("FONTNAME", (3, 0), (3, 0), "FiraCode"),
                        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                        ("FONTSIZE", (0, 0), (-1, -1), 11),
                        ("GRID", (0, 0), (1, 0), 0.5, colors.black),
                        ("GRID", (3, 0), (3, 0), 0.5, colors.black),
                        ("LEFTPADDING", (0, 0), (-1, -1), 8),
                        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                        ("TOPPADDING", (0, 0), (-1, -1), 8),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                    ]
                )
            )
            elements.append(badges_table1)
            elements.append(Spacer(1, 0.1 * inch))

            # Tipo and Modo badges row
            tipo_display = f"☰ {tipo.capitalize()}" if tipo else "N/A"
            modo_display = f"☰ {modo.capitalize()}" if modo else "N/A"
            modo_color = (
                COLOR_ENS_AUTO if modo.lower() == "automatico" else COLOR_ENS_MANUAL
            )

            badges_row2 = [[tipo_display, "", modo_display]]
            badges_table2 = Table(
                badges_row2, colWidths=[2.2 * inch, 0.5 * inch, 2.2 * inch]
            )
            badges_table2.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (0, 0), COLOR_ENS_TIPO),
                        ("TEXTCOLOR", (0, 0), (0, 0), COLOR_WHITE),
                        ("FONTNAME", (0, 0), (0, 0), "PlusJakartaSans"),
                        ("BACKGROUND", (2, 0), (2, 0), modo_color),
                        ("TEXTCOLOR", (2, 0), (2, 0), COLOR_WHITE),
                        ("FONTNAME", (2, 0), (2, 0), "PlusJakartaSans"),
                        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                        ("FONTSIZE", (0, 0), (-1, -1), 11),
                        ("GRID", (0, 0), (0, 0), 0.5, colors.black),
                        ("GRID", (2, 0), (2, 0), 0.5, colors.black),
                        ("LEFTPADDING", (0, 0), (-1, -1), 10),
                        ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                        ("TOPPADDING", (0, 0), (-1, -1), 8),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                    ]
                )
            )
            elements.append(badges_table2)
            elements.append(Spacer(1, 0.1 * inch))

            # Dimensiones badges
            if dimensiones:
                if isinstance(dimensiones, str):
                    dim_list = [d.strip().lower() for d in dimensiones.split(",")]
                else:
                    dim_list = [
                        d.lower() if isinstance(d, str) else str(d) for d in dimensiones
                    ]

                dim_badges = []
                for dim in dim_list:
                    if dim in DIMENSION_MAPPING:
                        abbrev, dim_color = DIMENSION_MAPPING[dim]
                        dim_badges.append((abbrev, dim_color))

                if dim_badges:
                    dim_label = [["Dimensiones:"] + [b[0] for b in dim_badges]]
                    dim_widths = [1.2 * inch] + [0.4 * inch] * len(dim_badges)
                    dim_table = Table(dim_label, colWidths=dim_widths)

                    dim_styles = [
                        ("FONTNAME", (0, 0), (0, 0), "PlusJakartaSans"),
                        ("FONTSIZE", (0, 0), (-1, -1), 11),
                        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                        ("LEFTPADDING", (0, 0), (-1, -1), 4),
                        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
                        ("TOPPADDING", (0, 0), (-1, -1), 6),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                    ]
                    for idx, (_, dim_color) in enumerate(dim_badges):
                        col_idx = idx + 1
                        dim_styles.extend(
                            [
                                (
                                    "BACKGROUND",
                                    (col_idx, 0),
                                    (col_idx, 0),
                                    dim_color,
                                ),
                                ("TEXTCOLOR", (col_idx, 0), (col_idx, 0), COLOR_WHITE),
                                ("FONTNAME", (col_idx, 0), (col_idx, 0), "FiraCode"),
                                ("GRID", (col_idx, 0), (col_idx, 0), 0.5, colors.black),
                            ]
                        )

                    dim_table.setStyle(TableStyle(dim_styles))
                    elements.append(dim_table)
                    elements.append(Spacer(1, 0.15 * inch))

            # Info table - use Paragraph for text wrapping
            info_data = [
                [
                    "Descripción:",
                    Paragraph(descripcion, self.styles["normal_center"]),
                ],
                ["Marco:", marco],
                [
                    "Categoría:",
                    Paragraph(categoria, self.styles["normal_center"]),
                ],
                ["ID Grupo Control:", id_grupo],
            ]
            info_table = Table(info_data, colWidths=[2 * inch, 4.5 * inch])
            info_table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (0, -1), COLOR_BLUE),
                        ("TEXTCOLOR", (0, 0), (0, -1), COLOR_WHITE),
                        ("FONTNAME", (0, 0), (0, -1), "FiraCode"),
                        ("FONTSIZE", (0, 0), (0, -1), 10),
                        ("BACKGROUND", (1, 0), (1, -1), COLOR_BG_BLUE),
                        ("TEXTCOLOR", (1, 0), (1, -1), COLOR_GRAY),
                        ("FONTNAME", (1, 0), (1, -1), "PlusJakartaSans"),
                        ("FONTSIZE", (1, 0), (1, -1), 10),
                        ("ALIGN", (0, 0), (0, -1), "LEFT"),
                        ("ALIGN", (1, 0), (1, -1), "LEFT"),
                        ("VALIGN", (0, 0), (-1, -1), "TOP"),
                        ("GRID", (0, 0), (-1, -1), 1, COLOR_BORDER_GRAY),
                        ("LEFTPADDING", (0, 0), (-1, -1), 8),
                        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                        ("TOPPADDING", (0, 0), (-1, -1), 6),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                    ]
                )
            )
            elements.append(info_table)
            elements.append(Spacer(1, 0.3 * inch))

        return elements
