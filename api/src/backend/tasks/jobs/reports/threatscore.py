import gc

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
from .charts import create_vertical_bar_chart, get_chart_color_for_percentage
from .components import get_color_for_compliance, get_color_for_weight
from .config import COLOR_HIGH_RISK, COLOR_WHITE


class ThreatScoreReportGenerator(BaseComplianceReportGenerator):
    """
    PDF report generator for Prowler ThreatScore framework.

    This generator creates comprehensive PDF reports containing:
    - Compliance overview and metadata
    - Section-by-section compliance scores with charts
    - Overall ThreatScore calculation
    - Critical failed requirements
    - Detailed findings for each requirement
    """

    def create_executive_summary(self, data: ComplianceData) -> list:
        """
        Create the executive summary section with ThreatScore calculation.

        Args:
            data: Aggregated compliance data.

        Returns:
            List of ReportLab elements.
        """
        elements = []

        elements.append(Paragraph("Compliance Score by Sections", self.styles["h1"]))
        elements.append(Spacer(1, 0.2 * inch))

        # Create section score chart
        chart_buffer = self._create_section_score_chart(data)
        chart_image = Image(chart_buffer, width=7 * inch, height=5.5 * inch)
        elements.append(chart_image)

        # Calculate overall ThreatScore
        overall_compliance = self._calculate_threatscore(data)

        elements.append(Spacer(1, 0.3 * inch))

        # Summary table
        summary_data = [["ThreatScore:", f"{overall_compliance:.2f}%"]]
        compliance_color = get_color_for_compliance(overall_compliance)

        summary_table = Table(summary_data, colWidths=[2.5 * inch, 2 * inch])
        summary_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (0, 0), colors.Color(0.1, 0.3, 0.5)),
                    ("TEXTCOLOR", (0, 0), (0, 0), colors.white),
                    ("FONTNAME", (0, 0), (0, 0), "FiraCode"),
                    ("FONTSIZE", (0, 0), (0, 0), 12),
                    ("BACKGROUND", (1, 0), (1, 0), compliance_color),
                    ("TEXTCOLOR", (1, 0), (1, 0), colors.white),
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

        return elements

    def _build_body_sections(self, data: ComplianceData) -> list:
        """Override section order: Requirements Index before Critical Requirements."""
        elements = []

        # Page break to separate from executive summary
        elements.append(PageBreak())

        # Requirements index first
        elements.extend(self.create_requirements_index(data))

        # Critical requirements section (already starts with PageBreak internally)
        elements.extend(self.create_charts_section(data))
        elements.append(PageBreak())
        gc.collect()

        return elements

    def create_charts_section(self, data: ComplianceData) -> list:
        """
        Create the critical failed requirements section.

        Args:
            data: Aggregated compliance data.

        Returns:
            List of ReportLab elements.
        """
        elements = []
        min_risk_level = getattr(self, "_min_risk_level", 4)

        # Start on a new page
        elements.append(PageBreak())
        elements.append(
            Paragraph("Top Requirements by Level of Risk", self.styles["h1"])
        )
        elements.append(Spacer(1, 0.1 * inch))
        elements.append(
            Paragraph(
                f"Critical Failed Requirements (Risk Level ≥ {min_risk_level})",
                self.styles["h2"],
            )
        )
        elements.append(Spacer(1, 0.2 * inch))

        critical_failed = self._get_critical_failed_requirements(data, min_risk_level)

        if not critical_failed:
            elements.append(
                Paragraph(
                    "✅ No critical failed requirements found. Great job!",
                    self.styles["normal"],
                )
            )
        else:
            elements.append(
                Paragraph(
                    f"Found {len(critical_failed)} critical failed requirements "
                    "that require immediate attention:",
                    self.styles["normal"],
                )
            )
            elements.append(Spacer(1, 0.5 * inch))

            table = self._create_critical_requirements_table(critical_failed)
            elements.append(table)

            # Immediate action required banner
            elements.append(Spacer(1, 0.3 * inch))
            elements.append(self._create_action_required_banner())

        return elements

    def create_requirements_index(self, data: ComplianceData) -> list:
        """
        Create the requirements index organized by section and subsection.

        Args:
            data: Aggregated compliance data.

        Returns:
            List of ReportLab elements.
        """
        elements = []

        elements.append(Paragraph("Requirements Index", self.styles["h1"]))

        # Organize requirements by section and subsection
        sections = {}
        for req_id in data.attributes_by_requirement_id:
            m = get_requirement_metadata(req_id, data.attributes_by_requirement_id)
            if m:
                section = getattr(m, "Section", "N/A")
                subsection = getattr(m, "SubSection", "N/A")
                title = getattr(m, "Title", "N/A")

                if section not in sections:
                    sections[section] = {}
                if subsection not in sections[section]:
                    sections[section][subsection] = []

                sections[section][subsection].append({"id": req_id, "title": title})

        section_num = 1
        for section_name, subsections in sections.items():
            elements.append(
                Paragraph(f"{section_num}. {section_name}", self.styles["h2"])
            )

            for subsection_name, requirements in subsections.items():
                elements.append(Paragraph(f"{subsection_name}", self.styles["h3"]))

                for req in requirements:
                    elements.append(
                        Paragraph(
                            f"{req['id']} - {req['title']}", self.styles["normal"]
                        )
                    )

            section_num += 1
            elements.append(Spacer(1, 0.1 * inch))

        return elements

    def _create_section_score_chart(self, data: ComplianceData):
        """
        Create the section compliance score chart using weighted ThreatScore formula.

        The section score uses the same weighted formula as the overall ThreatScore:
        Score = Σ(rate_i * total_findings_i * weight_i * rfac_i) / Σ(total_findings_i * weight_i * rfac_i)
        Where rfac_i = 1 + 0.25 * risk_level

        Sections without findings are shown with 100% score.

        Args:
            data: Aggregated compliance data.

        Returns:
            BytesIO buffer containing the chart image.
        """
        # First, collect ALL sections from requirements (including those without findings)
        all_sections = set()
        sections_data = {}

        for req in data.requirements:
            m = get_requirement_metadata(req.id, data.attributes_by_requirement_id)
            if m:
                section = getattr(m, "Section", "Other")
                all_sections.add(section)

                # Only calculate scores for requirements with findings
                if req.total_findings == 0:
                    continue

                risk_level_raw = getattr(m, "LevelOfRisk", 0)
                weight_raw = getattr(m, "Weight", 0)
                # Ensure numeric types for calculations (compliance data may have str)
                try:
                    risk_level = int(risk_level_raw) if risk_level_raw else 0
                except (ValueError, TypeError):
                    risk_level = 0
                try:
                    weight = int(weight_raw) if weight_raw else 0
                except (ValueError, TypeError):
                    weight = 0

                # ThreatScore formula components
                rate_i = req.passed_findings / req.total_findings
                rfac_i = 1 + 0.25 * risk_level

                if section not in sections_data:
                    sections_data[section] = {
                        "numerator": 0,
                        "denominator": 0,
                    }

                sections_data[section]["numerator"] += (
                    rate_i * req.total_findings * weight * rfac_i
                )
                sections_data[section]["denominator"] += (
                    req.total_findings * weight * rfac_i
                )

        # Calculate percentages for all sections
        labels = []
        values = []
        for section in sorted(all_sections):
            if section in sections_data and sections_data[section]["denominator"] > 0:
                pct = (
                    sections_data[section]["numerator"]
                    / sections_data[section]["denominator"]
                ) * 100
            else:
                # Sections without findings get 100%
                pct = 100.0
            labels.append(section)
            values.append(pct)

        return create_vertical_bar_chart(
            labels=labels,
            values=values,
            ylabel="Compliance Score (%)",
            xlabel="",
            color_func=get_chart_color_for_percentage,
            rotation=0,
        )

    def _calculate_threatscore(self, data: ComplianceData) -> float:
        """
        Calculate the overall ThreatScore using the weighted formula.

        Args:
            data: Aggregated compliance data.

        Returns:
            Overall ThreatScore percentage.
        """
        numerator = 0
        denominator = 0
        has_findings = False

        for req in data.requirements:
            if req.total_findings == 0:
                continue

            has_findings = True
            m = get_requirement_metadata(req.id, data.attributes_by_requirement_id)

            if m:
                risk_level_raw = getattr(m, "LevelOfRisk", 0)
                weight_raw = getattr(m, "Weight", 0)
                # Ensure numeric types for calculations (compliance data may have str)
                try:
                    risk_level = int(risk_level_raw) if risk_level_raw else 0
                except (ValueError, TypeError):
                    risk_level = 0
                try:
                    weight = int(weight_raw) if weight_raw else 0
                except (ValueError, TypeError):
                    weight = 0

                rate_i = req.passed_findings / req.total_findings
                rfac_i = 1 + 0.25 * risk_level

                numerator += rate_i * req.total_findings * weight * rfac_i
                denominator += req.total_findings * weight * rfac_i

        if not has_findings:
            return 100.0
        if denominator > 0:
            return (numerator / denominator) * 100
        return 0.0

    def _get_critical_failed_requirements(
        self, data: ComplianceData, min_risk_level: int
    ) -> list[dict]:
        """
        Get critical failed requirements sorted by risk level and weight.

        Args:
            data: Aggregated compliance data.
            min_risk_level: Minimum risk level threshold.

        Returns:
            List of critical failed requirement dictionaries.
        """
        critical = []

        for req in data.requirements:
            if req.status != StatusChoices.FAIL:
                continue

            m = get_requirement_metadata(req.id, data.attributes_by_requirement_id)

            if m:
                risk_level_raw = getattr(m, "LevelOfRisk", 0)
                weight_raw = getattr(m, "Weight", 0)
                # Ensure numeric types for calculations (compliance data may have str)
                try:
                    risk_level = int(risk_level_raw) if risk_level_raw else 0
                except (ValueError, TypeError):
                    risk_level = 0
                try:
                    weight = int(weight_raw) if weight_raw else 0
                except (ValueError, TypeError):
                    weight = 0

                if risk_level >= min_risk_level:
                    critical.append(
                        {
                            "id": req.id,
                            "risk_level": risk_level,
                            "weight": weight,
                            "title": getattr(m, "Title", "N/A"),
                            "section": getattr(m, "Section", "N/A"),
                        }
                    )

        critical.sort(key=lambda x: (x["risk_level"], x["weight"]), reverse=True)
        return critical

    def _create_critical_requirements_table(self, critical_requirements: list) -> Table:
        """
        Create the critical requirements table.

        Args:
            critical_requirements: List of critical requirement dictionaries.

        Returns:
            ReportLab Table element.
        """
        table_data = [["Risk", "Weight", "Requirement ID", "Title", "Section"]]

        for req in critical_requirements:
            title = req["title"]
            if len(title) > 50:
                title = title[:47] + "..."

            table_data.append(
                [
                    str(req["risk_level"]),
                    str(req["weight"]),
                    req["id"],
                    title,
                    req["section"],
                ]
            )

        table = Table(
            table_data,
            colWidths=[0.7 * inch, 0.9 * inch, 1.3 * inch, 3.1 * inch, 1.5 * inch],
        )

        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), COLOR_HIGH_RISK),
                    ("TEXTCOLOR", (0, 0), (-1, 0), COLOR_WHITE),
                    ("FONTNAME", (0, 0), (-1, 0), "FiraCode"),
                    ("FONTSIZE", (0, 0), (-1, 0), 10),
                    ("BACKGROUND", (0, 1), (0, -1), COLOR_HIGH_RISK),
                    ("TEXTCOLOR", (0, 1), (0, -1), COLOR_WHITE),
                    ("FONTNAME", (0, 1), (0, -1), "FiraCode"),
                    ("ALIGN", (0, 1), (0, -1), "CENTER"),
                    ("FONTSIZE", (0, 1), (0, -1), 12),
                    ("ALIGN", (1, 1), (1, -1), "CENTER"),
                    ("FONTNAME", (1, 1), (1, -1), "FiraCode"),
                    ("FONTNAME", (2, 1), (2, -1), "FiraCode"),
                    ("FONTSIZE", (2, 1), (2, -1), 9),
                    ("FONTNAME", (3, 1), (-1, -1), "PlusJakartaSans"),
                    ("FONTSIZE", (3, 1), (-1, -1), 8),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("GRID", (0, 0), (-1, -1), 1, colors.Color(0.7, 0.7, 0.7)),
                    ("LEFTPADDING", (0, 0), (-1, -1), 6),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                    ("TOPPADDING", (0, 0), (-1, -1), 8),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                    ("BACKGROUND", (1, 1), (-1, -1), colors.Color(0.98, 0.98, 0.98)),
                ]
            )
        )

        # Color weight column based on value
        for idx, req in enumerate(critical_requirements):
            row_idx = idx + 1
            weight_color = get_color_for_weight(req["weight"])
            table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (1, row_idx), (1, row_idx), weight_color),
                        ("TEXTCOLOR", (1, row_idx), (1, row_idx), COLOR_WHITE),
                    ]
                )
            )

        return table

    def _create_action_required_banner(self) -> Table:
        """
        Create the 'Immediate Action Required' banner for critical requirements.

        Returns:
            ReportLab Table element styled as a red-bordered alert banner.
        """
        banner_style = ParagraphStyle(
            "ActionRequired",
            fontName="PlusJakartaSans",
            fontSize=11,
            textColor=COLOR_HIGH_RISK,
            leading=16,
        )

        banner_content = Paragraph(
            "<b>IMMEDIATE ACTION REQUIRED:</b><br/>"
            "These requirements have the highest risk levels and have failed "
            "compliance checks. Please prioritize addressing these issues to "
            "improve your security posture.",
            banner_style,
        )

        banner_table = Table(
            [[banner_content]],
            colWidths=[6.5 * inch],
        )
        banner_table.setStyle(
            TableStyle(
                [
                    (
                        "BACKGROUND",
                        (0, 0),
                        (0, 0),
                        colors.Color(0.98, 0.92, 0.92),
                    ),
                    ("BOX", (0, 0), (0, 0), 2, COLOR_HIGH_RISK),
                    ("LEFTPADDING", (0, 0), (0, 0), 20),
                    ("RIGHTPADDING", (0, 0), (0, 0), 20),
                    ("TOPPADDING", (0, 0), (0, 0), 15),
                    ("BOTTOMPADDING", (0, 0), (0, 0), 15),
                ]
            )
        )

        return banner_table
