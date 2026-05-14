import os
from collections import defaultdict

from reportlab.lib.units import inch
from reportlab.platypus import Image, PageBreak, Paragraph, Spacer, Table, TableStyle

from api.models import StatusChoices

from .base import (
    BaseComplianceReportGenerator,
    ComplianceData,
    get_requirement_metadata,
)
from .charts import create_horizontal_bar_chart, get_chart_color_for_percentage
from .config import (
    COLOR_BORDER_GRAY,
    COLOR_DARK_GRAY,
    COLOR_GRAY,
    COLOR_GRID_GRAY,
    COLOR_HIGH_RISK,
    COLOR_NIS2_BG_BLUE,
    COLOR_NIS2_PRIMARY,
    COLOR_SAFE,
    COLOR_WHITE,
    NIS2_SECTION_TITLES,
    NIS2_SECTIONS,
)


def _extract_section_number(section_string: str) -> str:
    """Extract the section number from a full NIS2 section title.

    NIS2 section strings are formatted like:
    "1 POLICY ON THE SECURITY OF NETWORK AND INFORMATION SYSTEMS..."

    This function extracts just the leading number.

    Args:
        section_string: Full section title string.

    Returns:
        Section number as string (e.g., "1", "2", "11").
    """
    if not section_string:
        return "Other"
    parts = section_string.split()
    if parts and parts[0].isdigit():
        return parts[0]
    return "Other"


class NIS2ReportGenerator(BaseComplianceReportGenerator):
    """
    PDF report generator for NIS2 Directive (EU) 2022/2555.

    This generator creates comprehensive PDF reports containing:
    - Cover page with both Prowler and NIS2 logos
    - Executive summary with overall compliance score
    - Section analysis with horizontal bar chart
    - SubSection breakdown table
    - Critical failed requirements
    - Requirements index organized by section and subsection
    - Detailed findings for failed requirements
    """

    def create_cover_page(self, data: ComplianceData) -> list:
        """
        Create the NIS2 report cover page with both logos.

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
        nis2_logo_path = os.path.join(
            os.path.dirname(__file__), "../../assets/img/nis2_logo.png"
        )

        prowler_logo = Image(prowler_logo_path, width=3.5 * inch, height=0.7 * inch)
        nis2_logo = Image(nis2_logo_path, width=2.3 * inch, height=1.5 * inch)

        logos_table = Table(
            [[prowler_logo, nis2_logo]], colWidths=[4 * inch, 2.5 * inch]
        )
        logos_table.setStyle(
            TableStyle(
                [
                    ("ALIGN", (0, 0), (0, 0), "LEFT"),
                    ("ALIGN", (1, 0), (1, 0), "RIGHT"),
                    ("VALIGN", (0, 0), (0, 0), "MIDDLE"),
                    ("VALIGN", (1, 0), (1, 0), "MIDDLE"),
                ]
            )
        )
        elements.append(logos_table)
        elements.append(Spacer(1, 0.3 * inch))

        # Title
        title = Paragraph(
            "NIS2 Compliance Report<br/>Directive (EU) 2022/2555",
            self.styles["title"],
        )
        elements.append(title)
        elements.append(Spacer(1, 0.3 * inch))

        # Compliance metadata table - use base class helper for consistency
        info_rows = self._build_info_rows(data, language="en")
        # Convert tuples to lists and wrap long text in Paragraphs
        metadata_data = []
        for label, value in info_rows:
            if label in ("Name:", "Description:") and value:
                metadata_data.append(
                    [label, Paragraph(value, self.styles["normal_center"])]
                )
            else:
                metadata_data.append([label, value])

        metadata_table = Table(metadata_data, colWidths=[2 * inch, 4 * inch])
        metadata_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (0, -1), COLOR_NIS2_PRIMARY),
                    ("TEXTCOLOR", (0, 0), (0, -1), COLOR_WHITE),
                    ("FONTNAME", (0, 0), (0, -1), "FiraCode"),
                    ("BACKGROUND", (1, 0), (1, -1), COLOR_NIS2_BG_BLUE),
                    ("TEXTCOLOR", (1, 0), (1, -1), COLOR_GRAY),
                    ("FONTNAME", (1, 0), (1, -1), "PlusJakartaSans"),
                    ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                    ("VALIGN", (0, 0), (-1, -1), "TOP"),
                    ("FONTSIZE", (0, 0), (-1, -1), 11),
                    ("GRID", (0, 0), (-1, -1), 1, COLOR_BORDER_GRAY),
                    ("LEFTPADDING", (0, 0), (-1, -1), 10),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 10),
                    ("TOPPADDING", (0, 0), (-1, -1), 8),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                ]
            )
        )
        elements.append(metadata_table)

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

        elements.append(Paragraph("Executive Summary", self.styles["h1"]))
        elements.append(Spacer(1, 0.1 * inch))

        # Calculate statistics
        total = len(data.requirements)
        passed = sum(1 for r in data.requirements if r.status == StatusChoices.PASS)
        failed = sum(1 for r in data.requirements if r.status == StatusChoices.FAIL)
        manual = sum(1 for r in data.requirements if r.status == StatusChoices.MANUAL)

        # Calculate compliance excluding manual
        evaluated = passed + failed
        overall_compliance = (passed / evaluated * 100) if evaluated > 0 else 100

        # Summary statistics table
        summary_data = [
            ["Metric", "Value"],
            ["Total Requirements", str(total)],
            ["Passed ✓", str(passed)],
            ["Failed ✗", str(failed)],
            ["Manual ⊙", str(manual)],
            ["Overall Compliance", f"{overall_compliance:.1f}%"],
        ]

        summary_table = Table(summary_data, colWidths=[3 * inch, 2 * inch])
        summary_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), COLOR_NIS2_PRIMARY),
                    ("TEXTCOLOR", (0, 0), (-1, 0), COLOR_WHITE),
                    ("BACKGROUND", (0, 2), (0, 2), COLOR_SAFE),
                    ("TEXTCOLOR", (0, 2), (0, 2), COLOR_WHITE),
                    ("BACKGROUND", (0, 3), (0, 3), COLOR_HIGH_RISK),
                    ("TEXTCOLOR", (0, 3), (0, 3), COLOR_WHITE),
                    ("BACKGROUND", (0, 4), (0, 4), COLOR_DARK_GRAY),
                    ("TEXTCOLOR", (0, 4), (0, 4), COLOR_WHITE),
                    ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                    ("FONTNAME", (0, 0), (-1, 0), "PlusJakartaSans"),
                    ("FONTSIZE", (0, 0), (-1, 0), 12),
                    ("FONTSIZE", (0, 1), (-1, -1), 10),
                    ("BOTTOMPADDING", (0, 0), (-1, 0), 10),
                    ("GRID", (0, 0), (-1, -1), 0.5, COLOR_BORDER_GRAY),
                    (
                        "ROWBACKGROUNDS",
                        (1, 1),
                        (1, -1),
                        [COLOR_WHITE, COLOR_NIS2_BG_BLUE],
                    ),
                ]
            )
        )
        elements.append(summary_table)

        return elements

    def create_charts_section(self, data: ComplianceData) -> list:
        """
        Create the charts section with section analysis.

        Args:
            data: Aggregated compliance data.

        Returns:
            List of ReportLab elements.
        """
        elements = []

        # Section chart
        elements.append(Paragraph("Compliance by Section", self.styles["h1"]))
        elements.append(Spacer(1, 0.1 * inch))
        elements.append(
            Paragraph(
                "The following chart shows compliance percentage for each main section "
                "of the NIS2 directive:",
                self.styles["normal_center"],
            )
        )
        elements.append(Spacer(1, 0.1 * inch))

        chart_buffer = self._create_section_chart(data)
        chart_buffer.seek(0)
        chart_image = Image(chart_buffer, width=6.5 * inch, height=5 * inch)
        elements.append(chart_image)
        elements.append(PageBreak())

        # SubSection breakdown table
        elements.append(Paragraph("SubSection Breakdown", self.styles["h1"]))
        elements.append(Spacer(1, 0.1 * inch))

        subsection_table = self._create_subsection_table(data)
        elements.append(subsection_table)

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
        elements.append(Spacer(1, 0.1 * inch))

        # Organize by section number and subsection
        sections = {}
        for req in data.requirements:
            m = get_requirement_metadata(req.id, data.attributes_by_requirement_id)
            if m:
                full_section = getattr(m, "Section", "Other")
                # Extract section number from full title (e.g., "1 POLICY..." -> "1")
                section_num = _extract_section_number(full_section)
                subsection = getattr(m, "SubSection", "")
                description = getattr(m, "Description", req.description)

                if section_num not in sections:
                    sections[section_num] = {}
                if subsection not in sections[section_num]:
                    sections[section_num][subsection] = []

                sections[section_num][subsection].append(
                    {
                        "id": req.id,
                        "description": description,
                        "status": req.status,
                    }
                )

        # Sort by NIS2 section order
        for section in NIS2_SECTIONS:
            if section not in sections:
                continue

            section_title = NIS2_SECTION_TITLES.get(section, f"Section {section}")
            elements.append(Paragraph(section_title, self.styles["h2"]))

            for subsection_name, reqs in sections[section].items():
                if subsection_name:
                    # Truncate long subsection names for display
                    display_subsection = (
                        subsection_name[:80] + "..."
                        if len(subsection_name) > 80
                        else subsection_name
                    )
                    elements.append(Paragraph(display_subsection, self.styles["h3"]))

                for req in reqs:
                    status_indicator = (
                        "✓" if req["status"] == StatusChoices.PASS else "✗"
                    )
                    if req["status"] == StatusChoices.MANUAL:
                        status_indicator = "⊙"

                    desc = (
                        req["description"][:60] + "..."
                        if len(req["description"]) > 60
                        else req["description"]
                    )
                    elements.append(
                        Paragraph(
                            f"{status_indicator} {req['id']}: {desc}",
                            self.styles["normal"],
                        )
                    )

            elements.append(Spacer(1, 0.1 * inch))

        return elements

    def _create_section_chart(self, data: ComplianceData):
        """
        Create the section compliance chart.

        Args:
            data: Aggregated compliance data.

        Returns:
            BytesIO buffer containing the chart image.
        """
        section_scores = defaultdict(lambda: {"passed": 0, "total": 0})

        for req in data.requirements:
            if req.status == StatusChoices.MANUAL:
                continue

            m = get_requirement_metadata(req.id, data.attributes_by_requirement_id)
            if m:
                full_section = getattr(m, "Section", "Other")
                # Extract section number from full title (e.g., "1 POLICY..." -> "1")
                section_num = _extract_section_number(full_section)
                section_scores[section_num]["total"] += 1
                if req.status == StatusChoices.PASS:
                    section_scores[section_num]["passed"] += 1

        # Build labels and values in NIS2 section order
        labels = []
        values = []
        for section in NIS2_SECTIONS:
            if section in section_scores and section_scores[section]["total"] > 0:
                scores = section_scores[section]
                pct = (scores["passed"] / scores["total"]) * 100
                section_title = NIS2_SECTION_TITLES.get(section, f"Section {section}")
                labels.append(section_title)
                values.append(pct)

        return create_horizontal_bar_chart(
            labels=labels,
            values=values,
            xlabel="Compliance (%)",
            color_func=get_chart_color_for_percentage,
        )

    def _create_subsection_table(self, data: ComplianceData) -> Table:
        """
        Create the subsection breakdown table.

        Args:
            data: Aggregated compliance data.

        Returns:
            ReportLab Table element.
        """
        subsection_scores = defaultdict(lambda: {"passed": 0, "failed": 0, "manual": 0})

        for req in data.requirements:
            m = get_requirement_metadata(req.id, data.attributes_by_requirement_id)
            if m:
                full_section = getattr(m, "Section", "")
                subsection = getattr(m, "SubSection", "")
                # Use section number + subsection for grouping
                section_num = _extract_section_number(full_section)
                # Create a shorter key using section number
                if subsection:
                    # Extract subsection number if present (e.g., "1.1 Policy..." -> "1.1")
                    subsection_parts = subsection.split()
                    if subsection_parts:
                        key = subsection_parts[0]  # Just the number like "1.1"
                    else:
                        key = f"{section_num}"
                else:
                    key = section_num

                if req.status == StatusChoices.PASS:
                    subsection_scores[key]["passed"] += 1
                elif req.status == StatusChoices.FAIL:
                    subsection_scores[key]["failed"] += 1
                else:
                    subsection_scores[key]["manual"] += 1

        table_data = [["Section", "Passed", "Failed", "Manual", "Compliance"]]
        for key, scores in sorted(
            subsection_scores.items(), key=lambda x: self._sort_section_key(x[0])
        ):
            total = scores["passed"] + scores["failed"]
            pct = (scores["passed"] / total * 100) if total > 0 else 100
            table_data.append(
                [
                    key,
                    str(scores["passed"]),
                    str(scores["failed"]),
                    str(scores["manual"]),
                    f"{pct:.1f}%",
                ]
            )

        table = Table(
            table_data,
            colWidths=[1.2 * inch, 0.9 * inch, 0.9 * inch, 0.9 * inch, 1.2 * inch],
        )
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), COLOR_NIS2_PRIMARY),
                    ("TEXTCOLOR", (0, 0), (-1, 0), COLOR_WHITE),
                    ("FONTNAME", (0, 0), (-1, 0), "FiraCode"),
                    ("FONTSIZE", (0, 0), (-1, 0), 10),
                    ("ALIGN", (0, 0), (-1, -1), "CENTER"),
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
                        [COLOR_WHITE, COLOR_NIS2_BG_BLUE],
                    ),
                ]
            )
        )

        return table

    def _sort_section_key(self, key: str) -> tuple:
        """Sort section keys numerically (e.g., 1, 1.1, 1.2, 2, 11)."""
        parts = key.split(".")
        result = []
        for part in parts:
            try:
                result.append(int(part))
            except ValueError:
                result.append(float("inf"))
        return tuple(result)
