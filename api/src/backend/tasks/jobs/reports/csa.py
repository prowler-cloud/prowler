from collections import defaultdict

from celery.utils.log import get_task_logger
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
    COLOR_BG_BLUE,
    COLOR_BLUE,
    COLOR_BORDER_GRAY,
    COLOR_DARK_GRAY,
    COLOR_GRID_GRAY,
    COLOR_HIGH_RISK,
    COLOR_SAFE,
    COLOR_WHITE,
    CSA_CCM_SECTION_SHORT_NAMES,
    CSA_CCM_SECTIONS,
)

logger = get_task_logger(__name__)


class CSAReportGenerator(BaseComplianceReportGenerator):
    """
    PDF report generator for CSA Cloud Controls Matrix (CCM) v4.0.

    This generator creates comprehensive PDF reports containing:
    - Cover page with Prowler logo
    - Executive summary with overall compliance score
    - Section analysis with horizontal bar chart
    - Section breakdown table
    - Requirements index organized by section
    - Detailed findings for failed requirements
    """

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

        logger.info(
            "CSA CCM Executive Summary: total=%d, passed=%d, failed=%d, manual=%d",
            total,
            passed,
            failed,
            manual,
        )

        # Log sample of requirements for debugging
        for req in data.requirements[:5]:
            logger.info(
                "  Requirement %s: status=%s, passed_findings=%d, total_findings=%d",
                req.id,
                req.status,
                req.passed_findings,
                req.total_findings,
            )

        # Calculate compliance excluding manual
        evaluated = passed + failed
        overall_compliance = (passed / evaluated * 100) if evaluated > 0 else 100

        # Summary statistics table
        summary_data = [
            ["Metric", "Value"],
            ["Total Requirements", str(total)],
            ["Passed \u2713", str(passed)],
            ["Failed \u2717", str(failed)],
            ["Manual \u2299", str(manual)],
            ["Overall Compliance", f"{overall_compliance:.1f}%"],
        ]

        summary_table = Table(summary_data, colWidths=[3 * inch, 2 * inch])
        summary_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), COLOR_BLUE),
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
                        [COLOR_WHITE, COLOR_BG_BLUE],
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
                "The following chart shows compliance percentage for each domain "
                "of the CSA Cloud Controls Matrix:",
                self.styles["normal_center"],
            )
        )
        elements.append(Spacer(1, 0.1 * inch))

        chart_buffer = self._create_section_chart(data)
        chart_buffer.seek(0)
        chart_image = Image(chart_buffer, width=6.5 * inch, height=5 * inch)
        elements.append(chart_image)
        elements.append(PageBreak())

        # Section breakdown table
        elements.append(Paragraph("Section Breakdown", self.styles["h1"]))
        elements.append(Spacer(1, 0.1 * inch))

        section_table = self._create_section_table(data)
        elements.append(section_table)

        return elements

    def create_requirements_index(self, data: ComplianceData) -> list:
        """
        Create the requirements index organized by section.

        Args:
            data: Aggregated compliance data.

        Returns:
            List of ReportLab elements.
        """
        elements = []

        elements.append(Paragraph("Requirements Index", self.styles["h1"]))
        elements.append(Spacer(1, 0.1 * inch))

        # Organize by section
        sections = {}
        for req in data.requirements:
            m = get_requirement_metadata(req.id, data.attributes_by_requirement_id)
            if m:
                section = getattr(m, "Section", "Other")

                if section not in sections:
                    sections[section] = []

                sections[section].append(
                    {
                        "id": req.id,
                        "description": req.description,
                        "status": req.status,
                    }
                )

        # Sort by CSA CCM section order
        for section in CSA_CCM_SECTIONS:
            if section not in sections:
                continue

            elements.append(Paragraph(section, self.styles["h2"]))

            for req in sections[section]:
                status_indicator = (
                    "\u2713" if req["status"] == StatusChoices.PASS else "\u2717"
                )
                if req["status"] == StatusChoices.MANUAL:
                    status_indicator = "\u2299"

                desc = (
                    req["description"][:80] + "..."
                    if len(req["description"]) > 80
                    else req["description"]
                )
                elements.append(
                    Paragraph(
                        f"{status_indicator} <b>{req['id']}</b>: {desc}",
                        self.styles["normal"],
                    )
                )

            elements.append(Spacer(1, 0.1 * inch))

        return elements

    def _render_requirement_detail_extras(self, req, data: ComplianceData) -> list:
        """
        Render CSA CCM attributes in the detailed findings view.

        Shows CCMLite flag, IaaS/PaaS/SaaS applicability, and
        cross-framework references after the status badge for each requirement.

        Args:
            req: The requirement being rendered.
            data: Aggregated compliance data.

        Returns:
            List of ReportLab elements.
        """
        m = get_requirement_metadata(req.id, data.attributes_by_requirement_id)
        if not m:
            return []
        return self._format_requirement_attributes(m)

    def _format_requirement_attributes(self, m) -> list:
        """
        Format CSA CCM requirement attributes as compact PDF elements.

        Displays CCMLite flag, IaaS/PaaS/SaaS applicability, and
        cross-framework references from ScopeApplicability.

        Args:
            m: Requirement metadata (CSA_CCM_Requirement_Attribute).

        Returns:
            List of ReportLab elements.
        """
        elements = []

        # Applicability line: CCMLite | IaaS | PaaS | SaaS
        ccm_lite = getattr(m, "CCMLite", "")
        iaas = getattr(m, "IaaS", "")
        paas = getattr(m, "PaaS", "")
        saas = getattr(m, "SaaS", "")

        applicability_parts = []
        if ccm_lite:
            applicability_parts.append(f"CCMLite: {ccm_lite}")
        if iaas:
            applicability_parts.append(f"IaaS: {iaas}")
        if paas:
            applicability_parts.append(f"PaaS: {paas}")
        if saas:
            applicability_parts.append(f"SaaS: {saas}")

        if applicability_parts:
            elements.append(
                Paragraph(
                    f"<font color='#4A5568' size='10'>"
                    f"{'&nbsp;&nbsp;|&nbsp;&nbsp;'.join(applicability_parts)}"
                    f"</font>",
                    self._attr_style(),
                )
            )

        # ScopeApplicability references (compact)
        scope_list = getattr(m, "ScopeApplicability", [])
        if scope_list:
            refs = []
            for scope in scope_list:
                ref_id = scope.get("ReferenceId", "") if isinstance(scope, dict) else ""
                identifiers = (
                    scope.get("Identifiers", []) if isinstance(scope, dict) else []
                )
                if ref_id and identifiers:
                    ids_str = ", ".join(str(i) for i in identifiers[:4])
                    if len(identifiers) > 4:
                        ids_str += "..."
                    refs.append(f"{ref_id}: {ids_str}")

            if refs:
                refs_text = "&nbsp;&nbsp;|&nbsp;&nbsp;".join(refs)
                elements.append(
                    Paragraph(
                        f"<font color='#718096' size='9'>{refs_text}</font>",
                        self._attr_style(),
                    )
                )

        return elements

    def _attr_style(self):
        """
        Return a compact style for attribute text lines.

        Returns:
            ParagraphStyle for attribute display.
        """
        from reportlab.lib.styles import ParagraphStyle

        return ParagraphStyle(
            "AttrLine",
            parent=self.styles["normal"],
            fontSize=10,
            spaceBefore=2,
            spaceAfter=2,
            leftIndent=30,
            leading=13,
        )

    def _create_section_chart(self, data: ComplianceData):
        """
        Create the section compliance chart.

        Args:
            data: Aggregated compliance data.

        Returns:
            BytesIO buffer containing the chart image.
        """
        section_scores = defaultdict(lambda: {"passed": 0, "total": 0})

        no_metadata_count = 0
        for req in data.requirements:
            if req.status == StatusChoices.MANUAL:
                continue

            m = get_requirement_metadata(req.id, data.attributes_by_requirement_id)
            if m:
                section = getattr(m, "Section", "Other")
                section_scores[section]["total"] += 1
                if req.status == StatusChoices.PASS:
                    section_scores[section]["passed"] += 1
            else:
                no_metadata_count += 1

        if no_metadata_count > 0:
            logger.warning(
                "CSA CCM chart: %d requirements had no metadata", no_metadata_count
            )

        logger.info("CSA CCM section scores:")
        for section in CSA_CCM_SECTIONS:
            if section in section_scores:
                scores = section_scores[section]
                pct = (
                    (scores["passed"] / scores["total"] * 100)
                    if scores["total"] > 0
                    else 0
                )
                logger.info(
                    "  %s: %d/%d (%.1f%%)",
                    section,
                    scores["passed"],
                    scores["total"],
                    pct,
                )

        # Build labels and values in CSA CCM section order
        labels = []
        values = []
        for section in CSA_CCM_SECTIONS:
            if section in section_scores and section_scores[section]["total"] > 0:
                scores = section_scores[section]
                pct = (scores["passed"] / scores["total"]) * 100
                # Use short name if available
                label = CSA_CCM_SECTION_SHORT_NAMES.get(section, section)
                labels.append(label)
                values.append(pct)

        return create_horizontal_bar_chart(
            labels=labels,
            values=values,
            xlabel="Compliance (%)",
            color_func=get_chart_color_for_percentage,
        )

    def _create_section_table(self, data: ComplianceData) -> Table:
        """
        Create the section breakdown table.

        Args:
            data: Aggregated compliance data.

        Returns:
            ReportLab Table element.
        """
        section_scores = defaultdict(lambda: {"passed": 0, "failed": 0, "manual": 0})

        for req in data.requirements:
            m = get_requirement_metadata(req.id, data.attributes_by_requirement_id)
            if m:
                section = getattr(m, "Section", "Other")

                if req.status == StatusChoices.PASS:
                    section_scores[section]["passed"] += 1
                elif req.status == StatusChoices.FAIL:
                    section_scores[section]["failed"] += 1
                else:
                    section_scores[section]["manual"] += 1

        table_data = [["Section", "Passed", "Failed", "Manual", "Compliance"]]
        for section in CSA_CCM_SECTIONS:
            if section not in section_scores:
                continue
            scores = section_scores[section]
            total = scores["passed"] + scores["failed"]
            pct = (scores["passed"] / total * 100) if total > 0 else 100
            # Use short name if available
            label = CSA_CCM_SECTION_SHORT_NAMES.get(section, section)
            table_data.append(
                [
                    label,
                    str(scores["passed"]),
                    str(scores["failed"]),
                    str(scores["manual"]),
                    f"{pct:.1f}%",
                ]
            )

        table = Table(
            table_data,
            colWidths=[2.4 * inch, 0.9 * inch, 0.9 * inch, 0.9 * inch, 1.2 * inch],
        )
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), COLOR_BLUE),
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
                        [COLOR_WHITE, COLOR_BG_BLUE],
                    ),
                ]
            )
        )

        return table
