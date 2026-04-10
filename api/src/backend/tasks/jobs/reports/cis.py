import os
import re
from collections import defaultdict
from typing import Any

from reportlab.lib.units import inch
from reportlab.platypus import Image, PageBreak, Paragraph, Spacer, Table, TableStyle

from api.models import StatusChoices

from .base import (
    BaseComplianceReportGenerator,
    ComplianceData,
    RequirementData,
    get_requirement_metadata,
)
from .charts import (
    create_horizontal_bar_chart,
    create_pie_chart,
    create_stacked_bar_chart,
    get_chart_color_for_percentage,
)
from .components import ColumnConfig, create_data_table, escape_html, truncate_text
from .config import (
    CHART_COLOR_GREEN_1,
    CHART_COLOR_RED,
    CHART_COLOR_YELLOW,
    COLOR_BG_BLUE,
    COLOR_BLUE,
    COLOR_BORDER_GRAY,
    COLOR_DARK_GRAY,
    COLOR_GRAY,
    COLOR_GRID_GRAY,
    COLOR_HIGH_RISK,
    COLOR_LIGHT_BLUE,
    COLOR_SAFE,
    COLOR_WHITE,
)

# Ordered buckets used both in the executive summary tables and the charts
# section. Exposed as module constants so the two call sites never drift.
_PROFILE_BUCKET_ORDER: tuple[str, ...] = ("L1", "L2", "Other")
_ASSESSMENT_BUCKET_ORDER: tuple[str, ...] = ("Automated", "Manual")

# Anchored matchers for profile normalization — substring checks on "L1"/"L2"
# would happily match unrelated tokens like "CL2 Worker" or "HL2" coming from
# future CIS profile enum values.
_LEVEL_2_RE = re.compile(r"(?:\bLevel\s*2\b|\bL2\b|Level_2)")
_LEVEL_1_RE = re.compile(r"(?:\bLevel\s*1\b|\bL1\b|Level_1)")


def _normalize_profile(profile: Any) -> str:
    """Bucket a CIS Profile enum/string into one of: ``L1``, ``L2``, ``Other``.

    The ``CIS_Requirement_Attribute_Profile`` enum has values like
    ``"Level 1"``, ``"Level 2"``, ``"E3 Level 1"``, ``"E5 Level 2"``. We
    collapse them into three buckets to keep charts and badges readable
    across CIS variants, using anchored regex matches so that future enum
    values cannot accidentally promote e.g. ``"CL2 Worker"`` into ``L2``.

    Args:
        profile: The profile value (enum member, string, or ``None``).

    Returns:
        One of ``"L1"``, ``"L2"``, ``"Other"``.
    """
    if profile is None:
        return "Other"
    value = getattr(profile, "value", None) or str(profile)
    if _LEVEL_2_RE.search(value):
        return "L2"
    if _LEVEL_1_RE.search(value):
        return "L1"
    return "Other"


def _profile_badge_text(bucket: str) -> str:
    """Map a normalized profile bucket (L1/L2/Other) to a short badge label."""
    return {"L1": "Level 1", "L2": "Level 2"}.get(bucket, "Other")


# =============================================================================
# CIS Report Generator
# =============================================================================


class CISReportGenerator(BaseComplianceReportGenerator):
    """
    PDF report generator for CIS (Center for Internet Security) Benchmarks.

    CIS differs from single-version frameworks (ENS, NIS2, CSA) in that:
      - Each provider has multiple CIS versions (e.g. AWS: 1.4, 1.5, ..., 6.0).
      - Section names differ across versions and providers and MUST be derived
        at runtime from the loaded compliance data.
      - Requirements carry Profile (Level 1/Level 2) and AssessmentStatus
        (Automated/Manual) attributes that drive the executive summary and
        charts.

    This generator produces:
      - Cover page with Prowler logo and dynamic CIS version/provider metadata
      - Executive summary with overall compliance score, counts, and breakdowns
        by Profile and AssessmentStatus
      - Charts: overall status pie, pass rate by section (horizontal bar),
        Level 1 vs Level 2 pass/fail distribution (stacked bar)
      - Requirements index grouped by dynamic section
      - Detailed findings for FAIL requirements with CIS-specific audit /
        remediation / rationale details
    """

    # Per-run memoization cache for ``_compute_statistics``. ``generate()``
    # is the public entry point and is called once per PDF, so scoping the
    # cache to the last seen ComplianceData instance is enough to avoid the
    # double computation between executive summary and charts section.
    _stats_cache_key: int | None = None
    _stats_cache_value: dict | None = None

    # Body section ordering — ensure every top-level section starts on its
    # own clean page. The base class only puts a PageBreak AFTER Charts and
    # Requirements Index, so Executive Summary and Charts end up sharing a
    # page. This override prepends a PageBreak so Compliance Analysis always
    # begins on a fresh page.
    def _build_body_sections(self, data: ComplianceData) -> list:
        return [PageBreak(), *super()._build_body_sections(data)]

    # -------------------------------------------------------------------------
    # Cover page override — shows dynamic CIS version + provider in the title
    # -------------------------------------------------------------------------

    def create_cover_page(self, data: ComplianceData) -> list:
        """Create the CIS report cover page with Prowler + CIS logos side by side."""
        elements = []

        # Create logos side by side (same pattern as NIS2 / ENS)
        prowler_logo_path = os.path.join(
            os.path.dirname(__file__), "../../assets/img/prowler_logo.png"
        )
        cis_logo_path = os.path.join(
            os.path.dirname(__file__), "../../assets/img/cis_logo.png"
        )

        if os.path.exists(cis_logo_path):
            prowler_logo = Image(prowler_logo_path, width=3.5 * inch, height=0.7 * inch)
            cis_logo = Image(cis_logo_path, width=2.3 * inch, height=1.1 * inch)
            logos_table = Table(
                [[prowler_logo, cis_logo]], colWidths=[4 * inch, 2.5 * inch]
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
        elif os.path.exists(prowler_logo_path):
            # Fallback: only the Prowler logo if the CIS asset is missing
            elements.append(Image(prowler_logo_path, width=5 * inch, height=1 * inch))

        elements.append(Spacer(1, 0.5 * inch))

        # Dynamic title: "CIS Benchmark v5.0 — AWS Compliance Report"
        provider_label = ""
        if data.provider_obj:
            provider_label = f" — {data.provider_obj.provider.upper()}"
        title_text = (
            f"CIS Benchmark v{data.version}{provider_label}<br/>Compliance Report"
        )
        elements.append(Paragraph(title_text, self.styles["title"]))
        elements.append(Spacer(1, 0.5 * inch))

        # Metadata table via base class helper
        info_rows = self._build_info_rows(data, language=self.config.language)
        metadata_data = []
        for label, value in info_rows:
            if label in ("Name:", "Description:") and value:
                metadata_data.append(
                    [label, Paragraph(str(value), self.styles["normal_center"])]
                )
            else:
                metadata_data.append([label, value])

        metadata_table = Table(metadata_data, colWidths=[2 * inch, 4 * inch])
        metadata_table.setStyle(
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

    # -------------------------------------------------------------------------
    # Executive Summary
    # -------------------------------------------------------------------------

    def create_executive_summary(self, data: ComplianceData) -> list:
        """Create the CIS executive summary section."""
        elements = []

        elements.append(Paragraph("Executive Summary", self.styles["h1"]))
        elements.append(Spacer(1, 0.1 * inch))

        stats = self._compute_statistics(data)

        # --- Summary metrics table ---
        summary_data = [
            ["Metric", "Value"],
            ["Total Requirements", str(stats["total"])],
            ["Passed", str(stats["passed"])],
            ["Failed", str(stats["failed"])],
            ["Manual", str(stats["manual"])],
            ["Overall Compliance", f"{stats['overall_compliance']:.1f}%"],
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
                    ("FONTNAME", (0, 0), (-1, 0), "PlusJakartaSans"),
                    ("FONTSIZE", (0, 0), (-1, 0), 12),
                    ("FONTSIZE", (0, 1), (-1, -1), 10),
                    ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("GRID", (0, 0), (-1, -1), 0.5, COLOR_BORDER_GRAY),
                    ("BOTTOMPADDING", (0, 0), (-1, 0), 10),
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
        elements.append(Spacer(1, 0.25 * inch))

        # --- Profile breakdown table ---
        elements.append(Paragraph("Breakdown by Profile", self.styles["h2"]))
        elements.append(Spacer(1, 0.1 * inch))
        profile_counts = stats["profile_counts"]
        profile_table_data = [["Profile", "Passed", "Failed", "Manual", "Total"]]
        for bucket in _PROFILE_BUCKET_ORDER:
            counts = profile_counts.get(bucket, {"passed": 0, "failed": 0, "manual": 0})
            total = counts["passed"] + counts["failed"] + counts["manual"]
            if total == 0:
                continue
            profile_table_data.append(
                [
                    _profile_badge_text(bucket),
                    str(counts["passed"]),
                    str(counts["failed"]),
                    str(counts["manual"]),
                    str(total),
                ]
            )
        profile_table = Table(
            profile_table_data,
            colWidths=[1.5 * inch, 1 * inch, 1 * inch, 1 * inch, 1 * inch],
        )
        profile_table.setStyle(
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
                    (
                        "ROWBACKGROUNDS",
                        (0, 1),
                        (-1, -1),
                        [COLOR_WHITE, COLOR_BG_BLUE],
                    ),
                ]
            )
        )
        elements.append(profile_table)
        elements.append(Spacer(1, 0.25 * inch))

        # --- Assessment status breakdown ---
        elements.append(Paragraph("Breakdown by Assessment Status", self.styles["h2"]))
        elements.append(Spacer(1, 0.1 * inch))
        assessment_counts = stats["assessment_counts"]
        assessment_table_data = [["Assessment", "Passed", "Failed", "Manual", "Total"]]
        for bucket in _ASSESSMENT_BUCKET_ORDER:
            counts = assessment_counts.get(
                bucket, {"passed": 0, "failed": 0, "manual": 0}
            )
            total = counts["passed"] + counts["failed"] + counts["manual"]
            if total == 0:
                continue
            assessment_table_data.append(
                [
                    bucket,
                    str(counts["passed"]),
                    str(counts["failed"]),
                    str(counts["manual"]),
                    str(total),
                ]
            )
        assessment_table = Table(
            assessment_table_data,
            colWidths=[1.5 * inch, 1 * inch, 1 * inch, 1 * inch, 1 * inch],
        )
        assessment_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), COLOR_LIGHT_BLUE),
                    ("TEXTCOLOR", (0, 0), (-1, 0), COLOR_WHITE),
                    ("FONTNAME", (0, 0), (-1, 0), "FiraCode"),
                    ("FONTSIZE", (0, 0), (-1, 0), 10),
                    ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("FONTSIZE", (0, 1), (-1, -1), 9),
                    ("GRID", (0, 0), (-1, -1), 0.5, COLOR_GRID_GRAY),
                    (
                        "ROWBACKGROUNDS",
                        (0, 1),
                        (-1, -1),
                        [COLOR_WHITE, COLOR_BG_BLUE],
                    ),
                ]
            )
        )
        elements.append(assessment_table)
        elements.append(Spacer(1, 0.25 * inch))

        # --- Top 5 failing sections ---
        top_failing = stats["top_failing_sections"]
        if top_failing:
            elements.append(
                Paragraph("Top Sections with Lowest Compliance", self.styles["h2"])
            )
            elements.append(Spacer(1, 0.1 * inch))
            top_table_data = [["Section", "Passed", "Failed", "Compliance"]]
            for section_label, section_stats in top_failing:
                passed = section_stats["passed"]
                failed = section_stats["failed"]
                total = passed + failed
                pct = (passed / total * 100) if total > 0 else 100
                top_table_data.append(
                    [
                        truncate_text(section_label, 55),
                        str(passed),
                        str(failed),
                        f"{pct:.1f}%",
                    ]
                )
            top_table = Table(
                top_table_data,
                colWidths=[3.5 * inch, 0.9 * inch, 0.9 * inch, 1.2 * inch],
            )
            top_table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), COLOR_HIGH_RISK),
                        ("TEXTCOLOR", (0, 0), (-1, 0), COLOR_WHITE),
                        ("FONTNAME", (0, 0), (-1, 0), "FiraCode"),
                        ("FONTSIZE", (0, 0), (-1, 0), 10),
                        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                        ("FONTSIZE", (0, 1), (-1, -1), 9),
                        ("GRID", (0, 0), (-1, -1), 0.5, COLOR_GRID_GRAY),
                        (
                            "ROWBACKGROUNDS",
                            (0, 1),
                            (-1, -1),
                            [COLOR_WHITE, COLOR_BG_BLUE],
                        ),
                    ]
                )
            )
            elements.append(top_table)

        return elements

    # -------------------------------------------------------------------------
    # Charts section
    # -------------------------------------------------------------------------

    def create_charts_section(self, data: ComplianceData) -> list:
        """Create the CIS charts section."""
        elements = []

        elements.append(Paragraph("Compliance Analysis", self.styles["h1"]))
        elements.append(Spacer(1, 0.1 * inch))

        # --- Pie chart: overall Pass / Fail / Manual ---
        stats = self._compute_statistics(data)
        pie_labels = []
        pie_values = []
        pie_colors = []
        if stats["passed"] > 0:
            pie_labels.append(f"Pass ({stats['passed']})")
            pie_values.append(stats["passed"])
            pie_colors.append(CHART_COLOR_GREEN_1)
        if stats["failed"] > 0:
            pie_labels.append(f"Fail ({stats['failed']})")
            pie_values.append(stats["failed"])
            pie_colors.append(CHART_COLOR_RED)
        if stats["manual"] > 0:
            pie_labels.append(f"Manual ({stats['manual']})")
            pie_values.append(stats["manual"])
            pie_colors.append(CHART_COLOR_YELLOW)

        if pie_values:
            elements.append(Paragraph("Overall Status Distribution", self.styles["h2"]))
            elements.append(Spacer(1, 0.1 * inch))
            pie_buffer = create_pie_chart(
                labels=pie_labels,
                values=pie_values,
                colors=pie_colors,
            )
            pie_buffer.seek(0)
            elements.append(Image(pie_buffer, width=4.5 * inch, height=4.5 * inch))
            elements.append(Spacer(1, 0.2 * inch))

        # --- Horizontal bar: pass rate by section ---
        section_stats = stats["section_stats"]
        if section_stats:
            elements.append(PageBreak())
            elements.append(Paragraph("Compliance by Section", self.styles["h1"]))
            elements.append(Spacer(1, 0.1 * inch))
            elements.append(
                Paragraph(
                    "The following chart shows compliance percentage for each CIS "
                    "section based on automated checks:",
                    self.styles["normal_center"],
                )
            )
            elements.append(Spacer(1, 0.1 * inch))

            # Sort sections by pass rate descending for readability
            sorted_sections = sorted(
                section_stats.items(),
                key=lambda item: (
                    (item[1]["passed"] / (item[1]["passed"] + item[1]["failed"]) * 100)
                    if (item[1]["passed"] + item[1]["failed"]) > 0
                    else 100
                ),
                reverse=True,
            )
            bar_labels = []
            bar_values = []
            for section_label, section_data in sorted_sections:
                total = section_data["passed"] + section_data["failed"]
                if total == 0:
                    continue
                pct = (section_data["passed"] / total) * 100
                bar_labels.append(truncate_text(section_label, 60))
                bar_values.append(pct)

            if bar_values:
                bar_buffer = create_horizontal_bar_chart(
                    labels=bar_labels,
                    values=bar_values,
                    xlabel="Compliance (%)",
                    color_func=get_chart_color_for_percentage,
                    label_fontsize=9,
                )
                bar_buffer.seek(0)
                elements.append(Image(bar_buffer, width=6.5 * inch, height=5 * inch))

        # --- Stacked bar: Level 1 vs Level 2 pass/fail ---
        profile_counts = stats["profile_counts"]
        has_profile_data = any(
            (counts["passed"] + counts["failed"]) > 0
            for counts in profile_counts.values()
        )
        if has_profile_data:
            elements.append(PageBreak())
            elements.append(Paragraph("Profile Breakdown", self.styles["h1"]))
            elements.append(Spacer(1, 0.1 * inch))
            elements.append(
                Paragraph(
                    "Distribution of Pass / Fail / Manual across CIS profile levels.",
                    self.styles["normal_center"],
                )
            )
            elements.append(Spacer(1, 0.1 * inch))

            profile_labels = []
            pass_series = []
            fail_series = []
            manual_series = []
            for bucket in _PROFILE_BUCKET_ORDER:
                counts = profile_counts.get(bucket)
                if not counts:
                    continue
                total = counts["passed"] + counts["failed"] + counts["manual"]
                if total == 0:
                    continue
                profile_labels.append(_profile_badge_text(bucket))
                pass_series.append(counts["passed"])
                fail_series.append(counts["failed"])
                manual_series.append(counts["manual"])

            if profile_labels:
                stacked_buffer = create_stacked_bar_chart(
                    labels=profile_labels,
                    data_series={
                        "Pass": pass_series,
                        "Fail": fail_series,
                        "Manual": manual_series,
                    },
                    xlabel="Profile",
                    ylabel="Requirements",
                )
                stacked_buffer.seek(0)
                elements.append(Image(stacked_buffer, width=6 * inch, height=4 * inch))

        return elements

    # -------------------------------------------------------------------------
    # Requirements Index
    # -------------------------------------------------------------------------

    def create_requirements_index(self, data: ComplianceData) -> list:
        """Create the CIS requirements index grouped by dynamic section."""
        elements = []

        elements.append(Paragraph("Requirements Index", self.styles["h1"]))
        elements.append(Spacer(1, 0.1 * inch))

        sections = self._derive_sections(data)
        by_section: dict[str, list[dict]] = defaultdict(list)
        for req in data.requirements:
            meta = get_requirement_metadata(req.id, data.attributes_by_requirement_id)
            section = "Other"
            profile_bucket = "Other"
            assessment = ""
            if meta:
                section = getattr(meta, "Section", "Other") or "Other"
                profile_bucket = _normalize_profile(getattr(meta, "Profile", None))
                assessment_enum = getattr(meta, "AssessmentStatus", None)
                assessment = getattr(assessment_enum, "value", None) or str(
                    assessment_enum or ""
                )
            by_section[section].append(
                {
                    "id": req.id,
                    "description": truncate_text(req.description, 80),
                    "profile": _profile_badge_text(profile_bucket),
                    "assessment": assessment or "-",
                    "status": (req.status or "").upper(),
                }
            )

        columns = [
            ColumnConfig("ID", 0.9 * inch, "id", align="LEFT"),
            ColumnConfig("Description", 3.2 * inch, "description", align="LEFT"),
            ColumnConfig("Profile", 0.9 * inch, "profile"),
            ColumnConfig("Assessment", 1 * inch, "assessment"),
            ColumnConfig("Status", 0.7 * inch, "status"),
        ]

        for section in sections:
            rows = by_section.get(section, [])
            if not rows:
                continue
            elements.append(Paragraph(truncate_text(section, 90), self.styles["h2"]))
            elements.append(Spacer(1, 0.05 * inch))
            table = create_data_table(
                data=rows,
                columns=columns,
                header_color=self.config.primary_color,
                normal_style=self.styles["normal_center"],
            )
            elements.append(table)
            elements.append(Spacer(1, 0.15 * inch))

        return elements

    # -------------------------------------------------------------------------
    # Detailed findings hook — inject CIS-specific rationale / audit content
    # -------------------------------------------------------------------------

    def _render_requirement_detail_extras(
        self, req: RequirementData, data: ComplianceData
    ) -> list:
        """Render CIS rationale, impact, audit, remediation and references."""
        extras = []
        meta = get_requirement_metadata(req.id, data.attributes_by_requirement_id)
        if meta is None:
            return extras

        field_map = [
            ("Rationale", "RationaleStatement"),
            ("Impact", "ImpactStatement"),
            ("Audit Procedure", "AuditProcedure"),
            ("Remediation", "RemediationProcedure"),
            ("References", "References"),
        ]

        for label, attr_name in field_map:
            value = getattr(meta, attr_name, None)
            if not value:
                continue
            text = str(value).strip()
            if not text:
                continue
            extras.append(Paragraph(f"<b>{label}:</b>", self.styles["h3"]))
            extras.append(Paragraph(escape_html(text), self.styles["normal"]))
            extras.append(Spacer(1, 0.08 * inch))

        return extras

    # -------------------------------------------------------------------------
    # Private helpers
    # -------------------------------------------------------------------------

    def _derive_sections(self, data: ComplianceData) -> list[str]:
        """Extract ordered unique Section names from loaded compliance data."""
        seen: dict[str, bool] = {}
        for req in data.requirements:
            meta = get_requirement_metadata(req.id, data.attributes_by_requirement_id)
            if meta is None:
                continue
            section = getattr(meta, "Section", None) or "Other"
            if section not in seen:
                seen[section] = True
        return list(seen.keys())

    def _compute_statistics(self, data: ComplianceData) -> dict:
        """Aggregate all statistics needed for summary and charts.

        Memoized per-``ComplianceData`` instance via ``_stats_cache_*``: the
        executive summary and the charts section both need the same numbers,
        so they would otherwise re-iterate the requirements twice. We key on
        ``id(data)`` because ``ComplianceData`` is a dataclass and its
        instances are not hashable.

        Returns a dict with:
          - total, passed, failed, manual: int
          - overall_compliance: float (percentage)
          - profile_counts: {"L1": {"passed", "failed", "manual"}, ...}
          - assessment_counts: {"Automated": {...}, "Manual": {...}}
          - section_stats: {section_name: {"passed", "failed", "manual"}, ...}
          - top_failing_sections: list[(section_name, stats)] (up to 5)
        """
        cache_key = id(data)
        if self._stats_cache_key == cache_key and self._stats_cache_value is not None:
            return self._stats_cache_value
        stats = self._compute_statistics_uncached(data)
        self._stats_cache_key = cache_key
        self._stats_cache_value = stats
        return stats

    def _compute_statistics_uncached(self, data: ComplianceData) -> dict:
        """Actual aggregation kernel; call ``_compute_statistics`` instead."""
        total = len(data.requirements)
        passed = sum(1 for r in data.requirements if r.status == StatusChoices.PASS)
        failed = sum(1 for r in data.requirements if r.status == StatusChoices.FAIL)
        manual = sum(1 for r in data.requirements if r.status == StatusChoices.MANUAL)

        evaluated = passed + failed
        overall_compliance = (passed / evaluated * 100) if evaluated > 0 else 100.0

        profile_counts: dict[str, dict[str, int]] = {
            "L1": {"passed": 0, "failed": 0, "manual": 0},
            "L2": {"passed": 0, "failed": 0, "manual": 0},
            "Other": {"passed": 0, "failed": 0, "manual": 0},
        }
        assessment_counts: dict[str, dict[str, int]] = {
            "Automated": {"passed": 0, "failed": 0, "manual": 0},
            "Manual": {"passed": 0, "failed": 0, "manual": 0},
        }
        section_stats: dict[str, dict[str, int]] = defaultdict(
            lambda: {"passed": 0, "failed": 0, "manual": 0}
        )

        for req in data.requirements:
            meta = get_requirement_metadata(req.id, data.attributes_by_requirement_id)
            if meta is None:
                continue

            profile_bucket = _normalize_profile(getattr(meta, "Profile", None))
            assessment_enum = getattr(meta, "AssessmentStatus", None)
            assessment_value = getattr(assessment_enum, "value", None) or str(
                assessment_enum or ""
            )
            assessment_bucket = (
                "Automated" if assessment_value == "Automated" else "Manual"
            )
            section = getattr(meta, "Section", None) or "Other"

            status_key = {
                StatusChoices.PASS: "passed",
                StatusChoices.FAIL: "failed",
                StatusChoices.MANUAL: "manual",
            }.get(req.status)
            if status_key is None:
                continue

            profile_counts[profile_bucket][status_key] += 1
            assessment_counts[assessment_bucket][status_key] += 1
            section_stats[section][status_key] += 1

        # Top 5 sections with lowest pass rate (only sections with evaluated reqs)
        def _section_rate(item):
            _, stats_ = item
            evaluated_ = stats_["passed"] + stats_["failed"]
            if evaluated_ == 0:
                return 101  # sort evaluated=0 to the bottom
            return stats_["passed"] / evaluated_ * 100

        top_failing_sections = sorted(
            (
                item
                for item in section_stats.items()
                if (item[1]["passed"] + item[1]["failed"]) > 0
            ),
            key=_section_rate,
        )[:5]

        return {
            "total": total,
            "passed": passed,
            "failed": failed,
            "manual": manual,
            "overall_compliance": overall_compliance,
            "profile_counts": profile_counts,
            "assessment_counts": assessment_counts,
            "section_stats": dict(section_stats),
            "top_failing_sections": top_failing_sections,
        }
