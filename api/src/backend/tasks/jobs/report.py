import io
import os
from collections import defaultdict
from pathlib import Path
from shutil import rmtree

import matplotlib.pyplot as plt
from celery.utils.log import get_task_logger
from config.django.base import DJANGO_FINDINGS_BATCH_SIZE, DJANGO_TMP_OUTPUT_DIRECTORY
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen import canvas
from reportlab.platypus import (
    Image,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)
from tasks.jobs.export import _generate_output_directory, _upload_to_s3
from tasks.utils import batched

from api.db_router import READ_REPLICA_ALIAS
from api.db_utils import rls_transaction
from api.models import Finding, Provider, ScanSummary
from api.utils import initialize_prowler_provider
from prowler.lib.check.compliance_models import Compliance
from prowler.lib.outputs.finding import Finding as FindingOutput

pdfmetrics.registerFont(
    TTFont(
        "PlusJakartaSans",
        os.path.join(
            os.path.dirname(__file__), "../assets/fonts/PlusJakartaSans-Regular.ttf"
        ),
    )
)

pdfmetrics.registerFont(
    TTFont(
        "FiraCode",
        os.path.join(os.path.dirname(__file__), "../assets/fonts/FiraCode-Regular.ttf"),
    )
)

logger = get_task_logger(__name__)


def _create_pdf_styles() -> dict[str, ParagraphStyle]:
    """
    Create and return PDF paragraph styles used throughout the report.

    Returns:
        dict[str, ParagraphStyle]: A dictionary containing the following styles:
            - 'title': Title style with prowler green color
            - 'h1': Heading 1 style with blue color and background
            - 'h2': Heading 2 style with light blue color
            - 'h3': Heading 3 style for sub-headings
            - 'normal': Normal text style with left indent
            - 'normal_center': Normal text style without indent
    """
    styles = getSampleStyleSheet()
    prowler_dark_green = colors.Color(0.1, 0.5, 0.2)

    title_style = ParagraphStyle(
        "CustomTitle",
        parent=styles["Title"],
        fontSize=24,
        textColor=prowler_dark_green,
        spaceAfter=20,
        fontName="PlusJakartaSans",
        alignment=TA_CENTER,
    )

    h1 = ParagraphStyle(
        "CustomH1",
        parent=styles["Heading1"],
        fontSize=18,
        textColor=colors.Color(0.2, 0.4, 0.6),
        spaceBefore=20,
        spaceAfter=12,
        fontName="PlusJakartaSans",
        leftIndent=0,
        borderWidth=2,
        borderColor=colors.Color(0.2, 0.4, 0.6),
        borderPadding=8,
        backColor=colors.Color(0.95, 0.97, 1.0),
    )

    h2 = ParagraphStyle(
        "CustomH2",
        parent=styles["Heading2"],
        fontSize=14,
        textColor=colors.Color(0.3, 0.5, 0.7),
        spaceBefore=15,
        spaceAfter=8,
        fontName="PlusJakartaSans",
        leftIndent=10,
        borderWidth=1,
        borderColor=colors.Color(0.7, 0.8, 0.9),
        borderPadding=5,
        backColor=colors.Color(0.98, 0.99, 1.0),
    )

    h3 = ParagraphStyle(
        "CustomH3",
        parent=styles["Heading3"],
        fontSize=12,
        textColor=colors.Color(0.4, 0.6, 0.8),
        spaceBefore=10,
        spaceAfter=6,
        fontName="PlusJakartaSans",
        leftIndent=20,
    )

    normal = ParagraphStyle(
        "CustomNormal",
        parent=styles["Normal"],
        fontSize=10,
        textColor=colors.Color(0.2, 0.2, 0.2),
        spaceBefore=4,
        spaceAfter=4,
        leftIndent=30,
        fontName="PlusJakartaSans",
    )

    normal_center = ParagraphStyle(
        "CustomNormalCenter",
        parent=styles["Normal"],
        fontSize=10,
        textColor=colors.Color(0.2, 0.2, 0.2),
        fontName="PlusJakartaSans",
    )

    return {
        "title": title_style,
        "h1": h1,
        "h2": h2,
        "h3": h3,
        "normal": normal,
        "normal_center": normal_center,
    }


def _create_risk_component(risk_level: int, weight: int, score: int = 0) -> Table:
    """
    Create a visual risk component table for the PDF report.

    Args:
        risk_level (int): The risk level (0-5), where higher values indicate higher risk.
        weight (int): The weight of the risk component.
        score (int): The calculated score. Defaults to 0.

    Returns:
        Table: A ReportLab Table object with colored cells representing risk, weight, and score.
    """
    if risk_level >= 4:
        risk_color = colors.Color(0.8, 0.2, 0.2)
    elif risk_level >= 3:
        risk_color = colors.Color(0.9, 0.6, 0.2)
    elif risk_level >= 2:
        risk_color = colors.Color(0.9, 0.9, 0.2)
    else:
        risk_color = colors.Color(0.2, 0.8, 0.2)

    if weight <= 50:
        weight_color = colors.Color(0.2, 0.8, 0.2)
    elif weight <= 100:
        weight_color = colors.Color(0.9, 0.9, 0.2)
    else:
        weight_color = colors.Color(0.8, 0.2, 0.2)

    score_color = colors.Color(0.4, 0.4, 0.4)

    data = [
        [
            "Risk Level:",
            str(risk_level),
            "Weight:",
            str(weight),
            "Score:",
            str(score),
        ]
    ]

    table = Table(
        data,
        colWidths=[
            0.8 * inch,
            0.4 * inch,
            0.6 * inch,
            0.4 * inch,
            0.5 * inch,
            0.4 * inch,
        ],
    )

    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, 0), colors.Color(0.9, 0.9, 0.9)),
                ("BACKGROUND", (1, 0), (1, 0), risk_color),
                ("TEXTCOLOR", (1, 0), (1, 0), colors.white),
                ("FONTNAME", (1, 0), (1, 0), "FiraCode"),
                ("BACKGROUND", (2, 0), (2, 0), colors.Color(0.9, 0.9, 0.9)),
                ("BACKGROUND", (3, 0), (3, 0), weight_color),
                ("TEXTCOLOR", (3, 0), (3, 0), colors.white),
                ("FONTNAME", (3, 0), (3, 0), "FiraCode"),
                ("BACKGROUND", (4, 0), (4, 0), colors.Color(0.9, 0.9, 0.9)),
                ("BACKGROUND", (5, 0), (5, 0), score_color),
                ("TEXTCOLOR", (5, 0), (5, 0), colors.white),
                ("FONTNAME", (5, 0), (5, 0), "FiraCode"),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("FONTSIZE", (0, 0), (-1, -1), 10),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.black),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                ("TOPPADDING", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ]
        )
    )

    return table


def _create_status_component(status: str) -> Table:
    """
    Create a visual status component with colored background.

    Args:
        status (str): The status value (e.g., "PASS", "FAIL", "MANUAL").

    Returns:
        Table: A ReportLab Table object displaying the status with appropriate color coding.
    """
    if status.upper() == "PASS":
        status_color = colors.Color(0.2, 0.8, 0.2)
    elif status.upper() == "FAIL":
        status_color = colors.Color(0.8, 0.2, 0.2)
    else:
        status_color = colors.Color(0.4, 0.4, 0.4)

    data = [["State:", status.upper()]]

    table = Table(data, colWidths=[0.6 * inch, 0.8 * inch])

    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, 0), colors.Color(0.9, 0.9, 0.9)),
                ("FONTNAME", (0, 0), (0, 0), "PlusJakartaSans"),
                ("BACKGROUND", (1, 0), (1, 0), status_color),
                ("TEXTCOLOR", (1, 0), (1, 0), colors.white),
                ("FONTNAME", (1, 0), (1, 0), "FiraCode"),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("FONTSIZE", (0, 0), (-1, -1), 12),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.black),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 10),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
            ]
        )
    )

    return table


def _create_section_score_chart(resp_reqs: list[dict], attrs_map: dict) -> io.BytesIO:
    """
    Create a bar chart showing compliance score by section using ThreatScore formula.

    Args:
        resp_reqs (list[dict]): List of requirement dictionaries with status and findings data.
        attrs_map (dict): Mapping of requirement IDs to their attributes including risk level and weight.

    Returns:
        io.BytesIO: A BytesIO buffer containing the chart image in PNG format.
    """
    # Define expected sections
    expected_sections = [
        "1. IAM",
        "2. Attack Surface",
        "3. Logging and Monitoring",
        "4. Encryption",
    ]

    # Initialize all expected sections with default values
    sections_data = {
        section: {
            "numerator": 0,
            "denominator": 0,
            "has_findings": False,
        }
        for section in expected_sections
    }

    # Collect data from requirements
    for req in resp_reqs:
        req_id = req["id"]
        attr = attrs_map.get(req_id, {})

        metadata = attr.get("attributes", {}).get("req_attributes", [])
        if metadata:
            m = metadata[0]
            section = getattr(m, "Section", "Unknown")

            # Add section if not in expected list (for flexibility)
            if section not in sections_data:
                sections_data[section] = {
                    "numerator": 0,
                    "denominator": 0,
                    "has_findings": False,
                }

            # Get findings data
            passed_findings = req["attributes"].get("passed_findings", 0)
            total_findings = req["attributes"].get("total_findings", 0)

            if total_findings > 0:
                sections_data[section]["has_findings"] = True
                risk_level = getattr(m, "LevelOfRisk", 0)
                weight = getattr(m, "Weight", 0)

                # Calculate using ThreatScore formula from UI
                rate_i = passed_findings / total_findings
                rfac_i = 1 + 0.25 * risk_level

                sections_data[section]["numerator"] += (
                    rate_i * total_findings * weight * rfac_i
                )
                sections_data[section]["denominator"] += (
                    total_findings * weight * rfac_i
                )

    section_names = []
    compliance_percentages = []

    for section, data in sections_data.items():
        if data["has_findings"] and data["denominator"] > 0:
            compliance_percentage = (data["numerator"] / data["denominator"]) * 100
        else:
            compliance_percentage = 100  # No findings = 100% (PASS)

        section_names.append(section)
        compliance_percentages.append(compliance_percentage)

    # Sort alphabetically by section name
    sorted_data = sorted(
        zip(section_names, compliance_percentages),
        key=lambda x: x[0],
    )
    section_names, compliance_percentages = (
        zip(*sorted_data) if sorted_data else ([], [])
    )

    fig, ax = plt.subplots(figsize=(12, 8))

    colors_list = []
    for percentage in compliance_percentages:
        if percentage >= 80:
            color = "#4CAF50"
        elif percentage >= 60:
            color = "#8BC34A"
        elif percentage >= 40:
            color = "#FFEB3B"
        elif percentage >= 20:
            color = "#FF9800"
        else:
            color = "#F44336"
        colors_list.append(color)

    bars = ax.bar(section_names, compliance_percentages, color=colors_list)

    ax.set_ylabel("Compliance Score (%)", fontsize=12)
    ax.set_xlabel("Section", fontsize=12)
    ax.set_ylim(0, 100)

    for bar, percentage in zip(bars, compliance_percentages):
        height = bar.get_height()
        ax.text(
            bar.get_x() + bar.get_width() / 2.0,
            height + 1,
            f"{percentage:.1f}%",
            ha="center",
            va="bottom",
            fontweight="bold",
        )

    plt.xticks(rotation=45, ha="right")

    ax.grid(True, alpha=0.3, axis="y")

    plt.tight_layout()

    buffer = io.BytesIO()
    plt.savefig(buffer, format="png", dpi=300, bbox_inches="tight")
    buffer.seek(0)
    plt.close()

    return buffer


def _add_pdf_footer(canvas_obj: canvas.Canvas, doc: SimpleDocTemplate) -> None:
    """
    Add footer with page number and branding to each page of the PDF.

    Args:
        canvas_obj (canvas.Canvas): The ReportLab canvas object for drawing.
        doc (SimpleDocTemplate): The document template containing page information.
    """
    width, height = doc.pagesize
    page_num_text = f"Page {doc.page}"
    canvas_obj.setFont("PlusJakartaSans", 9)
    canvas_obj.setFillColorRGB(0.4, 0.4, 0.4)
    canvas_obj.drawString(30, 20, page_num_text)
    powered_text = "Powered by Prowler"
    text_width = canvas_obj.stringWidth(powered_text, "PlusJakartaSans", 9)
    canvas_obj.drawString(width - text_width - 30, 20, powered_text)


def _build_findings_index(
    tenant_id: str, scan_id: str, prowler_provider
) -> tuple[dict[str, list], dict[str, dict]]:
    """
    Build an index of findings by check_id to avoid O(n×m) complexity.

    This function processes findings in batches to avoid loading all findings
    into memory at once, addressing concerns about scans with very large numbers
    of findings (e.g., 1M+).

    Args:
        tenant_id (str): The tenant ID for Row-Level Security context.
        scan_id (str): The ID of the scan to retrieve findings for.
        prowler_provider: The initialized Prowler provider instance.

    Returns:
        tuple[dict[str, list], dict[str, dict]]: A tuple containing:
            - findings_by_check: Dictionary mapping check_id to list of finding objects.
            - requirement_stats: Dictionary mapping check_id to stats dict with 'passed' and 'total' counts.
    """
    logger.info("Building findings index by check_id")
    findings_by_check = defaultdict(list)
    requirement_stats = defaultdict(lambda: {"passed": 0, "total": 0})

    findings_qs = (
        Finding.all_objects.filter(tenant_id=tenant_id, scan_id=scan_id)
        .order_by("uid")
        .iterator()
    )

    with rls_transaction(tenant_id, using=READ_REPLICA_ALIAS):
        for batch, is_last in batched(findings_qs, DJANGO_FINDINGS_BATCH_SIZE):
            for finding in batch:
                # Transform to FindingOutput
                finding_output = FindingOutput.transform_api_finding(
                    finding, prowler_provider
                )
                check_id = finding_output.check_id

                # Add to index for detailed findings lookup
                findings_by_check[check_id].append(finding_output)

                # Update stats for requirement calculations
                requirement_stats[check_id]["total"] += 1
                if getattr(finding_output, "status", "").upper() == "PASS":
                    requirement_stats[check_id]["passed"] += 1

    logger.info(f"Built findings index with {len(findings_by_check)} unique checks")
    return dict(findings_by_check), dict(requirement_stats)


def _calculate_requirements_data(
    compliance_obj, requirement_stats: dict[str, dict]
) -> tuple[dict, list[dict]]:
    """
    Calculate requirement status and statistics using the findings index.

    This replaces the O(n×m) nested loop with O(n) lookups using the findings index.

    Args:
        compliance_obj: The compliance framework object containing requirements.
        requirement_stats (dict[str, dict]): Pre-built statistics mapping check_id to pass/total counts.

    Returns:
        tuple[dict, list[dict]]: A tuple containing:
            - attrs_map: Dictionary mapping requirement IDs to their attributes.
            - resp_reqs: List of requirement dictionaries with status and statistics.
    """
    attrs_map = {}
    resp_reqs = []

    for req in compliance_obj.Requirements:
        req_id = req.Id
        attrs_map[req_id] = {
            "attributes": {
                "req_attributes": getattr(req, "Attributes", []),
                "checks": getattr(req, "Checks", []),
            },
            "description": getattr(req, "Description", ""),
        }

        # Calculate passed and total findings for this requirement using the index
        req_checks = getattr(req, "Checks", [])
        passed_findings = 0
        total_findings = 0
        status = "UNKNOWN"
        description = getattr(req, "Description", "")

        # Use the pre-built index instead of iterating over all findings
        for check_id in req_checks:
            if check_id in requirement_stats:
                stats = requirement_stats[check_id]
                total_findings += stats["total"]
                passed_findings += stats["passed"]

                # Set status based on first check (for backward compatibility)
                if status == "UNKNOWN" and stats["total"] > 0:
                    # If we have findings, set status (we'll refine below)
                    status = "FAIL"  # Default, will be refined

        # Determine overall status for the requirement
        if total_findings > 0:
            if passed_findings == total_findings:
                status = "PASS"
            elif passed_findings == 0:
                status = "FAIL"
            else:
                status = "FAIL"  # Partial pass is still considered FAIL
        else:
            status = "MANUAL"

        resp_reqs.append(
            {
                "id": req_id,
                "attributes": {
                    "framework": getattr(compliance_obj, "Framework", "N/A"),
                    "version": getattr(compliance_obj, "Version", "N/A"),
                    "status": status,
                    "description": description,
                    "passed_findings": passed_findings,
                    "total_findings": total_findings,
                },
            }
        )

    return attrs_map, resp_reqs


def generate_threatscore_report(
    tenant_id: str,
    scan_id: str,
    compliance_id: str,
    output_path: str,
    provider_id: str,
    only_failed: bool = True,
    min_risk_level: int = 4,
) -> None:
    """
    Generate a PDF compliance report based on Prowler ThreatScore framework.

    This function creates a comprehensive PDF report containing:
    - Compliance overview and metadata
    - Section-by-section compliance scores with charts
    - Overall ThreatScore calculation
    - Critical failed requirements
    - Detailed findings for each requirement

    Args:
        tenant_id (str): The tenant ID for Row-Level Security context.
        scan_id (str): ID of the scan executed by Prowler.
        compliance_id (str): ID of the compliance framework (e.g., "prowler_threatscore_aws").
        output_path (str): Output PDF file path (e.g., "/tmp/threatscore_report.pdf").
        provider_id (str): Provider ID for the scan.
        only_failed (bool): If True, only requirements with status "FAIL" will be included
            in the detailed requirements section. Defaults to True.
        min_risk_level (int): Minimum risk level for critical failed requirements. Defaults to 4.

    Raises:
        Exception: If any error occurs during PDF generation, it will be logged and re-raised.
    """
    logger.info(
        f"Generating the report for the scan {scan_id} with provider {provider_id}"
    )
    try:
        # Get PDF styles
        pdf_styles = _create_pdf_styles()
        title_style = pdf_styles["title"]
        h1 = pdf_styles["h1"]
        h2 = pdf_styles["h2"]
        h3 = pdf_styles["h3"]
        normal = pdf_styles["normal"]
        normal_center = pdf_styles["normal_center"]

        # Get compliance and provider information
        with rls_transaction(tenant_id, using=READ_REPLICA_ALIAS):
            provider_obj = Provider.objects.get(id=provider_id)
            prowler_provider = initialize_prowler_provider(provider_obj)
            provider_type = provider_obj.provider

            frameworks_bulk = Compliance.get_bulk(provider_type)
            compliance_obj = frameworks_bulk[compliance_id]
            compliance_framework = getattr(compliance_obj, "Framework", "N/A")
            compliance_version = getattr(compliance_obj, "Version", "N/A")
            compliance_name = getattr(compliance_obj, "Name", "N/A")
            compliance_description = getattr(compliance_obj, "Description", "")

        # Build findings index (fixes O(n×m) issue and memory concern)
        logger.info(f"Getting findings for scan {scan_id}")
        findings_by_check, requirement_stats = _build_findings_index(
            tenant_id, scan_id, prowler_provider
        )

        # Calculate requirements data using the index
        attrs_map, resp_reqs = _calculate_requirements_data(
            compliance_obj, requirement_stats
        )

        # Initialize PDF document
        doc = SimpleDocTemplate(
            output_path,
            pagesize=letter,
            title=f"Prowler ThreatScore Report - {compliance_framework}",
            author="Prowler",
            subject=f"Compliance Report for {compliance_framework}",
            creator="Prowler Engineering Team",
            keywords=f"compliance,{compliance_framework},security,framework,prowler",
        )

        elements = []

        # Add logo
        img_path = os.path.join(
            os.path.dirname(__file__), "../assets/img/prowler_logo.png"
        )
        logo = Image(
            img_path,
            width=5 * inch,
            height=1 * inch,
        )
        elements.append(logo)

        elements.append(Spacer(1, 0.5 * inch))
        elements.append(Paragraph("Prowler ThreatScore Report", title_style))
        elements.append(Spacer(1, 0.5 * inch))

        # Add compliance information table
        info_data = [
            ["Framework:", compliance_framework],
            ["ID:", compliance_id],
            ["Name:", Paragraph(compliance_name, normal_center)],
            ["Version:", compliance_version],
            ["Scan ID:", scan_id],
            ["Description:", Paragraph(compliance_description, normal_center)],
        ]
        info_table = Table(info_data, colWidths=[2 * inch, 4 * inch])
        info_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (0, 5), colors.Color(0.2, 0.4, 0.6)),
                    ("TEXTCOLOR", (0, 0), (0, 5), colors.white),
                    ("FONTNAME", (0, 0), (0, 5), "FiraCode"),
                    ("BACKGROUND", (1, 0), (1, 5), colors.Color(0.95, 0.97, 1.0)),
                    ("TEXTCOLOR", (1, 0), (1, 5), colors.Color(0.2, 0.2, 0.2)),
                    ("FONTNAME", (1, 0), (1, 5), "PlusJakartaSans"),
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
        elements.append(PageBreak())

        # Add compliance score chart
        elements.append(Paragraph("Compliance Score by Sections", h1))
        elements.append(Spacer(1, 0.2 * inch))

        chart_buffer = _create_section_score_chart(resp_reqs, attrs_map)
        chart_image = Image(chart_buffer, width=7 * inch, height=5.5 * inch)
        elements.append(chart_image)

        # Calculate overall ThreatScore using the same formula as the UI
        numerator = 0
        denominator = 0
        has_findings = False

        for req in resp_reqs:
            req_id = req["id"]
            attr = attrs_map.get(req_id, {})

            # Get findings data
            passed_findings = req["attributes"].get("passed_findings", 0)
            total_findings = req["attributes"].get("total_findings", 0)

            # Skip if no findings (avoid division by zero)
            if total_findings == 0:
                continue

            has_findings = True
            metadata = attr.get("attributes", {}).get("req_attributes", [])
            if metadata and len(metadata) > 0:
                m = metadata[0]
                risk_level = getattr(m, "LevelOfRisk", 0)
                weight = getattr(m, "Weight", 0)

                # Calculate using ThreatScore formula from UI
                rate_i = passed_findings / total_findings
                rfac_i = 1 + 0.25 * risk_level

                numerator += rate_i * total_findings * weight * rfac_i
                denominator += total_findings * weight * rfac_i

        # Calculate ThreatScore (percentualScore)
        # If no findings exist, consider it 100% (PASS)
        if not has_findings:
            overall_compliance = 100
        elif denominator > 0:
            overall_compliance = (numerator / denominator) * 100
        else:
            overall_compliance = 0

        elements.append(Spacer(1, 0.3 * inch))

        summary_data = [
            ["ThreatScore:", f"{overall_compliance:.2f}%"],
        ]

        if overall_compliance >= 80:
            compliance_color = colors.Color(0.2, 0.8, 0.2)
        elif overall_compliance >= 60:
            compliance_color = colors.Color(0.8, 0.8, 0.2)
        else:
            compliance_color = colors.Color(0.8, 0.2, 0.2)

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
        elements.append(PageBreak())

        # Add requirements index
        elements.append(Paragraph("Requirements Index", h1))

        sections = {}
        for req_id, req in attrs_map.items():
            meta = req["attributes"]["req_attributes"][0]
            section = getattr(meta, "Section", "N/A")
            subsection = getattr(meta, "SubSection", "N/A")
            title = getattr(meta, "Title", "N/A")

            if section not in sections:
                sections[section] = {}
            if subsection not in sections[section]:
                sections[section][subsection] = []

            sections[section][subsection].append({"id": req_id, "title": title})

        section_num = 1
        for section_name, subsections in sections.items():
            elements.append(Paragraph(f"{section_num}. {section_name}", h2))

            subsection_num = 1
            for subsection_name, requirements in subsections.items():
                elements.append(Paragraph(f"{subsection_name}", h3))

                req_num = 1
                for req in requirements:
                    elements.append(Paragraph(f"{req['id']} - {req['title']}", normal))
                    req_num += 1

                subsection_num += 1

            section_num += 1
            elements.append(Spacer(1, 0.1 * inch))

        elements.append(PageBreak())

        # Add critical failed requirements section
        elements.append(Paragraph("Top Requirements by Level of Risk", h1))
        elements.append(Spacer(1, 0.1 * inch))
        elements.append(
            Paragraph(
                f"Critical Failed Requirements (Risk Level ≥ {min_risk_level})", h2
            )
        )
        elements.append(Spacer(1, 0.2 * inch))

        critical_reqs = []
        for req in resp_reqs:
            status = req["attributes"]["status"]
            if status == "FAIL":
                metadata = (
                    attrs_map.get(req["id"], {})
                    .get("attributes", {})
                    .get("req_attributes", [{}])[0]
                )
                if metadata:
                    risk_level = getattr(metadata, "LevelOfRisk", 0)
                    weight = getattr(metadata, "Weight", 0)

                    if risk_level >= min_risk_level:
                        critical_reqs.append(
                            {
                                "req": req,
                                "attr": attrs_map[req["id"]],
                                "risk_level": risk_level,
                                "weight": weight,
                                "metadata": metadata,
                            }
                        )

        critical_reqs.sort(key=lambda x: (x["risk_level"], x["weight"]), reverse=True)

        if not critical_reqs:
            elements.append(
                Paragraph(
                    "✅ No critical failed requirements found. Great job!", normal
                )
            )
        else:
            elements.append(
                Paragraph(
                    f"Found {len(critical_reqs)} critical failed requirements that require immediate attention:",
                    normal,
                )
            )
            elements.append(Spacer(1, 0.5 * inch))

            table_data = [["Risk", "Weight", "Requirement ID", "Title", "Section"]]

            for idx, critical_req in enumerate(critical_reqs):
                req_id = critical_req["req"]["id"]
                risk_level = critical_req["risk_level"]
                weight = critical_req["weight"]
                title = getattr(critical_req["metadata"], "Title", "N/A")
                section = getattr(critical_req["metadata"], "Section", "N/A")

                if len(title) > 50:
                    title = title[:47] + "..."

                table_data.append(
                    [str(risk_level), str(weight), req_id, title, section]
                )

            critical_table = Table(
                table_data,
                colWidths=[0.7 * inch, 0.9 * inch, 1.3 * inch, 3.1 * inch, 1.5 * inch],
            )

            critical_table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.Color(0.8, 0.2, 0.2)),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                        ("FONTNAME", (0, 0), (-1, 0), "FiraCode"),
                        ("FONTSIZE", (0, 0), (-1, 0), 10),
                        ("BACKGROUND", (0, 1), (0, -1), colors.Color(0.8, 0.2, 0.2)),
                        ("TEXTCOLOR", (0, 1), (0, -1), colors.white),
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
                        (
                            "BACKGROUND",
                            (1, 1),
                            (-1, -1),
                            colors.Color(0.98, 0.98, 0.98),
                        ),
                    ]
                )
            )

            for idx, critical_req in enumerate(critical_reqs):
                row_idx = idx + 1
                weight = critical_req["weight"]

                if weight >= 150:
                    weight_color = colors.Color(0.8, 0.2, 0.2)
                elif weight >= 100:
                    weight_color = colors.Color(0.9, 0.6, 0.2)
                else:
                    weight_color = colors.Color(0.9, 0.9, 0.2)

                critical_table.setStyle(
                    TableStyle(
                        [
                            ("BACKGROUND", (1, row_idx), (1, row_idx), weight_color),
                            ("TEXTCOLOR", (1, row_idx), (1, row_idx), colors.white),
                        ]
                    )
                )

            elements.append(critical_table)
            elements.append(Spacer(1, 0.2 * inch))

            # Get styles for warning
            styles = getSampleStyleSheet()
            warning_text = """
            <b>IMMEDIATE ACTION REQUIRED:</b><br/>
            These requirements have the highest risk levels and have failed compliance checks.
            Please prioritize addressing these issues to improve your security posture.
            """

            warning_style = ParagraphStyle(
                "Warning",
                parent=styles["Normal"],
                fontSize=11,
                textColor=colors.Color(0.8, 0.2, 0.2),
                spaceBefore=10,
                spaceAfter=10,
                leftIndent=20,
                rightIndent=20,
                fontName="PlusJakartaSans",
                backColor=colors.Color(1.0, 0.95, 0.95),
                borderWidth=2,
                borderColor=colors.Color(0.8, 0.2, 0.2),
                borderPadding=10,
            )

            elements.append(Paragraph(warning_text, warning_style))

        elements.append(PageBreak())

        # Add detailed requirements section
        def get_weight(req):
            req_id = req["id"]
            attr = attrs_map.get(req_id, {})
            metadata = attr.get("attributes", {}).get("req_attributes", [])
            if metadata:
                return getattr(metadata[0], "Weight", 0)
            return 0

        sorted_reqs = sorted(resp_reqs, key=get_weight, reverse=True)

        if only_failed:
            sorted_reqs = [
                req for req in sorted_reqs if req["attributes"]["status"] == "FAIL"
            ]

        for req in sorted_reqs:
            req_id = req["id"]
            attr = attrs_map.get(req_id, {})
            desc = req["attributes"]["description"]
            status = req["attributes"]["status"]

            elements.append(Paragraph(f"{req_id}: {attr.get('description', desc)}", h1))

            status_component = _create_status_component(status)
            elements.append(status_component)
            elements.append(Spacer(1, 0.1 * inch))

            metadata = attr.get("attributes", {}).get("req_attributes", [])
            if metadata and len(metadata) > 0:
                m = metadata[0]
                elements.append(Paragraph("Title: ", h3))
                elements.append(Paragraph(f"{getattr(m, 'Title', 'N/A')}", normal))
                elements.append(Paragraph("Section: ", h3))
                elements.append(Paragraph(f"{getattr(m, 'Section', 'N/A')}", normal))
                elements.append(Paragraph("SubSection: ", h3))
                elements.append(Paragraph(f"{getattr(m, 'SubSection', 'N/A')}", normal))
                elements.append(Paragraph("Description: ", h3))
                elements.append(
                    Paragraph(f"{getattr(m, 'AttributeDescription', 'N/A')}", normal)
                )
                elements.append(Paragraph("Additional Information: ", h3))
                elements.append(
                    Paragraph(f"{getattr(m, 'AdditionalInformation', 'N/A')}", normal)
                )
                elements.append(Spacer(1, 0.1 * inch))

                risk_level = getattr(m, "LevelOfRisk", 0)
                weight = getattr(m, "Weight", 0)

                if status == "PASS":
                    score = risk_level * weight
                else:
                    score = 0

                risk_component = _create_risk_component(risk_level, weight, score)
                elements.append(risk_component)
                elements.append(Spacer(1, 0.1 * inch))

            # Use the findings index to get findings for this requirement's checks
            checks = attr.get("attributes", {}).get("checks", [])
            for cid in checks:
                elements.append(Paragraph(f"Check: {cid}", h2))
                elements.append(Spacer(1, 0.1 * inch))

                # Use the findings index instead of a function closure
                finds = findings_by_check.get(cid, [])

                if not finds:
                    elements.append(
                        Paragraph("- No information for this finding currently", normal)
                    )
                else:
                    findings_table_data = [
                        [
                            "Finding",
                            "Resource name",
                            "Severity",
                            "Status",
                            "Region",
                        ]
                    ]
                    for f in finds:
                        check_meta = getattr(f, "metadata", {})
                        title = getattr(
                            check_meta, "CheckTitle", getattr(f, "check_id", "")
                        )
                        resource_name = getattr(f, "resource_name", "")
                        if not resource_name:
                            resource_name = getattr(f, "resource_uid", "")
                        severity = getattr(check_meta, "Severity", "").capitalize()
                        finding_status = getattr(f, "status", "").upper()
                        region = getattr(f, "region", "global")

                        findings_table_data.append(
                            [
                                Paragraph(title, normal_center),
                                Paragraph(resource_name, normal_center),
                                Paragraph(severity, normal_center),
                                Paragraph(finding_status, normal_center),
                                Paragraph(region, normal_center),
                            ]
                        )
                    findings_table = Table(
                        findings_table_data,
                        colWidths=[
                            2.5 * inch,
                            3 * inch,
                            0.9 * inch,
                            0.9 * inch,
                            0.9 * inch,
                        ],
                    )
                    findings_table.setStyle(
                        TableStyle(
                            [
                                (
                                    "BACKGROUND",
                                    (0, 0),
                                    (-1, 0),
                                    colors.Color(0.2, 0.4, 0.6),
                                ),
                                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                                ("FONTNAME", (0, 0), (-1, 0), "FiraCode"),
                                ("ALIGN", (0, 0), (0, 0), "CENTER"),
                                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                                ("FONTSIZE", (0, 0), (-1, -1), 9),
                                (
                                    "GRID",
                                    (0, 0),
                                    (-1, -1),
                                    0.1,
                                    colors.Color(0.7, 0.8, 0.9),
                                ),
                                ("LEFTPADDING", (0, 0), (0, 0), 0),
                                ("RIGHTPADDING", (0, 0), (0, 0), 0),
                                ("TOPPADDING", (0, 0), (-1, -1), 4),
                                ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
                            ]
                        )
                    )
                    elements.append(findings_table)
                elements.append(Spacer(1, 0.1 * inch))

            elements.append(PageBreak())

        # Build the PDF
        doc.build(elements, onFirstPage=_add_pdf_footer, onLaterPages=_add_pdf_footer)
    except Exception as e:
        logger.info(
            f"Error building the document, line {e.__traceback__.tb_lineno} -- {e}"
        )
        raise e


def generate_threatscore_report_job(
    tenant_id: str, scan_id: str, provider_id: str
) -> dict[str, bool | str]:
    """
    Job function to generate a threatscore report and upload it to S3.

    This function orchestrates the complete report generation workflow:
    1. Validates that the scan has findings
    2. Checks provider type compatibility
    3. Generates the output directory
    4. Calls generate_threatscore_report to create the PDF
    5. Uploads the PDF to S3
    6. Cleans up temporary files

    Args:
        tenant_id (str): The tenant ID for Row-Level Security context.
        scan_id (str): The ID of the scan to generate a report for.
        provider_id (str): The ID of the provider used in the scan.

    Returns:
        dict[str, bool | str]: A dictionary containing:
            - 'upload' (bool): True if the report was successfully uploaded to S3, False otherwise.
            - 'error' (str): Error message if an exception occurred (only present on error).
    """
    # Check if the scan has findings and get provider info
    with rls_transaction(tenant_id, using=READ_REPLICA_ALIAS):
        if not ScanSummary.objects.filter(scan_id=scan_id).exists():
            logger.info(f"No findings found for scan {scan_id}")
            return {"upload": False}

        provider_obj = Provider.objects.get(id=provider_id)
        provider_uid = provider_obj.uid
        provider_type = provider_obj.provider

        if provider_type not in ["aws", "azure", "gcp", "m365"]:
            logger.info(
                f"Provider {provider_id} is not supported for threatscore report"
            )
            return {"upload": False}

    # This compliance is hardcoded because is the only one that is available for the threatscore report
    compliance_id = f"prowler_threatscore_{provider_type}"
    logger.info(
        f"Generating threatscore report for scan {scan_id} with compliance {compliance_id} inside the job"
    )
    try:
        logger.info("Generating the output directory")
        out_dir, _, threatscore_path = _generate_output_directory(
            DJANGO_TMP_OUTPUT_DIRECTORY, provider_uid, tenant_id, scan_id
        )
    except Exception as e:
        logger.error(f"Error generating output directory: {e}")
        return {"error": str(e)}

    pdf_path = f"{threatscore_path}_threatscore_report.pdf"
    logger.info(f"The path for the threatscore report is {pdf_path}")
    generate_threatscore_report(
        tenant_id=tenant_id,
        scan_id=scan_id,
        compliance_id=compliance_id,
        output_path=pdf_path,
        provider_id=provider_id,
        only_failed=True,
        min_risk_level=4,
    )

    upload_uri = _upload_to_s3(tenant_id, pdf_path, scan_id)
    if upload_uri:
        try:
            rmtree(Path(pdf_path).parent, ignore_errors=True)
        except Exception as e:
            logger.error(f"Error deleting output files: {e}")
        final_location, did_upload = upload_uri, True
    else:
        final_location, did_upload = out_dir, False

    logger.info(f"Threatscore report outputs at {final_location}")

    return {"upload": did_upload}
