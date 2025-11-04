import io
import os
from collections import defaultdict
from pathlib import Path
from shutil import rmtree

import matplotlib.pyplot as plt
from celery.utils.log import get_task_logger
from config.django.base import DJANGO_FINDINGS_BATCH_SIZE, DJANGO_TMP_OUTPUT_DIRECTORY
from django.db.models import Count, Q
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
from api.models import Finding, Provider, ScanSummary, StatusChoices
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


def _create_ens_nivel_badge(nivel: str) -> Table:
    """
    Create a visual badge for ENS requirement level (Nivel).

    Args:
        nivel (str): The level value (e.g., "alto", "medio", "bajo", "opcional").

    Returns:
        Table: A ReportLab Table object displaying the level with appropriate color coding.
    """
    nivel_lower = nivel.lower()

    if nivel_lower == "alto":
        nivel_color = colors.Color(0.8, 0.2, 0.2)
    elif nivel_lower == "medio":
        nivel_color = colors.Color(0.98, 0.75, 0.13)
    elif nivel_lower == "bajo":
        nivel_color = colors.Color(0.06, 0.72, 0.51)
    else:
        nivel_color = colors.Color(0.42, 0.45, 0.50)

    data = [[f"Nivel: {nivel.upper()}"]]

    table = Table(data, colWidths=[1.4 * inch])

    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, 0), nivel_color),
                ("TEXTCOLOR", (0, 0), (0, 0), colors.white),
                ("FONTNAME", (0, 0), (0, 0), "FiraCode"),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("FONTSIZE", (0, 0), (-1, -1), 11),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.black),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ]
        )
    )

    return table


def _create_ens_tipo_badge(tipo: str) -> Table:
    """
    Create a visual badge for ENS requirement type (Tipo).

    Args:
        tipo (str): The type value (e.g., "requisito", "refuerzo", "recomendacion", "medida").

    Returns:
        Table: A ReportLab Table object displaying the type with appropriate styling.
    """
    tipo_lower = tipo.lower()

    tipo_icons = {
        "requisito": "⚠️",
        "refuerzo": "🛡️",
        "recomendacion": "💡",
        "medida": "📋",
    }

    icon = tipo_icons.get(tipo_lower, "")
    tipo_color = colors.Color(0.2, 0.4, 0.6)

    data = [[f"{icon} {tipo.capitalize()}"]]

    table = Table(data, colWidths=[1.8 * inch])

    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, 0), tipo_color),
                ("TEXTCOLOR", (0, 0), (0, 0), colors.white),
                ("FONTNAME", (0, 0), (0, 0), "PlusJakartaSans"),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("FONTSIZE", (0, 0), (-1, -1), 11),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.black),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ]
        )
    )

    return table


def _create_ens_dimension_badges(dimensiones: list[str]) -> Table:
    """
    Create visual badges for ENS security dimensions.

    Args:
        dimensiones (list[str]): List of dimension names (e.g., ["trazabilidad", "autenticidad"]).

    Returns:
        Table: A ReportLab Table object with color-coded badges for each dimension.
    """
    dimension_mapping = {
        "trazabilidad": ("T", colors.Color(0.26, 0.52, 0.96)),
        "autenticidad": ("A", colors.Color(0.30, 0.69, 0.31)),
        "integridad": ("I", colors.Color(0.61, 0.15, 0.69)),
        "confidencialidad": ("C", colors.Color(0.96, 0.26, 0.21)),
        "disponibilidad": ("D", colors.Color(1.0, 0.60, 0.0)),
    }

    badges = []
    for dimension in dimensiones:
        dimension_lower = dimension.lower()
        if dimension_lower in dimension_mapping:
            badge_text, badge_color = dimension_mapping[dimension_lower]
            badges.append((badge_text, badge_color))

    if not badges:
        data = [["N/A"]]
        table = Table(data, colWidths=[1 * inch])
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (0, 0), colors.Color(0.9, 0.9, 0.9)),
                    ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                    ("FONTSIZE", (0, 0), (-1, -1), 10),
                ]
            )
        )
        return table

    data = [[badge[0] for badge in badges]]
    col_widths = [0.4 * inch] * len(badges)

    table = Table(data, colWidths=col_widths)

    styles = [
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("FONTNAME", (0, 0), (-1, -1), "FiraCode"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("TEXTCOLOR", (0, 0), (-1, -1), colors.white),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.black),
        ("LEFTPADDING", (0, 0), (-1, -1), 4),
        ("RIGHTPADDING", (0, 0), (-1, -1), 4),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
    ]

    for idx, (_, badge_color) in enumerate(badges):
        styles.append(("BACKGROUND", (idx, 0), (idx, 0), badge_color))

    table.setStyle(TableStyle(styles))

    return table


def _create_ens_mode_badge(modo: str) -> Table:
    """
    Create a visual badge for ENS execution mode (ModoEjecucion).

    Args:
        modo (str): The execution mode (e.g., "automático", "manual").

    Returns:
        Table: A ReportLab Table object displaying the execution mode.
    """
    modo_lower = modo.lower()

    if "auto" in modo_lower:
        icon = "🤖"
        modo_text = "Automático"
        modo_color = colors.Color(0.30, 0.69, 0.31)
    else:
        icon = "👤"
        modo_text = "Manual"
        modo_color = colors.Color(0.96, 0.60, 0.0)

    data = [[f"{icon} {modo_text}"]]

    table = Table(data, colWidths=[1.6 * inch])

    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, 0), modo_color),
                ("TEXTCOLOR", (0, 0), (0, 0), colors.white),
                ("FONTNAME", (0, 0), (0, 0), "PlusJakartaSans"),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("FONTSIZE", (0, 0), (-1, -1), 10),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.black),
                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 8),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ]
        )
    )

    return table


def _create_section_score_chart(
    requirements_list: list[dict], attributes_by_requirement_id: dict
) -> io.BytesIO:
    """
    Create a bar chart showing compliance score by section using ThreatScore formula.

    Args:
        requirements_list (list[dict]): List of requirement dictionaries with status and findings data.
        attributes_by_requirement_id (dict): Mapping of requirement IDs to their attributes including risk level and weight.

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
    for requirement in requirements_list:
        requirement_id = requirement["id"]
        requirement_attributes = attributes_by_requirement_id.get(requirement_id, {})

        metadata = requirement_attributes.get("attributes", {}).get(
            "req_attributes", []
        )
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
            passed_findings = requirement["attributes"].get("passed_findings", 0)
            total_findings = requirement["attributes"].get("total_findings", 0)

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


def _create_marco_category_chart(
    requirements_list: list[dict], attributes_by_requirement_id: dict
) -> io.BytesIO:
    """
    Create a bar chart showing compliance percentage by Marco (Section) and Categoría.

    Args:
        requirements_list (list[dict]): List of requirement dictionaries with status and findings data.
        attributes_by_requirement_id (dict): Mapping of requirement IDs to their attributes.

    Returns:
        io.BytesIO: A BytesIO buffer containing the chart image in PNG format.
    """
    # Collect data by Marco and Categoría
    marco_categoria_data = defaultdict(lambda: {"passed": 0, "total": 0})

    for requirement in requirements_list:
        requirement_id = requirement["id"]
        requirement_attributes = attributes_by_requirement_id.get(requirement_id, {})
        requirement_status = requirement["attributes"].get(
            "status", StatusChoices.MANUAL
        )

        metadata = requirement_attributes.get("attributes", {}).get(
            "req_attributes", []
        )
        if metadata:
            m = metadata[0]
            marco = getattr(m, "Marco", "N/A")
            categoria = getattr(m, "Categoria", "N/A")

            key = f"{marco} - {categoria}"
            marco_categoria_data[key]["total"] += 1
            if requirement_status == StatusChoices.PASS:
                marco_categoria_data[key]["passed"] += 1

    # Calculate percentages
    categories = []
    percentages = []

    for category, data in sorted(marco_categoria_data.items()):
        if data["total"] > 0:
            percentage = (data["passed"] / data["total"]) * 100
        else:
            percentage = 0

        categories.append(category)
        percentages.append(percentage)

    if not categories:
        # Return empty chart if no data
        fig, ax = plt.subplots(figsize=(12, 6))
        ax.text(0.5, 0.5, "No data available", ha="center", va="center", fontsize=14)
        ax.set_xlim(0, 1)
        ax.set_ylim(0, 1)
        ax.axis("off")
        buffer = io.BytesIO()
        plt.savefig(buffer, format="png", dpi=300, bbox_inches="tight")
        buffer.seek(0)
        plt.close()
        return buffer

    # Create horizontal bar chart
    fig, ax = plt.subplots(figsize=(12, max(8, len(categories) * 0.4)))

    colors_list = []
    for percentage in percentages:
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

    y_pos = range(len(categories))
    bars = ax.barh(y_pos, percentages, color=colors_list)

    ax.set_yticks(y_pos)
    ax.set_yticklabels(categories, fontsize=9)
    ax.set_xlabel("Porcentaje de Cumplimiento (%)", fontsize=12)
    ax.set_xlim(0, 100)

    # Add percentage labels
    for bar, percentage in zip(bars, percentages):
        width = bar.get_width()
        ax.text(
            width + 1,
            bar.get_y() + bar.get_height() / 2.0,
            f"{percentage:.1f}%",
            ha="left",
            va="center",
            fontweight="bold",
            fontsize=8,
        )

    ax.grid(True, alpha=0.3, axis="x")
    plt.tight_layout()

    buffer = io.BytesIO()
    plt.savefig(buffer, format="png", dpi=300, bbox_inches="tight")
    buffer.seek(0)
    plt.close()

    return buffer


def _create_dimensions_radar_chart(
    requirements_list: list[dict], attributes_by_requirement_id: dict
) -> io.BytesIO:
    """
    Create a radar/spider chart showing compliance percentage by security dimension.

    Args:
        requirements_list (list[dict]): List of requirement dictionaries with status and findings data.
        attributes_by_requirement_id (dict): Mapping of requirement IDs to their attributes.

    Returns:
        io.BytesIO: A BytesIO buffer containing the chart image in PNG format.
    """
    # Define the 5 dimensions
    dimension_names = [
        "Trazabilidad",
        "Autenticidad",
        "Integridad",
        "Confidencialidad",
        "Disponibilidad",
    ]

    dimension_keys = [
        "trazabilidad",
        "autenticidad",
        "integridad",
        "confidencialidad",
        "disponibilidad",
    ]

    dimension_data = {key: {"passed": 0, "total": 0} for key in dimension_keys}

    # Collect data for each dimension
    for requirement in requirements_list:
        requirement_id = requirement["id"]
        requirement_attributes = attributes_by_requirement_id.get(requirement_id, {})
        requirement_status = requirement["attributes"].get(
            "status", StatusChoices.MANUAL
        )

        metadata = requirement_attributes.get("attributes", {}).get(
            "req_attributes", []
        )
        if metadata:
            m = metadata[0]
            dimensiones = getattr(m, "Dimensiones", [])

            for dimension in dimensiones:
                dimension_lower = dimension.lower()
                if dimension_lower in dimension_data:
                    dimension_data[dimension_lower]["total"] += 1
                    if requirement_status == StatusChoices.PASS:
                        dimension_data[dimension_lower]["passed"] += 1

    # Calculate percentages
    percentages = []
    for key in dimension_keys:
        if dimension_data[key]["total"] > 0:
            percentage = (
                dimension_data[key]["passed"] / dimension_data[key]["total"]
            ) * 100
        else:
            percentage = 100  # No requirements = 100% (no failures)
        percentages.append(percentage)

    # Create radar chart
    angles = [
        n / float(len(dimension_names)) * 2 * 3.14159
        for n in range(len(dimension_names))
    ]
    percentages += percentages[:1]
    angles += angles[:1]

    fig, ax = plt.subplots(figsize=(10, 10), subplot_kw=dict(projection="polar"))

    ax.plot(angles, percentages, "o-", linewidth=2, color="#2196F3")
    ax.fill(angles, percentages, alpha=0.25, color="#2196F3")
    ax.set_xticks(angles[:-1])
    ax.set_xticklabels(dimension_names, fontsize=11)
    ax.set_ylim(0, 100)
    ax.set_yticks([20, 40, 60, 80, 100])
    ax.set_yticklabels(["20%", "40%", "60%", "80%", "100%"], fontsize=9)
    ax.grid(True, alpha=0.3)

    plt.tight_layout()

    buffer = io.BytesIO()
    plt.savefig(buffer, format="png", dpi=300, bbox_inches="tight")
    buffer.seek(0)
    plt.close()

    return buffer


def _aggregate_requirement_statistics_from_database(
    tenant_id: str, scan_id: str
) -> dict[str, dict[str, int]]:
    """
    Aggregate finding statistics by check_id using database aggregation.

    This function uses Django ORM aggregation to calculate pass/fail statistics
    entirely in the database, avoiding the need to load findings into memory.

    Args:
        tenant_id (str): The tenant ID for Row-Level Security context.
        scan_id (str): The ID of the scan to retrieve findings for.

    Returns:
        dict[str, dict[str, int]]: Dictionary mapping check_id to statistics:
            - 'passed' (int): Number of passed findings for this check
            - 'total' (int): Total number of findings for this check

    Example:
        {
            'aws_iam_user_mfa_enabled': {'passed': 10, 'total': 15},
            'aws_s3_bucket_public_access': {'passed': 0, 'total': 5}
        }
    """
    requirement_statistics_by_check_id = {}

    with rls_transaction(tenant_id, using=READ_REPLICA_ALIAS):
        # Use database aggregation to calculate stats without loading findings into memory
        aggregated_statistics_queryset = (
            Finding.all_objects.filter(tenant_id=tenant_id, scan_id=scan_id)
            .values("check_id")
            .annotate(
                total_findings=Count("id"),
                passed_findings=Count("id", filter=Q(status=StatusChoices.PASS)),
            )
        )

        for aggregated_stat in aggregated_statistics_queryset:
            check_id = aggregated_stat["check_id"]
            requirement_statistics_by_check_id[check_id] = {
                "passed": aggregated_stat["passed_findings"],
                "total": aggregated_stat["total_findings"],
            }

    logger.info(
        f"Aggregated statistics for {len(requirement_statistics_by_check_id)} unique checks"
    )
    return requirement_statistics_by_check_id


def _load_findings_for_requirement_checks(
    tenant_id: str, scan_id: str, check_ids: list[str], prowler_provider
) -> dict[str, list[FindingOutput]]:
    """
    Load findings for specific check IDs on-demand.

    This function loads only the findings needed for a specific set of checks,
    minimizing memory usage by avoiding loading all findings at once. This is used
    when generating detailed findings tables for specific requirements in the PDF.

    Args:
        tenant_id (str): The tenant ID for Row-Level Security context.
        scan_id (str): The ID of the scan to retrieve findings for.
        check_ids (list[str]): List of check IDs to load findings for.
        prowler_provider: The initialized Prowler provider instance.

    Returns:
        dict[str, list[FindingOutput]]: Dictionary mapping check_id to list of FindingOutput objects.

    Example:
        {
            'aws_iam_user_mfa_enabled': [FindingOutput(...), FindingOutput(...)],
            'aws_s3_bucket_public_access': [FindingOutput(...)]
        }
    """
    findings_by_check_id = defaultdict(list)

    if not check_ids:
        return dict(findings_by_check_id)

    logger.info(f"Loading findings for {len(check_ids)} checks on-demand")

    findings_queryset = (
        Finding.all_objects.filter(
            tenant_id=tenant_id, scan_id=scan_id, check_id__in=check_ids
        )
        .order_by("uid")
        .iterator()
    )

    with rls_transaction(tenant_id, using=READ_REPLICA_ALIAS):
        for batch, is_last_batch in batched(
            findings_queryset, DJANGO_FINDINGS_BATCH_SIZE
        ):
            for finding_model in batch:
                finding_output = FindingOutput.transform_api_finding(
                    finding_model, prowler_provider
                )
                findings_by_check_id[finding_output.check_id].append(finding_output)

    total_findings_loaded = sum(
        len(findings) for findings in findings_by_check_id.values()
    )
    logger.info(
        f"Loaded {total_findings_loaded} findings for {len(findings_by_check_id)} checks"
    )

    return dict(findings_by_check_id)


def _calculate_requirements_data_from_statistics(
    compliance_obj, requirement_statistics_by_check_id: dict[str, dict[str, int]]
) -> tuple[dict[str, dict], list[dict]]:
    """
    Calculate requirement status and statistics using pre-aggregated database statistics.

    This function uses O(n) lookups with pre-aggregated statistics from the database,
    avoiding the need to iterate over all findings for each requirement.

    Args:
        compliance_obj: The compliance framework object containing requirements.
        requirement_statistics_by_check_id (dict[str, dict[str, int]]): Pre-aggregated statistics
            mapping check_id to {'passed': int, 'total': int} counts.

    Returns:
        tuple[dict[str, dict], list[dict]]: A tuple containing:
            - attributes_by_requirement_id: Dictionary mapping requirement IDs to their attributes.
            - requirements_list: List of requirement dictionaries with status and statistics.
    """
    attributes_by_requirement_id = {}
    requirements_list = []

    compliance_framework = getattr(compliance_obj, "Framework", "N/A")
    compliance_version = getattr(compliance_obj, "Version", "N/A")

    for requirement in compliance_obj.Requirements:
        requirement_id = requirement.Id
        requirement_description = getattr(requirement, "Description", "")
        requirement_checks = getattr(requirement, "Checks", [])
        requirement_attributes = getattr(requirement, "Attributes", [])

        # Store requirement metadata for later use
        attributes_by_requirement_id[requirement_id] = {
            "attributes": {
                "req_attributes": requirement_attributes,
                "checks": requirement_checks,
            },
            "description": requirement_description,
        }

        # Calculate aggregated passed and total findings for this requirement
        total_passed_findings = 0
        total_findings_count = 0

        for check_id in requirement_checks:
            if check_id in requirement_statistics_by_check_id:
                check_statistics = requirement_statistics_by_check_id[check_id]
                total_findings_count += check_statistics["total"]
                total_passed_findings += check_statistics["passed"]

        # Determine overall requirement status based on findings
        if total_findings_count > 0:
            if total_passed_findings == total_findings_count:
                requirement_status = StatusChoices.PASS
            else:
                # Partial pass or complete fail both count as FAIL
                requirement_status = StatusChoices.FAIL
        else:
            # No findings means manual review required
            requirement_status = StatusChoices.MANUAL

        requirements_list.append(
            {
                "id": requirement_id,
                "attributes": {
                    "framework": compliance_framework,
                    "version": compliance_version,
                    "status": requirement_status,
                    "description": requirement_description,
                    "passed_findings": total_passed_findings,
                    "total_findings": total_findings_count,
                },
            }
        )

    return attributes_by_requirement_id, requirements_list


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

        # Aggregate requirement statistics from database (memory-efficient)
        logger.info(f"Aggregating requirement statistics for scan {scan_id}")
        requirement_statistics_by_check_id = (
            _aggregate_requirement_statistics_from_database(tenant_id, scan_id)
        )

        # Calculate requirements data using aggregated statistics
        attributes_by_requirement_id, requirements_list = (
            _calculate_requirements_data_from_statistics(
                compliance_obj, requirement_statistics_by_check_id
            )
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

        chart_buffer = _create_section_score_chart(
            requirements_list, attributes_by_requirement_id
        )
        chart_image = Image(chart_buffer, width=7 * inch, height=5.5 * inch)
        elements.append(chart_image)

        # Calculate overall ThreatScore using the same formula as the UI
        numerator = 0
        denominator = 0
        has_findings = False

        for requirement in requirements_list:
            requirement_id = requirement["id"]
            requirement_attributes = attributes_by_requirement_id.get(
                requirement_id, {}
            )

            # Get findings data
            passed_findings = requirement["attributes"].get("passed_findings", 0)
            total_findings = requirement["attributes"].get("total_findings", 0)

            # Skip if no findings (avoid division by zero)
            if total_findings == 0:
                continue

            has_findings = True
            metadata = requirement_attributes.get("attributes", {}).get(
                "req_attributes", []
            )
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
        for (
            requirement_id,
            requirement_attributes,
        ) in attributes_by_requirement_id.items():
            meta = requirement_attributes["attributes"]["req_attributes"][0]
            section = getattr(meta, "Section", "N/A")
            subsection = getattr(meta, "SubSection", "N/A")
            title = getattr(meta, "Title", "N/A")

            if section not in sections:
                sections[section] = {}
            if subsection not in sections[section]:
                sections[section][subsection] = []

            sections[section][subsection].append({"id": requirement_id, "title": title})

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

        critical_failed_requirements = []
        for requirement in requirements_list:
            requirement_status = requirement["attributes"]["status"]
            if requirement_status == StatusChoices.FAIL:
                requirement_id = requirement["id"]
                metadata = (
                    attributes_by_requirement_id.get(requirement_id, {})
                    .get("attributes", {})
                    .get("req_attributes", [{}])[0]
                )
                if metadata:
                    risk_level = getattr(metadata, "LevelOfRisk", 0)
                    weight = getattr(metadata, "Weight", 0)

                    if risk_level >= min_risk_level:
                        critical_failed_requirements.append(
                            {
                                "requirement": requirement,
                                "attributes": attributes_by_requirement_id[
                                    requirement_id
                                ],
                                "risk_level": risk_level,
                                "weight": weight,
                                "metadata": metadata,
                            }
                        )

        critical_failed_requirements.sort(
            key=lambda x: (x["risk_level"], x["weight"]), reverse=True
        )

        if not critical_failed_requirements:
            elements.append(
                Paragraph(
                    "✅ No critical failed requirements found. Great job!", normal
                )
            )
        else:
            elements.append(
                Paragraph(
                    f"Found {len(critical_failed_requirements)} critical failed requirements that require immediate attention:",
                    normal,
                )
            )
            elements.append(Spacer(1, 0.5 * inch))

            table_data = [["Risk", "Weight", "Requirement ID", "Title", "Section"]]

            for idx, critical_failed_requirement in enumerate(
                critical_failed_requirements
            ):
                requirement_id = critical_failed_requirement["requirement"]["id"]
                risk_level = critical_failed_requirement["risk_level"]
                weight = critical_failed_requirement["weight"]
                title = getattr(critical_failed_requirement["metadata"], "Title", "N/A")
                section = getattr(
                    critical_failed_requirement["metadata"], "Section", "N/A"
                )

                if len(title) > 50:
                    title = title[:47] + "..."

                table_data.append(
                    [str(risk_level), str(weight), requirement_id, title, section]
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

            for idx, critical_failed_requirement in enumerate(
                critical_failed_requirements
            ):
                row_idx = idx + 1
                weight = critical_failed_requirement["weight"]

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
        def get_weight_for_requirement(requirement_dict):
            requirement_id = requirement_dict["id"]
            requirement_attributes = attributes_by_requirement_id.get(
                requirement_id, {}
            )
            metadata = requirement_attributes.get("attributes", {}).get(
                "req_attributes", []
            )
            if metadata:
                return getattr(metadata[0], "Weight", 0)
            return 0

        sorted_requirements = sorted(
            requirements_list, key=get_weight_for_requirement, reverse=True
        )

        if only_failed:
            sorted_requirements = [
                requirement
                for requirement in sorted_requirements
                if requirement["attributes"]["status"] == StatusChoices.FAIL
            ]

        # Collect all check IDs for requirements that will be displayed
        # This allows us to load only the findings we actually need (memory optimization)
        check_ids_to_load = []
        for requirement in sorted_requirements:
            requirement_id = requirement["id"]
            requirement_attributes = attributes_by_requirement_id.get(
                requirement_id, {}
            )
            check_ids = requirement_attributes.get("attributes", {}).get("checks", [])
            check_ids_to_load.extend(check_ids)

        # Load findings on-demand only for the checks that will be displayed
        logger.info(
            f"Loading findings on-demand for {len(sorted_requirements)} requirements"
        )
        findings_by_check_id = _load_findings_for_requirement_checks(
            tenant_id, scan_id, check_ids_to_load, prowler_provider
        )

        for requirement in sorted_requirements:
            requirement_id = requirement["id"]
            requirement_attributes = attributes_by_requirement_id.get(
                requirement_id, {}
            )
            requirement_description = requirement["attributes"]["description"]
            requirement_status = requirement["attributes"]["status"]

            elements.append(
                Paragraph(
                    f"{requirement_id}: {requirement_attributes.get('description', requirement_description)}",
                    h1,
                )
            )

            status_component = _create_status_component(requirement_status)
            elements.append(status_component)
            elements.append(Spacer(1, 0.1 * inch))

            metadata = requirement_attributes.get("attributes", {}).get(
                "req_attributes", []
            )
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

                if requirement_status == StatusChoices.PASS:
                    score = risk_level * weight
                else:
                    score = 0

                risk_component = _create_risk_component(risk_level, weight, score)
                elements.append(risk_component)
                elements.append(Spacer(1, 0.1 * inch))

            # Get findings for this requirement's checks (loaded on-demand earlier)
            requirement_check_ids = requirement_attributes.get("attributes", {}).get(
                "checks", []
            )
            for check_id in requirement_check_ids:
                elements.append(Paragraph(f"Check: {check_id}", h2))
                elements.append(Spacer(1, 0.1 * inch))

                # Get findings for this check (already loaded on-demand)
                check_findings = findings_by_check_id.get(check_id, [])

                if not check_findings:
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
                    for finding_output in check_findings:
                        check_metadata = getattr(finding_output, "metadata", {})
                        finding_title = getattr(
                            check_metadata,
                            "CheckTitle",
                            getattr(finding_output, "check_id", ""),
                        )
                        resource_name = getattr(finding_output, "resource_name", "")
                        if not resource_name:
                            resource_name = getattr(finding_output, "resource_uid", "")
                        severity = getattr(check_metadata, "Severity", "").capitalize()
                        finding_status = getattr(finding_output, "status", "").upper()
                        region = getattr(finding_output, "region", "global")

                        findings_table_data.append(
                            [
                                Paragraph(finding_title, normal_center),
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


def generate_ens_report(
    tenant_id: str,
    scan_id: str,
    compliance_id: str,
    output_path: str,
    provider_id: str,
    include_manual: bool = True,
) -> None:
    """
    Generate a PDF compliance report for ENS RD2022 framework.

    This function creates a comprehensive PDF report containing:
    - Compliance overview and metadata
    - Executive summary with overall compliance score
    - Marco/Categoría analysis with charts
    - Security dimensions radar chart
    - Requirement type distribution
    - Execution mode distribution
    - Critical failed requirements (nivel alto)
    - Requirements index
    - Detailed findings for failed and manual requirements

    Args:
        tenant_id (str): The tenant ID for Row-Level Security context.
        scan_id (str): ID of the scan executed by Prowler.
        compliance_id (str): ID of the compliance framework (e.g., "ens_rd2022_aws").
        output_path (str): Output PDF file path (e.g., "/tmp/ens_report.pdf").
        provider_id (str): Provider ID for the scan.
        include_manual (bool): If True, include requirements with manual execution mode
            in the detailed requirements section. Defaults to True.

    Raises:
        Exception: If any error occurs during PDF generation, it will be logged and re-raised.
    """
    logger.info(f"Generating ENS report for scan {scan_id} with provider {provider_id}")
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

        # Aggregate requirement statistics from database (memory-efficient)
        logger.info(f"Aggregating requirement statistics for scan {scan_id}")
        requirement_statistics_by_check_id = (
            _aggregate_requirement_statistics_from_database(tenant_id, scan_id)
        )

        # Calculate requirements data using aggregated statistics
        attributes_by_requirement_id, requirements_list = (
            _calculate_requirements_data_from_statistics(
                compliance_obj, requirement_statistics_by_check_id
            )
        )

        # Initialize PDF document
        doc = SimpleDocTemplate(
            output_path,
            pagesize=letter,
            title=f"Informe de Cumplimiento ENS - {compliance_framework}",
            author="Prowler",
            subject=f"Informe de Cumplimiento para {compliance_framework}",
            creator="Prowler Engineering Team",
            keywords=f"compliance,{compliance_framework},security,ens,prowler",
        )

        elements = []

        # SECTION 1: PORTADA (Cover Page)
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
        elements.append(
            Paragraph("Informe de Cumplimiento ENS RD 311/2022", title_style)
        )
        elements.append(Spacer(1, 0.5 * inch))

        # Add compliance information table
        info_data = [
            ["Framework:", compliance_framework],
            ["ID:", compliance_id],
            ["Nombre:", Paragraph(compliance_name, normal_center)],
            ["Versión:", compliance_version],
            ["Proveedor:", provider_type.upper()],
            ["Scan ID:", scan_id],
            ["Descripción:", Paragraph(compliance_description, normal_center)],
        ]
        info_table = Table(info_data, colWidths=[2 * inch, 4 * inch])
        info_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (0, 6), colors.Color(0.2, 0.4, 0.6)),
                    ("TEXTCOLOR", (0, 0), (0, 6), colors.white),
                    ("FONTNAME", (0, 0), (0, 6), "FiraCode"),
                    ("BACKGROUND", (1, 0), (1, 6), colors.Color(0.95, 0.97, 1.0)),
                    ("TEXTCOLOR", (1, 0), (1, 6), colors.Color(0.2, 0.2, 0.2)),
                    ("FONTNAME", (1, 0), (1, 6), "PlusJakartaSans"),
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

        # SECTION 2: RESUMEN EJECUTIVO (Executive Summary)
        elements.append(Paragraph("Resumen Ejecutivo", h1))
        elements.append(Spacer(1, 0.2 * inch))

        # Calculate overall compliance (simple PASS/TOTAL)
        total_requirements = len(requirements_list)
        passed_requirements = sum(
            1
            for req in requirements_list
            if req["attributes"]["status"] == StatusChoices.PASS
        )
        failed_requirements = sum(
            1
            for req in requirements_list
            if req["attributes"]["status"] == StatusChoices.FAIL
        )
        manual_requirements = sum(
            1
            for req in requirements_list
            if req["attributes"]["status"] == StatusChoices.MANUAL
        )

        overall_compliance = (
            (passed_requirements / total_requirements * 100)
            if total_requirements > 0
            else 0
        )

        if overall_compliance >= 80:
            compliance_color = colors.Color(0.2, 0.8, 0.2)
        elif overall_compliance >= 60:
            compliance_color = colors.Color(0.8, 0.8, 0.2)
        else:
            compliance_color = colors.Color(0.8, 0.2, 0.2)

        summary_data = [
            ["Nivel de Cumplimiento Global:", f"{overall_compliance:.2f}%"],
        ]

        summary_table = Table(summary_data, colWidths=[3 * inch, 2 * inch])
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
        elements.append(Spacer(1, 0.3 * inch))

        # Summary counts table
        counts_data = [
            ["Estado", "Cantidad", "Porcentaje"],
            [
                "CUMPLE",
                str(passed_requirements),
                f"{(passed_requirements / total_requirements * 100):.1f}%",
            ],
            [
                "NO CUMPLE",
                str(failed_requirements),
                f"{(failed_requirements / total_requirements * 100):.1f}%",
            ],
            [
                "MANUAL",
                str(manual_requirements),
                f"{(manual_requirements / total_requirements * 100):.1f}%",
            ],
            ["TOTAL", str(total_requirements), "100%"],
        ]

        counts_table = Table(counts_data, colWidths=[2 * inch, 1.5 * inch, 1.5 * inch])
        counts_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.Color(0.2, 0.4, 0.6)),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTNAME", (0, 0), (-1, 0), "FiraCode"),
                    ("BACKGROUND", (0, 1), (0, 1), colors.Color(0.2, 0.8, 0.2)),
                    ("TEXTCOLOR", (0, 1), (0, 1), colors.white),
                    ("BACKGROUND", (0, 2), (0, 2), colors.Color(0.8, 0.2, 0.2)),
                    ("TEXTCOLOR", (0, 2), (0, 2), colors.white),
                    ("BACKGROUND", (0, 3), (0, 3), colors.Color(0.96, 0.60, 0.0)),
                    ("TEXTCOLOR", (0, 3), (0, 3), colors.white),
                    ("BACKGROUND", (0, 4), (0, 4), colors.Color(0.4, 0.4, 0.4)),
                    ("TEXTCOLOR", (0, 4), (0, 4), colors.white),
                    ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("FONTSIZE", (0, 0), (-1, -1), 10),
                    ("GRID", (0, 0), (-1, -1), 1, colors.Color(0.7, 0.7, 0.7)),
                    ("LEFTPADDING", (0, 0), (-1, -1), 8),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                    ("TOPPADDING", (0, 0), (-1, -1), 6),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ]
            )
        )
        elements.append(counts_table)
        elements.append(Spacer(1, 0.3 * inch))

        # Summary by Nivel
        nivel_data = defaultdict(lambda: {"passed": 0, "total": 0})
        for requirement in requirements_list:
            requirement_id = requirement["id"]
            requirement_attributes = attributes_by_requirement_id.get(
                requirement_id, {}
            )
            requirement_status = requirement["attributes"]["status"]

            metadata = requirement_attributes.get("attributes", {}).get(
                "req_attributes", []
            )
            if metadata:
                m = metadata[0]
                nivel = getattr(m, "Nivel", "N/A")
                nivel_data[nivel]["total"] += 1
                if requirement_status == StatusChoices.PASS:
                    nivel_data[nivel]["passed"] += 1

        elements.append(Paragraph("Cumplimiento por Nivel", h2))
        nivel_table_data = [["Nivel", "Cumplidos", "Total", "Porcentaje"]]
        for nivel in ["alto", "medio", "bajo", "opcional"]:
            if nivel in nivel_data:
                data = nivel_data[nivel]
                percentage = (
                    (data["passed"] / data["total"] * 100) if data["total"] > 0 else 0
                )
                nivel_table_data.append(
                    [
                        nivel.capitalize(),
                        str(data["passed"]),
                        str(data["total"]),
                        f"{percentage:.1f}%",
                    ]
                )

        nivel_table = Table(
            nivel_table_data, colWidths=[1.5 * inch, 1.5 * inch, 1.5 * inch, 1.5 * inch]
        )
        nivel_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.Color(0.2, 0.4, 0.6)),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTNAME", (0, 0), (-1, 0), "FiraCode"),
                    ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("FONTSIZE", (0, 0), (-1, -1), 10),
                    ("GRID", (0, 0), (-1, -1), 1, colors.Color(0.7, 0.7, 0.7)),
                    ("LEFTPADDING", (0, 0), (-1, -1), 8),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                    ("TOPPADDING", (0, 0), (-1, -1), 6),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ]
            )
        )
        elements.append(nivel_table)
        elements.append(PageBreak())

        # SECTION 3: ANÁLISIS POR MARCOS (Marco Analysis)
        elements.append(Paragraph("Análisis por Marcos y Categorías", h1))
        elements.append(Spacer(1, 0.2 * inch))

        chart_buffer = _create_marco_category_chart(
            requirements_list, attributes_by_requirement_id
        )
        chart_image = Image(chart_buffer, width=7 * inch, height=5 * inch)
        elements.append(chart_image)
        elements.append(PageBreak())

        # SECTION 4: DIMENSIONES DE SEGURIDAD (Security Dimensions)
        elements.append(Paragraph("Análisis por Dimensiones de Seguridad", h1))
        elements.append(Spacer(1, 0.2 * inch))

        radar_buffer = _create_dimensions_radar_chart(
            requirements_list, attributes_by_requirement_id
        )
        radar_image = Image(radar_buffer, width=6 * inch, height=6 * inch)
        elements.append(radar_image)
        elements.append(PageBreak())

        # SECTION 5: DISTRIBUCIÓN POR TIPO (Type Distribution)
        elements.append(Paragraph("Distribución por Tipo de Requisito", h1))
        elements.append(Spacer(1, 0.2 * inch))

        tipo_data = defaultdict(lambda: {"passed": 0, "total": 0})
        for requirement in requirements_list:
            requirement_id = requirement["id"]
            requirement_attributes = attributes_by_requirement_id.get(
                requirement_id, {}
            )
            requirement_status = requirement["attributes"]["status"]

            metadata = requirement_attributes.get("attributes", {}).get(
                "req_attributes", []
            )
            if metadata:
                m = metadata[0]
                tipo = getattr(m, "Tipo", "N/A")
                tipo_data[tipo]["total"] += 1
                if requirement_status == StatusChoices.PASS:
                    tipo_data[tipo]["passed"] += 1

        tipo_table_data = [["Tipo", "Cumplidos", "Total", "Porcentaje"]]
        for tipo in ["requisito", "refuerzo", "recomendacion", "medida"]:
            if tipo in tipo_data:
                data = tipo_data[tipo]
                percentage = (
                    (data["passed"] / data["total"] * 100) if data["total"] > 0 else 0
                )
                tipo_table_data.append(
                    [
                        tipo.capitalize(),
                        str(data["passed"]),
                        str(data["total"]),
                        f"{percentage:.1f}%",
                    ]
                )

        tipo_table = Table(
            tipo_table_data, colWidths=[2 * inch, 1.5 * inch, 1.5 * inch, 1.5 * inch]
        )
        tipo_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.Color(0.2, 0.4, 0.6)),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTNAME", (0, 0), (-1, 0), "FiraCode"),
                    ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("FONTSIZE", (0, 0), (-1, -1), 10),
                    ("GRID", (0, 0), (-1, -1), 1, colors.Color(0.7, 0.7, 0.7)),
                    ("LEFTPADDING", (0, 0), (-1, -1), 8),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                    ("TOPPADDING", (0, 0), (-1, -1), 6),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ]
            )
        )
        elements.append(tipo_table)
        elements.append(PageBreak())

        # SECTION 6: MODO DE EJECUCIÓN (Execution Mode)
        elements.append(Paragraph("Distribución por Modo de Ejecución", h1))
        elements.append(Spacer(1, 0.2 * inch))

        modo_data = defaultdict(lambda: {"passed": 0, "total": 0})
        for requirement in requirements_list:
            requirement_id = requirement["id"]
            requirement_attributes = attributes_by_requirement_id.get(
                requirement_id, {}
            )
            requirement_status = requirement["attributes"]["status"]

            metadata = requirement_attributes.get("attributes", {}).get(
                "req_attributes", []
            )
            if metadata:
                m = metadata[0]
                modo = getattr(m, "ModoEjecucion", "N/A")
                modo_key = "automático" if "auto" in modo.lower() else "manual"
                modo_data[modo_key]["total"] += 1
                if requirement_status == StatusChoices.PASS:
                    modo_data[modo_key]["passed"] += 1

        modo_table_data = [["Modo", "Cumplidos", "Total", "Porcentaje"]]
        for modo in ["automático", "manual"]:
            if modo in modo_data:
                data = modo_data[modo]
                percentage = (
                    (data["passed"] / data["total"] * 100) if data["total"] > 0 else 0
                )
                modo_table_data.append(
                    [
                        modo.capitalize(),
                        str(data["passed"]),
                        str(data["total"]),
                        f"{percentage:.1f}%",
                    ]
                )

        modo_table = Table(
            modo_table_data, colWidths=[2 * inch, 1.5 * inch, 1.5 * inch, 1.5 * inch]
        )
        modo_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.Color(0.2, 0.4, 0.6)),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTNAME", (0, 0), (-1, 0), "FiraCode"),
                    ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                    ("FONTSIZE", (0, 0), (-1, -1), 10),
                    ("GRID", (0, 0), (-1, -1), 1, colors.Color(0.7, 0.7, 0.7)),
                    ("LEFTPADDING", (0, 0), (-1, -1), 8),
                    ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                    ("TOPPADDING", (0, 0), (-1, -1), 6),
                    ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                ]
            )
        )
        elements.append(modo_table)
        elements.append(PageBreak())

        # SECTION 7: REQUISITOS CRÍTICOS NO CUMPLIDOS (Critical Failed Requirements)
        elements.append(Paragraph("Requisitos Críticos No Cumplidos", h1))
        elements.append(Spacer(1, 0.2 * inch))

        critical_failed = []
        for requirement in requirements_list:
            requirement_status = requirement["attributes"]["status"]
            if requirement_status == StatusChoices.FAIL:
                requirement_id = requirement["id"]
                metadata = (
                    attributes_by_requirement_id.get(requirement_id, {})
                    .get("attributes", {})
                    .get("req_attributes", [{}])[0]
                )
                if metadata:
                    nivel = getattr(metadata, "Nivel", "")
                    if nivel.lower() == "alto":
                        critical_failed.append(
                            {
                                "requirement": requirement,
                                "metadata": metadata,
                            }
                        )

        if not critical_failed:
            elements.append(
                Paragraph(
                    "✅ No se encontraron requisitos críticos no cumplidos.", normal
                )
            )
        else:
            elements.append(
                Paragraph(
                    f"Se encontraron {len(critical_failed)} requisitos de nivel Alto que no cumplen:",
                    normal,
                )
            )
            elements.append(Spacer(1, 0.3 * inch))

            critical_table_data = [["ID", "Descripción", "Marco", "Categoría", "Tipo"]]
            for item in critical_failed:
                requirement_id = item["requirement"]["id"]
                description = item["requirement"]["attributes"]["description"]
                marco = getattr(item["metadata"], "Marco", "N/A")
                categoria = getattr(item["metadata"], "Categoria", "N/A")
                tipo = getattr(item["metadata"], "Tipo", "N/A")

                if len(description) > 50:
                    description = description[:47] + "..."

                critical_table_data.append(
                    [requirement_id, description, marco, categoria, tipo.capitalize()]
                )

            critical_table = Table(
                critical_table_data,
                colWidths=[1.3 * inch, 2.5 * inch, 1.5 * inch, 1.5 * inch, 1 * inch],
            )
            critical_table.setStyle(
                TableStyle(
                    [
                        ("BACKGROUND", (0, 0), (-1, 0), colors.Color(0.8, 0.2, 0.2)),
                        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                        ("FONTNAME", (0, 0), (-1, 0), "FiraCode"),
                        ("FONTSIZE", (0, 0), (-1, 0), 9),
                        ("FONTNAME", (0, 1), (0, -1), "FiraCode"),
                        ("FONTSIZE", (0, 1), (-1, -1), 8),
                        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                        ("GRID", (0, 0), (-1, -1), 1, colors.Color(0.7, 0.7, 0.7)),
                        ("LEFTPADDING", (0, 0), (-1, -1), 6),
                        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
                        ("TOPPADDING", (0, 0), (-1, -1), 6),
                        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                        (
                            "BACKGROUND",
                            (1, 1),
                            (-1, -1),
                            colors.Color(0.98, 0.98, 0.98),
                        ),
                    ]
                )
            )
            elements.append(critical_table)

        elements.append(PageBreak())

        # SECTION 8: ÍNDICE DE REQUISITOS (Requirements Index)
        elements.append(Paragraph("Índice de Requisitos", h1))
        elements.append(Spacer(1, 0.2 * inch))

        # Group by Marco → Categoría
        marco_categoria_index = defaultdict(lambda: defaultdict(list))
        for (
            requirement_id,
            requirement_attributes,
        ) in attributes_by_requirement_id.items():
            metadata = requirement_attributes["attributes"]["req_attributes"][0]
            marco = getattr(metadata, "Marco", "N/A")
            categoria = getattr(metadata, "Categoria", "N/A")
            id_grupo = getattr(metadata, "IdGrupoControl", "N/A")

            marco_categoria_index[marco][categoria].append(
                {
                    "id": requirement_id,
                    "id_grupo": id_grupo,
                    "description": requirement_attributes["description"],
                }
            )

        for marco, categorias in sorted(marco_categoria_index.items()):
            elements.append(Paragraph(f"Marco: {marco.capitalize()}", h2))
            for categoria, requirements in sorted(categorias.items()):
                elements.append(Paragraph(f"Categoría: {categoria.capitalize()}", h3))
                for req in requirements:
                    desc = req["description"]
                    if len(desc) > 80:
                        desc = desc[:77] + "..."
                    elements.append(Paragraph(f"{req['id']} - {desc}", normal))
                elements.append(Spacer(1, 0.05 * inch))

        elements.append(PageBreak())

        # SECTION 9: DETALLE DE REQUISITOS (Detailed Requirements)
        elements.append(Paragraph("Detalle de Requisitos", h1))
        elements.append(Spacer(1, 0.2 * inch))

        # Filter: NO CUMPLE + MANUAL (if include_manual)
        filtered_requirements = [
            req
            for req in requirements_list
            if req["attributes"]["status"] == StatusChoices.FAIL
            or (include_manual and req["attributes"]["status"] == StatusChoices.MANUAL)
        ]

        if not filtered_requirements:
            elements.append(
                Paragraph("✅ Todos los requisitos automáticos cumplen.", normal)
            )
        else:
            elements.append(
                Paragraph(
                    f"Se muestran {len(filtered_requirements)} requisitos que requieren atención:",
                    normal,
                )
            )
            elements.append(Spacer(1, 0.2 * inch))

            # Collect check IDs to load
            check_ids_to_load = []
            for requirement in filtered_requirements:
                requirement_id = requirement["id"]
                requirement_attributes = attributes_by_requirement_id.get(
                    requirement_id, {}
                )
                check_ids = requirement_attributes.get("attributes", {}).get(
                    "checks", []
                )
                check_ids_to_load.extend(check_ids)

            # Load findings on-demand
            logger.info(
                f"Loading findings on-demand for {len(filtered_requirements)} requirements"
            )
            findings_by_check_id = _load_findings_for_requirement_checks(
                tenant_id, scan_id, check_ids_to_load, prowler_provider
            )

            for requirement in filtered_requirements:
                requirement_id = requirement["id"]
                requirement_attributes = attributes_by_requirement_id.get(
                    requirement_id, {}
                )
                requirement_status = requirement["attributes"]["status"]

                elements.append(Paragraph(f"{requirement_id}", h1))

                # Status badge
                status_component = _create_status_component(requirement_status)
                elements.append(status_component)
                elements.append(Spacer(1, 0.1 * inch))

                metadata = requirement_attributes.get("attributes", {}).get(
                    "req_attributes", []
                )
                if metadata and len(metadata) > 0:
                    m = metadata[0]

                    # Nivel badge
                    nivel = getattr(m, "Nivel", "N/A")
                    nivel_badge = _create_ens_nivel_badge(nivel)
                    elements.append(nivel_badge)
                    elements.append(Spacer(1, 0.1 * inch))

                    # Tipo badge
                    tipo = getattr(m, "Tipo", "N/A")
                    tipo_badge = _create_ens_tipo_badge(tipo)
                    elements.append(tipo_badge)
                    elements.append(Spacer(1, 0.1 * inch))

                    # Modo badge
                    modo = getattr(m, "ModoEjecucion", "N/A")
                    modo_badge = _create_ens_mode_badge(modo)
                    elements.append(modo_badge)
                    elements.append(Spacer(1, 0.1 * inch))

                    # Dimensiones badges
                    dimensiones = getattr(m, "Dimensiones", [])
                    if dimensiones:
                        elements.append(Paragraph("Dimensiones:", h3))
                        dim_badges = _create_ens_dimension_badges(dimensiones)
                        elements.append(dim_badges)
                        elements.append(Spacer(1, 0.1 * inch))

                    # Details
                    elements.append(Paragraph("Marco:", h3))
                    elements.append(Paragraph(f"{getattr(m, 'Marco', 'N/A')}", normal))
                    elements.append(Paragraph("Categoría:", h3))
                    elements.append(
                        Paragraph(f"{getattr(m, 'Categoria', 'N/A')}", normal)
                    )
                    elements.append(Paragraph("ID Grupo Control:", h3))
                    elements.append(
                        Paragraph(f"{getattr(m, 'IdGrupoControl', 'N/A')}", normal)
                    )
                    elements.append(Paragraph("Descripción del Control:", h3))
                    elements.append(
                        Paragraph(f"{getattr(m, 'DescripcionControl', 'N/A')}", normal)
                    )
                    elements.append(Spacer(1, 0.1 * inch))

                # Findings for checks
                requirement_check_ids = requirement_attributes.get(
                    "attributes", {}
                ).get("checks", [])
                for check_id in requirement_check_ids:
                    elements.append(Paragraph(f"Check: {check_id}", h2))
                    elements.append(Spacer(1, 0.1 * inch))

                    check_findings = findings_by_check_id.get(check_id, [])

                    if not check_findings:
                        elements.append(
                            Paragraph(
                                "- No hay información disponible para este check",
                                normal,
                            )
                        )
                    else:
                        findings_table_data = [
                            ["Finding", "Resource name", "Severity", "Status", "Region"]
                        ]
                        for finding_output in check_findings:
                            check_metadata = getattr(finding_output, "metadata", {})
                            finding_title = getattr(
                                check_metadata,
                                "CheckTitle",
                                getattr(finding_output, "check_id", ""),
                            )
                            resource_name = getattr(finding_output, "resource_name", "")
                            if not resource_name:
                                resource_name = getattr(
                                    finding_output, "resource_uid", ""
                                )
                            severity = getattr(
                                check_metadata, "Severity", ""
                            ).capitalize()
                            finding_status = getattr(
                                finding_output, "status", ""
                            ).upper()
                            region = getattr(finding_output, "region", "global")

                            findings_table_data.append(
                                [
                                    Paragraph(finding_title, normal_center),
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
        logger.error(
            f"Error building ENS report, line {e.__traceback__.tb_lineno} -- {e}"
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
        out_dir, _, threatscore_path, _ = _generate_output_directory(
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

    upload_uri = _upload_to_s3(
        tenant_id,
        scan_id,
        pdf_path,
        f"threatscore/{Path(pdf_path).name}",
    )
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


def generate_ens_report_job(
    tenant_id: str, scan_id: str, provider_id: str
) -> dict[str, bool | str]:
    """
    Job function to generate an ENS RD2022 compliance report and upload it to S3.

    This function orchestrates the complete ENS report generation workflow:
    1. Validates that the scan has findings
    2. Checks provider type compatibility
    3. Generates the output directory
    4. Calls generate_ens_report to create the PDF
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

        if provider_type not in ["aws", "azure", "gcp"]:
            logger.info(f"Provider {provider_id} is not supported for ENS report")
            return {"upload": False}

    # Determine compliance_id based on provider
    compliance_id = f"ens_rd2022_{provider_type}"
    logger.info(
        f"Generating ENS report for scan {scan_id} with compliance {compliance_id} inside the job"
    )
    try:
        logger.info("Generating the output directory")
        out_dir, _, _, ens_path = _generate_output_directory(
            DJANGO_TMP_OUTPUT_DIRECTORY, provider_uid, tenant_id, scan_id
        )
    except Exception as e:
        logger.error(f"Error generating output directory: {e}")
        return {"error": str(e)}

    pdf_path = f"{ens_path}_ens_report.pdf"
    logger.info(f"The path for the ENS report is {pdf_path}")
    generate_ens_report(
        tenant_id=tenant_id,
        scan_id=scan_id,
        compliance_id=compliance_id,
        output_path=pdf_path,
        provider_id=provider_id,
        include_manual=True,
    )

    upload_uri = _upload_to_s3(
        tenant_id,
        scan_id,
        pdf_path,
        f"ens/{Path(pdf_path).name}",
    )
    if upload_uri:
        try:
            rmtree(Path(pdf_path).parent, ignore_errors=True)
        except Exception as e:
            logger.error(f"Error deleting output files: {e}")
        final_location, did_upload = upload_uri, True
    else:
        final_location, did_upload = out_dir, False

    logger.info(f"ENS report outputs at {final_location}")

    return {"upload": did_upload}
