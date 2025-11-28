import io
import os
from collections import defaultdict
from pathlib import Path
from shutil import rmtree

import matplotlib.pyplot as plt
from celery.utils.log import get_task_logger
from config.django.base import DJANGO_TMP_OUTPUT_DIRECTORY
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
from tasks.jobs.export import _generate_compliance_output_directory, _upload_to_s3
from tasks.jobs.threatscore import compute_threatscore_metrics
from tasks.jobs.threatscore_utils import (
    _aggregate_requirement_statistics_from_database,
    _calculate_requirements_data_from_statistics,
    _load_findings_for_requirement_checks,
)

from api.db_router import READ_REPLICA_ALIAS
from api.db_utils import rls_transaction
from api.models import Provider, ScanSummary, StatusChoices, ThreatScoreSnapshot
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

# Color constants
COLOR_PROWLER_DARK_GREEN = colors.Color(0.1, 0.5, 0.2)
COLOR_BLUE = colors.Color(0.2, 0.4, 0.6)
COLOR_LIGHT_BLUE = colors.Color(0.3, 0.5, 0.7)
COLOR_LIGHTER_BLUE = colors.Color(0.4, 0.6, 0.8)
COLOR_BG_BLUE = colors.Color(0.95, 0.97, 1.0)
COLOR_BG_LIGHT_BLUE = colors.Color(0.98, 0.99, 1.0)
COLOR_GRAY = colors.Color(0.2, 0.2, 0.2)
COLOR_LIGHT_GRAY = colors.Color(0.9, 0.9, 0.9)
COLOR_BORDER_GRAY = colors.Color(0.7, 0.8, 0.9)
COLOR_GRID_GRAY = colors.Color(0.7, 0.7, 0.7)
COLOR_DARK_GRAY = colors.Color(0.4, 0.4, 0.4)
COLOR_HEADER_DARK = colors.Color(0.1, 0.3, 0.5)
COLOR_HEADER_MEDIUM = colors.Color(0.15, 0.35, 0.55)
COLOR_WHITE = colors.white

# Risk and status colors
COLOR_HIGH_RISK = colors.Color(0.8, 0.2, 0.2)
COLOR_MEDIUM_RISK = colors.Color(0.9, 0.6, 0.2)
COLOR_LOW_RISK = colors.Color(0.9, 0.9, 0.2)
COLOR_SAFE = colors.Color(0.2, 0.8, 0.2)

# ENS specific colors
COLOR_ENS_ALTO = colors.Color(0.8, 0.2, 0.2)
COLOR_ENS_MEDIO = colors.Color(0.98, 0.75, 0.13)
COLOR_ENS_BAJO = colors.Color(0.06, 0.72, 0.51)
COLOR_ENS_OPCIONAL = colors.Color(0.42, 0.45, 0.50)
COLOR_ENS_TIPO = colors.Color(0.2, 0.4, 0.6)
COLOR_ENS_AUTO = colors.Color(0.30, 0.69, 0.31)
COLOR_ENS_MANUAL = colors.Color(0.96, 0.60, 0.0)

# NIS2 specific colors
COLOR_NIS2_PRIMARY = colors.Color(0.12, 0.23, 0.54)  # EU Blue #1E3A8A
COLOR_NIS2_SECONDARY = colors.Color(0.23, 0.51, 0.96)  # Light Blue #3B82F6
COLOR_NIS2_BG_BLUE = colors.Color(0.96, 0.97, 0.99)  # Very light blue background

# Chart colors
CHART_COLOR_GREEN_1 = "#4CAF50"
CHART_COLOR_GREEN_2 = "#8BC34A"
CHART_COLOR_YELLOW = "#FFEB3B"
CHART_COLOR_ORANGE = "#FF9800"
CHART_COLOR_RED = "#F44336"
CHART_COLOR_BLUE = "#2196F3"

# ENS dimension mappings
DIMENSION_MAPPING = {
    "trazabilidad": ("T", colors.Color(0.26, 0.52, 0.96)),
    "autenticidad": ("A", colors.Color(0.30, 0.69, 0.31)),
    "integridad": ("I", colors.Color(0.61, 0.15, 0.69)),
    "confidencialidad": ("C", colors.Color(0.96, 0.26, 0.21)),
    "disponibilidad": ("D", colors.Color(1.0, 0.60, 0.0)),
}

# ENS tipo icons
TIPO_ICONS = {
    "requisito": "⚠️",
    "refuerzo": "🛡️",
    "recomendacion": "💡",
    "medida": "📋",
}

# Dimension names for charts
DIMENSION_NAMES = [
    "Trazabilidad",
    "Autenticidad",
    "Integridad",
    "Confidencialidad",
    "Disponibilidad",
]

DIMENSION_KEYS = [
    "trazabilidad",
    "autenticidad",
    "integridad",
    "confidencialidad",
    "disponibilidad",
]

# ENS nivel order
ENS_NIVEL_ORDER = ["alto", "medio", "bajo", "opcional"]

# ENS tipo order
ENS_TIPO_ORDER = ["requisito", "refuerzo", "recomendacion", "medida"]

# ThreatScore expected sections
THREATSCORE_SECTIONS = [
    "1. IAM",
    "2. Attack Surface",
    "3. Logging and Monitoring",
    "4. Encryption",
]

# NIS2 main sections (simplified for chart display)
NIS2_SECTIONS = [
    "1",  # Policy on Security
    "2",  # Risk Management
    "3",  # Incident Handling
    "4",  # Business Continuity
    "5",  # Supply Chain Security
    "6",  # Acquisition & Development
    "7",  # Effectiveness Assessment
    "9",  # Cryptography
    "11",  # Access Control
    "12",  # Asset Management
]

# Table column widths (in inches)
COL_WIDTH_SMALL = 0.4 * inch
COL_WIDTH_MEDIUM = 0.9 * inch
COL_WIDTH_LARGE = 1.5 * inch
COL_WIDTH_XLARGE = 2 * inch
COL_WIDTH_XXLARGE = 3 * inch

# Common padding values
PADDING_SMALL = 4
PADDING_MEDIUM = 6
PADDING_LARGE = 8
PADDING_XLARGE = 10


# Cache for PDF styles to avoid recreating them on every call
_PDF_STYLES_CACHE: dict[str, ParagraphStyle] | None = None


# Helper functions for performance optimization
def _get_color_for_risk_level(risk_level: int) -> colors.Color:
    """Get color based on risk level using optimized lookup."""
    if risk_level >= 4:
        return COLOR_HIGH_RISK
    elif risk_level >= 3:
        return COLOR_MEDIUM_RISK
    elif risk_level >= 2:
        return COLOR_LOW_RISK
    return COLOR_SAFE


def _get_color_for_weight(weight: int) -> colors.Color:
    """Get color based on weight using optimized lookup."""
    if weight > 100:
        return COLOR_HIGH_RISK
    elif weight > 50:
        return COLOR_LOW_RISK
    return COLOR_SAFE


def _get_color_for_compliance(percentage: float) -> colors.Color:
    """Get color based on compliance percentage."""
    if percentage >= 80:
        return COLOR_SAFE
    elif percentage >= 60:
        return COLOR_LOW_RISK
    return COLOR_HIGH_RISK


def _get_chart_color_for_percentage(percentage: float) -> str:
    """Get chart color string based on percentage."""
    if percentage >= 80:
        return CHART_COLOR_GREEN_1
    elif percentage >= 60:
        return CHART_COLOR_GREEN_2
    elif percentage >= 40:
        return CHART_COLOR_YELLOW
    elif percentage >= 20:
        return CHART_COLOR_ORANGE
    return CHART_COLOR_RED


def _get_ens_nivel_color(nivel: str) -> colors.Color:
    """Get ENS nivel color using optimized lookup."""
    nivel_lower = nivel.lower()
    if nivel_lower == "alto":
        return COLOR_ENS_ALTO
    elif nivel_lower == "medio":
        return COLOR_ENS_MEDIO
    elif nivel_lower == "bajo":
        return COLOR_ENS_BAJO
    return COLOR_ENS_OPCIONAL


def _safe_getattr(obj, attr: str, default: str = "N/A") -> str:
    """Optimized getattr with default value."""
    return getattr(obj, attr, default)


def _create_info_table_style() -> TableStyle:
    """Create a reusable table style for information/metadata tables."""
    return TableStyle(
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
            ("LEFTPADDING", (0, 0), (-1, -1), PADDING_XLARGE),
            ("RIGHTPADDING", (0, 0), (-1, -1), PADDING_XLARGE),
            ("TOPPADDING", (0, 0), (-1, -1), PADDING_LARGE),
            ("BOTTOMPADDING", (0, 0), (-1, -1), PADDING_LARGE),
        ]
    )


def _create_header_table_style(header_color: colors.Color = None) -> TableStyle:
    """Create a reusable table style for tables with headers."""
    if header_color is None:
        header_color = COLOR_BLUE

    return TableStyle(
        [
            ("BACKGROUND", (0, 0), (-1, 0), header_color),
            ("TEXTCOLOR", (0, 0), (-1, 0), COLOR_WHITE),
            ("FONTNAME", (0, 0), (-1, 0), "FiraCode"),
            ("FONTSIZE", (0, 0), (-1, 0), 10),
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("FONTSIZE", (1, 1), (-1, -1), 9),
            ("GRID", (0, 0), (-1, -1), 1, COLOR_GRID_GRAY),
            ("LEFTPADDING", (0, 0), (-1, -1), PADDING_MEDIUM),
            ("RIGHTPADDING", (0, 0), (-1, -1), PADDING_MEDIUM),
            ("TOPPADDING", (0, 0), (-1, -1), PADDING_MEDIUM),
            ("BOTTOMPADDING", (0, 0), (-1, -1), PADDING_MEDIUM),
        ]
    )


def _create_findings_table_style() -> TableStyle:
    """Create a reusable table style for findings tables."""
    return TableStyle(
        [
            ("BACKGROUND", (0, 0), (-1, 0), COLOR_BLUE),
            ("TEXTCOLOR", (0, 0), (-1, 0), COLOR_WHITE),
            ("FONTNAME", (0, 0), (-1, 0), "FiraCode"),
            ("ALIGN", (0, 0), (0, 0), "CENTER"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("FONTSIZE", (0, 0), (-1, -1), 9),
            ("GRID", (0, 0), (-1, -1), 0.1, COLOR_BORDER_GRAY),
            ("LEFTPADDING", (0, 0), (0, 0), 0),
            ("RIGHTPADDING", (0, 0), (0, 0), 0),
            ("TOPPADDING", (0, 0), (-1, -1), PADDING_SMALL),
            ("BOTTOMPADDING", (0, 0), (-1, -1), PADDING_SMALL),
        ]
    )


def _create_pdf_styles() -> dict[str, ParagraphStyle]:
    """
    Create and return PDF paragraph styles used throughout the report.

    Styles are cached on first call to improve performance.

    Returns:
        dict[str, ParagraphStyle]: A dictionary containing the following styles:
            - 'title': Title style with prowler green color
            - 'h1': Heading 1 style with blue color and background
            - 'h2': Heading 2 style with light blue color
            - 'h3': Heading 3 style for sub-headings
            - 'normal': Normal text style with left indent
            - 'normal_center': Normal text style without indent
    """
    global _PDF_STYLES_CACHE

    if _PDF_STYLES_CACHE is not None:
        return _PDF_STYLES_CACHE

    styles = getSampleStyleSheet()

    title_style = ParagraphStyle(
        "CustomTitle",
        parent=styles["Title"],
        fontSize=24,
        textColor=COLOR_PROWLER_DARK_GREEN,
        spaceAfter=20,
        fontName="PlusJakartaSans",
        alignment=TA_CENTER,
    )

    h1 = ParagraphStyle(
        "CustomH1",
        parent=styles["Heading1"],
        fontSize=18,
        textColor=COLOR_BLUE,
        spaceBefore=20,
        spaceAfter=12,
        fontName="PlusJakartaSans",
        leftIndent=0,
        borderWidth=2,
        borderColor=COLOR_BLUE,
        borderPadding=PADDING_LARGE,
        backColor=COLOR_BG_BLUE,
    )

    h2 = ParagraphStyle(
        "CustomH2",
        parent=styles["Heading2"],
        fontSize=14,
        textColor=COLOR_LIGHT_BLUE,
        spaceBefore=15,
        spaceAfter=8,
        fontName="PlusJakartaSans",
        leftIndent=10,
        borderWidth=1,
        borderColor=COLOR_BORDER_GRAY,
        borderPadding=5,
        backColor=COLOR_BG_LIGHT_BLUE,
    )

    h3 = ParagraphStyle(
        "CustomH3",
        parent=styles["Heading3"],
        fontSize=12,
        textColor=COLOR_LIGHTER_BLUE,
        spaceBefore=10,
        spaceAfter=6,
        fontName="PlusJakartaSans",
        leftIndent=20,
    )

    normal = ParagraphStyle(
        "CustomNormal",
        parent=styles["Normal"],
        fontSize=10,
        textColor=COLOR_GRAY,
        spaceBefore=PADDING_SMALL,
        spaceAfter=PADDING_SMALL,
        leftIndent=30,
        fontName="PlusJakartaSans",
    )

    normal_center = ParagraphStyle(
        "CustomNormalCenter",
        parent=styles["Normal"],
        fontSize=10,
        textColor=COLOR_GRAY,
        fontName="PlusJakartaSans",
    )

    _PDF_STYLES_CACHE = {
        "title": title_style,
        "h1": h1,
        "h2": h2,
        "h3": h3,
        "normal": normal,
        "normal_center": normal_center,
    }

    return _PDF_STYLES_CACHE


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
    risk_color = _get_color_for_risk_level(risk_level)
    weight_color = _get_color_for_weight(weight)

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
            COL_WIDTH_SMALL,
            0.6 * inch,
            COL_WIDTH_SMALL,
            0.5 * inch,
            COL_WIDTH_SMALL,
        ],
    )

    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, 0), COLOR_LIGHT_GRAY),
                ("BACKGROUND", (1, 0), (1, 0), risk_color),
                ("TEXTCOLOR", (1, 0), (1, 0), COLOR_WHITE),
                ("FONTNAME", (1, 0), (1, 0), "FiraCode"),
                ("BACKGROUND", (2, 0), (2, 0), COLOR_LIGHT_GRAY),
                ("BACKGROUND", (3, 0), (3, 0), weight_color),
                ("TEXTCOLOR", (3, 0), (3, 0), COLOR_WHITE),
                ("FONTNAME", (3, 0), (3, 0), "FiraCode"),
                ("BACKGROUND", (4, 0), (4, 0), COLOR_LIGHT_GRAY),
                ("BACKGROUND", (5, 0), (5, 0), COLOR_DARK_GRAY),
                ("TEXTCOLOR", (5, 0), (5, 0), COLOR_WHITE),
                ("FONTNAME", (5, 0), (5, 0), "FiraCode"),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("FONTSIZE", (0, 0), (-1, -1), 10),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.black),
                ("LEFTPADDING", (0, 0), (-1, -1), PADDING_MEDIUM),
                ("RIGHTPADDING", (0, 0), (-1, -1), PADDING_MEDIUM),
                ("TOPPADDING", (0, 0), (-1, -1), PADDING_LARGE),
                ("BOTTOMPADDING", (0, 0), (-1, -1), PADDING_LARGE),
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
    status_upper = status.upper()
    if status_upper == "PASS":
        status_color = COLOR_SAFE
    elif status_upper == "FAIL":
        status_color = COLOR_HIGH_RISK
    else:
        status_color = COLOR_DARK_GRAY

    data = [["State:", status_upper]]

    table = Table(data, colWidths=[0.6 * inch, 0.8 * inch])

    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, 0), COLOR_LIGHT_GRAY),
                ("FONTNAME", (0, 0), (0, 0), "PlusJakartaSans"),
                ("BACKGROUND", (1, 0), (1, 0), status_color),
                ("TEXTCOLOR", (1, 0), (1, 0), COLOR_WHITE),
                ("FONTNAME", (1, 0), (1, 0), "FiraCode"),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("FONTSIZE", (0, 0), (-1, -1), 12),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.black),
                ("LEFTPADDING", (0, 0), (-1, -1), PADDING_LARGE),
                ("RIGHTPADDING", (0, 0), (-1, -1), PADDING_LARGE),
                ("TOPPADDING", (0, 0), (-1, -1), PADDING_XLARGE),
                ("BOTTOMPADDING", (0, 0), (-1, -1), PADDING_XLARGE),
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
    nivel_color = _get_ens_nivel_color(nivel)
    data = [[f"Nivel: {nivel.upper()}"]]

    table = Table(data, colWidths=[1.4 * inch])

    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, 0), nivel_color),
                ("TEXTCOLOR", (0, 0), (0, 0), COLOR_WHITE),
                ("FONTNAME", (0, 0), (0, 0), "FiraCode"),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("FONTSIZE", (0, 0), (-1, -1), 11),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.black),
                ("LEFTPADDING", (0, 0), (-1, -1), PADDING_LARGE),
                ("RIGHTPADDING", (0, 0), (-1, -1), PADDING_LARGE),
                ("TOPPADDING", (0, 0), (-1, -1), PADDING_LARGE),
                ("BOTTOMPADDING", (0, 0), (-1, -1), PADDING_LARGE),
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
    icon = TIPO_ICONS.get(tipo_lower, "")

    data = [[f"{icon} {tipo.capitalize()}"]]

    table = Table(data, colWidths=[1.8 * inch])

    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (0, 0), COLOR_ENS_TIPO),
                ("TEXTCOLOR", (0, 0), (0, 0), COLOR_WHITE),
                ("FONTNAME", (0, 0), (0, 0), "PlusJakartaSans"),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("FONTSIZE", (0, 0), (-1, -1), 11),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.black),
                ("LEFTPADDING", (0, 0), (-1, -1), PADDING_LARGE),
                ("RIGHTPADDING", (0, 0), (-1, -1), PADDING_LARGE),
                ("TOPPADDING", (0, 0), (-1, -1), PADDING_LARGE),
                ("BOTTOMPADDING", (0, 0), (-1, -1), PADDING_LARGE),
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
    badges = [
        DIMENSION_MAPPING[dimension.lower()]
        for dimension in dimensiones
        if dimension.lower() in DIMENSION_MAPPING
    ]

    if not badges:
        data = [["N/A"]]
        table = Table(data, colWidths=[1 * inch])
        table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (0, 0), COLOR_LIGHT_GRAY),
                    ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                    ("FONTSIZE", (0, 0), (-1, -1), 10),
                ]
            )
        )
        return table

    data = [[badge[0] for badge in badges]]
    col_widths = [COL_WIDTH_SMALL] * len(badges)

    table = Table(data, colWidths=col_widths)

    styles = [
        ("ALIGN", (0, 0), (-1, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("FONTNAME", (0, 0), (-1, -1), "FiraCode"),
        ("FONTSIZE", (0, 0), (-1, -1), 10),
        ("TEXTCOLOR", (0, 0), (-1, -1), COLOR_WHITE),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.black),
        ("LEFTPADDING", (0, 0), (-1, -1), PADDING_SMALL),
        ("RIGHTPADDING", (0, 0), (-1, -1), PADDING_SMALL),
        ("TOPPADDING", (0, 0), (-1, -1), PADDING_MEDIUM),
        ("BOTTOMPADDING", (0, 0), (-1, -1), PADDING_MEDIUM),
    ]

    for idx, (_, badge_color) in enumerate(badges):
        styles.append(("BACKGROUND", (idx, 0), (idx, 0), badge_color))

    table.setStyle(TableStyle(styles))

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
    # Initialize all expected sections with default values
    sections_data = {
        section: {
            "numerator": 0,
            "denominator": 0,
            "has_findings": False,
        }
        for section in THREATSCORE_SECTIONS
    }

    # Collect data from requirements
    for requirement in requirements_list:
        requirement_id = requirement["id"]
        requirement_attributes = attributes_by_requirement_id.get(requirement_id, {})

        metadata = requirement_attributes.get("attributes", {}).get(
            "req_attributes", []
        )
        if not metadata:
            continue

        m = metadata[0]
        section = _safe_getattr(m, "Section", "Unknown")

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
            risk_level = _safe_getattr(m, "LevelOfRisk", 0)
            weight = _safe_getattr(m, "Weight", 0)

            # Calculate using ThreatScore formula from UI
            rate_i = passed_findings / total_findings
            rfac_i = 1 + 0.25 * risk_level

            sections_data[section]["numerator"] += (
                rate_i * total_findings * weight * rfac_i
            )
            sections_data[section]["denominator"] += total_findings * weight * rfac_i

    # Calculate percentages
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
    sorted_data = sorted(zip(section_names, compliance_percentages), key=lambda x: x[0])
    if not sorted_data:
        section_names, compliance_percentages = [], []
    else:
        section_names, compliance_percentages = zip(*sorted_data)

    # Generate chart
    fig, ax = plt.subplots(figsize=(12, 8))

    # Use helper function for color selection
    colors_list = [_get_chart_color_for_percentage(p) for p in compliance_percentages]

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
    try:
        plt.savefig(buffer, format="png", dpi=300, bbox_inches="tight")
        buffer.seek(0)
    finally:
        plt.close(fig)

    return buffer


def _add_pdf_footer(
    canvas_obj: canvas.Canvas, doc: SimpleDocTemplate, compliance_name: str
) -> None:
    """
    Add footer with page number and branding to each page of the PDF.

    Args:
        canvas_obj (canvas.Canvas): The ReportLab canvas object for drawing.
        doc (SimpleDocTemplate): The document template containing page information.
    """
    canvas_obj.saveState()
    width, height = doc.pagesize
    page_num_text = (
        f"{'Página' if 'ens' in compliance_name.lower() else 'Page'} {doc.page}"
    )
    canvas_obj.setFont("PlusJakartaSans", 9)
    canvas_obj.setFillColorRGB(0.4, 0.4, 0.4)
    canvas_obj.drawString(30, 20, page_num_text)
    powered_text = "Powered by Prowler"
    text_width = canvas_obj.stringWidth(powered_text, "PlusJakartaSans", 9)
    canvas_obj.drawString(width - text_width - 30, 20, powered_text)
    canvas_obj.restoreState()


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
        if not metadata:
            continue

        m = metadata[0]
        marco = _safe_getattr(m, "Marco")
        categoria = _safe_getattr(m, "Categoria")

        key = f"{marco} - {categoria}"
        marco_categoria_data[key]["total"] += 1
        if requirement_status == StatusChoices.PASS:
            marco_categoria_data[key]["passed"] += 1

    # Calculate percentages
    categories = []
    percentages = []

    for category, data in sorted(marco_categoria_data.items()):
        percentage = (data["passed"] / data["total"] * 100) if data["total"] > 0 else 0
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
        try:
            plt.savefig(buffer, format="png", dpi=300, bbox_inches="tight")
            buffer.seek(0)
        finally:
            plt.close(fig)
        return buffer

    # Create horizontal bar chart
    fig, ax = plt.subplots(figsize=(12, max(8, len(categories) * 0.4)))

    # Use helper function for color selection
    colors_list = [_get_chart_color_for_percentage(p) for p in percentages]

    y_pos = range(len(categories))
    bars = ax.barh(y_pos, percentages, color=colors_list)

    ax.set_yticks(y_pos)
    ax.set_yticklabels(categories, fontsize=16)
    ax.set_xlabel("Porcentaje de Cumplimiento (%)", fontsize=14)
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
            fontsize=10,
        )

    ax.grid(True, alpha=0.3, axis="x")
    plt.tight_layout()

    buffer = io.BytesIO()
    try:
        # Render canvas and save explicitly from the figure to avoid state bleed
        fig.canvas.draw()
        fig.savefig(buffer, format="png", dpi=300, bbox_inches="tight")
        buffer.seek(0, io.SEEK_END)
    finally:
        plt.close(fig)

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
    dimension_data = {key: {"passed": 0, "total": 0} for key in DIMENSION_KEYS}

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
        if not metadata:
            continue

        m = metadata[0]
        dimensiones_attr = getattr(m, "Dimensiones", None)
        dimensiones = dimensiones_attr or []
        if isinstance(dimensiones, str):
            dimensiones = [dimensiones]

        for dimension in dimensiones:
            dimension_lower = dimension.lower()
            if dimension_lower in dimension_data:
                dimension_data[dimension_lower]["total"] += 1
                if requirement_status == StatusChoices.PASS:
                    dimension_data[dimension_lower]["passed"] += 1

    # Calculate percentages
    percentages = [
        (
            (dimension_data[key]["passed"] / dimension_data[key]["total"] * 100)
            if dimension_data[key]["total"] > 0
            else 100
        )  # No requirements = 100% (no failures)
        for key in DIMENSION_KEYS
    ]

    # Create radar chart
    num_dims = len(DIMENSION_NAMES)
    angles = [n / float(num_dims) * 2 * 3.14159 for n in range(num_dims)]
    percentages += percentages[:1]
    angles += angles[:1]

    fig, ax = plt.subplots(figsize=(10, 10), subplot_kw=dict(projection="polar"))

    ax.plot(angles, percentages, "o-", linewidth=2, color=CHART_COLOR_BLUE)
    ax.fill(angles, percentages, alpha=0.25, color=CHART_COLOR_BLUE)
    ax.set_xticks(angles[:-1])
    ax.set_xticklabels(DIMENSION_NAMES, fontsize=14)
    ax.set_ylim(0, 100)
    ax.set_yticks([20, 40, 60, 80, 100])
    ax.set_yticklabels(["20%", "40%", "60%", "80%", "100%"], fontsize=12)
    ax.grid(True, alpha=0.3)

    plt.tight_layout()

    buffer = io.BytesIO()
    try:
        fig.canvas.draw()
        fig.savefig(buffer, format="png", dpi=300, bbox_inches="tight")
        buffer.seek(0, io.SEEK_END)
    finally:
        plt.close(fig)

    return buffer


def generate_threatscore_report(
    tenant_id: str,
    scan_id: str,
    compliance_id: str,
    output_path: str,
    provider_id: str,
    only_failed: bool = True,
    min_risk_level: int = 4,
    provider_obj=None,
    requirement_statistics: dict[str, dict[str, int]] | None = None,
    findings_cache: dict[str, list[FindingOutput]] | None = None,
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
        provider_obj (Provider, optional): Pre-fetched Provider object to avoid duplicate queries.
            If None, the provider will be fetched from the database.
        requirement_statistics (dict, optional): Pre-aggregated requirement statistics to avoid
            duplicate database aggregations. If None, statistics will be aggregated from the database.
        findings_cache (dict, optional): Cache of already loaded findings to avoid duplicate queries.
            If None, findings will be loaded from the database. When provided, reduces database
            queries and transformation overhead when generating multiple reports.

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
            # Use provided provider_obj or fetch from database
            if provider_obj is None:
                provider_obj = Provider.objects.get(id=provider_id)

            prowler_provider = initialize_prowler_provider(provider_obj)
            provider_type = provider_obj.provider

            frameworks_bulk = Compliance.get_bulk(provider_type)
            compliance_obj = frameworks_bulk[compliance_id]
            compliance_framework = _safe_getattr(compliance_obj, "Framework")
            compliance_version = _safe_getattr(compliance_obj, "Version")
            compliance_name = _safe_getattr(compliance_obj, "Name")
            compliance_description = _safe_getattr(compliance_obj, "Description", "")

        # Aggregate requirement statistics from database (memory-efficient)
        # Use provided requirement_statistics or fetch from database
        if requirement_statistics is None:
            logger.info(f"Aggregating requirement statistics for scan {scan_id}")
            requirement_statistics_by_check_id = (
                _aggregate_requirement_statistics_from_database(tenant_id, scan_id)
            )
        else:
            logger.info(
                f"Reusing pre-aggregated requirement statistics for scan {scan_id}"
            )
            requirement_statistics_by_check_id = requirement_statistics

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
        info_table = Table(info_data, colWidths=[COL_WIDTH_XLARGE, 4 * inch])
        info_table.setStyle(_create_info_table_style())

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

        compliance_color = _get_color_for_compliance(overall_compliance)

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
            tenant_id, scan_id, check_ids_to_load, prowler_provider, findings_cache
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
        doc.build(
            elements,
            onFirstPage=_add_pdf_footer,
            onLaterPages=_add_pdf_footer,
            compliance_name=compliance_name,
        )
    except Exception as e:
        tb_lineno = e.__traceback__.tb_lineno if e.__traceback__ else "unknown"
        logger.info(f"Error building the document, line {tb_lineno} -- {e}")
        raise e


def _create_nis2_section_chart(
    requirements_list: list[dict], attributes_by_requirement_id: dict
) -> io.BytesIO:
    """
    Create a horizontal bar chart showing compliance percentage by NIS2 section.

    Args:
        requirements_list (list[dict]): List of requirement dictionaries with status and findings data.
        attributes_by_requirement_id (dict): Mapping of requirement IDs to their attributes.

    Returns:
        io.BytesIO: A BytesIO buffer containing the chart image in PNG format.
    """
    # Initialize sections data
    sections_data = defaultdict(lambda: {"passed": 0, "total": 0})

    # Collect data from requirements
    for requirement in requirements_list:
        requirement_id = requirement["id"]
        requirement_attributes = attributes_by_requirement_id.get(requirement_id, {})

        metadata = requirement_attributes.get("attributes", {}).get(
            "req_attributes", []
        )
        if not metadata:
            continue

        m = metadata[0]
        section_full = _safe_getattr(m, "Section", "")

        # Extract section number (e.g., "1" from "1 POLICY ON...")
        section_number = section_full.split()[0] if section_full else "Unknown"

        # Get findings data
        passed_findings = requirement["attributes"].get("passed_findings", 0)
        total_findings = requirement["attributes"].get("total_findings", 0)

        if total_findings > 0:
            sections_data[section_number]["passed"] += passed_findings
            sections_data[section_number]["total"] += total_findings

    # Calculate percentages and prepare data for chart
    section_names = []
    compliance_percentages = []

    # Get section titles for display
    section_titles = {
        "1": "1. Policy on Security",
        "2": "2. Risk Management",
        "3": "3. Incident Handling",
        "4": "4. Business Continuity",
        "5": "5. Supply Chain",
        "6": "6. Acquisition & Dev",
        "7": "7. Effectiveness",
        "9": "9. Cryptography",
        "11": "11. Access Control",
        "12": "12. Asset Management",
    }

    # Sort by section number
    for section_num in sorted(
        sections_data.keys(), key=lambda x: int(x) if x.isdigit() else 999
    ):
        data = sections_data[section_num]
        if data["total"] > 0:
            compliance_percentage = (data["passed"] / data["total"]) * 100
        else:
            compliance_percentage = 100  # No findings = 100% (PASS)

        section_title = section_titles.get(section_num, f"{section_num}. Unknown")
        section_names.append(section_title)
        compliance_percentages.append(compliance_percentage)

    # Generate horizontal bar chart
    fig, ax = plt.subplots(figsize=(10, 8))

    # Use color helper for compliance percentage
    colors_list = [_get_chart_color_for_percentage(p) for p in compliance_percentages]

    bars = ax.barh(section_names, compliance_percentages, color=colors_list)

    ax.set_xlabel("Compliance (%)", fontsize=12)
    ax.set_xlim(0, 100)

    # Add percentage labels
    for bar, percentage in zip(bars, compliance_percentages):
        width = bar.get_width()
        ax.text(
            width + 1,
            bar.get_y() + bar.get_height() / 2.0,
            f"{percentage:.1f}%",
            ha="left",
            va="center",
            fontweight="bold",
        )

    ax.grid(True, alpha=0.3, axis="x")
    plt.tight_layout()

    buffer = io.BytesIO()
    try:
        fig.canvas.draw()
        fig.savefig(buffer, format="png", dpi=300, bbox_inches="tight")
        buffer.seek(0, io.SEEK_END)
    finally:
        plt.close(fig)

    return buffer


def _create_nis2_subsection_table(
    requirements_list: list[dict], attributes_by_requirement_id: dict
) -> Table:
    """
    Create a table showing compliance by subsection.

    Args:
        requirements_list (list[dict]): List of requirement dictionaries.
        attributes_by_requirement_id (dict): Mapping of requirement IDs to their attributes.

    Returns:
        Table: A ReportLab table showing subsection breakdown.
    """
    # Collect data by subsection
    subsections_data = defaultdict(lambda: {"passed": 0, "failed": 0, "manual": 0})

    for requirement in requirements_list:
        requirement_id = requirement["id"]
        requirement_attributes = attributes_by_requirement_id.get(requirement_id, {})

        metadata = requirement_attributes.get("attributes", {}).get(
            "req_attributes", []
        )
        if not metadata:
            continue

        m = metadata[0]
        subsection = _safe_getattr(m, "SubSection", "Unknown")
        status = requirement["attributes"].get("status", StatusChoices.MANUAL)

        if status == StatusChoices.PASS:
            subsections_data[subsection]["passed"] += 1
        elif status == StatusChoices.FAIL:
            subsections_data[subsection]["failed"] += 1
        else:
            subsections_data[subsection]["manual"] += 1

    # Create table data
    table_data = [["SubSection", "Total", "Pass", "Fail", "Manual", "Compliance %"]]

    for subsection in sorted(subsections_data.keys()):
        data = subsections_data[subsection]
        total = data["passed"] + data["failed"] + data["manual"]
        compliance = (
            (data["passed"] / (data["passed"] + data["failed"]) * 100)
            if (data["passed"] + data["failed"]) > 0
            else 100
        )

        if len(subsection) > 100:
            subsection = subsection[:80] + "..."

        table_data.append(
            [
                subsection,  # No truncate - let it wrap naturally
                str(total),
                str(data["passed"]),
                str(data["failed"]),
                str(data["manual"]),
                f"{compliance:.1f}%",
            ]
        )

    # Create table with wider SubSection column
    table = Table(
        table_data,
        colWidths=[
            4.5 * inch,
            0.6 * inch,
            0.6 * inch,
            0.6 * inch,
            0.7 * inch,
            1 * inch,
        ],
    )
    table.setStyle(
        TableStyle(
            [
                ("BACKGROUND", (0, 0), (-1, 0), COLOR_NIS2_PRIMARY),
                ("TEXTCOLOR", (0, 0), (-1, 0), COLOR_WHITE),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("ALIGN", (0, 1), (0, -1), "LEFT"),
                ("FONTNAME", (0, 0), (-1, 0), "PlusJakartaSans"),
                ("FONTSIZE", (0, 0), (-1, 0), 10),
                ("FONTSIZE", (0, 1), (-1, -1), 9),
                ("BOTTOMPADDING", (0, 0), (-1, 0), 8),
                ("TOPPADDING", (0, 0), (-1, 0), 8),
                ("GRID", (0, 0), (-1, -1), 0.5, COLOR_BORDER_GRAY),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [COLOR_WHITE, COLOR_NIS2_BG_BLUE]),
            ]
        )
    )

    return table


def _create_nis2_requirements_index(
    requirements_list: list[dict], attributes_by_requirement_id: dict, h2, h3, normal
) -> list:
    """
    Create a hierarchical requirements index organized by Section and SubSection.

    Args:
        requirements_list (list[dict]): List of requirement dictionaries.
        attributes_by_requirement_id (dict): Mapping of requirement IDs to their attributes.
        h2, h3, normal: Paragraph styles.

    Returns:
        list: List of ReportLab elements for the index.
    """
    elements = []

    # Organize requirements by section and subsection
    sections_hierarchy = defaultdict(lambda: defaultdict(list))

    for requirement in requirements_list:
        requirement_id = requirement["id"]
        requirement_attributes = attributes_by_requirement_id.get(requirement_id, {})

        metadata = requirement_attributes.get("attributes", {}).get(
            "req_attributes", []
        )
        if not metadata:
            continue

        m = metadata[0]
        section = _safe_getattr(m, "Section", "Unknown")
        subsection = _safe_getattr(m, "SubSection", "Unknown")
        status = requirement["attributes"].get("status", StatusChoices.MANUAL)

        # Status indicator
        if status == StatusChoices.PASS:
            status_indicator = "✓"
        elif status == StatusChoices.FAIL:
            status_indicator = "✗"
        else:
            status_indicator = "⊙"

        description = requirement["attributes"].get(
            "description", "No description available"
        )
        sections_hierarchy[section][subsection].append(
            {
                "id": requirement_id,
                "description": (
                    description[:100] + "..." if len(description) > 100 else description
                ),
                "status_indicator": status_indicator,
            }
        )

    # Build the index
    for section in sorted(sections_hierarchy.keys()):
        # Section header
        elements.append(Paragraph(section, h2))

        subsections = sections_hierarchy[section]
        for subsection in sorted(subsections.keys()):
            # Subsection header
            elements.append(Paragraph(f"  {subsection}", h3))

            # Requirements
            for req in subsections[subsection]:
                req_text = (
                    f"    {req['status_indicator']} {req['id']} - {req['description']}"
                )
                elements.append(Paragraph(req_text, normal))

        elements.append(Spacer(1, 0.1 * inch))

    return elements


def generate_ens_report(
    tenant_id: str,
    scan_id: str,
    compliance_id: str,
    output_path: str,
    provider_id: str,
    include_manual: bool = True,
    provider_obj=None,
    requirement_statistics: dict[str, dict[str, int]] | None = None,
    findings_cache: dict[str, list[FindingOutput]] | None = None,
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
        provider_obj (Provider, optional): Pre-fetched Provider object to avoid duplicate queries.
            If None, the provider will be fetched from the database.
        requirement_statistics (dict, optional): Pre-aggregated requirement statistics to avoid
            duplicate database aggregations. If None, statistics will be aggregated from the database.
        findings_cache (dict, optional): Cache of already loaded findings to avoid duplicate queries.
            If None, findings will be loaded from the database. When provided, reduces database
            queries and transformation overhead when generating multiple reports.

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
            # Use provided provider_obj or fetch from database
            if provider_obj is None:
                provider_obj = Provider.objects.get(id=provider_id)

            prowler_provider = initialize_prowler_provider(provider_obj)
            provider_type = provider_obj.provider

            frameworks_bulk = Compliance.get_bulk(provider_type)
            compliance_obj = frameworks_bulk[compliance_id]
            compliance_framework = _safe_getattr(compliance_obj, "Framework")
            compliance_version = _safe_getattr(compliance_obj, "Version")
            compliance_name = _safe_getattr(compliance_obj, "Name")
            compliance_description = _safe_getattr(compliance_obj, "Description", "")

        # Aggregate requirement statistics from database (memory-efficient)
        # Use provided requirement_statistics or fetch from database
        if requirement_statistics is None:
            logger.info(f"Aggregating requirement statistics for scan {scan_id}")
            requirement_statistics_by_check_id = (
                _aggregate_requirement_statistics_from_database(tenant_id, scan_id)
            )
        else:
            logger.info(
                f"Reusing pre-aggregated requirement statistics for scan {scan_id}"
            )
            requirement_statistics_by_check_id = requirement_statistics

        # Calculate requirements data using aggregated statistics
        attributes_by_requirement_id, requirements_list = (
            _calculate_requirements_data_from_statistics(
                compliance_obj, requirement_statistics_by_check_id
            )
        )

        # Count manual requirements before filtering
        manual_requirements_count = sum(
            1
            for req in requirements_list
            if req["attributes"]["status"] == StatusChoices.MANUAL
        )
        total_requirements_count = len(requirements_list)

        # Filter out manual requirements for the report
        requirements_list = [
            req
            for req in requirements_list
            if req["attributes"]["status"] != StatusChoices.MANUAL
        ]

        logger.info(
            f"Filtered {manual_requirements_count} manual requirements out of {total_requirements_count} total requirements"
        )

        # Initialize PDF document
        doc = SimpleDocTemplate(
            output_path,
            pagesize=letter,
            title="Informe de Cumplimiento ENS - Prowler",
            author="Prowler",
            subject=f"Informe de Cumplimiento para {compliance_framework}",
            creator="Prowler Engineering Team",
            keywords=f"compliance,{compliance_framework},security,ens,prowler",
        )

        elements = []

        # SECTION 1: PORTADA (Cover Page)
        # Create logos side by side
        prowler_logo_path = os.path.join(
            os.path.dirname(__file__), "../assets/img/prowler_logo.png"
        )
        ens_logo_path = os.path.join(
            os.path.dirname(__file__), "../assets/img/ens_logo.png"
        )

        prowler_logo = Image(
            prowler_logo_path,
            width=3.5 * inch,
            height=0.7 * inch,
        )
        ens_logo = Image(
            ens_logo_path,
            width=1.5 * inch,
            height=2 * inch,
        )

        # Create table with both logos
        logos_table = Table(
            [[prowler_logo, ens_logo]], colWidths=[4 * inch, 2.5 * inch]
        )
        logos_table.setStyle(
            TableStyle(
                [
                    ("ALIGN", (0, 0), (0, 0), "LEFT"),
                    ("ALIGN", (1, 0), (1, 0), "RIGHT"),
                    ("VALIGN", (0, 0), (0, 0), "MIDDLE"),  # Prowler logo middle
                    ("VALIGN", (1, 0), (1, 0), "TOP"),  # ENS logo top
                ]
            )
        )
        elements.append(logos_table)
        elements.append(Spacer(1, 0.3 * inch))
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
        elements.append(Spacer(1, 0.5 * inch))

        # Add warning about excluded manual requirements
        warning_text = (
            f"<b>AVISO:</b> Este informe no incluye los requisitos de ejecución manual. "
            f"El compliance <b>{compliance_id}</b> contiene un total de "
            f"<b>{manual_requirements_count} requisitos manuales</b> que no han sido evaluados "
            f"automáticamente y por tanto no están reflejados en las estadísticas de este reporte. "
            f"El análisis se basa únicamente en los <b>{len(requirements_list)} requisitos automatizados</b>."
        )
        warning_paragraph = Paragraph(warning_text, normal)
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

        # Add legend explaining ENS values
        elements.append(Paragraph("Leyenda de Valores ENS", h2))
        elements.append(Spacer(1, 0.2 * inch))

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
        <b>Modo de Ejecución:</b><br/>
        • <b>Automático:</b> El requisito puede verificarse automáticamente mediante escaneo<br/>
        • <b>Manual:</b> Requiere verificación manual por parte de un auditor<br/>
        <br/>
        <b>Dimensiones de Seguridad:</b><br/>
        • <b>C (Confidencialidad):</b> Protección contra accesos no autorizados a la información<br/>
        • <b>I (Integridad):</b> Garantía de exactitud y completitud de la información<br/>
        • <b>T (Trazabilidad):</b> Capacidad de rastrear acciones y eventos<br/>
        • <b>A (Autenticidad):</b> Verificación de identidad de usuarios y sistemas<br/>
        • <b>D (Disponibilidad):</b> Acceso a la información cuando se necesita<br/>
        <br/>
        <b>Estados de Cumplimiento:</b><br/>
        • <b>CUMPLE (PASS):</b> El requisito se cumple satisfactoriamente<br/>
        • <b>NO CUMPLE (FAIL):</b> El requisito no se cumple y requiere corrección<br/>
        • <b>MANUAL:</b> Requiere revisión manual para determinar cumplimiento
        """
        legend_paragraph = Paragraph(legend_text, normal)
        legend_table = Table([[legend_paragraph]], colWidths=[6.5 * inch])
        legend_table.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (0, 0), colors.Color(0.95, 0.97, 1.0)),
                    ("TEXTCOLOR", (0, 0), (0, 0), colors.Color(0.2, 0.2, 0.2)),
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
        elements.append(legend_table)
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
                    ("BACKGROUND", (0, 3), (0, 3), colors.Color(0.4, 0.4, 0.4)),
                    ("TEXTCOLOR", (0, 3), (0, 3), colors.white),
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
            if not metadata:
                continue

            m = metadata[0]
            nivel = _safe_getattr(m, "Nivel")
            nivel_data[nivel]["total"] += 1
            if requirement_status == StatusChoices.PASS:
                nivel_data[nivel]["passed"] += 1

        elements.append(Paragraph("Cumplimiento por Nivel", h2))
        nivel_table_data = [["Nivel", "Cumplidos", "Total", "Porcentaje"]]
        for nivel in ENS_NIVEL_ORDER:
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
            if not metadata:
                continue

            m = metadata[0]
            tipo = _safe_getattr(m, "Tipo")
            tipo_data[tipo]["total"] += 1
            if requirement_status == StatusChoices.PASS:
                tipo_data[tipo]["passed"] += 1

        tipo_table_data = [["Tipo", "Cumplidos", "Total", "Porcentaje"]]
        for tipo in ENS_TIPO_ORDER:
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

        # SECTION 6: REQUISITOS CRÍTICOS NO CUMPLIDOS (Critical Failed Requirements)
        elements.append(Paragraph("Requisitos Críticos No Cumplidos", h1))
        elements.append(Spacer(1, 0.2 * inch))

        critical_failed = []
        for requirement in requirements_list:
            requirement_status = requirement["attributes"]["status"]
            if requirement_status == StatusChoices.FAIL:
                requirement_id = requirement["id"]
                req_attributes = attributes_by_requirement_id.get(
                    requirement_id, {}
                ).get("attributes", {})
                metadata_list = req_attributes.get("req_attributes", [])
                if metadata_list:
                    metadata = metadata_list[0]
                    nivel = _safe_getattr(metadata, "Nivel", "")
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

            critical_table_data = [["ID", "Descripción", "Marco", "Categoría"]]
            for item in critical_failed:
                requirement_id = item["requirement"]["id"]
                description = item["requirement"]["attributes"]["description"]
                marco = _safe_getattr(item["metadata"], "Marco")
                categoria = _safe_getattr(item["metadata"], "Categoria")

                if len(description) > 60:
                    description = description[:57] + "..."

                critical_table_data.append(
                    [requirement_id, description, marco, categoria]
                )

            critical_table = Table(
                critical_table_data,
                colWidths=[1.5 * inch, 3.3 * inch, 1.5 * inch, 2 * inch],
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

        # SECTION 7: ÍNDICE DE REQUISITOS (Requirements Index)
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

        # SECTION 8: DETALLE DE REQUISITOS (Detailed Requirements)
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
                tenant_id, scan_id, check_ids_to_load, prowler_provider, findings_cache
            )

            for requirement in filtered_requirements:
                requirement_id = requirement["id"]
                requirement_attributes = attributes_by_requirement_id.get(
                    requirement_id, {}
                )
                requirement_status = requirement["attributes"]["status"]
                requirement_description = requirement_attributes.get("description", "")

                # Requirement ID header in a box
                req_id_paragraph = Paragraph(requirement_id, h2)
                req_id_table = Table([[req_id_paragraph]], colWidths=[6.5 * inch])
                req_id_table.setStyle(
                    TableStyle(
                        [
                            (
                                "BACKGROUND",
                                (0, 0),
                                (0, 0),
                                colors.Color(0.15, 0.35, 0.55),
                            ),
                            ("TEXTCOLOR", (0, 0), (0, 0), colors.white),
                            ("ALIGN", (0, 0), (0, 0), "CENTER"),
                            ("VALIGN", (0, 0), (0, 0), "MIDDLE"),
                            ("LEFTPADDING", (0, 0), (-1, -1), 15),
                            ("RIGHTPADDING", (0, 0), (-1, -1), 15),
                            ("TOPPADDING", (0, 0), (-1, -1), 10),
                            ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
                            ("BOX", (0, 0), (-1, -1), 2, colors.Color(0.2, 0.4, 0.6)),
                        ]
                    )
                )
                elements.append(req_id_table)
                elements.append(Spacer(1, 0.15 * inch))

                metadata = requirement_attributes.get("attributes", {}).get(
                    "req_attributes", []
                )
                if metadata and len(metadata) > 0:
                    m = metadata[0]

                    # Create all badges
                    status_component = _create_status_component(requirement_status)
                    nivel = getattr(m, "Nivel", "N/A")
                    nivel_badge = _create_ens_nivel_badge(nivel)
                    tipo = getattr(m, "Tipo", "N/A")
                    tipo_badge = _create_ens_tipo_badge(tipo)

                    # Organize badges in a horizontal table (2 rows x 2 cols)
                    badges_table = Table(
                        [[status_component, nivel_badge], [tipo_badge]],
                        colWidths=[3.25 * inch, 3.25 * inch],
                    )
                    badges_table.setStyle(
                        TableStyle(
                            [
                                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                                ("LEFTPADDING", (0, 0), (-1, -1), 5),
                                ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                                ("TOPPADDING", (0, 0), (-1, -1), 5),
                                ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                            ]
                        )
                    )
                    elements.append(badges_table)
                    elements.append(Spacer(1, 0.15 * inch))

                    # Dimensiones badges (if present)
                    dimensiones = getattr(m, "Dimensiones", [])
                    if dimensiones:
                        dim_label = Paragraph("<b>Dimensiones:</b>", normal)
                        dim_badges = _create_ens_dimension_badges(dimensiones)
                        dim_table = Table(
                            [[dim_label, dim_badges]], colWidths=[1.5 * inch, 5 * inch]
                        )
                        dim_table.setStyle(
                            TableStyle(
                                [
                                    ("ALIGN", (0, 0), (0, 0), "LEFT"),
                                    ("ALIGN", (1, 0), (1, 0), "LEFT"),
                                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                                ]
                            )
                        )
                        elements.append(dim_table)
                        elements.append(Spacer(1, 0.15 * inch))

                    # Requirement details in a clean table
                    details_data = [
                        ["Descripción:", Paragraph(requirement_description, normal)],
                        ["Marco:", Paragraph(getattr(m, "Marco", "N/A"), normal)],
                        [
                            "Categoría:",
                            Paragraph(getattr(m, "Categoria", "N/A"), normal),
                        ],
                        [
                            "ID Grupo Control:",
                            Paragraph(getattr(m, "IdGrupoControl", "N/A"), normal),
                        ],
                        [
                            "Descripción del Control:",
                            Paragraph(getattr(m, "DescripcionControl", "N/A"), normal),
                        ],
                    ]
                    details_table = Table(
                        details_data, colWidths=[2.2 * inch, 4.5 * inch]
                    )
                    details_table.setStyle(
                        TableStyle(
                            [
                                (
                                    "BACKGROUND",
                                    (0, 0),
                                    (0, -1),
                                    colors.Color(0.9, 0.93, 0.96),
                                ),
                                (
                                    "TEXTCOLOR",
                                    (0, 0),
                                    (0, -1),
                                    colors.Color(0.2, 0.2, 0.2),
                                ),
                                ("FONTNAME", (0, 0), (0, -1), "FiraCode"),
                                ("FONTSIZE", (0, 0), (-1, -1), 10),
                                ("ALIGN", (0, 0), (0, -1), "LEFT"),
                                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                                (
                                    "GRID",
                                    (0, 0),
                                    (-1, -1),
                                    0.5,
                                    colors.Color(0.7, 0.8, 0.9),
                                ),
                                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                                ("TOPPADDING", (0, 0), (-1, -1), 6),
                                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                            ]
                        )
                    )
                    elements.append(details_table)
                    elements.append(Spacer(1, 0.2 * inch))

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
        logger.info("Building PDF...")
        doc.build(elements, onFirstPage=_add_pdf_footer, onLaterPages=_add_pdf_footer)
    except Exception as e:
        tb_lineno = e.__traceback__.tb_lineno if e.__traceback__ else "unknown"
        logger.error(f"Error building ENS report, line {tb_lineno} -- {e}")
        raise e


def generate_nis2_report(
    tenant_id: str,
    scan_id: str,
    compliance_id: str,
    output_path: str,
    provider_id: str,
    only_failed: bool = True,
    include_manual: bool = False,
    provider_obj=None,
    requirement_statistics: dict[str, dict[str, int]] | None = None,
    findings_cache: dict[str, list[FindingOutput]] | None = None,
) -> None:
    """
    Generate a PDF compliance report for NIS2 Directive (EU) 2022/2555.

    This function creates a comprehensive PDF report containing:
    - Compliance overview and metadata
    - Executive summary with overall compliance score
    - Section analysis with horizontal bar chart
    - SubSection breakdown table
    - Critical failed requirements
    - Requirements index organized by section and subsection
    - Detailed findings for failed requirements

    Args:
        tenant_id (str): The tenant ID for Row-Level Security context.
        scan_id (str): ID of the scan executed by Prowler.
        compliance_id (str): ID of the compliance framework (e.g., "nis2_aws").
        output_path (str): Output PDF file path (e.g., "/tmp/nis2_report.pdf").
        provider_id (str): Provider ID for the scan.
        only_failed (bool): If True, only requirements with status "FAIL" will be included
            in the detailed requirements section. Defaults to True.
        include_manual (bool): If True, includes MANUAL requirements in the detailed findings
            section along with FAIL requirements. Defaults to True.
        provider_obj (Provider, optional): Pre-fetched Provider object to avoid duplicate queries.
            If None, the provider will be fetched from the database.
        requirement_statistics (dict, optional): Pre-aggregated requirement statistics to avoid
            duplicate database aggregations. If None, statistics will be aggregated from the database.
        findings_cache (dict, optional): Cache of already loaded findings to avoid duplicate queries.
            If None, findings will be loaded from the database.

    Raises:
        Exception: If any error occurs during PDF generation, it will be logged and re-raised.
    """
    logger.info(
        f"Generating NIS2 report for scan {scan_id} with provider {provider_id}"
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
            # Use provided provider_obj or fetch from database
            if provider_obj is None:
                provider_obj = Provider.objects.get(id=provider_id)

            prowler_provider = initialize_prowler_provider(provider_obj)
            provider_type = provider_obj.provider

            frameworks_bulk = Compliance.get_bulk(provider_type)
            compliance_obj = frameworks_bulk[compliance_id]
            compliance_framework = _safe_getattr(compliance_obj, "Framework")
            compliance_version = _safe_getattr(compliance_obj, "Version")
            compliance_name = _safe_getattr(compliance_obj, "Name")
            compliance_description = _safe_getattr(compliance_obj, "Description", "")

        # Aggregate requirement statistics from database
        if requirement_statistics is None:
            logger.info(f"Aggregating requirement statistics for scan {scan_id}")
            requirement_statistics_by_check_id = (
                _aggregate_requirement_statistics_from_database(tenant_id, scan_id)
            )
        else:
            logger.info(
                f"Reusing pre-aggregated requirement statistics for scan {scan_id}"
            )
            requirement_statistics_by_check_id = requirement_statistics

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
            title="NIS2 Compliance Report - Prowler",
            author="Prowler",
            subject=f"Compliance Report for {compliance_framework}",
            creator="Prowler Engineering Team",
            keywords=f"compliance,{compliance_framework},security,nis2,prowler,eu",
        )

        elements = []

        # SECTION 1: Cover Page
        # Create logos side by side
        prowler_logo_path = os.path.join(
            os.path.dirname(__file__), "../assets/img/prowler_logo.png"
        )
        nis2_logo_path = os.path.join(
            os.path.dirname(__file__), "../assets/img/nis2_logo.png"
        )

        prowler_logo = Image(
            prowler_logo_path,
            width=3.5 * inch,
            height=0.7 * inch,
        )
        nis2_logo = Image(
            nis2_logo_path,
            width=2.3 * inch,
            height=1.5 * inch,
        )

        # Create table with both logos
        logos_table = Table(
            [[prowler_logo, nis2_logo]], colWidths=[4 * inch, 2.5 * inch]
        )
        logos_table.setStyle(
            TableStyle(
                [
                    ("ALIGN", (0, 0), (0, 0), "LEFT"),
                    ("ALIGN", (1, 0), (1, 0), "RIGHT"),
                    ("VALIGN", (0, 0), (0, 0), "MIDDLE"),  # Prowler logo middle
                    ("VALIGN", (1, 0), (1, 0), "MIDDLE"),  # NIS2 logo middle
                ]
            )
        )
        elements.append(logos_table)
        elements.append(Spacer(1, 0.3 * inch))

        # Title
        title = Paragraph(
            "NIS2 Compliance Report<br/>Directive (EU) 2022/2555",
            title_style,
        )
        elements.append(title)
        elements.append(Spacer(1, 0.3 * inch))

        # Compliance metadata table
        metadata_data = [
            ["Framework:", compliance_framework],
            ["Name:", Paragraph(compliance_name, normal_center)],
            ["Version:", compliance_version or "N/A"],
            ["Provider:", provider_type.upper()],
            ["Scan ID:", scan_id],
            ["Description:", Paragraph(compliance_description, normal_center)],
        ]

        metadata_table = Table(metadata_data, colWidths=[COL_WIDTH_XLARGE, 4 * inch])
        metadata_table.setStyle(_create_info_table_style())
        elements.append(metadata_table)
        elements.append(PageBreak())

        # SECTION 2: Executive Summary
        elements.append(Paragraph("Executive Summary", h1))
        elements.append(Spacer(1, 0.1 * inch))

        # Calculate overall statistics
        total_requirements = len(requirements_list)
        passed_requirements = sum(
            1
            for req in requirements_list
            if req["attributes"].get("status") == StatusChoices.PASS
        )
        failed_requirements = sum(
            1
            for req in requirements_list
            if req["attributes"].get("status") == StatusChoices.FAIL
        )
        manual_requirements = sum(
            1
            for req in requirements_list
            if req["attributes"].get("status") == StatusChoices.MANUAL
        )

        overall_compliance = (
            (passed_requirements / (passed_requirements + failed_requirements) * 100)
            if (passed_requirements + failed_requirements) > 0
            else 100
        )

        # Summary statistics table
        summary_data = [
            ["Metric", "Value"],
            ["Total Requirements", str(total_requirements)],
            ["Passed ✓", str(passed_requirements)],
            ["Failed ✗", str(failed_requirements)],
            ["Manual ⊙", str(manual_requirements)],
            ["Overall Compliance", f"{overall_compliance:.1f}%"],
        ]

        summary_table = Table(summary_data, colWidths=[3 * inch, 2 * inch])
        summary_table.setStyle(
            TableStyle(
                [
                    # Header row
                    ("BACKGROUND", (0, 0), (-1, 0), COLOR_NIS2_PRIMARY),
                    ("TEXTCOLOR", (0, 0), (-1, 0), COLOR_WHITE),
                    # Status-specific colors for left column
                    ("BACKGROUND", (0, 2), (0, 2), COLOR_SAFE),  # Passed row
                    ("TEXTCOLOR", (0, 2), (0, 2), COLOR_WHITE),
                    ("BACKGROUND", (0, 3), (0, 3), COLOR_HIGH_RISK),  # Failed row
                    ("TEXTCOLOR", (0, 3), (0, 3), COLOR_WHITE),
                    ("BACKGROUND", (0, 4), (0, 4), COLOR_DARK_GRAY),  # Manual row
                    ("TEXTCOLOR", (0, 4), (0, 4), COLOR_WHITE),
                    # General styling
                    ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                    ("FONTNAME", (0, 0), (-1, 0), "PlusJakartaSans"),
                    ("FONTSIZE", (0, 0), (-1, 0), 12),
                    ("FONTSIZE", (0, 1), (-1, -1), 10),
                    ("BOTTOMPADDING", (0, 0), (-1, 0), 10),
                    ("GRID", (0, 0), (-1, -1), 0.5, COLOR_BORDER_GRAY),
                    # Alternating backgrounds for right column
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
        elements.append(PageBreak())

        # SECTION 3: Compliance by Section Analysis
        elements.append(Paragraph("Compliance by Section", h1))
        elements.append(Spacer(1, 0.1 * inch))

        elements.append(
            Paragraph(
                "The following chart shows compliance percentage for each main section of the NIS2 directive:",
                normal_center,
            )
        )
        elements.append(Spacer(1, 0.1 * inch))

        # Create section chart
        section_chart_buffer = _create_nis2_section_chart(
            requirements_list, attributes_by_requirement_id
        )
        section_chart_buffer.seek(0)
        section_chart = Image(section_chart_buffer, width=6.5 * inch, height=5 * inch)
        elements.append(section_chart)
        elements.append(PageBreak())

        # SECTION 4: SubSection Breakdown
        elements.append(Paragraph("SubSection Breakdown", h1))
        elements.append(Spacer(1, 0.1 * inch))

        subsection_table = _create_nis2_subsection_table(
            requirements_list, attributes_by_requirement_id
        )
        elements.append(subsection_table)
        elements.append(PageBreak())

        # SECTION 5: Requirements Index
        elements.append(Paragraph("Requirements Index", h1))
        elements.append(Spacer(1, 0.1 * inch))

        index_elements = _create_nis2_requirements_index(
            requirements_list, attributes_by_requirement_id, h2, h3, normal
        )
        elements.extend(index_elements)
        elements.append(PageBreak())

        # SECTION 6: Detailed Findings
        elements.append(Paragraph("Detailed Findings", h1))
        elements.append(Spacer(1, 0.2 * inch))

        # Filter requirements for detailed findings (FAIL + MANUAL if include_manual)
        filtered_requirements = [
            req
            for req in requirements_list
            if req["attributes"]["status"] == StatusChoices.FAIL
            or (include_manual and req["attributes"]["status"] == StatusChoices.MANUAL)
        ]

        if not filtered_requirements:
            elements.append(
                Paragraph("✅ All automatic requirements are compliant.", normal)
            )
        else:
            elements.append(
                Paragraph(
                    f"Showing {len(filtered_requirements)} requirements that need attention:",
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
                f"Loading findings on-demand for {len(filtered_requirements)} NIS2 requirements"
            )
            findings_by_check_id = _load_findings_for_requirement_checks(
                tenant_id, scan_id, check_ids_to_load, prowler_provider, findings_cache
            )

            for requirement in filtered_requirements:
                requirement_id = requirement["id"]
                requirement_attributes = attributes_by_requirement_id.get(
                    requirement_id, {}
                )
                requirement_status = requirement["attributes"]["status"]
                requirement_description = requirement_attributes.get("description", "")

                # Requirement ID header in a box
                req_id_paragraph = Paragraph(f"Requirement: {requirement_id}", h2)
                req_id_table = Table([[req_id_paragraph]], colWidths=[6.5 * inch])
                req_id_table.setStyle(
                    TableStyle(
                        [
                            ("BACKGROUND", (0, 0), (0, 0), COLOR_NIS2_PRIMARY),
                            ("TEXTCOLOR", (0, 0), (0, 0), colors.white),
                            ("ALIGN", (0, 0), (0, 0), "CENTER"),
                            ("VALIGN", (0, 0), (0, 0), "MIDDLE"),
                            ("LEFTPADDING", (0, 0), (-1, -1), 15),
                            ("RIGHTPADDING", (0, 0), (-1, -1), 15),
                            ("TOPPADDING", (0, 0), (-1, -1), 10),
                            ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
                            ("BOX", (0, 0), (-1, -1), 2, COLOR_NIS2_SECONDARY),
                        ]
                    )
                )
                elements.append(req_id_table)
                elements.append(Spacer(1, 0.15 * inch))

                metadata = requirement_attributes.get("attributes", {}).get(
                    "req_attributes", []
                )
                if metadata:
                    m = metadata[0]
                    section = _safe_getattr(m, "Section", "Unknown")
                    subsection = _safe_getattr(m, "SubSection", "Unknown")
                    service = _safe_getattr(m, "Service", "generic")

                    # Status badge
                    status_text = (
                        "✓ PASS"
                        if requirement_status == StatusChoices.PASS
                        else (
                            "✗ FAIL"
                            if requirement_status == StatusChoices.FAIL
                            else "⊙ MANUAL"
                        )
                    )
                    status_color = (
                        COLOR_SAFE
                        if requirement_status == StatusChoices.PASS
                        else (
                            COLOR_HIGH_RISK
                            if requirement_status == StatusChoices.FAIL
                            else COLOR_DARK_GRAY
                        )
                    )

                    status_badge = Paragraph(
                        f"<b>{status_text}</b>",
                        ParagraphStyle(
                            "status_badge",
                            parent=normal,
                            alignment=1,
                            textColor=colors.white,
                            fontSize=14,
                        ),
                    )
                    status_table = Table([[status_badge]], colWidths=[6.5 * inch])
                    status_table.setStyle(
                        TableStyle(
                            [
                                ("BACKGROUND", (0, 0), (0, 0), status_color),
                                ("ALIGN", (0, 0), (0, 0), "CENTER"),
                                ("VALIGN", (0, 0), (0, 0), "MIDDLE"),
                                ("TOPPADDING", (0, 0), (-1, -1), 8),
                                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                            ]
                        )
                    )
                    elements.append(status_table)
                    elements.append(Spacer(1, 0.15 * inch))

                    # Requirement details table
                    details_data = [
                        [
                            "Description:",
                            Paragraph(requirement_description, normal_center),
                        ],
                        ["Section:", Paragraph(section, normal_center)],
                        ["SubSection:", Paragraph(subsection, normal_center)],
                        ["Service:", service],
                    ]
                    details_table = Table(
                        details_data, colWidths=[2.2 * inch, 4.5 * inch]
                    )
                    details_table.setStyle(
                        TableStyle(
                            [
                                (
                                    "BACKGROUND",
                                    (0, 0),
                                    (0, -1),
                                    COLOR_NIS2_BG_BLUE,
                                ),
                                ("TEXTCOLOR", (0, 0), (0, -1), COLOR_GRAY),
                                ("FONTNAME", (0, 0), (0, -1), "FiraCode"),
                                ("FONTSIZE", (0, 0), (-1, -1), 10),
                                ("ALIGN", (0, 0), (0, -1), "LEFT"),
                                ("VALIGN", (0, 0), (-1, -1), "TOP"),
                                ("GRID", (0, 0), (-1, -1), 0.5, COLOR_BORDER_GRAY),
                                ("LEFTPADDING", (0, 0), (-1, -1), 8),
                                ("RIGHTPADDING", (0, 0), (-1, -1), 8),
                                ("TOPPADDING", (0, 0), (-1, -1), 6),
                                ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                            ]
                        )
                    )
                    elements.append(details_table)
                    elements.append(Spacer(1, 0.2 * inch))

                # Findings for checks
                requirement_check_ids = requirement_attributes.get(
                    "attributes", {}
                ).get("checks", [])
                for check_id in requirement_check_ids:
                    elements.append(Paragraph(f"Check: {check_id}", h3))
                    elements.append(Spacer(1, 0.1 * inch))

                    check_findings = findings_by_check_id.get(check_id, [])

                    if not check_findings:
                        elements.append(
                            Paragraph(
                                "- No information available for this check", normal
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
                                        COLOR_NIS2_PRIMARY,
                                    ),
                                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                                    ("FONTNAME", (0, 0), (-1, 0), "FiraCode"),
                                    ("ALIGN", (0, 0), (0, 0), "CENTER"),
                                    ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                                    ("FONTSIZE", (0, 0), (-1, -1), 9),
                                    ("GRID", (0, 0), (-1, -1), 0.5, COLOR_BORDER_GRAY),
                                    (
                                        "ROWBACKGROUNDS",
                                        (0, 1),
                                        (-1, -1),
                                        [colors.white, COLOR_NIS2_BG_BLUE],
                                    ),
                                    ("LEFTPADDING", (0, 0), (-1, -1), 5),
                                    ("RIGHTPADDING", (0, 0), (-1, -1), 5),
                                    ("TOPPADDING", (0, 0), (-1, -1), 5),
                                    ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
                                ]
                            )
                        )
                        elements.append(findings_table)

                    elements.append(Spacer(1, 0.15 * inch))

                elements.append(Spacer(1, 0.2 * inch))

        # Build the PDF
        logger.info("Building NIS2 PDF...")
        doc.build(elements, onFirstPage=_add_pdf_footer, onLaterPages=_add_pdf_footer)
        logger.info(f"NIS2 report successfully generated at {output_path}")

    except Exception as e:
        tb_lineno = e.__traceback__.tb_lineno if e.__traceback__ else "unknown"
        logger.error(f"Error building NIS2 report, line {tb_lineno} -- {e}")
        raise e


def generate_compliance_reports(
    tenant_id: str,
    scan_id: str,
    provider_id: str,
    generate_threatscore: bool = True,
    generate_ens: bool = True,
    generate_nis2: bool = True,
    only_failed_threatscore: bool = True,
    min_risk_level_threatscore: int = 4,
    include_manual_ens: bool = True,
    include_manual_nis2: bool = False,
    only_failed_nis2: bool = True,
) -> dict[str, dict[str, bool | str]]:
    """
    Generate multiple compliance reports (ThreatScore, ENS, and/or NIS2) with shared database queries.

    This function optimizes the generation of multiple reports by:
    - Fetching the provider object once
    - Aggregating requirement statistics once (shared across all reports)
    - Reusing compliance framework data when possible

    This can reduce database queries by up to 50-70% when generating multiple reports.

    Args:
        tenant_id (str): The tenant ID for Row-Level Security context.
        scan_id (str): The ID of the scan to generate reports for.
        provider_id (str): The ID of the provider used in the scan.
        generate_threatscore (bool): Whether to generate ThreatScore report. Defaults to True.
        generate_ens (bool): Whether to generate ENS report. Defaults to True.
        generate_nis2 (bool): Whether to generate NIS2 report. Defaults to True.
        only_failed_threatscore (bool): For ThreatScore, only include failed requirements. Defaults to True.
        min_risk_level_threatscore (int): Minimum risk level for ThreatScore critical requirements. Defaults to 4.
        include_manual_ens (bool): For ENS, include manual requirements. Defaults to True.
        only_failed_nis2 (bool): For NIS2, only include failed requirements. Defaults to True.

    Returns:
        dict[str, dict[str, bool | str]]: Dictionary with results for each report:
            {
                'threatscore': {'upload': bool, 'path': str, 'error': str (optional)},
                'ens': {'upload': bool, 'path': str, 'error': str (optional)},
                'nis2': {'upload': bool, 'path': str, 'error': str (optional)}
            }

    Example:
        >>> results = generate_compliance_reports(
        ...     tenant_id="tenant-123",
        ...     scan_id="scan-456",
        ...     provider_id="provider-789",
        ...     generate_threatscore=True,
        ...     generate_ens=True,
        ...     generate_nis2=True
        ... )
        >>> print(results['threatscore']['upload'])
        True
    """
    logger.info(
        f"Generating compliance reports for scan {scan_id} with provider {provider_id}"
        f" (ThreatScore: {generate_threatscore}, ENS: {generate_ens}, NIS2: {generate_nis2})"
    )

    results = {}

    # Validate that the scan has findings and get provider info (shared query)
    with rls_transaction(tenant_id, using=READ_REPLICA_ALIAS):
        if not ScanSummary.objects.filter(scan_id=scan_id).exists():
            logger.info(f"No findings found for scan {scan_id}")
            if generate_threatscore:
                results["threatscore"] = {"upload": False, "path": ""}
            if generate_ens:
                results["ens"] = {"upload": False, "path": ""}
            if generate_nis2:
                results["nis2"] = {"upload": False, "path": ""}
            return results

        # Fetch provider once (optimization)
        provider_obj = Provider.objects.get(id=provider_id)
        provider_uid = provider_obj.uid
        provider_type = provider_obj.provider

    # Check provider compatibility
    if generate_threatscore and provider_type not in [
        "aws",
        "azure",
        "gcp",
        "m365",
        "kubernetes",
    ]:
        logger.info(
            f"Provider {provider_id} ({provider_type}) is not supported for ThreatScore report"
        )
        results["threatscore"] = {"upload": False, "path": ""}
        generate_threatscore = False

    if generate_ens and provider_type not in ["aws", "azure", "gcp"]:
        logger.info(
            f"Provider {provider_id} ({provider_type}) is not supported for ENS report"
        )
        results["ens"] = {"upload": False, "path": ""}
        generate_ens = False

    if generate_nis2 and provider_type not in ["aws", "azure", "gcp"]:
        logger.info(
            f"Provider {provider_id} ({provider_type}) is not supported for NIS2 report"
        )
        results["nis2"] = {"upload": False, "path": ""}
        generate_nis2 = False

    # If no reports to generate, return early
    if not generate_threatscore and not generate_ens and not generate_nis2:
        return results

    # Aggregate requirement statistics once (major optimization)
    logger.info(
        f"Aggregating requirement statistics once for all reports (scan {scan_id})"
    )
    requirement_statistics = _aggregate_requirement_statistics_from_database(
        tenant_id, scan_id
    )

    # Create shared findings cache (major optimization for findings queries)
    findings_cache = {}
    logger.info("Created shared findings cache for both reports")

    # Generate output directories for each compliance framework
    try:
        logger.info("Generating output directories")
        threatscore_path = _generate_compliance_output_directory(
            DJANGO_TMP_OUTPUT_DIRECTORY,
            provider_uid,
            tenant_id,
            scan_id,
            compliance_framework="threatscore",
        )
        ens_path = _generate_compliance_output_directory(
            DJANGO_TMP_OUTPUT_DIRECTORY,
            provider_uid,
            tenant_id,
            scan_id,
            compliance_framework="ens",
        )
        nis2_path = _generate_compliance_output_directory(
            DJANGO_TMP_OUTPUT_DIRECTORY,
            provider_uid,
            tenant_id,
            scan_id,
            compliance_framework="nis2",
        )
        # Extract base scan directory for cleanup (parent of threatscore directory)
        out_dir = str(Path(threatscore_path).parent.parent)
    except Exception as e:
        logger.error(f"Error generating output directory: {e}")
        error_dict = {"error": str(e), "upload": False, "path": ""}
        if generate_threatscore:
            results["threatscore"] = error_dict.copy()
        if generate_ens:
            results["ens"] = error_dict.copy()
        if generate_nis2:
            results["nis2"] = error_dict.copy()
        return results

    # Generate ThreatScore report
    if generate_threatscore:
        compliance_id_threatscore = f"prowler_threatscore_{provider_type}"
        pdf_path_threatscore = f"{threatscore_path}_threatscore_report.pdf"
        logger.info(
            f"Generating ThreatScore report with compliance {compliance_id_threatscore}"
        )

        try:
            generate_threatscore_report(
                tenant_id=tenant_id,
                scan_id=scan_id,
                compliance_id=compliance_id_threatscore,
                output_path=pdf_path_threatscore,
                provider_id=provider_id,
                only_failed=only_failed_threatscore,
                min_risk_level=min_risk_level_threatscore,
                provider_obj=provider_obj,  # Reuse provider object
                requirement_statistics=requirement_statistics,  # Reuse statistics
                findings_cache=findings_cache,  # Share findings cache
            )

            # Compute and store ThreatScore metrics snapshot
            logger.info(f"Computing ThreatScore metrics for scan {scan_id}")
            try:
                metrics = compute_threatscore_metrics(
                    tenant_id=tenant_id,
                    scan_id=scan_id,
                    provider_id=provider_id,
                    compliance_id=compliance_id_threatscore,
                    min_risk_level=min_risk_level_threatscore,
                )

                # Create snapshot in database
                with rls_transaction(tenant_id):
                    # Get previous snapshot for the same provider to calculate delta
                    previous_snapshot = (
                        ThreatScoreSnapshot.objects.filter(
                            tenant_id=tenant_id,
                            provider_id=provider_id,
                            compliance_id=compliance_id_threatscore,
                        )
                        .order_by("-inserted_at")
                        .first()
                    )

                    # Calculate score delta (improvement)
                    score_delta = None
                    if previous_snapshot:
                        score_delta = metrics["overall_score"] - float(
                            previous_snapshot.overall_score
                        )

                    snapshot = ThreatScoreSnapshot.objects.create(
                        tenant_id=tenant_id,
                        scan_id=scan_id,
                        provider_id=provider_id,
                        compliance_id=compliance_id_threatscore,
                        overall_score=metrics["overall_score"],
                        score_delta=score_delta,
                        section_scores=metrics["section_scores"],
                        critical_requirements=metrics["critical_requirements"],
                        total_requirements=metrics["total_requirements"],
                        passed_requirements=metrics["passed_requirements"],
                        failed_requirements=metrics["failed_requirements"],
                        manual_requirements=metrics["manual_requirements"],
                        total_findings=metrics["total_findings"],
                        passed_findings=metrics["passed_findings"],
                        failed_findings=metrics["failed_findings"],
                    )

                    delta_msg = (
                        f" (delta: {score_delta:+.2f}%)"
                        if score_delta is not None
                        else ""
                    )
                    logger.info(
                        f"ThreatScore snapshot created with ID {snapshot.id} "
                        f"(score: {snapshot.overall_score}%{delta_msg})"
                    )
            except Exception as e:
                # Log error but don't fail the job if snapshot creation fails
                logger.error(f"Error creating ThreatScore snapshot: {e}")

            upload_uri_threatscore = _upload_to_s3(
                tenant_id,
                scan_id,
                pdf_path_threatscore,
                f"threatscore/{Path(pdf_path_threatscore).name}",
            )

            if upload_uri_threatscore:
                results["threatscore"] = {
                    "upload": True,
                    "path": upload_uri_threatscore,
                }
                logger.info(f"ThreatScore report uploaded to {upload_uri_threatscore}")
            else:
                results["threatscore"] = {"upload": False, "path": out_dir}
                logger.warning(f"ThreatScore report saved locally at {out_dir}")

        except Exception as e:
            logger.error(f"Error generating ThreatScore report: {e}")
            results["threatscore"] = {"upload": False, "path": "", "error": str(e)}

    # Generate ENS report
    if generate_ens:
        compliance_id_ens = f"ens_rd2022_{provider_type}"
        pdf_path_ens = f"{ens_path}_ens_report.pdf"
        logger.info(f"Generating ENS report with compliance {compliance_id_ens}")

        try:
            generate_ens_report(
                tenant_id=tenant_id,
                scan_id=scan_id,
                compliance_id=compliance_id_ens,
                output_path=pdf_path_ens,
                provider_id=provider_id,
                include_manual=include_manual_ens,
                provider_obj=provider_obj,  # Reuse provider object
                requirement_statistics=requirement_statistics,  # Reuse statistics
                findings_cache=findings_cache,  # Share findings cache
            )

            upload_uri_ens = _upload_to_s3(
                tenant_id,
                scan_id,
                pdf_path_ens,
                f"ens/{Path(pdf_path_ens).name}",
            )

            if upload_uri_ens:
                results["ens"] = {"upload": True, "path": upload_uri_ens}
                logger.info(f"ENS report uploaded to {upload_uri_ens}")
            else:
                results["ens"] = {"upload": False, "path": out_dir}
                logger.warning(f"ENS report saved locally at {out_dir}")

        except Exception as e:
            logger.error(f"Error generating ENS report: {e}")
            results["ens"] = {"upload": False, "path": "", "error": str(e)}

    # Generate NIS2 report
    if generate_nis2:
        compliance_id_nis2 = f"nis2_{provider_type}"
        pdf_path_nis2 = f"{nis2_path}_nis2_report.pdf"
        logger.info(f"Generating NIS2 report with compliance {compliance_id_nis2}")

        try:
            generate_nis2_report(
                tenant_id=tenant_id,
                scan_id=scan_id,
                compliance_id=compliance_id_nis2,
                output_path=pdf_path_nis2,
                provider_id=provider_id,
                only_failed=only_failed_nis2,
                include_manual=include_manual_nis2,
                provider_obj=provider_obj,  # Reuse provider object
                requirement_statistics=requirement_statistics,  # Reuse statistics
                findings_cache=findings_cache,  # Share findings cache
            )

            upload_uri_nis2 = _upload_to_s3(
                tenant_id,
                scan_id,
                pdf_path_nis2,
                f"nis2/{Path(pdf_path_nis2).name}",
            )

            if upload_uri_nis2:
                results["nis2"] = {"upload": True, "path": upload_uri_nis2}
                logger.info(f"NIS2 report uploaded to {upload_uri_nis2}")
            else:
                results["nis2"] = {"upload": False, "path": out_dir}
                logger.warning(f"NIS2 report saved locally at {out_dir}")

        except Exception as e:
            logger.error(f"Error generating NIS2 report: {e}")
            results["nis2"] = {"upload": False, "path": "", "error": str(e)}

    # Clean up temporary files if all reports were uploaded successfully
    all_uploaded = all(
        result.get("upload", False)
        for result in results.values()
        if result.get("upload") is not None
    )

    if all_uploaded:
        try:
            rmtree(Path(out_dir), ignore_errors=True)
            logger.info(f"Cleaned up temporary files at {out_dir}")
        except Exception as e:
            logger.error(f"Error deleting output files: {e}")

    logger.info(f"Compliance reports generation completed. Results: {results}")
    return results


def generate_compliance_reports_job(
    tenant_id: str,
    scan_id: str,
    provider_id: str,
    generate_threatscore: bool = True,
    generate_ens: bool = True,
    generate_nis2: bool = True,
) -> dict[str, dict[str, bool | str]]:
    """
    Job function to generate ThreatScore, ENS, and/or NIS2 compliance reports with optimized database queries.

    This function efficiently generates compliance reports by:
    - Fetching the provider object once (shared across all reports)
    - Aggregating requirement statistics once (shared across all reports)
    - Sharing findings cache between reports to avoid duplicate queries
    - Reducing total database queries by 50-70% compared to generating reports separately

    Use this job when you need to generate compliance reports for a scan.

    Args:
        tenant_id (str): The tenant ID for Row-Level Security context.
        scan_id (str): The ID of the scan to generate reports for.
        provider_id (str): The ID of the provider used in the scan.
        generate_threatscore (bool): Whether to generate ThreatScore report. Defaults to True.
        generate_ens (bool): Whether to generate ENS report. Defaults to True.
        generate_nis2 (bool): Whether to generate NIS2 report. Defaults to True.

    Returns:
        dict[str, dict[str, bool | str]]: Dictionary with results for each report:
            {
                'threatscore': {'upload': bool, 'path': str, 'error': str (optional)},
                'ens': {'upload': bool, 'path': str, 'error': str (optional)},
                'nis2': {'upload': bool, 'path': str, 'error': str (optional)}
            }

    Example:
        >>> results = generate_compliance_reports_job(
        ...     tenant_id="tenant-123",
        ...     scan_id="scan-456",
        ...     provider_id="provider-789"
        ... )
        >>> if results['threatscore']['upload']:
        ...     print(f"ThreatScore uploaded to {results['threatscore']['path']}")
        >>> if results['ens']['upload']:
        ...     print(f"ENS uploaded to {results['ens']['path']}")
        >>> if results['nis2']['upload']:
        ...     print(f"NIS2 uploaded to {results['nis2']['path']}")
    """
    logger.info(
        f"Starting optimized compliance reports job for scan {scan_id} "
        f"(ThreatScore: {generate_threatscore}, ENS: {generate_ens}, NIS2: {generate_nis2})"
    )

    try:
        results = generate_compliance_reports(
            tenant_id=tenant_id,
            scan_id=scan_id,
            provider_id=provider_id,
            generate_threatscore=generate_threatscore,
            generate_ens=generate_ens,
            generate_nis2=generate_nis2,
            only_failed_threatscore=True,
            min_risk_level_threatscore=4,
            include_manual_ens=True,
            include_manual_nis2=False,
            only_failed_nis2=True,
        )
        logger.info("Optimized compliance reports job completed successfully")
        return results

    except Exception as e:
        logger.error(f"Error in optimized compliance reports job: {e}")
        error_result = {"upload": False, "path": "", "error": str(e)}
        results = {}
        if generate_threatscore:
            results["threatscore"] = error_result.copy()
        if generate_ens:
            results["ens"] = error_result.copy()
        if generate_nis2:
            results["nis2"] = error_result.copy()
        return results
