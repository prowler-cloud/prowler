from dataclasses import dataclass, field

from reportlab.lib import colors
from reportlab.lib.units import inch

# =============================================================================
# Performance & Memory Optimization Settings
# =============================================================================
# These settings control memory usage and performance for large reports.
# Adjust these values if workers are running out of memory.

# Chart settings - lower DPI = less memory, 150 is good quality for PDF
CHART_DPI_DEFAULT = 150

# LongTable threshold - use LongTable for tables with more rows than this
# LongTable handles page breaks better and has optimized memory for large tables
LONG_TABLE_THRESHOLD = 50

# Skip alternating row colors for tables larger than this (reduces memory)
ALTERNATE_ROWS_MAX_SIZE = 200

# Database query batch size for findings (matches Django settings)
# Larger = fewer queries but more memory per batch
FINDINGS_BATCH_SIZE = 2000


# =============================================================================
# Base colors
# =============================================================================
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
COLOR_NIS2_PRIMARY = colors.Color(0.12, 0.23, 0.54)
COLOR_NIS2_SECONDARY = colors.Color(0.23, 0.51, 0.96)
COLOR_NIS2_BG_BLUE = colors.Color(0.96, 0.97, 0.99)

# Chart colors (hex strings for matplotlib)
CHART_COLOR_GREEN_1 = "#4CAF50"
CHART_COLOR_GREEN_2 = "#8BC34A"
CHART_COLOR_YELLOW = "#FFEB3B"
CHART_COLOR_ORANGE = "#FF9800"
CHART_COLOR_RED = "#F44336"
CHART_COLOR_BLUE = "#2196F3"

# ENS dimension mappings: dimension name -> (abbreviation, color)
DIMENSION_MAPPING = {
    "trazabilidad": ("T", colors.Color(0.26, 0.52, 0.96)),
    "autenticidad": ("A", colors.Color(0.30, 0.69, 0.31)),
    "integridad": ("I", colors.Color(0.61, 0.15, 0.69)),
    "confidencialidad": ("C", colors.Color(0.96, 0.26, 0.21)),
    "disponibilidad": ("D", colors.Color(1.0, 0.60, 0.0)),
}

# ENS tipo icons
TIPO_ICONS = {
    "requisito": "\u26a0\ufe0f",
    "refuerzo": "\U0001f6e1\ufe0f",
    "recomendacion": "\U0001f4a1",
    "medida": "\U0001f4cb",
}

# Dimension names for charts (Spanish)
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

# ENS nivel and tipo order
ENS_NIVEL_ORDER = ["alto", "medio", "bajo", "opcional"]
ENS_TIPO_ORDER = ["requisito", "refuerzo", "recomendacion", "medida"]

# ThreatScore sections
THREATSCORE_SECTIONS = [
    "1. IAM",
    "2. Attack Surface",
    "3. Logging and Monitoring",
    "4. Encryption",
]

# NIS2 sections
NIS2_SECTIONS = [
    "1",
    "2",
    "3",
    "4",
    "5",
    "6",
    "7",
    "9",
    "11",
    "12",
]

NIS2_SECTION_TITLES = {
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

# Table column widths
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


@dataclass
class FrameworkConfig:
    """
    Configuration for a compliance framework PDF report.

    This dataclass defines all the configurable aspects of a compliance framework
    report, including visual styling, metadata fields, and feature flags.

    Attributes:
        name (str): Internal framework identifier (e.g., "prowler_threatscore").
        display_name (str): Human-readable framework name for the report title.
        logo_filename (str | None): Optional filename of the framework logo in assets/img/.
        primary_color (colors.Color): Main color used for headers and important elements.
        secondary_color (colors.Color): Secondary color for sub-headers and accents.
        bg_color (colors.Color): Background color for highlighted sections.
        attribute_fields (list[str]): List of metadata field names to extract from requirements.
        sections (list[str] | None): Optional ordered list of section names for grouping.
        language (str): Report language ("en" for English, "es" for Spanish).
        has_risk_levels (bool): Whether the framework uses numeric risk levels.
        has_dimensions (bool): Whether the framework uses security dimensions (ENS).
        has_niveles (bool): Whether the framework uses nivel classification (ENS).
        has_weight (bool): Whether requirements have weight values.
    """

    name: str
    display_name: str
    logo_filename: str | None = None
    primary_color: colors.Color = field(default_factory=lambda: COLOR_BLUE)
    secondary_color: colors.Color = field(default_factory=lambda: COLOR_LIGHT_BLUE)
    bg_color: colors.Color = field(default_factory=lambda: COLOR_BG_BLUE)
    attribute_fields: list[str] = field(default_factory=list)
    sections: list[str] | None = None
    language: str = "en"
    has_risk_levels: bool = False
    has_dimensions: bool = False
    has_niveles: bool = False
    has_weight: bool = False


FRAMEWORK_REGISTRY: dict[str, FrameworkConfig] = {
    "prowler_threatscore": FrameworkConfig(
        name="prowler_threatscore",
        display_name="Prowler ThreatScore",
        logo_filename=None,
        primary_color=COLOR_BLUE,
        secondary_color=COLOR_LIGHT_BLUE,
        bg_color=COLOR_BG_BLUE,
        attribute_fields=[
            "Title",
            "Section",
            "SubSection",
            "LevelOfRisk",
            "Weight",
            "AttributeDescription",
            "AdditionalInformation",
        ],
        sections=THREATSCORE_SECTIONS,
        language="en",
        has_risk_levels=True,
        has_weight=True,
    ),
    "ens": FrameworkConfig(
        name="ens",
        display_name="ENS RD2022",
        logo_filename="ens_logo.png",
        primary_color=COLOR_ENS_ALTO,
        secondary_color=COLOR_ENS_MEDIO,
        bg_color=COLOR_BG_BLUE,
        attribute_fields=[
            "IdGrupoControl",
            "Marco",
            "Categoria",
            "DescripcionControl",
            "Tipo",
            "Nivel",
            "Dimensiones",
            "ModoEjecucion",
        ],
        sections=None,
        language="es",
        has_risk_levels=False,
        has_dimensions=True,
        has_niveles=True,
        has_weight=False,
    ),
    "nis2": FrameworkConfig(
        name="nis2",
        display_name="NIS2 Directive",
        logo_filename="nis2_logo.png",
        primary_color=COLOR_NIS2_PRIMARY,
        secondary_color=COLOR_NIS2_SECONDARY,
        bg_color=COLOR_NIS2_BG_BLUE,
        attribute_fields=[
            "Section",
            "SubSection",
            "Description",
        ],
        sections=NIS2_SECTIONS,
        language="en",
        has_risk_levels=False,
        has_dimensions=False,
        has_niveles=False,
        has_weight=False,
    ),
}


def get_framework_config(compliance_id: str) -> FrameworkConfig | None:
    """
    Get framework configuration based on compliance ID.

    Args:
        compliance_id (str): The compliance framework identifier (e.g., "prowler_threatscore_aws").

    Returns:
        FrameworkConfig | None: The framework configuration if found, None otherwise.
    """
    compliance_lower = compliance_id.lower()

    if "threatscore" in compliance_lower:
        return FRAMEWORK_REGISTRY["prowler_threatscore"]
    if "ens" in compliance_lower:
        return FRAMEWORK_REGISTRY["ens"]
    if "nis2" in compliance_lower:
        return FRAMEWORK_REGISTRY["nis2"]

    return None
