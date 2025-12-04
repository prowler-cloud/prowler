"""
Compliance PDF Report Generation Framework.

This package provides a modular, extensible framework for generating
PDF compliance reports. It uses the Strategy Pattern with Template Method
to allow easy addition of new compliance frameworks.

Example usage for creating a new framework report:

    from tasks.jobs.reports import (
        BaseComplianceReportGenerator,
        ComplianceData,
        FrameworkConfig,
        create_horizontal_bar_chart,
        create_status_badge,
    )

    class CISReportGenerator(BaseComplianceReportGenerator):
        def create_executive_summary(self, data: ComplianceData) -> list:
            # CIS-specific implementation
            ...

        def create_charts_section(self, data: ComplianceData) -> list:
            chart = create_horizontal_bar_chart(...)
            ...

        def create_requirements_index(self, data: ComplianceData) -> list:
            ...

    # Register in config.py and use:
    generator = CISReportGenerator(FRAMEWORK_REGISTRY["cis"])
    generator.generate(tenant_id, scan_id, compliance_id, output_path, provider_id)
"""

# Base classes and data structures
from .base import (
    BaseComplianceReportGenerator,
    ComplianceData,
    RequirementData,
    create_pdf_styles,
)

# Chart functions
from .charts import (
    create_horizontal_bar_chart,
    create_pie_chart,
    create_radar_chart,
    create_stacked_bar_chart,
    create_vertical_bar_chart,
    get_chart_color_for_percentage,
)

# Reusable components
from .components import (  # Color helpers; Badge components; Risk component; Table components; Section components
    ColumnConfig,
    create_badge,
    create_data_table,
    create_findings_table,
    create_info_table,
    create_multi_badge_row,
    create_risk_component,
    create_section_header,
    create_status_badge,
    create_summary_table,
    get_color_for_compliance,
    get_color_for_risk_level,
    get_color_for_weight,
    get_status_color,
)

# Framework configuration
from .config import (  # Main configuration; Color constants; ENS colors; NIS2 colors; Chart colors; ENS constants; Section constants; Layout constants
    CHART_COLOR_BLUE,
    CHART_COLOR_GREEN_1,
    CHART_COLOR_GREEN_2,
    CHART_COLOR_ORANGE,
    CHART_COLOR_RED,
    CHART_COLOR_YELLOW,
    COL_WIDTH_LARGE,
    COL_WIDTH_MEDIUM,
    COL_WIDTH_SMALL,
    COL_WIDTH_XLARGE,
    COL_WIDTH_XXLARGE,
    COLOR_BG_BLUE,
    COLOR_BG_LIGHT_BLUE,
    COLOR_BLUE,
    COLOR_DARK_GRAY,
    COLOR_ENS_ALTO,
    COLOR_ENS_BAJO,
    COLOR_ENS_MEDIO,
    COLOR_ENS_OPCIONAL,
    COLOR_GRAY,
    COLOR_HIGH_RISK,
    COLOR_LIGHT_BLUE,
    COLOR_LIGHT_GRAY,
    COLOR_LIGHTER_BLUE,
    COLOR_LOW_RISK,
    COLOR_MEDIUM_RISK,
    COLOR_NIS2_PRIMARY,
    COLOR_NIS2_SECONDARY,
    COLOR_PROWLER_DARK_GREEN,
    COLOR_SAFE,
    COLOR_WHITE,
    DIMENSION_KEYS,
    DIMENSION_MAPPING,
    DIMENSION_NAMES,
    ENS_NIVEL_ORDER,
    ENS_TIPO_ORDER,
    FRAMEWORK_REGISTRY,
    NIS2_SECTION_TITLES,
    NIS2_SECTIONS,
    PADDING_LARGE,
    PADDING_MEDIUM,
    PADDING_SMALL,
    PADDING_XLARGE,
    THREATSCORE_SECTIONS,
    TIPO_ICONS,
    FrameworkConfig,
    get_framework_config,
)

# Framework-specific generators
from .ens import ENSReportGenerator
from .nis2 import NIS2ReportGenerator
from .threatscore import ThreatScoreReportGenerator

__all__ = [
    # Base classes
    "BaseComplianceReportGenerator",
    "ComplianceData",
    "RequirementData",
    "create_pdf_styles",
    # Framework-specific generators
    "ThreatScoreReportGenerator",
    "ENSReportGenerator",
    "NIS2ReportGenerator",
    # Configuration
    "FrameworkConfig",
    "FRAMEWORK_REGISTRY",
    "get_framework_config",
    # Color constants
    "COLOR_BLUE",
    "COLOR_LIGHT_BLUE",
    "COLOR_LIGHTER_BLUE",
    "COLOR_BG_BLUE",
    "COLOR_BG_LIGHT_BLUE",
    "COLOR_GRAY",
    "COLOR_LIGHT_GRAY",
    "COLOR_DARK_GRAY",
    "COLOR_WHITE",
    "COLOR_HIGH_RISK",
    "COLOR_MEDIUM_RISK",
    "COLOR_LOW_RISK",
    "COLOR_SAFE",
    "COLOR_PROWLER_DARK_GREEN",
    "COLOR_ENS_ALTO",
    "COLOR_ENS_MEDIO",
    "COLOR_ENS_BAJO",
    "COLOR_ENS_OPCIONAL",
    "COLOR_NIS2_PRIMARY",
    "COLOR_NIS2_SECONDARY",
    "CHART_COLOR_BLUE",
    "CHART_COLOR_GREEN_1",
    "CHART_COLOR_GREEN_2",
    "CHART_COLOR_YELLOW",
    "CHART_COLOR_ORANGE",
    "CHART_COLOR_RED",
    # ENS constants
    "DIMENSION_MAPPING",
    "DIMENSION_NAMES",
    "DIMENSION_KEYS",
    "ENS_NIVEL_ORDER",
    "ENS_TIPO_ORDER",
    "TIPO_ICONS",
    # Section constants
    "THREATSCORE_SECTIONS",
    "NIS2_SECTIONS",
    "NIS2_SECTION_TITLES",
    # Layout constants
    "COL_WIDTH_SMALL",
    "COL_WIDTH_MEDIUM",
    "COL_WIDTH_LARGE",
    "COL_WIDTH_XLARGE",
    "COL_WIDTH_XXLARGE",
    "PADDING_SMALL",
    "PADDING_MEDIUM",
    "PADDING_LARGE",
    "PADDING_XLARGE",
    # Color helpers
    "get_color_for_risk_level",
    "get_color_for_weight",
    "get_color_for_compliance",
    "get_status_color",
    # Badge components
    "create_badge",
    "create_status_badge",
    "create_multi_badge_row",
    # Risk component
    "create_risk_component",
    # Table components
    "create_info_table",
    "create_data_table",
    "create_findings_table",
    "ColumnConfig",
    # Section components
    "create_section_header",
    "create_summary_table",
    # Chart functions
    "get_chart_color_for_percentage",
    "create_vertical_bar_chart",
    "create_horizontal_bar_chart",
    "create_radar_chart",
    "create_pie_chart",
    "create_stacked_bar_chart",
]
