"""
Tests for the reports base architecture.

This module tests the new PDF report generation framework including:
- Configuration and registry
- Reusable components
- Chart generation
- Base class functionality
"""

import io

import pytest
from reportlab.lib.units import inch
from tasks.jobs.reports import (  # Configuration; Colors; Components; Charts; Base
    CHART_COLOR_GREEN_1,
    CHART_COLOR_RED,
    COLOR_BLUE,
    COLOR_HIGH_RISK,
    COLOR_SAFE,
    FRAMEWORK_REGISTRY,
    BaseComplianceReportGenerator,
    ColumnConfig,
    ComplianceData,
    FrameworkConfig,
    RequirementData,
    create_badge,
    create_data_table,
    create_horizontal_bar_chart,
    create_info_table,
    create_multi_badge_row,
    create_pdf_styles,
    create_pie_chart,
    create_radar_chart,
    create_risk_component,
    create_status_badge,
    create_summary_table,
    create_vertical_bar_chart,
    get_chart_color_for_percentage,
    get_color_for_compliance,
    get_color_for_risk_level,
    get_color_for_weight,
    get_framework_config,
    get_status_color,
)

# =============================================================================
# Configuration Tests
# =============================================================================


class TestFrameworkConfig:
    """Tests for FrameworkConfig dataclass."""

    def test_framework_config_creation(self):
        """Test creating a FrameworkConfig with required fields."""
        config = FrameworkConfig(
            name="test_framework",
            display_name="Test Framework",
        )

        assert config.name == "test_framework"
        assert config.display_name == "Test Framework"
        assert config.logo_filename is None
        assert config.language == "en"
        assert config.has_risk_levels is False

    def test_framework_config_with_all_fields(self):
        """Test creating a FrameworkConfig with all fields."""
        config = FrameworkConfig(
            name="custom",
            display_name="Custom Framework",
            logo_filename="custom_logo.png",
            primary_color=COLOR_BLUE,
            secondary_color=COLOR_SAFE,
            attribute_fields=["Section", "SubSection"],
            sections=["1. Security", "2. Compliance"],
            language="es",
            has_risk_levels=True,
            has_dimensions=True,
            has_niveles=True,
            has_weight=True,
        )

        assert config.name == "custom"
        assert config.logo_filename == "custom_logo.png"
        assert config.language == "es"
        assert config.has_risk_levels is True
        assert config.has_dimensions is True
        assert len(config.attribute_fields) == 2
        assert len(config.sections) == 2


class TestFrameworkRegistry:
    """Tests for the framework registry."""

    def test_registry_contains_threatscore(self):
        """Test that ThreatScore is in the registry."""
        assert "prowler_threatscore" in FRAMEWORK_REGISTRY
        config = FRAMEWORK_REGISTRY["prowler_threatscore"]
        assert config.has_risk_levels is True
        assert config.has_weight is True

    def test_registry_contains_ens(self):
        """Test that ENS is in the registry."""
        assert "ens" in FRAMEWORK_REGISTRY
        config = FRAMEWORK_REGISTRY["ens"]
        assert config.language == "es"
        assert config.has_niveles is True
        assert config.has_dimensions is True

    def test_registry_contains_nis2(self):
        """Test that NIS2 is in the registry."""
        assert "nis2" in FRAMEWORK_REGISTRY
        config = FRAMEWORK_REGISTRY["nis2"]
        assert config.language == "en"

    def test_get_framework_config_threatscore(self):
        """Test getting ThreatScore config."""
        config = get_framework_config("prowler_threatscore_aws")
        assert config is not None
        assert config.name == "prowler_threatscore"

    def test_get_framework_config_ens(self):
        """Test getting ENS config."""
        config = get_framework_config("ens_rd2022_aws")
        assert config is not None
        assert config.name == "ens"

    def test_get_framework_config_nis2(self):
        """Test getting NIS2 config."""
        config = get_framework_config("nis2_aws")
        assert config is not None
        assert config.name == "nis2"

    def test_get_framework_config_unknown(self):
        """Test getting unknown framework returns None."""
        config = get_framework_config("unknown_framework")
        assert config is None


# =============================================================================
# Color Helper Tests
# =============================================================================


class TestColorHelpers:
    """Tests for color helper functions."""

    def test_get_color_for_risk_level_high(self):
        """Test high risk level returns red."""
        assert get_color_for_risk_level(5) == COLOR_HIGH_RISK
        assert get_color_for_risk_level(4) == COLOR_HIGH_RISK

    def test_get_color_for_risk_level_medium(self):
        """Test medium risk level returns orange."""
        from tasks.jobs.reports import COLOR_MEDIUM_RISK

        assert get_color_for_risk_level(3) == COLOR_MEDIUM_RISK

    def test_get_color_for_risk_level_low(self):
        """Test low risk level returns yellow."""
        from tasks.jobs.reports import COLOR_LOW_RISK

        assert get_color_for_risk_level(2) == COLOR_LOW_RISK

    def test_get_color_for_risk_level_safe(self):
        """Test safe risk level returns green."""
        assert get_color_for_risk_level(1) == COLOR_SAFE
        assert get_color_for_risk_level(0) == COLOR_SAFE

    def test_get_color_for_weight_high(self):
        """Test high weight returns red."""
        assert get_color_for_weight(150) == COLOR_HIGH_RISK
        assert get_color_for_weight(101) == COLOR_HIGH_RISK

    def test_get_color_for_weight_medium(self):
        """Test medium weight returns yellow."""
        from tasks.jobs.reports import COLOR_LOW_RISK

        assert get_color_for_weight(100) == COLOR_LOW_RISK
        assert get_color_for_weight(51) == COLOR_LOW_RISK

    def test_get_color_for_weight_low(self):
        """Test low weight returns green."""
        assert get_color_for_weight(50) == COLOR_SAFE
        assert get_color_for_weight(0) == COLOR_SAFE

    def test_get_color_for_compliance_high(self):
        """Test high compliance returns green."""
        assert get_color_for_compliance(100) == COLOR_SAFE
        assert get_color_for_compliance(80) == COLOR_SAFE

    def test_get_color_for_compliance_medium(self):
        """Test medium compliance returns yellow."""
        from tasks.jobs.reports import COLOR_LOW_RISK

        assert get_color_for_compliance(79) == COLOR_LOW_RISK
        assert get_color_for_compliance(60) == COLOR_LOW_RISK

    def test_get_color_for_compliance_low(self):
        """Test low compliance returns red."""
        assert get_color_for_compliance(59) == COLOR_HIGH_RISK
        assert get_color_for_compliance(0) == COLOR_HIGH_RISK

    def test_get_status_color_pass(self):
        """Test PASS status returns green."""
        assert get_status_color("PASS") == COLOR_SAFE
        assert get_status_color("pass") == COLOR_SAFE

    def test_get_status_color_fail(self):
        """Test FAIL status returns red."""
        assert get_status_color("FAIL") == COLOR_HIGH_RISK
        assert get_status_color("fail") == COLOR_HIGH_RISK

    def test_get_status_color_manual(self):
        """Test MANUAL status returns gray."""
        from tasks.jobs.reports import COLOR_DARK_GRAY

        assert get_status_color("MANUAL") == COLOR_DARK_GRAY


class TestChartColorHelpers:
    """Tests for chart color functions."""

    def test_chart_color_for_high_percentage(self):
        """Test high percentage returns green."""
        assert get_chart_color_for_percentage(100) == CHART_COLOR_GREEN_1
        assert get_chart_color_for_percentage(80) == CHART_COLOR_GREEN_1

    def test_chart_color_for_medium_high_percentage(self):
        """Test medium-high percentage returns light green."""
        from tasks.jobs.reports import CHART_COLOR_GREEN_2

        assert get_chart_color_for_percentage(79) == CHART_COLOR_GREEN_2
        assert get_chart_color_for_percentage(60) == CHART_COLOR_GREEN_2

    def test_chart_color_for_low_percentage(self):
        """Test low percentage returns red."""
        assert get_chart_color_for_percentage(19) == CHART_COLOR_RED
        assert get_chart_color_for_percentage(0) == CHART_COLOR_RED


# =============================================================================
# Component Tests
# =============================================================================


class TestBadgeComponents:
    """Tests for badge component functions."""

    def test_create_badge_returns_table(self):
        """Test create_badge returns a Table object."""
        from reportlab.platypus import Table

        badge = create_badge("Test", COLOR_BLUE)
        assert isinstance(badge, Table)

    def test_create_badge_with_custom_width(self):
        """Test create_badge with custom width."""
        badge = create_badge("Test", COLOR_BLUE, width=2 * inch)
        assert badge is not None

    def test_create_status_badge_pass(self):
        """Test status badge for PASS."""
        from reportlab.platypus import Table

        badge = create_status_badge("PASS")
        assert isinstance(badge, Table)

    def test_create_status_badge_fail(self):
        """Test status badge for FAIL."""
        badge = create_status_badge("FAIL")
        assert badge is not None

    def test_create_multi_badge_row_with_badges(self):
        """Test multi-badge row with data."""
        from reportlab.platypus import Table

        badges = [
            ("A", COLOR_BLUE),
            ("B", COLOR_SAFE),
        ]
        table = create_multi_badge_row(badges)
        assert isinstance(table, Table)

    def test_create_multi_badge_row_empty(self):
        """Test multi-badge row with empty list."""
        table = create_multi_badge_row([])
        assert table is not None


class TestRiskComponent:
    """Tests for risk component function."""

    def test_create_risk_component_returns_table(self):
        """Test risk component returns a Table."""
        from reportlab.platypus import Table

        component = create_risk_component(risk_level=4, weight=100, score=50)
        assert isinstance(component, Table)

    def test_create_risk_component_high_risk(self):
        """Test risk component with high risk level."""
        component = create_risk_component(risk_level=5, weight=150, score=100)
        assert component is not None

    def test_create_risk_component_low_risk(self):
        """Test risk component with low risk level."""
        component = create_risk_component(risk_level=1, weight=10, score=10)
        assert component is not None


class TestTableComponents:
    """Tests for table component functions."""

    def test_create_info_table(self):
        """Test info table creation."""
        from reportlab.platypus import Table

        rows = [
            ("Label 1:", "Value 1"),
            ("Label 2:", "Value 2"),
        ]
        table = create_info_table(rows)
        assert isinstance(table, Table)

    def test_create_info_table_with_custom_widths(self):
        """Test info table with custom column widths."""
        rows = [("Test:", "Value")]
        table = create_info_table(rows, label_width=3 * inch, value_width=3 * inch)
        assert table is not None

    def test_create_data_table(self):
        """Test data table creation."""
        from reportlab.platypus import Table

        data = [
            {"name": "Item 1", "value": "100"},
            {"name": "Item 2", "value": "200"},
        ]
        columns = [
            ColumnConfig("Name", 2 * inch, "name"),
            ColumnConfig("Value", 1 * inch, "value"),
        ]
        table = create_data_table(data, columns)
        assert isinstance(table, Table)

    def test_create_data_table_with_callable_field(self):
        """Test data table with callable field."""
        data = [{"raw_value": 100}]
        columns = [
            ColumnConfig("Formatted", 2 * inch, lambda x: f"${x['raw_value']}"),
        ]
        table = create_data_table(data, columns)
        assert table is not None

    def test_create_summary_table(self):
        """Test summary table creation."""
        from reportlab.platypus import Table

        table = create_summary_table(
            label="Score:",
            value="85%",
            value_color=COLOR_SAFE,
        )
        assert isinstance(table, Table)


# =============================================================================
# Chart Tests
# =============================================================================


class TestChartCreation:
    """Tests for chart creation functions."""

    def test_create_vertical_bar_chart(self):
        """Test vertical bar chart creation."""
        buffer = create_vertical_bar_chart(
            labels=["A", "B", "C"],
            values=[80, 60, 40],
        )
        assert isinstance(buffer, io.BytesIO)
        assert buffer.getvalue()  # Not empty

    def test_create_vertical_bar_chart_with_options(self):
        """Test vertical bar chart with custom options."""
        buffer = create_vertical_bar_chart(
            labels=["Section 1", "Section 2"],
            values=[90, 70],
            ylabel="Compliance",
            title="Test Chart",
            figsize=(8, 6),
        )
        assert isinstance(buffer, io.BytesIO)

    def test_create_horizontal_bar_chart(self):
        """Test horizontal bar chart creation."""
        buffer = create_horizontal_bar_chart(
            labels=["Category 1", "Category 2", "Category 3"],
            values=[85, 65, 45],
        )
        assert isinstance(buffer, io.BytesIO)
        assert buffer.getvalue()

    def test_create_horizontal_bar_chart_with_options(self):
        """Test horizontal bar chart with custom options."""
        buffer = create_horizontal_bar_chart(
            labels=["A", "B"],
            values=[100, 50],
            xlabel="Percentage",
            title="Custom Chart",
        )
        assert isinstance(buffer, io.BytesIO)

    def test_create_radar_chart(self):
        """Test radar chart creation."""
        buffer = create_radar_chart(
            labels=["Dim 1", "Dim 2", "Dim 3", "Dim 4", "Dim 5"],
            values=[80, 70, 60, 90, 75],
        )
        assert isinstance(buffer, io.BytesIO)
        assert buffer.getvalue()

    def test_create_radar_chart_with_options(self):
        """Test radar chart with custom options."""
        buffer = create_radar_chart(
            labels=["A", "B", "C"],
            values=[50, 60, 70],
            color="#FF0000",
            fill_alpha=0.5,
            title="Custom Radar",
        )
        assert isinstance(buffer, io.BytesIO)

    def test_create_pie_chart(self):
        """Test pie chart creation."""
        buffer = create_pie_chart(
            labels=["Pass", "Fail"],
            values=[80, 20],
        )
        assert isinstance(buffer, io.BytesIO)
        assert buffer.getvalue()


# =============================================================================
# Data Class Tests
# =============================================================================


class TestDataClasses:
    """Tests for data classes."""

    def test_requirement_data_creation(self):
        """Test RequirementData creation."""
        req = RequirementData(
            id="REQ-001",
            description="Test requirement",
            status="PASS",
            passed_findings=10,
            total_findings=10,
        )
        assert req.id == "REQ-001"
        assert req.status == "PASS"
        assert req.passed_findings == 10

    def test_compliance_data_creation(self):
        """Test ComplianceData creation."""
        data = ComplianceData(
            tenant_id="tenant-123",
            scan_id="scan-456",
            provider_id="provider-789",
            compliance_id="test_compliance",
            framework="Test",
            name="Test Compliance",
            version="1.0",
            description="Test description",
        )
        assert data.tenant_id == "tenant-123"
        assert data.framework == "Test"
        assert data.requirements == []


# =============================================================================
# PDF Styles Tests
# =============================================================================


class TestPDFStyles:
    """Tests for PDF styles."""

    def test_create_pdf_styles_returns_dict(self):
        """Test that create_pdf_styles returns a dictionary."""
        styles = create_pdf_styles()
        assert isinstance(styles, dict)

    def test_create_pdf_styles_has_required_keys(self):
        """Test that styles dict has all required keys."""
        styles = create_pdf_styles()
        required_keys = ["title", "h1", "h2", "h3", "normal", "normal_center"]
        for key in required_keys:
            assert key in styles

    def test_create_pdf_styles_caches_result(self):
        """Test that styles are cached."""
        styles1 = create_pdf_styles()
        styles2 = create_pdf_styles()
        assert styles1 is styles2


# =============================================================================
# Base Generator Tests
# =============================================================================


class TestBaseComplianceReportGenerator:
    """Tests for BaseComplianceReportGenerator."""

    def test_cannot_instantiate_directly(self):
        """Test that base class cannot be instantiated directly."""
        config = FrameworkConfig(name="test", display_name="Test")
        with pytest.raises(TypeError):
            BaseComplianceReportGenerator(config)

    def test_concrete_implementation(self):
        """Test that a concrete implementation can be created."""

        class ConcreteGenerator(BaseComplianceReportGenerator):
            def create_executive_summary(self, data):
                return []

            def create_charts_section(self, data):
                return []

            def create_requirements_index(self, data):
                return []

        config = FrameworkConfig(name="test", display_name="Test")
        generator = ConcreteGenerator(config)
        assert generator.config.name == "test"
        assert generator.styles is not None

    def test_get_footer_text_english(self):
        """Test footer text in English."""

        class ConcreteGenerator(BaseComplianceReportGenerator):
            def create_executive_summary(self, data):
                return []

            def create_charts_section(self, data):
                return []

            def create_requirements_index(self, data):
                return []

        config = FrameworkConfig(name="test", display_name="Test", language="en")
        generator = ConcreteGenerator(config)
        left, right = generator.get_footer_text(1)
        assert left == "Page 1"
        assert right == "Powered by Prowler"

    def test_get_footer_text_spanish(self):
        """Test footer text in Spanish."""

        class ConcreteGenerator(BaseComplianceReportGenerator):
            def create_executive_summary(self, data):
                return []

            def create_charts_section(self, data):
                return []

            def create_requirements_index(self, data):
                return []

        config = FrameworkConfig(name="test", display_name="Test", language="es")
        generator = ConcreteGenerator(config)
        left, right = generator.get_footer_text(1)
        assert left == "Página 1"


# =============================================================================
# Integration Tests
# =============================================================================


class TestExampleReportGenerator:
    """Integration tests using an example report generator."""

    def setup_method(self):
        """Set up test fixtures."""

        class ExampleGenerator(BaseComplianceReportGenerator):
            """Example concrete implementation for testing."""

            def create_executive_summary(self, data):
                from reportlab.platypus import Paragraph

                return [
                    Paragraph("Executive Summary", self.styles["h1"]),
                    Paragraph(
                        f"Total requirements: {len(data.requirements)}",
                        self.styles["normal"],
                    ),
                ]

            def create_charts_section(self, data):
                from reportlab.platypus import Image

                chart_buffer = create_vertical_bar_chart(
                    labels=["Pass", "Fail"],
                    values=[80, 20],
                )
                return [Image(chart_buffer, width=6 * inch, height=4 * inch)]

            def create_requirements_index(self, data):
                from reportlab.platypus import Paragraph

                elements = [Paragraph("Requirements Index", self.styles["h1"])]
                for req in data.requirements:
                    elements.append(
                        Paragraph(
                            f"- {req.id}: {req.description}", self.styles["normal"]
                        )
                    )
                return elements

        self.generator_class = ExampleGenerator

    def test_example_generator_creation(self):
        """Test creating example generator."""
        config = FrameworkConfig(name="example", display_name="Example Framework")
        generator = self.generator_class(config)
        assert generator is not None

    def test_example_generator_executive_summary(self):
        """Test executive summary generation."""
        config = FrameworkConfig(name="example", display_name="Example Framework")
        generator = self.generator_class(config)

        data = ComplianceData(
            tenant_id="t1",
            scan_id="s1",
            provider_id="p1",
            compliance_id="c1",
            framework="Test",
            name="Test",
            version="1.0",
            description="",
            requirements=[
                RequirementData(id="R1", description="Req 1", status="PASS"),
                RequirementData(id="R2", description="Req 2", status="FAIL"),
            ],
        )

        elements = generator.create_executive_summary(data)
        assert len(elements) == 2

    def test_example_generator_charts_section(self):
        """Test charts section generation."""
        config = FrameworkConfig(name="example", display_name="Example Framework")
        generator = self.generator_class(config)

        data = ComplianceData(
            tenant_id="t1",
            scan_id="s1",
            provider_id="p1",
            compliance_id="c1",
            framework="Test",
            name="Test",
            version="1.0",
            description="",
        )

        elements = generator.create_charts_section(data)
        assert len(elements) == 1

    def test_example_generator_requirements_index(self):
        """Test requirements index generation."""
        config = FrameworkConfig(name="example", display_name="Example Framework")
        generator = self.generator_class(config)

        data = ComplianceData(
            tenant_id="t1",
            scan_id="s1",
            provider_id="p1",
            compliance_id="c1",
            framework="Test",
            name="Test",
            version="1.0",
            description="",
            requirements=[
                RequirementData(id="R1", description="Requirement 1", status="PASS"),
            ],
        )

        elements = generator.create_requirements_index(data)
        assert len(elements) == 2  # Header + 1 requirement
