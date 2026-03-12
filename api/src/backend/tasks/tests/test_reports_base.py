import io

import pytest
from reportlab.lib.units import inch
from reportlab.platypus import Image, LongTable, Paragraph, Spacer, Table
from tasks.jobs.reports import (  # Configuration; Colors; Components; Charts; Base
    CHART_COLOR_GREEN_1,
    CHART_COLOR_GREEN_2,
    CHART_COLOR_ORANGE,
    CHART_COLOR_RED,
    CHART_COLOR_YELLOW,
    COLOR_BLUE,
    COLOR_DARK_GRAY,
    COLOR_HIGH_RISK,
    COLOR_LOW_RISK,
    COLOR_MEDIUM_RISK,
    COLOR_SAFE,
    FRAMEWORK_REGISTRY,
    BaseComplianceReportGenerator,
    ColumnConfig,
    ComplianceData,
    FrameworkConfig,
    RequirementData,
    create_badge,
    create_data_table,
    create_findings_table,
    create_horizontal_bar_chart,
    create_info_table,
    create_multi_badge_row,
    create_pdf_styles,
    create_pie_chart,
    create_radar_chart,
    create_risk_component,
    create_section_header,
    create_stacked_bar_chart,
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

    def test_get_color_for_risk_level_very_high(self):
        """Test very high risk level (>5) still returns high risk color."""
        assert get_color_for_risk_level(10) == COLOR_HIGH_RISK
        assert get_color_for_risk_level(100) == COLOR_HIGH_RISK

    def test_get_color_for_risk_level_medium(self):
        """Test medium risk level returns orange."""
        assert get_color_for_risk_level(3) == COLOR_MEDIUM_RISK

    def test_get_color_for_risk_level_low(self):
        """Test low risk level returns yellow."""
        assert get_color_for_risk_level(2) == COLOR_LOW_RISK

    def test_get_color_for_risk_level_safe(self):
        """Test safe risk level returns green."""
        assert get_color_for_risk_level(1) == COLOR_SAFE
        assert get_color_for_risk_level(0) == COLOR_SAFE

    def test_get_color_for_risk_level_negative(self):
        """Test negative risk level returns safe color."""
        assert get_color_for_risk_level(-1) == COLOR_SAFE

    def test_get_color_for_weight_high(self):
        """Test high weight returns red."""
        assert get_color_for_weight(150) == COLOR_HIGH_RISK
        assert get_color_for_weight(101) == COLOR_HIGH_RISK

    def test_get_color_for_weight_medium(self):
        """Test medium weight returns yellow."""
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
        assert get_status_color("MANUAL") == COLOR_DARK_GRAY


class TestChartColorHelpers:
    """Tests for chart color functions."""

    def test_chart_color_for_high_percentage(self):
        """Test high percentage returns green."""
        assert get_chart_color_for_percentage(100) == CHART_COLOR_GREEN_1
        assert get_chart_color_for_percentage(80) == CHART_COLOR_GREEN_1

    def test_chart_color_for_medium_high_percentage(self):
        """Test medium-high percentage returns light green."""
        assert get_chart_color_for_percentage(79) == CHART_COLOR_GREEN_2
        assert get_chart_color_for_percentage(60) == CHART_COLOR_GREEN_2

    def test_chart_color_for_medium_percentage(self):
        """Test medium percentage returns yellow."""
        assert get_chart_color_for_percentage(59) == CHART_COLOR_YELLOW
        assert get_chart_color_for_percentage(40) == CHART_COLOR_YELLOW

    def test_chart_color_for_medium_low_percentage(self):
        """Test medium-low percentage returns orange."""
        assert get_chart_color_for_percentage(39) == CHART_COLOR_ORANGE
        assert get_chart_color_for_percentage(20) == CHART_COLOR_ORANGE

    def test_chart_color_for_low_percentage(self):
        """Test low percentage returns red."""
        assert get_chart_color_for_percentage(19) == CHART_COLOR_RED
        assert get_chart_color_for_percentage(0) == CHART_COLOR_RED

    def test_chart_color_boundary_values(self):
        """Test chart color at exact boundary values."""
        # Exact boundaries
        assert get_chart_color_for_percentage(80) == CHART_COLOR_GREEN_1
        assert get_chart_color_for_percentage(60) == CHART_COLOR_GREEN_2
        assert get_chart_color_for_percentage(40) == CHART_COLOR_YELLOW
        assert get_chart_color_for_percentage(20) == CHART_COLOR_ORANGE


# =============================================================================
# Component Tests
# =============================================================================


class TestBadgeComponents:
    """Tests for badge component functions."""

    def test_create_badge_returns_table(self):
        """Test create_badge returns a Table object."""
        badge = create_badge("Test", COLOR_BLUE)
        assert isinstance(badge, Table)

    def test_create_badge_with_custom_width(self):
        """Test create_badge with custom width."""
        badge = create_badge("Test", COLOR_BLUE, width=2 * inch)
        assert badge is not None

    def test_create_status_badge_pass(self):
        """Test status badge for PASS."""
        badge = create_status_badge("PASS")
        assert isinstance(badge, Table)

    def test_create_status_badge_fail(self):
        """Test status badge for FAIL."""
        badge = create_status_badge("FAIL")
        assert badge is not None

    def test_create_multi_badge_row_with_badges(self):
        """Test multi-badge row with data."""
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
        table = create_summary_table(
            label="Score:",
            value="85%",
            value_color=COLOR_SAFE,
        )
        assert isinstance(table, Table)

    def test_create_summary_table_with_custom_widths(self):
        """Test summary table with custom widths."""
        table = create_summary_table(
            label="ThreatScore:",
            value="92.5%",
            value_color=COLOR_SAFE,
            label_width=3 * inch,
            value_width=2.5 * inch,
        )
        assert isinstance(table, Table)


class TestFindingsTable:
    """Tests for findings table component."""

    def test_create_findings_table_with_dicts(self):
        """Test findings table creation with dict data."""
        findings = [
            {
                "title": "Finding 1",
                "resource_name": "resource-1",
                "severity": "HIGH",
                "status": "FAIL",
                "region": "us-east-1",
            },
            {
                "title": "Finding 2",
                "resource_name": "resource-2",
                "severity": "LOW",
                "status": "PASS",
                "region": "eu-west-1",
            },
        ]
        table = create_findings_table(findings)
        assert isinstance(table, Table)

    def test_create_findings_table_with_custom_columns(self):
        """Test findings table with custom column configuration."""
        findings = [{"name": "Test", "value": "100"}]
        columns = [
            ColumnConfig("Name", 2 * inch, "name"),
            ColumnConfig("Value", 1 * inch, "value"),
        ]
        table = create_findings_table(findings, columns=columns)
        assert table is not None

    def test_create_findings_table_empty(self):
        """Test findings table with empty list."""
        table = create_findings_table([])
        assert table is not None


class TestSectionHeader:
    """Tests for section header component."""

    def test_create_section_header_with_spacer(self):
        """Test section header with spacer."""
        styles = create_pdf_styles()
        elements = create_section_header("Test Header", styles["h1"])

        assert len(elements) == 2
        assert isinstance(elements[0], Paragraph)
        assert isinstance(elements[1], Spacer)

    def test_create_section_header_without_spacer(self):
        """Test section header without spacer."""
        styles = create_pdf_styles()
        elements = create_section_header("Test Header", styles["h1"], add_spacer=False)

        assert len(elements) == 1
        assert isinstance(elements[0], Paragraph)

    def test_create_section_header_custom_spacer_height(self):
        """Test section header with custom spacer height."""
        styles = create_pdf_styles()
        elements = create_section_header("Test Header", styles["h2"], spacer_height=0.5)

        assert len(elements) == 2


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

    def test_create_pie_chart_with_options(self):
        """Test pie chart with custom options."""
        buffer = create_pie_chart(
            labels=["Pass", "Fail", "Manual"],
            values=[60, 30, 10],
            colors=["#4CAF50", "#F44336", "#9E9E9E"],
            title="Status Distribution",
            autopct="%1.0f%%",
        )
        assert isinstance(buffer, io.BytesIO)

    def test_create_stacked_bar_chart(self):
        """Test stacked bar chart creation."""
        buffer = create_stacked_bar_chart(
            labels=["Section 1", "Section 2", "Section 3"],
            data_series={
                "Pass": [8, 6, 4],
                "Fail": [2, 4, 6],
            },
        )
        assert isinstance(buffer, io.BytesIO)
        assert buffer.getvalue()

    def test_create_stacked_bar_chart_with_options(self):
        """Test stacked bar chart with custom options."""
        buffer = create_stacked_bar_chart(
            labels=["A", "B"],
            data_series={
                "Pass": [10, 5],
                "Fail": [2, 3],
                "Manual": [1, 2],
            },
            colors={
                "Pass": "#4CAF50",
                "Fail": "#F44336",
                "Manual": "#9E9E9E",
            },
            xlabel="Categories",
            ylabel="Requirements",
            title="Requirements by Status",
        )
        assert isinstance(buffer, io.BytesIO)

    def test_create_stacked_bar_chart_without_legend(self):
        """Test stacked bar chart without legend."""
        buffer = create_stacked_bar_chart(
            labels=["X", "Y"],
            data_series={"A": [1, 2]},
            show_legend=False,
        )
        assert isinstance(buffer, io.BytesIO)

    def test_create_vertical_bar_chart_without_labels(self):
        """Test vertical bar chart without value labels."""
        buffer = create_vertical_bar_chart(
            labels=["A", "B"],
            values=[50, 75],
            show_labels=False,
        )
        assert isinstance(buffer, io.BytesIO)

    def test_create_vertical_bar_chart_with_explicit_colors(self):
        """Test vertical bar chart with explicit color list."""
        buffer = create_vertical_bar_chart(
            labels=["Pass", "Fail"],
            values=[80, 20],
            colors=["#4CAF50", "#F44336"],
        )
        assert isinstance(buffer, io.BytesIO)

    def test_create_horizontal_bar_chart_auto_figsize(self):
        """Test horizontal bar chart auto-calculates figure size for many items."""
        labels = [f"Item {i}" for i in range(20)]
        values = [50 + i * 2 for i in range(20)]
        buffer = create_horizontal_bar_chart(
            labels=labels,
            values=values,
        )
        assert isinstance(buffer, io.BytesIO)

    def test_create_horizontal_bar_chart_with_explicit_colors(self):
        """Test horizontal bar chart with explicit colors."""
        buffer = create_horizontal_bar_chart(
            labels=["A", "B", "C"],
            values=[80, 60, 40],
            colors=["#4CAF50", "#FFEB3B", "#F44336"],
        )
        assert isinstance(buffer, io.BytesIO)

    def test_create_radar_chart_with_custom_ticks(self):
        """Test radar chart with custom y-axis ticks."""
        buffer = create_radar_chart(
            labels=["A", "B", "C", "D"],
            values=[25, 50, 75, 100],
            y_ticks=[0, 25, 50, 75, 100],
        )
        assert isinstance(buffer, io.BytesIO)


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

    def test_requirement_data_with_failed_findings(self):
        """Test RequirementData with failed findings."""
        req = RequirementData(
            id="REQ-002",
            description="Failed requirement",
            status="FAIL",
            passed_findings=3,
            failed_findings=7,
            total_findings=10,
        )
        assert req.failed_findings == 7
        assert req.total_findings == 10

    def test_requirement_data_defaults(self):
        """Test RequirementData default values."""
        req = RequirementData(
            id="REQ-003",
            description="Minimal requirement",
            status="MANUAL",
        )
        assert req.passed_findings == 0
        assert req.failed_findings == 0
        assert req.total_findings == 0

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

    def test_compliance_data_with_requirements(self):
        """Test ComplianceData with requirements list."""
        reqs = [
            RequirementData(id="R1", description="Req 1", status="PASS"),
            RequirementData(id="R2", description="Req 2", status="FAIL"),
        ]
        data = ComplianceData(
            tenant_id="t1",
            scan_id="s1",
            provider_id="p1",
            compliance_id="c1",
            framework="Test",
            name="Test",
            version="1.0",
            description="",
            requirements=reqs,
        )
        assert len(data.requirements) == 2
        assert data.requirements[0].id == "R1"

    def test_compliance_data_with_attributes(self):
        """Test ComplianceData with attributes dictionary."""
        data = ComplianceData(
            tenant_id="t1",
            scan_id="s1",
            provider_id="p1",
            compliance_id="c1",
            framework="Test",
            name="Test",
            version="1.0",
            description="",
            attributes_by_requirement_id={
                "R1": {"attributes": {"key": "value"}},
            },
        )
        assert "R1" in data.attributes_by_requirement_id
        assert data.attributes_by_requirement_id["R1"]["attributes"]["key"] == "value"


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


class TestBuildInfoRows:
    """Tests for _build_info_rows helper method."""

    def _create_generator(self, language="en"):
        """Create a concrete generator for testing."""

        class ConcreteGenerator(BaseComplianceReportGenerator):
            def create_executive_summary(self, data):
                return []

            def create_charts_section(self, data):
                return []

            def create_requirements_index(self, data):
                return []

        config = FrameworkConfig(name="test", display_name="Test", language=language)
        return ConcreteGenerator(config)

    def test_build_info_rows_english(self):
        """Test info rows are built with English labels."""
        generator = self._create_generator(language="en")
        data = ComplianceData(
            tenant_id="t1",
            scan_id="scan-123",
            provider_id="p1",
            compliance_id="test_compliance",
            framework="Test Framework",
            name="Test Name",
            version="1.0",
            description="Test description",
        )

        rows = generator._build_info_rows(data, language="en")

        assert ("Framework:", "Test Framework") in rows
        assert ("Name:", "Test Name") in rows
        assert ("Version:", "1.0") in rows
        assert ("Scan ID:", "scan-123") in rows
        assert ("Description:", "Test description") in rows

    def test_build_info_rows_spanish(self):
        """Test info rows are built with Spanish labels."""
        generator = self._create_generator(language="es")
        data = ComplianceData(
            tenant_id="t1",
            scan_id="scan-123",
            provider_id="p1",
            compliance_id="test_compliance",
            framework="Test Framework",
            name="Test Name",
            version="1.0",
            description="Test description",
        )

        rows = generator._build_info_rows(data, language="es")

        assert ("Framework:", "Test Framework") in rows
        assert ("Nombre:", "Test Name") in rows
        assert ("Versión:", "1.0") in rows
        assert ("Scan ID:", "scan-123") in rows
        assert ("Descripción:", "Test description") in rows

    def test_build_info_rows_with_provider(self):
        """Test info rows include provider info when available."""
        from unittest.mock import Mock

        generator = self._create_generator(language="en")

        mock_provider = Mock()
        mock_provider.provider = "aws"
        mock_provider.uid = "123456789012"
        mock_provider.alias = "my-account"

        data = ComplianceData(
            tenant_id="t1",
            scan_id="scan-123",
            provider_id="p1",
            compliance_id="test_compliance",
            framework="Test",
            name="Test",
            version="1.0",
            description="",
            provider_obj=mock_provider,
        )

        rows = generator._build_info_rows(data, language="en")

        assert ("Provider:", "AWS") in rows
        assert ("Account ID:", "123456789012") in rows
        assert ("Alias:", "my-account") in rows

    def test_build_info_rows_with_provider_spanish(self):
        """Test provider info uses Spanish labels."""
        from unittest.mock import Mock

        generator = self._create_generator(language="es")

        mock_provider = Mock()
        mock_provider.provider = "azure"
        mock_provider.uid = "subscription-id"
        mock_provider.alias = "mi-suscripcion"

        data = ComplianceData(
            tenant_id="t1",
            scan_id="scan-123",
            provider_id="p1",
            compliance_id="test_compliance",
            framework="Test",
            name="Test",
            version="1.0",
            description="",
            provider_obj=mock_provider,
        )

        rows = generator._build_info_rows(data, language="es")

        assert ("Proveedor:", "AZURE") in rows
        assert ("Account ID:", "subscription-id") in rows
        assert ("Alias:", "mi-suscripcion") in rows

    def test_build_info_rows_without_provider(self):
        """Test info rows work without provider info."""
        generator = self._create_generator(language="en")
        data = ComplianceData(
            tenant_id="t1",
            scan_id="scan-123",
            provider_id="p1",
            compliance_id="test_compliance",
            framework="Test",
            name="Test",
            version="1.0",
            description="",
            provider_obj=None,
        )

        rows = generator._build_info_rows(data, language="en")

        # Provider info should not be present
        labels = [label for label, _ in rows]
        assert "Provider:" not in labels
        assert "Account ID:" not in labels
        assert "Alias:" not in labels

    def test_build_info_rows_provider_with_missing_fields(self):
        """Test provider info handles None values gracefully."""
        from unittest.mock import Mock

        generator = self._create_generator(language="en")

        mock_provider = Mock()
        mock_provider.provider = "gcp"
        mock_provider.uid = None
        mock_provider.alias = None

        data = ComplianceData(
            tenant_id="t1",
            scan_id="scan-123",
            provider_id="p1",
            compliance_id="test_compliance",
            framework="Test",
            name="Test",
            version="1.0",
            description="",
            provider_obj=mock_provider,
        )

        rows = generator._build_info_rows(data, language="en")

        assert ("Provider:", "GCP") in rows
        assert ("Account ID:", "N/A") in rows
        assert ("Alias:", "N/A") in rows

    def test_build_info_rows_without_description(self):
        """Test info rows exclude description when empty."""
        generator = self._create_generator(language="en")
        data = ComplianceData(
            tenant_id="t1",
            scan_id="scan-123",
            provider_id="p1",
            compliance_id="test_compliance",
            framework="Test",
            name="Test",
            version="1.0",
            description="",
        )

        rows = generator._build_info_rows(data, language="en")

        labels = [label for label, _ in rows]
        assert "Description:" not in labels

    def test_build_info_rows_defaults_to_english(self):
        """Test unknown language defaults to English labels."""
        generator = self._create_generator(language="en")
        data = ComplianceData(
            tenant_id="t1",
            scan_id="scan-123",
            provider_id="p1",
            compliance_id="test_compliance",
            framework="Test",
            name="Test",
            version="1.0",
            description="Desc",
        )

        rows = generator._build_info_rows(data, language="fr")  # Unknown language

        # Should use English labels as fallback
        assert ("Name:", "Test") in rows
        assert ("Description:", "Desc") in rows


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
                return [
                    Paragraph("Executive Summary", self.styles["h1"]),
                    Paragraph(
                        f"Total requirements: {len(data.requirements)}",
                        self.styles["normal"],
                    ),
                ]

            def create_charts_section(self, data):
                chart_buffer = create_vertical_bar_chart(
                    labels=["Pass", "Fail"],
                    values=[80, 20],
                )
                return [Image(chart_buffer, width=6 * inch, height=4 * inch)]

            def create_requirements_index(self, data):
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


# =============================================================================
# Edge Case Tests
# =============================================================================


class TestChartEdgeCases:
    """Tests for chart edge cases."""

    def test_vertical_bar_chart_empty_data(self):
        """Test vertical bar chart with empty data."""
        buffer = create_vertical_bar_chart(labels=[], values=[])
        assert isinstance(buffer, io.BytesIO)

    def test_vertical_bar_chart_single_item(self):
        """Test vertical bar chart with single item."""
        buffer = create_vertical_bar_chart(labels=["Single"], values=[75.0])
        assert isinstance(buffer, io.BytesIO)

    def test_horizontal_bar_chart_empty_data(self):
        """Test horizontal bar chart with empty data."""
        buffer = create_horizontal_bar_chart(labels=[], values=[])
        assert isinstance(buffer, io.BytesIO)

    def test_horizontal_bar_chart_single_item(self):
        """Test horizontal bar chart with single item."""
        buffer = create_horizontal_bar_chart(labels=["Single"], values=[50.0])
        assert isinstance(buffer, io.BytesIO)

    def test_radar_chart_minimum_points(self):
        """Test radar chart with minimum number of points (3)."""
        buffer = create_radar_chart(
            labels=["A", "B", "C"],
            values=[30.0, 60.0, 90.0],
        )
        assert isinstance(buffer, io.BytesIO)

    def test_pie_chart_single_slice(self):
        """Test pie chart with single slice."""
        buffer = create_pie_chart(labels=["Only"], values=[100.0])
        assert isinstance(buffer, io.BytesIO)

    def test_pie_chart_many_slices(self):
        """Test pie chart with many slices."""
        labels = [f"Item {i}" for i in range(10)]
        values = [10.0] * 10
        buffer = create_pie_chart(labels=labels, values=values)
        assert isinstance(buffer, io.BytesIO)

    def test_stacked_bar_chart_single_series(self):
        """Test stacked bar chart with single series."""
        buffer = create_stacked_bar_chart(
            labels=["A", "B"],
            data_series={"Only": [10.0, 20.0]},
        )
        assert isinstance(buffer, io.BytesIO)

    def test_stacked_bar_chart_empty_data(self):
        """Test stacked bar chart with empty data."""
        buffer = create_stacked_bar_chart(labels=[], data_series={})
        assert isinstance(buffer, io.BytesIO)


class TestComponentEdgeCases:
    """Tests for component edge cases."""

    def test_create_badge_empty_text(self):
        """Test badge with empty text."""
        badge = create_badge("", COLOR_BLUE)
        assert badge is not None

    def test_create_badge_long_text(self):
        """Test badge with very long text."""
        long_text = "A" * 100
        badge = create_badge(long_text, COLOR_BLUE, width=5 * inch)
        assert badge is not None

    def test_create_status_badge_unknown_status(self):
        """Test status badge with unknown status."""
        badge = create_status_badge("UNKNOWN")
        assert badge is not None

    def test_create_multi_badge_row_single_badge(self):
        """Test multi-badge row with single badge."""
        badges = [("A", COLOR_BLUE)]
        table = create_multi_badge_row(badges)
        assert table is not None

    def test_create_multi_badge_row_many_badges(self):
        """Test multi-badge row with many badges."""
        badges = [(chr(65 + i), COLOR_BLUE) for i in range(10)]  # A-J
        table = create_multi_badge_row(badges)
        assert table is not None

    def test_create_info_table_empty(self):
        """Test info table with empty rows."""
        table = create_info_table([])
        assert isinstance(table, Table)

    def test_create_info_table_long_values(self):
        """Test info table with very long values wraps properly."""
        rows = [
            ("Key:", "A" * 200),  # Very long value
        ]
        styles = create_pdf_styles()
        table = create_info_table(rows, normal_style=styles["normal"])
        assert table is not None

    def test_create_data_table_empty(self):
        """Test data table with empty data."""
        columns = [
            ColumnConfig("Name", 2 * inch, "name"),
        ]
        table = create_data_table([], columns)
        assert table is not None

    def test_create_data_table_large_dataset(self):
        """Test data table with large dataset uses LongTable."""
        # Create more than 50 rows to trigger LongTable
        data = [{"name": f"Item {i}"} for i in range(60)]
        columns = [ColumnConfig("Name", 2 * inch, "name")]
        table = create_data_table(data, columns)
        # Should be a LongTable for large datasets
        assert isinstance(table, LongTable)

    def test_create_risk_component_zero_values(self):
        """Test risk component with zero values."""
        component = create_risk_component(risk_level=0, weight=0, score=0)
        assert component is not None

    def test_create_risk_component_max_values(self):
        """Test risk component with maximum values."""
        component = create_risk_component(risk_level=5, weight=200, score=1000)
        assert component is not None


class TestColorEdgeCases:
    """Tests for color function edge cases."""

    def test_get_color_for_compliance_boundary_80(self):
        """Test compliance color at exactly 80%."""
        assert get_color_for_compliance(80) == COLOR_SAFE

    def test_get_color_for_compliance_boundary_60(self):
        """Test compliance color at exactly 60%."""
        assert get_color_for_compliance(60) == COLOR_LOW_RISK

    def test_get_color_for_compliance_over_100(self):
        """Test compliance color for values over 100."""
        assert get_color_for_compliance(150) == COLOR_SAFE

    def test_get_color_for_weight_boundary_100(self):
        """Test weight color at exactly 100."""
        assert get_color_for_weight(100) == COLOR_LOW_RISK

    def test_get_color_for_weight_boundary_50(self):
        """Test weight color at exactly 50."""
        assert get_color_for_weight(50) == COLOR_SAFE

    def test_get_status_color_case_insensitive(self):
        """Test that status color is case insensitive."""
        assert get_status_color("PASS") == get_status_color("pass")
        assert get_status_color("FAIL") == get_status_color("Fail")
        assert get_status_color("MANUAL") == get_status_color("manual")


class TestFrameworkConfigEdgeCases:
    """Tests for FrameworkConfig edge cases."""

    def test_framework_config_empty_sections(self):
        """Test FrameworkConfig with empty sections list."""
        config = FrameworkConfig(
            name="test",
            display_name="Test",
            sections=[],
        )
        assert config.sections == []

    def test_framework_config_empty_attribute_fields(self):
        """Test FrameworkConfig with empty attribute fields."""
        config = FrameworkConfig(
            name="test",
            display_name="Test",
            attribute_fields=[],
        )
        assert config.attribute_fields == []

    def test_get_framework_config_case_variations(self):
        """Test get_framework_config with different case variations."""
        # Test case insensitivity
        assert get_framework_config("PROWLER_THREATSCORE_AWS") is not None
        assert get_framework_config("ENS_RD2022_AWS") is not None
        assert get_framework_config("NIS2_AWS") is not None

    def test_get_framework_config_partial_match(self):
        """Test that partial matches work correctly."""
        # Should match based on substring
        assert get_framework_config("my_custom_threatscore_compliance") is not None
        assert get_framework_config("ens_something_else") is not None
        assert get_framework_config("nis2_gcp") is not None
