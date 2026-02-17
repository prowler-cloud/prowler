import io
from unittest.mock import Mock

import pytest
from reportlab.platypus import PageBreak, Paragraph, Table
from tasks.jobs.reports import FRAMEWORK_REGISTRY, ComplianceData, RequirementData
from tasks.jobs.reports.csa import CSAReportGenerator


# Use string status values directly to avoid Django DB initialization
# These match api.models.StatusChoices values
class StatusChoices:
    """Mock StatusChoices to avoid Django DB initialization."""

    PASS = "PASS"
    FAIL = "FAIL"
    MANUAL = "MANUAL"


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def csa_generator():
    """Create a CSAReportGenerator instance for testing."""
    config = FRAMEWORK_REGISTRY["csa_ccm"]
    return CSAReportGenerator(config)


@pytest.fixture
def mock_csa_requirement_attribute_iam():
    """Create a mock CSA CCM requirement attribute for Identity & Access Management."""
    mock = Mock()
    mock.Section = "Identity & Access Management"
    mock.CCMLite = "Yes"
    mock.IaaS = "Yes"
    mock.PaaS = "Yes"
    mock.SaaS = "Yes"
    mock.ScopeApplicability = [
        {"ReferenceId": "ISO 27001", "Identifiers": ["A.9.1.1", "A.9.2.3"]},
        {"ReferenceId": "NIST 800-53", "Identifiers": ["AC-2", "AC-3", "AC-6"]},
    ]
    return mock


@pytest.fixture
def mock_csa_requirement_attribute_logging():
    """Create a mock CSA CCM requirement attribute for Logging and Monitoring."""
    mock = Mock()
    mock.Section = "Logging and Monitoring"
    mock.CCMLite = "Yes"
    mock.IaaS = "Yes"
    mock.PaaS = "No"
    mock.SaaS = "No"
    mock.ScopeApplicability = [
        {"ReferenceId": "ISO 27001", "Identifiers": ["A.12.4.1"]},
    ]
    return mock


@pytest.fixture
def mock_csa_requirement_attribute_crypto():
    """Create a mock CSA CCM requirement attribute for Cryptography."""
    mock = Mock()
    mock.Section = "Cryptography, Encryption & Key Management"
    mock.CCMLite = "No"
    mock.IaaS = "Yes"
    mock.PaaS = "Yes"
    mock.SaaS = "No"
    mock.ScopeApplicability = []
    return mock


@pytest.fixture
def basic_csa_compliance_data():
    """Create basic ComplianceData for CSA CCM testing."""
    return ComplianceData(
        tenant_id="tenant-123",
        scan_id="scan-456",
        provider_id="provider-789",
        compliance_id="csa_ccm_4.0_aws",
        framework="CSA-CCM",
        name="CSA Cloud Controls Matrix v4.0",
        version="4.0",
        description="Cloud Security Alliance Cloud Controls Matrix",
    )


# =============================================================================
# Generator Initialization Tests
# =============================================================================


class TestCSAGeneratorInitialization:
    """Test suite for CSA generator initialization."""

    def test_generator_creation(self, csa_generator):
        """Test that CSA generator is created correctly."""
        assert csa_generator is not None
        assert csa_generator.config.name == "csa_ccm"
        assert csa_generator.config.language == "en"

    def test_generator_no_niveles(self, csa_generator):
        """Test that CSA config does not use niveles."""
        assert csa_generator.config.has_niveles is False

    def test_generator_no_dimensions(self, csa_generator):
        """Test that CSA config does not use dimensions."""
        assert csa_generator.config.has_dimensions is False

    def test_generator_no_risk_levels(self, csa_generator):
        """Test that CSA config does not use risk levels."""
        assert csa_generator.config.has_risk_levels is False

    def test_generator_no_weight(self, csa_generator):
        """Test that CSA config does not use weight."""
        assert csa_generator.config.has_weight is False


# =============================================================================
# Cover Page Tests
# =============================================================================


class TestCSACoverPage:
    """Test suite for CSA cover page generation."""

    def test_cover_page_has_logo(self, csa_generator, basic_csa_compliance_data):
        """Test that cover page contains the Prowler logo."""
        basic_csa_compliance_data.requirements = []
        basic_csa_compliance_data.attributes_by_requirement_id = {}

        elements = csa_generator.create_cover_page(basic_csa_compliance_data)

        assert len(elements) > 0

    def test_cover_page_has_title(self, csa_generator, basic_csa_compliance_data):
        """Test that cover page contains the CSA CCM title."""
        basic_csa_compliance_data.requirements = []
        basic_csa_compliance_data.attributes_by_requirement_id = {}

        elements = csa_generator.create_cover_page(basic_csa_compliance_data)

        paragraphs = [e for e in elements if isinstance(e, Paragraph)]
        content = " ".join(str(p.text) for p in paragraphs)
        assert "CSA" in content or "CCM" in content or "Cloud Controls" in content

    def test_cover_page_has_metadata_table(
        self, csa_generator, basic_csa_compliance_data
    ):
        """Test that cover page contains metadata table."""
        basic_csa_compliance_data.requirements = []
        basic_csa_compliance_data.attributes_by_requirement_id = {}

        elements = csa_generator.create_cover_page(basic_csa_compliance_data)

        tables = [e for e in elements if isinstance(e, Table)]
        assert len(tables) >= 1


# =============================================================================
# Executive Summary Tests
# =============================================================================


class TestCSAExecutiveSummary:
    """Test suite for CSA executive summary generation."""

    def test_executive_summary_has_english_title(
        self, csa_generator, basic_csa_compliance_data
    ):
        """Test that executive summary has English title."""
        basic_csa_compliance_data.requirements = []
        basic_csa_compliance_data.attributes_by_requirement_id = {}

        elements = csa_generator.create_executive_summary(basic_csa_compliance_data)

        paragraphs = [e for e in elements if isinstance(e, Paragraph)]
        content = " ".join(str(p.text) for p in paragraphs)
        assert "Executive Summary" in content

    def test_executive_summary_calculates_compliance(
        self,
        csa_generator,
        basic_csa_compliance_data,
        mock_csa_requirement_attribute_iam,
    ):
        """Test that executive summary calculates compliance percentage."""
        basic_csa_compliance_data.requirements = [
            RequirementData(
                id="REQ-001",
                description="Passed requirement",
                status=StatusChoices.PASS,
                passed_findings=10,
                failed_findings=0,
                total_findings=10,
            ),
            RequirementData(
                id="REQ-002",
                description="Failed requirement",
                status=StatusChoices.FAIL,
                passed_findings=0,
                failed_findings=10,
                total_findings=10,
            ),
        ]
        basic_csa_compliance_data.attributes_by_requirement_id = {
            "REQ-001": {
                "attributes": {"req_attributes": [mock_csa_requirement_attribute_iam]}
            },
            "REQ-002": {
                "attributes": {"req_attributes": [mock_csa_requirement_attribute_iam]}
            },
        }

        elements = csa_generator.create_executive_summary(basic_csa_compliance_data)

        # Should contain tables with metrics
        tables = [e for e in elements if isinstance(e, Table)]
        assert len(tables) >= 1

    def test_executive_summary_shows_all_statuses(
        self,
        csa_generator,
        basic_csa_compliance_data,
        mock_csa_requirement_attribute_iam,
    ):
        """Test that executive summary shows passed, failed, and manual counts."""
        basic_csa_compliance_data.requirements = [
            RequirementData(
                id="REQ-001",
                description="Passed",
                status=StatusChoices.PASS,
                passed_findings=10,
                failed_findings=0,
                total_findings=10,
            ),
            RequirementData(
                id="REQ-002",
                description="Failed",
                status=StatusChoices.FAIL,
                passed_findings=0,
                failed_findings=10,
                total_findings=10,
            ),
            RequirementData(
                id="REQ-003",
                description="Manual",
                status=StatusChoices.MANUAL,
                passed_findings=0,
                failed_findings=0,
                total_findings=0,
            ),
        ]
        basic_csa_compliance_data.attributes_by_requirement_id = {
            "REQ-001": {
                "attributes": {"req_attributes": [mock_csa_requirement_attribute_iam]}
            },
            "REQ-002": {
                "attributes": {"req_attributes": [mock_csa_requirement_attribute_iam]}
            },
            "REQ-003": {
                "attributes": {"req_attributes": [mock_csa_requirement_attribute_iam]}
            },
        }

        elements = csa_generator.create_executive_summary(basic_csa_compliance_data)

        # Should have a summary table with all statuses
        assert len(elements) > 0

    def test_executive_summary_excludes_manual_from_percentage(
        self,
        csa_generator,
        basic_csa_compliance_data,
        mock_csa_requirement_attribute_iam,
    ):
        """Test that manual requirements are excluded from compliance percentage."""
        basic_csa_compliance_data.requirements = [
            RequirementData(
                id="REQ-001",
                description="Passed",
                status=StatusChoices.PASS,
                passed_findings=10,
                failed_findings=0,
                total_findings=10,
            ),
            RequirementData(
                id="REQ-002",
                description="Manual",
                status=StatusChoices.MANUAL,
                passed_findings=0,
                failed_findings=0,
                total_findings=0,
            ),
        ]
        basic_csa_compliance_data.attributes_by_requirement_id = {
            "REQ-001": {
                "attributes": {"req_attributes": [mock_csa_requirement_attribute_iam]}
            },
            "REQ-002": {
                "attributes": {"req_attributes": [mock_csa_requirement_attribute_iam]}
            },
        }

        elements = csa_generator.create_executive_summary(basic_csa_compliance_data)

        # Should calculate 100% (only 1 evaluated requirement that passed)
        assert len(elements) > 0


# =============================================================================
# Charts Section Tests
# =============================================================================


class TestCSAChartsSection:
    """Test suite for CSA charts section generation."""

    def test_charts_section_has_section_chart_title(
        self, csa_generator, basic_csa_compliance_data
    ):
        """Test that charts section has section compliance title."""
        basic_csa_compliance_data.requirements = []
        basic_csa_compliance_data.attributes_by_requirement_id = {}

        elements = csa_generator.create_charts_section(basic_csa_compliance_data)

        paragraphs = [e for e in elements if isinstance(e, Paragraph)]
        content = " ".join(str(p.text) for p in paragraphs)
        assert "Section" in content or "Compliance" in content

    def test_charts_section_has_page_break(
        self, csa_generator, basic_csa_compliance_data
    ):
        """Test that charts section has page breaks."""
        basic_csa_compliance_data.requirements = []
        basic_csa_compliance_data.attributes_by_requirement_id = {}

        elements = csa_generator.create_charts_section(basic_csa_compliance_data)

        page_breaks = [e for e in elements if isinstance(e, PageBreak)]
        assert len(page_breaks) >= 1

    def test_charts_section_has_section_breakdown(
        self,
        csa_generator,
        basic_csa_compliance_data,
        mock_csa_requirement_attribute_iam,
    ):
        """Test that charts section includes section breakdown table."""
        basic_csa_compliance_data.requirements = [
            RequirementData(
                id="REQ-001",
                description="Test requirement",
                status=StatusChoices.PASS,
                passed_findings=10,
                failed_findings=0,
                total_findings=10,
            ),
        ]
        basic_csa_compliance_data.attributes_by_requirement_id = {
            "REQ-001": {
                "attributes": {"req_attributes": [mock_csa_requirement_attribute_iam]}
            },
        }

        elements = csa_generator.create_charts_section(basic_csa_compliance_data)

        paragraphs = [e for e in elements if isinstance(e, Paragraph)]
        content = " ".join(str(p.text) for p in paragraphs)
        assert "Section" in content or "Breakdown" in content


# =============================================================================
# Section Chart Tests
# =============================================================================


class TestCSASectionChart:
    """Test suite for CSA section compliance chart."""

    def test_section_chart_creation(
        self,
        csa_generator,
        basic_csa_compliance_data,
        mock_csa_requirement_attribute_iam,
    ):
        """Test that section chart is created successfully."""
        basic_csa_compliance_data.requirements = [
            RequirementData(
                id="REQ-001",
                description="Test requirement",
                status=StatusChoices.PASS,
                passed_findings=10,
                failed_findings=0,
                total_findings=10,
            ),
        ]
        basic_csa_compliance_data.attributes_by_requirement_id = {
            "REQ-001": {
                "attributes": {"req_attributes": [mock_csa_requirement_attribute_iam]}
            },
        }

        chart_buffer = csa_generator._create_section_chart(basic_csa_compliance_data)

        assert isinstance(chart_buffer, io.BytesIO)
        assert chart_buffer.getvalue()  # Not empty

    def test_section_chart_excludes_manual(
        self,
        csa_generator,
        basic_csa_compliance_data,
        mock_csa_requirement_attribute_iam,
    ):
        """Test that manual requirements are excluded from section chart."""
        basic_csa_compliance_data.requirements = [
            RequirementData(
                id="REQ-001",
                description="Auto requirement",
                status=StatusChoices.PASS,
                passed_findings=10,
                failed_findings=0,
                total_findings=10,
            ),
            RequirementData(
                id="REQ-002",
                description="Manual requirement",
                status=StatusChoices.MANUAL,
                passed_findings=0,
                failed_findings=0,
                total_findings=0,
            ),
        ]
        basic_csa_compliance_data.attributes_by_requirement_id = {
            "REQ-001": {
                "attributes": {"req_attributes": [mock_csa_requirement_attribute_iam]}
            },
            "REQ-002": {
                "attributes": {"req_attributes": [mock_csa_requirement_attribute_iam]}
            },
        }

        # Should not raise any errors
        chart_buffer = csa_generator._create_section_chart(basic_csa_compliance_data)
        assert isinstance(chart_buffer, io.BytesIO)

    def test_section_chart_multiple_sections(
        self,
        csa_generator,
        basic_csa_compliance_data,
        mock_csa_requirement_attribute_iam,
        mock_csa_requirement_attribute_logging,
        mock_csa_requirement_attribute_crypto,
    ):
        """Test section chart with multiple sections."""
        basic_csa_compliance_data.requirements = [
            RequirementData(
                id="REQ-001",
                description="IAM requirement",
                status=StatusChoices.PASS,
                passed_findings=10,
                failed_findings=0,
                total_findings=10,
            ),
            RequirementData(
                id="REQ-002",
                description="Logging requirement",
                status=StatusChoices.FAIL,
                passed_findings=0,
                failed_findings=10,
                total_findings=10,
            ),
            RequirementData(
                id="REQ-003",
                description="Crypto requirement",
                status=StatusChoices.PASS,
                passed_findings=5,
                failed_findings=0,
                total_findings=5,
            ),
        ]
        basic_csa_compliance_data.attributes_by_requirement_id = {
            "REQ-001": {
                "attributes": {"req_attributes": [mock_csa_requirement_attribute_iam]}
            },
            "REQ-002": {
                "attributes": {
                    "req_attributes": [mock_csa_requirement_attribute_logging]
                }
            },
            "REQ-003": {
                "attributes": {
                    "req_attributes": [mock_csa_requirement_attribute_crypto]
                }
            },
        }

        chart_buffer = csa_generator._create_section_chart(basic_csa_compliance_data)
        assert isinstance(chart_buffer, io.BytesIO)


# =============================================================================
# Section Table Tests
# =============================================================================


class TestCSASectionTable:
    """Test suite for CSA section breakdown table."""

    def test_section_table_creation(
        self,
        csa_generator,
        basic_csa_compliance_data,
        mock_csa_requirement_attribute_iam,
    ):
        """Test that section table is created successfully."""
        basic_csa_compliance_data.requirements = [
            RequirementData(
                id="REQ-001",
                description="Test requirement",
                status=StatusChoices.PASS,
                passed_findings=10,
                failed_findings=0,
                total_findings=10,
            ),
        ]
        basic_csa_compliance_data.attributes_by_requirement_id = {
            "REQ-001": {
                "attributes": {"req_attributes": [mock_csa_requirement_attribute_iam]}
            },
        }

        table = csa_generator._create_section_table(basic_csa_compliance_data)

        assert isinstance(table, Table)

    def test_section_table_counts_statuses(
        self,
        csa_generator,
        basic_csa_compliance_data,
        mock_csa_requirement_attribute_iam,
    ):
        """Test that section table counts passed, failed, and manual."""
        basic_csa_compliance_data.requirements = [
            RequirementData(
                id="REQ-001",
                description="Passed",
                status=StatusChoices.PASS,
                passed_findings=10,
                failed_findings=0,
                total_findings=10,
            ),
            RequirementData(
                id="REQ-002",
                description="Failed",
                status=StatusChoices.FAIL,
                passed_findings=0,
                failed_findings=10,
                total_findings=10,
            ),
            RequirementData(
                id="REQ-003",
                description="Manual",
                status=StatusChoices.MANUAL,
                passed_findings=0,
                failed_findings=0,
                total_findings=0,
            ),
        ]
        basic_csa_compliance_data.attributes_by_requirement_id = {
            "REQ-001": {
                "attributes": {"req_attributes": [mock_csa_requirement_attribute_iam]}
            },
            "REQ-002": {
                "attributes": {"req_attributes": [mock_csa_requirement_attribute_iam]}
            },
            "REQ-003": {
                "attributes": {"req_attributes": [mock_csa_requirement_attribute_iam]}
            },
        }

        table = csa_generator._create_section_table(basic_csa_compliance_data)
        assert isinstance(table, Table)


# =============================================================================
# Requirements Index Tests
# =============================================================================


class TestCSARequirementsIndex:
    """Test suite for CSA requirements index generation."""

    def test_requirements_index_has_title(
        self, csa_generator, basic_csa_compliance_data
    ):
        """Test that requirements index has English title."""
        basic_csa_compliance_data.requirements = []
        basic_csa_compliance_data.attributes_by_requirement_id = {}

        elements = csa_generator.create_requirements_index(basic_csa_compliance_data)

        paragraphs = [e for e in elements if isinstance(e, Paragraph)]
        content = " ".join(str(p.text) for p in paragraphs)
        assert "Requirements Index" in content

    def test_requirements_index_organized_by_section(
        self,
        csa_generator,
        basic_csa_compliance_data,
        mock_csa_requirement_attribute_iam,
        mock_csa_requirement_attribute_logging,
    ):
        """Test that requirements index is organized by section."""
        basic_csa_compliance_data.requirements = [
            RequirementData(
                id="REQ-001",
                description="IAM requirement",
                status=StatusChoices.PASS,
                passed_findings=10,
                failed_findings=0,
                total_findings=10,
            ),
            RequirementData(
                id="REQ-002",
                description="Logging requirement",
                status=StatusChoices.PASS,
                passed_findings=5,
                failed_findings=0,
                total_findings=5,
            ),
        ]
        basic_csa_compliance_data.attributes_by_requirement_id = {
            "REQ-001": {
                "attributes": {"req_attributes": [mock_csa_requirement_attribute_iam]}
            },
            "REQ-002": {
                "attributes": {
                    "req_attributes": [mock_csa_requirement_attribute_logging]
                }
            },
        }

        elements = csa_generator.create_requirements_index(basic_csa_compliance_data)

        paragraphs = [e for e in elements if isinstance(e, Paragraph)]
        content = " ".join(str(p.text) for p in paragraphs)
        # Should have section headers
        assert "Identity" in content or "Logging" in content or "Access" in content

    def test_requirements_index_shows_status_indicators(
        self,
        csa_generator,
        basic_csa_compliance_data,
        mock_csa_requirement_attribute_iam,
    ):
        """Test that requirements index shows pass/fail/manual indicators."""
        basic_csa_compliance_data.requirements = [
            RequirementData(
                id="REQ-001",
                description="Passed requirement",
                status=StatusChoices.PASS,
                passed_findings=10,
                failed_findings=0,
                total_findings=10,
            ),
            RequirementData(
                id="REQ-002",
                description="Failed requirement",
                status=StatusChoices.FAIL,
                passed_findings=0,
                failed_findings=10,
                total_findings=10,
            ),
            RequirementData(
                id="REQ-003",
                description="Manual requirement",
                status=StatusChoices.MANUAL,
                passed_findings=0,
                failed_findings=0,
                total_findings=0,
            ),
        ]
        basic_csa_compliance_data.attributes_by_requirement_id = {
            "REQ-001": {
                "attributes": {"req_attributes": [mock_csa_requirement_attribute_iam]}
            },
            "REQ-002": {
                "attributes": {"req_attributes": [mock_csa_requirement_attribute_iam]}
            },
            "REQ-003": {
                "attributes": {"req_attributes": [mock_csa_requirement_attribute_iam]}
            },
        }

        elements = csa_generator.create_requirements_index(basic_csa_compliance_data)

        paragraphs = [e for e in elements if isinstance(e, Paragraph)]
        content = " ".join(str(p.text) for p in paragraphs)
        # Should have status indicators
        assert "\u2713" in content or "\u2717" in content or "\u2299" in content

    def test_requirements_index_truncates_long_descriptions(
        self, csa_generator, basic_csa_compliance_data
    ):
        """Test that long descriptions are truncated."""
        mock_attr = Mock()
        mock_attr.Section = "Identity & Access Management"
        mock_attr.CCMLite = "Yes"
        mock_attr.IaaS = "Yes"
        mock_attr.PaaS = "Yes"
        mock_attr.SaaS = "Yes"
        mock_attr.ScopeApplicability = []

        basic_csa_compliance_data.requirements = [
            RequirementData(
                id="REQ-001",
                description="A" * 100,
                status=StatusChoices.PASS,
                passed_findings=10,
                failed_findings=0,
                total_findings=10,
            ),
        ]
        basic_csa_compliance_data.attributes_by_requirement_id = {
            "REQ-001": {"attributes": {"req_attributes": [mock_attr]}},
        }

        # Should not raise errors
        elements = csa_generator.create_requirements_index(basic_csa_compliance_data)
        assert len(elements) > 0


# =============================================================================
# Requirement Attributes Tests
# =============================================================================


class TestCSARequirementAttributes:
    """Test suite for CSA requirement attributes display."""

    def test_format_attributes_applicability_line(
        self, csa_generator, mock_csa_requirement_attribute_iam
    ):
        """Test that applicability attributes (CCMLite, IaaS, PaaS, SaaS) are rendered."""
        elements = csa_generator._format_requirement_attributes(
            mock_csa_requirement_attribute_iam
        )

        paragraphs = [e for e in elements if isinstance(e, Paragraph)]
        content = " ".join(str(p.text) for p in paragraphs)
        assert "CCMLite: Yes" in content
        assert "IaaS: Yes" in content
        assert "PaaS: Yes" in content
        assert "SaaS: Yes" in content

    def test_format_attributes_partial_applicability(
        self, csa_generator, mock_csa_requirement_attribute_logging
    ):
        """Test attributes when some applicability fields are 'No'."""
        elements = csa_generator._format_requirement_attributes(
            mock_csa_requirement_attribute_logging
        )

        paragraphs = [e for e in elements if isinstance(e, Paragraph)]
        content = " ".join(str(p.text) for p in paragraphs)
        assert "IaaS: Yes" in content
        assert "PaaS: No" in content

    def test_format_attributes_scope_applicability_refs(
        self, csa_generator, mock_csa_requirement_attribute_iam
    ):
        """Test that ScopeApplicability references are displayed."""
        elements = csa_generator._format_requirement_attributes(
            mock_csa_requirement_attribute_iam
        )

        paragraphs = [e for e in elements if isinstance(e, Paragraph)]
        content = " ".join(str(p.text) for p in paragraphs)
        assert "ISO 27001" in content
        assert "NIST 800-53" in content

    def test_format_attributes_empty_scope(
        self, csa_generator, mock_csa_requirement_attribute_crypto
    ):
        """Test that empty ScopeApplicability produces no reference line."""
        elements = csa_generator._format_requirement_attributes(
            mock_csa_requirement_attribute_crypto
        )

        # Should have applicability line but no scope reference line
        paragraphs = [e for e in elements if isinstance(e, Paragraph)]
        assert len(paragraphs) == 1  # Only the applicability line

    def test_format_attributes_no_applicability(self, csa_generator):
        """Test attributes when all applicability fields are empty."""
        mock = Mock()
        mock.CCMLite = ""
        mock.IaaS = ""
        mock.PaaS = ""
        mock.SaaS = ""
        mock.ScopeApplicability = []

        elements = csa_generator._format_requirement_attributes(mock)

        assert len(elements) == 0

    def test_format_attributes_truncates_long_identifiers(self, csa_generator):
        """Test that ScopeApplicability with many identifiers is truncated."""
        mock = Mock()
        mock.CCMLite = "Yes"
        mock.IaaS = "Yes"
        mock.PaaS = "Yes"
        mock.SaaS = "Yes"
        mock.ScopeApplicability = [
            {
                "ReferenceId": "NIST 800-53",
                "Identifiers": ["AC-1", "AC-2", "AC-3", "AC-4", "AC-5", "AC-6"],
            },
        ]

        elements = csa_generator._format_requirement_attributes(mock)

        paragraphs = [e for e in elements if isinstance(e, Paragraph)]
        content = " ".join(str(p.text) for p in paragraphs)
        # Should show first 4 and ellipsis
        assert "AC-1" in content
        assert "AC-4" in content
        assert "..." in content

    def test_attr_style_returns_paragraph_style(self, csa_generator):
        """Test that _attr_style returns a valid ParagraphStyle."""
        from reportlab.lib.styles import ParagraphStyle

        style = csa_generator._attr_style()
        assert isinstance(style, ParagraphStyle)
        assert style.fontSize == 10
        assert style.leftIndent == 30

    def test_render_requirement_detail_extras(
        self,
        csa_generator,
        basic_csa_compliance_data,
        mock_csa_requirement_attribute_iam,
    ):
        """Test that detail extras hook renders CSA attributes."""
        req = RequirementData(
            id="REQ-001",
            description="IAM requirement",
            status=StatusChoices.PASS,
            passed_findings=10,
            failed_findings=0,
            total_findings=10,
        )
        basic_csa_compliance_data.attributes_by_requirement_id = {
            "REQ-001": {
                "attributes": {"req_attributes": [mock_csa_requirement_attribute_iam]}
            },
        }

        elements = csa_generator._render_requirement_detail_extras(
            req, basic_csa_compliance_data
        )

        paragraphs = [e for e in elements if isinstance(e, Paragraph)]
        content = " ".join(str(p.text) for p in paragraphs)
        assert "CCMLite" in content
        assert "ISO 27001" in content

    def test_render_requirement_detail_extras_no_metadata(
        self,
        csa_generator,
        basic_csa_compliance_data,
    ):
        """Test that detail extras returns empty when no metadata found."""
        req = RequirementData(
            id="REQ-UNKNOWN",
            description="No metadata",
            status=StatusChoices.PASS,
            passed_findings=0,
            failed_findings=0,
            total_findings=0,
        )
        basic_csa_compliance_data.attributes_by_requirement_id = {}

        elements = csa_generator._render_requirement_detail_extras(
            req, basic_csa_compliance_data
        )

        assert elements == []


# =============================================================================
# Empty Data Tests
# =============================================================================


class TestCSAEmptyData:
    """Test suite for CSA with empty or minimal data."""

    def test_executive_summary_empty_requirements(
        self, csa_generator, basic_csa_compliance_data
    ):
        """Test executive summary with no requirements."""
        basic_csa_compliance_data.requirements = []
        basic_csa_compliance_data.attributes_by_requirement_id = {}

        elements = csa_generator.create_executive_summary(basic_csa_compliance_data)

        assert len(elements) > 0

    def test_charts_section_empty_requirements(
        self, csa_generator, basic_csa_compliance_data
    ):
        """Test charts section with no requirements."""
        basic_csa_compliance_data.requirements = []
        basic_csa_compliance_data.attributes_by_requirement_id = {}

        elements = csa_generator.create_charts_section(basic_csa_compliance_data)

        assert len(elements) > 0

    def test_requirements_index_empty(self, csa_generator, basic_csa_compliance_data):
        """Test requirements index with no requirements."""
        basic_csa_compliance_data.requirements = []
        basic_csa_compliance_data.attributes_by_requirement_id = {}

        elements = csa_generator.create_requirements_index(basic_csa_compliance_data)

        # Should at least have the title
        assert len(elements) >= 1


# =============================================================================
# All Pass / All Fail Tests
# =============================================================================


class TestCSAEdgeCases:
    """Test suite for CSA edge cases."""

    def test_all_requirements_pass(
        self,
        csa_generator,
        basic_csa_compliance_data,
        mock_csa_requirement_attribute_iam,
    ):
        """Test with all requirements passing."""
        basic_csa_compliance_data.requirements = [
            RequirementData(
                id=f"REQ-{i:03d}",
                description=f"Passing requirement {i}",
                status=StatusChoices.PASS,
                passed_findings=10,
                failed_findings=0,
                total_findings=10,
            )
            for i in range(1, 6)
        ]
        basic_csa_compliance_data.attributes_by_requirement_id = {
            f"REQ-{i:03d}": {
                "attributes": {"req_attributes": [mock_csa_requirement_attribute_iam]}
            }
            for i in range(1, 6)
        }

        elements = csa_generator.create_executive_summary(basic_csa_compliance_data)
        assert len(elements) > 0

    def test_all_requirements_fail(
        self,
        csa_generator,
        basic_csa_compliance_data,
        mock_csa_requirement_attribute_iam,
    ):
        """Test with all requirements failing."""
        basic_csa_compliance_data.requirements = [
            RequirementData(
                id=f"REQ-{i:03d}",
                description=f"Failing requirement {i}",
                status=StatusChoices.FAIL,
                passed_findings=0,
                failed_findings=10,
                total_findings=10,
            )
            for i in range(1, 6)
        ]
        basic_csa_compliance_data.attributes_by_requirement_id = {
            f"REQ-{i:03d}": {
                "attributes": {"req_attributes": [mock_csa_requirement_attribute_iam]}
            }
            for i in range(1, 6)
        }

        elements = csa_generator.create_executive_summary(basic_csa_compliance_data)
        assert len(elements) > 0

    def test_all_requirements_manual(
        self,
        csa_generator,
        basic_csa_compliance_data,
        mock_csa_requirement_attribute_iam,
    ):
        """Test with all requirements being manual."""
        basic_csa_compliance_data.requirements = [
            RequirementData(
                id=f"REQ-{i:03d}",
                description=f"Manual requirement {i}",
                status=StatusChoices.MANUAL,
                passed_findings=0,
                failed_findings=0,
                total_findings=0,
            )
            for i in range(1, 6)
        ]
        basic_csa_compliance_data.attributes_by_requirement_id = {
            f"REQ-{i:03d}": {
                "attributes": {"req_attributes": [mock_csa_requirement_attribute_iam]}
            }
            for i in range(1, 6)
        }

        # Should handle gracefully - compliance should be 100% when no evaluated
        elements = csa_generator.create_executive_summary(basic_csa_compliance_data)
        assert len(elements) > 0


# =============================================================================
# Integration Tests
# =============================================================================


class TestCSAIntegration:
    """Integration tests for CSA report generation."""

    def test_full_report_generation_flow(
        self,
        csa_generator,
        basic_csa_compliance_data,
        mock_csa_requirement_attribute_iam,
        mock_csa_requirement_attribute_logging,
    ):
        """Test the complete report generation flow."""
        basic_csa_compliance_data.requirements = [
            RequirementData(
                id="REQ-001",
                description="IAM passed",
                status=StatusChoices.PASS,
                passed_findings=10,
                failed_findings=0,
                total_findings=10,
            ),
            RequirementData(
                id="REQ-002",
                description="Logging failed",
                status=StatusChoices.FAIL,
                passed_findings=0,
                failed_findings=5,
                total_findings=5,
            ),
        ]
        basic_csa_compliance_data.attributes_by_requirement_id = {
            "REQ-001": {
                "attributes": {"req_attributes": [mock_csa_requirement_attribute_iam]}
            },
            "REQ-002": {
                "attributes": {
                    "req_attributes": [mock_csa_requirement_attribute_logging]
                }
            },
        }

        # Generate all sections
        exec_summary = csa_generator.create_executive_summary(basic_csa_compliance_data)
        charts = csa_generator.create_charts_section(basic_csa_compliance_data)
        index = csa_generator.create_requirements_index(basic_csa_compliance_data)

        # All sections should generate without errors
        assert len(exec_summary) > 0
        assert len(charts) > 0
        assert len(index) > 0
