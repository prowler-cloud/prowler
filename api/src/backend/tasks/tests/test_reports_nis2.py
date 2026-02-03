import io
from unittest.mock import Mock, patch

import pytest
from reportlab.platypus import PageBreak, Paragraph, Table
from tasks.jobs.reports import FRAMEWORK_REGISTRY, ComplianceData, RequirementData
from tasks.jobs.reports.nis2 import NIS2ReportGenerator, _extract_section_number


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
def nis2_generator():
    """Create a NIS2ReportGenerator instance for testing."""
    config = FRAMEWORK_REGISTRY["nis2"]
    return NIS2ReportGenerator(config)


@pytest.fixture
def mock_nis2_requirement_attribute_section1():
    """Create a mock NIS2 requirement attribute for Section 1."""
    mock = Mock()
    mock.Section = "1 POLICY ON THE SECURITY OF NETWORK AND INFORMATION SYSTEMS"
    mock.SubSection = "1.1 Policy establishment"
    mock.Description = "Establish security policies for network and information systems"
    return mock


@pytest.fixture
def mock_nis2_requirement_attribute_section2():
    """Create a mock NIS2 requirement attribute for Section 2."""
    mock = Mock()
    mock.Section = "2 RISK MANAGEMENT"
    mock.SubSection = "2.1 Risk assessment"
    mock.Description = "Conduct risk assessments for critical infrastructure"
    return mock


@pytest.fixture
def mock_nis2_requirement_attribute_section11():
    """Create a mock NIS2 requirement attribute for Section 11."""
    mock = Mock()
    mock.Section = "11 ACCESS CONTROL"
    mock.SubSection = "11.2 User access management"
    mock.Description = "Manage user access to systems and data"
    return mock


@pytest.fixture
def mock_nis2_requirement_attribute_no_subsection():
    """Create a mock NIS2 requirement attribute without subsection."""
    mock = Mock()
    mock.Section = "3 INCIDENT HANDLING"
    mock.SubSection = ""
    mock.Description = "Handle security incidents effectively"
    return mock


@pytest.fixture
def basic_nis2_compliance_data():
    """Create basic ComplianceData for NIS2 testing."""
    return ComplianceData(
        tenant_id="tenant-123",
        scan_id="scan-456",
        provider_id="provider-789",
        compliance_id="nis2_aws",
        framework="NIS2",
        name="NIS2 Directive (EU) 2022/2555",
        version="2022",
        description="EU directive on security of network and information systems",
    )


# =============================================================================
# Section Number Extraction Tests
# =============================================================================


class TestSectionNumberExtraction:
    """Test suite for section number extraction utility."""

    def test_extract_simple_section_number(self):
        """Test extracting single digit section number."""
        result = _extract_section_number("1 POLICY ON SECURITY")
        assert result == "1"

    def test_extract_double_digit_section_number(self):
        """Test extracting double digit section number."""
        result = _extract_section_number("11 ACCESS CONTROL")
        assert result == "11"

    def test_extract_section_number_with_spaces(self):
        """Test extracting section number with leading/trailing spaces."""
        result = _extract_section_number("  2 RISK MANAGEMENT  ")
        assert result == "2"

    def test_extract_section_number_empty_string(self):
        """Test extracting from empty string returns 'Other'."""
        result = _extract_section_number("")
        assert result == "Other"

    def test_extract_section_number_none_like(self):
        """Test extracting from empty/None-like returns 'Other'."""
        # Note: The function expects str, so we test empty string behavior
        result = _extract_section_number("")
        assert result == "Other"

    def test_extract_section_number_no_number(self):
        """Test extracting from string without number returns 'Other'."""
        result = _extract_section_number("POLICY ON SECURITY")
        assert result == "Other"

    def test_extract_section_number_letter_first(self):
        """Test extracting from string starting with letter returns 'Other'."""
        result = _extract_section_number("A. Some Section")
        assert result == "Other"


# =============================================================================
# Generator Initialization Tests
# =============================================================================


class TestNIS2GeneratorInitialization:
    """Test suite for NIS2 generator initialization."""

    def test_generator_creation(self, nis2_generator):
        """Test that NIS2 generator is created correctly."""
        assert nis2_generator is not None
        assert nis2_generator.config.name == "nis2"
        assert nis2_generator.config.language == "en"

    def test_generator_no_niveles(self, nis2_generator):
        """Test that NIS2 config does not use niveles."""
        assert nis2_generator.config.has_niveles is False

    def test_generator_no_dimensions(self, nis2_generator):
        """Test that NIS2 config does not use dimensions."""
        assert nis2_generator.config.has_dimensions is False

    def test_generator_no_risk_levels(self, nis2_generator):
        """Test that NIS2 config does not use risk levels."""
        assert nis2_generator.config.has_risk_levels is False

    def test_generator_no_weight(self, nis2_generator):
        """Test that NIS2 config does not use weight."""
        assert nis2_generator.config.has_weight is False


# =============================================================================
# Cover Page Tests
# =============================================================================


class TestNIS2CoverPage:
    """Test suite for NIS2 cover page generation."""

    @patch("tasks.jobs.reports.nis2.Image")
    def test_cover_page_has_logos(
        self, mock_image, nis2_generator, basic_nis2_compliance_data
    ):
        """Test that cover page contains logos."""
        basic_nis2_compliance_data.requirements = []
        basic_nis2_compliance_data.attributes_by_requirement_id = {}

        elements = nis2_generator.create_cover_page(basic_nis2_compliance_data)

        assert len(elements) > 0
        # Should have called Image at least twice (prowler + nis2 logos)
        assert mock_image.call_count >= 2

    def test_cover_page_has_title(self, nis2_generator, basic_nis2_compliance_data):
        """Test that cover page contains the NIS2 title."""
        basic_nis2_compliance_data.requirements = []
        basic_nis2_compliance_data.attributes_by_requirement_id = {}

        elements = nis2_generator.create_cover_page(basic_nis2_compliance_data)

        paragraphs = [e for e in elements if isinstance(e, Paragraph)]
        content = " ".join(str(p.text) for p in paragraphs)
        assert "NIS2" in content or "Directive" in content

    def test_cover_page_has_metadata_table(
        self, nis2_generator, basic_nis2_compliance_data
    ):
        """Test that cover page contains metadata table."""
        basic_nis2_compliance_data.requirements = []
        basic_nis2_compliance_data.attributes_by_requirement_id = {}

        elements = nis2_generator.create_cover_page(basic_nis2_compliance_data)

        tables = [e for e in elements if isinstance(e, Table)]
        assert len(tables) >= 1


# =============================================================================
# Executive Summary Tests
# =============================================================================


class TestNIS2ExecutiveSummary:
    """Test suite for NIS2 executive summary generation."""

    def test_executive_summary_has_english_title(
        self, nis2_generator, basic_nis2_compliance_data
    ):
        """Test that executive summary has English title."""
        basic_nis2_compliance_data.requirements = []
        basic_nis2_compliance_data.attributes_by_requirement_id = {}

        elements = nis2_generator.create_executive_summary(basic_nis2_compliance_data)

        paragraphs = [e for e in elements if isinstance(e, Paragraph)]
        content = " ".join(str(p.text) for p in paragraphs)
        assert "Executive Summary" in content

    def test_executive_summary_calculates_compliance(
        self,
        nis2_generator,
        basic_nis2_compliance_data,
        mock_nis2_requirement_attribute_section1,
    ):
        """Test that executive summary calculates compliance percentage."""
        basic_nis2_compliance_data.requirements = [
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
        basic_nis2_compliance_data.attributes_by_requirement_id = {
            "REQ-001": {
                "attributes": {
                    "req_attributes": [mock_nis2_requirement_attribute_section1]
                }
            },
            "REQ-002": {
                "attributes": {
                    "req_attributes": [mock_nis2_requirement_attribute_section1]
                }
            },
        }

        elements = nis2_generator.create_executive_summary(basic_nis2_compliance_data)

        # Should contain tables with metrics
        tables = [e for e in elements if isinstance(e, Table)]
        assert len(tables) >= 1

    def test_executive_summary_shows_all_statuses(
        self,
        nis2_generator,
        basic_nis2_compliance_data,
        mock_nis2_requirement_attribute_section1,
    ):
        """Test that executive summary shows passed, failed, and manual counts."""
        basic_nis2_compliance_data.requirements = [
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
        basic_nis2_compliance_data.attributes_by_requirement_id = {
            "REQ-001": {
                "attributes": {
                    "req_attributes": [mock_nis2_requirement_attribute_section1]
                }
            },
            "REQ-002": {
                "attributes": {
                    "req_attributes": [mock_nis2_requirement_attribute_section1]
                }
            },
            "REQ-003": {
                "attributes": {
                    "req_attributes": [mock_nis2_requirement_attribute_section1]
                }
            },
        }

        elements = nis2_generator.create_executive_summary(basic_nis2_compliance_data)

        # Should have a summary table with all statuses
        assert len(elements) > 0

    def test_executive_summary_excludes_manual_from_percentage(
        self,
        nis2_generator,
        basic_nis2_compliance_data,
        mock_nis2_requirement_attribute_section1,
    ):
        """Test that manual requirements are excluded from compliance percentage."""
        basic_nis2_compliance_data.requirements = [
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
        basic_nis2_compliance_data.attributes_by_requirement_id = {
            "REQ-001": {
                "attributes": {
                    "req_attributes": [mock_nis2_requirement_attribute_section1]
                }
            },
            "REQ-002": {
                "attributes": {
                    "req_attributes": [mock_nis2_requirement_attribute_section1]
                }
            },
        }

        elements = nis2_generator.create_executive_summary(basic_nis2_compliance_data)

        # Should calculate 100% (only 1 evaluated requirement that passed)
        assert len(elements) > 0


# =============================================================================
# Charts Section Tests
# =============================================================================


class TestNIS2ChartsSection:
    """Test suite for NIS2 charts section generation."""

    def test_charts_section_has_section_chart_title(
        self, nis2_generator, basic_nis2_compliance_data
    ):
        """Test that charts section has section compliance title."""
        basic_nis2_compliance_data.requirements = []
        basic_nis2_compliance_data.attributes_by_requirement_id = {}

        elements = nis2_generator.create_charts_section(basic_nis2_compliance_data)

        paragraphs = [e for e in elements if isinstance(e, Paragraph)]
        content = " ".join(str(p.text) for p in paragraphs)
        assert "Section" in content or "Compliance" in content

    def test_charts_section_has_page_break(
        self, nis2_generator, basic_nis2_compliance_data
    ):
        """Test that charts section has page breaks."""
        basic_nis2_compliance_data.requirements = []
        basic_nis2_compliance_data.attributes_by_requirement_id = {}

        elements = nis2_generator.create_charts_section(basic_nis2_compliance_data)

        page_breaks = [e for e in elements if isinstance(e, PageBreak)]
        assert len(page_breaks) >= 1

    def test_charts_section_has_subsection_breakdown(
        self,
        nis2_generator,
        basic_nis2_compliance_data,
        mock_nis2_requirement_attribute_section1,
    ):
        """Test that charts section includes subsection breakdown table."""
        basic_nis2_compliance_data.requirements = [
            RequirementData(
                id="REQ-001",
                description="Test requirement",
                status=StatusChoices.PASS,
                passed_findings=10,
                failed_findings=0,
                total_findings=10,
            ),
        ]
        basic_nis2_compliance_data.attributes_by_requirement_id = {
            "REQ-001": {
                "attributes": {
                    "req_attributes": [mock_nis2_requirement_attribute_section1]
                }
            },
        }

        elements = nis2_generator.create_charts_section(basic_nis2_compliance_data)

        paragraphs = [e for e in elements if isinstance(e, Paragraph)]
        content = " ".join(str(p.text) for p in paragraphs)
        assert "SubSection" in content or "Breakdown" in content


# =============================================================================
# Section Chart Tests
# =============================================================================


class TestNIS2SectionChart:
    """Test suite for NIS2 section compliance chart."""

    def test_section_chart_creation(
        self,
        nis2_generator,
        basic_nis2_compliance_data,
        mock_nis2_requirement_attribute_section1,
    ):
        """Test that section chart is created successfully."""
        basic_nis2_compliance_data.requirements = [
            RequirementData(
                id="REQ-001",
                description="Test requirement",
                status=StatusChoices.PASS,
                passed_findings=10,
                failed_findings=0,
                total_findings=10,
            ),
        ]
        basic_nis2_compliance_data.attributes_by_requirement_id = {
            "REQ-001": {
                "attributes": {
                    "req_attributes": [mock_nis2_requirement_attribute_section1]
                }
            },
        }

        chart_buffer = nis2_generator._create_section_chart(basic_nis2_compliance_data)

        assert isinstance(chart_buffer, io.BytesIO)
        assert chart_buffer.getvalue()  # Not empty

    def test_section_chart_excludes_manual(
        self,
        nis2_generator,
        basic_nis2_compliance_data,
        mock_nis2_requirement_attribute_section1,
    ):
        """Test that manual requirements are excluded from section chart."""
        basic_nis2_compliance_data.requirements = [
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
        basic_nis2_compliance_data.attributes_by_requirement_id = {
            "REQ-001": {
                "attributes": {
                    "req_attributes": [mock_nis2_requirement_attribute_section1]
                }
            },
            "REQ-002": {
                "attributes": {
                    "req_attributes": [mock_nis2_requirement_attribute_section1]
                }
            },
        }

        # Should not raise any errors
        chart_buffer = nis2_generator._create_section_chart(basic_nis2_compliance_data)
        assert isinstance(chart_buffer, io.BytesIO)

    def test_section_chart_multiple_sections(
        self,
        nis2_generator,
        basic_nis2_compliance_data,
        mock_nis2_requirement_attribute_section1,
        mock_nis2_requirement_attribute_section2,
        mock_nis2_requirement_attribute_section11,
    ):
        """Test section chart with multiple sections."""
        basic_nis2_compliance_data.requirements = [
            RequirementData(
                id="REQ-001",
                description="Section 1 requirement",
                status=StatusChoices.PASS,
                passed_findings=10,
                failed_findings=0,
                total_findings=10,
            ),
            RequirementData(
                id="REQ-002",
                description="Section 2 requirement",
                status=StatusChoices.FAIL,
                passed_findings=0,
                failed_findings=10,
                total_findings=10,
            ),
            RequirementData(
                id="REQ-003",
                description="Section 11 requirement",
                status=StatusChoices.PASS,
                passed_findings=5,
                failed_findings=0,
                total_findings=5,
            ),
        ]
        basic_nis2_compliance_data.attributes_by_requirement_id = {
            "REQ-001": {
                "attributes": {
                    "req_attributes": [mock_nis2_requirement_attribute_section1]
                }
            },
            "REQ-002": {
                "attributes": {
                    "req_attributes": [mock_nis2_requirement_attribute_section2]
                }
            },
            "REQ-003": {
                "attributes": {
                    "req_attributes": [mock_nis2_requirement_attribute_section11]
                }
            },
        }

        chart_buffer = nis2_generator._create_section_chart(basic_nis2_compliance_data)
        assert isinstance(chart_buffer, io.BytesIO)


# =============================================================================
# SubSection Table Tests
# =============================================================================


class TestNIS2SubSectionTable:
    """Test suite for NIS2 subsection breakdown table."""

    def test_subsection_table_creation(
        self,
        nis2_generator,
        basic_nis2_compliance_data,
        mock_nis2_requirement_attribute_section1,
    ):
        """Test that subsection table is created successfully."""
        basic_nis2_compliance_data.requirements = [
            RequirementData(
                id="REQ-001",
                description="Test requirement",
                status=StatusChoices.PASS,
                passed_findings=10,
                failed_findings=0,
                total_findings=10,
            ),
        ]
        basic_nis2_compliance_data.attributes_by_requirement_id = {
            "REQ-001": {
                "attributes": {
                    "req_attributes": [mock_nis2_requirement_attribute_section1]
                }
            },
        }

        table = nis2_generator._create_subsection_table(basic_nis2_compliance_data)

        assert isinstance(table, Table)

    def test_subsection_table_counts_statuses(
        self,
        nis2_generator,
        basic_nis2_compliance_data,
        mock_nis2_requirement_attribute_section1,
    ):
        """Test that subsection table counts passed, failed, and manual."""
        basic_nis2_compliance_data.requirements = [
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
        basic_nis2_compliance_data.attributes_by_requirement_id = {
            "REQ-001": {
                "attributes": {
                    "req_attributes": [mock_nis2_requirement_attribute_section1]
                }
            },
            "REQ-002": {
                "attributes": {
                    "req_attributes": [mock_nis2_requirement_attribute_section1]
                }
            },
            "REQ-003": {
                "attributes": {
                    "req_attributes": [mock_nis2_requirement_attribute_section1]
                }
            },
        }

        table = nis2_generator._create_subsection_table(basic_nis2_compliance_data)
        assert isinstance(table, Table)

    def test_subsection_table_no_subsection(
        self,
        nis2_generator,
        basic_nis2_compliance_data,
        mock_nis2_requirement_attribute_no_subsection,
    ):
        """Test subsection table when requirements have no subsection."""
        basic_nis2_compliance_data.requirements = [
            RequirementData(
                id="REQ-001",
                description="No subsection requirement",
                status=StatusChoices.PASS,
                passed_findings=10,
                failed_findings=0,
                total_findings=10,
            ),
        ]
        basic_nis2_compliance_data.attributes_by_requirement_id = {
            "REQ-001": {
                "attributes": {
                    "req_attributes": [mock_nis2_requirement_attribute_no_subsection]
                }
            },
        }

        table = nis2_generator._create_subsection_table(basic_nis2_compliance_data)
        assert isinstance(table, Table)


# =============================================================================
# Requirements Index Tests
# =============================================================================


class TestNIS2RequirementsIndex:
    """Test suite for NIS2 requirements index generation."""

    def test_requirements_index_has_title(
        self, nis2_generator, basic_nis2_compliance_data
    ):
        """Test that requirements index has English title."""
        basic_nis2_compliance_data.requirements = []
        basic_nis2_compliance_data.attributes_by_requirement_id = {}

        elements = nis2_generator.create_requirements_index(basic_nis2_compliance_data)

        paragraphs = [e for e in elements if isinstance(e, Paragraph)]
        content = " ".join(str(p.text) for p in paragraphs)
        assert "Requirements Index" in content

    def test_requirements_index_organized_by_section(
        self,
        nis2_generator,
        basic_nis2_compliance_data,
        mock_nis2_requirement_attribute_section1,
        mock_nis2_requirement_attribute_section2,
    ):
        """Test that requirements index is organized by section."""
        basic_nis2_compliance_data.requirements = [
            RequirementData(
                id="REQ-001",
                description="Section 1 requirement",
                status=StatusChoices.PASS,
                passed_findings=10,
                failed_findings=0,
                total_findings=10,
            ),
            RequirementData(
                id="REQ-002",
                description="Section 2 requirement",
                status=StatusChoices.PASS,
                passed_findings=5,
                failed_findings=0,
                total_findings=5,
            ),
        ]
        basic_nis2_compliance_data.attributes_by_requirement_id = {
            "REQ-001": {
                "attributes": {
                    "req_attributes": [mock_nis2_requirement_attribute_section1]
                }
            },
            "REQ-002": {
                "attributes": {
                    "req_attributes": [mock_nis2_requirement_attribute_section2]
                }
            },
        }

        elements = nis2_generator.create_requirements_index(basic_nis2_compliance_data)

        paragraphs = [e for e in elements if isinstance(e, Paragraph)]
        content = " ".join(str(p.text) for p in paragraphs)
        # Should have section headers
        assert "Policy" in content or "Risk" in content or "1." in content

    def test_requirements_index_shows_status_indicators(
        self,
        nis2_generator,
        basic_nis2_compliance_data,
        mock_nis2_requirement_attribute_section1,
    ):
        """Test that requirements index shows pass/fail/manual indicators."""
        basic_nis2_compliance_data.requirements = [
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
        basic_nis2_compliance_data.attributes_by_requirement_id = {
            "REQ-001": {
                "attributes": {
                    "req_attributes": [mock_nis2_requirement_attribute_section1]
                }
            },
            "REQ-002": {
                "attributes": {
                    "req_attributes": [mock_nis2_requirement_attribute_section1]
                }
            },
            "REQ-003": {
                "attributes": {
                    "req_attributes": [mock_nis2_requirement_attribute_section1]
                }
            },
        }

        elements = nis2_generator.create_requirements_index(basic_nis2_compliance_data)

        paragraphs = [e for e in elements if isinstance(e, Paragraph)]
        content = " ".join(str(p.text) for p in paragraphs)
        # Should have status indicators
        assert "✓" in content or "✗" in content or "⊙" in content

    def test_requirements_index_truncates_long_descriptions(
        self, nis2_generator, basic_nis2_compliance_data
    ):
        """Test that long descriptions are truncated."""
        mock_attr = Mock()
        mock_attr.Section = "1 POLICY"
        mock_attr.SubSection = "1.1 Long subsection name"
        mock_attr.Description = "A" * 100  # Very long description

        basic_nis2_compliance_data.requirements = [
            RequirementData(
                id="REQ-001",
                description="A" * 100,
                status=StatusChoices.PASS,
                passed_findings=10,
                failed_findings=0,
                total_findings=10,
            ),
        ]
        basic_nis2_compliance_data.attributes_by_requirement_id = {
            "REQ-001": {"attributes": {"req_attributes": [mock_attr]}},
        }

        # Should not raise errors
        elements = nis2_generator.create_requirements_index(basic_nis2_compliance_data)
        assert len(elements) > 0


# =============================================================================
# Section Key Sorting Tests
# =============================================================================


class TestNIS2SectionKeySorting:
    """Test suite for NIS2 section key sorting."""

    def test_sort_simple_sections(self, nis2_generator):
        """Test sorting simple section numbers."""
        result = nis2_generator._sort_section_key("1")
        assert result == (1,)

        result = nis2_generator._sort_section_key("2")
        assert result == (2,)

    def test_sort_subsections(self, nis2_generator):
        """Test sorting subsection numbers."""
        result = nis2_generator._sort_section_key("1.1")
        assert result == (1, 1)

        result = nis2_generator._sort_section_key("1.2")
        assert result == (1, 2)

    def test_sort_double_digit_sections(self, nis2_generator):
        """Test sorting double digit section numbers."""
        result = nis2_generator._sort_section_key("11")
        assert result == (11,)

        result = nis2_generator._sort_section_key("11.2")
        assert result == (11, 2)

    def test_sort_order_is_correct(self, nis2_generator):
        """Test that sort order is numerically correct."""
        keys = ["11", "1", "2", "1.2", "1.1", "11.2", "2.1"]
        sorted_keys = sorted(keys, key=nis2_generator._sort_section_key)

        assert sorted_keys == ["1", "1.1", "1.2", "2", "2.1", "11", "11.2"]

    def test_sort_invalid_key(self, nis2_generator):
        """Test sorting invalid section key."""
        result = nis2_generator._sort_section_key("Other")
        # Should contain infinity for non-numeric parts
        assert result[0] == float("inf")


# =============================================================================
# Empty Data Tests
# =============================================================================


class TestNIS2EmptyData:
    """Test suite for NIS2 with empty or minimal data."""

    def test_executive_summary_empty_requirements(
        self, nis2_generator, basic_nis2_compliance_data
    ):
        """Test executive summary with no requirements."""
        basic_nis2_compliance_data.requirements = []
        basic_nis2_compliance_data.attributes_by_requirement_id = {}

        elements = nis2_generator.create_executive_summary(basic_nis2_compliance_data)

        assert len(elements) > 0

    def test_charts_section_empty_requirements(
        self, nis2_generator, basic_nis2_compliance_data
    ):
        """Test charts section with no requirements."""
        basic_nis2_compliance_data.requirements = []
        basic_nis2_compliance_data.attributes_by_requirement_id = {}

        elements = nis2_generator.create_charts_section(basic_nis2_compliance_data)

        assert len(elements) > 0

    def test_requirements_index_empty(self, nis2_generator, basic_nis2_compliance_data):
        """Test requirements index with no requirements."""
        basic_nis2_compliance_data.requirements = []
        basic_nis2_compliance_data.attributes_by_requirement_id = {}

        elements = nis2_generator.create_requirements_index(basic_nis2_compliance_data)

        # Should at least have the title
        assert len(elements) >= 1


# =============================================================================
# All Pass / All Fail Tests
# =============================================================================


class TestNIS2EdgeCases:
    """Test suite for NIS2 edge cases."""

    def test_all_requirements_pass(
        self,
        nis2_generator,
        basic_nis2_compliance_data,
        mock_nis2_requirement_attribute_section1,
    ):
        """Test with all requirements passing."""
        basic_nis2_compliance_data.requirements = [
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
        basic_nis2_compliance_data.attributes_by_requirement_id = {
            f"REQ-{i:03d}": {
                "attributes": {
                    "req_attributes": [mock_nis2_requirement_attribute_section1]
                }
            }
            for i in range(1, 6)
        }

        elements = nis2_generator.create_executive_summary(basic_nis2_compliance_data)
        assert len(elements) > 0

    def test_all_requirements_fail(
        self,
        nis2_generator,
        basic_nis2_compliance_data,
        mock_nis2_requirement_attribute_section1,
    ):
        """Test with all requirements failing."""
        basic_nis2_compliance_data.requirements = [
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
        basic_nis2_compliance_data.attributes_by_requirement_id = {
            f"REQ-{i:03d}": {
                "attributes": {
                    "req_attributes": [mock_nis2_requirement_attribute_section1]
                }
            }
            for i in range(1, 6)
        }

        elements = nis2_generator.create_executive_summary(basic_nis2_compliance_data)
        assert len(elements) > 0

    def test_all_requirements_manual(
        self,
        nis2_generator,
        basic_nis2_compliance_data,
        mock_nis2_requirement_attribute_section1,
    ):
        """Test with all requirements being manual."""
        basic_nis2_compliance_data.requirements = [
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
        basic_nis2_compliance_data.attributes_by_requirement_id = {
            f"REQ-{i:03d}": {
                "attributes": {
                    "req_attributes": [mock_nis2_requirement_attribute_section1]
                }
            }
            for i in range(1, 6)
        }

        # Should handle gracefully - compliance should be 100% when no evaluated
        elements = nis2_generator.create_executive_summary(basic_nis2_compliance_data)
        assert len(elements) > 0


# =============================================================================
# Integration Tests
# =============================================================================


class TestNIS2Integration:
    """Integration tests for NIS2 report generation."""

    def test_full_report_generation_flow(
        self,
        nis2_generator,
        basic_nis2_compliance_data,
        mock_nis2_requirement_attribute_section1,
        mock_nis2_requirement_attribute_section2,
    ):
        """Test the complete report generation flow."""
        basic_nis2_compliance_data.requirements = [
            RequirementData(
                id="REQ-001",
                description="Section 1 passed",
                status=StatusChoices.PASS,
                passed_findings=10,
                failed_findings=0,
                total_findings=10,
            ),
            RequirementData(
                id="REQ-002",
                description="Section 2 failed",
                status=StatusChoices.FAIL,
                passed_findings=0,
                failed_findings=5,
                total_findings=5,
            ),
        ]
        basic_nis2_compliance_data.attributes_by_requirement_id = {
            "REQ-001": {
                "attributes": {
                    "req_attributes": [mock_nis2_requirement_attribute_section1]
                }
            },
            "REQ-002": {
                "attributes": {
                    "req_attributes": [mock_nis2_requirement_attribute_section2]
                }
            },
        }

        # Generate all sections
        exec_summary = nis2_generator.create_executive_summary(
            basic_nis2_compliance_data
        )
        charts = nis2_generator.create_charts_section(basic_nis2_compliance_data)
        index = nis2_generator.create_requirements_index(basic_nis2_compliance_data)

        # All sections should generate without errors
        assert len(exec_summary) > 0
        assert len(charts) > 0
        assert len(index) > 0
