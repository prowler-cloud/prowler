import io
from unittest.mock import Mock

import pytest
from reportlab.platypus import Image, PageBreak, Paragraph, Table
from tasks.jobs.reports import (
    FRAMEWORK_REGISTRY,
    ComplianceData,
    RequirementData,
    ThreatScoreReportGenerator,
)

from api.models import StatusChoices

# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def threatscore_generator():
    """Create a ThreatScoreReportGenerator instance for testing."""
    config = FRAMEWORK_REGISTRY["prowler_threatscore"]
    return ThreatScoreReportGenerator(config)


@pytest.fixture
def mock_requirement_attribute():
    """Create a mock requirement attribute with numeric values."""
    mock = Mock()
    mock.LevelOfRisk = 4
    mock.Weight = 100
    mock.Section = "1. IAM"
    mock.SubSection = "1.1 Access Control"
    mock.Title = "Test Requirement"
    mock.AttributeDescription = "Test Description"
    return mock


@pytest.fixture
def mock_requirement_attribute_string_values():
    """Create a mock requirement attribute with string values (edge case)."""
    mock = Mock()
    mock.LevelOfRisk = "5"  # String instead of int
    mock.Weight = "150"  # String instead of int
    mock.Section = "2. Attack Surface"
    mock.SubSection = "2.1 Exposure"
    mock.Title = "String Values Requirement"
    mock.AttributeDescription = "Test with string numeric values"
    return mock


@pytest.fixture
def mock_requirement_attribute_invalid_values():
    """Create a mock requirement attribute with invalid values (edge case)."""
    mock = Mock()
    mock.LevelOfRisk = "High"  # Invalid string
    mock.Weight = "Critical"  # Invalid string
    mock.Section = "3. Logging"
    mock.SubSection = "3.1 Audit"
    mock.Title = "Invalid Values Requirement"
    mock.AttributeDescription = "Test with invalid string values"
    return mock


@pytest.fixture
def mock_requirement_attribute_empty_values():
    """Create a mock requirement attribute with empty values."""
    mock = Mock()
    mock.LevelOfRisk = ""
    mock.Weight = ""
    mock.Section = "4. Encryption"
    mock.SubSection = "4.1 Data at Rest"
    mock.Title = "Empty Values Requirement"
    mock.AttributeDescription = "Test with empty values"
    return mock


@pytest.fixture
def mock_requirement_attribute_none_values():
    """Create a mock requirement attribute with None values."""
    mock = Mock()
    mock.LevelOfRisk = None
    mock.Weight = None
    mock.Section = "1. IAM"
    mock.SubSection = "1.2 Policies"
    mock.Title = "None Values Requirement"
    mock.AttributeDescription = "Test with None values"
    return mock


@pytest.fixture
def basic_compliance_data():
    """Create basic ComplianceData for testing."""
    return ComplianceData(
        tenant_id="tenant-123",
        scan_id="scan-456",
        provider_id="provider-789",
        compliance_id="prowler_threatscore_aws",
        framework="Prowler ThreatScore",
        name="ThreatScore AWS",
        version="1.0",
        description="Security assessment framework",
    )


# =============================================================================
# ThreatScore Calculation Tests
# =============================================================================


class TestThreatScoreCalculation:
    """Test suite for ThreatScore calculation logic."""

    def test_calculate_threatscore_no_findings_returns_100(
        self, threatscore_generator, basic_compliance_data
    ):
        """Test that 100% is returned when there are no findings."""
        basic_compliance_data.requirements = [
            RequirementData(
                id="REQ-001",
                description="Test requirement",
                status=StatusChoices.PASS,
                passed_findings=0,
                failed_findings=0,
                total_findings=0,
            )
        ]
        basic_compliance_data.attributes_by_requirement_id = {}

        result = threatscore_generator._calculate_threatscore(basic_compliance_data)

        assert result == 100.0

    def test_calculate_threatscore_all_passed(
        self, threatscore_generator, basic_compliance_data, mock_requirement_attribute
    ):
        """Test ThreatScore calculation when all findings pass."""
        basic_compliance_data.requirements = [
            RequirementData(
                id="REQ-001",
                description="Test requirement",
                status=StatusChoices.PASS,
                passed_findings=10,
                failed_findings=0,
                total_findings=10,
            )
        ]
        basic_compliance_data.attributes_by_requirement_id = {
            "REQ-001": {
                "attributes": {"req_attributes": [mock_requirement_attribute]},
            }
        }

        result = threatscore_generator._calculate_threatscore(basic_compliance_data)

        assert result == 100.0

    def test_calculate_threatscore_all_failed(
        self, threatscore_generator, basic_compliance_data, mock_requirement_attribute
    ):
        """Test ThreatScore calculation when all findings fail."""
        basic_compliance_data.requirements = [
            RequirementData(
                id="REQ-001",
                description="Test requirement",
                status=StatusChoices.FAIL,
                passed_findings=0,
                failed_findings=10,
                total_findings=10,
            )
        ]
        basic_compliance_data.attributes_by_requirement_id = {
            "REQ-001": {
                "attributes": {"req_attributes": [mock_requirement_attribute]},
            }
        }

        result = threatscore_generator._calculate_threatscore(basic_compliance_data)

        assert result == 0.0

    def test_calculate_threatscore_mixed_findings(
        self, threatscore_generator, basic_compliance_data, mock_requirement_attribute
    ):
        """Test ThreatScore calculation with mixed pass/fail findings."""
        basic_compliance_data.requirements = [
            RequirementData(
                id="REQ-001",
                description="Test requirement",
                status=StatusChoices.FAIL,
                passed_findings=7,
                failed_findings=3,
                total_findings=10,
            )
        ]
        basic_compliance_data.attributes_by_requirement_id = {
            "REQ-001": {
                "attributes": {"req_attributes": [mock_requirement_attribute]},
            }
        }

        result = threatscore_generator._calculate_threatscore(basic_compliance_data)

        # rate_i = 7/10 = 0.7
        # rfac_i = 1 + 0.25 * 4 = 2.0
        # numerator = 0.7 * 10 * 100 * 2.0 = 1400
        # denominator = 10 * 100 * 2.0 = 2000
        # score = (1400 / 2000) * 100 = 70.0
        assert result == 70.0

    def test_calculate_threatscore_multiple_requirements(
        self, threatscore_generator, basic_compliance_data
    ):
        """Test ThreatScore calculation with multiple requirements."""
        mock_attr_1 = Mock()
        mock_attr_1.LevelOfRisk = 5
        mock_attr_1.Weight = 100

        mock_attr_2 = Mock()
        mock_attr_2.LevelOfRisk = 3
        mock_attr_2.Weight = 50

        basic_compliance_data.requirements = [
            RequirementData(
                id="REQ-001",
                description="High risk requirement",
                status=StatusChoices.FAIL,
                passed_findings=8,
                failed_findings=2,
                total_findings=10,
            ),
            RequirementData(
                id="REQ-002",
                description="Low risk requirement",
                status=StatusChoices.PASS,
                passed_findings=5,
                failed_findings=0,
                total_findings=5,
            ),
        ]
        basic_compliance_data.attributes_by_requirement_id = {
            "REQ-001": {"attributes": {"req_attributes": [mock_attr_1]}},
            "REQ-002": {"attributes": {"req_attributes": [mock_attr_2]}},
        }

        result = threatscore_generator._calculate_threatscore(basic_compliance_data)

        # REQ-001: rate=0.8, rfac=2.25, num=0.8*10*100*2.25=1800, den=10*100*2.25=2250
        # REQ-002: rate=1.0, rfac=1.75, num=1.0*5*50*1.75=437.5, den=5*50*1.75=437.5
        # total_num = 1800 + 437.5 = 2237.5
        # total_den = 2250 + 437.5 = 2687.5
        # score = (2237.5 / 2687.5) * 100 ≈ 83.26%
        assert 83.0 < result < 84.0

    def test_calculate_threatscore_zero_weight(
        self, threatscore_generator, basic_compliance_data
    ):
        """Test ThreatScore calculation with zero weight."""
        mock_attr = Mock()
        mock_attr.LevelOfRisk = 4
        mock_attr.Weight = 0

        basic_compliance_data.requirements = [
            RequirementData(
                id="REQ-001",
                description="Zero weight requirement",
                status=StatusChoices.FAIL,
                passed_findings=5,
                failed_findings=5,
                total_findings=10,
            )
        ]
        basic_compliance_data.attributes_by_requirement_id = {
            "REQ-001": {"attributes": {"req_attributes": [mock_attr]}},
        }

        result = threatscore_generator._calculate_threatscore(basic_compliance_data)

        # With weight=0, denominator will be 0, should return 0.0
        assert result == 0.0


# =============================================================================
# Type Conversion Tests (Critical for bug fix validation)
# =============================================================================


class TestTypeConversionSafety:
    """Test suite for type conversion safety in ThreatScore calculations."""

    def test_calculate_threatscore_with_string_risk_level(
        self,
        threatscore_generator,
        basic_compliance_data,
        mock_requirement_attribute_string_values,
    ):
        """Test that string LevelOfRisk is correctly converted to int."""
        basic_compliance_data.requirements = [
            RequirementData(
                id="REQ-001",
                description="String values test",
                status=StatusChoices.FAIL,
                passed_findings=5,
                failed_findings=5,
                total_findings=10,
            )
        ]
        basic_compliance_data.attributes_by_requirement_id = {
            "REQ-001": {
                "attributes": {
                    "req_attributes": [mock_requirement_attribute_string_values]
                }
            },
        }

        # Should not raise TypeError: '<=' not supported between 'str' and 'int'
        result = threatscore_generator._calculate_threatscore(basic_compliance_data)

        # LevelOfRisk="5" -> 5, Weight="150" -> 150
        # rate_i = 0.5, rfac_i = 1 + 0.25*5 = 2.25
        # numerator = 0.5 * 10 * 150 * 2.25 = 1687.5
        # denominator = 10 * 150 * 2.25 = 3375
        # score = 50.0
        assert result == 50.0

    def test_calculate_threatscore_with_invalid_string_values(
        self,
        threatscore_generator,
        basic_compliance_data,
        mock_requirement_attribute_invalid_values,
    ):
        """Test that invalid string values default to 0."""
        basic_compliance_data.requirements = [
            RequirementData(
                id="REQ-001",
                description="Invalid values test",
                status=StatusChoices.FAIL,
                passed_findings=5,
                failed_findings=5,
                total_findings=10,
            )
        ]
        basic_compliance_data.attributes_by_requirement_id = {
            "REQ-001": {
                "attributes": {
                    "req_attributes": [mock_requirement_attribute_invalid_values]
                }
            },
        }

        # Should not raise ValueError, should default to 0
        result = threatscore_generator._calculate_threatscore(basic_compliance_data)

        # With weight=0 (from invalid string), denominator is 0
        assert result == 0.0

    def test_calculate_threatscore_with_empty_values(
        self,
        threatscore_generator,
        basic_compliance_data,
        mock_requirement_attribute_empty_values,
    ):
        """Test that empty string values default to 0."""
        basic_compliance_data.requirements = [
            RequirementData(
                id="REQ-001",
                description="Empty values test",
                status=StatusChoices.FAIL,
                passed_findings=5,
                failed_findings=5,
                total_findings=10,
            )
        ]
        basic_compliance_data.attributes_by_requirement_id = {
            "REQ-001": {
                "attributes": {
                    "req_attributes": [mock_requirement_attribute_empty_values]
                }
            },
        }

        result = threatscore_generator._calculate_threatscore(basic_compliance_data)

        # Empty strings should default to 0
        assert result == 0.0

    def test_calculate_threatscore_with_none_values(
        self,
        threatscore_generator,
        basic_compliance_data,
        mock_requirement_attribute_none_values,
    ):
        """Test that None values default to 0."""
        basic_compliance_data.requirements = [
            RequirementData(
                id="REQ-001",
                description="None values test",
                status=StatusChoices.FAIL,
                passed_findings=5,
                failed_findings=5,
                total_findings=10,
            )
        ]
        basic_compliance_data.attributes_by_requirement_id = {
            "REQ-001": {
                "attributes": {
                    "req_attributes": [mock_requirement_attribute_none_values]
                }
            },
        }

        result = threatscore_generator._calculate_threatscore(basic_compliance_data)

        # None values should default to 0
        assert result == 0.0

    def test_critical_failed_requirements_with_string_risk_level(
        self,
        threatscore_generator,
        basic_compliance_data,
        mock_requirement_attribute_string_values,
    ):
        """Test that critical requirements filter works with string LevelOfRisk."""
        basic_compliance_data.requirements = [
            RequirementData(
                id="REQ-001",
                description="High risk with string",
                status=StatusChoices.FAIL,
                passed_findings=0,
                failed_findings=10,
                total_findings=10,
            )
        ]
        basic_compliance_data.attributes_by_requirement_id = {
            "REQ-001": {
                "attributes": {
                    "req_attributes": [mock_requirement_attribute_string_values]
                }
            },
        }

        # Should not raise TypeError
        result = threatscore_generator._get_critical_failed_requirements(
            basic_compliance_data, min_risk_level=4
        )

        # LevelOfRisk="5" should be converted to 5, which is >= 4
        assert len(result) == 1
        assert result[0]["id"] == "REQ-001"
        assert result[0]["risk_level"] == 5
        assert result[0]["weight"] == 150

    def test_critical_failed_requirements_with_invalid_risk_level(
        self,
        threatscore_generator,
        basic_compliance_data,
        mock_requirement_attribute_invalid_values,
    ):
        """Test that invalid LevelOfRisk is excluded from critical requirements."""
        basic_compliance_data.requirements = [
            RequirementData(
                id="REQ-001",
                description="Invalid risk level",
                status=StatusChoices.FAIL,
                passed_findings=0,
                failed_findings=10,
                total_findings=10,
            )
        ]
        basic_compliance_data.attributes_by_requirement_id = {
            "REQ-001": {
                "attributes": {
                    "req_attributes": [mock_requirement_attribute_invalid_values]
                }
            },
        }

        result = threatscore_generator._get_critical_failed_requirements(
            basic_compliance_data, min_risk_level=4
        )

        # Invalid string defaults to 0, which is < 4
        assert len(result) == 0


# =============================================================================
# Critical Failed Requirements Tests
# =============================================================================


class TestCriticalFailedRequirements:
    """Test suite for critical failed requirements identification."""

    def test_get_critical_failed_no_failures(
        self, threatscore_generator, basic_compliance_data, mock_requirement_attribute
    ):
        """Test that no critical requirements are returned when all pass."""
        basic_compliance_data.requirements = [
            RequirementData(
                id="REQ-001",
                description="Passing requirement",
                status=StatusChoices.PASS,
                passed_findings=10,
                failed_findings=0,
                total_findings=10,
            )
        ]
        basic_compliance_data.attributes_by_requirement_id = {
            "REQ-001": {"attributes": {"req_attributes": [mock_requirement_attribute]}},
        }

        result = threatscore_generator._get_critical_failed_requirements(
            basic_compliance_data, min_risk_level=4
        )

        assert len(result) == 0

    def test_get_critical_failed_below_threshold(
        self, threatscore_generator, basic_compliance_data
    ):
        """Test that low risk failures are not included."""
        mock_attr = Mock()
        mock_attr.LevelOfRisk = 2  # Below threshold of 4
        mock_attr.Weight = 100
        mock_attr.Title = "Low Risk"
        mock_attr.Section = "1. IAM"

        basic_compliance_data.requirements = [
            RequirementData(
                id="REQ-001",
                description="Low risk failure",
                status=StatusChoices.FAIL,
                passed_findings=0,
                failed_findings=10,
                total_findings=10,
            )
        ]
        basic_compliance_data.attributes_by_requirement_id = {
            "REQ-001": {"attributes": {"req_attributes": [mock_attr]}},
        }

        result = threatscore_generator._get_critical_failed_requirements(
            basic_compliance_data, min_risk_level=4
        )

        assert len(result) == 0

    def test_get_critical_failed_at_threshold(
        self, threatscore_generator, basic_compliance_data
    ):
        """Test that requirements at exactly the threshold are included."""
        mock_attr = Mock()
        mock_attr.LevelOfRisk = 4  # Exactly at threshold
        mock_attr.Weight = 100
        mock_attr.Title = "At Threshold"
        mock_attr.Section = "1. IAM"

        basic_compliance_data.requirements = [
            RequirementData(
                id="REQ-001",
                description="At threshold failure",
                status=StatusChoices.FAIL,
                passed_findings=0,
                failed_findings=10,
                total_findings=10,
            )
        ]
        basic_compliance_data.attributes_by_requirement_id = {
            "REQ-001": {"attributes": {"req_attributes": [mock_attr]}},
        }

        result = threatscore_generator._get_critical_failed_requirements(
            basic_compliance_data, min_risk_level=4
        )

        assert len(result) == 1
        assert result[0]["risk_level"] == 4

    def test_get_critical_failed_sorted_by_risk_and_weight(
        self, threatscore_generator, basic_compliance_data
    ):
        """Test that critical requirements are sorted by risk level then weight."""
        mock_attr_1 = Mock()
        mock_attr_1.LevelOfRisk = 4
        mock_attr_1.Weight = 150
        mock_attr_1.Title = "Mid risk, high weight"
        mock_attr_1.Section = "1. IAM"

        mock_attr_2 = Mock()
        mock_attr_2.LevelOfRisk = 5
        mock_attr_2.Weight = 50
        mock_attr_2.Title = "High risk, low weight"
        mock_attr_2.Section = "2. Attack Surface"

        mock_attr_3 = Mock()
        mock_attr_3.LevelOfRisk = 5
        mock_attr_3.Weight = 100
        mock_attr_3.Title = "High risk, mid weight"
        mock_attr_3.Section = "3. Logging"

        basic_compliance_data.requirements = [
            RequirementData(
                id="REQ-001",
                description="First",
                status=StatusChoices.FAIL,
                passed_findings=0,
                failed_findings=5,
                total_findings=5,
            ),
            RequirementData(
                id="REQ-002",
                description="Second",
                status=StatusChoices.FAIL,
                passed_findings=0,
                failed_findings=5,
                total_findings=5,
            ),
            RequirementData(
                id="REQ-003",
                description="Third",
                status=StatusChoices.FAIL,
                passed_findings=0,
                failed_findings=5,
                total_findings=5,
            ),
        ]
        basic_compliance_data.attributes_by_requirement_id = {
            "REQ-001": {"attributes": {"req_attributes": [mock_attr_1]}},
            "REQ-002": {"attributes": {"req_attributes": [mock_attr_2]}},
            "REQ-003": {"attributes": {"req_attributes": [mock_attr_3]}},
        }

        result = threatscore_generator._get_critical_failed_requirements(
            basic_compliance_data, min_risk_level=4
        )

        assert len(result) == 3
        # Sorted by (risk_level, weight) descending
        # First: risk=5, weight=100 (REQ-003)
        # Second: risk=5, weight=50 (REQ-002)
        # Third: risk=4, weight=150 (REQ-001)
        assert result[0]["id"] == "REQ-003"
        assert result[1]["id"] == "REQ-002"
        assert result[2]["id"] == "REQ-001"

    def test_get_critical_failed_manual_status_excluded(
        self, threatscore_generator, basic_compliance_data, mock_requirement_attribute
    ):
        """Test that MANUAL status requirements are excluded."""
        basic_compliance_data.requirements = [
            RequirementData(
                id="REQ-001",
                description="Manual requirement",
                status=StatusChoices.MANUAL,
                passed_findings=0,
                failed_findings=0,
                total_findings=0,
            )
        ]
        basic_compliance_data.attributes_by_requirement_id = {
            "REQ-001": {"attributes": {"req_attributes": [mock_requirement_attribute]}},
        }

        result = threatscore_generator._get_critical_failed_requirements(
            basic_compliance_data, min_risk_level=4
        )

        assert len(result) == 0


# =============================================================================
# Section Score Chart Tests
# =============================================================================


class TestSectionScoreChart:
    """Test suite for section score chart generation."""

    def test_create_section_chart_empty_data(
        self, threatscore_generator, basic_compliance_data
    ):
        """Test chart creation with no requirements."""
        basic_compliance_data.requirements = []
        basic_compliance_data.attributes_by_requirement_id = {}

        result = threatscore_generator._create_section_score_chart(
            basic_compliance_data
        )

        assert isinstance(result, io.BytesIO)
        assert result.getvalue()  # Should have content

    def test_create_section_chart_single_section(
        self, threatscore_generator, basic_compliance_data, mock_requirement_attribute
    ):
        """Test chart creation with a single section."""
        basic_compliance_data.requirements = [
            RequirementData(
                id="REQ-001",
                description="IAM requirement",
                status=StatusChoices.PASS,
                passed_findings=10,
                failed_findings=0,
                total_findings=10,
            )
        ]
        basic_compliance_data.attributes_by_requirement_id = {
            "REQ-001": {"attributes": {"req_attributes": [mock_requirement_attribute]}},
        }

        result = threatscore_generator._create_section_score_chart(
            basic_compliance_data
        )

        assert isinstance(result, io.BytesIO)

    def test_create_section_chart_multiple_sections(
        self, threatscore_generator, basic_compliance_data
    ):
        """Test chart creation with multiple sections."""
        mock_attr_1 = Mock()
        mock_attr_1.LevelOfRisk = 4
        mock_attr_1.Weight = 100
        mock_attr_1.Section = "1. IAM"

        mock_attr_2 = Mock()
        mock_attr_2.LevelOfRisk = 3
        mock_attr_2.Weight = 50
        mock_attr_2.Section = "2. Attack Surface"

        basic_compliance_data.requirements = [
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
                description="Attack Surface requirement",
                status=StatusChoices.FAIL,
                passed_findings=5,
                failed_findings=5,
                total_findings=10,
            ),
        ]
        basic_compliance_data.attributes_by_requirement_id = {
            "REQ-001": {"attributes": {"req_attributes": [mock_attr_1]}},
            "REQ-002": {"attributes": {"req_attributes": [mock_attr_2]}},
        }

        result = threatscore_generator._create_section_score_chart(
            basic_compliance_data
        )

        assert isinstance(result, io.BytesIO)

    def test_create_section_chart_no_findings_section_gets_100(
        self, threatscore_generator, basic_compliance_data
    ):
        """Test that sections without findings get 100% score."""
        mock_attr = Mock()
        mock_attr.LevelOfRisk = 4
        mock_attr.Weight = 100
        mock_attr.Section = "1. IAM"

        basic_compliance_data.requirements = [
            RequirementData(
                id="REQ-001",
                description="No findings requirement",
                status=StatusChoices.MANUAL,
                passed_findings=0,
                failed_findings=0,
                total_findings=0,
            )
        ]
        basic_compliance_data.attributes_by_requirement_id = {
            "REQ-001": {"attributes": {"req_attributes": [mock_attr]}},
        }

        # Chart should be created without errors
        result = threatscore_generator._create_section_score_chart(
            basic_compliance_data
        )

        assert isinstance(result, io.BytesIO)


# =============================================================================
# Executive Summary Tests
# =============================================================================


class TestExecutiveSummary:
    """Test suite for executive summary generation."""

    def test_executive_summary_contains_chart(
        self, threatscore_generator, basic_compliance_data, mock_requirement_attribute
    ):
        """Test that executive summary contains a chart."""
        basic_compliance_data.requirements = [
            RequirementData(
                id="REQ-001",
                description="Test requirement",
                status=StatusChoices.PASS,
                passed_findings=10,
                failed_findings=0,
                total_findings=10,
            )
        ]
        basic_compliance_data.attributes_by_requirement_id = {
            "REQ-001": {"attributes": {"req_attributes": [mock_requirement_attribute]}},
        }

        elements = threatscore_generator.create_executive_summary(basic_compliance_data)

        assert len(elements) > 0
        assert any(isinstance(e, Image) for e in elements)

    def test_executive_summary_contains_score_table(
        self, threatscore_generator, basic_compliance_data, mock_requirement_attribute
    ):
        """Test that executive summary contains a score table."""
        basic_compliance_data.requirements = [
            RequirementData(
                id="REQ-001",
                description="Test requirement",
                status=StatusChoices.PASS,
                passed_findings=10,
                failed_findings=0,
                total_findings=10,
            )
        ]
        basic_compliance_data.attributes_by_requirement_id = {
            "REQ-001": {"attributes": {"req_attributes": [mock_requirement_attribute]}},
        }

        elements = threatscore_generator.create_executive_summary(basic_compliance_data)

        assert any(isinstance(e, Table) for e in elements)


# =============================================================================
# Charts Section Tests
# =============================================================================


class TestChartsSection:
    """Test suite for charts section generation."""

    def test_charts_section_no_critical_failures(
        self, threatscore_generator, basic_compliance_data, mock_requirement_attribute
    ):
        """Test charts section when no critical failures exist."""
        basic_compliance_data.requirements = [
            RequirementData(
                id="REQ-001",
                description="Passing requirement",
                status=StatusChoices.PASS,
                passed_findings=10,
                failed_findings=0,
                total_findings=10,
            )
        ]
        basic_compliance_data.attributes_by_requirement_id = {
            "REQ-001": {"attributes": {"req_attributes": [mock_requirement_attribute]}},
        }

        elements = threatscore_generator.create_charts_section(basic_compliance_data)

        assert len(elements) > 0
        # Should contain success message
        paragraphs = [e for e in elements if isinstance(e, Paragraph)]
        content = " ".join(str(p.text) for p in paragraphs)
        assert "No critical failed requirements" in content or "Great job" in content

    def test_charts_section_with_critical_failures(
        self, threatscore_generator, basic_compliance_data
    ):
        """Test charts section when critical failures exist."""
        mock_attr = Mock()
        mock_attr.LevelOfRisk = 5
        mock_attr.Weight = 100
        mock_attr.Title = "Critical Failure"
        mock_attr.Section = "1. IAM"

        basic_compliance_data.requirements = [
            RequirementData(
                id="REQ-001",
                description="Critical failure",
                status=StatusChoices.FAIL,
                passed_findings=0,
                failed_findings=10,
                total_findings=10,
            )
        ]
        basic_compliance_data.attributes_by_requirement_id = {
            "REQ-001": {"attributes": {"req_attributes": [mock_attr]}},
        }

        elements = threatscore_generator.create_charts_section(basic_compliance_data)

        assert len(elements) > 0
        # Should contain a table with critical requirements
        assert any(isinstance(e, Table) for e in elements)

    def test_charts_section_starts_with_page_break(
        self, threatscore_generator, basic_compliance_data
    ):
        """Test that charts section starts with a page break."""
        basic_compliance_data.requirements = []
        basic_compliance_data.attributes_by_requirement_id = {}

        elements = threatscore_generator.create_charts_section(basic_compliance_data)

        assert len(elements) > 0
        assert isinstance(elements[0], PageBreak)

    def test_charts_section_respects_min_risk_level(
        self, threatscore_generator, basic_compliance_data
    ):
        """Test that charts section respects the min_risk_level setting."""
        threatscore_generator._min_risk_level = 5  # Higher threshold

        mock_attr = Mock()
        mock_attr.LevelOfRisk = 4  # Below the new threshold
        mock_attr.Weight = 100
        mock_attr.Title = "Medium Risk"
        mock_attr.Section = "1. IAM"

        basic_compliance_data.requirements = [
            RequirementData(
                id="REQ-001",
                description="Medium risk failure",
                status=StatusChoices.FAIL,
                passed_findings=0,
                failed_findings=10,
                total_findings=10,
            )
        ]
        basic_compliance_data.attributes_by_requirement_id = {
            "REQ-001": {"attributes": {"req_attributes": [mock_attr]}},
        }

        elements = threatscore_generator.create_charts_section(basic_compliance_data)

        # Should not contain a table since risk=4 < min=5
        tables = [e for e in elements if isinstance(e, Table)]
        assert len(tables) == 0


# =============================================================================
# Requirements Index Tests
# =============================================================================


class TestRequirementsIndex:
    """Test suite for requirements index generation."""

    def test_requirements_index_empty(
        self, threatscore_generator, basic_compliance_data
    ):
        """Test requirements index with no requirements."""
        basic_compliance_data.requirements = []
        basic_compliance_data.attributes_by_requirement_id = {}

        elements = threatscore_generator.create_requirements_index(
            basic_compliance_data
        )

        assert len(elements) >= 1  # At least the header
        assert isinstance(elements[0], Paragraph)

    def test_requirements_index_single_requirement(
        self, threatscore_generator, basic_compliance_data, mock_requirement_attribute
    ):
        """Test requirements index with a single requirement."""
        basic_compliance_data.requirements = [
            RequirementData(
                id="REQ-001",
                description="Test requirement",
                status=StatusChoices.PASS,
                passed_findings=10,
                failed_findings=0,
                total_findings=10,
            )
        ]
        basic_compliance_data.attributes_by_requirement_id = {
            "REQ-001": {"attributes": {"req_attributes": [mock_requirement_attribute]}},
        }

        elements = threatscore_generator.create_requirements_index(
            basic_compliance_data
        )

        assert len(elements) >= 2  # Header + at least section header

    def test_requirements_index_organized_by_section(
        self, threatscore_generator, basic_compliance_data
    ):
        """Test that requirements index is organized by section."""
        mock_attr_1 = Mock()
        mock_attr_1.Section = "1. IAM"
        mock_attr_1.SubSection = "1.1 Access"
        mock_attr_1.Title = "IAM Requirement"

        mock_attr_2 = Mock()
        mock_attr_2.Section = "2. Attack Surface"
        mock_attr_2.SubSection = "2.1 Exposure"
        mock_attr_2.Title = "Attack Surface Requirement"

        basic_compliance_data.requirements = []
        basic_compliance_data.attributes_by_requirement_id = {
            "REQ-001": {"attributes": {"req_attributes": [mock_attr_1]}},
            "REQ-002": {"attributes": {"req_attributes": [mock_attr_2]}},
        }

        elements = threatscore_generator.create_requirements_index(
            basic_compliance_data
        )

        # Check that section headers are present
        paragraphs = [e for e in elements if isinstance(e, Paragraph)]
        content = " ".join(str(p.text) for p in paragraphs)
        assert "IAM" in content or "1." in content


# =============================================================================
# Critical Requirements Table Tests
# =============================================================================


class TestCriticalRequirementsTable:
    """Test suite for critical requirements table generation."""

    def test_create_table_single_requirement(self, threatscore_generator):
        """Test table creation with a single requirement."""
        critical = [
            {
                "id": "REQ-001",
                "risk_level": 5,
                "weight": 100,
                "title": "Test Requirement",
                "section": "1. IAM",
            }
        ]

        table = threatscore_generator._create_critical_requirements_table(critical)

        assert isinstance(table, Table)

    def test_create_table_truncates_long_titles(self, threatscore_generator):
        """Test that long titles are truncated."""
        critical = [
            {
                "id": "REQ-001",
                "risk_level": 5,
                "weight": 100,
                "title": "A" * 100,  # Very long title
                "section": "1. IAM",
            }
        ]

        table = threatscore_generator._create_critical_requirements_table(critical)

        # Table should be created without errors
        assert isinstance(table, Table)

    def test_create_table_multiple_requirements(self, threatscore_generator):
        """Test table creation with multiple requirements."""
        critical = [
            {
                "id": "REQ-001",
                "risk_level": 5,
                "weight": 150,
                "title": "First",
                "section": "1. IAM",
            },
            {
                "id": "REQ-002",
                "risk_level": 4,
                "weight": 100,
                "title": "Second",
                "section": "2. Attack Surface",
            },
        ]

        table = threatscore_generator._create_critical_requirements_table(critical)

        assert isinstance(table, Table)
