from unittest.mock import Mock, patch

import pytest
from reportlab.platypus import Image, LongTable, Paragraph, Table
from tasks.jobs.reports import FRAMEWORK_REGISTRY, ComplianceData, RequirementData
from tasks.jobs.reports.cis import (
    CISReportGenerator,
    _normalize_profile,
    _profile_badge_text,
)

from api.models import StatusChoices

# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def cis_generator():
    """Create a CISReportGenerator instance for testing."""
    config = FRAMEWORK_REGISTRY["cis"]
    return CISReportGenerator(config)


def _make_attr(
    section: str,
    profile_value: str = "Level 1",
    assessment_value: str = "Automated",
    sub_section: str = "",
    **extras,
) -> Mock:
    """Build a mock CIS_Requirement_Attribute with duck-typed fields."""
    attr = Mock()
    attr.Section = section
    attr.SubSection = sub_section
    # CIS enums have `.value`. Use a simple Mock that exposes `.value`.
    attr.Profile = Mock(value=profile_value)
    attr.AssessmentStatus = Mock(value=assessment_value)
    attr.Description = extras.get("description", "desc")
    attr.RationaleStatement = extras.get("rationale", "the rationale")
    attr.ImpactStatement = extras.get("impact", "the impact")
    attr.RemediationProcedure = extras.get("remediation", "the remediation")
    attr.AuditProcedure = extras.get("audit", "the audit")
    attr.AdditionalInformation = ""
    attr.DefaultValue = ""
    attr.References = extras.get("references", "https://example.com")
    return attr


@pytest.fixture
def basic_cis_compliance_data():
    """Create basic ComplianceData for CIS testing (no requirements)."""
    return ComplianceData(
        tenant_id="tenant-123",
        scan_id="scan-456",
        provider_id="provider-789",
        compliance_id="cis_5.0_aws",
        framework="CIS",
        name="CIS Amazon Web Services Foundations Benchmark v5.0.0",
        version="5.0",
        description="Center for Internet Security AWS Foundations Benchmark",
    )


@pytest.fixture
def populated_cis_compliance_data(basic_cis_compliance_data):
    """CIS data with mixed requirements across 2 sections, Profile L1/L2, Pass/Fail/Manual."""
    data = basic_cis_compliance_data
    data.requirements = [
        RequirementData(
            id="1.1",
            description="Maintain current contact details",
            status=StatusChoices.PASS,
            passed_findings=5,
            failed_findings=0,
            total_findings=5,
            checks=["aws_check_1"],
        ),
        RequirementData(
            id="1.2",
            description="Ensure root account has no access keys",
            status=StatusChoices.FAIL,
            passed_findings=0,
            failed_findings=3,
            total_findings=3,
            checks=["aws_check_2"],
        ),
        RequirementData(
            id="1.3",
            description="Ensure MFA is enabled for all IAM users",
            status=StatusChoices.MANUAL,
            checks=[],
        ),
        RequirementData(
            id="2.1",
            description="Ensure S3 Buckets are logging",
            status=StatusChoices.PASS,
            passed_findings=2,
            failed_findings=0,
            total_findings=2,
            checks=["aws_check_3"],
        ),
        RequirementData(
            id="2.2",
            description="Ensure encryption at rest is enabled",
            status=StatusChoices.FAIL,
            passed_findings=0,
            failed_findings=4,
            total_findings=4,
            checks=["aws_check_4"],
        ),
    ]
    data.attributes_by_requirement_id = {
        "1.1": {
            "attributes": {
                "req_attributes": [
                    _make_attr(
                        "1 Identity and Access Management",
                        profile_value="Level 1",
                        assessment_value="Automated",
                    )
                ],
                "checks": ["aws_check_1"],
            }
        },
        "1.2": {
            "attributes": {
                "req_attributes": [
                    _make_attr(
                        "1 Identity and Access Management",
                        profile_value="Level 1",
                        assessment_value="Automated",
                    )
                ],
                "checks": ["aws_check_2"],
            }
        },
        "1.3": {
            "attributes": {
                "req_attributes": [
                    _make_attr(
                        "1 Identity and Access Management",
                        profile_value="Level 2",
                        assessment_value="Manual",
                    )
                ],
                "checks": [],
            }
        },
        "2.1": {
            "attributes": {
                "req_attributes": [
                    _make_attr(
                        "2 Storage",
                        profile_value="Level 2",
                        assessment_value="Automated",
                    )
                ],
                "checks": ["aws_check_3"],
            }
        },
        "2.2": {
            "attributes": {
                "req_attributes": [
                    _make_attr(
                        "2 Storage",
                        profile_value="Level 1",
                        assessment_value="Automated",
                    )
                ],
                "checks": ["aws_check_4"],
            }
        },
    }
    return data


# =============================================================================
# Helper function tests
# =============================================================================


class TestNormalizeProfile:
    """Test suite for _normalize_profile helper."""

    def test_level_1_string(self):
        assert _normalize_profile(Mock(value="Level 1")) == "L1"

    def test_level_2_string(self):
        assert _normalize_profile(Mock(value="Level 2")) == "L2"

    def test_e3_level_1(self):
        assert _normalize_profile(Mock(value="E3 Level 1")) == "L1"

    def test_e5_level_2(self):
        assert _normalize_profile(Mock(value="E5 Level 2")) == "L2"

    def test_none_returns_other(self):
        assert _normalize_profile(None) == "Other"

    def test_substring_trap_rejected(self):
        """Unrelated tokens containing the literal ``L2`` must NOT map to L2."""
        # A future enum value like "CL2 Kubernetes Worker" would be silently
        # misclassified by a naive substring check.
        assert _normalize_profile(Mock(value="CL2 Worker")) == "Other"
        assert _normalize_profile(Mock(value="HL2 Legacy")) == "Other"

    def test_raw_string_level_1(self):
        # Mock without .value falls back to str(profile); use a real string
        class NoValue:
            def __str__(self):
                return "Level 1"

        assert _normalize_profile(NoValue()) == "L1"

    def test_unknown_profile_returns_other(self):
        assert _normalize_profile(Mock(value="Custom Profile")) == "Other"


class TestProfileBadgeText:
    def test_l1_label(self):
        assert _profile_badge_text("L1") == "Level 1"

    def test_l2_label(self):
        assert _profile_badge_text("L2") == "Level 2"

    def test_other_label(self):
        assert _profile_badge_text("Other") == "Other"


# =============================================================================
# Generator initialization
# =============================================================================


class TestCISGeneratorInitialization:
    def test_generator_created(self, cis_generator):
        assert cis_generator is not None
        assert cis_generator.config.name == "cis"

    def test_generator_language(self, cis_generator):
        assert cis_generator.config.language == "en"

    def test_generator_sections_dynamic(self, cis_generator):
        # CIS sections differ per variant so config.sections MUST be None
        assert cis_generator.config.sections is None

    def test_attribute_fields_contain_cis_specific(self, cis_generator):
        for field in ("Profile", "AssessmentStatus", "RationaleStatement"):
            assert field in cis_generator.config.attribute_fields


# =============================================================================
# _derive_sections
# =============================================================================


class TestDeriveSections:
    def test_preserves_first_seen_order(
        self, cis_generator, populated_cis_compliance_data
    ):
        sections = cis_generator._derive_sections(populated_cis_compliance_data)
        assert sections == [
            "1 Identity and Access Management",
            "2 Storage",
        ]

    def test_deduplicates_sections(self, cis_generator, basic_cis_compliance_data):
        basic_cis_compliance_data.requirements = [
            RequirementData(id="1.1", description="a", status=StatusChoices.PASS),
            RequirementData(id="1.2", description="b", status=StatusChoices.PASS),
        ]
        attr = _make_attr("1 IAM")
        basic_cis_compliance_data.attributes_by_requirement_id = {
            "1.1": {"attributes": {"req_attributes": [attr], "checks": []}},
            "1.2": {"attributes": {"req_attributes": [attr], "checks": []}},
        }
        assert cis_generator._derive_sections(basic_cis_compliance_data) == ["1 IAM"]

    def test_empty_data_returns_empty(self, cis_generator, basic_cis_compliance_data):
        basic_cis_compliance_data.requirements = []
        basic_cis_compliance_data.attributes_by_requirement_id = {}
        assert cis_generator._derive_sections(basic_cis_compliance_data) == []


# =============================================================================
# _compute_statistics
# =============================================================================


class TestComputeStatistics:
    def test_totals(self, cis_generator, populated_cis_compliance_data):
        stats = cis_generator._compute_statistics(populated_cis_compliance_data)
        assert stats["total"] == 5
        assert stats["passed"] == 2
        assert stats["failed"] == 2
        assert stats["manual"] == 1

    def test_overall_compliance_excludes_manual(
        self, cis_generator, populated_cis_compliance_data
    ):
        stats = cis_generator._compute_statistics(populated_cis_compliance_data)
        # 2 passed / 4 evaluated (pass + fail) = 50%
        assert stats["overall_compliance"] == pytest.approx(50.0)

    def test_overall_compliance_all_manual(
        self, cis_generator, basic_cis_compliance_data
    ):
        basic_cis_compliance_data.requirements = [
            RequirementData(id="x", description="d", status=StatusChoices.MANUAL),
        ]
        attr = _make_attr("1 IAM", profile_value="Level 1", assessment_value="Manual")
        basic_cis_compliance_data.attributes_by_requirement_id = {
            "x": {"attributes": {"req_attributes": [attr], "checks": []}},
        }
        stats = cis_generator._compute_statistics(basic_cis_compliance_data)
        # No evaluated → defaults to 100%
        assert stats["overall_compliance"] == 100.0

    def test_profile_counts(self, cis_generator, populated_cis_compliance_data):
        stats = cis_generator._compute_statistics(populated_cis_compliance_data)
        profile = stats["profile_counts"]
        # From fixture:
        #   L1: 1.1 (PASS, Auto), 1.2 (FAIL, Auto), 2.2 (FAIL, Auto) → pass=1, fail=2, manual=0
        #   L2: 1.3 (MANUAL, Manual), 2.1 (PASS, Auto) → pass=1, fail=0, manual=1
        assert profile["L1"] == {"passed": 1, "failed": 2, "manual": 0}
        assert profile["L2"] == {"passed": 1, "failed": 0, "manual": 1}

    def test_assessment_counts(self, cis_generator, populated_cis_compliance_data):
        stats = cis_generator._compute_statistics(populated_cis_compliance_data)
        assessment = stats["assessment_counts"]
        # Automated: 1.1 PASS, 1.2 FAIL, 2.1 PASS, 2.2 FAIL → pass=2, fail=2, manual=0
        # Manual: 1.3 MANUAL → pass=0, fail=0, manual=1
        assert assessment["Automated"] == {"passed": 2, "failed": 2, "manual": 0}
        assert assessment["Manual"] == {"passed": 0, "failed": 0, "manual": 1}

    def test_top_failing_sections_includes_all_evaluated(
        self, cis_generator, populated_cis_compliance_data
    ):
        stats = cis_generator._compute_statistics(populated_cis_compliance_data)
        top = stats["top_failing_sections"]
        # Both sections have 1 PASS + 1 FAIL evaluated → tied at 50%. The
        # sort is stable, so both must appear and both must be capped at
        # 5 entries.
        assert len(top) == 2
        section_names = {name for name, _ in top}
        assert section_names == {
            "1 Identity and Access Management",
            "2 Storage",
        }

    def test_compute_statistics_is_memoized(
        self, cis_generator, populated_cis_compliance_data
    ):
        """Calling ``_compute_statistics`` twice with the same data must
        reuse the cached value and not re-run the uncached kernel."""
        with patch.object(
            CISReportGenerator,
            "_compute_statistics_uncached",
            wraps=cis_generator._compute_statistics_uncached,
        ) as spy:
            cis_generator._compute_statistics(populated_cis_compliance_data)
            cis_generator._compute_statistics(populated_cis_compliance_data)
            assert spy.call_count == 1


# =============================================================================
# Executive summary
# =============================================================================


class TestCISExecutiveSummary:
    def test_title_present(self, cis_generator, populated_cis_compliance_data):
        elements = cis_generator.create_executive_summary(populated_cis_compliance_data)
        paragraphs = [e for e in elements if isinstance(e, Paragraph)]
        text = " ".join(str(p.text) for p in paragraphs)
        assert "Executive Summary" in text

    def test_tables_rendered(self, cis_generator, populated_cis_compliance_data):
        elements = cis_generator.create_executive_summary(populated_cis_compliance_data)
        tables = [e for e in elements if isinstance(e, Table)]
        # Exact count: Summary, Profile, Assessment, Top Failing Sections = 4.
        assert len(tables) == 4

    def test_no_requirements(self, cis_generator, basic_cis_compliance_data):
        basic_cis_compliance_data.requirements = []
        basic_cis_compliance_data.attributes_by_requirement_id = {}
        elements = cis_generator.create_executive_summary(basic_cis_compliance_data)
        # With no requirements: Summary table always renders, and both Profile
        # and Assessment breakdown tables render with a 0-filled default row,
        # but Top Failing Sections is suppressed → exactly 3 tables.
        tables = [e for e in elements if isinstance(e, Table)]
        assert len(tables) == 3


# =============================================================================
# Charts section
# =============================================================================


class TestCISChartsSection:
    def test_charts_rendered(self, cis_generator, populated_cis_compliance_data):
        elements = cis_generator.create_charts_section(populated_cis_compliance_data)
        # At least 1 image for the pie + 1 for section bar + 1 for stacked
        images = [e for e in elements if isinstance(e, Image)]
        assert len(images) >= 1

    def test_charts_no_data_no_crash(self, cis_generator, basic_cis_compliance_data):
        basic_cis_compliance_data.requirements = []
        basic_cis_compliance_data.attributes_by_requirement_id = {}
        elements = cis_generator.create_charts_section(basic_cis_compliance_data)
        # Must not raise; may or may not have any Image
        assert isinstance(elements, list)


# =============================================================================
# Requirements index
# =============================================================================


class TestCISRequirementsIndex:
    def test_title_present(self, cis_generator, populated_cis_compliance_data):
        elements = cis_generator.create_requirements_index(
            populated_cis_compliance_data
        )
        paragraphs = [e for e in elements if isinstance(e, Paragraph)]
        text = " ".join(str(p.text) for p in paragraphs)
        assert "Requirements Index" in text

    def test_groups_by_section(self, cis_generator, populated_cis_compliance_data):
        elements = cis_generator.create_requirements_index(
            populated_cis_compliance_data
        )
        paragraphs = [e for e in elements if isinstance(e, Paragraph)]
        text = " ".join(str(p.text) for p in paragraphs)
        assert "1 Identity and Access Management" in text
        assert "2 Storage" in text

    def test_renders_tables_per_section(
        self, cis_generator, populated_cis_compliance_data
    ):
        elements = cis_generator.create_requirements_index(
            populated_cis_compliance_data
        )
        # One table per section with requirements. ``create_data_table``
        # returns a LongTable when the row count exceeds its threshold and a
        # plain Table otherwise — both are valid.
        tables = [e for e in elements if isinstance(e, (Table, LongTable))]
        assert len(tables) == 2


# =============================================================================
# Detailed findings extras hook
# =============================================================================


class TestRenderRequirementDetailExtras:
    def test_inserts_all_fields(self, cis_generator, populated_cis_compliance_data):
        req = populated_cis_compliance_data.requirements[1]  # 1.2 FAIL
        extras = cis_generator._render_requirement_detail_extras(
            req, populated_cis_compliance_data
        )
        text = " ".join(str(p.text) for p in extras if isinstance(p, Paragraph))
        assert "Rationale" in text
        assert "Impact" in text
        assert "Audit Procedure" in text
        assert "Remediation" in text
        assert "References" in text

    def test_missing_metadata_returns_empty(
        self, cis_generator, basic_cis_compliance_data
    ):
        basic_cis_compliance_data.attributes_by_requirement_id = {}
        req = RequirementData(id="99", description="unknown", status=StatusChoices.FAIL)
        extras = cis_generator._render_requirement_detail_extras(
            req, basic_cis_compliance_data
        )
        assert extras == []

    def test_escapes_html_chars(self, cis_generator, basic_cis_compliance_data):
        attr = _make_attr(
            "1 IAM",
            rationale="<script>alert('x')</script>",
        )
        basic_cis_compliance_data.attributes_by_requirement_id = {
            "1.1": {"attributes": {"req_attributes": [attr], "checks": []}}
        }
        req = RequirementData(id="1.1", description="d", status=StatusChoices.FAIL)
        extras = cis_generator._render_requirement_detail_extras(
            req, basic_cis_compliance_data
        )
        text = " ".join(str(p.text) for p in extras if isinstance(p, Paragraph))
        assert "<script>" not in text
        assert "&lt;script&gt;" in text


# =============================================================================
# Cover page
# =============================================================================


class TestCISCoverPage:
    @patch("tasks.jobs.reports.cis.Image")
    def test_cover_page_has_logo(
        self, mock_image, cis_generator, basic_cis_compliance_data
    ):
        elements = cis_generator.create_cover_page(basic_cis_compliance_data)
        assert len(elements) > 0
        assert mock_image.call_count >= 1

    def test_cover_page_title_includes_version(
        self, cis_generator, basic_cis_compliance_data
    ):
        elements = cis_generator.create_cover_page(basic_cis_compliance_data)
        paragraphs = [e for e in elements if isinstance(e, Paragraph)]
        content = " ".join(str(p.text) for p in paragraphs)
        assert "CIS Benchmark" in content
        assert "5.0" in content

    def test_cover_page_title_includes_provider_when_set(
        self, cis_generator, basic_cis_compliance_data
    ):
        provider = Mock()
        provider.provider = "aws"
        provider.uid = "123456789012"
        provider.alias = "test-account"
        basic_cis_compliance_data.provider_obj = provider
        elements = cis_generator.create_cover_page(basic_cis_compliance_data)
        paragraphs = [e for e in elements if isinstance(e, Paragraph)]
        content = " ".join(str(p.text) for p in paragraphs)
        assert "AWS" in content
