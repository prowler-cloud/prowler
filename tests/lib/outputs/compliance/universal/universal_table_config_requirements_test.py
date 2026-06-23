"""Integration coverage for ConfigRequirements in the console table generators.

The table generators aggregate pass/fail counts, so a requirement whose config
is too loose must count its (otherwise PASS) finding as FAIL. Driven through the
universal table renderer, which backs the table output for every framework using
the shared ``get_effective_status`` helper."""

from types import SimpleNamespace
from unittest.mock import patch

from prowler.lib.check.compliance_models import (
    ComplianceFramework,
    OutputsConfig,
    TableConfig,
    UniversalComplianceRequirement,
)
from prowler.lib.outputs.compliance.universal.universal_table import get_universal_table

_MODULE = "prowler.providers.common.provider.Provider.get_global_provider"
_CHECK = "securityhub_enabled"


def _finding(status="PASS"):
    return SimpleNamespace(
        check_metadata=SimpleNamespace(CheckID=_CHECK), status=status, muted=False
    )


# The overview table is only printed when there is more than one finding, so the
# tests use two PASS findings (both mapping the constrained check).
_FINDINGS = [_finding("PASS"), _finding("PASS")]


def _framework():
    req = UniversalComplianceRequirement(
        id="1.1",
        description="region check",
        attributes={"Section": "Monitoring"},
        checks={"aws": [_CHECK]},
        config_requirements=[
            {
                "Check": _CHECK,
                "ConfigKey": "mute_non_default_regions",
                "Operator": "eq",
                "Value": False,
            }
        ],
    )
    return ComplianceFramework(
        framework="TestFW",
        name="Test Framework",
        provider="AWS",
        version="1.0",
        description="Test",
        requirements=[req],
        outputs=OutputsConfig(table_config=TableConfig(group_by="Section")),
    )


def _render(audit_config, capsys, output_directory):
    with patch(_MODULE) as mock_gp:
        mock_gp.return_value.audit_config = audit_config
        get_universal_table(
            findings=_FINDINGS,
            bulk_checks_metadata={},
            compliance_framework_name="testfw_1.0_aws",
            output_filename="out",
            output_directory=str(output_directory),
            compliance_overview=False,
            framework=_framework(),
            provider="aws",
        )
    return capsys.readouterr().out


class Test_Universal_Table_Config_Requirements:
    def test_violating_config_counts_pass_finding_as_fail(self, capsys, tmp_path):
        out = _render({"mute_non_default_regions": True}, capsys, tmp_path)
        assert "FAIL(2)" in out
        assert "PASS(2)" not in out

    def test_valid_config_keeps_pass_count(self, capsys, tmp_path):
        out = _render({"mute_non_default_regions": False}, capsys, tmp_path)
        assert "PASS(2)" in out
        assert "FAIL(2)" not in out

    def test_absent_config_keeps_pass_count(self, capsys, tmp_path):
        out = _render({}, capsys, tmp_path)
        assert "PASS(2)" in out
        assert "FAIL(2)" not in out


def _framework_two_requirements():
    """Same check evidences two requirements; only one carries a guardrail.

    Drives the double-count scenario: with the config violated, the shared
    finding is FAIL for the constrained requirement and PASS for the other, so
    its index would land in both pass and fail counts without FAIL precedence.
    """
    constrained = UniversalComplianceRequirement(
        id="1.1",
        description="region check",
        attributes={"Section": "Monitoring"},
        checks={"aws": [_CHECK]},
        config_requirements=[
            {
                "Check": _CHECK,
                "Provider": "aws",
                "ConfigKey": "mute_non_default_regions",
                "Operator": "eq",
                "Value": False,
            }
        ],
    )
    unconstrained = UniversalComplianceRequirement(
        id="2.1",
        description="other check",
        attributes={"Section": "Logging"},
        checks={"aws": [_CHECK]},
    )
    return ComplianceFramework(
        framework="TestFW",
        name="Test Framework",
        provider="AWS",
        version="1.0",
        description="Test",
        requirements=[constrained, unconstrained],
        outputs=OutputsConfig(table_config=TableConfig(group_by="Section")),
    )


class Test_Universal_Table_Multi_Requirement_Dedup:
    def test_finding_in_two_requirements_counted_once_with_fail_precedence(
        self, capsys, tmp_path
    ):
        # mute=True violates the constrained requirement → each shared PASS
        # finding must be counted once as FAIL in the overview, not double
        # counted as both PASS and FAIL across the two requirements it maps.
        with patch(_MODULE) as mock_gp:
            mock_gp.return_value.audit_config = {"mute_non_default_regions": True}
            mock_gp.return_value.type = "aws"
            get_universal_table(
                findings=_FINDINGS,
                bulk_checks_metadata={},
                compliance_framework_name="testfw_1.0_aws",
                output_filename="out",
                output_directory=str(tmp_path),
                compliance_overview=True,
                framework=_framework_two_requirements(),
                provider="aws",
            )
        out = capsys.readouterr().out
        # Two findings, each counted once as FAIL → 100% FAIL, 0 PASS.
        assert "(2) FAIL" in out
        assert "(0) PASS" in out
