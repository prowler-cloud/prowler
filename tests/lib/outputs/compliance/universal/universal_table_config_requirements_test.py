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


def _render(audit_config, capsys):
    with patch(_MODULE) as mock_gp:
        mock_gp.return_value.audit_config = audit_config
        get_universal_table(
            findings=_FINDINGS,
            bulk_checks_metadata={},
            compliance_framework_name="testfw_1.0_aws",
            output_filename="out",
            output_directory="/tmp",
            compliance_overview=False,
            framework=_framework(),
            provider="aws",
        )
    return capsys.readouterr().out


class Test_Universal_Table_Config_Requirements:
    def test_violating_config_counts_pass_finding_as_fail(self, capsys):
        out = _render({"mute_non_default_regions": True}, capsys)
        assert "FAIL(2)" in out
        assert "PASS(2)" not in out

    def test_valid_config_keeps_pass_count(self, capsys):
        out = _render({"mute_non_default_regions": False}, capsys)
        assert "PASS(2)" in out
        assert "FAIL(2)" not in out

    def test_absent_config_keeps_pass_count(self, capsys):
        out = _render({}, capsys)
        assert "PASS(2)" in out
        assert "FAIL(2)" not in out
