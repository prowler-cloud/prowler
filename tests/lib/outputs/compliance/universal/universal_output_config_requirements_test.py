"""Coverage for ConfigRequirements + provider scoping in the universal CSV.

The universal CSV must apply the same effective-status logic as the OCSF/table
outputs: a config-invalid PASS is reported as FAIL instead of leaking the raw
finding status. Provider scoping must also hold, so a constraint scoped to
another provider (e.g. Azure) never affects this provider's output (e.g. AWS).
"""

from types import SimpleNamespace
from unittest.mock import patch

from prowler.lib.check.compliance_models import (
    AttributeMetadata,
    ComplianceFramework,
    OutputsConfig,
    TableConfig,
    UniversalComplianceRequirement,
)
from prowler.lib.outputs.compliance.universal.universal_output import (
    UniversalComplianceOutput,
)

_MODULE = "prowler.providers.common.provider.Provider.get_global_provider"


def _make_finding(check_id, status="PASS", provider="aws"):
    finding = SimpleNamespace()
    finding.provider = provider
    finding.account_uid = "123456789012"
    finding.account_name = "test-account"
    finding.region = "us-east-1"
    finding.status = status
    finding.status_extended = f"{check_id} is {status}"
    finding.resource_uid = f"arn:aws:iam::123456789012:{check_id}"
    finding.resource_name = check_id
    finding.muted = False
    finding.check_id = check_id
    finding.metadata = SimpleNamespace(Provider=provider, CheckID=check_id)
    finding.compliance = {}
    return finding


def _make_framework(constraint, provider="AWS", check_provider="aws"):
    req = UniversalComplianceRequirement(
        id="1.1",
        description="test requirement",
        attributes={"Section": "IAM"},
        checks={check_provider: ["check_a"]},
        config_requirements=[constraint],
    )
    return ComplianceFramework(
        framework="TestFW",
        name="Test Framework",
        provider=provider,
        version="1.0",
        description="Test framework",
        requirements=[req],
        attributes_metadata=[AttributeMetadata(key="Section", type="str")],
        outputs=OutputsConfig(table_config=TableConfig(group_by="Section")),
    )


def _run(framework, audit_config, provider="aws", status="PASS"):
    findings = [_make_finding("check_a", status, provider)]
    with patch(_MODULE) as mock_gp:
        mock_gp.return_value.audit_config = audit_config
        mock_gp.return_value.type = provider
        out = UniversalComplianceOutput(
            findings=findings, framework=framework, provider=provider
        )
    return out.data[0].dict()


class Test_Universal_CSV_Config_Requirements:
    _CONSTRAINT = {
        "Check": "check_a",
        "ConfigKey": "max_unused_access_keys_days",
        "Operator": "lte",
        "Value": 45,
    }

    def test_violating_config_forces_fail(self):
        fw = _make_framework(self._CONSTRAINT)
        row = _run(fw, {"max_unused_access_keys_days": 120})
        assert row["Status"] == "FAIL"
        assert "Configuration not valid" in row["StatusExtended"]

    def test_valid_config_keeps_pass(self):
        fw = _make_framework(self._CONSTRAINT)
        row = _run(fw, {"max_unused_access_keys_days": 30})
        assert row["Status"] == "PASS"
        assert "Configuration not valid" not in row["StatusExtended"]

    def test_absent_config_assumes_default_ok(self):
        fw = _make_framework(self._CONSTRAINT)
        row = _run(fw, {})
        assert row["Status"] == "PASS"


class Test_Universal_CSV_Provider_Scoping:
    def test_azure_constraint_does_not_affect_aws_output(self):
        """An Azure-scoped constraint must not force an AWS output to FAIL."""
        constraint = {
            "Check": "check_a",
            "ConfigKey": "max_unused_access_keys_days",
            "Operator": "lte",
            "Value": 45,
            "Provider": "azure",
        }
        fw = _make_framework(constraint)
        # Even with a config that *would* violate the constraint, the AWS output
        # must keep PASS because the constraint is scoped to Azure.
        row = _run(fw, {"max_unused_access_keys_days": 120}, provider="aws")
        assert row["Status"] == "PASS"
        assert "Configuration not valid" not in row["StatusExtended"]
