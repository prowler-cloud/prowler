"""Top-level status consistency and provider scoping for the OCSF output.

Two regressions are covered here:

1. The event's top-level ``status_code``/``status_detail`` must reflect the
   effective (config-aware) status, so a config-invalid PASS cannot produce an
   event where ``compliance.status_id`` says FAIL while ``status_code`` still
   says PASS. The nested Check object keeps the raw finding status.
2. Provider scoping: an Azure-scoped constraint must never affect an AWS output
   even when the global provider would otherwise be relied upon.
"""

from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import patch

from py_ocsf_models.objects.compliance_status import StatusID as ComplianceStatusID

from prowler.lib.check.compliance_models import (
    ComplianceFramework,
    OutputsConfig,
    TableConfig,
    UniversalComplianceRequirement,
)
from prowler.lib.outputs.compliance.universal.ocsf_compliance import (
    OCSFComplianceOutput,
)

_MODULE = "prowler.providers.common.provider.Provider.get_global_provider"


def _finding(check_id, status="PASS", provider="aws"):
    finding = SimpleNamespace()
    finding.provider = provider
    finding.account_uid = "123456789012"
    finding.account_name = "test-account"
    finding.account_organization_uid = "org-123"
    finding.account_organization_name = "test-org"
    finding.region = "us-east-1"
    finding.status = status
    finding.status_extended = f"{check_id} is {status}"
    finding.resource_uid = f"arn:aws:iam::123456789012:{check_id}"
    finding.resource_name = check_id
    finding.resource_details = "details"
    finding.resource_metadata = {}
    finding.resource_tags = {"Name": "test"}
    finding.partition = "aws"
    finding.muted = False
    finding.check_id = check_id
    finding.uid = "test-finding-uid"
    finding.timestamp = datetime(2025, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
    finding.prowler_version = "5.0.0"
    finding.metadata = SimpleNamespace(
        CheckID=check_id,
        CheckTitle=f"Title for {check_id}",
        Description=f"Description for {check_id}",
        Severity="medium",
        ServiceName="iam",
        ResourceType="aws-iam-role",
    )
    return finding


def _framework(constraint, provider="AWS", check_provider="aws"):
    req = UniversalComplianceRequirement(
        id="REQ-1",
        description="Requirement REQ-1",
        attributes={},
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
        attributes_metadata=None,
        outputs=OutputsConfig(table_config=TableConfig(group_by="Section")),
    )


def _run(framework, audit_config, provider="aws", status="PASS"):
    findings = [_finding("check_a", status, provider)]
    with patch(_MODULE) as mock_gp:
        mock_gp.return_value.audit_config = audit_config
        mock_gp.return_value.type = provider
        out = OCSFComplianceOutput(
            findings=findings, framework=framework, provider=provider
        )
    return out.data[0]


_CONSTRAINT = {
    "Check": "check_a",
    "ConfigKey": "max_unused_access_keys_days",
    "Operator": "lte",
    "Value": 45,
}


class Test_OCSF_TopLevel_Status:
    def test_config_invalid_pass_forces_toplevel_fail(self):
        event = _run(_framework(_CONSTRAINT), {"max_unused_access_keys_days": 120})
        # Top-level and nested compliance status agree: both FAIL.
        assert event.compliance.status_id == ComplianceStatusID.Fail
        assert event.status_code == "FAIL"
        assert "Configuration not valid" in event.status_detail
        assert event.status_detail == event.message
        # The nested Check preserves the raw finding result.
        assert event.compliance.checks[0].status == "PASS"

    def test_valid_config_keeps_toplevel_pass(self):
        event = _run(_framework(_CONSTRAINT), {"max_unused_access_keys_days": 30})
        assert event.compliance.status_id == ComplianceStatusID.Pass
        assert event.status_code == "PASS"
        assert "Configuration not valid" not in event.status_detail


class Test_OCSF_Provider_Scoping:
    def test_azure_constraint_does_not_affect_aws_output(self):
        constraint = {**_CONSTRAINT, "Provider": "azure"}
        event = _run(
            _framework(constraint), {"max_unused_access_keys_days": 120}, provider="aws"
        )
        assert event.compliance.status_id == ComplianceStatusID.Pass
        assert event.status_code == "PASS"
        assert "Configuration not valid" not in event.status_detail
