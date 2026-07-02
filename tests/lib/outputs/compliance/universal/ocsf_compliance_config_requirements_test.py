"""Integration coverage for ConfigRequirements in the OCSF compliance output.

OCSF is the universal output path every framework renders through, so it is the
natural place to exercise the requirement-level config override end to end across
all operators. When a requirement's configurable check ran with a config too
loose to trust, the Compliance status must be FAIL (even on a PASS finding) and
the message must carry the ``Configuration not valid`` marker. The Check status keeps
the real finding status.
"""

from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import patch

import pytest
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
    finding.account_email = ""
    finding.account_organization_uid = "org-123"
    finding.account_organization_name = "test-org"
    finding.account_tags = {"env": "test"}
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
    finding.compliance = {}
    finding.metadata = SimpleNamespace(
        Provider=provider,
        CheckID=check_id,
        CheckTitle=f"Title for {check_id}",
        CheckType=["test-type"],
        Description=f"Description for {check_id}",
        Severity="medium",
        ServiceName="iam",
        ResourceType="aws-iam-role",
        Risk="risk",
        RelatedUrl="https://example.com",
        Remediation=SimpleNamespace(
            Recommendation=SimpleNamespace(Text="Fix", Url="https://fix.com"),
        ),
        DependsOn=[],
        RelatedTo=[],
        Categories=["test"],
        Notes="",
        AdditionalURLs=[],
    )
    return finding


def _framework(check_id, constraint):
    req = UniversalComplianceRequirement(
        id="REQ-1",
        description="Requirement REQ-1",
        attributes={},
        checks={"aws": [check_id]},
        config_requirements=[constraint],
    )
    return ComplianceFramework(
        framework="TestFW",
        name="Test Framework",
        provider="AWS",
        version="1.0",
        description="Test framework",
        requirements=[req],
        attributes_metadata=None,
        outputs=OutputsConfig(table_config=TableConfig(group_by="Section")),
    )


def _run(check_id, constraint, audit_config):
    fw = _framework(check_id, constraint)
    findings = [_finding(check_id, "PASS")]
    with patch(_MODULE) as mock_gp:
        mock_gp.return_value.audit_config = audit_config
        out = OCSFComplianceOutput(findings=findings, framework=fw, provider="aws")
    return out.data[0]


# (check, constraint, violating_config, valid_config)
_CASES = [
    (
        "securityhub_enabled",
        {
            "Check": "securityhub_enabled",
            "ConfigKey": "mute_non_default_regions",
            "Operator": "eq",
            "Value": False,
        },
        {"mute_non_default_regions": True},
        {"mute_non_default_regions": False},
    ),
    (
        "iam_user_accesskey_unused",
        {
            "Check": "iam_user_accesskey_unused",
            "ConfigKey": "max_unused_access_keys_days",
            "Operator": "lte",
            "Value": 45,
        },
        {"max_unused_access_keys_days": 120},
        {"max_unused_access_keys_days": 30},
    ),
    (
        "cloudwatch_log_group_retention_policy_specific_days_enabled",
        {
            "Check": "cloudwatch_log_group_retention_policy_specific_days_enabled",
            "ConfigKey": "log_group_retention_days",
            "Operator": "gte",
            "Value": 365,
        },
        {"log_group_retention_days": 90},
        {"log_group_retention_days": 365},
    ),
    (
        "sqlserver_recommended_minimal_tls_version",
        {
            "Check": "sqlserver_recommended_minimal_tls_version",
            "ConfigKey": "recommended_minimal_tls_versions",
            "Operator": "subset",
            "Value": ["1.2", "1.3"],
        },
        {"recommended_minimal_tls_versions": ["1.0", "1.2", "1.3"]},
        {"recommended_minimal_tls_versions": ["1.3"]},
    ),
    (
        "acm_certificates_with_secure_key_algorithms",
        {
            "Check": "acm_certificates_with_secure_key_algorithms",
            "ConfigKey": "insecure_key_algorithms",
            "Operator": "superset",
            "Value": ["RSA-1024", "P-192"],
        },
        {"insecure_key_algorithms": ["P-192"]},
        {"insecure_key_algorithms": ["RSA-1024", "P-192"]},
    ),
]


class Test_OCSF_Config_Requirements:
    @pytest.mark.parametrize(
        "check,constraint,bad,ok",
        _CASES,
        ids=[c[1]["Operator"] for c in _CASES],
    )
    def test_violating_config_fails_requirement(self, check, constraint, bad, ok):
        cf = _run(check, constraint, bad)
        assert cf.compliance.status_id == ComplianceStatusID.Fail
        assert "Configuration not valid" in cf.message

    @pytest.mark.parametrize(
        "check,constraint,bad,ok",
        _CASES,
        ids=[c[1]["Operator"] for c in _CASES],
    )
    def test_valid_config_keeps_pass(self, check, constraint, bad, ok):
        cf = _run(check, constraint, ok)
        assert cf.compliance.status_id == ComplianceStatusID.Pass
        assert "Configuration not valid" not in cf.message

    def test_absent_config_assumes_default_ok(self):
        check, constraint, _bad, _ok = _CASES[0]
        cf = _run(check, constraint, {})
        assert cf.compliance.status_id == ComplianceStatusID.Pass
