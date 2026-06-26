"""Regression coverage for ConfigRequirements on MITRE requirements.

``mitre_attack_aws.json`` declares ``ConfigRequirements`` on its requirements,
but ``Mitre_Requirement`` historically did not define the field, so Pydantic
silently dropped the constraints during MITRE parsing and the config validation
logic never saw them. These tests prove the constraints survive parsing and that
a violated MITRE config requirement forces the compliance result to FAIL through
the universal output path.
"""

from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import patch

from py_ocsf_models.objects.compliance_status import StatusID as ComplianceStatusID

from prowler.lib.check.compliance_models import (
    Compliance,
    Mitre_Requirement,
    adapt_legacy_to_universal,
)
from prowler.lib.outputs.compliance.universal.ocsf_compliance import (
    OCSFComplianceOutput,
)

_MODULE = "prowler.providers.common.provider.Provider.get_global_provider"


def _mitre_compliance(check_id):
    """A minimal one-requirement MITRE framework with a config constraint."""
    return Compliance(
        Framework="MITRE-ATTACK",
        Name="MITRE ATT&CK",
        Provider="AWS",
        Version="",
        Description="Test MITRE framework",
        Requirements=[
            {
                "Name": "Test Technique",
                "Id": "T9999",
                "Tactics": ["initial-access"],
                "SubTechniques": [],
                "Platforms": ["AWS"],
                "Description": "Requirement T9999",
                "TechniqueURL": "https://attack.mitre.org/techniques/T9999",
                "Checks": [check_id],
                "ConfigRequirements": [
                    {
                        "Check": check_id,
                        "ConfigKey": "mute_non_default_regions",
                        "Operator": "eq",
                        "Value": False,
                    }
                ],
                "Attributes": [
                    {
                        "AWSService": "service",
                        "Category": "category",
                        "Value": "value",
                        "Comment": "comment",
                    }
                ],
            }
        ],
    )


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


class Test_Mitre_Config_Requirements:
    def test_config_requirements_survive_mitre_parsing(self):
        """Real mitre_attack_aws.json constraints must not be dropped on parse."""
        compliance = Compliance.parse_file(
            "prowler/compliance/aws/mitre_attack_aws.json"
        )
        requirement = next(r for r in compliance.Requirements if r.Id == "T1190")
        assert isinstance(requirement, Mitre_Requirement)
        assert requirement.ConfigRequirements
        # And they propagate through the legacy -> universal adapter unchanged.
        universal = adapt_legacy_to_universal(compliance)
        universal_requirement = next(
            r for r in universal.requirements if r.id == "T1190"
        )
        assert universal_requirement.config_requirements
        assert len(universal_requirement.config_requirements) == len(
            requirement.ConfigRequirements
        )

    def test_violating_mitre_config_forces_fail(self):
        """A PASS finding becomes FAIL when the MITRE config constraint is violated."""
        check_id = "drs_job_exist"
        framework = adapt_legacy_to_universal(_mitre_compliance(check_id))
        findings = [_finding(check_id, "PASS")]
        with patch(_MODULE) as mock_gp:
            mock_gp.return_value.audit_config = {"mute_non_default_regions": True}
            out = OCSFComplianceOutput(
                findings=findings, framework=framework, provider="aws"
            )
        event = out.data[0]
        assert event.compliance.status_id == ComplianceStatusID.Fail
        assert event.status_code == "FAIL"
        assert "Configuration not valid" in event.message
        # The nested Check object keeps the real (raw) finding status.
        assert event.compliance.checks[0].status == "PASS"

    def test_valid_mitre_config_keeps_pass(self):
        check_id = "drs_job_exist"
        framework = adapt_legacy_to_universal(_mitre_compliance(check_id))
        findings = [_finding(check_id, "PASS")]
        with patch(_MODULE) as mock_gp:
            mock_gp.return_value.audit_config = {"mute_non_default_regions": False}
            out = OCSFComplianceOutput(
                findings=findings, framework=framework, provider="aws"
            )
        event = out.data[0]
        assert event.compliance.status_id == ComplianceStatusID.Pass
        assert event.status_code == "PASS"
        assert "Configuration not valid" not in event.message
