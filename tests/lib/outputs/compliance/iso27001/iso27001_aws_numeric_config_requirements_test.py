"""Integration coverage for a numeric (lte) ConfigRequirements in a CSV output.

ISO 27001 AWS A.8.10 maps ``ec2_instance_older_than_specific_days`` with a
``max_ec2_instance_age_in_days lte 180`` constraint (the config.yaml default,
applied as a security floor by the sdk-config-compliance coverage work): if the
user loosens the threshold above 180 the check can PASS while the requirement is
not really satisfied, so the requirement row must be FAIL with [CONFIG NOT VALID].
Mirrors cis_azure_config_requirements_test.py but for a numeric threshold.
"""

import json
import pathlib
from types import SimpleNamespace
from unittest.mock import patch

from prowler.lib.check.compliance_models import Compliance
from prowler.lib.outputs.compliance.iso27001.iso27001_aws import AWSISO27001

_REPO_ROOT = pathlib.Path(__file__).resolve().parents[5]
_FRAMEWORK = _REPO_ROOT / "prowler" / "compliance" / "aws" / "iso27001_2022_aws.json"
_REQUIREMENT_ID = "A.8.10"
_CHECK = "ec2_instance_older_than_specific_days"
_KEY = "max_ec2_instance_age_in_days"


def _load():
    return Compliance(**json.load(open(_FRAMEWORK)))


def _finding(check_id, status):
    return SimpleNamespace(
        provider="aws",
        account_uid="123456789012",
        region="us-east-1",
        check_id=check_id,
        status=status,
        status_extended=f"{check_id} {status}",
        resource_uid="arn:aws:ec2:us-east-1:123456789012:instance/i-0",
        resource_name="i-0",
        muted=False,
    )


def _rows_for(audit_config):
    findings = [_finding(_CHECK, "PASS")]
    with patch(
        "prowler.providers.common.provider.Provider.get_global_provider"
    ) as mock_gp:
        mock_gp.return_value.audit_config = audit_config
        mock_gp.return_value.type = "aws"
        out = AWSISO27001(findings=findings, compliance=_load(), file_path=None)
    return [r for r in out._data if r.Requirements_Id == _REQUIREMENT_ID]


class Test_ISO27001_AWS_Numeric_Constraint:
    def test_loosened_threshold_forces_fail(self):
        # 365 > 180 -> the applied config is looser than the requirement needs.
        rows = _rows_for({_KEY: 365})
        assert rows, f"expected a row for requirement {_REQUIREMENT_ID}"
        assert all(r.Status == "FAIL" for r in rows)
        assert all("CONFIG NOT VALID" in r.StatusExtended for r in rows)

    def test_default_threshold_keeps_pass(self):
        # 180 == the floor -> satisfies lte 180, the PASS stands.
        rows = _rows_for({_KEY: 180})
        assert rows
        assert all(r.Status == "PASS" for r in rows)

    def test_unset_config_keeps_pass(self):
        # Key not set -> default assumed adequate, no override.
        rows = _rows_for({})
        assert rows
        assert all(r.Status == "PASS" for r in rows)
