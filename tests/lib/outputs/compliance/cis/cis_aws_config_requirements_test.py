"""Integration coverage for requirement-level config validation in the CIS AWS
CSV output. Requirement CIS 6.0 AWS 2.11 maps two configurable checks; when the
scan config is looser than the requirement demands, the requirement row must be
FAIL even if the underlying finding is PASS. The applied config is read from the
active provider's ``audit_config``."""

import json
import pathlib
from types import SimpleNamespace
from unittest.mock import patch

from prowler.lib.check.compliance_models import Compliance
from prowler.lib.outputs.compliance.cis.cis_aws import AWSCIS

_REPO_ROOT = pathlib.Path(__file__).resolve().parents[5]
_CIS_6_0 = _REPO_ROOT / "prowler" / "compliance" / "aws" / "cis_6.0_aws.json"


def _load_cis_60() -> Compliance:
    return Compliance(**json.load(open(_CIS_6_0)))


def _finding(check_id: str, status: str):
    return SimpleNamespace(
        provider="aws",
        account_uid="123456789012",
        region="us-east-1",
        check_id=check_id,
        status=status,
        status_extended=f"{check_id} {status}",
        resource_uid="arn:aws:iam::123456789012:user/bob",
        resource_name="bob",
        muted=False,
    )


def _rows_for(requirement_id, findings, audit_config):
    with patch(
        "prowler.providers.common.provider.Provider.get_global_provider"
    ) as mock_gp:
        mock_gp.return_value.audit_config = audit_config
        out = AWSCIS(findings=findings, compliance=_load_cis_60(), file_path=None)
    return [r for r in out._data if r.Requirements_Id == requirement_id]


class Test_CIS_AWS_Config_Requirements:
    def test_loose_config_forces_requirement_fail(self):
        findings = [_finding("iam_user_accesskey_unused", "PASS")]
        rows = _rows_for("2.11", findings, {"max_unused_access_keys_days": 120})
        assert rows, "expected a row for requirement 2.11"
        assert all(r.Status == "FAIL" for r in rows)
        assert all("Configuration not valid" in r.StatusExtended for r in rows)

    def test_valid_config_keeps_finding_status(self):
        findings = [_finding("iam_user_accesskey_unused", "PASS")]
        rows = _rows_for("2.11", findings, {"max_unused_access_keys_days": 45})
        assert rows
        assert all(r.Status == "PASS" for r in rows)
        assert all("Configuration not valid" not in r.StatusExtended for r in rows)

    def test_absent_config_assumes_default_ok(self):
        findings = [_finding("iam_user_accesskey_unused", "PASS")]
        rows = _rows_for("2.11", findings, {})
        assert rows
        assert all(r.Status == "PASS" for r in rows)

    def test_other_requirements_unaffected(self):
        # A finding for a check without ConfigRequirements keeps its status even
        # when the config is loose for a different requirement.
        findings = [_finding("iam_rotate_access_key_90_days", "PASS")]
        rows = _rows_for("2.13", findings, {"max_unused_access_keys_days": 120})
        assert rows
        assert all(r.Status == "PASS" for r in rows)

    def test_region_mute_constraint_forces_fail(self):
        # Requirement 5.16 maps securityhub_enabled with a
        # mute_non_default_regions == false constraint: muting non-default
        # regions makes the PASS untrustworthy, so the row must be FAIL.
        findings = [_finding("securityhub_enabled", "PASS")]
        rows = _rows_for("5.16", findings, {"mute_non_default_regions": True})
        assert rows, "expected a row for requirement 5.16"
        assert all(r.Status == "FAIL" for r in rows)
        assert all("Configuration not valid" in r.StatusExtended for r in rows)

    def test_region_mute_constraint_default_passes(self):
        findings = [_finding("securityhub_enabled", "PASS")]
        rows = _rows_for("5.16", findings, {"mute_non_default_regions": False})
        assert rows
        assert all(r.Status == "PASS" for r in rows)
