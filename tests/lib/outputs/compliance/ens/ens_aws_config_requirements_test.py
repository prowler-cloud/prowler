"""Integration coverage proving the shared requirement-level config validation
is applied beyond CIS. ENS RD2022 AWS requirement ``op.exp.1.aws.cfg.1`` maps
``config_recorder_all_regions_enabled`` with a ``mute_non_default_regions ==
false`` constraint; muting non-default regions makes a PASS untrustworthy, so
the requirement row must be FAIL even when the finding PASSes. The applied
config is read from the active provider's ``audit_config``."""

import json
import pathlib
from types import SimpleNamespace
from unittest.mock import patch

from prowler.lib.check.compliance_models import Compliance
from prowler.lib.outputs.compliance.ens.ens_aws import AWSENS

_REPO_ROOT = pathlib.Path(__file__).resolve().parents[5]
_ENS = _REPO_ROOT / "prowler" / "compliance" / "aws" / "ens_rd2022_aws.json"
_REQUIREMENT_ID = "op.exp.1.aws.cfg.1"


def _load_ens() -> Compliance:
    return Compliance(**json.load(open(_ENS)))


def _finding(check_id: str, status: str):
    return SimpleNamespace(
        provider="aws",
        account_uid="123456789012",
        region="us-east-1",
        check_id=check_id,
        status=status,
        status_extended=f"{check_id} {status}",
        resource_uid="arn:aws:config:us-east-1:123456789012:recorder/default",
        resource_name="default",
        muted=False,
    )


def _rows_for(requirement_id, findings, audit_config):
    with patch(
        "prowler.providers.common.provider.Provider.get_global_provider"
    ) as mock_gp:
        mock_gp.return_value.audit_config = audit_config
        out = AWSENS(findings=findings, compliance=_load_ens(), file_path=None)
    return [r for r in out._data if r.Requirements_Id == requirement_id]


class Test_ENS_AWS_Config_Requirements:
    def test_region_mute_constraint_forces_fail(self):
        findings = [_finding("config_recorder_all_regions_enabled", "PASS")]
        rows = _rows_for(_REQUIREMENT_ID, findings, {"mute_non_default_regions": True})
        assert rows, f"expected a row for requirement {_REQUIREMENT_ID}"
        assert all(r.Status == "FAIL" for r in rows)
        assert all("Configuration not valid" in r.StatusExtended for r in rows)

    def test_default_config_keeps_finding_status(self):
        findings = [_finding("config_recorder_all_regions_enabled", "PASS")]
        rows = _rows_for(_REQUIREMENT_ID, findings, {})
        assert rows
        assert all(r.Status == "PASS" for r in rows)
        assert all("Configuration not valid" not in r.StatusExtended for r in rows)
