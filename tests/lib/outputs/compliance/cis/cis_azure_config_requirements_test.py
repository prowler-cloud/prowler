"""Integration coverage for the ``subset`` set-operator in a CSV output.

CIS Azure 5.0 requirement 9.1.3 maps ``storage_smb_channel_encryption_with_secure_algorithm``
with a ``recommended_smb_channel_encryption_algorithms subset ["AES-256-GCM"]``
constraint: widening the allowlist with a weaker algorithm makes the PASS
untrustworthy, so the requirement row must be FAIL. Exercises the shared override
path through a per-provider CSV class (not just OCSF)."""

import json
import pathlib
from types import SimpleNamespace
from unittest.mock import patch

from prowler.lib.check.compliance_models import Compliance
from prowler.lib.outputs.compliance.cis.cis_azure import AzureCIS

_REPO_ROOT = pathlib.Path(__file__).resolve().parents[5]
_CIS_5_0_AZURE = _REPO_ROOT / "prowler" / "compliance" / "azure" / "cis_5.0_azure.json"
_REQUIREMENT_ID = "9.1.3"
_CHECK = "storage_smb_channel_encryption_with_secure_algorithm"


def _load():
    return Compliance(**json.load(open(_CIS_5_0_AZURE)))


def _finding(check_id, status):
    return SimpleNamespace(
        provider="azure",
        account_uid="00000000-0000-0000-0000-000000000000",
        region="eastus",
        check_id=check_id,
        status=status,
        status_extended=f"{check_id} {status}",
        resource_uid="/subscriptions/x/storageAccounts/sa",
        resource_name="sa",
        muted=False,
    )


def _rows_for(audit_config):
    findings = [_finding(_CHECK, "PASS")]
    with patch(
        "prowler.providers.common.provider.Provider.get_global_provider"
    ) as mock_gp:
        mock_gp.return_value.audit_config = audit_config
        out = AzureCIS(findings=findings, compliance=_load(), file_path=None)
    return [r for r in out._data if r.Requirements_Id == _REQUIREMENT_ID]


class Test_CIS_Azure_Subset_Constraint:
    def test_widened_allowlist_forces_fail(self):
        rows = _rows_for(
            {
                "recommended_smb_channel_encryption_algorithms": [
                    "AES-128-CCM",
                    "AES-256-GCM",
                ]
            }
        )
        assert rows, f"expected a row for requirement {_REQUIREMENT_ID}"
        assert all(r.Status == "FAIL" for r in rows)
        assert all("CONFIG NOT VALID" in r.StatusExtended for r in rows)

    def test_secure_allowlist_keeps_pass(self):
        rows = _rows_for(
            {"recommended_smb_channel_encryption_algorithms": ["AES-256-GCM"]}
        )
        assert rows
        assert all(r.Status == "PASS" for r in rows)

    def test_absent_config_keeps_pass(self):
        rows = _rows_for({})
        assert rows
        assert all(r.Status == "PASS" for r in rows)
