"""Regression: Backup selections must be queried using the plan's own AWS Region.

Place at tests/providers/aws/services/backup/backup_multi_region_test.py
and run: uv run pytest tests/providers/aws/services/backup/backup_multi_region_test.py -q
"""

from types import SimpleNamespace
from unittest.mock import Mock

from botocore.exceptions import ClientError

from prowler.providers.aws.services.backup.backup_service import Backup


def _mock_backup_client(region, local_plan_id, resource_arn):
    client = Mock()
    client.region = region
    paginator = Mock()

    def paginate(*, BackupPlanId):
        if BackupPlanId != local_plan_id:
            raise ClientError(
                {
                    "Error": {
                        "Code": "ResourceNotFoundException",
                        "Message": "Backup plan not found in this Region",
                    }
                },
                "ListBackupSelections",
            )
        return [{"BackupSelectionsList": [{"SelectionId": "selection-1"}]}]

    paginator.paginate.side_effect = paginate
    client.get_paginator.return_value = paginator
    client.get_backup_selection.return_value = {
        "BackupSelection": {"Resources": [resource_arn]}
    }
    return client


def test_backup_selections_are_collected_only_in_matching_region():
    """Cross-Region lookups must not prevent collecting later local plans."""
    backup = Backup.__new__(Backup)
    backup.backup_plans = [
        SimpleNamespace(id="plan-us", region="us-east-1"),
        SimpleNamespace(id="plan-kr", region="ap-northeast-2"),
    ]
    backup.protected_resources = []
    backup.backup_selections = []

    us_resource = "arn:aws:ec2:us-east-1:123456789012:volume/vol-us"
    kr_resource = "arn:aws:ec2:ap-northeast-2:123456789012:volume/vol-kr"
    us_client = _mock_backup_client("us-east-1", "plan-us", us_resource)
    kr_client = _mock_backup_client("ap-northeast-2", "plan-kr", kr_resource)

    backup._list_backup_selections(us_client)
    backup._list_backup_selections(kr_client)

    assert sorted(backup.protected_resources) == sorted([us_resource, kr_resource])
    us_client.get_paginator.return_value.paginate.assert_called_once_with(
        BackupPlanId="plan-us"
    )
    kr_client.get_paginator.return_value.paginate.assert_called_once_with(
        BackupPlanId="plan-kr"
    )
    us_client.get_backup_selection.assert_called_once_with(
        BackupPlanId="plan-us", SelectionId="selection-1"
    )
    kr_client.get_backup_selection.assert_called_once_with(
        BackupPlanId="plan-kr", SelectionId="selection-1"
    )
