from copy import deepcopy
from unittest import mock

import pytest
from boto3 import client
from botocore.client import BaseClient
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    mocked_api_response,
    set_mocked_aws_provider,
)


class Test_ec2_ebs_backup_selection_exclusions:
    """Exercise selection membership through the real Backup and EC2 collectors."""

    @pytest.mark.parametrize(
        "target_name,separate_selection_order,expected_status",
        [
            pytest.param("excluded", None, "FAIL", id="excluded-volume-must-fail"),
            pytest.param("covered", None, "PASS", id="covered-volume-control"),
            pytest.param(
                "excluded", "after", "PASS", id="covered-by-later-selection-control"
            ),
            pytest.param(
                "excluded", "before", "PASS", id="covered-by-earlier-selection-control"
            ),
        ],
    )
    @mock_aws
    def test_ec2_ebs_backup_selection_exclusions(
        self,
        target_name: str,
        separate_selection_order: str | None,
        expected_status: str,
    ) -> None:
        """NotResources excludes only this selection, not an independent selection.

        This tests backup-plan assignment, not successful or restorable backups.
        AWS semantics: https://docs.aws.amazon.com/aws-backup/latest/devguide/assigning-resources-json.html
        """
        from prowler.providers.aws.services.backup.backup_service import Backup
        from prowler.providers.aws.services.ec2.ec2_service import EC2

        ec2_api = client("ec2", region_name=AWS_REGION_US_EAST_1)
        volumes = {
            name: ec2_api.create_volume(
                AvailabilityZone="us-east-1a", Size=10, VolumeType="gp2"
            )["VolumeId"]
            for name in ("excluded", "covered")
        }
        volume_arns = {
            name: f"arn:aws:ec2:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:volume/{volume_id}"
            for name, volume_id in volumes.items()
        }
        backup_api = client("backup", region_name=AWS_REGION_US_EAST_1)
        plan_id = backup_api.create_backup_plan(
            BackupPlan={
                "BackupPlanName": "selection-exclusion-regression",
                "Rules": [
                    {
                        "RuleName": "DailyBackup",
                        "TargetBackupVaultName": "test-vault",
                        "ScheduleExpression": "cron(0 12 * * ? *)",
                    }
                ],
            }
        )["BackupPlanId"]
        role_arn = (
            f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:role/service-role/"
            "AWSBackupDefaultServiceRole"
        )
        selections = {
            "wildcard-except-excluded": {
                "SelectionName": "wildcard-except-excluded",
                "IamRoleArn": role_arn,
                "Resources": ["*"],
                "NotResources": [volume_arns["excluded"]],
            }
        }
        if separate_selection_order:
            selections["explicit-volume"] = {
                "SelectionName": "explicit-volume",
                "IamRoleArn": role_arn,
                "Resources": [volume_arns["excluded"]],
            }
        selection_ids = list(selections)
        if separate_selection_order == "before":
            selection_ids.reverse()

        # Moto 5.1.11 does not implement these selection APIs. Validate responses
        # before returning them at the SDK boundary; do not mock the collector.
        list_response = mocked_api_response(
            "backup",
            "ListBackupSelections",
            {
                "BackupSelectionsList": [
                    {
                        "SelectionId": selection_id,
                        "SelectionName": selections[selection_id]["SelectionName"],
                        "BackupPlanId": plan_id,
                        "IamRoleArn": role_arn,
                    }
                    for selection_id in selection_ids
                ]
            },
        )
        get_responses = {
            selection_id: mocked_api_response(
                "backup",
                "GetBackupSelection",
                {
                    "BackupSelection": selection,
                    "SelectionId": selection_id,
                    "BackupPlanId": plan_id,
                },
            )
            for selection_id, selection in selections.items()
        }
        retrieved_ids = set()
        make_api_call = BaseClient._make_api_call

        def selection_api_call(api_client, operation_name, kwargs):
            if api_client.meta.service_model.service_name == "backup":
                if operation_name == "ListBackupSelections":
                    assert kwargs["BackupPlanId"] == plan_id
                    return deepcopy(list_response)
                if operation_name == "GetBackupSelection":
                    assert kwargs["BackupPlanId"] == plan_id
                    selection_id = kwargs["SelectionId"]
                    retrieved_ids.add(selection_id)
                    return deepcopy(get_responses[selection_id])
            return make_api_call(api_client, operation_name, kwargs)

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])
        check_module = (
            "prowler.providers.aws.services.ec2."
            "ec2_ebs_volume_protected_by_backup_plan."
            "ec2_ebs_volume_protected_by_backup_plan"
        )
        with (
            mock.patch.object(BaseClient, "_make_api_call", new=selection_api_call),
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
        ):
            backup = Backup(aws_provider)
            ec2 = EC2(aws_provider)
            with (
                mock.patch(f"{check_module}.backup_client", new=backup),
                mock.patch(f"{check_module}.ec2_client", new=ec2),
            ):
                from prowler.providers.aws.services.ec2.ec2_ebs_volume_protected_by_backup_plan.ec2_ebs_volume_protected_by_backup_plan import (
                    ec2_ebs_volume_protected_by_backup_plan,
                )

                findings = ec2_ebs_volume_protected_by_backup_plan().execute()

        assert retrieved_ids == set(selection_ids)
        assert len(findings) == 2
        findings_by_id = {finding.resource_id: finding for finding in findings}
        assert set(findings_by_id) == set(volumes.values())
        finding = findings_by_id[volumes[target_name]]
        assert finding.resource_arn == volume_arns[target_name]
        assert finding.region == AWS_REGION_US_EAST_1
        print(
            f"target={target_name}; selections={selections}; "
            f"collected_resources={backup.protected_resources}; "
            f"actual={finding.status}; expected={expected_status}"
        )
        assert finding.status == expected_status
        protection = "protected" if expected_status == "PASS" else "not protected"
        assert finding.status_extended == (
            f"EBS Volume {volumes[target_name]} is {protection} by a backup plan."
        )
