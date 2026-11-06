"""Exercise selection-local exclusions through the real collectors and checks."""

from importlib import import_module
from unittest.mock import patch

import pytest
from boto3 import client
from botocore.client import BaseClient
from moto import mock_aws

from prowler.providers.aws.services.backup.backup_service import Backup
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    mocked_api_response,
    set_mocked_aws_provider,
)

REGION = AWS_REGION_US_EAST_1
CHECKS = {
    "ebs": ("ec2", "EC2", "ec2_ebs_volume_protected_by_backup_plan"),
    "table": ("dynamodb", "DynamoDB", "dynamodb_table_protected_by_backup_plan"),
    "instance": ("rds", "RDS", "rds_instance_protected_by_backup_plan"),
    "cluster": ("rds", "RDS", "rds_cluster_protected_by_backup_plan"),
}


def create_resources(kind):
    """Create two resources in Moto and return their actual ARNs."""
    arns = {}
    for name in ("excluded", "covered"):
        if kind == "ebs":
            volume = client("ec2", region_name=REGION).create_volume(
                AvailabilityZone=f"{REGION}a", Size=10
            )
            arn = (
                f"arn:aws:ec2:{REGION}:{AWS_ACCOUNT_NUMBER}:volume/{volume['VolumeId']}"
            )
        elif kind == "table":
            arn = client("dynamodb", region_name=REGION).create_table(
                TableName=name,
                AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
                KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
                BillingMode="PAY_PER_REQUEST",
            )["TableDescription"]["TableArn"]
        elif kind == "instance":
            arn = client("rds", region_name=REGION).create_db_instance(
                DBInstanceIdentifier=name,
                DBInstanceClass="db.t3.medium",
                Engine="postgres",
                MasterUsername="admin",
                MasterUserPassword="mock-password",
            )["DBInstance"]["DBInstanceArn"]
        else:
            arn = client("rds", region_name=REGION).create_db_cluster(
                DBClusterIdentifier=name,
                Engine="aurora-postgresql",
                MasterUsername="admin",
                MasterUserPassword="mock-password",
            )["DBCluster"]["DBClusterArn"]
        arns[name] = arn
    return arns


def collect_backup(provider, plans):
    """Supply schema-validated responses without replacing collector methods."""
    calls = []
    original = BaseClient._make_api_call
    role = f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:role/backup-test"

    def api_call(api_client, operation, kwargs):
        """Return validated Backup responses and delegate other service calls.

        Args:
            api_client: Botocore client making the request.
            operation: SDK operation name to dispatch.
            kwargs: Request parameters supplied by the collector.

        Returns:
            A schema-validated Backup response or the delegated SDK response.
        """
        if api_client.meta.service_model.service_name != "backup":
            return original(api_client, operation, kwargs)
        calls.append((operation, kwargs.copy()))
        if operation == "ListBackupPlans":
            response = {
                "BackupPlansList": [
                    {
                        "BackupPlanId": plan_id,
                        "BackupPlanName": plan_id,
                        "VersionId": "version-1",
                        "BackupPlanArn": f"arn:aws:backup:{REGION}:{AWS_ACCOUNT_NUMBER}:backup-plan:{plan_id}",
                    }
                    for plan_id in plans
                ]
            }
        elif operation == "ListBackupSelections":
            response = {
                "BackupSelectionsList": [
                    {
                        "SelectionId": selection_id,
                        "SelectionName": selection_id,
                        "BackupPlanId": kwargs["BackupPlanId"],
                        "IamRoleArn": role,
                    }
                    for selection_id in plans[kwargs["BackupPlanId"]]
                ]
            }
        elif operation == "GetBackupSelection":
            response = {
                "BackupSelection": {
                    "SelectionName": kwargs["SelectionId"],
                    "IamRoleArn": role,
                    **plans[kwargs["BackupPlanId"]][kwargs["SelectionId"]],
                }
            }
        else:
            response = {
                "ListBackupVaults": {"BackupVaultList": []},
                "ListReportPlans": {"ReportPlans": []},
                "ListTags": {"Tags": {}},
            }[operation]
        return mocked_api_response("backup", operation, response)

    with patch.object(BaseClient, "_make_api_call", new=api_call):
        backup = Backup(provider)
    assert {operation for operation, _ in calls} <= {
        "ListBackupPlans",
        "ListBackupSelections",
        "GetBackupSelection",
        "ListBackupVaults",
        "ListReportPlans",
        "ListTags",
    }
    assert {
        (kwargs["BackupPlanId"], kwargs["SelectionId"])
        for operation, kwargs in calls
        if operation == "GetBackupSelection"
    } == {
        (plan_id, selection_id)
        for plan_id, selections in plans.items()
        for selection_id in selections
    }
    assert backup.protected_resources == [
        resource
        for selections in plans.values()
        for selection in selections.values()
        for resource in selection.get("Resources", [])
    ]
    return backup


@mock_aws
def test_preserves_flat_resources_and_filters_selections_independently():
    """Keep flattened resources intact while filtering selections independently."""
    excluded = f"arn:aws:ec2:{REGION}:{AWS_ACCOUNT_NUMBER}:volume/vol-excluded"
    covered = f"arn:aws:ec2:{REGION}:{AWS_ACCOUNT_NUMBER}:volume/vol-covered"
    backup = collect_backup(
        set_mocked_aws_provider([REGION]),
        {
            "plan": {
                "wildcard": {"Resources": ["*"], "NotResources": [excluded]},
                "explicit": {"Resources": [excluded], "NotResources": [covered]},
            }
        },
    )

    assert backup.protected_resources == ["*", excluded]
    assert backup.get_protected_resources(excluded) == [excluded]
    assert backup.get_protected_resources(covered) == ["*"]
    assert backup.protected_resources == ["*", excluded]


@pytest.mark.parametrize("kind", CHECKS)
@pytest.mark.parametrize(
    "scenario",
    [
        "no-exclusion",
        "exact",
        "resource-type-wildcard",
        "resource-prefix-wildcard",
        "nonmatching-exclusion",
        "separate-before",
        "separate-after",
        "other-plan",
        "two-excluding-selections",
        "unrelated-selection",
        "multiple-exclusions",
    ],
)
@mock_aws
def test_selection_exclusions_through_collectors_and_checks(kind, scenario):
    """Exclusions belong to one selection; other selections can still cover."""
    arns = create_resources(kind)
    excluded = arns["excluded"]
    covered = arns["covered"]
    selections = {"wildcard": {"Resources": ["*"], "NotResources": [excluded]}}
    plans = {"plan": selections}
    expected = {excluded: "FAIL", covered: "PASS"}

    if scenario == "no-exclusion":
        selections["wildcard"].pop("NotResources")
        expected[excluded] = "PASS"
    elif scenario == "resource-type-wildcard":
        parts = excluded.split(":", 5)
        separator = "/" if "/" in parts[5] else ":"
        resource_type = parts[5].split(separator, 1)[0]
        selections["wildcard"]["NotResources"] = [
            f"arn:aws:{parts[2]}:*:*:{resource_type}{separator}*"
        ]
        expected[covered] = "FAIL"
    elif scenario == "resource-prefix-wildcard":
        # Select a prefix that distinguishes these two generated resource IDs.
        prefix = next(
            excluded[:length]
            for length in range(1, len(excluded) + 1)
            if not covered.startswith(excluded[:length])
        )
        selections["wildcard"]["NotResources"] = [f"{prefix}*"]
    elif scenario == "nonmatching-exclusion":
        selections["wildcard"]["NotResources"] = [
            excluded.replace(AWS_ACCOUNT_NUMBER, "999999999999")
        ]
        expected[excluded] = "PASS"
    elif scenario in {"separate-before", "separate-after", "other-plan"}:
        independent = {"explicit": {"Resources": [excluded]}}
        if scenario == "other-plan":
            plans["other-plan"] = independent
        elif scenario == "separate-before":
            plans["plan"] = {**independent, **selections}
        else:
            selections.update(independent)
        expected[excluded] = "PASS"
    elif scenario == "two-excluding-selections":
        selections["other-wildcard"] = {
            "Resources": ["*"],
            "NotResources": [covered],
        }
        expected[excluded] = "PASS"
    elif scenario == "unrelated-selection":
        selections["unrelated"] = {"Resources": [covered]}
    elif scenario == "multiple-exclusions":
        selections["wildcard"]["NotResources"] = [covered, excluded]
        expected[covered] = "FAIL"

    provider = set_mocked_aws_provider([REGION])
    backup = collect_backup(provider, plans)
    service, service_class, check_name = CHECKS[kind]
    with patch(
        "prowler.providers.common.provider.Provider.get_global_provider",
        return_value=provider,
    ):
        service_module = import_module(
            f"prowler.providers.aws.services.{service}.{service}_service"
        )
        resource_client = getattr(service_module, service_class)(provider)
        check_module = import_module(
            f"prowler.providers.aws.services.{service}.{check_name}.{check_name}"
        )
        with patch.object(check_module, "backup_client", backup), patch.object(
            check_module, f"{service}_client", resource_client
        ):
            findings = getattr(check_module, check_name)().execute()

    assert len(findings) == 2
    assert {finding.resource_arn: finding.status for finding in findings} == expected
    assert all(finding.region == REGION for finding in findings)
