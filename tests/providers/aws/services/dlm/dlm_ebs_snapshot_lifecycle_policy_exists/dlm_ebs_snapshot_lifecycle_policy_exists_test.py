from unittest import mock

from boto3 import client, resource
from moto import mock_aws

from prowler.providers.aws.services.dlm.dlm_service import LifecyclePolicy
from tests.providers.aws.audit_info_utils import (
    AWS_ACCOUNT_ARN,
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_audit_info,
)

LIFECYCLE_POLICY_ID = "policy-XXXXXXXXXXXX"


class Test_dlm_ebs_snapshot_lifecycle_policy_exists:
    @mock_aws
    def test_no_ebs_snapshot_no_lifecycle_policies(self):
        # DLM Mock Client
        dlm_client = mock.MagicMock
        dlm_client.audited_account = AWS_ACCOUNT_NUMBER
        dlm_client.audited_account_arn = AWS_ACCOUNT_ARN
        dlm_client.lifecycle_policies = {}

        audit_info = set_mocked_aws_audit_info([AWS_REGION_US_EAST_1])

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        with mock.patch(
            "prowler.providers.aws.services.dlm.dlm_service.DLM",
            new=dlm_client,
        ), mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_service.EC2",
            return_value=EC2(audit_info),
        ) as ec2_client, mock.patch(
            "prowler.providers.aws.services.ec2.ec2_client.ec2_client",
            new=ec2_client,
        ):
            from prowler.providers.aws.services.dlm.dlm_ebs_snapshot_lifecycle_policy_exists.dlm_ebs_snapshot_lifecycle_policy_exists import (
                dlm_ebs_snapshot_lifecycle_policy_exists,
            )

            check = dlm_ebs_snapshot_lifecycle_policy_exists()
            result = check.execute()
            assert len(result) == 0

    @mock_aws
    def test_one_ebs_snapshot_and_dlm_lifecycle_policy(self):
        # Generate EC2 Client
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        ec2_resource = resource("ec2", region_name=AWS_REGION_US_EAST_1)
        # Create EC2 Volume and Snapshot
        volume_id = ec2_resource.create_volume(
            AvailabilityZone="us-east-1a",
            Size=80,
            VolumeType="gp2",
        ).id
        _ = ec2_client.create_snapshot(
            VolumeId=volume_id,
            TagSpecifications=[
                {
                    "ResourceType": "snapshot",
                    "Tags": [
                        {"Key": "test", "Value": "test"},
                    ],
                },
            ],
        )["SnapshotId"]

        # DLM Mock Client
        dlm_client = mock.MagicMock
        dlm_client.audited_account = AWS_ACCOUNT_NUMBER
        dlm_client.audited_account_arn = AWS_ACCOUNT_ARN
        dlm_client.lifecycle_policies = {
            AWS_REGION_US_EAST_1: {
                LIFECYCLE_POLICY_ID: LifecyclePolicy(
                    id=LIFECYCLE_POLICY_ID,
                    state="ENABLED",
                    tags={},
                    type="EBS_SNAPSHOT_MANAGEMENT",
                )
            }
        }

        audit_info = set_mocked_aws_audit_info([AWS_REGION_US_EAST_1])

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.dlm.dlm_ebs_snapshot_lifecycle_policy_exists.dlm_ebs_snapshot_lifecycle_policy_exists.ec2_client",
            new=EC2(audit_info),
        ), mock.patch(
            "prowler.providers.aws.services.dlm.dlm_ebs_snapshot_lifecycle_policy_exists.dlm_ebs_snapshot_lifecycle_policy_exists.dlm_client",
            new=dlm_client,
        ):
            from prowler.providers.aws.services.dlm.dlm_ebs_snapshot_lifecycle_policy_exists.dlm_ebs_snapshot_lifecycle_policy_exists import (
                dlm_ebs_snapshot_lifecycle_policy_exists,
            )

            check = dlm_ebs_snapshot_lifecycle_policy_exists()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].status_extended == "EBS snapshot lifecycle policies found."
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_id == AWS_ACCOUNT_NUMBER
            assert result[0].resource_arn == AWS_ACCOUNT_ARN

    @mock_aws
    def test_one_ebs_snapshot_and_no_dlm_lifecycle_policy(self):
        # Generate EC2 Client
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        ec2_resource = resource("ec2", region_name=AWS_REGION_US_EAST_1)
        # Create EC2 Volume and Snapshot
        volume_id = ec2_resource.create_volume(
            AvailabilityZone="us-east-1a",
            Size=80,
            VolumeType="gp2",
        ).id
        _ = ec2_client.create_snapshot(
            VolumeId=volume_id,
            TagSpecifications=[
                {
                    "ResourceType": "snapshot",
                    "Tags": [
                        {"Key": "test", "Value": "test"},
                    ],
                },
            ],
        )["SnapshotId"]

        # DLM Mock Client
        dlm_client = mock.MagicMock
        dlm_client.audited_account = AWS_ACCOUNT_NUMBER
        dlm_client.audited_account_arn = AWS_ACCOUNT_ARN
        dlm_client.lifecycle_policies = {}

        # from prowler.providers.aws.services.ec2.ec2_service import EC2

        audit_info = set_mocked_aws_audit_info([AWS_REGION_US_EAST_1])

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.dlm.dlm_ebs_snapshot_lifecycle_policy_exists.dlm_ebs_snapshot_lifecycle_policy_exists.ec2_client",
            new=EC2(audit_info),
        ), mock.patch(
            "prowler.providers.aws.services.dlm.dlm_ebs_snapshot_lifecycle_policy_exists.dlm_ebs_snapshot_lifecycle_policy_exists.dlm_client",
            new=dlm_client,
        ):
            from prowler.providers.aws.services.dlm.dlm_ebs_snapshot_lifecycle_policy_exists.dlm_ebs_snapshot_lifecycle_policy_exists import (
                dlm_ebs_snapshot_lifecycle_policy_exists,
            )

            check = dlm_ebs_snapshot_lifecycle_policy_exists()
            result = check.execute()
            assert len(result) == 0

    @mock_aws
    def test_no_ebs_snapshot_and_dlm_lifecycle_policy(self):
        # DLM Mock Client
        dlm_client = mock.MagicMock
        dlm_client.audited_account = AWS_ACCOUNT_NUMBER
        dlm_client.audited_account_arn = AWS_ACCOUNT_ARN
        dlm_client.lifecycle_policies = {
            AWS_REGION_US_EAST_1: {
                LIFECYCLE_POLICY_ID: LifecyclePolicy(
                    id=LIFECYCLE_POLICY_ID,
                    state="ENABLED",
                    tags={},
                    type="EBS_SNAPSHOT_MANAGEMENT",
                )
            }
        }

        # from prowler.providers.aws.services.ec2.ec2_service import EC2

        audit_info = set_mocked_aws_audit_info([AWS_REGION_US_EAST_1])

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.dlm.dlm_ebs_snapshot_lifecycle_policy_exists.dlm_ebs_snapshot_lifecycle_policy_exists.ec2_client",
            new=EC2(audit_info),
        ) as ec2_client, mock.patch(
            "prowler.providers.aws.services.dlm.dlm_ebs_snapshot_lifecycle_policy_exists.dlm_ebs_snapshot_lifecycle_policy_exists.dlm_client",
            new=dlm_client,
        ):
            # Remove all snapshots
            ec2_client.regions_with_snapshots = {}

            from prowler.providers.aws.services.dlm.dlm_ebs_snapshot_lifecycle_policy_exists.dlm_ebs_snapshot_lifecycle_policy_exists import (
                dlm_ebs_snapshot_lifecycle_policy_exists,
            )

            check = dlm_ebs_snapshot_lifecycle_policy_exists()
            result = check.execute()
            assert len(result) == 0
