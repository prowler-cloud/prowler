from unittest import mock

from boto3 import client, resource
from moto import mock_aws

from prowler.providers.aws.services.dlm.dlm_service import LifecyclePolicy
from tests.providers.aws.utils import (
    AWS_ACCOUNT_ARN,
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
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

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        with mock.patch(
            "prowler.providers.aws.services.dlm.dlm_service.DLM",
            new=dlm_client,
        ), mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_service.EC2",
            return_value=EC2(aws_provider),
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
        dlm_client.region = AWS_REGION_US_EAST_1
        dlm_client.audited_partition = "aws"
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
        dlm_client.lifecycle_policy_arn_template = f"arn:{dlm_client.audited_partition}:dlm:{dlm_client.region}:{dlm_client.audited_account}:policy"
        dlm_client.__get_lifecycle_policy_arn_template__ = mock.MagicMock(
            return_value=dlm_client.lifecycle_policy_arn_template
        )
        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.dlm.dlm_ebs_snapshot_lifecycle_policy_exists.dlm_ebs_snapshot_lifecycle_policy_exists.ec2_client",
            new=EC2(aws_provider),
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
            assert (
                result[0].resource_arn
                == f"arn:aws:dlm:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:policy"
            )

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

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.dlm.dlm_ebs_snapshot_lifecycle_policy_exists.dlm_ebs_snapshot_lifecycle_policy_exists.ec2_client",
            new=EC2(aws_provider),
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

        aws_provider = set_mocked_aws_provider([AWS_REGION_US_EAST_1])

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.dlm.dlm_ebs_snapshot_lifecycle_policy_exists.dlm_ebs_snapshot_lifecycle_policy_exists.ec2_client",
            new=EC2(aws_provider),
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
