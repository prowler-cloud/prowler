from unittest import mock

from boto3 import client, resource
from mock import patch
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_REGION_EU_WEST_1,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)


def mock_generate_regional_clients(provider, service):
    regional_client = provider._session.current_session.client(
        service, region_name=AWS_REGION_US_EAST_1
    )
    regional_client.region = AWS_REGION_US_EAST_1
    return {AWS_REGION_US_EAST_1: regional_client}


@patch(
    "prowler.providers.aws.aws_provider.AwsProvider.generate_regional_clients",
    new=mock_generate_regional_clients,
)
class Test_ec2_ebs_public_snapshot:
    @mock_aws
    def test_ec2_default_snapshots(self):
        from prowler.providers.aws.services.ec2.ec2_service import EC2

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_ebs_public_snapshot.ec2_ebs_public_snapshot.ec2_client",
            new=EC2(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_ebs_public_snapshot.ec2_ebs_public_snapshot import (
                ec2_ebs_public_snapshot,
            )

            check = ec2_ebs_public_snapshot()
            result = check.execute()

            # Default snapshots
            assert len(result) == 561

    @mock_aws
    def test_ec2_public_snapshot(self):
        # Create EC2 Mocked Resources
        ec2 = resource("ec2", region_name=AWS_REGION_US_EAST_1)
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        volume = ec2.create_volume(Size=80, AvailabilityZone=f"{AWS_REGION_US_EAST_1}a")
        snapshot = volume.create_snapshot(Description="testsnap")
        ec2_client.modify_snapshot_attribute(
            SnapshotId=snapshot.id,
            Attribute="createVolumePermission",
            OperationType="add",
            GroupNames=["all"],
        )

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_ebs_public_snapshot.ec2_ebs_public_snapshot.ec2_client",
            new=EC2(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_ebs_public_snapshot.ec2_ebs_public_snapshot import (
                ec2_ebs_public_snapshot,
            )

            check = ec2_ebs_public_snapshot()
            results = check.execute()

            # Default snapshots + 1 created
            assert len(results) == 562

            for snap in results:
                if snap.resource_id == snapshot.id:
                    assert snap.region == AWS_REGION_US_EAST_1
                    assert snap.resource_tags == []
                    assert snap.status == "FAIL"
                    assert (
                        snap.status_extended
                        == f"EBS Snapshot {snapshot.id} is currently Public."
                    )
                    assert (
                        snap.resource_arn
                        == f"arn:{aws_provider.identity.partition}:ec2:{AWS_REGION_US_EAST_1}:{aws_provider.identity.account}:snapshot/{snapshot.id}"
                    )

    @mock_aws
    def test_ec2_private_snapshot(self):
        # Create EC2 Mocked Resources
        ec2 = resource("ec2", region_name=AWS_REGION_US_EAST_1)
        snapshot = volume = ec2.create_volume(
            Size=80, AvailabilityZone=f"{AWS_REGION_US_EAST_1}a", Encrypted=True
        )
        snapshot = volume.create_snapshot(Description="testsnap")

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_ebs_public_snapshot.ec2_ebs_public_snapshot.ec2_client",
            new=EC2(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_ebs_public_snapshot.ec2_ebs_public_snapshot import (
                ec2_ebs_public_snapshot,
            )

            check = ec2_ebs_public_snapshot()
            results = check.execute()

            # Default snapshots + 1 created
            assert len(results) == 562

            for snap in results:
                if snap.resource_id == snapshot.id:
                    assert snap.region == AWS_REGION_US_EAST_1
                    assert snap.resource_tags == []
                    assert snap.status == "PASS"
                    assert (
                        snap.status_extended
                        == f"EBS Snapshot {snapshot.id} is not Public."
                    )
                    assert (
                        snap.resource_arn
                        == f"arn:{aws_provider.identity.partition}:ec2:{AWS_REGION_US_EAST_1}:{aws_provider.identity.account}:snapshot/{snapshot.id}"
                    )
