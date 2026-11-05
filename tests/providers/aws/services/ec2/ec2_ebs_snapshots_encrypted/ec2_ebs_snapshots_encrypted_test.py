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


def _self_owned_snapshot_count():
    paginator = client("ec2", region_name=AWS_REGION_US_EAST_1).get_paginator(
        "describe_snapshots"
    )
    return sum(len(page["Snapshots"]) for page in paginator.paginate(OwnerIds=["self"]))


@patch(
    "prowler.providers.aws.aws_provider.AwsProvider.generate_regional_clients",
    new=mock_generate_regional_clients,
)
class Test_ec2_ebs_snapshots_encrypted:
    @mock_aws
    def test_ec2_default_snapshots(self):
        from prowler.providers.aws.services.ec2.ec2_service import EC2

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.ec2.ec2_ebs_snapshots_encrypted.ec2_ebs_snapshots_encrypted.ec2_client",
                new=EC2(aws_provider),
            ),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_ebs_snapshots_encrypted.ec2_ebs_snapshots_encrypted import (
                ec2_ebs_snapshots_encrypted,
            )

            check = ec2_ebs_snapshots_encrypted()
            result = check.execute()

            assert len(result) == _self_owned_snapshot_count()

    @mock_aws
    def test_ec2_unencrypted_snapshot(self):
        # Create EC2 Mocked Resources
        ec2 = resource("ec2", region_name=AWS_REGION_US_EAST_1)
        volume = ec2.create_volume(Size=80, AvailabilityZone=f"{AWS_REGION_US_EAST_1}a")
        snapshot = volume.create_snapshot(Description="testsnap")

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.ec2.ec2_ebs_snapshots_encrypted.ec2_ebs_snapshots_encrypted.ec2_client",
                new=EC2(aws_provider),
            ),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_ebs_snapshots_encrypted.ec2_ebs_snapshots_encrypted import (
                ec2_ebs_snapshots_encrypted,
            )

            check = ec2_ebs_snapshots_encrypted()
            results = check.execute()

            assert len(results) == _self_owned_snapshot_count()

            for snap in results:
                if snap.resource_id == snapshot.id:
                    assert snap.region == AWS_REGION_US_EAST_1
                    assert snap.resource_tags == []
                    assert snap.status == "FAIL"
                    assert (
                        snap.status_extended
                        == f"EBS Snapshot {snapshot.id} is unencrypted."
                    )
                    assert (
                        snap.resource_arn
                        == f"arn:{aws_provider.identity.partition}:ec2:{AWS_REGION_US_EAST_1}:{aws_provider.identity.account}:snapshot/{snapshot.id}"
                    )

    @mock_aws
    def test_ec2_encrypted_snapshot(self):
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

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.ec2.ec2_ebs_snapshots_encrypted.ec2_ebs_snapshots_encrypted.ec2_client",
                new=EC2(aws_provider),
            ),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_ebs_snapshots_encrypted.ec2_ebs_snapshots_encrypted import (
                ec2_ebs_snapshots_encrypted,
            )

            check = ec2_ebs_snapshots_encrypted()
            results = check.execute()

            assert len(results) == _self_owned_snapshot_count()

            for snap in results:
                if snap.resource_id == snapshot.id:
                    assert snap.region == AWS_REGION_US_EAST_1
                    assert snap.resource_tags == []
                    assert snap.status == "PASS"
                    assert (
                        snap.status_extended
                        == f"EBS Snapshot {snapshot.id} is encrypted."
                    )
                    assert (
                        snap.resource_arn
                        == f"arn:{aws_provider.identity.partition}:ec2:{AWS_REGION_US_EAST_1}:{aws_provider.identity.account}:snapshot/{snapshot.id}"
                    )
