from unittest import mock

from boto3 import resource
from mock import patch
from moto import mock_aws

from tests.providers.aws.audit_info_utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    AWS_REGION_US_EAST_1,
    AWS_REGION_US_EAST_1_AZA,
    set_mocked_aws_audit_info,
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
class Test_ec2_ebs_volume_snapshots_exists:
    @mock_aws
    def test_no_volumes(self):
        from prowler.providers.aws.services.ec2.ec2_service import EC2

        current_audit_info = set_mocked_aws_audit_info(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_ebs_volume_snapshots_exists.ec2_ebs_volume_snapshots_exists.ec2_client",
            new=EC2(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_ebs_volume_snapshots_exists.ec2_ebs_volume_snapshots_exists import (
                ec2_ebs_volume_snapshots_exists,
            )

            check = ec2_ebs_volume_snapshots_exists()
            result = check.execute()

            assert len(result) == 0

    @mock_aws
    def test_ec2_volume_without_snapshots(self):
        ec2 = resource("ec2", region_name=AWS_REGION_US_EAST_1)
        volume = ec2.create_volume(Size=80, AvailabilityZone=AWS_REGION_US_EAST_1_AZA)
        volume_arn = f"arn:aws:ec2:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:volume/{volume.id}"
        from prowler.providers.aws.services.ec2.ec2_service import EC2

        current_audit_info = set_mocked_aws_audit_info(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_ebs_volume_snapshots_exists.ec2_ebs_volume_snapshots_exists.ec2_client",
            new=EC2(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_ebs_volume_snapshots_exists.ec2_ebs_volume_snapshots_exists import (
                ec2_ebs_volume_snapshots_exists,
            )

            check = ec2_ebs_volume_snapshots_exists()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Snapshots not found for the EBS volume {volume.id}."
            )
            assert result[0].resource_id == volume.id
            assert result[0].resource_arn == volume_arn
            assert result[0].resource_tags is None
            assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_ec2_volume_with_snapshot(self):
        # Create EC2 Mocked Resources
        ec2 = resource("ec2", region_name=AWS_REGION_US_EAST_1)
        volume = ec2.create_volume(Size=80, AvailabilityZone=AWS_REGION_US_EAST_1_AZA)
        volume_arn = f"arn:aws:ec2:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:volume/{volume.id}"
        _ = volume.create_snapshot(Description="testsnap")

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        current_audit_info = set_mocked_aws_audit_info(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_ebs_volume_snapshots_exists.ec2_ebs_volume_snapshots_exists.ec2_client",
            new=EC2(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_ebs_volume_snapshots_exists.ec2_ebs_volume_snapshots_exists import (
                ec2_ebs_volume_snapshots_exists,
            )

            check = ec2_ebs_volume_snapshots_exists()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Snapshots found for the EBS volume {result[0].resource_id}."
            )
            assert result[0].resource_id == volume.id
            assert result[0].resource_arn == volume_arn
            assert result[0].resource_tags is None
            assert result[0].region == AWS_REGION_US_EAST_1

    @mock_aws
    def test_ec2_volume_with_and_without_snapshot(self):
        # Create EC2 Mocked Resources
        ec2 = resource("ec2", region_name=AWS_REGION_US_EAST_1)

        volume1 = ec2.create_volume(Size=80, AvailabilityZone=AWS_REGION_US_EAST_1_AZA)
        volume1_arn = f"arn:aws:ec2:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:volume/{volume1.id}"
        _ = volume1.create_snapshot(Description="test-snap")

        volume2 = ec2.create_volume(Size=80, AvailabilityZone=AWS_REGION_US_EAST_1_AZA)
        volume2_arn = f"arn:aws:ec2:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:volume/{volume2.id}"

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        current_audit_info = set_mocked_aws_audit_info(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_ebs_volume_snapshots_exists.ec2_ebs_volume_snapshots_exists.ec2_client",
            new=EC2(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_ebs_volume_snapshots_exists.ec2_ebs_volume_snapshots_exists import (
                ec2_ebs_volume_snapshots_exists,
            )

            check = ec2_ebs_volume_snapshots_exists()
            result = check.execute()

            assert len(result) == 2
            for res in result:
                if res.resource_id == volume1.id:
                    assert res.status == "PASS"
                    assert (
                        res.status_extended
                        == f"Snapshots found for the EBS volume {res.resource_id}."
                    )
                    assert res.resource_id == volume1.id
                    assert res.resource_arn == volume1_arn
                    assert res.resource_tags is None
                    assert res.region == AWS_REGION_US_EAST_1
                if res.resource_id == volume2.id:
                    assert res.status == "FAIL"
                    assert (
                        res.status_extended
                        == f"Snapshots not found for the EBS volume {res.resource_id}."
                    )
                    assert res.resource_id == volume2.id
                    assert res.resource_arn == volume2_arn
                    assert res.resource_tags is None
                    assert res.region == AWS_REGION_US_EAST_1
