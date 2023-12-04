from unittest import mock

from boto3 import resource
from mock import patch
from moto import mock_ec2

from tests.providers.aws.audit_info_utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_audit_info,
)

AWS_REGION_AZ = "us-east-1a"

AWS_ACCOUNT_ARN = f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"


def mock_generate_regional_clients(service, audit_info, _):
    regional_client = audit_info.audit_session.client(
        service, region_name=AWS_REGION_EU_WEST_1
    )
    regional_client.region = AWS_REGION_EU_WEST_1
    return {AWS_REGION_EU_WEST_1: regional_client}


@patch(
    "prowler.providers.aws.lib.service.service.generate_regional_clients",
    new=mock_generate_regional_clients,
)
class Test_ec2_ebs_volume_snapshots_exists:
    @mock_ec2
    def test_no_volumes(self):
        from prowler.providers.aws.services.ec2.ec2_service import EC2

        current_audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
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

    @mock_ec2
    def test_ec2_volume_without_snapshots(self):
        ec2 = resource("ec2", region_name=AWS_REGION_EU_WEST_1)
        volume = ec2.create_volume(Size=80, AvailabilityZone=AWS_REGION_AZ)
        volume_arn = f"arn:aws:ec2:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:volume/{volume.id}"
        from prowler.providers.aws.services.ec2.ec2_service import EC2

        current_audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
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
            assert result[0].region == AWS_REGION_EU_WEST_1

    @mock_ec2
    def test_ec2_volume_with_snapshot(self):
        # Create EC2 Mocked Resources
        ec2 = resource("ec2", region_name=AWS_REGION_EU_WEST_1)
        volume = ec2.create_volume(Size=80, AvailabilityZone=AWS_REGION_AZ)
        volume_arn = f"arn:aws:ec2:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:volume/{volume.id}"
        _ = volume.create_snapshot(Description="testsnap")

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        current_audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
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
            assert result[0].region == AWS_REGION_EU_WEST_1

    @mock_ec2
    def test_ec2_volume_with_and_without_snapshot(self):
        # Create EC2 Mocked Resources
        ec2 = resource("ec2", region_name=AWS_REGION_EU_WEST_1)

        volume1 = ec2.create_volume(Size=80, AvailabilityZone=AWS_REGION_AZ)
        volume1_arn = f"arn:aws:ec2:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:volume/{volume1.id}"
        _ = volume1.create_snapshot(Description="test-snap")

        volume2 = ec2.create_volume(Size=80, AvailabilityZone=AWS_REGION_AZ)
        volume2_arn = f"arn:aws:ec2:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:volume/{volume2.id}"

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        current_audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
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
                    assert res.region == AWS_REGION_EU_WEST_1
                if res.resource_id == volume2.id:
                    assert res.status == "FAIL"
                    assert (
                        res.status_extended
                        == f"Snapshots not found for the EBS volume {res.resource_id}."
                    )
                    assert res.resource_id == volume2.id
                    assert res.resource_arn == volume2_arn
                    assert res.resource_tags is None
                    assert res.region == AWS_REGION_EU_WEST_1
