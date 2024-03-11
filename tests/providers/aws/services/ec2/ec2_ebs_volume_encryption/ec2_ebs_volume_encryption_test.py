from unittest import mock

from boto3 import resource
from moto import mock_aws

from tests.providers.aws.audit_info_utils import (
    AWS_REGION_EU_WEST_1,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)


class Test_ec2_ebs_volume_encryption:
    @mock_aws
    def test_ec2_no_volumes(self):
        from prowler.providers.aws.services.ec2.ec2_service import EC2

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_ebs_volume_encryption.ec2_ebs_volume_encryption.ec2_client",
            new=EC2(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_ebs_volume_encryption.ec2_ebs_volume_encryption import (
                ec2_ebs_volume_encryption,
            )

            check = ec2_ebs_volume_encryption()
            result = check.execute()

            assert len(result) == 0

    @mock_aws
    def test_ec2_unencrypted_volume(self):
        # Create EC2 Mocked Resources
        ec2 = resource("ec2", region_name=AWS_REGION_US_EAST_1)
        volume = ec2.create_volume(Size=80, AvailabilityZone=f"{AWS_REGION_US_EAST_1}a")

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_ebs_volume_encryption.ec2_ebs_volume_encryption.ec2_client",
            new=EC2(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_ebs_volume_encryption.ec2_ebs_volume_encryption import (
                ec2_ebs_volume_encryption,
            )

            check = ec2_ebs_volume_encryption()
            result = check.execute()

            assert len(result) == 1

            assert result[0].status == "FAIL"
            assert result[0].region == AWS_REGION_US_EAST_1
            # Moto creates the volume with None in the tags attribute
            assert result[0].resource_tags is None
            assert (
                result[0].status_extended == f"EBS Snapshot {volume.id} is unencrypted."
            )
            assert (
                result[0].resource_arn
                == f"arn:{aws_provider.identity.partition}:ec2:{AWS_REGION_US_EAST_1}:{aws_provider.identity.account}:volume/{volume.id}"
            )

    @mock_aws
    def test_ec2_encrypted_volume(self):
        # Create EC2 Mocked Resources
        ec2 = resource("ec2", region_name=AWS_REGION_US_EAST_1)
        volume = ec2.create_volume(
            Size=80, AvailabilityZone=f"{AWS_REGION_US_EAST_1}a", Encrypted=True
        )

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

        with mock.patch(
            "prowler.providers.common.common.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_ebs_volume_encryption.ec2_ebs_volume_encryption.ec2_client",
            new=EC2(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_ebs_volume_encryption.ec2_ebs_volume_encryption import (
                ec2_ebs_volume_encryption,
            )

            check = ec2_ebs_volume_encryption()
            result = check.execute()

            assert len(result) == 1

            assert result[0].status == "PASS"
            assert result[0].region == AWS_REGION_US_EAST_1
            # Moto creates the volume with None in the tags attribute
            assert result[0].resource_tags is None
            assert (
                result[0].status_extended == f"EBS Snapshot {volume.id} is encrypted."
            )
            assert (
                result[0].resource_arn
                == f"arn:{aws_provider.identity.partition}:ec2:{AWS_REGION_US_EAST_1}:{aws_provider.identity.account}:volume/{volume.id}"
            )
