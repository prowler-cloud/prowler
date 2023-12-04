from unittest import mock

from boto3 import resource
from moto import mock_ec2

from tests.providers.aws.audit_info_utils import (
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_audit_info,
)

AWS_REGION = "us-east-1"
AWS_ACCOUNT_NUMBER = "123456789012"


class Test_ec2_ebs_volume_encryption:
    @mock_ec2
    def test_ec2_no_volumes(self):
        from prowler.providers.aws.services.ec2.ec2_service import EC2

        current_audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_ebs_volume_encryption.ec2_ebs_volume_encryption.ec2_client",
            new=EC2(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_ebs_volume_encryption.ec2_ebs_volume_encryption import (
                ec2_ebs_volume_encryption,
            )

            check = ec2_ebs_volume_encryption()
            result = check.execute()

            assert len(result) == 0

    @mock_ec2
    def test_ec2_unencrypted_volume(self):
        # Create EC2 Mocked Resources
        ec2 = resource("ec2", region_name=AWS_REGION)
        volume = ec2.create_volume(Size=80, AvailabilityZone=f"{AWS_REGION}a")

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        current_audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_ebs_volume_encryption.ec2_ebs_volume_encryption.ec2_client",
            new=EC2(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_ebs_volume_encryption.ec2_ebs_volume_encryption import (
                ec2_ebs_volume_encryption,
            )

            check = ec2_ebs_volume_encryption()
            result = check.execute()

            assert len(result) == 1

            assert result[0].status == "FAIL"
            assert result[0].region == AWS_REGION
            # Moto creates the volume with None in the tags attribute
            assert result[0].resource_tags is None
            assert (
                result[0].status_extended == f"EBS Snapshot {volume.id} is unencrypted."
            )
            assert (
                result[0].resource_arn
                == f"arn:{current_audit_info.audited_partition}:ec2:{AWS_REGION}:{current_audit_info.audited_account}:volume/{volume.id}"
            )

    @mock_ec2
    def test_ec2_encrypted_volume(self):
        # Create EC2 Mocked Resources
        ec2 = resource("ec2", region_name=AWS_REGION)
        volume = ec2.create_volume(
            Size=80, AvailabilityZone=f"{AWS_REGION}a", Encrypted=True
        )

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        current_audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_ebs_volume_encryption.ec2_ebs_volume_encryption.ec2_client",
            new=EC2(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_ebs_volume_encryption.ec2_ebs_volume_encryption import (
                ec2_ebs_volume_encryption,
            )

            check = ec2_ebs_volume_encryption()
            result = check.execute()

            assert len(result) == 1

            assert result[0].status == "PASS"
            assert result[0].region == AWS_REGION
            # Moto creates the volume with None in the tags attribute
            assert result[0].resource_tags is None
            assert (
                result[0].status_extended == f"EBS Snapshot {volume.id} is encrypted."
            )
            assert (
                result[0].resource_arn
                == f"arn:{current_audit_info.audited_partition}:ec2:{AWS_REGION}:{current_audit_info.audited_account}:volume/{volume.id}"
            )
