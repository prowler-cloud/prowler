from unittest import mock

from boto3 import resource
from moto import mock_ec2

AWS_REGION = "us-east-1"


class Test_ec2_ebs_volume_encryption:
    @mock_ec2
    def test_ec2_no_volumes(self):

        from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
        from prowler.providers.aws.services.ec2.ec2_service import EC2

        current_audit_info.audited_partition = "aws"
        current_audit_info.audited_regions = ["eu-west-1", "us-east-1"]

        with mock.patch(
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

        from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
        from prowler.providers.aws.services.ec2.ec2_service import EC2

        current_audit_info.audited_partition = "aws"
        current_audit_info.audited_regions = ["eu-west-1", "us-east-1"]

        with mock.patch(
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

        from prowler.providers.aws.lib.audit_info.audit_info import current_audit_info
        from prowler.providers.aws.services.ec2.ec2_service import EC2

        current_audit_info.audited_partition = "aws"
        current_audit_info.audited_regions = ["eu-west-1", "us-east-1"]

        with mock.patch(
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
            assert (
                result[0].status_extended == f"EBS Snapshot {volume.id} is encrypted."
            )
            assert (
                result[0].resource_arn
                == f"arn:{current_audit_info.audited_partition}:ec2:{AWS_REGION}:{current_audit_info.audited_account}:volume/{volume.id}"
            )
