from re import search
from unittest import mock

from boto3 import client
from moto import mock_ec2

AWS_REGION = "us-east-1"
EXAMPLE_AMI_ID = "ami-12c6146b"


class Test_ec2_ebs_default_encryption:
    @mock_ec2
    def test_ec2_ebs_encryption_enabled(self):
        # Create EC2 Mocked Resources
        ec2_client = client("ec2", region_name=AWS_REGION)
        ec2_client.enable_ebs_encryption_by_default()

        from providers.aws.lib.audit_info.audit_info import current_audit_info
        from providers.aws.services.ec2.ec2_service import EC2

        current_audit_info.audited_partition = "aws"

        with mock.patch(
            "providers.aws.services.ec2.ec2_ebs_default_encryption.ec2_ebs_default_encryption.ec2_client",
            new=EC2(current_audit_info),
        ):
            # Test Check
            from providers.aws.services.ec2.ec2_ebs_default_encryption.ec2_ebs_default_encryption import (
                ec2_ebs_default_encryption,
            )

            check = ec2_ebs_default_encryption()
            results = check.execute()

            # One result per region
            assert len(results) == 25
            for result in results:
                if result.region == AWS_REGION:
                    assert result.status == "PASS"
                    assert search(
                        "EBS Default Encryption is activated",
                        result.status_extended,
                    )

    @mock_ec2
    def test_ec2_ebs_encryption_disabled(self):

        from providers.aws.lib.audit_info.audit_info import current_audit_info
        from providers.aws.services.ec2.ec2_service import EC2

        current_audit_info.audited_partition = "aws"

        with mock.patch(
            "providers.aws.services.ec2.ec2_ebs_default_encryption.ec2_ebs_default_encryption.ec2_client",
            new=EC2(current_audit_info),
        ):
            # Test Check
            from providers.aws.services.ec2.ec2_ebs_default_encryption.ec2_ebs_default_encryption import (
                ec2_ebs_default_encryption,
            )

            check = ec2_ebs_default_encryption()
            result = check.execute()

            # One result per region
            assert len(result) == 25
            assert result[0].status == "FAIL"
            assert search(
                "EBS Default Encryption is not activated",
                result[0].status_extended,
            )
