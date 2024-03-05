from unittest import mock

from boto3 import client, resource
from moto import mock_aws

from tests.providers.aws.audit_info_utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_audit_info,
)

EXAMPLE_AMI_ID = "ami-12c6146b"


class Test_ec2_ebs_default_encryption:
    @mock_aws
    def test_ec2_ebs_encryption_enabled(self):
        # Create EC2 Mocked Resources
        ec2_client = client("ec2", region_name=AWS_REGION_US_EAST_1)
        ec2_client.enable_ebs_encryption_by_default()

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        current_audit_info = set_mocked_aws_audit_info(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_ebs_default_encryption.ec2_ebs_default_encryption.ec2_client",
            new=EC2(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_ebs_default_encryption.ec2_ebs_default_encryption import (
                ec2_ebs_default_encryption,
            )

            check = ec2_ebs_default_encryption()
            results = check.execute()

            # One result per region
            assert len(results) == 2
            for result in results:
                if result.region == AWS_REGION_US_EAST_1:
                    assert result.status == "PASS"
                    assert (
                        result.status_extended == "EBS Default Encryption is activated."
                    )
                    assert result.resource_id == AWS_ACCOUNT_NUMBER
                    assert (
                        result.resource_arn
                        == f"arn:aws:ec2:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:volume"
                    )

    @mock_aws
    def test_ec2_ebs_encryption_disabled(self):
        from prowler.providers.aws.services.ec2.ec2_service import EC2

        current_audit_info = set_mocked_aws_audit_info(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_ebs_default_encryption.ec2_ebs_default_encryption.ec2_client",
            new=EC2(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_ebs_default_encryption.ec2_ebs_default_encryption import (
                ec2_ebs_default_encryption,
            )

            check = ec2_ebs_default_encryption()
            result = check.execute()

            # One result per region
            assert len(result) == 2
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended == "EBS Default Encryption is not activated."
            )
            assert result[0].resource_id == AWS_ACCOUNT_NUMBER
            assert (
                result[0].resource_arn
                == f"arn:aws:ec2:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:volume"
            )
            assert result[1].status == "FAIL"
            assert (
                result[1].status_extended == "EBS Default Encryption is not activated."
            )
            assert result[1].resource_id == AWS_ACCOUNT_NUMBER
            assert (
                result[1].resource_arn
                == f"arn:aws:ec2:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:volume"
            )

    @mock_aws
    def test_ec2_ebs_encryption_disabled_ignored(self):
        from prowler.providers.aws.services.ec2.ec2_service import EC2

        current_audit_info = set_mocked_aws_audit_info(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1],
            ignore_unused_services=True,
        )

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_ebs_default_encryption.ec2_ebs_default_encryption.ec2_client",
            new=EC2(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_ebs_default_encryption.ec2_ebs_default_encryption import (
                ec2_ebs_default_encryption,
            )

            check = ec2_ebs_default_encryption()
            result = check.execute()

            # One result per region
            assert len(result) == 0

    @mock_aws
    def test_ec2_ebs_encryption_disabled_ignoring_with_volumes(self):
        # Create EC2 Mocked Resources
        ec2 = resource("ec2", region_name=AWS_REGION_US_EAST_1)
        ec2.create_volume(Size=36, AvailabilityZone=f"{AWS_REGION_US_EAST_1}a")
        from prowler.providers.aws.services.ec2.ec2_service import EC2

        current_audit_info = set_mocked_aws_audit_info(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1],
            ignore_unused_services=True,
        )

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.ec2.ec2_ebs_default_encryption.ec2_ebs_default_encryption.ec2_client",
            new=EC2(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.ec2.ec2_ebs_default_encryption.ec2_ebs_default_encryption import (
                ec2_ebs_default_encryption,
            )

            check = ec2_ebs_default_encryption()
            result = check.execute()

            # One result per region
            assert len(result) == 1
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended == "EBS Default Encryption is not activated."
            )
            assert result[0].resource_id == AWS_ACCOUNT_NUMBER
            assert (
                result[0].resource_arn
                == f"arn:aws:ec2:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:volume"
            )
