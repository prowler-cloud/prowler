from re import search
from unittest import mock

from boto3 import client, session
from moto import mock_ec2

from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info
from prowler.providers.common.models import Audit_Metadata

AWS_REGION = "us-east-1"
EXAMPLE_AMI_ID = "ami-12c6146b"
AWS_ACCOUNT_NUMBER = "123456789012"


class Test_ec2_ebs_default_encryption:
    def set_mocked_audit_info(self):
        audit_info = AWS_Audit_Info(
            session_config=None,
            original_session=None,
            audit_session=session.Session(
                profile_name=None,
                botocore_session=None,
            ),
            audited_account=AWS_ACCOUNT_NUMBER,
            audited_account_arn=f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root",
            audited_user_id=None,
            audited_partition="aws",
            audited_identity_arn=None,
            profile=None,
            profile_region=None,
            credentials=None,
            assumed_role_info=None,
            audited_regions=["us-east-1", "eu-west-1"],
            organizations_metadata=None,
            audit_resources=None,
            mfa_enabled=False,
            audit_metadata=Audit_Metadata(
                services_scanned=0,
                expected_checks=[],
                completed_checks=0,
                audit_progress=0,
            ),
        )

        return audit_info

    @mock_ec2
    def test_ec2_ebs_encryption_enabled(self):
        # Create EC2 Mocked Resources
        ec2_client = client("ec2", region_name=AWS_REGION)
        ec2_client.enable_ebs_encryption_by_default()

        from prowler.providers.aws.services.ec2.ec2_service import EC2

        current_audit_info = self.set_mocked_audit_info()

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
                if result.region == AWS_REGION:
                    assert result.status == "PASS"
                    assert search(
                        "EBS Default Encryption is activated",
                        result.status_extended,
                    )

    @mock_ec2
    def test_ec2_ebs_encryption_disabled(self):
        from prowler.providers.aws.services.ec2.ec2_service import EC2

        current_audit_info = self.set_mocked_audit_info()

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
            assert search(
                "EBS Default Encryption is not activated",
                result[0].status_extended,
            )
