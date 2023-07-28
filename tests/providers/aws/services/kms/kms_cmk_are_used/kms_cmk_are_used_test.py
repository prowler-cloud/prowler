from unittest import mock

from boto3 import client, session
from moto import mock_kms

from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info
from prowler.providers.common.models import Audit_Metadata

AWS_REGION = "us-east-1"
AWS_ACCOUNT_NUMBER = "123456789012"


class Test_kms_cmk_are_used:
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

    @mock_kms
    def test_kms_no_keys(self):
        from prowler.providers.aws.services.kms.kms_service import KMS

        current_audit_info = self.set_mocked_audit_info()

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.kms.kms_cmk_are_used.kms_cmk_are_used.kms_client",
            new=KMS(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.kms.kms_cmk_are_used.kms_cmk_are_used import (
                kms_cmk_are_used,
            )

            check = kms_cmk_are_used()
            result = check.execute()

            assert len(result) == 0

    @mock_kms
    def test_kms_cmk_are_used(self):
        # Generate KMS Client
        kms_client = client("kms", region_name=AWS_REGION)
        # Create enabled KMS key
        key = kms_client.create_key()["KeyMetadata"]

        from prowler.providers.aws.services.kms.kms_service import KMS

        current_audit_info = self.set_mocked_audit_info()

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.kms.kms_cmk_are_used.kms_cmk_are_used.kms_client",
            new=KMS(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.kms.kms_cmk_are_used.kms_cmk_are_used import (
                kms_cmk_are_used,
            )

            check = kms_cmk_are_used()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].status_extended == f"KMS CMK {key['KeyId']} is being used."
            assert result[0].resource_id == key["KeyId"]
            assert result[0].resource_arn == key["Arn"]

    @mock_kms
    def test_kms_key_with_deletion(self):
        # Generate KMS Client
        kms_client = client("kms", region_name=AWS_REGION)
        # Creaty KMS key with deletion
        key = kms_client.create_key()["KeyMetadata"]
        kms_client.schedule_key_deletion(KeyId=key["KeyId"])

        from prowler.providers.aws.services.kms.kms_service import KMS

        current_audit_info = self.set_mocked_audit_info()

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.kms.kms_cmk_are_used.kms_cmk_are_used.kms_client",
            new=KMS(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.kms.kms_cmk_are_used.kms_cmk_are_used import (
                kms_cmk_are_used,
            )

            check = kms_cmk_are_used()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"KMS CMK {key['KeyId']} is not being used but it has scheduled deletion."
            )
            assert result[0].resource_id == key["KeyId"]
            assert result[0].resource_arn == key["Arn"]

    @mock_kms
    def test_kms_disabled_key(self):
        # Generate KMS Client
        kms_client = client("kms", region_name=AWS_REGION)
        # Creaty KMS key with deletion
        key = kms_client.create_key()["KeyMetadata"]
        kms_client.disable_key(KeyId=key["KeyId"])

        from prowler.providers.aws.services.kms.kms_service import KMS

        current_audit_info = self.set_mocked_audit_info()

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.kms.kms_cmk_are_used.kms_cmk_are_used.kms_client",
            new=KMS(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.kms.kms_cmk_are_used.kms_cmk_are_used import (
                kms_cmk_are_used,
            )

            check = kms_cmk_are_used()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"KMS CMK {key['KeyId']} is not being used."
            )
            assert result[0].resource_id == key["KeyId"]
            assert result[0].resource_arn == key["Arn"]
