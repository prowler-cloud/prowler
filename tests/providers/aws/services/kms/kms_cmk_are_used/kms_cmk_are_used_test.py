from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.audit_info_utils import (
    AWS_REGION_US_EAST_1,
    set_mocked_aws_audit_info,
)


class Test_kms_cmk_are_used:
    @mock_aws
    def test_kms_no_keys(self):
        from prowler.providers.aws.services.kms.kms_service import KMS

        current_audit_info = set_mocked_aws_audit_info([AWS_REGION_US_EAST_1])

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

    @mock_aws
    def test_kms_cmk_are_used(self):
        # Generate KMS Client
        kms_client = client("kms", region_name=AWS_REGION_US_EAST_1)
        # Create enabled KMS key
        key = kms_client.create_key()["KeyMetadata"]

        from prowler.providers.aws.services.kms.kms_service import KMS

        current_audit_info = set_mocked_aws_audit_info([AWS_REGION_US_EAST_1])

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

    @mock_aws
    def test_kms_key_with_deletion(self):
        # Generate KMS Client
        kms_client = client("kms", region_name=AWS_REGION_US_EAST_1)
        # Creaty KMS key with deletion
        key = kms_client.create_key()["KeyMetadata"]
        kms_client.schedule_key_deletion(KeyId=key["KeyId"])

        from prowler.providers.aws.services.kms.kms_service import KMS

        current_audit_info = set_mocked_aws_audit_info([AWS_REGION_US_EAST_1])

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

    @mock_aws
    def test_kms_disabled_key(self):
        # Generate KMS Client
        kms_client = client("kms", region_name=AWS_REGION_US_EAST_1)
        # Creaty KMS key with deletion
        key = kms_client.create_key()["KeyMetadata"]
        kms_client.disable_key(KeyId=key["KeyId"])

        from prowler.providers.aws.services.kms.kms_service import KMS

        current_audit_info = set_mocked_aws_audit_info([AWS_REGION_US_EAST_1])

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
