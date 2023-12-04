from unittest import mock

from boto3 import client
from moto import mock_kms

from tests.providers.aws.audit_info_utils import (
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_audit_info,
)


class Test_kms_cmk_rotation_enabled:
    @mock_kms
    def test_kms_no_key(self):
        from prowler.providers.aws.services.kms.kms_service import KMS

        current_audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.kms.kms_cmk_rotation_enabled.kms_cmk_rotation_enabled.kms_client",
            new=KMS(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.kms.kms_cmk_rotation_enabled.kms_cmk_rotation_enabled import (
                kms_cmk_rotation_enabled,
            )

            check = kms_cmk_rotation_enabled()
            result = check.execute()

            assert len(result) == 0

    @mock_kms
    def test_kms_cmk_rotation_enabled(self):
        # Generate KMS Client
        kms_client = client("kms", region_name=AWS_REGION_EU_WEST_1)
        # Creaty KMS key with rotation
        key = kms_client.create_key()["KeyMetadata"]
        kms_client.enable_key_rotation(KeyId=key["KeyId"])

        from prowler.providers.aws.services.kms.kms_service import KMS

        current_audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.kms.kms_cmk_rotation_enabled.kms_cmk_rotation_enabled.kms_client",
            new=KMS(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.kms.kms_cmk_rotation_enabled.kms_cmk_rotation_enabled import (
                kms_cmk_rotation_enabled,
            )

            check = kms_cmk_rotation_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"KMS CMK {key['KeyId']} has automatic rotation enabled."
            )
            assert result[0].resource_id == key["KeyId"]
            assert result[0].resource_arn == key["Arn"]

    @mock_kms
    def test_kms_cmk_rotation_disabled(self):
        # Generate KMS Client
        kms_client = client("kms", region_name=AWS_REGION_EU_WEST_1)
        # Creaty KMS key without rotation
        key = kms_client.create_key()["KeyMetadata"]

        from prowler.providers.aws.services.kms.kms_service import KMS

        current_audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.kms.kms_cmk_rotation_enabled.kms_cmk_rotation_enabled.kms_client",
            new=KMS(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.kms.kms_cmk_rotation_enabled.kms_cmk_rotation_enabled import (
                kms_cmk_rotation_enabled,
            )

            check = kms_cmk_rotation_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"KMS CMK {key['KeyId']} has automatic rotation disabled."
            )
            assert result[0].resource_id == key["KeyId"]
            assert result[0].resource_arn == key["Arn"]
