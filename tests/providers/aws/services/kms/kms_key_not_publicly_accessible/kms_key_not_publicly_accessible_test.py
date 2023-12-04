import json
from unittest import mock

from boto3 import client
from moto import mock_kms

from tests.providers.aws.audit_info_utils import (
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_audit_info,
)


class Test_kms_key_not_publicly_accessible:
    @mock_kms
    def test_no_kms_keys(self):
        from prowler.providers.aws.services.kms.kms_service import KMS

        current_audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.kms.kms_key_not_publicly_accessible.kms_key_not_publicly_accessible.kms_client",
            new=KMS(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.kms.kms_key_not_publicly_accessible.kms_key_not_publicly_accessible import (
                kms_key_not_publicly_accessible,
            )

            check = kms_key_not_publicly_accessible()
            result = check.execute()

            assert len(result) == 0

    @mock_kms
    def test_kms_key_not_publicly_accessible(self):
        # Generate KMS Client
        kms_client = client("kms", region_name=AWS_REGION_EU_WEST_1)
        # Creaty KMS key without policy
        key = kms_client.create_key()["KeyMetadata"]

        from prowler.providers.aws.services.kms.kms_service import KMS

        current_audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.kms.kms_key_not_publicly_accessible.kms_key_not_publicly_accessible.kms_client",
            new=KMS(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.kms.kms_key_not_publicly_accessible.kms_key_not_publicly_accessible import (
                kms_key_not_publicly_accessible,
            )

            check = kms_key_not_publicly_accessible()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"KMS key {key['KeyId']} is not exposed to Public."
            )
            assert result[0].resource_id == key["KeyId"]
            assert result[0].resource_arn == key["Arn"]

    @mock_kms
    def test_kms_key_public_accessible(self):
        # Generate KMS Client
        kms_client = client("kms", region_name=AWS_REGION_EU_WEST_1)
        # Creaty KMS key with public policy
        key = kms_client.create_key(
            Policy=json.dumps(
                {
                    "Version": "2012-10-17",
                    "Id": "key-default-1",
                    "Statement": [
                        {
                            "Sid": "Enable IAM User Permissions",
                            "Effect": "Allow",
                            "Principal": "*",
                            "Action": "kms:*",
                            "Resource": "*",
                        }
                    ],
                }
            )
        )["KeyMetadata"]

        from prowler.providers.aws.services.kms.kms_service import KMS

        current_audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.kms.kms_key_not_publicly_accessible.kms_key_not_publicly_accessible.kms_client",
            new=KMS(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.kms.kms_key_not_publicly_accessible.kms_key_not_publicly_accessible import (
                kms_key_not_publicly_accessible,
            )

            check = kms_key_not_publicly_accessible()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"KMS key {key['KeyId']} may be publicly accessible."
            )
            assert result[0].resource_id == key["KeyId"]
            assert result[0].resource_arn == key["Arn"]

    @mock_kms
    def test_kms_key_empty_principal(self):
        # Generate KMS Client
        kms_client = client("kms", region_name=AWS_REGION_EU_WEST_1)
        # Creaty KMS key with public policy
        key = kms_client.create_key(
            Policy=json.dumps(
                {
                    "Version": "2012-10-17",
                    "Id": "key-default-1",
                    "Statement": [
                        {
                            "Sid": "Enable IAM User Permissions",
                            "Effect": "Allow",
                            "Action": "kms:*",
                            "Resource": "*",
                        }
                    ],
                }
            )
        )["KeyMetadata"]

        from prowler.providers.aws.services.kms.kms_service import KMS

        current_audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.kms.kms_key_not_publicly_accessible.kms_key_not_publicly_accessible.kms_client",
            new=KMS(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.kms.kms_key_not_publicly_accessible.kms_key_not_publicly_accessible import (
                kms_key_not_publicly_accessible,
            )

            check = kms_key_not_publicly_accessible()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"KMS key {key['KeyId']} is not exposed to Public."
            )
            assert result[0].resource_id == key["KeyId"]
            assert result[0].resource_arn == key["Arn"]
