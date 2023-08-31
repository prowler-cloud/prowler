from re import search
from unittest import mock

from boto3 import client, session
from moto import mock_dynamodb

from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info
from prowler.providers.common.models import Audit_Metadata

AWS_REGION = "us-east-1"
AWS_ACCOUNT_NUMBER = "123456789012"


class Test_dynamodb_tables_kms_cmk_encryption_enabled:
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

    @mock_dynamodb
    def test_dynamodb_no_tables(self):
        from prowler.providers.aws.services.dynamodb.dynamodb_service import DynamoDB

        current_audit_info = self.set_mocked_audit_info()

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.dynamodb.dynamodb_tables_kms_cmk_encryption_enabled.dynamodb_tables_kms_cmk_encryption_enabled.dynamodb_client",
            new=DynamoDB(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.dynamodb.dynamodb_tables_kms_cmk_encryption_enabled.dynamodb_tables_kms_cmk_encryption_enabled import (
                dynamodb_tables_kms_cmk_encryption_enabled,
            )

            check = dynamodb_tables_kms_cmk_encryption_enabled()
            result = check.execute()

            assert len(result) == 0

    @mock_dynamodb
    def test_dynamodb_table_kms_encryption(self):
        dynamodb_client = client("dynamodb", region_name=AWS_REGION)
        table = dynamodb_client.create_table(
            TableName="test1",
            AttributeDefinitions=[
                {"AttributeName": "client", "AttributeType": "S"},
                {"AttributeName": "app", "AttributeType": "S"},
            ],
            KeySchema=[
                {"AttributeName": "client", "KeyType": "HASH"},
                {"AttributeName": "app", "KeyType": "RANGE"},
            ],
            BillingMode="PAY_PER_REQUEST",
            SSESpecification={"Enabled": True, "KMSMasterKeyId": "/custom-kms-key"},
        )["TableDescription"]
        from prowler.providers.aws.services.dynamodb.dynamodb_service import DynamoDB

        current_audit_info = self.set_mocked_audit_info()

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.dynamodb.dynamodb_tables_kms_cmk_encryption_enabled.dynamodb_tables_kms_cmk_encryption_enabled.dynamodb_client",
            new=DynamoDB(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.dynamodb.dynamodb_tables_kms_cmk_encryption_enabled.dynamodb_tables_kms_cmk_encryption_enabled import (
                dynamodb_tables_kms_cmk_encryption_enabled,
            )

            check = dynamodb_tables_kms_cmk_encryption_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert search("KMS encryption enabled", result[0].status_extended)
            assert result[0].resource_id == table["TableName"]
            assert result[0].resource_arn == table["TableArn"]
            assert result[0].region == AWS_REGION
            assert result[0].resource_tags == []

    @mock_dynamodb
    def test_dynamodb_table_default_encryption(self):
        dynamodb_client = client("dynamodb", region_name=AWS_REGION)
        table = dynamodb_client.create_table(
            TableName="test1",
            AttributeDefinitions=[
                {"AttributeName": "client", "AttributeType": "S"},
                {"AttributeName": "app", "AttributeType": "S"},
            ],
            KeySchema=[
                {"AttributeName": "client", "KeyType": "HASH"},
                {"AttributeName": "app", "KeyType": "RANGE"},
            ],
            BillingMode="PAY_PER_REQUEST",
        )["TableDescription"]
        from prowler.providers.aws.services.dynamodb.dynamodb_service import DynamoDB

        current_audit_info = self.set_mocked_audit_info()

        with mock.patch(
            "prowler.providers.aws.lib.audit_info.audit_info.current_audit_info",
            new=current_audit_info,
        ), mock.patch(
            "prowler.providers.aws.services.dynamodb.dynamodb_tables_kms_cmk_encryption_enabled.dynamodb_tables_kms_cmk_encryption_enabled.dynamodb_client",
            new=DynamoDB(current_audit_info),
        ):
            # Test Check
            from prowler.providers.aws.services.dynamodb.dynamodb_tables_kms_cmk_encryption_enabled.dynamodb_tables_kms_cmk_encryption_enabled import (
                dynamodb_tables_kms_cmk_encryption_enabled,
            )

            check = dynamodb_tables_kms_cmk_encryption_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert search("DEFAULT encryption enabled", result[0].status_extended)
            assert result[0].resource_id == table["TableName"]
            assert result[0].resource_arn == table["TableArn"]
            assert result[0].region == AWS_REGION
            assert result[0].resource_tags == []
