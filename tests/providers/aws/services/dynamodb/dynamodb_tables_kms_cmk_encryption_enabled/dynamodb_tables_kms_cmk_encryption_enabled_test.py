from re import search
from unittest import mock

from boto3 import client
from moto import mock_dynamodb

from tests.providers.aws.audit_info_utils import (
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_audit_info,
)


class Test_dynamodb_tables_kms_cmk_encryption_enabled:
    @mock_dynamodb
    def test_dynamodb_no_tables(self):
        from prowler.providers.aws.services.dynamodb.dynamodb_service import DynamoDB

        current_audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])

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
        dynamodb_client = client("dynamodb", region_name=AWS_REGION_EU_WEST_1)
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

        current_audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])

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
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].resource_tags == []

    @mock_dynamodb
    def test_dynamodb_table_default_encryption(self):
        dynamodb_client = client("dynamodb", region_name=AWS_REGION_EU_WEST_1)
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

        current_audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])

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
            assert result[0].region == AWS_REGION_EU_WEST_1
            assert result[0].resource_tags == []
