from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_REGION_EU_WEST_1,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)


class Test_dynamodb_table_deletion_protection_enabled:
    @mock_aws
    def test_dynamodb_no_tables(self):
        from prowler.providers.aws.services.dynamodb.dynamodb_service import DynamoDB

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.dynamodb.dynamodb_table_deletion_protection_enabled.dynamodb_table_deletion_protection_enabled.dynamodb_client",
            new=DynamoDB(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.dynamodb.dynamodb_table_deletion_protection_enabled.dynamodb_table_deletion_protection_enabled import (
                dynamodb_table_deletion_protection_enabled,
            )

            check = dynamodb_table_deletion_protection_enabled()
            result = check.execute()

            assert len(result) == 0

    @mock_aws
    def test_dynamodb_table_with_deletion_protection_enabled(self):
        dynamodb_client = client("dynamodb", region_name=AWS_REGION_US_EAST_1)
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
            DeletionProtectionEnabled=True,
            BillingMode="PAY_PER_REQUEST",
        )["TableDescription"]

        from prowler.providers.aws.services.dynamodb.dynamodb_service import DynamoDB

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.dynamodb.dynamodb_table_deletion_protection_enabled.dynamodb_table_deletion_protection_enabled.dynamodb_client",
            new=DynamoDB(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.dynamodb.dynamodb_table_deletion_protection_enabled.dynamodb_table_deletion_protection_enabled import (
                dynamodb_table_deletion_protection_enabled,
            )

            check = dynamodb_table_deletion_protection_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].status_extended == (
                "DynamoDB table test1 has deletion protection enabled."
            )
            assert result[0].resource_id == table["TableName"]
            assert result[0].resource_arn == table["TableArn"]
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_tags == []

    @mock_aws
    def test_dynamodb_table_without_deletion_protection_enabled(self):
        dynamodb_client = client("dynamodb", region_name=AWS_REGION_US_EAST_1)
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
            DeletionProtectionEnabled=False,
            BillingMode="PAY_PER_REQUEST",
        )["TableDescription"]

        from prowler.providers.aws.services.dynamodb.dynamodb_service import DynamoDB

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.dynamodb.dynamodb_table_deletion_protection_enabled.dynamodb_table_deletion_protection_enabled.dynamodb_client",
            new=DynamoDB(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.dynamodb.dynamodb_table_deletion_protection_enabled.dynamodb_table_deletion_protection_enabled import (
                dynamodb_table_deletion_protection_enabled,
            )

            check = dynamodb_table_deletion_protection_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended == (
                "DynamoDB table test1 does not have deletion protection enabled."
            )
            assert result[0].resource_id == table["TableName"]
            assert result[0].resource_arn == table["TableArn"]
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_tags == []
