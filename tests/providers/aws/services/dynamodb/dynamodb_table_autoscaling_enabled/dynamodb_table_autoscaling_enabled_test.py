from unittest import mock

from boto3 import client
from moto import mock_aws

from tests.providers.aws.utils import (
    AWS_REGION_EU_WEST_1,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)


class Test_dynamodb_table_autoscaling_enabled:
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
            "prowler.providers.aws.services.dynamodb.dynamodb_table_autoscaling_enabled.dynamodb_table_autoscaling_enabled.dynamodb_client",
            new=DynamoDB(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.dynamodb.dynamodb_table_autoscaling_enabled.dynamodb_table_autoscaling_enabled import (
                dynamodb_table_autoscaling_enabled,
            )

            check = dynamodb_table_autoscaling_enabled()
            result = check.execute()

            assert len(result) == 0

    @mock_aws
    def test_dynamodb_table_on_demand(self):
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
            "prowler.providers.aws.services.dynamodb.dynamodb_table_autoscaling_enabled.dynamodb_table_autoscaling_enabled.dynamodb_client",
            new=DynamoDB(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.dynamodb.dynamodb_table_autoscaling_enabled.dynamodb_table_autoscaling_enabled import (
                dynamodb_table_autoscaling_enabled,
            )

            check = dynamodb_table_autoscaling_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].status_extended == (
                "DynamoDB table test1 automatically scales capacity on demand."
            )
            assert result[0].resource_id == table["TableName"]
            assert result[0].resource_arn == table["TableArn"]
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_tags == []

    @mock_aws
    def test_dynamodb_table_provisioned_with_autoscaling(self):
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
            BillingMode="PROVISIONED",
            ProvisionedThroughput={"ReadCapacityUnits": 5, "WriteCapacityUnits": 5},
        )["TableDescription"]

        autoscaling_client = client(
            "application-autoscaling", region_name=AWS_REGION_US_EAST_1
        )
        autoscaling_client.register_scalable_target(
            ServiceNamespace="dynamodb",
            ResourceId=f"table/{table['TableName']}",
            ScalableDimension="dynamodb:table:ReadCapacityUnits",
            MinCapacity=1,
            MaxCapacity=10,
        )
        autoscaling_client.register_scalable_target(
            ServiceNamespace="dynamodb",
            ResourceId=f"table/{table['TableName']}",
            ScalableDimension="dynamodb:table:WriteCapacityUnits",
            MinCapacity=1,
            MaxCapacity=10,
        )

        from prowler.providers.aws.services.autoscaling.autoscaling_service import (
            ApplicationAutoScaling,
        )
        from prowler.providers.aws.services.dynamodb.dynamodb_service import DynamoDB

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.dynamodb.dynamodb_table_autoscaling_enabled.dynamodb_table_autoscaling_enabled.dynamodb_client",
            new=DynamoDB(aws_provider),
        ), mock.patch(
            "prowler.providers.aws.services.dynamodb.dynamodb_table_autoscaling_enabled.dynamodb_table_autoscaling_enabled.applicationautoscaling_client",
            new=ApplicationAutoScaling(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.dynamodb.dynamodb_table_autoscaling_enabled.dynamodb_table_autoscaling_enabled import (
                dynamodb_table_autoscaling_enabled,
            )

            check = dynamodb_table_autoscaling_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert result[0].status_extended == (
                "DynamoDB table test1 is in provisioned mode with auto scaling enabled for both read and write capacity units."
            )
            assert result[0].resource_id == table["TableName"]
            assert result[0].resource_arn == table["TableArn"]
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_tags == []

    @mock_aws
    def test_dynamodb_table_provisioned_only_with_read_autoscaling(self):
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
            BillingMode="PROVISIONED",
            ProvisionedThroughput={"ReadCapacityUnits": 5, "WriteCapacityUnits": 5},
        )["TableDescription"]

        autoscaling_client = client(
            "application-autoscaling", region_name=AWS_REGION_US_EAST_1
        )
        autoscaling_client.register_scalable_target(
            ServiceNamespace="dynamodb",
            ResourceId=f"table/{table['TableName']}",
            ScalableDimension="dynamodb:table:ReadCapacityUnits",
            MinCapacity=1,
            MaxCapacity=10,
        )

        from prowler.providers.aws.services.autoscaling.autoscaling_service import (
            ApplicationAutoScaling,
        )
        from prowler.providers.aws.services.dynamodb.dynamodb_service import DynamoDB

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.dynamodb.dynamodb_table_autoscaling_enabled.dynamodb_table_autoscaling_enabled.dynamodb_client",
            new=DynamoDB(aws_provider),
        ), mock.patch(
            "prowler.providers.aws.services.dynamodb.dynamodb_table_autoscaling_enabled.dynamodb_table_autoscaling_enabled.applicationautoscaling_client",
            new=ApplicationAutoScaling(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.dynamodb.dynamodb_table_autoscaling_enabled.dynamodb_table_autoscaling_enabled import (
                dynamodb_table_autoscaling_enabled,
            )

            check = dynamodb_table_autoscaling_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended == (
                "DynamoDB table test1 is in provisioned mode without auto scaling enabled for write."
            )
            assert result[0].resource_id == table["TableName"]
            assert result[0].resource_arn == table["TableArn"]
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_tags == []

    @mock_aws
    def test_dynamodb_table_provisioned_only_with_write_autoscaling(self):
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
            BillingMode="PROVISIONED",
            ProvisionedThroughput={"ReadCapacityUnits": 5, "WriteCapacityUnits": 5},
        )["TableDescription"]

        autoscaling_client = client(
            "application-autoscaling", region_name=AWS_REGION_US_EAST_1
        )
        autoscaling_client.register_scalable_target(
            ServiceNamespace="dynamodb",
            ResourceId=f"table/{table['TableName']}",
            ScalableDimension="dynamodb:table:WriteCapacityUnits",
            MinCapacity=1,
            MaxCapacity=10,
        )

        from prowler.providers.aws.services.autoscaling.autoscaling_service import (
            ApplicationAutoScaling,
        )
        from prowler.providers.aws.services.dynamodb.dynamodb_service import DynamoDB

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.dynamodb.dynamodb_table_autoscaling_enabled.dynamodb_table_autoscaling_enabled.dynamodb_client",
            new=DynamoDB(aws_provider),
        ), mock.patch(
            "prowler.providers.aws.services.dynamodb.dynamodb_table_autoscaling_enabled.dynamodb_table_autoscaling_enabled.applicationautoscaling_client",
            new=ApplicationAutoScaling(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.dynamodb.dynamodb_table_autoscaling_enabled.dynamodb_table_autoscaling_enabled import (
                dynamodb_table_autoscaling_enabled,
            )

            check = dynamodb_table_autoscaling_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended == (
                "DynamoDB table test1 is in provisioned mode without auto scaling enabled for read."
            )
            assert result[0].resource_id == table["TableName"]
            assert result[0].resource_arn == table["TableArn"]
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_tags == []

    @mock_aws
    def test_dynamodb_table_provisioned_without_autoscaling(self):
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
            BillingMode="PROVISIONED",
            ProvisionedThroughput={"ReadCapacityUnits": 5, "WriteCapacityUnits": 5},
        )["TableDescription"]

        from prowler.providers.aws.services.autoscaling.autoscaling_service import (
            ApplicationAutoScaling,
        )
        from prowler.providers.aws.services.dynamodb.dynamodb_service import DynamoDB

        aws_provider = set_mocked_aws_provider(
            [AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1]
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=aws_provider,
        ), mock.patch(
            "prowler.providers.aws.services.dynamodb.dynamodb_table_autoscaling_enabled.dynamodb_table_autoscaling_enabled.dynamodb_client",
            new=DynamoDB(aws_provider),
        ), mock.patch(
            "prowler.providers.aws.services.dynamodb.dynamodb_table_autoscaling_enabled.dynamodb_table_autoscaling_enabled.applicationautoscaling_client",
            new=ApplicationAutoScaling(aws_provider),
        ):
            # Test Check
            from prowler.providers.aws.services.dynamodb.dynamodb_table_autoscaling_enabled.dynamodb_table_autoscaling_enabled import (
                dynamodb_table_autoscaling_enabled,
            )

            check = dynamodb_table_autoscaling_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert result[0].status_extended == (
                "DynamoDB table test1 is in provisioned mode without auto scaling enabled for read, write."
            )
            assert result[0].resource_id == table["TableName"]
            assert result[0].resource_arn == table["TableArn"]
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_tags == []
