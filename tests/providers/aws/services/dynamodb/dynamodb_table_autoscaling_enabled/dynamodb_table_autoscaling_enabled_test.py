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

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.dynamodb.dynamodb_table_autoscaling_enabled.dynamodb_table_autoscaling_enabled.dynamodb_client",
                new=DynamoDB(aws_provider),
            ),
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

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.dynamodb.dynamodb_table_autoscaling_enabled.dynamodb_table_autoscaling_enabled.dynamodb_client",
                new=DynamoDB(aws_provider),
            ),
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

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.dynamodb.dynamodb_table_autoscaling_enabled.dynamodb_table_autoscaling_enabled.dynamodb_client",
                new=DynamoDB(aws_provider),
            ),
            mock.patch(
                "prowler.providers.aws.services.dynamodb.dynamodb_table_autoscaling_enabled.dynamodb_table_autoscaling_enabled.applicationautoscaling_client",
                new=ApplicationAutoScaling(aws_provider),
            ),
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

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.dynamodb.dynamodb_table_autoscaling_enabled.dynamodb_table_autoscaling_enabled.dynamodb_client",
                new=DynamoDB(aws_provider),
            ),
            mock.patch(
                "prowler.providers.aws.services.dynamodb.dynamodb_table_autoscaling_enabled.dynamodb_table_autoscaling_enabled.applicationautoscaling_client",
                new=ApplicationAutoScaling(aws_provider),
            ),
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

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.dynamodb.dynamodb_table_autoscaling_enabled.dynamodb_table_autoscaling_enabled.dynamodb_client",
                new=DynamoDB(aws_provider),
            ),
            mock.patch(
                "prowler.providers.aws.services.dynamodb.dynamodb_table_autoscaling_enabled.dynamodb_table_autoscaling_enabled.applicationautoscaling_client",
                new=ApplicationAutoScaling(aws_provider),
            ),
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

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.dynamodb.dynamodb_table_autoscaling_enabled.dynamodb_table_autoscaling_enabled.dynamodb_client",
                new=DynamoDB(aws_provider),
            ),
            mock.patch(
                "prowler.providers.aws.services.dynamodb.dynamodb_table_autoscaling_enabled.dynamodb_table_autoscaling_enabled.applicationautoscaling_client",
                new=ApplicationAutoScaling(aws_provider),
            ),
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

    @mock_aws
    def test_dynamodb_table_provisioned_same_name_other_region_autoscaling(self):
        # Same-named provisioned tables in two regions. Only the us-east-1
        # table has autoscaling targets, so the eu-west-1 table must FAIL.
        for region in (AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1):
            client("dynamodb", region_name=region).create_table(
                TableName="orders",
                AttributeDefinitions=[
                    {"AttributeName": "pk", "AttributeType": "S"},
                ],
                KeySchema=[
                    {"AttributeName": "pk", "KeyType": "HASH"},
                ],
                BillingMode="PROVISIONED",
                ProvisionedThroughput={
                    "ReadCapacityUnits": 5,
                    "WriteCapacityUnits": 5,
                },
            )

        autoscaling_client = client(
            "application-autoscaling", region_name=AWS_REGION_US_EAST_1
        )
        for dimension in (
            "dynamodb:table:ReadCapacityUnits",
            "dynamodb:table:WriteCapacityUnits",
        ):
            autoscaling_client.register_scalable_target(
                ServiceNamespace="dynamodb",
                ResourceId="table/orders",
                ScalableDimension=dimension,
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

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.dynamodb.dynamodb_table_autoscaling_enabled.dynamodb_table_autoscaling_enabled.dynamodb_client",
                new=DynamoDB(aws_provider),
            ),
            mock.patch(
                "prowler.providers.aws.services.dynamodb.dynamodb_table_autoscaling_enabled.dynamodb_table_autoscaling_enabled.applicationautoscaling_client",
                new=ApplicationAutoScaling(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.dynamodb.dynamodb_table_autoscaling_enabled.dynamodb_table_autoscaling_enabled import (
                dynamodb_table_autoscaling_enabled,
            )

            result = dynamodb_table_autoscaling_enabled().execute()

            assert len(result) == 2
            by_region = {finding.region: finding for finding in result}
            assert by_region[AWS_REGION_US_EAST_1].status == "PASS"
            assert by_region[AWS_REGION_EU_WEST_1].status == "FAIL"
            assert by_region[AWS_REGION_EU_WEST_1].status_extended == (
                "DynamoDB table orders is in provisioned mode without auto scaling enabled for read, write."
            )

    @mock_aws
    def test_dynamodb_table_provisioned_dimensions_split_across_regions(self):
        # Same-named provisioned tables in two regions with the read target
        # in one region and the write target in the other. Neither table has
        # both dimensions in its own region, so both must FAIL.
        for region in (AWS_REGION_EU_WEST_1, AWS_REGION_US_EAST_1):
            client("dynamodb", region_name=region).create_table(
                TableName="orders",
                AttributeDefinitions=[
                    {"AttributeName": "pk", "AttributeType": "S"},
                ],
                KeySchema=[
                    {"AttributeName": "pk", "KeyType": "HASH"},
                ],
                BillingMode="PROVISIONED",
                ProvisionedThroughput={
                    "ReadCapacityUnits": 5,
                    "WriteCapacityUnits": 5,
                },
            )

        client(
            "application-autoscaling", region_name=AWS_REGION_EU_WEST_1
        ).register_scalable_target(
            ServiceNamespace="dynamodb",
            ResourceId="table/orders",
            ScalableDimension="dynamodb:table:ReadCapacityUnits",
            MinCapacity=1,
            MaxCapacity=10,
        )
        client(
            "application-autoscaling", region_name=AWS_REGION_US_EAST_1
        ).register_scalable_target(
            ServiceNamespace="dynamodb",
            ResourceId="table/orders",
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

        with (
            mock.patch(
                "prowler.providers.common.provider.Provider.get_global_provider",
                return_value=aws_provider,
            ),
            mock.patch(
                "prowler.providers.aws.services.dynamodb.dynamodb_table_autoscaling_enabled.dynamodb_table_autoscaling_enabled.dynamodb_client",
                new=DynamoDB(aws_provider),
            ),
            mock.patch(
                "prowler.providers.aws.services.dynamodb.dynamodb_table_autoscaling_enabled.dynamodb_table_autoscaling_enabled.applicationautoscaling_client",
                new=ApplicationAutoScaling(aws_provider),
            ),
        ):
            from prowler.providers.aws.services.dynamodb.dynamodb_table_autoscaling_enabled.dynamodb_table_autoscaling_enabled import (
                dynamodb_table_autoscaling_enabled,
            )

            result = dynamodb_table_autoscaling_enabled().execute()

            assert len(result) == 2
            by_region = {finding.region: finding for finding in result}
            assert by_region[AWS_REGION_EU_WEST_1].status == "FAIL"
            assert by_region[AWS_REGION_EU_WEST_1].status_extended == (
                "DynamoDB table orders is in provisioned mode without auto scaling enabled for write."
            )
            assert by_region[AWS_REGION_US_EAST_1].status == "FAIL"
            assert by_region[AWS_REGION_US_EAST_1].status_extended == (
                "DynamoDB table orders is in provisioned mode without auto scaling enabled for read."
            )
