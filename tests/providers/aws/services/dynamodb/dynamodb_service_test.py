from boto3 import client
from moto import mock_aws

from prowler.providers.aws.services.dynamodb.dynamodb_service import DAX, DynamoDB
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)


class Test_DynamoDB_Service:
    # Test Dynamo Service
    @mock_aws
    def test_service(self):
        # Dynamo client for this test class
        aws_provider = set_mocked_aws_provider()
        dynamodb = DynamoDB(aws_provider)
        assert dynamodb.service == "dynamodb"

    # Test Dynamo Client
    @mock_aws
    def test_client(self):
        # Dynamo client for this test class
        aws_provider = set_mocked_aws_provider()
        dynamodb = DynamoDB(aws_provider)
        for regional_client in dynamodb.regional_clients.values():
            assert regional_client.__class__.__name__ == "DynamoDB"

    # Test Dynamo Session
    @mock_aws
    def test__get_session__(self):
        # Dynamo client for this test class
        aws_provider = set_mocked_aws_provider()
        dynamodb = DynamoDB(aws_provider)
        assert dynamodb.session.__class__.__name__ == "Session"

    # Test Dynamo Session
    @mock_aws
    def test_audited_account(self):
        # Dynamo client for this test class
        aws_provider = set_mocked_aws_provider()
        dynamodb = DynamoDB(aws_provider)
        assert dynamodb.audited_account == AWS_ACCOUNT_NUMBER

    # Test DynamoDB List Tables
    @mock_aws
    def test_list_tables(self):
        # Generate DynamoDB Client
        dynamodb_client = client("dynamodb", region_name=AWS_REGION_US_EAST_1)
        # Create DynamoDB Tables
        dynamodb_client.create_table(
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
        )
        dynamodb_client.create_table(
            TableName="test2",
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
        )
        # DynamoDB client for this test class
        aws_provider = set_mocked_aws_provider()
        dynamo = DynamoDB(aws_provider)
        assert len(dynamo.tables) == 2
        table_names = [table.name for table in dynamo.tables.values()]
        assert "test1" in table_names
        assert "test2" in table_names
        for table in dynamo.tables.values():
            assert table.region == AWS_REGION_US_EAST_1
        table_billing = [table.billing_mode for table in dynamo.tables.values()]
        assert "PAY_PER_REQUEST" in table_billing
        assert "PROVISIONED" in table_billing

    # Test DynamoDB Describe Table
    @mock_aws
    def test_describe_table(self):
        # Generate DynamoDB Client
        dynamodb_client = client("dynamodb", region_name=AWS_REGION_US_EAST_1)
        # Create DynamoDB Table
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
            Tags=[
                {"Key": "test", "Value": "test"},
            ],
            DeletionProtectionEnabled=True,
        )["TableDescription"]
        # DynamoDB client for this test class
        aws_provider = set_mocked_aws_provider()
        dynamo = DynamoDB(aws_provider)
        assert len(dynamo.tables) == 1
        tables_arn, tables = next(iter(dynamo.tables.items()))
        assert tables_arn == table["TableArn"]
        assert tables.name == "test1"
        assert tables.region == AWS_REGION_US_EAST_1
        assert tables.tags == [
            {"Key": "test", "Value": "test"},
        ]
        assert tables.billing_mode == "PAY_PER_REQUEST"
        assert tables.deletion_protection

    # Test DynamoDB Describe Continuous Backups
    @mock_aws
    def test_describe_continuous_backups(self):
        # Generate DynamoDB Client
        dynamodb_client = client("dynamodb", region_name=AWS_REGION_US_EAST_1)
        # Create DynamoDB Table
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
        dynamodb_client.update_continuous_backups(
            TableName="test1",
            PointInTimeRecoverySpecification={"PointInTimeRecoveryEnabled": True},
        )
        # DynamoDB client for this test class
        aws_provider = set_mocked_aws_provider()
        dynamo = DynamoDB(aws_provider)
        assert len(dynamo.tables) == 1
        tables_arn, tables = next(iter(dynamo.tables.items()))
        assert tables_arn == table["TableArn"]
        assert tables.name == "test1"
        assert tables.pitr
        assert tables.region == AWS_REGION_US_EAST_1

    # Test DAX Describe Clusters
    @mock_aws
    def test_describe_clusters(self):
        # Generate DAX Client
        dax_client = client("dax", region_name=AWS_REGION_US_EAST_1)
        # Create DAX Clusters
        iam_role_arn = f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:role/aws-service-role/dax.amazonaws.com/AWSServiceRoleForDAX"
        dax_client.create_cluster(
            ClusterName="daxcluster1",
            NodeType="dax.t3.small",
            ReplicationFactor=3,
            IamRoleArn=iam_role_arn,
            SSESpecification={"Enabled": True},
            Tags=[
                {"Key": "test", "Value": "test"},
            ],
            ClusterEndpointEncryptionType="TLS",
        )
        dax_client.create_cluster(
            ClusterName="daxcluster2",
            NodeType="dax.t3.small",
            ReplicationFactor=3,
            IamRoleArn=iam_role_arn,
            SSESpecification={"Enabled": True},
            Tags=[
                {"Key": "test", "Value": "test"},
            ],
        )
        # DAX client for this test class
        aws_provider = set_mocked_aws_provider()
        dax = DAX(aws_provider)
        assert len(dax.clusters) == 2

        assert dax.clusters[0].name == "daxcluster1"
        assert dax.clusters[0].region == AWS_REGION_US_EAST_1
        assert dax.clusters[0].encryption
        assert dax.clusters[0].tags == [
            {"Key": "test", "Value": "test"},
        ]
        assert dax.clusters[0].tls_encryption
        assert dax.clusters[1].name == "daxcluster2"
        assert dax.clusters[1].region == AWS_REGION_US_EAST_1
        assert dax.clusters[1].encryption
        assert dax.clusters[1].tags == [
            {"Key": "test", "Value": "test"},
        ]
        assert not dax.clusters[1].tls_encryption
