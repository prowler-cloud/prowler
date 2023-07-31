from boto3 import client, session
from moto import mock_dax, mock_dynamodb

from prowler.providers.aws.lib.audit_info.models import AWS_Audit_Info
from prowler.providers.aws.services.dynamodb.dynamodb_service import DAX, DynamoDB
from prowler.providers.common.models import Audit_Metadata

AWS_ACCOUNT_NUMBER = "123456789012"
AWS_REGION = "us-east-1"


class Test_DynamoDB_Service:
    # Mocked Audit Info
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
            audited_regions=None,
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

    # Test Dynamo Service
    @mock_dynamodb
    def test_service(self):
        # Dynamo client for this test class
        audit_info = self.set_mocked_audit_info()
        dynamodb = DynamoDB(audit_info)
        assert dynamodb.service == "dynamodb"

    # Test Dynamo Client
    @mock_dynamodb
    def test_client(self):
        # Dynamo client for this test class
        audit_info = self.set_mocked_audit_info()
        dynamodb = DynamoDB(audit_info)
        for regional_client in dynamodb.regional_clients.values():
            assert regional_client.__class__.__name__ == "DynamoDB"

    # Test Dynamo Session
    @mock_dynamodb
    def test__get_session__(self):
        # Dynamo client for this test class
        audit_info = self.set_mocked_audit_info()
        dynamodb = DynamoDB(audit_info)
        assert dynamodb.session.__class__.__name__ == "Session"

    # Test Dynamo Session
    @mock_dynamodb
    def test_audited_account(self):
        # Dynamo client for this test class
        audit_info = self.set_mocked_audit_info()
        dynamodb = DynamoDB(audit_info)
        assert dynamodb.audited_account == AWS_ACCOUNT_NUMBER

    # Test DynamoDB List Tables
    @mock_dynamodb
    def test__list_tables__(self):
        # Generate DynamoDB Client
        dynamodb_client = client("dynamodb", region_name=AWS_REGION)
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
            BillingMode="PAY_PER_REQUEST",
        )
        # DynamoDB client for this test class
        audit_info = self.set_mocked_audit_info()
        dynamo = DynamoDB(audit_info)
        assert len(dynamo.tables) == 2
        assert dynamo.tables[0].name == "test1"
        assert dynamo.tables[1].name == "test2"
        assert dynamo.tables[0].region == AWS_REGION
        assert dynamo.tables[1].region == AWS_REGION

    # Test DynamoDB Describe Table
    @mock_dynamodb
    def test__describe_table__(self):
        # Generate DynamoDB Client
        dynamodb_client = client("dynamodb", region_name=AWS_REGION)
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
        )["TableDescription"]
        # DynamoDB client for this test class
        audit_info = self.set_mocked_audit_info()
        dynamo = DynamoDB(audit_info)
        assert len(dynamo.tables) == 1
        assert dynamo.tables[0].arn == table["TableArn"]
        assert dynamo.tables[0].name == "test1"
        assert dynamo.tables[0].region == AWS_REGION
        assert dynamo.tables[0].tags == [
            {"Key": "test", "Value": "test"},
        ]

    # Test DynamoDB Describe Continuous Backups
    @mock_dynamodb
    def test__describe_continuous_backups__(self):
        # Generate DynamoDB Client
        dynamodb_client = client("dynamodb", region_name=AWS_REGION)
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
        audit_info = self.set_mocked_audit_info()
        dynamo = DynamoDB(audit_info)
        assert len(dynamo.tables) == 1
        assert dynamo.tables[0].arn == table["TableArn"]
        assert dynamo.tables[0].name == "test1"
        assert dynamo.tables[0].pitr
        assert dynamo.tables[0].region == AWS_REGION

    # Test DAX Describe Clusters
    @mock_dax
    def test__describe_clusters__(self):
        # Generate DAX Client
        dax_client = client("dax", region_name=AWS_REGION)
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
        audit_info = self.set_mocked_audit_info()
        dax = DAX(audit_info)
        assert len(dax.clusters) == 2

        assert dax.clusters[0].name == "daxcluster1"
        assert dax.clusters[0].region == AWS_REGION
        assert dax.clusters[0].encryption
        assert dax.clusters[0].tags == [
            {"Key": "test", "Value": "test"},
        ]

        assert dax.clusters[1].name == "daxcluster2"
        assert dax.clusters[1].region == AWS_REGION
        assert dax.clusters[1].encryption
        assert dax.clusters[1].tags == [
            {"Key": "test", "Value": "test"},
        ]
