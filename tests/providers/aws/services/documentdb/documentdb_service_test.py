import botocore
from mock import patch

from prowler.providers.aws.services.documentdb.documentdb_service import (
    DocumentDB,
    Instance,
)
from tests.providers.aws.audit_info_utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

DOC_DB_CLUSTER_ID = "test-cluster"
DOC_DB_INSTANCE_NAME = "test-db"
DOC_DB_INSTANCE_ARN = (
    f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:db:{DOC_DB_INSTANCE_NAME}"
)
DOC_DB_ENGINE_VERSION = "5.0.0"

# Mocking Access Analyzer Calls
make_api_call = botocore.client.BaseClient._make_api_call


def mock_make_api_call(self, operation_name, kwargs):
    """
    As you can see the operation_name has the list_analyzers snake_case form but
    we are using the ListAnalyzers form.
    Rationale -> https://github.com/boto/botocore/blob/develop/botocore/client.py#L810:L816

    We have to mock every AWS API call using Boto3
    """
    if operation_name == "DescribeDBInstances":
        return {
            "DBInstances": [
                {
                    "DBInstanceIdentifier": DOC_DB_INSTANCE_NAME,
                    "DBInstanceClass": "string",
                    "Engine": "docdb",
                    "DBInstanceStatus": "available",
                    "BackupRetentionPeriod": 1,
                    "EngineVersion": "5.0.0",
                    "AutoMinorVersionUpgrade": False,
                    "PubliclyAccessible": False,
                    "DBClusterIdentifier": DOC_DB_CLUSTER_ID,
                    "StorageEncrypted": False,
                    "DbiResourceId": "string",
                    "CACertificateIdentifier": "string",
                    "CopyTagsToSnapshot": True | False,
                    "PromotionTier": 123,
                    "DBInstanceArn": DOC_DB_INSTANCE_ARN,
                },
            ]
        }
    if operation_name == "ListTagsForResource":
        return {"TagList": [{"Key": "environment", "Value": "test"}]}

    return make_api_call(self, operation_name, kwargs)


def mock_generate_regional_clients(provider, service):
    regional_client = provider._session.current_session.client(
        service, region_name=AWS_REGION_US_EAST_1
    )
    regional_client.region = AWS_REGION_US_EAST_1
    return {AWS_REGION_US_EAST_1: regional_client}


@patch(
    "prowler.providers.aws.aws_provider.AwsProvider.generate_regional_clients",
    new=mock_generate_regional_clients,
)
# Patch every AWS call using Boto3
@patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
class Test_DocumentDB_Service:
    # Test DocumentDB Service
    def test_service(self):
        aws_provider = set_mocked_aws_provider()
        docdb = DocumentDB(aws_provider)
        assert docdb.service == "docdb"

    # Test DocumentDB Client
    def test_client(self):
        aws_provider = set_mocked_aws_provider()
        docdb = DocumentDB(aws_provider)
        assert docdb.client.__class__.__name__ == "DocDB"

    # Test DocumentDB Session
    def test__get_session__(self):
        aws_provider = set_mocked_aws_provider()
        docdb = DocumentDB(aws_provider)
        assert docdb.session.__class__.__name__ == "Session"

    # Test DocumentDB Session
    def test_audited_account(self):
        aws_provider = set_mocked_aws_provider()
        docdb = DocumentDB(aws_provider)
        assert docdb.audited_account == AWS_ACCOUNT_NUMBER

    # Test DocumentDB Get DocumentDB Contacts
    def test_describe_db_instances(self):
        aws_provider = set_mocked_aws_provider()
        docdb = DocumentDB(aws_provider)
        assert docdb.db_instances == {
            DOC_DB_INSTANCE_ARN: Instance(
                id=DOC_DB_INSTANCE_NAME,
                arn=DOC_DB_INSTANCE_ARN,
                engine="docdb",
                engine_version="5.0.0",
                status="available",
                public=False,
                encrypted=False,
                cluster_id=DOC_DB_CLUSTER_ID,
                region=AWS_REGION_US_EAST_1,
                tags=[{"Key": "environment", "Value": "test"}],
            )
        }
