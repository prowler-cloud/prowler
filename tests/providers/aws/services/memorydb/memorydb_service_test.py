import botocore
from mock import patch

from prowler.providers.aws.services.memorydb.memorydb_service import Cluster, MemoryDB
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

MEM_DB_CLUSTER_NAME = "test-cluster"
MEM_DB_CLUSTER_ARN = f"arn:aws:memorydb:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:cluster:{MEM_DB_CLUSTER_NAME}"
MEM_DB_ENGINE_VERSION = "5.0.0"

# Mocking Access Analyzer Calls
make_api_call = botocore.client.BaseClient._make_api_call


def mock_make_api_call(self, operation_name, kwargs):
    """
    As you can see the operation_name has the list_analyzers snake_case form but
    we are using the ListAnalyzers form.
    Rationale -> https://github.com/boto/botocore/blob/develop/botocore/client.py#L810:L816

    We have to mock every AWS API call using Boto3
    """
    if operation_name == "DescribeClusters":
        return {
            "Clusters": [
                {
                    "Name": MEM_DB_CLUSTER_NAME,
                    "Description": "Test",
                    "Status": "test",
                    "NumberOfShards": 123,
                    "AvailabilityMode": "singleaz",
                    "Engine": "valkey",
                    "EngineVersion": MEM_DB_ENGINE_VERSION,
                    "EnginePatchVersion": "5.0.6",
                    "SecurityGroups": [
                        {"SecurityGroupId": "sg-0a1434xxxxxc9fae", "Status": "active"},
                    ],
                    "TLSEnabled": True,
                    "ARN": MEM_DB_CLUSTER_ARN,
                    "SnapshotRetentionLimit": 5,
                    "AutoMinorVersionUpgrade": True,
                },
            ]
        }
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
class Test_MemoryDB_Service:
    # Test MemoryDB Service
    def test_service(self):
        aws_provider = set_mocked_aws_provider()
        memorydb = MemoryDB(aws_provider)
        assert memorydb.service == "memorydb"

    # Test MemoryDB Client
    def test_client(self):
        aws_provider = set_mocked_aws_provider()
        memorydb = MemoryDB(aws_provider)
        assert memorydb.client.__class__.__name__ == "MemoryDB"

    # Test MemoryDB Session
    def test__get_session__(self):
        aws_provider = set_mocked_aws_provider()
        memorydb = MemoryDB(aws_provider)
        assert memorydb.session.__class__.__name__ == "Session"

    # Test MemoryDB Session
    def test_audited_account(self):
        aws_provider = set_mocked_aws_provider()
        memorydb = MemoryDB(aws_provider)
        assert memorydb.audited_account == AWS_ACCOUNT_NUMBER

    # Test MemoryDB Describe Clusters
    def test_describe_clusters(self):
        aws_provider = set_mocked_aws_provider()
        memorydb = MemoryDB(aws_provider)
        assert memorydb.clusters == {
            MEM_DB_CLUSTER_ARN: Cluster(
                name=MEM_DB_CLUSTER_NAME,
                arn=MEM_DB_CLUSTER_ARN,
                number_of_shards=123,
                engine="valkey",
                engine_version=MEM_DB_ENGINE_VERSION,
                engine_patch_version="5.0.6",
                multi_az="singleaz",
                region=AWS_REGION_US_EAST_1,
                security_groups=["sg-0a1434xxxxxc9fae"],
                tls_enabled=True,
                auto_minor_version_upgrade=True,
                snapshot_limit=5,
            )
        }
