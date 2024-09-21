import botocore
from mock import patch

from prowler.providers.aws.services.elasticache.elasticache_service import (
    Cluster,
    ElastiCache,
    ReplicationGroup,
)
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    AWS_REGION_US_EAST_1_AZA,
    AWS_REGION_US_EAST_1_AZB,
    set_mocked_aws_provider,
)

SUBNET_GROUP_NAME = "default"
SUBNET_1 = "subnet-1"
SUBNET_2 = "subnet-2"

ELASTICACHE_CLUSTER_NAME = "test-cluster"
ELASTICACHE_CLUSTER_ARN = f"arn:aws:elasticache:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:cluster:{ELASTICACHE_CLUSTER_NAME}"
ELASTICACHE_ENGINE = "redis"
ELASTICACHE_ENGINE_MEMCACHED = "memcached"

ELASTICACHE_CLUSTER_TAGS = [
    {"Key": "environment", "Value": "test"},
]

REPLICATION_GROUP_ID = "clustered-redis"
REPLICATION_GROUP_ARN = f"arn:aws:elasticache:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:replicationgroup:{REPLICATION_GROUP_ID}"
REPLICATION_GROUP_STATUS = "available"
REPLICATION_GROUP_SNAPSHOT_RETENTION = "0"
REPLICATION_GROUP_ENCRYPTION = True
REPLICATION_GROUP_TRANSIT_ENCRYPTION = True
REPLICATION_GROUP_MULTI_AZ = "enabled"
REPLICATION_GROUP_TAGS = [
    {"Key": "environment", "Value": "test"},
]
AUTO_MINOR_VERSION_UPGRADE = True
AUTOMATIC_FAILOVER = "enabled"


# Mocking Access Analyzer Calls
make_api_call = botocore.client.BaseClient._make_api_call


def mock_make_api_call(self, operation_name, kwargs):
    """
    As you can see the operation_name has the list_analyzers snake_case form but
    we are using the ListAnalyzers form.
    Rationale -> https://github.com/boto/botocore/blob/develop/botocore/client.py#L810:L816

    We have to mock every AWS API call using Boto3
    """
    if operation_name == "DescribeCacheClusters":
        return {
            "CacheClusters": [
                {
                    "CacheClusterId": ELASTICACHE_CLUSTER_NAME,
                    "CacheSubnetGroupName": SUBNET_GROUP_NAME,
                    "ARN": ELASTICACHE_CLUSTER_ARN,
                    "Engine": ELASTICACHE_ENGINE,
                    "SecurityGroups": [],
                    "AutoMinorVersionUpgrade": AUTO_MINOR_VERSION_UPGRADE,
                    "EngineVersion": "6.0",
                    "AuthTokenEnabled": False,
                },
            ]
        }
    if operation_name == "DescribeCacheSubnetGroups":
        return {
            "CacheSubnetGroups": [
                {
                    "CacheSubnetGroupName": SUBNET_GROUP_NAME,
                    "CacheSubnetGroupDescription": "Subnet Group",
                    "VpcId": "vpc-1",
                    "SubnetGroupStatus": "Complete",
                    "Subnets": [
                        {
                            "SubnetIdentifier": "subnet-1",
                            "SubnetAvailabilityZone": {
                                "Name": AWS_REGION_US_EAST_1_AZA
                            },
                            "SubnetStatus": "Active",
                        },
                        {
                            "SubnetIdentifier": "subnet-2",
                            "SubnetAvailabilityZone": {
                                "Name": AWS_REGION_US_EAST_1_AZB
                            },
                            "SubnetStatus": "Active",
                        },
                    ],
                    "DBSubnetGroupArn": f"arn:aws:rds:{AWS_REGION_US_EAST_1}:{AWS_ACCOUNT_NUMBER}:subgrp:{SUBNET_GROUP_NAME}",
                }
            ]
        }
    if operation_name == "ListTagsForResource":
        return {"TagList": ELASTICACHE_CLUSTER_TAGS}
    if operation_name == "DescribeReplicationGroups":
        return {
            "ReplicationGroups": [
                {
                    "ReplicationGroupId": REPLICATION_GROUP_ID,
                    "Status": REPLICATION_GROUP_STATUS,
                    "SnapshotRetentionLimit": REPLICATION_GROUP_SNAPSHOT_RETENTION,
                    "MultiAZ": REPLICATION_GROUP_MULTI_AZ,
                    "TransitEncryptionEnabled": REPLICATION_GROUP_TRANSIT_ENCRYPTION,
                    "AtRestEncryptionEnabled": REPLICATION_GROUP_ENCRYPTION,
                    "ARN": REPLICATION_GROUP_ARN,
                    "AutoMinorVersionUpgrade": AUTO_MINOR_VERSION_UPGRADE,
                    "Memberclusters": [ELASTICACHE_CLUSTER_NAME],
                    "AuthTokenEnabled": False,
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
class Test_ElastiCache_Service:
    # Test ElastiCache Service
    def test_service(self):
        aws_provider = set_mocked_aws_provider()
        elasticache = ElastiCache(aws_provider)
        assert elasticache.service == "elasticache"

    # Test ElastiCache Client]
    def test_client(self):
        aws_provider = set_mocked_aws_provider()
        elasticache = ElastiCache(aws_provider)
        assert elasticache.client.__class__.__name__ == "ElastiCache"

    # Test ElastiCache Session
    def test__get_session__(self):
        aws_provider = set_mocked_aws_provider()
        elasticache = ElastiCache(aws_provider)
        assert elasticache.session.__class__.__name__ == "Session"

    # Test ElastiCache Session
    def test_audited_account(self):
        aws_provider = set_mocked_aws_provider()
        elasticache = ElastiCache(aws_provider)
        assert elasticache.audited_account == AWS_ACCOUNT_NUMBER

    # Test Elasticache Redis cache clusters
    def test_describe_cache_clusters(self):
        aws_provider = set_mocked_aws_provider()
        elasticache = ElastiCache(aws_provider)

        assert len(elasticache.clusters) == 1
        assert elasticache.clusters[ELASTICACHE_CLUSTER_ARN]
        assert elasticache.clusters[ELASTICACHE_CLUSTER_ARN] == Cluster(
            arn=ELASTICACHE_CLUSTER_ARN,
            id=ELASTICACHE_CLUSTER_NAME,
            engine=ELASTICACHE_ENGINE,
            region=AWS_REGION_US_EAST_1,
            security_groups=[],
            cache_subnet_group_id=SUBNET_GROUP_NAME,
            subnets=[SUBNET_1, SUBNET_2],
            tags=ELASTICACHE_CLUSTER_TAGS,
            auto_minor_version_upgrade=AUTO_MINOR_VERSION_UPGRADE,
            engine_version=6.0,
            auth_token_enabled=False,
        )

    # Test Elasticache Redis replication_groups
    def test_describe_replication_groups(self):
        aws_provider = set_mocked_aws_provider()
        elasticache = ElastiCache(aws_provider)

        assert len(elasticache.replication_groups) == 1
        assert elasticache.replication_groups[REPLICATION_GROUP_ARN]
        assert elasticache.replication_groups[
            REPLICATION_GROUP_ARN
        ] == ReplicationGroup(
            id=REPLICATION_GROUP_ID,
            arn=REPLICATION_GROUP_ARN,
            region=AWS_REGION_US_EAST_1,
            status=REPLICATION_GROUP_STATUS,
            snapshot_retention=REPLICATION_GROUP_SNAPSHOT_RETENTION,
            encrypted=REPLICATION_GROUP_ENCRYPTION,
            transit_encryption=REPLICATION_GROUP_TRANSIT_ENCRYPTION,
            multi_az=REPLICATION_GROUP_MULTI_AZ,
            tags=REPLICATION_GROUP_TAGS,
            auto_minor_version_upgrade=AUTO_MINOR_VERSION_UPGRADE,
            auth_token_enabled=False,
            automatic_failover="disabled",
            engine_version="0.0",
        )
