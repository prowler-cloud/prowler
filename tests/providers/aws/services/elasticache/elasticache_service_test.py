import botocore
from mock import patch

from prowler.providers.aws.services.elasticache.elasticache_service import (
    Cluster,
    ElastiCache,
)
from tests.providers.aws.audit_info_utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_EU_WEST_1,
    set_mocked_aws_audit_info,
)

AWS_ACCOUNT_ARN = f"arn:aws:iam::{AWS_ACCOUNT_NUMBER}:root"


AWS_REGION_AZ1 = "us-east-1a"
AWS_REGION_AZ2 = "us-east-b"

SUBNET_GROUP_NAME = "default"
SUBNET_1 = "subnet-1"
SUBNET_2 = "subnet-2"

ELASTICACHE_CLUSTER_NAME = "test-cluster"
ELASTICACHE_CLUSTER_ARN = f"arn:aws:elasticache:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:{ELASTICACHE_CLUSTER_NAME}"
ELASTICACHE_ENGINE = "redis"

ELASTICACHE_CLUSTER_TAGS = [
    {"Key": "environment", "Value": "test"},
]

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
                            "SubnetAvailabilityZone": {"Name": AWS_REGION_AZ1},
                            "SubnetStatus": "Active",
                        },
                        {
                            "SubnetIdentifier": "subnet-2",
                            "SubnetAvailabilityZone": {"Name": AWS_REGION_AZ2},
                            "SubnetStatus": "Active",
                        },
                    ],
                    "DBSubnetGroupArn": f"arn:aws:rds:{AWS_REGION_EU_WEST_1}:{AWS_ACCOUNT_NUMBER}:subgrp:{SUBNET_GROUP_NAME}",
                }
            ]
        }
    if operation_name == "ListTagsForResource":
        return {"TagList": ELASTICACHE_CLUSTER_TAGS}

    return make_api_call(self, operation_name, kwargs)


def mock_generate_regional_clients(service, audit_info, _):
    regional_client = audit_info.audit_session.client(
        service, region_name=AWS_REGION_EU_WEST_1
    )
    regional_client.region = AWS_REGION_EU_WEST_1
    return {AWS_REGION_EU_WEST_1: regional_client}


@patch(
    "prowler.providers.aws.lib.service.service.generate_regional_clients",
    new=mock_generate_regional_clients,
)
# Patch every AWS call using Boto3
@patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
class Test_ElastiCache_Service:
    # Test ElastiCache Service
    def test_service(self):
        audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])
        elasticache = ElastiCache(audit_info)
        assert elasticache.service == "elasticache"

    # Test ElastiCache Client]
    def test_client(self):
        audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])
        elasticache = ElastiCache(audit_info)
        assert elasticache.client.__class__.__name__ == "ElastiCache"

    # Test ElastiCache Session
    def test__get_session__(self):
        audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])
        elasticache = ElastiCache(audit_info)
        assert elasticache.session.__class__.__name__ == "Session"

    # Test ElastiCache Session
    def test_audited_account(self):
        audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])
        elasticache = ElastiCache(audit_info)
        assert elasticache.audited_account == AWS_ACCOUNT_NUMBER

    # Test ElastiCache Clusters
    def test_describe_cache_clusters(self):
        audit_info = set_mocked_aws_audit_info([AWS_REGION_EU_WEST_1])
        elasticache = ElastiCache(audit_info)

        assert len(elasticache.clusters) == 1
        assert elasticache.clusters[ELASTICACHE_CLUSTER_ARN]
        assert elasticache.clusters[ELASTICACHE_CLUSTER_ARN] == Cluster(
            arn=ELASTICACHE_CLUSTER_ARN,
            name=ELASTICACHE_CLUSTER_NAME,
            id=ELASTICACHE_CLUSTER_NAME,
            region=AWS_REGION_EU_WEST_1,
            cache_subnet_group_id=SUBNET_GROUP_NAME,
            subnets=[SUBNET_1, SUBNET_2],
            tags=ELASTICACHE_CLUSTER_TAGS,
        )
