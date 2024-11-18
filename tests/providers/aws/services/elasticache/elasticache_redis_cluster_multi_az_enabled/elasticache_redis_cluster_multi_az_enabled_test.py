from unittest import mock

import botocore
from mock import MagicMock
from moto import mock_aws

from prowler.providers.aws.services.elasticache.elasticache_service import (
    ReplicationGroup,
)
from tests.providers.aws.services.elasticache.elasticache_service_test import (
    AUTO_MINOR_VERSION_UPGRADE,
    AUTOMATIC_FAILOVER,
)
from tests.providers.aws.utils import (
    AWS_ACCOUNT_NUMBER,
    AWS_REGION_US_EAST_1,
    set_mocked_aws_provider,
)

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


# Patch every AWS call using Boto3
make_api_call = botocore.client.BaseClient._make_api_call


class Test_elasticache_replication_group_multi_az_enabled:
    @mock_aws
    def test_elasticache_no_replication_groups(self):

        # Mock ElastiCache Service
        elasticache_service = MagicMock
        elasticache_service.replication_groups = {}

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider([AWS_REGION_US_EAST_1]),
        ), mock.patch(
            "prowler.providers.aws.services.elasticache.elasticache_service.ElastiCache",
            new=elasticache_service,
        ):
            from prowler.providers.aws.services.elasticache.elasticache_redis_cluster_multi_az_enabled.elasticache_redis_cluster_multi_az_enabled import (
                elasticache_redis_cluster_multi_az_enabled,
            )

            check = elasticache_redis_cluster_multi_az_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_elasticache_cluster_multi_az_disabled(self):
        # Mock ElastiCache Service
        elasticache_service = MagicMock
        elasticache_service.replication_groups = {}

        elasticache_service.replication_groups[REPLICATION_GROUP_ARN] = (
            ReplicationGroup(
                arn=REPLICATION_GROUP_ARN,
                id=REPLICATION_GROUP_ID,
                region=AWS_REGION_US_EAST_1,
                status=REPLICATION_GROUP_STATUS,
                snapshot_retention=REPLICATION_GROUP_SNAPSHOT_RETENTION,
                encrypted=False,
                transit_encryption=False,
                multi_az="disabled",
                tags=REPLICATION_GROUP_TAGS,
                auto_minor_version_upgrade=AUTO_MINOR_VERSION_UPGRADE,
                automatic_failover=AUTOMATIC_FAILOVER,
                engine_version="6.0",
                auth_token_enabled=False,
            )
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider([AWS_REGION_US_EAST_1]),
        ), mock.patch(
            "prowler.providers.aws.services.elasticache.elasticache_service.ElastiCache",
            new=elasticache_service,
        ):
            from prowler.providers.aws.services.elasticache.elasticache_redis_cluster_multi_az_enabled.elasticache_redis_cluster_multi_az_enabled import (
                elasticache_redis_cluster_multi_az_enabled,
            )

            check = elasticache_redis_cluster_multi_az_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Elasticache Redis cache cluster {REPLICATION_GROUP_ID} does not have Multi-AZ enabled."
            )
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_id == REPLICATION_GROUP_ID
            assert result[0].resource_arn == REPLICATION_GROUP_ARN
            assert result[0].resource_tags == REPLICATION_GROUP_TAGS

    def test_elasticache_redis_cluster_multi_az_enabled(self):
        # Mock ElastiCache Service
        elasticache_service = MagicMock
        elasticache_service.replication_groups = {}

        elasticache_service.replication_groups[REPLICATION_GROUP_ARN] = (
            ReplicationGroup(
                arn=REPLICATION_GROUP_ARN,
                id=REPLICATION_GROUP_ID,
                region=AWS_REGION_US_EAST_1,
                status=REPLICATION_GROUP_STATUS,
                snapshot_retention=REPLICATION_GROUP_SNAPSHOT_RETENTION,
                encrypted=REPLICATION_GROUP_ENCRYPTION,
                transit_encryption=REPLICATION_GROUP_TRANSIT_ENCRYPTION,
                multi_az=REPLICATION_GROUP_MULTI_AZ,
                tags=REPLICATION_GROUP_TAGS,
                auto_minor_version_upgrade=AUTO_MINOR_VERSION_UPGRADE,
                automatic_failover=AUTOMATIC_FAILOVER,
                engine_version="6.0",
                auth_token_enabled=False,
            )
        )

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider([AWS_REGION_US_EAST_1]),
        ), mock.patch(
            "prowler.providers.aws.services.elasticache.elasticache_service.ElastiCache",
            new=elasticache_service,
        ):
            from prowler.providers.aws.services.elasticache.elasticache_redis_cluster_multi_az_enabled.elasticache_redis_cluster_multi_az_enabled import (
                elasticache_redis_cluster_multi_az_enabled,
            )

            check = elasticache_redis_cluster_multi_az_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Elasticache Redis cache cluster {REPLICATION_GROUP_ID} has Multi-AZ enabled."
            )
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_id == REPLICATION_GROUP_ID
            assert result[0].resource_arn == REPLICATION_GROUP_ARN
            assert result[0].resource_tags == REPLICATION_GROUP_TAGS
