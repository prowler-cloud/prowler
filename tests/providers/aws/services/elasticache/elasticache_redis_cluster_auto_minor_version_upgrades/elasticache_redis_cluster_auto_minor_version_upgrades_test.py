from unittest import mock

from mock import MagicMock

from prowler.providers.aws.services.elasticache.elasticache_service import (
    ReplicationGroup,
)
from tests.providers.aws.services.elasticache.elasticache_service_test import (
    AUTO_MINOR_VERSION_UPGRADE,
    AUTOMATIC_FAILOVER,
    REPLICATION_GROUP_ARN,
    REPLICATION_GROUP_ENCRYPTION,
    REPLICATION_GROUP_ID,
    REPLICATION_GROUP_MULTI_AZ,
    REPLICATION_GROUP_SNAPSHOT_RETENTION,
    REPLICATION_GROUP_STATUS,
    REPLICATION_GROUP_TAGS,
)
from tests.providers.aws.utils import AWS_REGION_US_EAST_1, set_mocked_aws_provider

VPC_ID = "vpc-12345678901234567"


class Test_elasticache_redis_cluster_auto_minor_version_upgrades:
    def test_elasticache_no_clusters(self):
        # Mock VPC Service
        vpc_client = MagicMock
        vpc_client.vpc_subnets = {}

        # Mock ElastiCache Service
        elasticache_service = MagicMock
        elasticache_service.replication_groups = {}

        with mock.patch(
            "prowler.providers.common.provider.Provider.get_global_provider",
            return_value=set_mocked_aws_provider([AWS_REGION_US_EAST_1]),
        ), mock.patch(
            "prowler.providers.aws.services.elasticache.elasticache_service.ElastiCache",
            new=elasticache_service,
        ), mock.patch(
            "prowler.providers.aws.services.vpc.vpc_service.VPC",
            new=vpc_client,
        ), mock.patch(
            "prowler.providers.aws.services.vpc.vpc_client.vpc_client",
            new=vpc_client,
        ):
            from prowler.providers.aws.services.elasticache.elasticache_redis_cluster_auto_minor_version_upgrades.elasticache_redis_cluster_auto_minor_version_upgrades import (
                elasticache_redis_cluster_auto_minor_version_upgrades,
            )

            check = elasticache_redis_cluster_auto_minor_version_upgrades()
            result = check.execute()
            assert len(result) == 0

    def test_elasticache_clusters_auto_minor_version_upgrades_disabled(self):
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
                transit_encryption=False,
                multi_az=REPLICATION_GROUP_MULTI_AZ,
                tags=REPLICATION_GROUP_TAGS,
                auto_minor_version_upgrade=not AUTO_MINOR_VERSION_UPGRADE,
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
            from prowler.providers.aws.services.elasticache.elasticache_redis_cluster_auto_minor_version_upgrades.elasticache_redis_cluster_auto_minor_version_upgrades import (
                elasticache_redis_cluster_auto_minor_version_upgrades,
            )

            check = elasticache_redis_cluster_auto_minor_version_upgrades()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Elasticache Redis cache cluster {REPLICATION_GROUP_ID} does not have automated minor version upgrades enabled."
            )
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_id == REPLICATION_GROUP_ID
            assert result[0].resource_arn == REPLICATION_GROUP_ARN
            assert result[0].resource_tags == REPLICATION_GROUP_TAGS

    def test_elasticache_clusters_auto_minor_version_upgrades_enabled(self):
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
                transit_encryption=False,
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
            from prowler.providers.aws.services.elasticache.elasticache_redis_cluster_auto_minor_version_upgrades.elasticache_redis_cluster_auto_minor_version_upgrades import (
                elasticache_redis_cluster_auto_minor_version_upgrades,
            )

            check = elasticache_redis_cluster_auto_minor_version_upgrades()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Elasticache Redis cache cluster {REPLICATION_GROUP_ID} does have automated minor version upgrades enabled."
            )
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_id == REPLICATION_GROUP_ID
            assert result[0].resource_arn == REPLICATION_GROUP_ARN
            assert result[0].resource_tags == REPLICATION_GROUP_TAGS
