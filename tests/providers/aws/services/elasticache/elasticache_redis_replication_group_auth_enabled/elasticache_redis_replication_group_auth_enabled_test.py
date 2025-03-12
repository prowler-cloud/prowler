from unittest import mock

from mock import MagicMock, patch
from moto import mock_aws

from prowler.providers.aws.services.elasticache.elasticache_service import (
    ReplicationGroup,
)
from tests.providers.aws.services.elasticache.elasticache_service_test import (
    REPLICATION_GROUP_ARN,
    REPLICATION_GROUP_ENCRYPTION,
    REPLICATION_GROUP_ID,
    REPLICATION_GROUP_MULTI_AZ,
    REPLICATION_GROUP_SNAPSHOT_RETENTION,
    REPLICATION_GROUP_STATUS,
    REPLICATION_GROUP_TAGS,
    REPLICATION_GROUP_TRANSIT_ENCRYPTION,
    mock_make_api_call,
)
from tests.providers.aws.utils import AWS_REGION_US_EAST_1, set_mocked_aws_provider

VPC_ID = "vpc-12345678901234567"


# Patch every AWS call using Boto3
@patch("botocore.client.BaseClient._make_api_call", new=mock_make_api_call)
class Test_elasticache_redis_replication_group_auth_enabled:
    @mock_aws
    def test_elasticache_no_replication_groups(self):
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
            from prowler.providers.aws.services.elasticache.elasticache_redis_replication_group_auth_enabled.elasticache_redis_replication_group_auth_enabled import (
                elasticache_redis_replication_group_auth_enabled,
            )

            check = elasticache_redis_replication_group_auth_enabled()
            result = check.execute()
            assert len(result) == 0

    def test_elasticache_no_old_redis_replication_groups(self):
        # Mock ElastiCache Service
        elasticache_service = MagicMock
        engine_version = "6.0"
        elasticache_service.replication_groups = {
            REPLICATION_GROUP_ARN: ReplicationGroup(
                arn=REPLICATION_GROUP_ARN,
                id=REPLICATION_GROUP_ID,
                region=AWS_REGION_US_EAST_1,
                status=REPLICATION_GROUP_STATUS,
                snapshot_retention=REPLICATION_GROUP_SNAPSHOT_RETENTION,
                encrypted=REPLICATION_GROUP_ENCRYPTION,
                transit_encryption=REPLICATION_GROUP_TRANSIT_ENCRYPTION,
                multi_az=REPLICATION_GROUP_MULTI_AZ,
                tags=REPLICATION_GROUP_TAGS,
                automatic_failover="enabled",
                auto_minor_version_upgrade=False,
                engine_version=engine_version,
                auth_token_enabled=False,
            )
        }

        # Mock VPC Service
        vpc_client = MagicMock
        vpc_client.vpc_subnets = {}

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
            from prowler.providers.aws.services.elasticache.elasticache_redis_replication_group_auth_enabled.elasticache_redis_replication_group_auth_enabled import (
                elasticache_redis_replication_group_auth_enabled,
            )

            check = elasticache_redis_replication_group_auth_enabled()
            result = check.execute()
            assert len(result) == 1
            assert result[0].status == "MANUAL"
            assert (
                result[0].status_extended
                == f"Elasticache Redis replication group {REPLICATION_GROUP_ID} has version {engine_version} which supports Redis ACLs. Please review the ACL configuration."
            )
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_id == REPLICATION_GROUP_ID
            assert result[0].resource_arn == REPLICATION_GROUP_ARN
            assert result[0].resource_tags == REPLICATION_GROUP_TAGS

    def test_elasticache_redis_replication_group_auth_enabled(self):
        # Mock ElastiCache Service
        elasticache_service = MagicMock
        engine_version = "5.0"
        elasticache_service.replication_groups = {
            REPLICATION_GROUP_ARN: ReplicationGroup(
                arn=REPLICATION_GROUP_ARN,
                id=REPLICATION_GROUP_ID,
                region=AWS_REGION_US_EAST_1,
                status=REPLICATION_GROUP_STATUS,
                snapshot_retention=REPLICATION_GROUP_SNAPSHOT_RETENTION,
                encrypted=REPLICATION_GROUP_ENCRYPTION,
                transit_encryption=REPLICATION_GROUP_TRANSIT_ENCRYPTION,
                multi_az=REPLICATION_GROUP_MULTI_AZ,
                tags=REPLICATION_GROUP_TAGS,
                automatic_failover="enabled",
                auto_minor_version_upgrade=False,
                engine_version=engine_version,
                auth_token_enabled=True,
            )
        }

        # Mock VPC Service
        vpc_client = MagicMock
        vpc_client.vpc_subnets = {}

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
            from prowler.providers.aws.services.elasticache.elasticache_redis_replication_group_auth_enabled.elasticache_redis_replication_group_auth_enabled import (
                elasticache_redis_replication_group_auth_enabled,
            )

            check = elasticache_redis_replication_group_auth_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "PASS"
            assert (
                result[0].status_extended
                == f"Elasticache Redis replication group {REPLICATION_GROUP_ID}(v{engine_version}) does have AUTH enabled."
            )
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_id == REPLICATION_GROUP_ID
            assert result[0].resource_arn == REPLICATION_GROUP_ARN
            assert result[0].resource_tags == REPLICATION_GROUP_TAGS

    def test_elasticache_redis_cluster_auth_disabled(self):
        # Mock ElastiCache Service
        elasticache_service = MagicMock
        engine_version = "4.2"
        elasticache_service.replication_groups = {
            REPLICATION_GROUP_ARN: ReplicationGroup(
                arn=REPLICATION_GROUP_ARN,
                id=REPLICATION_GROUP_ID,
                region=AWS_REGION_US_EAST_1,
                status=REPLICATION_GROUP_STATUS,
                snapshot_retention=REPLICATION_GROUP_SNAPSHOT_RETENTION,
                encrypted=REPLICATION_GROUP_ENCRYPTION,
                transit_encryption=REPLICATION_GROUP_TRANSIT_ENCRYPTION,
                multi_az=REPLICATION_GROUP_MULTI_AZ,
                tags=REPLICATION_GROUP_TAGS,
                automatic_failover="enabled",
                auto_minor_version_upgrade=False,
                engine_version=engine_version,
                auth_token_enabled=False,
            )
        }

        # Mock VPC Service
        vpc_client = MagicMock
        vpc_client.vpc_subnets = {}

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
            from prowler.providers.aws.services.elasticache.elasticache_redis_replication_group_auth_enabled.elasticache_redis_replication_group_auth_enabled import (
                elasticache_redis_replication_group_auth_enabled,
            )

            check = elasticache_redis_replication_group_auth_enabled()
            result = check.execute()

            assert len(result) == 1
            assert result[0].status == "FAIL"
            assert (
                result[0].status_extended
                == f"Elasticache Redis replication group {REPLICATION_GROUP_ID}(v{engine_version}) does not have AUTH enabled."
            )
            assert result[0].region == AWS_REGION_US_EAST_1
            assert result[0].resource_id == REPLICATION_GROUP_ID
            assert result[0].resource_arn == REPLICATION_GROUP_ARN
            assert result[0].resource_tags == REPLICATION_GROUP_TAGS
